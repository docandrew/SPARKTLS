with Interfaces;           use Interfaces;
with SPARKTLS.RFLX_Bridge; use SPARKTLS.RFLX_Bridge;
with SPARKTLS.RFLX_Borrow;
with RFLX.TLS_Handshake.TLS_Handshake;
with RFLX.Tls_Parameters;

--  Parent body: shared utilities only.
--  Protocol-specific procedures are in child packages
--  (Client_Msgs, Server_Msgs, Certs).

package body SPARKTLS.Handshake
  with SPARK_Mode => On
is
   use type RBT.Length;
   use type RBT.Index;
   use type RBT.Bytes_Ptr;
   ----------------------------------------------------------------------------
   --  Parse_Handshake_Header
   ----------------------------------------------------------------------------

   procedure Parse_Handshake_Header
     (Data : in Byte_Seq; Msg_Type : out Maybe_HS_Msg; Msg_Len : out N32; OK : out Boolean)
   is
      use RFLX.TLS_Handshake.TLS_Handshake;
      Ctx : Context;
   begin
      Msg_Type := HT_Unknown;
      Msg_Len := 0;
      OK := False;

      if Data'Length < 4 or Data'Length > Max_Record_Plaintext then
         return;
      end if;

      declare
         Buf    : RBT.Bytes_Ptr;
         Holder : aliased SPARKTLS.RFLX_Borrow.Bounds_Holder;
      begin
         --  Read-only borrow of the whole message; we only read Tag + Length.
         SPARKTLS.RFLX_Borrow.Borrow_Read
           (Data, Data'First, N32 (Data'Length), Holder, Buf);
         Initialize (Ctx, Buf, Written_Last => RBT.Bit_Length (RBT.Length (Data'Length) * 8));
         Verify_Message (Ctx);

         if Well_Formed_Message (Ctx) then
            Msg_Type :=
              HS_Msg_From_Wire
                (Byte (RFLX.Tls_Parameters.To_Base_Integer (Get_Tag (Ctx))));
            Msg_Len := N32 (RFLX.TLS_Handshake.To_Base_Integer (Get_Length (Ctx)));
            --  Unknown handshake types map to HT_Unknown and are rejected.
            if Msg_Type /= HT_Unknown and then Msg_Len <= Max_HS_Msg then
               OK := True;
            end if;
         end if;

         Take_Buffer (Ctx, Buf);
         SPARKTLS.RFLX_Borrow.Discard (Buf);
      end;
   end Parse_Handshake_Header;

   ----------------------------------------------------------------------------
   --  ECDSA_To_DER
   ----------------------------------------------------------------------------

   procedure ECDSA_To_DER
     (R_Raw, S_Raw : in Byte_Seq; Half_Len : in N32; DER_Out : out Byte_Seq; DER_Len : out N32)
   is
      procedure Write_Int (Src : Byte_Seq; Pos : in out N32)
      with
        Pre =>
          Src'First = 0
          and Src'Last in 31 | 47
          and Pos in 2 .. 58
          and DER_Out'First = 0
          and DER_Out'Last >= Max_ECDSA_DER_Len - 1,
        Post => Pos in Pos'Old + 3 .. Pos'Old + Src'Last + 4
      is
         Src_Len : constant N32 := N32 (Src'Length);
         Skip    : N32 := 0;
         Pad     : Boolean;
      begin
         while Skip < Src_Len - 1 and then Src (Src'First + Skip) = 0 loop
            pragma Loop_Invariant (Skip in 0 .. Src_Len - 1);
            Skip := Skip + 1;
         end loop;
         Pad := Src (Src'First + Skip) >= 16#80#;
         DER_Out (Pos) := 16#02#;
         DER_Out (Pos + 1) := Byte (Src_Len - Skip + (if Pad then 1 else 0));
         Pos := Pos + 2;
         if Pad then
            DER_Out (Pos) := 0;
            Pos := Pos + 1;
         end if;
         declare
            Start_Pos : constant N32 := Pos
            with Ghost;
         begin
            for I in Skip .. Src_Len - 1 loop
               pragma Loop_Invariant (Pos = Start_Pos + (I - Skip));
               pragma Loop_Invariant (Pos in Start_Pos .. Start_Pos + (Src_Len - Skip - 1));
               DER_Out (Pos) := Src (Src'First + I);
               Pos := Pos + 1;
            end loop;
         end;
      end Write_Int;

      Pos : N32 := 2;
   begin
      DER_Out := (others => 0);
      DER_Len := 0;

      if Half_Len /= 32 and Half_Len /= 48 then
         return;
      end if;

      Write_Int (R_Raw (0 .. Half_Len - 1), Pos);
      Write_Int (S_Raw (0 .. Half_Len - 1), Pos);

      pragma Assert (Pos >= 2);
      DER_Out (0) := 16#30#;
      DER_Out (1) := Byte (Pos - 2);
      --  Max: 2 + 2*(2 + 1 + 48) = 104 <= Max_ECDSA_DER_Len
      DER_Len := (if Pos <= Max_ECDSA_DER_Len then Pos else Max_ECDSA_DER_Len);
   end ECDSA_To_DER;

   ----------------------------------------------------------------------------
   --  Pick_Sig_Algo
   --
   --  RFC 8446 4.2.3 sig algos we support per cert key type:
   --    Sign_Ed25519     -> ed25519 (0x0807)
   --    Sign_ECDSA_P256  -> ecdsa_secp256r1_sha256 (0x0403)
   --    Sign_ECDSA_P384  -> ecdsa_secp384r1_sha384 (0x0503)
   --    Sign_RSA_PSS     -> rsa_pss_rsae_sha256/384/512
   --                        (0x0804 / 0x0805 / 0x0806)
   ----------------------------------------------------------------------------
   function Pick_Sig_Algo
     (Sig_Algs : Byte_Seq; Cert : Signing_Algorithm; Allow_PKCS1_v1_5 : Boolean := False)
      return Maybe_Sig_Scheme
   is
      Pos : N32;
   begin
      if Cert = Sign_None or Sig_Algs'Length < 2 then
         return Scheme_None;
      end if;
      Pos := Sig_Algs'First;
      while Pos < Sig_Algs'Last loop
         pragma Loop_Invariant (Pos >= Sig_Algs'First and Pos < Sig_Algs'Last);
         pragma Loop_Variant (Increases => Pos);
         declare
            A : constant Maybe_Sig_Scheme :=
              Scheme_From_Wire
                (Unsigned_16 (Sig_Algs (Pos)) * 256 + Unsigned_16 (Sig_Algs (Pos + 1)));
         begin
            case Cert is
               when Sign_Ed25519 =>
                  if A = Sig_Ed25519 then
                     return A;
                  end if;

               when Sign_ECDSA_P256 =>
                  if A = Sig_ECDSA_P256_SHA256 then
                     return A;
                  end if;

               when Sign_ECDSA_P384 =>
                  if A = Sig_ECDSA_P384_SHA384 then
                     return A;
                  end if;

               when Sign_RSA_PSS =>
                  --  RSA private key handles both PSS and PKCS1 v1.5.
                  --  Sign_RSA_PSS is the storage type, not the wire
                  --  algorithm choice. Server's offer drives selection.
                  if A in Sig_RSA_PSS_SHA256 | Sig_RSA_PSS_SHA384 | Sig_RSA_PSS_SHA512 then
                     return A;
                  end if;
                  if Allow_PKCS1_v1_5
                    and A in Sig_RSA_PKCS1_SHA256 | Sig_RSA_PKCS1_SHA384 | Sig_RSA_PKCS1_SHA512
                  then
                     return A;
                  end if;

               when Sign_None =>
                  null;
            end case;
         end;
         Pos := Pos + 2;
      end loop;
      return Scheme_None;
   end Pick_Sig_Algo;

   function Pick_Sig_Algo_With_Prefs
     (Sig_Algs         : Byte_Seq;
      Cert             : Signing_Algorithm;
      Prefs            : Sig_Algo_List;
      Count            : Natural;
      Allow_PKCS1_v1_5 : Boolean := False) return Maybe_Sig_Scheme
   is
      Pos : N32;
   begin
      if Count = 0 then
         return Pick_Sig_Algo (Sig_Algs, Cert, Allow_PKCS1_v1_5);
      end if;
      if Sig_Algs'Length < 2 then
         return Scheme_None;
      end if;

      for J in Sig_Algo_Index loop
         exit when J >= Count;
         if Sig_Algo_Compatible_With_Cert (Prefs (J), Cert, Allow_PKCS1_v1_5) then
            Pos := Sig_Algs'First;
            while Pos < Sig_Algs'Last loop
               pragma Loop_Invariant (Pos >= Sig_Algs'First and Pos < Sig_Algs'Last);
               pragma Loop_Variant (Increases => Pos);
               if Prefs (J)
                  = Scheme_From_Wire
                      (Unsigned_16 (Sig_Algs (Pos)) * 256 + Unsigned_16 (Sig_Algs (Pos + 1)))
               then
                  return Prefs (J);
               end if;
               Pos := Pos + 2;
            end loop;
         end if;
      end loop;

      return Scheme_None;
   end Pick_Sig_Algo_With_Prefs;

end SPARKTLS.Handshake;
