with Ada.Unchecked_Deallocation;
with Interfaces; use Interfaces;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKTLSCrypto.Ed25519;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P384.ECDSA;
with SPARKTLSCrypto.RFC6979;
with SPARKTLSCrypto.RSA;
use SPARKTLSCrypto;
with SPARKTLS.RFLX_Bridge;           use SPARKTLS.RFLX_Bridge;
with RFLX.TLS_Handshake.Certificate;
with RFLX.TLS_Handshake.Certificate_Entries;
with RFLX.TLS_Handshake.Certificate_Entry;
with RFLX.TLS_Handshake.Certificate_Verify;
with RFLX.Tls_Parameters;
with RFLX.RFLX_Types;

package body SPARKTLS.Handshake.Certs with
   SPARK_Mode => On
is
   use type RBT.Length;
   use type RBT.Index;
   use type RBT.Bytes_Ptr;
   use type RBT.Bit_Length;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr)
   with Post => Buf = null;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr)
   with SPARK_Mode => Off
   is
      procedure Dealloc is new Ada.Unchecked_Deallocation
        (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
   begin
      Dealloc (Buf);
   end RFLX_Free;

   procedure Build_Certificate
     (Cert_DER : in     Byte_Seq;
      Cert_Len : in     N32;
      Result   :    out Byte_Seq;
      Len      :    out N32)
   is
      use RFLX.TLS_Handshake.Certificate;
      --  Certificate entry: cert_data_len(3) + cert_data + ext_len(2) = 5 + Cert_Len
      Entry_Len : constant N32 := 3 + Cert_Len + 2;
      List_Len  : constant N32 := Entry_Len;
      --  Body: context_len(1) + context(0) + list_len(3) + list
      Body_Len  : constant N32 := 1 + 3 + List_Len;
      Msg_Len   : constant N32 := 4 + Body_Len;
      Ctx        : Context;
   begin
      Result := (others => 0);
      Len := 0;

      if Msg_Len > N32 (Result'Length) then
         return;
      end if;

      declare
         Buf : RBT.Bytes_Ptr :=
           new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      begin
         Initialize (Ctx, Buf);

         --  Empty certificate_request_context.
         Set_Certificate_Request_Context_Length (Ctx, 0);
         Set_Certificate_Request_Context_Empty (Ctx);

         --  Certificate list with one entry.
         Set_Certificate_List_Length
           (Ctx, RFLX.TLS_Handshake.Certificate_List_Length (List_Len));

         declare
            Entries_Ctx : RFLX.TLS_Handshake.Certificate_Entries.Context;
         begin
            Switch_To_Certificate_List (Ctx, Entries_Ctx);

            declare
               E_Buf : RBT.Bytes_Ptr :=
                 new RBT.Bytes'(1 .. RBT.Index (Entry_Len) => 0);
               E_Ctx : RFLX.TLS_Handshake.Certificate_Entry.Context;
            begin
               RFLX.TLS_Handshake.Certificate_Entry.Initialize
                 (E_Ctx, E_Buf);
               RFLX.TLS_Handshake.Certificate_Entry.Set_Cert_Data_Length
                 (E_Ctx, RFLX.TLS_Handshake.Cert_Data_Length (Cert_Len));
               pragma Assert
                 (RFLX.TLS_Handshake.Certificate_Entry.Field_Size
                    (E_Ctx,
                     RFLX.TLS_Handshake.Certificate_Entry.F_Cert_Data)
                  = RBT.Bit_Length (Cert_Len) * RBT.Byte'Size);
               declare
                  Cert_Data : constant RBT.Bytes :=
                    To_RFLX (Cert_DER (0 .. Cert_Len - 1));
               begin
                  pragma Assert (Cert_Data'Length = RBT.Length (Cert_Len));
                  pragma Assert
                    (RFLX.TLS_Handshake.Certificate_Entry.Valid_Length
                       (E_Ctx,
                        RFLX.TLS_Handshake.Certificate_Entry.F_Cert_Data,
                        Cert_Data'Length));
                  RFLX.TLS_Handshake.Certificate_Entry.Set_Cert_Data
                    (E_Ctx, Cert_Data);
               end;
               RFLX.TLS_Handshake.Certificate_Entry.Set_Extensions_Length
                 (E_Ctx, 0);
               RFLX.TLS_Handshake.Certificate_Entry.Set_Extensions_Empty
                 (E_Ctx);
               if not RFLX.TLS_Handshake.Certificate_Entry
                        .Well_Formed_Message (E_Ctx)
                 or else RFLX.TLS_Handshake.Certificate_Entry.Size (E_Ctx) = 0
                 or else RFLX.TLS_Handshake.Certificate_Entries
                           .Available_Space (Entries_Ctx)
                         < RFLX.TLS_Handshake.Certificate_Entry.Size (E_Ctx)
               then
                  RFLX.TLS_Handshake.Certificate_Entry.Take_Buffer
                    (E_Ctx, E_Buf);
                  RFLX_Free (E_Buf);
                  RFLX.TLS_Handshake.Certificate_Entries.Take_Buffer
                    (Entries_Ctx, Buf);
                  RFLX_Free (Buf);
                  return;
               end if;
               RFLX.TLS_Handshake.Certificate_Entries.Append_Element
                 (Entries_Ctx, E_Ctx);
               RFLX.TLS_Handshake.Certificate_Entry.Take_Buffer
                 (E_Ctx, E_Buf);
               RFLX_Free (E_Buf);
            end;

            Update_Certificate_List (Ctx, Entries_Ctx);
         end;

         Take_Buffer (Ctx, Buf);

         --  Prepend the handshake header around the RFLX-built body.
         Result (0) := HT_Certificate;
         Result (1) := Byte (Body_Len / 65536);
         Result (2) := Byte ((Body_Len / 256) mod 256);
         Result (3) := Byte (Body_Len mod 256);
         Result (4 .. 4 + Body_Len - 1) :=
           To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));
         RFLX_Free (Buf);
      end;

      Len := Msg_Len;
   end Build_Certificate;

   procedure Build_Certificate_Chain
     (Id     : in     Identity;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
      --  Build the Certificate message manually (simpler than RFLX
      --  for variable-count entries).
      --
      --  Format:
      --    handshake_header(4)
      --    certificate_request_context_length(1) = 0
      --    certificate_list_length(3)
      --    for each cert:
      --      cert_data_length(3) + cert_data + extensions_length(2) = 0

      Pos : N32 := 0;

      procedure Put_U8 (V : Byte)
      with Pre  => Result'First = 0
                   and then Result'Last < N32'Last
                   and then Pos <= Result'Last + 1,
           Post => Pos <= Result'Last + 1
                   and then
                     (if Pos'Old <= Result'Last
                      then Pos = Pos'Old + 1
                      else Pos = Pos'Old)
      is
      begin
         if Pos <= Result'Last then
            Result (Pos) := V;
            Pos := Pos + 1;
         end if;
      end Put_U8;

      procedure Put_U24 (V : N32)
      with Pre  => Result'First = 0
                   and then Result'Last < N32'Last
                   and then Pos <= Result'Last + 1
                   and then V <= 16#FFFFFF#,
           Post => Pos <= Result'Last + 1
                   and then
                     (if Pos'Old <= Result'Last - 2
                      then Pos = Pos'Old + 3
                      else Pos <= Result'Last + 1)
      is
      begin
         Put_U8 (Byte (V / 65536));
         Put_U8 (Byte ((V / 256) mod 256));
         Put_U8 (Byte (V mod 256));
      end Put_U24;

      procedure Put_Cert_Entry (DER : Byte_Seq; DER_Len : N32)
      with Pre  => DER'First = 0
                   and then DER_Len > 0
                   and then DER_Len <= N32 (Max_Cert_DER)
                   and then DER'Last in 0 .. N32 (Max_Cert_DER) - 1
                   and then DER'Last >= DER_Len - 1
                   and then Result'First = 0
                   and then Result'Last < N32'Last
                   and then Pos <= Result'Last + 1,
           Post => Pos <= Result'Last + 1
      is
      begin
         Put_U24 (DER_Len);              --  cert_data_length
         if Pos <= Result'Last
            and then Result'Last - Pos >= DER_Len - 1
         then
            pragma Assert (Result'First = 0);
            pragma Assert (Pos >= Result'First);
            pragma Assert (Pos <= Result'Last - (DER_Len - 1));
            pragma Assert (Pos + DER_Len - 1 <= Result'Last);
            pragma Assert (DER_Len - 1 <= DER'Last);
            Result (Pos .. Pos + DER_Len - 1) := DER (0 .. DER_Len - 1);
            Pos := Pos + DER_Len;
         end if;
         Put_U8 (0); Put_U8 (0);         --  extensions_length = 0
      end Put_Cert_Entry;

      --  Compute total list length
      List_Len : N32;
   begin
      Result := (others => 0);
      Len := 0;

      if not Id.Has_Identity or Id.NaCl_Cert_Len = 0 then
         return;
      end if;

      --  Leaf entry: 3 + cert_len + 2
      List_Len := 3 + Id.NaCl_Cert_Len + 2;

      --  Intermediate entries. Each entry adds at most
      --  3 + Max_Cert_DER + 2 bytes; with at most Max_Pool_Size
      --  intermediates, total list ≤ leaf_entry + Max_Pool_Size *
      --  (Max_Cert_DER + 5), well below N32'Last.
      for I in 0 .. Id.Int_Count - 1 loop
         pragma Loop_Invariant
           (List_Len <= 3 + Id.NaCl_Cert_Len + 2
                        + N32 (I) * (3 + N32 (Max_Cert_DER) + 2));
         if Id.Ints (I).Present then
            List_Len := List_Len + 3 + N32 (Id.Ints (I).DER_Len) + 2;
         end if;
      end loop;

      declare
         Body_Len : constant N32 := 1 + 3 + List_Len;
         Msg_Len  : constant N32 := 4 + Body_Len;
      begin
         if Msg_Len > N32 (Result'Length) then
            return;
         end if;

         --  Handshake header
         Put_U8 (HT_Certificate);
         Put_U24 (Body_Len);

         --  certificate_request_context (empty)
         Put_U8 (0);

         --  certificate_list_length
         Put_U24 (List_Len);

         --  Leaf certificate entry
         Put_Cert_Entry (Id.NaCl_Cert_DER, Id.NaCl_Cert_Len);

         --  Intermediate certificate entries
         for I in 0 .. Id.Int_Count - 1 loop
            pragma Loop_Invariant (Pos <= Result'Last + 1);
            if Id.Ints (I).Present and then Id.Ints (I).DER_Len > 0 then
               declare
                  Int_DER : Byte_Seq (0 .. N32 (Id.Ints (I).DER_Len) - 1);
               begin
                  pragma Assert
                    (Id.Ints (I).DER_Len <= X509.N32 (Max_Cert_DER));
                  --  Convert X509.Byte_Seq to SPARKNaCl.Byte_Seq
                  for J in Int_DER'Range loop
                     pragma Assert (J <= N32 (Max_Cert_DER) - 1);
                     declare
                        J_Nat : constant Natural := Natural (J);
                        K     : constant X509.N32 := X509.N32 (J_Nat);
                     begin
                        pragma Assert (J_Nat <= Max_Cert_DER - 1);
                        pragma Assert (K >= Id.Ints (I).DER'First);
                        pragma Assert (K <= X509.N32 (Max_Cert_DER) - 1);
                        pragma Assert (K <= Id.Ints (I).DER'Last);
                        Int_DER (J) := Byte (Id.Ints (I).DER (K));
                     end;
                  end loop;
                  Put_Cert_Entry (Int_DER, N32 (Id.Ints (I).DER_Len));
               end;
            end if;
         end loop;

         Len := Pos;
      end;
   end Build_Certificate_Chain;

   --  RFC 8446 §4.4.3 CertificateVerify signed-content layout:
   --    64 bytes 0x20 || context_str (32 or 33) || 0x00 || transcript_hash
   --  Total: 129 (32-byte hash) or 130 (32-byte hash, client) or 145/146
   --  (48-byte hash). Sized at 146 so all four shapes fit.
   Max_CV_Content : constant N32 := 146;

   procedure Build_CV_Content
     (Transcript_Hash : in     Byte_Seq;
      Role            : in     TLS_Role;
      Content         :    out Byte_Seq;
      Content_Len     :    out N32)
   with Pre  => Content'First = 0
                and Content'Last = Max_CV_Content - 1
                and Transcript_Hash'First = 0
                and Transcript_Hash'Last in 31 | 47,
        Post => Content_Len = 99 + N32 (Transcript_Hash'Last)
                and Content_Len in 130 .. Max_CV_Content;

   procedure Build_CV_Content
     (Transcript_Hash : in     Byte_Seq;
      Role            : in     TLS_Role;
      Content         :    out Byte_Seq;
      Content_Len     :    out N32)
   is
      --  Context_Str is statically 32 bytes regardless of role.
      Server_Ctx : constant String := "TLS 1.3, server CertificateVerify";
      Client_Ctx : constant String := "TLS 1.3, client CertificateVerify";
      pragma Assert (Server_Ctx'Length = 33);
      pragma Assert (Client_Ctx'Length = 33);
      H_Len    : constant N32 := N32 (Transcript_Hash'Last) + 1;
   begin
      Content := (others => 0);
      Content (0 .. 63) := (others => 16#20#);
      if Role = Role_Server then
         for I in Server_Ctx'Range loop
            pragma Loop_Invariant (I in Server_Ctx'Range);
            Content (64 + N32 (I - Server_Ctx'First)) :=
               Byte (Character'Pos (Server_Ctx (I)));
         end loop;
      else
         for I in Client_Ctx'Range loop
            pragma Loop_Invariant (I in Client_Ctx'Range);
            Content (64 + N32 (I - Client_Ctx'First)) :=
               Byte (Character'Pos (Client_Ctx (I)));
         end loop;
      end if;
      Content (97) := 16#00#;  --  64 + 33
      Content (98 .. 97 + H_Len) := Transcript_Hash;
      Content_Len := 98 + H_Len;
   end Build_CV_Content;

   procedure Build_Certificate_Verify
     (Transcript_Hash : in     Byte_Seq;
      Id              : in     Identity;
      Sig_Algo_Wire   : in     Unsigned_16;
      Role            : in     TLS_Role;
      Random          : in     Random_Bytes_Fn;
      Result          :    out Byte_Seq;
      Len             :    out N32)
   is
      use RFLX.TLS_Handshake.Certificate_Verify;

      Content     : Byte_Seq (0 .. Max_CV_Content - 1);
      Content_Len : N32;

      Sig     : Byte_Seq (0 .. 511) := (others => 0);
      Sig_Len : N32 := 0;
      Sig_OK  : Boolean;

      Algo_Enum : RFLX.Tls_Parameters.TLS_SignatureScheme_Enum;
   begin
      Result := (others => 0);
      Len := 0;

      Build_CV_Content (Transcript_Hash, Role, Content, Content_Len);

      case Sig_Algo_Wire is
         when 16#0807# =>
            Algo_Enum := RFLX.Tls_Parameters.Ed25519_0807;
            Sig_Len := 64;
            declare
               SM_Len : constant N32 := 64 + Content_Len;
               SM     : Byte_Seq (0 .. SM_Len - 1);
               SK     : Bytes_64;
            begin
               SK := Id.Ed25519_Key;
               SPARKTLSCrypto.Ed25519.Sign
                 (SM, Content (0 .. Content_Len - 1), SK);
               Sig (0 .. 63) := SM (0 .. 63);
               Sig_OK := True;
            end;

         when 16#0403# =>
            Algo_Enum := RFLX.Tls_Parameters.Ecdsa_Secp256r1_Sha256;
            declare
               use SPARKTLSCrypto.Hashing.SHA256;
               H : constant Digest := Hash (Content (0 .. Content_Len - 1));
               K_Bytes : Bytes_32;
               K_OK    : Boolean;
               R_Half, S_Half : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
            begin
               --  RFC 6979 deterministic nonce. Abort signing if the
               --  fixed, constant-time candidate budget is exhausted.
               SPARKTLSCrypto.RFC6979.Derive_K_P256
                 (D => Bytes_32 (Id.ECDSA_P256_Key),
                  H => Bytes_32 (H),
                  K => K_Bytes,
                  OK => K_OK);
               if not K_OK then
                  Sig_OK := False;
                  return;
               end if;
               SPARKTLSCrypto.P256.ECDSA.Sign
                 (Hash  => H,
                  D     => SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half
                             (Id.ECDSA_P256_Key),
                  K     => SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half (K_Bytes),
                  R_Out => R_Half,
                  S_Out => S_Half,
                  OK    => Sig_OK);
               if Sig_OK then
                  ECDSA_To_DER
                    (Byte_Seq (R_Half), Byte_Seq (S_Half), 32,
                     Sig, Sig_Len);
               end if;
            end;

         when 16#0503# =>
            Algo_Enum := RFLX.Tls_Parameters.Ecdsa_Secp384r1_Sha384;
            declare
               use SPARKNaCl.Hashing.SHA384;
               H : constant Digest := Hash (Content (0 .. Content_Len - 1));
               K_Bytes : Bytes_48;
               K_OK    : Boolean;
               R_Half  : Byte_Seq (0 .. 47);
               S_Half  : Byte_Seq (0 .. 47);
            begin
               --  RFC 6979 deterministic nonce (HMAC-SHA-384 DRBG).
               SPARKTLSCrypto.RFC6979.Derive_K_P384
                 (D => Bytes_48 (Id.ECDSA_P384_Key),
                  H => Bytes_48 (H),
                  K => K_Bytes,
                  OK => K_OK);
               if not K_OK then
                  Sig_OK := False;
                  return;
               end if;
               SPARKTLSCrypto.P384.ECDSA.Sign
                 (Hash  => H,
                  D     => Byte_Seq (Id.ECDSA_P384_Key),
                  K     => Byte_Seq (K_Bytes),
                  R_Out => R_Half,
                  S_Out => S_Half,
                  OK    => Sig_OK);
               if Sig_OK then
                  ECDSA_To_DER (R_Half, S_Half, 48, Sig, Sig_Len);
               end if;
            end;

         when 16#0804# =>
            Algo_Enum := RFLX.Tls_Parameters.Rsa_Pss_Rsae_Sha256;
            declare
               use SPARKTLSCrypto.Hashing.SHA256;
               H    : constant Digest := Hash (Content (0 .. Content_Len - 1));
               Salt : Bytes_32;
            begin
               Random.all (Byte_Seq (Salt));
               SPARKTLSCrypto.RSA.Sign_PSS
                 (M_Hash    => Byte_Seq (H),
                  Hash_Len  => 32,
                  Hash_Alg  => SPARKTLSCrypto.RSA.PSS_SHA256,
                  Modulus   => Id.RSA_Modulus,
                  Mod_Len   => Id.RSA_Mod_Len,
                  Priv_Exp  => Id.RSA_Priv_Exp,
                  Salt      => Byte_Seq (Salt),
                  Signature => Sig,
                  Sig_Len   => Sig_Len,
                  OK        => Sig_OK);
            end;

         when 16#0805# =>
            Algo_Enum := RFLX.Tls_Parameters.Rsa_Pss_Rsae_Sha384;
            declare
               use SPARKNaCl.Hashing.SHA384;
               H    : constant Digest := Hash (Content (0 .. Content_Len - 1));
               Salt : Bytes_48;
            begin
               Random.all (Byte_Seq (Salt));
               SPARKTLSCrypto.RSA.Sign_PSS
                 (M_Hash    => Byte_Seq (H),
                  Hash_Len  => 48,
                  Hash_Alg  => SPARKTLSCrypto.RSA.PSS_SHA384,
                  Modulus   => Id.RSA_Modulus,
                  Mod_Len   => Id.RSA_Mod_Len,
                  Priv_Exp  => Id.RSA_Priv_Exp,
                  Salt      => Byte_Seq (Salt),
                  Signature => Sig,
                  Sig_Len   => Sig_Len,
                  OK        => Sig_OK);
            end;

         when 16#0806# =>
            Algo_Enum := RFLX.Tls_Parameters.Rsa_Pss_Rsae_Sha512;
            declare
               use SPARKNaCl.Hashing.SHA512;
               H    : constant Digest := Hash (Content (0 .. Content_Len - 1));
               Salt : Bytes_64;
            begin
               Random.all (Byte_Seq (Salt));
               SPARKTLSCrypto.RSA.Sign_PSS
                 (M_Hash    => Byte_Seq (H),
                  Hash_Len  => 64,
                  Hash_Alg  => SPARKTLSCrypto.RSA.PSS_SHA512,
                  Modulus   => Id.RSA_Modulus,
                  Mod_Len   => Id.RSA_Mod_Len,
                  Priv_Exp  => Id.RSA_Priv_Exp,
                  Salt      => Byte_Seq (Salt),
                  Signature => Sig,
                  Sig_Len   => Sig_Len,
                  OK        => Sig_OK);
            end;

         when others =>
            return;
      end case;

      --  All sign-OK paths produce non-zero Sig_Len (Ed25519: 64,
      --  ECDSA: ECDSA_To_DER yields >= 8, RSA: Mod_Len). Reject the
      --  pathological path so the RFLX builder sees a non-empty
      --  signature.
      if not Sig_OK or else Sig_Len = 0 then
         return;
      end if;

      declare
         Body_Len : constant N32 := 4 + Sig_Len;
         Msg_Len  : constant N32 := 4 + Body_Len;
         Buf      : RBT.Bytes_Ptr;
         Ctx      : Context;
      begin
         if Msg_Len > N32 (Result'Length) then
            return;
         end if;

         Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
         Initialize (Ctx, Buf);
         Set_Algorithm (Ctx, Algo_Enum);
         Set_Signature_Length
           (Ctx, RFLX.TLS_Handshake.Signature_Length (Sig_Len));
         pragma Assert
           (Field_Size (Ctx, F_Signature)
            = RBT.Bit_Length (Sig_Len) * RBT.Byte'Size);
         declare
            Signature_Data : constant RBT.Bytes :=
              To_RFLX (Sig (0 .. Sig_Len - 1));
         begin
            pragma Assert
              (Signature_Data'Length = RBT.Length (Sig_Len));
            pragma Assert
              (Valid_Length (Ctx, F_Signature, Signature_Data'Length));
            Set_Signature (Ctx, Signature_Data);
         end;
         Take_Buffer (Ctx, Buf);

         Result (0) := HT_Certificate_Verify;
         Result (1) := 16#00#;
         Result (2) := Byte (Body_Len / 256);
         Result (3) := Byte (Body_Len mod 256);
         Result (4 .. 4 + Body_Len - 1) :=
            To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));

         RFLX_Free (Buf);
         Len := Msg_Len;
      end;
   end Build_Certificate_Verify;

   ------------------------------------------------------------------
   --  RFC 8446 §4.4.2 TLS 1.3 Certificate parser (via RFLX)
   ------------------------------------------------------------------

   --  Copy a single RFLX-shape cert blob (1-based RBT.Bytes index) into
   --  the X509 Byte_Seq (0-based X509 index). Isolates the index
   --  conversion + loop-invariant arithmetic from the parent
   --  Parse_Certificate_Chain_13 body so the prover sees a tight
   --  obligation rather than a deeply-nested cascade.
   procedure Copy_Cert_To_X509
     (Cert_RFLX : in     RBT.Bytes;
      Cert_X    :    out X509.Byte_Seq)
   with Pre  => Cert_RFLX'First = 1
                and then Cert_X'First = 0
                and then Cert_X'Length > 0
                and then Cert_X'Length <= Max_Cert_DER
                and then Natural (Cert_RFLX'Length) = Cert_X'Length;

   procedure Copy_Cert_To_X509
     (Cert_RFLX : in     RBT.Bytes;
      Cert_X    :    out X509.Byte_Seq)
   is
   begin
      Cert_X := (others => 0);
      for J in Natural range 0 .. Cert_X'Length - 1 loop
         pragma Loop_Invariant
           (J in 0 .. Cert_X'Length - 1
            and J <= Max_Cert_DER - 1
            and X509.N32 (J) in Cert_X'Range
            and RBT.Index (J + 1) in Cert_RFLX'Range);
         Cert_X (X509.N32 (J)) :=
            X509.Byte (Cert_RFLX (RBT.Index (J + 1)));
      end loop;
   end Copy_Cert_To_X509;

   procedure Parse_X509_From_RFLX
     (Cert_RFLX : in     RBT.Bytes;
      C_Len     : in     N32;
      Cert      :    out X509.Certificate;
      OK        :    out Boolean)
   with Pre => C_Len > 0
               and then C_Len <= N32 (Max_Cert_DER)
               and then Cert_RFLX'First = 1
               and then Cert_RFLX'Length = RBT.Length (C_Len),
        Post => (if OK then X509.Is_Valid (Cert)
                            and X509.Spans_Valid
                                  (Cert, X509.N32 (C_Len) - 1));

   procedure Parse_X509_From_RFLX
     (Cert_RFLX : in     RBT.Bytes;
      C_Len     : in     N32;
      Cert      :    out X509.Certificate;
      OK        :    out Boolean)
   is
      Cert_X : X509.Byte_Seq (0 .. X509.N32 (C_Len) - 1);
   begin
      pragma Assert (X509.N32 (C_Len) <= X509.N32 (Max_Cert_DER));
      pragma Assert (Cert_X'Last < X509.N32'Last);
      Copy_Cert_To_X509 (Cert_RFLX, Cert_X);
      X509.Parse (Cert_X, Cert, OK);
   end Parse_X509_From_RFLX;

   --  Same as Copy_Cert_To_X509 but into the HC.Peer_Cert_DER buffer
   --  region (0-based, capacity Max_Cert_DER_Len).
   procedure Copy_Cert_To_Peer_DER
     (Cert_RFLX : in     RBT.Bytes;
      HC        : in out Handshake_Context;
      C_Len     : in     N32)
   with Pre  => Cert_RFLX'First = 1
                and then Cert_RFLX'Length = RBT.Length (C_Len)
                and then C_Len > 0
			                and then C_Len <= N32 (Max_Cert_DER)
			                and then Reasm_Coherent (HC),
	        Post => HC.Client_HS = HC.Client_HS'Old
	                and then HC.Transcript_Len = HC.Transcript_Len'Old
	                and then HC.Hash_Len = HC.Hash_Len'Old
	                and then (if HC.Cfg.Local'Old /= null
	                          then HC.Cfg.Local /= null)
	                and then (if HC.Cfg.Local'Old /= null
	                              and then HC.Cfg.Local'Old.Has_Identity
	                          then HC.Cfg.Local /= null
	                               and then HC.Cfg.Local.Has_Identity)
	                and then (if HC.Cfg.Random'Old /= null
	                          then HC.Cfg.Random /= null)
				                and then Reasm_Coherent (HC)
                  and then HC.Reasm_Len = HC.Reasm_Len'Old
                  and then HC.Reasm_Need = HC.Reasm_Need'Old
                  and then HC.Reasm_Hdr_Pending =
                    HC.Reasm_Hdr_Pending'Old
		                and then HC.Peer_Cert_DER_Len = C_Len;

   procedure Copy_Cert_To_Peer_DER
     (Cert_RFLX : in     RBT.Bytes;
      HC        : in out Handshake_Context;
      C_Len     : in     N32)
   is
   begin
      HC.Peer_Cert_DER_Len := C_Len;
      for I in N32 range 0 .. C_Len - 1 loop
         pragma Loop_Invariant
           (I in 0 .. C_Len - 1
            and RBT.Index (I + 1) in Cert_RFLX'Range);
			         pragma Loop_Invariant (Reasm_Coherent (HC));
         pragma Loop_Invariant (HC.Reasm_Len = HC.Reasm_Len'Loop_Entry);
         pragma Loop_Invariant
           (HC.Reasm_Need = HC.Reasm_Need'Loop_Entry);
         pragma Loop_Invariant
           (HC.Reasm_Hdr_Pending = HC.Reasm_Hdr_Pending'Loop_Entry);
         HC.Peer_Cert_DER (I) :=
            Byte (Cert_RFLX (RBT.Index (I + 1)));
      end loop;
   end Copy_Cert_To_Peer_DER;

   procedure Store_Intermediate
     (Cert_RFLX : in     RBT.Bytes;
      Cert      : in     X509.Certificate;
      C_Len     : in     N32;
      Target    :    out Pool_Entry)
   with Pre => Cert_RFLX'First = 1
               and Cert_RFLX'Length = RBT.Length (C_Len)
               and C_Len > 0
               and C_Len <= N32 (Max_Cert_DER)
               and X509.Is_Valid (Cert)
               and X509.Spans_Valid (Cert, X509.N32 (C_Len) - 1);

   procedure Store_Intermediate
     (Cert_RFLX : in     RBT.Bytes;
      Cert      : in     X509.Certificate;
      C_Len     : in     N32;
      Target    :    out Pool_Entry)
   is
      DER_Copy : Cert_DER_Buf := (others => 0);
   begin
      for I in N32 range 0 .. C_Len - 1 loop
         pragma Loop_Invariant
           (I in 0 .. C_Len - 1
            and I <= N32 (Max_Cert_DER) - 1
            and RBT.Index (I + 1) in Cert_RFLX'Range);
         DER_Copy (X509.N32 (I)) :=
            X509.Byte (Cert_RFLX (RBT.Index (I + 1)));
      end loop;
      Target :=
        (Cert    => Cert,
         DER     => DER_Copy,
         DER_Len => X509.N32 (C_Len),
         Present => True);
   end Store_Intermediate;

   procedure Parse_Certificate_Chain_13
     (HC                     : in out Handshake_Context;
      HS_Msg                 : in     Byte_Seq;
      Reject_Cert_Extensions : in     Boolean;
      OK                     :    out Boolean;
      Err                    :    out Error_Code)
   is
      package C13 renames RFLX.TLS_Handshake.Certificate;
      package C13_Entries renames RFLX.TLS_Handshake.Certificate_Entries;
      package C13_Entry renames RFLX.TLS_Handshake.Certificate_Entry;
      Body_Len : constant N32 := N32 (HS_Msg'Length) - 4;
      Buf      : RBT.Bytes_Ptr;
      Ctx      : C13.Context;
      Cert_Idx : Natural := 0;
      Ext_Reject : Boolean := False;
   begin
      HC.Peer_Cert_Valid := False;
      HC.Peer_Int_Count := 0;
      OK := False;
      Err := Decode_Error;

      --  Minimum body: ctx_len(1) + cert_list_len(3) = 4 bytes.
      if Body_Len < 4 then
         return;
      end if;

      declare
         Ctx_Len : constant N32 := N32 (HS_Msg (HS_Msg'First + 4));
      begin
         if Ctx_Len > Body_Len - 4 then
            return;
         end if;

         declare
            List_Off : constant N32 := HS_Msg'First + 5 + Ctx_Len;
            List_Len : constant N32 :=
              N32 (HS_Msg (List_Off)) * 65536
              + N32 (HS_Msg (List_Off + 1)) * 256
              + N32 (HS_Msg (List_Off + 2));
         begin
            if List_Len /= Body_Len - 4 - Ctx_Len
            then
               return;
            end if;
         end;
      end;

      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      Buf.all := To_RFLX (HS_Msg (HS_Msg'First + 4 ..
                                   HS_Msg'First + 4 + Body_Len - 1));
      C13.Initialize
        (Ctx, Buf,
         Written_Last => RBT.Bit_Length (Body_Len) * 8);
      C13.Verify_Message (Ctx);

      if not C13.Well_Formed_Message (Ctx) then
         C13.Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         return;
      end if;

      --  Walk certificate entries. Sequence iteration follows the
      --  RFLX message-sequence pattern: Switch → loop Has_Element →
      --  Switch / Verify_Message / Update.
      declare
         use type RBT.Bit_Length;
      begin
         if C13.Field_Size (Ctx, C13.F_Certificate_List) > 0 then
            declare
               Entries_Ctx : C13_Entries.Context;
            begin
               if not C13.Has_Buffer (Ctx) then
                  return;
               end if;
               if not
                 (C13.Valid_Next (Ctx, C13.F_Certificate_List)
                  and then C13.Field_First
                             (Ctx, C13.F_Certificate_List)
                           rem RBT.Byte'Size = 1
                  and then C13.Available_Space
                             (Ctx, C13.F_Certificate_List)
                           >= C13.Field_Size
                                (Ctx, C13.F_Certificate_List)
                  and then C13.Field_Condition
                             (Ctx, C13.F_Certificate_List))
               then
                  C13.Take_Buffer (Ctx, Buf);
                  RFLX_Free (Buf);
                  return;
               end if;
               C13.Switch_To_Certificate_List (Ctx, Entries_Ctx);

               while C13_Entries.Has_Element (Entries_Ctx)
                 and then Cert_Idx <= Max_Pool_Size
               loop
                  pragma Loop_Invariant
                    (C13_Entries.Has_Buffer (Entries_Ctx)
                     and then C13_Entries.Valid (Entries_Ctx)
                     and then HC.Client_HS = HC.Client_HS'Loop_Entry
	                     and then
	                       HC.Transcript_Len =
	                         HC.Transcript_Len'Loop_Entry
	                     and then HC.Hash_Len = HC.Hash_Len'Loop_Entry
	                     and then (if HC.Cfg.Local'Loop_Entry /= null
	                               then HC.Cfg.Local /= null)
	                     and then
	                       (if HC.Cfg.Local'Loop_Entry /= null
	                           and then HC.Cfg.Local'Loop_Entry.Has_Identity
	                        then HC.Cfg.Local /= null
	                             and then HC.Cfg.Local.Has_Identity)
	                     and then (if HC.Cfg.Random'Loop_Entry /= null
	                               then HC.Cfg.Random /= null)
						                     and then Reasm_Coherent (HC)
	                         and then
                           HC.Reasm_Len = HC.Reasm_Len'Loop_Entry
                         and then
                           HC.Reasm_Need = HC.Reasm_Need'Loop_Entry
                         and then
                           HC.Reasm_Hdr_Pending =
                             HC.Reasm_Hdr_Pending'Loop_Entry
		                     and then
                       (if HC.Peer_Cert_Valid
                        then HC.Peer_Cert_DER_Len
                             in 1 .. Max_Cert_DER_Len
                             and then X509.Spans_Valid
                               (HC.Peer_Cert,
                                X509.N32 (HC.Peer_Cert_DER_Len) - 1)));
                  declare
                     E_Ctx : C13_Entry.Context;
                  begin
                     C13_Entries.Switch (Entries_Ctx, E_Ctx);
                     C13_Entry.Verify_Message (E_Ctx);

                     if C13_Entry.Well_Formed_Message (E_Ctx) then
                        if C13_Entry.Valid
                             (E_Ctx, C13_Entry.F_Cert_Data_Length)
                          and then C13_Entry.Valid
                             (E_Ctx, C13_Entry.F_Extensions_Length)
                          and then C13_Entry.Well_Formed
                             (E_Ctx, C13_Entry.F_Cert_Data)
                          and then C13_Entry.Valid_Next
                             (E_Ctx, C13_Entry.F_Cert_Data)
                        then
                           declare
                              C_Len : constant N32 :=
                                N32
                                  (C13_Entry.Get_Cert_Data_Length (E_Ctx));
                           begin
                              --  RFC 8446 §4.4.2 per-cert extensions
                              --  policy check (client only).
                              if Reject_Cert_Extensions
                                and then N32
                                  (C13_Entry.Get_Extensions_Length (E_Ctx)) > 0
                              then
                                 Ext_Reject := True;
                              end if;
                              if C_Len > 0
                                and then C_Len <= N32 (Max_Cert_DER)
                                and then C13_Entry.Field_Size
                                  (E_Ctx, C13_Entry.F_Cert_Data)
                                    = RBT.Bit_Length (C_Len) * RBT.Byte'Size
                                and then RFLX.RFLX_Types.To_Length
                                  (C13_Entry.Field_Size
                                     (E_Ctx, C13_Entry.F_Cert_Data))
                                    = RBT.Length (C_Len)
                              then
                                 declare
                                    Cert_RFLX : RBT.Bytes
                                      (1 .. RBT.Index (C_Len));
                                 begin
                                    pragma Assert (Cert_RFLX'First = 1);
                                    pragma Assert
                                      (Cert_RFLX'Length = RBT.Length (C_Len));
                                    C13_Entry.Get_Cert_Data
                                      (E_Ctx, Cert_RFLX);

                                    if Cert_Idx = 0 then
                                       --  Leaf cert
                                       Copy_Cert_To_Peer_DER
                                         (Cert_RFLX, HC, C_Len);
                                       declare
                                          P_OK : Boolean;
                                       begin
                                          Parse_X509_From_RFLX
                                            (Cert_RFLX, C_Len,
                                             HC.Peer_Cert, P_OK);
                                          HC.Peer_Cert_Valid := P_OK
                                             and then
                                               X509.Is_Valid (HC.Peer_Cert);
                                          pragma Assert
                                            (if HC.Peer_Cert_Valid
                                             then HC.Peer_Cert_DER_Len
                                                  in 1 .. Max_Cert_DER_Len
                                                  and then X509.Spans_Valid
                                                    (HC.Peer_Cert,
                                                     X509.N32
                                                       (HC.Peer_Cert_DER_Len)
                                                     - 1));
                                       end;
                                    elsif HC.Peer_Int_Count < Max_Pool_Size
                                    then
                                       --  Intermediate cert
                                       declare
                                          Idx : constant Natural :=
                                            HC.Peer_Int_Count;
                                          C    : X509.Certificate;
                                          P_OK : Boolean;
                                       begin
                                          Parse_X509_From_RFLX
                                            (Cert_RFLX, C_Len, C, P_OK);
                                          if P_OK
                                            and then X509.Is_Valid (C)
                                          then
                                             Store_Intermediate
                                               (Cert_RFLX, C, C_Len,
                                                HC.Peer_Ints (Idx));
                                             HC.Peer_Int_Count :=
                                               HC.Peer_Int_Count + 1;
                                          end if;
                                       end;
                                    end if;
                                 end;
                                 Cert_Idx := Cert_Idx + 1;
                              end if;
                           end;
                        end if;
                     end if;

	                     C13_Entries.Update (Entries_Ctx, E_Ctx);
	                     if not C13_Entries.Has_Buffer (Entries_Ctx) then
	                        pragma Assert
	                          (if HC.Peer_Cert_Valid
	                           then HC.Peer_Cert_DER_Len
	                                in 1 .. Max_Cert_DER_Len
	                                and then X509.Spans_Valid
	                                  (HC.Peer_Cert,
	                                   X509.N32 (HC.Peer_Cert_DER_Len) - 1));
	                        return;
	                     end if;
	                     if not C13_Entries.Valid (Entries_Ctx) then
	                        C13_Entries.Take_Buffer (Entries_Ctx, Buf);
	                        RFLX_Free (Buf);
	                        pragma Assert
	                          (if HC.Peer_Cert_Valid
	                           then HC.Peer_Cert_DER_Len
	                                in 1 .. Max_Cert_DER_Len
	                                and then X509.Spans_Valid
	                                  (HC.Peer_Cert,
	                                   X509.N32 (HC.Peer_Cert_DER_Len) - 1));
	                        return;
	                     end if;
                  end;
               end loop;

               C13_Entries.Take_Buffer (Entries_Ctx, Buf);
               RFLX_Free (Buf);
	               if Ext_Reject then
	                  OK := False;
	                  Err := Unsupported_Extension;
	               else
	                  OK := True;
	                  Err := No_Error;
	               end if;
	               pragma Assert
	                 (if HC.Peer_Cert_Valid
	                  then HC.Peer_Cert_DER_Len
	                       in 1 .. Max_Cert_DER_Len
	                       and then X509.Spans_Valid
	                         (HC.Peer_Cert,
	                          X509.N32 (HC.Peer_Cert_DER_Len) - 1));
	               return;
	            end;
         end if;
      end;

      C13.Take_Buffer (Ctx, Buf);
      RFLX_Free (Buf);

	      if Ext_Reject then
	         OK := False;
	         Err := Unsupported_Extension;
	      else
	         OK := True;
	         Err := No_Error;
	      end if;
	      pragma Assert
	        (if HC.Peer_Cert_Valid
	         then HC.Peer_Cert_DER_Len
	              in 1 .. Max_Cert_DER_Len
	              and then X509.Spans_Valid
	                (HC.Peer_Cert,
	                 X509.N32 (HC.Peer_Cert_DER_Len) - 1));
	   end Parse_Certificate_Chain_13;

end SPARKTLS.Handshake.Certs;
