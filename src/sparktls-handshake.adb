with Ada.Unchecked_Deallocation;
with Interfaces; use Interfaces;
with SPARKTLS.RFLX_Bridge;           use SPARKTLS.RFLX_Bridge;
with RFLX.TLS_Handshake.TLS_Handshake;
with RFLX.TLS_Handshake.Finished;
with RFLX.Tls_Parameters;

--  Parent body: shared utilities only.
--  Protocol-specific procedures are in child packages
--  (Client_Msgs, Server_Msgs, Certs).
package body SPARKTLS.Handshake with
   SPARK_Mode => On
is
   use type RBT.Length;
   use type RBT.Index;
   use type RBT.Bytes_Ptr;

   --  Deallocate an RFLX buffer.
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

   --================================================================
   --  Parse_Handshake_Header
   --================================================================

   procedure Parse_Handshake_Header
     (Data     : in     Byte_Seq;
      Msg_Type :    out Byte;
      Msg_Len  :    out N32;
      OK       :    out Boolean)
   is
      use RFLX.TLS_Handshake.TLS_Handshake;
      Ctx : Context;
   begin
      Msg_Type := 0;
      Msg_Len  := 0;
      OK       := False;

      if Data'Length < 4 or Data'Length > Max_Record_Plaintext then
         return;
      end if;

      declare
         Buf : RBT.Bytes_Ptr :=
            new RBT.Bytes'(1 .. RBT.Index (Data'Length) => 0);
      begin
         Buf.all := To_RFLX (Data);
         Initialize (Ctx, Buf,
                     Written_Last =>
                        RBT.Bit_Length (RBT.Length (Data'Length) * 8));
         Verify_Message (Ctx);

         if Well_Formed_Message (Ctx) then
            Msg_Type := Byte (RFLX.Tls_Parameters.To_Base_Integer
                                (Get_Tag (Ctx)));
            Msg_Len  := N32 (RFLX.TLS_Handshake.To_Base_Integer
                               (Get_Length (Ctx)));
            --  Validate known handshake type (TLS 1.2 + 1.3)
            if Msg_Type in 16#01# | 16#02# | 16#04# | 16#08# |
                           16#0B# | 16#0C# | 16#0D# | 16#0E# |
                           16#0F# | 16#10# | 16#14#
               and then Msg_Len <= Max_HS_Msg
            then
               OK := True;
            end if;
         end if;

         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
      end;
   end Parse_Handshake_Header;

   --================================================================
   --  Build_Finished
   --================================================================

   procedure Build_Finished
     (Verify_Data : in     Bytes_32;
      Result      :    out Byte_Seq;
      Len         :    out N32)
   is
      use RFLX.TLS_Handshake.Finished;
      Body_Len : constant N32 := 32;
      Msg_Len  : constant N32 := 4 + Body_Len;
      Ctx : Context;
   begin
      Result := (others => 0);
      Len := 0;

      declare
         Buf : RBT.Bytes_Ptr := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      begin
         Initialize (Ctx, Buf);
         Set_Verify_Data (Ctx, To_RFLX (Verify_Data));
         Take_Buffer (Ctx, Buf);

         --  Prepend handshake header
         Result (0) := HT_Finished;
         Result (1) := 16#00#;
         Result (2) := 16#00#;
         Result (3) := Byte (Body_Len);
         Result (4 .. 4 + Body_Len - 1) :=
            To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));
         RFLX_Free (Buf);
      end;

      Len := Msg_Len;
   end Build_Finished;

   --================================================================
   --  ECDSA_To_DER
   --================================================================

   procedure ECDSA_To_DER
     (R_Raw, S_Raw : in     Byte_Seq;
      Half_Len     : in     N32;
      DER_Out      :    out Byte_Seq;
      DER_Len      :    out N32)
   is
      procedure Write_Int
        (Src : Byte_Seq; Pos : in out N32)
      with Pre  => Src'First = 0
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
         while Skip < Src_Len - 1
            and then Src (Src'First + Skip) = 0
         loop
            pragma Loop_Invariant (Skip in 0 .. Src_Len - 1);
            Skip := Skip + 1;
         end loop;
         Pad := Src (Src'First + Skip) >= 16#80#;
         DER_Out (Pos) := 16#02#;
         DER_Out (Pos + 1) := Byte (Src_Len - Skip
                                     + (if Pad then 1 else 0));
         Pos := Pos + 2;
         if Pad then
            DER_Out (Pos) := 0;
            Pos := Pos + 1;
         end if;
         declare
            Start_Pos : constant N32 := Pos with Ghost;
         begin
            for I in Skip .. Src_Len - 1 loop
               pragma Loop_Invariant
                 (Pos = Start_Pos + (I - Skip));
               pragma Loop_Invariant
                 (Pos in Start_Pos .. Start_Pos + (Src_Len - Skip - 1));
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
      DER_Len := (if Pos <= Max_ECDSA_DER_Len then Pos
                  else Max_ECDSA_DER_Len);
   end ECDSA_To_DER;

end SPARKTLS.Handshake;
