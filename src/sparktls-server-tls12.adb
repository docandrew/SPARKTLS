with Interfaces;                 use Interfaces;
with SPARKNaCl;                  use SPARKNaCl;
with SPARKNaCl.Hashing.SHA256;   use SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Scalar;
with SPARKTLS.Records;           use SPARKTLS.Records;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Key_Schedule_12;
with SPARKTLS.P256.Point;
with SPARKTLS.P384.Point;

package body SPARKTLS.Server.TLS12 with
   SPARK_Mode => Off
is
   use Handshake.TLS12;

   --  Append handshake message to transcript
   procedure Append_Transcript
     (HC   : in out Handshake_Context;
      Data : in     Byte_Seq)
   is
      Len : constant N32 := N32 (Data'Length);
   begin
      if HC.Transcript_Len + Len <= HC.Transcript'Length then
         HC.Transcript (HC.Transcript_Len ..
                          HC.Transcript_Len + Len - 1) := Data;
         HC.Transcript_Len := HC.Transcript_Len + Len;
      end if;
   end Append_Transcript;

   ------------------------------------------------------------------
   --  Build_Server_Flight_12
   --
   --  TLS 1.2 server flight (all plaintext records):
   --    ServerHello + Certificate + ServerKeyExchange + ServerHelloDone
   --
   --  After this, state = Server_Hello_Sent (reusing the TLS 1.3 state
   --  since the Advance dispatcher handles it the same way: drain output
   --  then wait for client response).
   ------------------------------------------------------------------

   procedure Build_Server_Flight_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
      Gen_Random : constant Random_Bytes_Fn := HC.Cfg.Random;
      Rec_Out    : N32;
   begin
      Result := OK;

      --  Select ECDHE group (prefer X25519 > P-256 > P-384)
      if HC.Client_Has_X25519 then
         HC.Selected_Group := Group_X25519;
      elsif HC.Client_Has_P256 then
         HC.Selected_Group := Group_Secp256r1;
      elsif HC.Client_Has_P384 then
         HC.Selected_Group := Group_Secp384r1;
      else
         S.Last_Error := Handshake_Failure;
         S.State := Error_State;
         Records.Build_Plaintext_Alert (2, 40, S.Output, Rec_Out);
         if Output_Pending (S) > 0 then
            Result := Has_Output;
         else
            Result := Error_Alert;
         end if;
         return;
      end if;

      --  Select cipher suite based on what the client offered.
      --  For now, use AES-128-GCM-SHA256 as default for TLS 1.2.
      --  TODO: negotiate from client's cipher suite list.
      S.Negotiated_Suite := Suite_AES_128_GCM_SHA256;

      --  Generate ephemeral ECDHE keypair
      case HC.Selected_Group is
         when Group_X25519 =>
            Gen_Random (Byte_Seq (HC.Local_SK));
         when Group_Secp256r1 =>
            Gen_Random (Byte_Seq (HC.P256_Local_SK));
         when Group_Secp384r1 =>
            Gen_Random (Byte_Seq (HC.P384_Local_SK));
         when others =>
            null;
      end case;

      --  1. Build ServerHello
      declare
         SH_Buf  : Byte_Seq (0 .. Max_Server_Hello_12 - 1);
         SH_Len  : N32;
      begin
         Build_Server_Hello_12 (S, HC, SH_Buf, SH_Len);
         if SH_Len = 0 then
            S.Last_Error := Internal_Error;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;

         --  Add to transcript
         Append_Transcript (HC, SH_Buf (0 .. SH_Len - 1));

         --  Wrap in plaintext record
         Records.Build_Handshake_Record
           (Fragment  => SH_Buf (0 .. SH_Len - 1),
            Output    => S.Output,
            Bytes_Out => Rec_Out);
      end;

      --  2. Build Certificate
      declare
         Cert_Buf : Byte_Seq (0 .. 8191);
         Cert_Len : N32;
      begin
         Handshake.Build_Certificate_Chain
           (HC.Cfg.Local.all, Cert_Buf, Cert_Len);
         if Cert_Len > 0 then
            Append_Transcript (HC, Cert_Buf (0 .. Cert_Len - 1));
            Records.Build_Handshake_Record
              (Fragment  => Cert_Buf (0 .. Cert_Len - 1),
               Output    => S.Output,
               Bytes_Out => Rec_Out);
         end if;
      end;

      --  3. Build ServerKeyExchange (ECDHE params + signature)
      declare
         SKE_Buf : Byte_Seq (0 .. Max_Server_Key_Exchange - 1);
         SKE_Len : N32;
      begin
         Build_Server_Key_Exchange
           (HC, HC.Cfg.Local.all, Gen_Random, SKE_Buf, SKE_Len);
         if SKE_Len > 0 then
            Append_Transcript (HC, SKE_Buf (0 .. SKE_Len - 1));
            Records.Build_Handshake_Record
              (Fragment  => SKE_Buf (0 .. SKE_Len - 1),
               Output    => S.Output,
               Bytes_Out => Rec_Out);
         end if;
      end;

      --  4. Build ServerHelloDone
      declare
         SHD_Buf : Byte_Seq (0 .. 3);
         SHD_Len : N32;
      begin
         Build_Server_Hello_Done (SHD_Buf, SHD_Len);
         Append_Transcript (HC, SHD_Buf (0 .. SHD_Len - 1));
         Records.Build_Handshake_Record
           (Fragment  => SHD_Buf (0 .. SHD_Len - 1),
            Output    => S.Output,
            Bytes_Out => Rec_Out);
      end;

      --  Transition: drain output, then wait for ClientKeyExchange
      S.State := Server_Hello_Sent;
      if Output_Pending (S) > 0 then
         Result := Has_Output;
      else
         Result := Need_Input;
      end if;
   end Build_Server_Flight_12;

   ------------------------------------------------------------------
   --  Process_Client_Key_Exchange_12
   ------------------------------------------------------------------

   procedure Process_Client_Key_Exchange_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
   begin
      Result := Error_Alert;
      raise Program_Error
        with "Process_Client_Key_Exchange_12 not yet implemented";
   end Process_Client_Key_Exchange_12;

   ------------------------------------------------------------------
   --  Process_Client_CCS_12
   ------------------------------------------------------------------

   procedure Process_Client_CCS_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
   begin
      Result := Error_Alert;
      raise Program_Error with "Process_Client_CCS_12 not yet implemented";
   end Process_Client_CCS_12;

   ------------------------------------------------------------------
   --  Process_Client_Finished_12
   ------------------------------------------------------------------

   procedure Process_Client_Finished_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
   begin
      Result := Error_Alert;
      raise Program_Error
        with "Process_Client_Finished_12 not yet implemented";
   end Process_Client_Finished_12;

   ------------------------------------------------------------------
   --  Derive_Keys_12
   ------------------------------------------------------------------

   procedure Derive_Keys_12
     (S  : in out Session;
      HC : in out Handshake_Context)
   is
   begin
      raise Program_Error with "Derive_Keys_12 not yet implemented";
   end Derive_Keys_12;

end SPARKTLS.Server.TLS12;
