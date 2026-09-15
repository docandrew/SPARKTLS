--  Record header length policy (RFC 8446 5.1 / 5.2, RFC 5246 6.2.1 / 6.2.3.3).
--
--  Parse_Record_Header refuses two kinds of length: above the RFC limit
--  and zero. Both raise Overflow so every consumer fails closed on one
--  flag, but they are different faults with different alerts, and
--  Records.Overflow_Error is the single place that tells them apart:
--  an oversized record is record_overflow; a zero-length application_data
--  record under keys is too short for the AEAD tag and therefore a
--  decryption failure, bad_record_mac; any other zero-length record is
--  unexpected_message. The tlsfuzzer chacha20 script draws its "0 bytes
--  long ciphertext" case in only some runs, so this pins the decision
--  where every run sees it.
--
--  Runs with no network and no ports, so it also executes under --checked.

with Ada.Text_IO;   use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;    use Interfaces;
with SPARKNaCl;     use SPARKNaCl;
with SPARKTLS;      use SPARKTLS;
with SPARKTLS.Records;

procedure Test_Record_Header_Length is
   use SPARKTLS.Records;

   Pass : Natural := 0;
   Fail : Natural := 0;

   procedure Check (Name : String; Ok : Boolean) is
   begin
      if Ok then
         Pass := Pass + 1;
      else
         Fail := Fail + 1;
         Put_Line ("FAIL: " & Name);
      end if;
   end Check;

   --  A record header followed by up to 16 bytes of body.
   procedure Parse
     (CT       : Byte;
      Length   : Natural;
      Avail    : N32;
      Rec      : out Parse_Result)
   is
      Buf : Byte_Seq (0 .. 20) := (others => 16#A1#);
   begin
      Buf (0) := CT;
      Buf (1) := 16#03#;
      Buf (2) := 16#03#;
      Buf (3) := Byte (Length / 256);
      Buf (4) := Byte (Length mod 256);
      Parse_Record_Header (Buf, Avail, Rec);
   end Parse;

   Rec : Parse_Result;
begin
   --  Zero-length application_data: the CI case. Under keys it is a
   --  decryption failure; before keys it is simply out of place.
   Parse (16#17#, 0, 5, Rec);
   Check ("empty app: not OK", not Rec.OK);
   Check ("empty app: Overflow set", Rec.Overflow);
   Check ("empty app: Empty set", Rec.Empty);
   Check ("empty app: content kept", Rec.Content = Content_Application_Data);
   Check ("empty app under keys -> bad_record_mac",
          Overflow_Error (Rec, Read_Encrypted => True) = Bad_Record_MAC);
   Check ("empty app before keys -> unexpected_message",
          Overflow_Error (Rec, Read_Encrypted => False) = Unexpected_Message);

   --  Zero-length handshake / alert / CCS: RFC 8446 5.1 forbids sending
   --  them; unexpected_message in every state.
   Parse (16#16#, 0, 5, Rec);
   Check ("empty handshake: Empty set", Rec.Overflow and Rec.Empty);
   Check ("empty handshake: content kept", Rec.Content = Content_Handshake);
   Check ("empty handshake under keys -> unexpected_message",
          Overflow_Error (Rec, Read_Encrypted => True) = Unexpected_Message);
   Parse (16#15#, 0, 5, Rec);
   Check ("empty alert -> unexpected_message",
          Rec.Empty
          and then Overflow_Error (Rec, Read_Encrypted => True) = Unexpected_Message);
   Parse (16#14#, 0, 5, Rec);
   Check ("empty CCS -> unexpected_message",
          Rec.Empty
          and then Overflow_Error (Rec, Read_Encrypted => False) = Unexpected_Message);

   --  Zero-length record of an undefined type: still Empty, content
   --  unknown, unexpected_message.
   Parse (16#18#, 0, 5, Rec);
   Check ("empty unknown type -> unexpected_message",
          (Rec.Empty and Rec.Content = Content_Unknown)
          and then Overflow_Error (Rec, Read_Encrypted => True) = Unexpected_Message);

   --  Above the limit is an overflow and nothing else: 2^14 + 256 + 1 for
   --  application_data, 2^14 + 1 for the plaintext types.
   Parse (16#17#, Max_Fragment + 256 + 1, 5, Rec);
   Check ("oversize app: Overflow, not Empty", Rec.Overflow and not Rec.Empty);
   Check ("oversize app -> record_overflow",
          Overflow_Error (Rec, Read_Encrypted => True) = Record_Overflow);
   Parse (16#16#, Max_Fragment + 1, 5, Rec);
   Check ("oversize handshake: Overflow, not Empty", Rec.Overflow and not Rec.Empty);
   Check ("oversize handshake -> record_overflow",
          Overflow_Error (Rec, Read_Encrypted => False) = Record_Overflow);

   --  At the limit with only the header present: neither fault, waiting
   --  for the body (Record_Len = 0 means "need input").
   Parse (16#17#, Max_Fragment + 256, 5, Rec);
   Check ("at-limit app, body pending: no fault",
          not Rec.OK and not Rec.Overflow and not Rec.Empty and Rec.Record_Len = 0);
   Parse (16#16#, Max_Fragment, 5, Rec);
   Check ("at-limit handshake, body pending: no fault",
          not Rec.OK and not Rec.Overflow and not Rec.Empty and Rec.Record_Len = 0);

   --  The smallest legal record: one byte.
   Parse (16#17#, 1, 6, Rec);
   Check ("1-byte app: OK", Rec.OK);
   Check ("1-byte app: fields",
          Rec.Content = Content_Application_Data
          and Rec.Fragment_Len = 1 and Rec.Record_Len = 6
          and Rec.Fragment_Pos = Record_Header_Size);
   Check ("1-byte app: no fault flags", not Rec.Overflow and not Rec.Empty);

   Put_Line ("=== record header length:" & Pass'Image & " passed,"
             & Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Record_Header_Length;
