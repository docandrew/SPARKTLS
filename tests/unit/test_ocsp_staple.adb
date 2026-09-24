--  Server-side OCSP stapling (RFC 6066 8).
--
--  TLS 1.3: Build_Certificate_Chain with Staple => True must put the
--  identity's response into the leaf CertificateEntry as a status_request
--  extension, and the client-side parser (Want_Staple => True) must hand
--  back exactly those bytes; with Staple => False nothing is added.
--  TLS 1.2: Build_Certificate_Status_12 lays out the CertificateStatus
--  message; the client parser of the same message is exercised by BoGo
--  and the integration lane.
--
--  Usage: test_ocsp_staple <cert.pem> <key.pem>
with Det_Random_Lib;
with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLS; use SPARKTLS;
with SPARKTLS.Credentials;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Handshake.TLS13;
with SPARKTLS.HS_Pool;
with X509;

procedure Test_OCSP_Staple is
   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then
         Pass := Pass + 1;
         Put_Line ("  PASS: " & Name);
      else
         Fail := Fail + 1;
         Put_Line ("  FAIL: " & Name);
      end if;
   end Check;

   --  Deterministic filler for the identity-load blinds: this test is
   --  about parsing and signing, not about the blind's randomness.
   procedure Test_Random (Output : out Byte_Seq) is
      V : Byte := 16#5B#;
   begin
      for I in Output'Range loop
         V := V * 13 + 7;
         Output (I) := V;
      end loop;
   end Test_Random;

   Id    : aliased Identity;
   Id_OK : Boolean;

   --  A fake OCSPResponse body: the builders and parsers carry it opaquely.
   Fake_Len : constant N32 := 301;
   Fake     : Byte_Seq (0 .. Fake_Len - 1);

   procedure Check_TLS13 (Staple : Boolean; Label : String) is
      D        : SPARKTLS.HS_Pool.HS_Data;
      HC       : Handshake_Context;
      Cert_Buf : Byte_Seq (0 .. 9 * (Max_Cert_DER_Len + 5) + 10 + Max_OCSP_Response + 8);
      Cert_Len : N32;
      P_OK     : Boolean;
      P_Err    : Error_Code;
      --  The extension appears only when asked AND a staple is configured.
      Expect   : constant Boolean := Staple and then Id.OCSP_Staple_Len > 0;
   begin
      SPARKTLS.Handshake.TLS13.Build_Certificate_Chain
        (Id => Id, Staple => Staple, Arena_Storage => D.Arena_Storage,
         Result => Cert_Buf, Len => Cert_Len);
      Check ("TLS 1.3 " & Label & ": Certificate builds", Cert_Len > 0);
      if Cert_Len = 0 then
         return;
      end if;
      declare
         Plain : constant N32 := 4 + 1 + 3 + 5 + Id.NaCl_Cert_Len;
      begin
         if Expect then
            Check ("TLS 1.3 " & Label & ": message grew by the extension",
                   Cert_Len = Plain + 8 + Fake_Len);
         else
            Check ("TLS 1.3 " & Label & ": message has no extension bytes",
                   Cert_Len = Plain);
         end if;
      end;
      SPARKTLS.Handshake.TLS13.Parse_Certificate_Chain_13
        (HC                     => HC,
         D                      => D,
         HS_Msg                 => Cert_Buf (0 .. Cert_Len - 1),
         Reject_Cert_Extensions => True,
         Want_Staple            => True,
         OK                     => P_OK,
         Err                    => P_Err);
      Check ("TLS 1.3 " & Label & ": client parser accepts the message", P_OK);
      if not P_OK then
         return;
      end if;
      if Expect then
         Check ("TLS 1.3 " & Label & ": parser recovers the staple length",
                D.Stapled_OCSP_Len = X509.N32 (Fake_Len) and then not D.Stapled_Too_Big);
         declare
            Same : Boolean := D.Stapled_OCSP_Len = X509.N32 (Fake_Len);
         begin
            if Same then
               for I in 0 .. Fake_Len - 1 loop
                  if D.Stapled_OCSP (X509.N32 (I)) /= X509.Byte (Fake (I)) then
                     Same := False;
                  end if;
               end loop;
            end if;
            Check ("TLS 1.3 " & Label & ": parser recovers the staple bytes", Same);
         end;
      else
         Check ("TLS 1.3 " & Label & ": parser sees no staple",
                D.Stapled_OCSP_Len = 0 and then not D.Stapled_Too_Big);
      end if;
      Check ("TLS 1.3 " & Label & ": leaf certificate still parses",
             D.Peer_Leaf.Present and then D.Peer_Leaf.DER_Len = X509.N32 (Id.NaCl_Cert_Len));
   end Check_TLS13;

begin
   Det_Random_Lib.Reset;   --  start SPARKTLS.RBG from the deterministic test source
   Put_Line ("OCSP stapling (server side)");
   Put_Line ("===========================");

   if Ada.Command_Line.Argument_Count /= 2 then
      Put_Line ("usage: test_ocsp_staple <cert.pem> <key.pem>");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   SPARKTLS.Credentials.Load_Identity
     (Id, Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2), Id_OK);
   Check ("identity loads", Id_OK);
   if not Id_OK then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
      return;
   end if;

   for I in Fake'Range loop
      Fake (I) := Byte (I mod 251);
   end loop;

   --  Set_OCSP_Staple bounds.
   declare
      OK  : Boolean;
      Big : constant Byte_Seq (0 .. N32 (Max_OCSP_Response)) := (others => 16#AA#);
   begin
      Set_OCSP_Staple (Id, Big, OK);
      Check ("oversized staple is refused", not OK and then Id.OCSP_Staple_Len = 0);
      Set_OCSP_Staple (Id, Fake, OK);
      Check ("staple attaches", OK and then Id.OCSP_Staple_Len = Fake_Len);
   end;

   --  Without a staple nothing is added even when asked.
   declare
      Saved : constant Byte_Seq := Id.OCSP_Staple (0 .. Fake_Len - 1);
      OK    : Boolean;
   begin
      Set_OCSP_Staple (Id, Byte_Seq'(1 .. 0 => 0), OK);
      Check ("staple clears", OK and then Id.OCSP_Staple_Len = 0);
      Check_TLS13 (Staple => True, Label => "asked, no staple configured");
      Set_OCSP_Staple (Id, Saved, OK);
   end;

   Check_TLS13 (Staple => False, Label => "not asked");
   Check_TLS13 (Staple => True, Label => "asked");

   --  TLS 1.2 CertificateStatus layout.
   declare
      Buf : Byte_Seq (0 .. SPARKTLS.Handshake.TLS12.Max_Certificate_Status_12 - 1);
      Len : N32;
   begin
      SPARKTLS.Handshake.TLS12.Build_Certificate_Status_12 (Id, Buf, Len);
      Check ("TLS 1.2 CertificateStatus length", Len = 8 + Fake_Len);
      Check ("TLS 1.2 CertificateStatus type 0x16", Buf (0) = 16#16#);
      Check ("TLS 1.2 CertificateStatus body length",
             N32 (Buf (1)) * 65536 + N32 (Buf (2)) * 256 + N32 (Buf (3)) = 4 + Fake_Len);
      Check ("TLS 1.2 CertificateStatus status_type ocsp", Buf (4) = 1);
      Check ("TLS 1.2 CertificateStatus response length",
             N32 (Buf (5)) * 65536 + N32 (Buf (6)) * 256 + N32 (Buf (7)) = Fake_Len);
      Check ("TLS 1.2 CertificateStatus response bytes",
             Buf (8 .. 7 + Fake_Len) = Fake);
   end;

   New_Line;
   Put_Line ("Pass:" & Pass'Image & " /" & Total'Image);
   if Fail = 0 then
      Put_Line ("PASS");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Success);
   else
      Put_Line ("FAIL");
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_OCSP_Staple;
