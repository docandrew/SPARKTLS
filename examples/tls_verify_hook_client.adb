--  Reference implementation: application certificate policy on top of the
--  proven core (Config.Verify_Peer) and client credential selection
--  (Config.Select_Client_Identity).
--
--  The core validates the server's chain first: path to a trust anchor,
--  RFC 5280, RFC 6125 hostname binding, EKU. Only if that PASSES is the
--  hook below consulted, and it can only veto. Three policies are shown:
--    --pin-sha256 HEX    certificate pinning: SHA-256 of the leaf DER must
--                        equal HEX (64 hex digits, as printed by
--                        `openssl x509 -outform DER | sha256sum`).
--    --require-san NAME  the leaf must carry NAME as a SAN dNSName.
--    --audit             print what the peer presented (CN, SANs, chain
--                        depth) -- the out-of-band revocation check an
--                        application would run (OCSP/CRL) goes here.
--  Credential selection: with --cert-file/--key-file (default identity)
--  and --alt-cert-file/--alt-key-file (alternate), the selector returns
--  the alternate when the server's certificate_authorities list names its
--  issuer, the default otherwise. A production picker compares each local
--  certificate's issuer DistinguishedName byte-for-byte with each element
--  of the list; this example searches for the issuer CN bytes inside the
--  list, which is enough to demonstrate the mechanism.
--
--  Usage:
--    tls_verify_hook_client --port N [--host HOSTNAME] --trust-cert FILE
--        [--pin-sha256 HEX] [--require-san NAME] [--audit]
--        [--cert-file FILE --key-file FILE]
--        [--alt-cert-file FILE --alt-key-file FILE]
--        [--message STR] [--expect-echo] [--expect-fail]
--        [--skip-hostname-verify]
--
--  Exit 0 on success, 1 on failure; --expect-fail inverts the exit code.

with Ada.Characters.Handling;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams;                use Ada.Streams;
with Ada.Text_IO;                use Ada.Text_IO;
with Ada.Calendar;
with Ada.Calendar.Formatting;
with Interfaces;                 use Interfaces;

with SPARKNaCl;                  use SPARKNaCl;
with SPARKTLSCrypto.Hashing.SHA256;

with SPARKTLS;                   use SPARKTLS;
with SPARKTLS.Client;
with SPARKTLS.Credentials;
with Entropy_Random;
with X509;

with GNAT.Sockets;               use GNAT.Sockets;

procedure TLS_Verify_Hook_Client is

   Exit_Success : constant := 0;
   Exit_Failure : constant := 1;

   subtype Path_Buf is String (1 .. 1024);
   Empty_Path : constant Path_Buf := (others => Character'Val (0));

   Cfg_Port        : Natural := 0;
   Cfg_Host        : String (1 .. 256) := (others => Character'Val (0));
   Cfg_Host_Len    : Natural := 0;
   Cfg_Cert        : Path_Buf := Empty_Path;
   Cfg_Key         : Path_Buf := Empty_Path;
   Cfg_Alt_Cert    : Path_Buf := Empty_Path;
   Cfg_Alt_Key     : Path_Buf := Empty_Path;
   Cfg_Trust       : Path_Buf := Empty_Path;
   Cfg_Pin         : String (1 .. 64) := (others => ' ');
   Have_Pin        : Boolean := False;
   Cfg_SAN         : String (1 .. 256) := (others => Character'Val (0));
   Cfg_SAN_Len     : Natural := 0;
   Cfg_Audit       : Boolean := False;
   Cfg_Message     : String (1 .. 4096) := (others => Character'Val (0));
   Cfg_Msg_Len     : Natural := 5;
   Cfg_Expect_Echo : Boolean := False;
   Cfg_Expect_Fail : Boolean := False;
   Cfg_Skip_Hostname_Verify : Boolean := False;

   procedure Err (M : String) is
   begin
      Put_Line (Standard_Error, "tls_verify_hook_client: " & M);
   end Err;

   function Trim (S : String) return String is
      Last : Natural := S'First - 1;
   begin
      for I in S'Range loop
         exit when S (I) = Character'Val (0);
         Last := I;
      end loop;
      return S (S'First .. Last);
   end Trim;

   procedure Set_Path (Dst : in out Path_Buf; Src : String) is
   begin
      Dst := Empty_Path;
      Dst (1 .. Src'Length) := Src;
   end Set_Path;

   procedure Parse_Args is
      I : Natural := 1;
      use Ada.Command_Line;

      function Next_Arg return String is
      begin
         I := I + 1;
         if I > Argument_Count then
            Err ("missing value after " & Argument (I - 1));
            Ada.Command_Line.Set_Exit_Status
              (Ada.Command_Line.Exit_Status (Exit_Failure));
            raise Program_Error;
         end if;
         return Argument (I);
      end Next_Arg;
   begin
      Cfg_Message (1 .. 5) := "hello";
      Cfg_Msg_Len := 5;
      Cfg_Host (1 .. 9) := "localhost";
      Cfg_Host_Len := 9;

      while I <= Argument_Count loop
         declare
            A : constant String := Argument (I);
         begin
            if A = "--port" then
               Cfg_Port := Natural'Value (Next_Arg);
            elsif A = "--host" then
               declare
                  V : constant String := Next_Arg;
               begin
                  Cfg_Host := (others => Character'Val (0));
                  Cfg_Host (1 .. V'Length) := V;
                  Cfg_Host_Len := V'Length;
               end;
            elsif A = "--cert-file" then
               Set_Path (Cfg_Cert, Next_Arg);
            elsif A = "--key-file" then
               Set_Path (Cfg_Key, Next_Arg);
            elsif A = "--alt-cert-file" then
               Set_Path (Cfg_Alt_Cert, Next_Arg);
            elsif A = "--alt-key-file" then
               Set_Path (Cfg_Alt_Key, Next_Arg);
            elsif A = "--trust-cert" then
               Set_Path (Cfg_Trust, Next_Arg);
            elsif A = "--pin-sha256" then
               declare
                  V : constant String :=
                    Ada.Characters.Handling.To_Lower (Next_Arg);
               begin
                  if V'Length /= 64 then
                     Err ("--pin-sha256 wants 64 hex digits");
                     raise Program_Error;
                  end if;
                  Cfg_Pin := V;
                  Have_Pin := True;
               end;
            elsif A = "--require-san" then
               declare
                  V : constant String :=
                    Ada.Characters.Handling.To_Lower (Next_Arg);
               begin
                  Cfg_SAN := (others => Character'Val (0));
                  Cfg_SAN (1 .. V'Length) := V;
                  Cfg_SAN_Len := V'Length;
               end;
            elsif A = "--audit" then
               Cfg_Audit := True;
            elsif A = "--message" then
               declare
                  V : constant String := Next_Arg;
               begin
                  Cfg_Message := (others => Character'Val (0));
                  Cfg_Message (1 .. V'Length) := V;
                  Cfg_Msg_Len := V'Length;
               end;
            elsif A = "--expect-echo" then
               Cfg_Expect_Echo := True;
            elsif A = "--expect-fail" then
               Cfg_Expect_Fail := True;
            elsif A = "--skip-hostname-verify" then
               Cfg_Skip_Hostname_Verify := True;
            else
               Err ("unknown arg: " & A);
               Ada.Command_Line.Set_Exit_Status
                 (Ada.Command_Line.Exit_Status (Exit_Failure));
               raise Program_Error;
            end if;
         end;
         I := I + 1;
      end loop;
   end Parse_Args;

   --  UTC clock for certificate validity (see mtls_test_client).
   function Current_Time return X509.Date_Time is
      use Ada.Calendar;
      Now : constant Time := Clock;
      Y   : Year_Number;
      Mo  : Month_Number;
      D   : Day_Number;
      Hr  : Ada.Calendar.Formatting.Hour_Number;
      Mn  : Ada.Calendar.Formatting.Minute_Number;
      Sc  : Ada.Calendar.Formatting.Second_Number;
      SS  : Ada.Calendar.Formatting.Second_Duration;
   begin
      Ada.Calendar.Formatting.Split
        (Now, Y, Mo, D, Hr, Mn, Sc, SS, Time_Zone => 0);
      return (Year   => Y, Month => Mo, Day => D,
              Hour   => Hr, Minute => Mn, Second => Sc);
   end Current_Time;

   ---------------------------------------------------------------------------
   --  Helpers over X509 spans (byte ranges into a certificate's DER)
   ---------------------------------------------------------------------------

   function Span_Text (DER : X509.Byte_Seq; Sp : X509.Span) return String is
      use type X509.N32;
   begin
      if not Sp.Present or else Sp.Last < Sp.First or else Sp.Last > DER'Last
      then
         return "";
      end if;
      declare
         R : String (1 .. Natural (Sp.Last - Sp.First + 1));
      begin
         for I in Sp.First .. Sp.Last loop
            R (Natural (I - Sp.First) + 1) := Character'Val (DER (I));
         end loop;
         return R;
      end;
   end Span_Text;

   function Hex (Digest : Byte_Seq) return String is
      Digits_16 : constant String := "0123456789abcdef";
      R         : String (1 .. 2 * Digest'Length);
      P         : Positive := 1;
   begin
      for B of Digest loop
         R (P)     := Digits_16 (Natural (B) / 16 + 1);
         R (P + 1) := Digits_16 (Natural (B) mod 16 + 1);
         P := P + 2;
      end loop;
      return R;
   end Hex;

   --  SHA-256 over the leaf DER, as `openssl x509 -outform DER | sha256sum`.
   function Leaf_Fingerprint (Leaf_DER : X509.Byte_Seq) return String is
      use type X509.N32;
      M : Byte_Seq (0 .. N32 (Leaf_DER'Length) - 1);
   begin
      for I in Leaf_DER'Range loop
         M (N32 (I - Leaf_DER'First)) := Leaf_DER (I);
      end loop;
      return Hex (Byte_Seq (SPARKTLSCrypto.Hashing.SHA256.Hash (M)));
   end Leaf_Fingerprint;

   ---------------------------------------------------------------------------
   --  The veto hook. Runs only after the core accepted the chain.
   ---------------------------------------------------------------------------

   function Verify_Peer
     (Leaf_DER  : X509.Byte_Seq;
      Leaf      : X509.Certificate;
      Ints       : SPARKTLS.Cert_Pool;
      Int_Count  : Natural;
      Anchor_DER : X509.Byte_Seq;
      Anchor     : X509.Certificate;
      Hostname   : String;
      Purpose    : SPARKTLS.Validation_Purpose) return Boolean
   is
      pragma Unreferenced (Ints);
      Accepted : Boolean := True;
   begin
      if Cfg_Audit then
         Put_Line ("AUDIT peer: purpose=" & Purpose'Image
                   & " hostname='" & Hostname & "'"
                   & " intermediates=" & Int_Count'Image
                   & " leaf_der_bytes=" & Leaf_DER'Length'Image);
         --  The trust anchor the core chained to: pin it here for CA pinning.
         if X509.Has_Subject_CN (Anchor) then
            Put_Line ("AUDIT anchor CN="
                      & Span_Text (Anchor_DER, X509.Subject_CN (Anchor)));
         end if;
         Put_Line ("AUDIT leaf sha256=" & Leaf_Fingerprint (Leaf_DER));
         if X509.Has_Subject_CN (Leaf) then
            Put_Line ("AUDIT subject CN="
                      & Span_Text (Leaf_DER, X509.Subject_CN (Leaf)));
         end if;
         for I in 1 .. X509.SAN_Count (Leaf) loop
            Put_Line ("AUDIT SAN dNSName="
                      & Span_Text (Leaf_DER, X509.SAN_DNS (Leaf, I)));
         end loop;
         --  An application that checks revocation out of band (OCSP, CRL)
         --  would do it here and return False on a revoked leaf.
      end if;

      if Have_Pin then
         declare
            Got : constant String := Leaf_Fingerprint (Leaf_DER);
         begin
            if Got /= Cfg_Pin then
               Err ("VETO: pin mismatch, leaf sha256=" & Got);
               Accepted := False;
            end if;
         end;
      end if;

      if Cfg_SAN_Len > 0 then
         declare
            Want  : constant String := Cfg_SAN (1 .. Cfg_SAN_Len);
            Found : Boolean := False;
         begin
            for I in 1 .. X509.SAN_Count (Leaf) loop
               if Ada.Characters.Handling.To_Lower
                    (Span_Text (Leaf_DER, X509.SAN_DNS (Leaf, I))) = Want
               then
                  Found := True;
               end if;
            end loop;
            if not Found then
               Err ("VETO: leaf has no SAN dNSName '" & Want & "'");
               Accepted := False;
            end if;
         end;
      end if;

      return Accepted;
   end Verify_Peer;

   ---------------------------------------------------------------------------
   --  Credential selection
   ---------------------------------------------------------------------------

   Id         : aliased SPARKTLS.Identity;
   Alt_Id     : aliased SPARKTLS.Identity;
   Have_Local : Boolean := False;
   Have_Alt   : Boolean := False;

   --  True when the issuer CN of Ident's certificate occurs inside the
   --  certificate_authorities list bytes the server sent.
   function Issuer_Named (Ident : SPARKTLS.Identity; CA_Names : Byte_Seq)
     return Boolean
   is
      use type X509.N32;
   begin
      if not Ident.Cert_Valid or else not X509.Has_Issuer_CN (Ident.Cert) then
         return False;
      end if;
      declare
         Sp  : constant X509.Span := X509.Issuer_CN (Ident.Cert);
         Len : constant N32 := N32 (Sp.Last - Sp.First + 1);
      begin
         if not Sp.Present or else Len = 0 or else Len > CA_Names'Length then
            return False;
         end if;
         for Start in CA_Names'First .. CA_Names'Last - Len + 1 loop
            declare
               Match : Boolean := True;
            begin
               for K in 0 .. Len - 1 loop
                  if CA_Names (Start + K)
                     /= Ident.Cert_DER (Sp.First + X509.N32 (K))
                  then
                     Match := False;
                     exit;
                  end if;
               end loop;
               if Match then
                  return True;
               end if;
            end;
         end loop;
         return False;
      end;
   end Issuer_Named;

   function Pick_Identity (CA_Names : Byte_Seq; Sig_Algos : Byte_Seq)
     return SPARKTLS.Maybe_Identity_Access is
   begin
      if Cfg_Audit then
         Put_Line ("AUDIT CertificateRequest: certificate_authorities_bytes="
                   & CA_Names'Length'Image
                   & " signature_schemes=" & Natural'Image (Sig_Algos'Length / 2));
      end if;
      if Have_Alt and then Issuer_Named (Alt_Id, CA_Names) then
         if Cfg_Audit then
            Put_Line ("AUDIT selected alternate identity (issuer named by server)");
         end if;
         return Alt_Id'Unchecked_Access;
      end if;
      if Have_Local then
         if Cfg_Audit then
            Put_Line ("AUDIT selected default identity");
         end if;
         return Id'Unchecked_Access;
      end if;
      --  No usable credential: decline (empty Certificate, RFC 8446 4.4.2).
      return null;
   end Pick_Identity;

   ---------------------------------------------------------------------------

   S       : SPARKTLS.Client_Session;
   Res     : SPARKTLS.Action;
   Sock    : Socket_Type;

   Net_Out : Byte_Seq (0 .. 16383);
   Net_In  : Byte_Seq (0 .. 16383);
   App_Buf : Byte_Seq (0 .. 4095);

   Roots    : aliased SPARKTLS.Trust_Store;
   Roots_OK : Boolean;
   Id_OK    : Boolean;
   Have_Trust : Boolean := False;

   App_Sent     : Boolean := False;
   App_Received : Boolean := False;
   Run_Failed   : Boolean := False;

   procedure Send_Pending is
      N    : N32;
      Last : Stream_Element_Offset;
   begin
      loop
         Drain_Ciphertext (S, Net_Out, N);
         exit when N = 0;
         declare
            SE : Stream_Element_Array (1 .. Stream_Element_Offset (N));
         begin
            for K in 0 .. N - 1 loop
               SE (Stream_Element_Offset (K + 1)) :=
                  Stream_Element (Net_Out (K));
            end loop;
            GNAT.Sockets.Send_Socket (Sock, SE, Last);
         end;
      end loop;
   end Send_Pending;

   procedure Recv_Once (Done : out Boolean) is
      SE   : Stream_Element_Array (1 .. 16384);
      Last : Stream_Element_Offset;
      Fed  : N32;
   begin
      Done := False;
      begin
         GNAT.Sockets.Receive_Socket (Sock, SE, Last);
      exception
         when others =>
            Done := True;
            return;
      end;
      if Last < SE'First then
         Done := True;
         return;
      end if;
      declare
         Avail : constant N32 := N32 (Last - SE'First + 1);
      begin
         for K in 0 .. Avail - 1 loop
            Net_In (K) := Byte (SE (SE'First + Stream_Element_Offset (K)));
         end loop;
         Feed_Ciphertext (S, Net_In (0 .. Avail - 1), Fed);
      end;
   end Recv_Once;

begin
   Entropy_Random.Init;
   Parse_Args;

   if Cfg_Port = 0 then
      Err ("--port required");
      Ada.Command_Line.Set_Exit_Status
        (Ada.Command_Line.Exit_Status (Exit_Failure));
      return;
   end if;

   Initialize;
   Create_Socket (Sock);
   Set_Socket_Option (Sock, Socket_Level,
      (Name => Receive_Timeout, Timeout => 5.0));
   begin
      Connect_Socket
        (Sock,
         (Family => Family_Inet,
          Addr   => Inet_Addr ("127.0.0.1"),
          Port   => Port_Type (Cfg_Port)));
   exception
      when E : others =>
         Err ("connect failed: " & Ada.Exceptions.Exception_Message (E));
         Ada.Command_Line.Set_Exit_Status
           (Ada.Command_Line.Exit_Status (Exit_Failure));
         return;
   end;

   --  Load credentials. The trust store is what makes the core's chain
   --  validation run; without it the handshake fails closed before the
   --  hook is ever consulted (the hook cannot admit an untrusted chain).
   declare
      Cert     : constant String := Trim (Cfg_Cert);
      Key      : constant String := Trim (Cfg_Key);
      Alt_Cert : constant String := Trim (Cfg_Alt_Cert);
      Alt_Key  : constant String := Trim (Cfg_Alt_Key);
      Trust    : constant String := Trim (Cfg_Trust);
   begin
      if Trust /= "" then
         SPARKTLS.Credentials.Load_Trust_Store (Roots, Trust, Roots_OK);
         if not Roots_OK then
            Err ("load trust failed: " & Trust);
            Ada.Command_Line.Set_Exit_Status
              (Ada.Command_Line.Exit_Status (Exit_Failure));
            return;
         end if;
         Have_Trust := True;
      end if;
      if Cert /= "" and Key /= "" then
         SPARKTLS.Credentials.Load_Identity (Id, Cert, Key, Id_OK);
         if not Id_OK then
            Err ("load identity failed: " & Cert);
            Ada.Command_Line.Set_Exit_Status
              (Ada.Command_Line.Exit_Status (Exit_Failure));
            return;
         end if;
         Have_Local := True;
      end if;
      if Alt_Cert /= "" and Alt_Key /= "" then
         SPARKTLS.Credentials.Load_Identity (Alt_Id, Alt_Cert, Alt_Key, Id_OK);
         if not Id_OK then
            Err ("load alternate identity failed: " & Alt_Cert);
            Ada.Command_Line.Set_Exit_Status
              (Ada.Command_Line.Exit_Status (Exit_Failure));
            return;
         end if;
         Have_Alt := True;
      end if;
   end;

   --  Mode_RFC5280: the test anchors are self-signed leaf certificates,
   --  which WebPKI mode rejects on purpose. Skip_Verify stays False: the
   --  hook is only meaningful on top of a verified chain.
   S := SPARKTLS.Client.Configure
     ((Server_Name            => SPARKTLS.To_Name (Cfg_Host (1 .. Cfg_Host_Len)),
       Trust                  =>
          (if Have_Trust then Roots'Unchecked_Access else null),
       Random                 => Entropy_Random.Random'Access,
       Get_Time               => Current_Time'Unrestricted_Access,
       Local                  =>
          (if Have_Local then Id'Unchecked_Access
           else SPARKTLS.No_Identity'Access),
       Verify_Mode            => SPARKTLS.Mode_RFC5280,
       Verify_Peer            => Verify_Peer'Unrestricted_Access,
       Select_Client_Identity =>
          (if Have_Alt then Pick_Identity'Unrestricted_Access else null),
       Skip_Hostname_Verify   => Cfg_Skip_Hostname_Verify,
       others                 => <>));

   Loop1 :
   loop
      SPARKTLS.Client.Advance (S, Res);
      case Res is
         when Has_Output =>
            Send_Pending;
         when Need_Input =>
            declare
               Done : Boolean;
            begin
               Recv_Once (Done);
               if Done then
                  if not App_Sent then
                     Err ("peer closed during handshake");
                     Run_Failed := True;
                  end if;
                  exit Loop1;
               end if;
            end;
         when OK =>
            null;
         when Handshake_Done =>
            declare
               Buf     : Byte_Seq (0 .. N32 (Cfg_Msg_Len) - 1);
               Written : N32;
            begin
               for I in 0 .. Cfg_Msg_Len - 1 loop
                  Buf (N32 (I)) := Byte (Character'Pos (
                     Cfg_Message (Cfg_Message'First + I)));
               end loop;
               SPARKTLS.Write_Plaintext (S, Buf, Written);
               Send_Pending;
               App_Sent := True;
            end;
         when Plaintext_Ready =>
            declare
               N : N32;
            begin
               Read_Plaintext (S, App_Buf, N);
               if N > 0 then
                  App_Received := True;
                  if Cfg_Expect_Echo then
                     Put_Line ("ECHO_RECEIVED bytes=" & N32'Image (N));
                  end if;
                  SPARKTLS.Client.Close_Notify (S);
                  Send_Pending;
               end if;
            end;
         when Error_Alert =>
            Send_Pending;
            Err ("handshake error: state=" & State (S)'Image
                 & " err=" & SPARKTLS.Describe (SPARKTLS.Last_Error (S)));
            Run_Failed := True;
            exit Loop1;
         when Shutdown =>
            exit Loop1;
      end case;
   end loop Loop1;

   declare
      Success : constant Boolean := not Run_Failed
         and then App_Sent
         and then (not Cfg_Expect_Echo or else App_Received);
      Final_OK : constant Boolean :=
         (if Cfg_Expect_Fail then not Success else Success);
   begin
      if Final_OK then
         Put_Line ("OK");
         Ada.Command_Line.Set_Exit_Status
           (Ada.Command_Line.Exit_Status (Exit_Success));
      else
         Err ("FAIL: success=" & Success'Image
              & " expect_fail=" & Cfg_Expect_Fail'Image
              & " app_sent=" & App_Sent'Image
              & " app_received=" & App_Received'Image);
         Ada.Command_Line.Set_Exit_Status
           (Ada.Command_Line.Exit_Status (Exit_Failure));
      end if;
   end;

exception
   when Program_Error =>
      null;
   when E : others =>
      Err (Ada.Exceptions.Exception_Message (E));
      Ada.Command_Line.Set_Exit_Status
        (Ada.Command_Line.Exit_Status (Exit_Failure));
end TLS_Verify_Hook_Client;
