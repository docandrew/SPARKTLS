--  tls_revocation_check - revocation checking with SPARKTLS, end to end.
--
--  Connects to a TLS server, validates its certificate chain against a
--  CA file, applies the revocation policy, and reports what evidence
--  the verdict rested on. No HTTP: the program stops once the handshake
--  has either completed or failed.
--
--  Usage:
--    tls_revocation_check HOST[:PORT] --cafile CA.pem
--                         [--policy soft|hard|off]
--                         [--crl FILE.der ...]
--                         [--no-staple-request]
--
--  What the library does for you:
--    * asks the server for a stapled OCSP response (status_request) and
--      verifies one that arrives: responder signature, CertID match
--      against the leaf and issuer, freshness window;
--    * checks the leaf (and every intermediate) against the CRLs you
--      attach, honouring issuer / key identifier / distribution-point
--      scoping (RFC 5280 6.3.3);
--    * enforces RFC 7633 must-staple.
--
--  What it does not do: fetch anything. OCSP evidence comes stapled from
--  the server; CRLs come from you. Download them however you like and
--  hand the DER bytes to Add_CRL before configuring the session.
--
--  Policies (SPARKTLS.Revocation_Policy):
--    soft  revoked => fail; no usable evidence => proceed (default)
--    hard  revoked => fail; no usable evidence => fail
--    off   no revocation processing at all
--
--  Exit status: 0 handshake accepted, 1 rejected, 2 usage / I/O error.

with Ada.Calendar;
with Ada.Calendar.Formatting;
with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Streams;             use Ada.Streams;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;             use Ada.Text_IO;
with GNAT.Sockets;
with Interfaces;              use Interfaces;
with SPARKNaCl;               use SPARKNaCl;
with SPARKTLS;                use SPARKTLS;
with SPARKTLS.Client;
with SPARKTLS.Credentials;
with SPARKTLS.Revocation;
with Entropy_Random;
with X509;
with X509.OCSP;

procedure TLS_Revocation_Check is

   ---------------------------------------------------------------------------
   --  Wall clock in UTC, the form the library wants for validity and
   --  freshness windows.
   ---------------------------------------------------------------------------
   function Current_Time return X509.Date_Time is
      use Ada.Calendar;
      Y  : Year_Number;
      Mo : Month_Number;
      D  : Day_Number;
      Hr : Formatting.Hour_Number;
      Mn : Formatting.Minute_Number;
      Sc : Formatting.Second_Number;
      SS : Formatting.Second_Duration;
   begin
      Formatting.Split (Clock, Y, Mo, D, Hr, Mn, Sc, SS, Time_Zone => 0);
      return (Year => Y, Month => Mo, Day => D,
              Hour => Hr, Minute => Mn, Second => Sc);
   end Current_Time;

   ---------------------------------------------------------------------------
   --  A file as a heap-allocated byte sequence. The CRL store keeps a
   --  pointer to the bytes for its lifetime, so they must outlive the
   --  session; heap allocation is the simplest way to guarantee that.
   ---------------------------------------------------------------------------
   function Read_File_Bytes (Path : String) return SPARKTLS.CRL_Bytes_Access is
      package SIO renames Ada.Streams.Stream_IO;
      File : SIO.File_Type;
   begin
      SIO.Open (File, SIO.In_File, Path);
      declare
         Size : constant Natural := Natural (SIO.Size (File));
         Raw  : Stream_Element_Array (1 .. Stream_Element_Offset (Size));
         Last : Stream_Element_Offset;
         B    : X509.Byte_Seq (0 .. X509.N32 (Size) - 1);
      begin
         SIO.Read (File, Raw, Last);
         SIO.Close (File);
         for I in B'Range loop
            B (I) := X509.Byte (Raw (Stream_Element_Offset (I) + 1));
         end loop;
         return new X509.Byte_Seq'(B);
      end;
   end Read_File_Bytes;

   ---------------------------------------------------------------------------
   --  Staple observer: called once per handshake when the server staples
   --  an OCSP response, before the library rules on it. This is an audit
   --  hook only (log what arrived); the verdict is the library's. Here we
   --  parse the response again purely to print a summary.
   ---------------------------------------------------------------------------
   Staple_Seen : Boolean := False;

   function Image (T : X509.Date_Time) return String is
      function Two (N : Natural) return String is
         S : constant String := Natural'Image (N + 100);
      begin
         return S (S'Last - 1 .. S'Last);
      end Two;
   begin
      return Natural'Image (T.Year) (2 .. 5) & "-" & Two (T.Month) & "-"
        & Two (T.Day) & " " & Two (T.Hour) & ":" & Two (T.Minute) & "Z";
   end Image;

   procedure Observe_Staple (Response : X509.Byte_Seq; Too_Big : Boolean) is
      V  : X509.OCSP.OCSP_View;
      OK : Boolean;
   begin
      Staple_Seen := True;
      if Too_Big then
         Put_Line ("staple: present but over Max_OCSP_Response; treated as absent");
         return;
      end if;
      Put_Line ("staple: " & Response'Length'Image & " bytes of OCSPResponse");
      X509.OCSP.Parse (Response, V, OK);
      if not OK then
         Put_Line ("staple: does not parse (the library will reject it)");
         return;
      end if;
      Put_Line ("staple: responseStatus = "
                & X509.OCSP.Response_Status'Image (X509.OCSP.Status (V)));
      if X509.OCSP.Response_Count (V) >= 1 then
         declare
            R : constant X509.OCSP.Single_Response := X509.OCSP.Get_Response (V, 1);
         begin
            Put_Line ("staple: certStatus = "
                      & X509.OCSP.Cert_Status'Image (R.Status)
                      & ", thisUpdate " & Image (R.This_Update)
                      & (if R.Has_Next_Update
                         then ", nextUpdate " & Image (R.Next_Update)
                         else ", no nextUpdate")
                      & ", CertID hash "
                      & X509.OCSP.Hash_Algorithm'Image (R.Hash_Algo));
         end;
      end if;
   end Observe_Staple;

   ---------------------------------------------------------------------------
   --  Command line
   ---------------------------------------------------------------------------
   procedure Usage is
   begin
      Put_Line (Standard_Error,
        "usage: tls_revocation_check HOST[:PORT] --cafile CA.pem"
        & " [--policy soft|hard|off] [--crl FILE.der ...] [--no-staple-request]");
   end Usage;

   Host        : String (1 .. 255) := (others => ' ');
   Host_Len    : Natural := 0;
   Port        : GNAT.Sockets.Port_Type := 443;
   CA_Arg      : Natural := 0;
   Policy      : SPARKTLS.Revocation_Policy := SPARKTLS.Soft_Fail;
   Ask_Staple  : Boolean := True;
   CRL_Store   : aliased SPARKTLS.CRL_Store;
   CRL_Count   : Natural := 0;

   --  Session state
   Roots    : aliased SPARKTLS.Trust_Store;
   Roots_OK : Boolean;
   S        : SPARKTLS.Client_Session;
   Res      : SPARKTLS.Action;
   Net_Buf  : Byte_Seq (0 .. 16383);
   N        : N32;
   Sock     : GNAT.Sockets.Socket_Type;
   Channel  : GNAT.Sockets.Stream_Access;

   --  Read one TLS record from the socket and feed it to the session.
   procedure Read_Record (Closed : out Boolean) is
   begin
      Closed := False;
      Byte_Seq'Read (Channel, Net_Buf (0 .. 4));
      declare
         Rec_Len : constant N32 := N32 (Net_Buf (3)) * 256 + N32 (Net_Buf (4));
      begin
         if Rec_Len > 0 and Rec_Len <= 16640 then
            Byte_Seq'Read (Channel, Net_Buf (5 .. 4 + Rec_Len));
            N := 5 + Rec_Len;
            SPARKTLS.Feed_Ciphertext (S, Net_Buf (0 .. N - 1), N);
         else
            Closed := True;
         end if;
      end;
   exception
      when others =>
         Closed := True;
   end Read_Record;

   procedure Rejected (Why : String) is
   begin
      Put_Line ("REJECTED: " & Why);
      GNAT.Sockets.Close_Socket (Sock);
      Ada.Command_Line.Set_Exit_Status (1);
   end Rejected;

begin
   --  Parse arguments. --crl may repeat; each file is attached in order,
   --  which matters only for reporting (the store is searched by scope,
   --  not by position).
   declare
      I : Positive := 1;
      Argc : constant Natural := Ada.Command_Line.Argument_Count;
   begin
      while I <= Argc loop
         declare
            Arg : constant String := Ada.Command_Line.Argument (I);
         begin
            if Arg = "--cafile" and then I < Argc then
               CA_Arg := I + 1;
               I := I + 1;
            elsif Arg = "--policy" and then I < Argc then
               declare
                  P : constant String := Ada.Command_Line.Argument (I + 1);
               begin
                  if P = "soft" then
                     Policy := SPARKTLS.Soft_Fail;
                  elsif P = "hard" then
                     Policy := SPARKTLS.Hard_Fail;
                  elsif P = "off" then
                     Policy := SPARKTLS.Ignore;
                  else
                     Usage;
                     Ada.Command_Line.Set_Exit_Status (2);
                     return;
                  end if;
               end;
               I := I + 1;
            elsif Arg = "--crl" and then I < Argc then
               declare
                  OK : Boolean;
               begin
                  SPARKTLS.Revocation.Add_CRL
                    (CRL_Store, Read_File_Bytes (Ada.Command_Line.Argument (I + 1)), OK);
                  if OK then
                     CRL_Count := CRL_Count + 1;
                     Put_Line ("crl: attached " & Ada.Command_Line.Argument (I + 1));
                  else
                     --  Unparseable, unsupported (delta / indirect) or
                     --  the store is full: say so and carry on. Under
                     --  hard policy the missing evidence will fail the
                     --  handshake, which is the right outcome.
                     Put_Line ("crl: REJECTED " & Ada.Command_Line.Argument (I + 1));
                  end if;
               end;
               I := I + 1;
            elsif Arg = "--no-staple-request" then
               Ask_Staple := False;
            elsif Arg'Length > 0 and then Arg (Arg'First) /= '-' and then Host_Len = 0 then
               --  HOST[:PORT]
               declare
                  Colon : Natural := 0;
               begin
                  for K in Arg'Range loop
                     if Arg (K) = ':' then
                        Colon := K;
                     end if;
                  end loop;
                  if Colon = 0 then
                     Host_Len := Arg'Length;
                     Host (1 .. Host_Len) := Arg;
                  else
                     Host_Len := Colon - Arg'First;
                     Host (1 .. Host_Len) := Arg (Arg'First .. Colon - 1);
                     Port := GNAT.Sockets.Port_Type'Value (Arg (Colon + 1 .. Arg'Last));
                  end if;
               end;
            else
               Usage;
               Ada.Command_Line.Set_Exit_Status (2);
               return;
            end if;
         end;
         I := I + 1;
      end loop;
   end;

   if Host_Len = 0 or CA_Arg = 0 then
      Usage;
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;

   --  Trust anchors. Chain validation is a prerequisite: revocation is
   --  only ever evaluated on a chain that already validated.
   SPARKTLS.Credentials.Load_Trust_Store
     (Roots, Ada.Command_Line.Argument (CA_Arg), Roots_OK);
   if not Roots_OK then
      Put_Line (Standard_Error, "error: cannot load " & Ada.Command_Line.Argument (CA_Arg));
      Ada.Command_Line.Set_Exit_Status (2);
      return;
   end if;

   --  TCP connect
   declare
      Hostname : constant String := Host (1 .. Host_Len);
      Entry_T  : constant GNAT.Sockets.Host_Entry_Type :=
        GNAT.Sockets.Get_Host_By_Name (Hostname);
      Addr     : constant GNAT.Sockets.Sock_Addr_Type :=
        (Family => GNAT.Sockets.Family_Inet,
         Addr   => GNAT.Sockets.Addresses (Entry_T, 1),
         Port   => Port);
   begin
      GNAT.Sockets.Create_Socket (Sock);
      GNAT.Sockets.Set_Socket_Option
        (Sock, GNAT.Sockets.Socket_Level,
         (Name => GNAT.Sockets.Receive_Timeout, Timeout => 10.0));
      GNAT.Sockets.Connect_Socket (Sock, Addr);
      Channel := GNAT.Sockets.Stream (Sock);

      --  The session. Everything revocation-related is in the Config:
      --    Revocation           the policy
      --    Request_OCSP_Staple  ask the server to staple (needed for
      --                         OCSP evidence and for must-staple)
      --    CRLs                 the store built above, or null
      --    Observe_Staple       optional audit hook
      --  Allow_SHA1_CertID and Revocation_Skew_Seconds keep their
      --  defaults (True; 300 s).
      S := SPARKTLS.Client.Configure
        ((Server_Name         => SPARKTLS.To_Name (Hostname),
          Trust               => Roots'Unchecked_Access,
          Random              => Entropy_Random.Random'Access,
          Get_Time            => Current_Time'Unrestricted_Access,
          Revocation          => Policy,
          Request_OCSP_Staple => Ask_Staple,
          CRLs                => (if CRL_Count > 0
                                  then CRL_Store'Unchecked_Access
                                  else null),
          Observe_Staple      => Observe_Staple'Unrestricted_Access,
          others              => <>));
   end;

   Put_Line ("policy: " & SPARKTLS.Revocation_Policy'Image (Policy)
             & ", staple requested: " & Boolean'Image (Ask_Staple)
             & ", CRLs attached:" & Natural'Image (CRL_Count));

   --  Drive the handshake. The revocation verdict is delivered like any
   --  other certificate failure: Advance reaches Error_State (a fatal
   --  alert is queued for the server) and Last_Error names the cause:
   --    Certificate_Revoked        alert 44  evidence says revoked
   --    Bad_Certificate (42)                 no usable evidence under
   --                                         hard policy, or must-staple
   --                                         without a staple
   --    Bad_Certificate_Status_Response (113) the stapled response itself
   --                                         is unacceptable
   loop
      SPARKTLS.Client.Advance (S, Res);
      case Res is
         when SPARKTLS.OK =>
            null;   --  progress made; call Advance again

         when SPARKTLS.Has_Output =>
            SPARKTLS.Drain_Ciphertext (S, Net_Buf, N);
            if N > 0 then
               Byte_Seq'Write (Channel, Net_Buf (0 .. N - 1));
            end if;
            if SPARKTLS.State (S) = SPARKTLS.Error_State then
               Rejected (SPARKTLS.Describe (SPARKTLS.Last_Error (S)));
               return;
            end if;

         when SPARKTLS.Need_Input =>
            declare
               Closed : Boolean;
            begin
               Read_Record (Closed);
               if Closed then
                  Rejected ("connection closed during handshake");
                  return;
               end if;
            end;

         when SPARKTLS.Handshake_Done =>
            exit;

         when SPARKTLS.Plaintext_Ready =>
            SPARKTLS.Read_Plaintext (S, Net_Buf, N);

         when SPARKTLS.Error_Alert =>
            Rejected (SPARKTLS.Describe (SPARKTLS.Last_Error (S)));
            return;

         when SPARKTLS.Shutdown =>
            Rejected ("server closed the connection during handshake");
            return;
      end case;
   end loop;

   --  Accepted. Be precise about what that means: under hard policy the
   --  library verified revocation evidence (a stapled response or a CRL
   --  covering the chain); under soft policy it only established that
   --  nothing usable said "revoked", and unusable or missing evidence was
   --  tolerated. The observer tells us whether a staple arrived at all.
   Put ("ACCEPTED: chain valid; ");
   case Policy is
      when SPARKTLS.Ignore =>
         Put_Line ("revocation not evaluated (policy off)");
      when SPARKTLS.Hard_Fail =>
         Put_Line ("revocation evidence verified ("
                   & (if Staple_Seen then "stapled OCSP" else "CRL") & ")");
      when SPARKTLS.Soft_Fail =>
         Put_Line ("not shown revoked; evidence available: "
                   & (if Staple_Seen then "stapled OCSP" else "no staple")
                   & (if CRL_Count > 0 then ", CRLs" else ", no CRLs")
                   & " (soft policy tolerates missing or unusable evidence;"
                   & " use --policy hard for assurance)");
   end case;
   GNAT.Sockets.Close_Socket (Sock);

exception
   when E : others =>
      Put_Line (Standard_Error, "error: " & Ada.Exceptions.Exception_Message (E));
      Ada.Command_Line.Set_Exit_Status (2);
end TLS_Revocation_Check;
