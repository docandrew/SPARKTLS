with Ada.Command_Line;
with Ada.Calendar;
with Ada.Calendar.Formatting;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLS; use SPARKTLS;
with SPARKTLS.Client;
with SPARKTLS.Server;
with SPARKTLS.Credentials;
with Entropy_Random;
with X509;
procedure Test_Fixed_Base_Handshake is
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
      --  Ada.Calendar.Split works in package Calendar's implementation-
      --  defined (local) time zone, RM 9.6. X.509 notBefore/notAfter are
      --  UTC, so a local split shifts every validity comparison by the
      --  host's UTC offset. Formatting.Split with Time_Zone => 0 is UTC.
      Ada.Calendar.Formatting.Split
        (Now, Y, Mo, D, Hr, Mn, Sc, SS, Time_Zone => 0);
      return (Year   => Y, Month => Mo, Day => D,
              Hour   => Hr, Minute => Mn, Second => Sc);
   end Current_Time;
   Id : aliased Identity;
   Roots : aliased Trust_Store;
   Loaded : Boolean;
   Message : constant Byte_Seq := (1, 2, 3, 4, 0, 255, 128, 64);
   procedure Exercise (Group : ECDHE_Group) is
      C : Client_Session;
      S : Server_Session;
      Got_Echo, Got_Request : Boolean := False;
      procedure Transfer (From, To : in out Session) is
         Buf : Byte_Seq (0 .. Buffer_Size'Last - 1);
         N, Fed : N32;
      begin
         Drain_Ciphertext (From, Buf, N);
         if N > 0 then
            Feed_Ciphertext (To, Buf (0 .. N - 1), Fed);
            if Fed /= N then raise Program_Error with "test transport overflow"; end if;
         end if;
      end Transfer;
      procedure Step is
         A : Action;
         Buf : Byte_Seq (0 .. 255);
         N, Written : N32;
      begin
         Client.Advance (C, A);
         if A = Error_Alert or A = Shutdown then
            raise Program_Error with "client: " & Describe (Last_Error (C));
         elsif A = Plaintext_Ready then
            Read_Plaintext (C, Buf, N);
            if N /= Message'Length or else Buf (0 .. N - 1) /= Message then
               raise Program_Error with "wrong encrypted echo";
            end if;
            Got_Echo := True;
         end if;
         Transfer (C, S);
         Server.Advance (S, A);
         if A = Error_Alert or A = Shutdown then
            raise Program_Error with "server: " & Describe (Last_Error (S));
         elsif A = Plaintext_Ready then
            Read_Plaintext (S, Buf, N);
            if N /= Message'Length or else Buf (0 .. N - 1) /= Message then
               raise Program_Error with "wrong encrypted request";
            end if;
            Got_Request := True;
            Write_Plaintext (S, Buf (0 .. N - 1), Written);
            if Written /= N then raise Program_Error with "short echo"; end if;
         end if;
         Transfer (S, C);
      end Step;
      Written : N32;
   begin
      S := Server.Configure ((Local => Id'Unchecked_Access,
                              Versions => TLS_1_3_Only, others => <>));
      C := Client.Configure
        ((Server_Name => To_Name ("localhost"), Trust => Roots'Unchecked_Access,
          Verify_Mode => Mode_RFC5280, Get_Time => Current_Time'Unrestricted_Access,
          Versions => TLS_1_3_Only, Client_Key_Share_Group => Group, others => <>));
      for I in 1 .. 100 loop
         Step;
         exit when State (C) = Connected and State (S) = Connected;
      end loop;
      if State (C) /= Connected or State (S) /= Connected then
         raise Program_Error with "handshake did not finish";
      end if;
      if not Client.Has_Peer_Certificate (C) then
         raise Program_Error with "missing verified peer certificate";
      end if;
      Write_Plaintext (C, Message, Written);
      if Written /= Message'Length then raise Program_Error with "short request"; end if;
      for I in 1 .. 100 loop
         Step;
         exit when Got_Echo;
      end loop;
      if not Got_Request or not Got_Echo then
         raise Program_Error with "encrypted exchange did not finish";
      end if;
      Drop (C); Drop (S);
      Put_Line ("PASS: verified TLS 1.3 and encrypted echo, " & Group'Image);
   end Exercise;
begin
   if Ada.Command_Line.Argument_Count /= 3 then
      raise Program_Error with "usage: test_fixed_base_handshake leaf.crt leaf.key ca.crt";
   end if;
   Entropy_Random.Init;
   Credentials.Load_Identity
     (Id, Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2), Loaded);
   if not Loaded then raise Program_Error with "identity load failed"; end if;
   Credentials.Load_Trust_Store (Roots, Ada.Command_Line.Argument (3), Loaded);
   if not Loaded then raise Program_Error with "trust store load failed"; end if;
   Exercise (Group_X25519);
   Exercise (Group_X25519MLKEM768);
end Test_Fixed_Base_Handshake;
