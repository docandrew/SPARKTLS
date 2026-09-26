--  Self-test for IO_Uring: a NOP round trip, then a TCP echo server on
--  accept, receive into a connection buffer, and send, driven by
--  an external client. One receive or one send is in flight at a time, as
--  the TLS server does it. Echoes until the client closes, then exits.
with Ada.Text_IO;  use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;   use Interfaces;
with Interfaces.C; use Interfaces.C;
with POSIX_Thin;   use POSIX_Thin;
with IO_Uring;     use IO_Uring;

procedure Uring_Selftest is
   R      : Ring;
   OK     : Boolean;
   E      : SQE_Access;
   C      : CQE;
   Found  : Boolean;
   Result : Integer;
   Listen : int;
   One    : aliased int := 1;
   Addr   : aliased Sockaddr_In;
   Dummy  : int;
   Client : int := -1;
   Buf    : aliased String (1 .. 4096);
   Have   : Natural := 0;   --  bytes received and not yet echoed
   Sent   : Natural := 0;   --  of those, bytes already sent
   Echoed : Unsigned_64 := 0;
   Port   : constant Natural := Natural'Value (Ada.Command_Line.Argument (1));
   Accept_Tag : constant := 1;
   Recv_Tag   : constant := 2;
   Send_Tag   : constant := 3;
   Done       : Boolean := False;
   Partial_Sends : Natural := 0;
begin
   Setup (R, 64, IORING_SETUP_SINGLE_ISSUER or IORING_SETUP_COOP_TASKRUN, OK);
   if not OK then Put_Line ("FAIL setup"); return; end if;

   E := Get_SQE (R);
   E.Opcode := IORING_OP_NOP; E.User_Data := 42;
   Submit (R, 1, Result);
   Next_CQE (R, C, Found);
   Put_Line ((if Found and then C.User_Data = 42 and then C.Res = 0 then "PASS" else "FAIL") & " nop round trip");

   Listen := C_Socket (AF_INET, SOCK_STREAM, 0);
   Dummy := C_Setsockopt (Listen, SOL_SOCKET, SO_REUSEADDR, One'Access, 4);
   Addr.Sin_Port := Htons (unsigned_short (Port));
   if C_Bind (Listen, Addr'Access, Sockaddr_In'Size / 8) < 0 or else C_Listen (Listen, 16) < 0 then
      Put_Line ("FAIL listen"); return;
   end if;
   Put_Line ("READY");

   E := Get_SQE (R);
   Prep_Accept (E, Listen, Accept_Tag);
   while not Done loop
      Submit (R, 1, Result);
      loop
         Next_CQE (R, C, Found);
         exit when not Found;
         case C.User_Data is
            when Accept_Tag =>
               if C.Res >= 0 and then Client < 0 then
                  Client := int (C.Res);
                  Put_Line ("PASS accept");
                  E := Get_SQE (R);
                  Prep_Recv (E, Client, Buf'Address, Buf'Length, Recv_Tag);
               end if;
            when Recv_Tag =>
               if C.Res > 0 then
                  Have := Natural (C.Res);
                  Sent := 0;
                  E := Get_SQE (R);
                  Prep_Send (E, Client, Buf'Address, Unsigned_32 (Have), Send_Tag);
               else
                  Done := True;   --  0 = peer closed; negative = error
               end if;
            when Send_Tag =>
               if C.Res <= 0 then
                  Done := True;
               else
                  Sent := Sent + Natural (C.Res);
                  Echoed := Echoed + Unsigned_64 (C.Res);
                  E := Get_SQE (R);
                  if Sent < Have then
                     --  A short send: the rest goes next.
                     Partial_Sends := Partial_Sends + 1;
                     Prep_Send (E, Client, Buf (Buf'First + Sent)'Address, Unsigned_32 (Have - Sent), Send_Tag);
                  else
                     Prep_Recv (E, Client, Buf'Address, Buf'Length, Recv_Tag);
                  end if;
               end if;
            when others => null;
         end case;
      end loop;
   end loop;
   Put_Line ("echoed" & Echoed'Image & " bytes (" & Partial_Sends'Image & " short sends )");
   Close (R);
end Uring_Selftest;
