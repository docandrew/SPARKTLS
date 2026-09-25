with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLS; use SPARKTLS;
with SPARKTLS.Send_Ciphertext;
with SPARKTLS.Test_Support;
procedure Test_Send_Ciphertext is
   package TS renames SPARKTLS.Test_Support;
   use type RBT_A.Index;
   use type RBT_A.Byte;
   Total : Natural := 0;
   procedure Check (OK : Boolean; What : String) is
   begin
      if not OK then raise Program_Error with What; end if;
      Total := Total + 1;
   end Check;
   procedure Exercise (Role : TLS_Role; Suite : Supported_Suite) is
      S, Ref : Session (Role);
      Expected : Byte_Seq (0 .. 65535) := (others => 0);
      Len, Pos, Limit, Calls : N32 := 0;
      Fail : Boolean := False;
      procedure Send (Data : RBT_A.Bytes; Sent : out N32) is
      begin
         Calls := Calls + 1;
         Check (N32 (Data'Length) = Len - Pos, "wrong offered length");
         for I in Data'Range loop
            Check (Data (I) = RBT_A.Byte (Expected (Pos + N32 (I - Data'First))),
                   "ciphertext changed or reordered");
         end loop;
         if Fail then raise Program_Error with "transport exception"; end if;
         Sent := N32'Min (Limit, N32 (Data'Length));
         Pos := Pos + Sent;
      end Send;
      procedure Flush is new SPARKTLS.Send_Ciphertext (Send);
      procedure Capture is
         B : Byte_Seq (0 .. Buffer_Size'Last - 1);
         N : N32;
      begin
         Drain_Ciphertext (Ref, B, N);
         if N > 0 then Expected (Len .. Len + N - 1) := B (0 .. N - 1); end if;
         Len := Len + N;
      end Capture;
      N, M : N32;
   begin
      TS.Install_Test_Traffic (S, Suite);
      TS.Install_Test_Traffic (Ref, Suite);
      Flush (S, N);
      Check (N = 0 and Calls = 0, "empty output called transport");
      for Round in 1 .. 4 loop
         Len := 0; Pos := 0;
         declare
            Plain : Byte_Seq (0 .. 20036);
         begin
            for I in Plain'Range loop Plain (I) := Byte ((I + N32 (Round)) mod 251); end loop;
            Write_Plaintext (S, Plain, N);
            Write_Plaintext (Ref, Plain, M);
            Check (N = M and N = Plain'Length, "write setup");
         end;
         Capture;
         Limit := 0;
         Flush (S, N);
         Flush (S, N);
         Check (N = 0 and Pos = 0 and Output_Pending (S) = Len, "zero progress consumed output");
         Fail := True;
         begin
            Flush (S, N);
            raise Constraint_Error with "expected callback exception";
         exception when Program_Error => null; end;
         Fail := False;
         Check (Output_Pending (S) = Len, "exception consumed output");
         Limit := 7; Flush (S, N);
         Check (N = 7 and Output_Pending (S) = Len - 7, "partial send");
         Request_Key_Update (S); Request_Key_Update (Ref); Capture;
         Check (TS.Write_Keys (S) = TS.Write_Keys (Ref), "key update changed keys");
         Limit := 16383; Flush (S, N);
         Limit := 1; Flush (S, N);
         Limit := 0; Flush (S, N);
         Limit := Buffer_Size'Last; Flush (S, N);
         Check (Pos = Len and Output_Pending (S) = 0, "drain completion");
         declare
            Before : constant N32 := Calls;
         begin
            Flush (S, N);
            Check (Calls = Before and N = 0, "empty after reuse");
         end;
      end loop;
   end Exercise;
begin
   for Role in TLS_Role loop
      for Suite in Supported_Suite loop Exercise (Role, Suite); end loop;
   end loop;
   Put_Line ("PASS:" & Total'Image & " direct ciphertext checks");
end Test_Send_Ciphertext;
