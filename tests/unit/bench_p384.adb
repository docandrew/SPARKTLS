--  P-384 microbenchmark (not a test; not run by run_all): ECDSA sign,
--  ECDSA verify, ECDHE shared secret, public-key derivation.
--  Usage: bench_p384 [iters]
with Ada.Text_IO;   use Ada.Text_IO;
with Ada.Command_Line;
with Ada.Real_Time; use Ada.Real_Time;
with SPARKNaCl;     use SPARKNaCl;
with SPARKTLSCrypto.P384.ECDSA;
with SPARKTLSCrypto.P384.Point;

procedure Bench_P384 is
   It : Positive := 50;

   procedure Report (What : String; Iters : Positive; Elapsed : Duration) is
      Us : constant Long_Float := Long_Float (Elapsed) * 1.0e6 / Long_Float (Iters);
   begin
      Put_Line (What & ":" & Integer'Image (Integer (Us)) & " us/op,"
                & Integer'Image (Integer (1.0e6 / Us)) & " ops/s");
   end Report;

   --  Fixed private scalar / nonce / hash (values below n, non-zero)
   D    : Byte_Seq (0 .. 47) := (others => 16#3C#);
   K    : Byte_Seq (0 .. 47) := (others => 16#5A#);
   Hash : constant Bytes_48 := (others => 16#A5#);
   Qx, Qy, R, S : Byte_Seq (0 .. 47) := (others => 0);
   PK   : Byte_Seq (0 .. 96) := (others => 0);
   Secret : Bytes_48;
   OK   : Boolean := True;
   Good : Boolean := True;
   T0, T1 : Time;
begin
   if Ada.Command_Line.Argument_Count >= 1 then
      It := Positive'Value (Ada.Command_Line.Argument (1));
   end if;
   D (0) := 16#01#; K (0) := 16#02#;   --  keep both below n

   SPARKTLSCrypto.P384.ECDSA.Public_Key (D, Qx, Qy);

   T0 := Clock;
   for I in 1 .. It loop
      SPARKTLSCrypto.P384.ECDSA.Sign (Hash, D, K, R, S, OK);
      Good := Good and OK;
   end loop;
   T1 := Clock;
   Report ("ECDSA P-384 sign  ", It, To_Duration (T1 - T0));

   T0 := Clock;
   for I in 1 .. It loop
      Good := Good and SPARKTLSCrypto.P384.ECDSA.Verify (Hash, Qx, Qy, R, S);
   end loop;
   T1 := Clock;
   Report ("ECDSA P-384 verify", It, To_Duration (T1 - T0));

   T0 := Clock;
   for I in 1 .. It loop
      SPARKTLSCrypto.P384.Point.P384_Mulgen (PK, D);
   end loop;
   T1 := Clock;
   Report ("P-384 keygen      ", It, To_Duration (T1 - T0));

   T0 := Clock;
   for I in 1 .. It loop
      SPARKTLSCrypto.P384.Point.P384_ECDHE (Secret, OK, K, PK);
      Good := Good and OK;
   end loop;
   T1 := Clock;
   Report ("P-384 ECDHE       ", It, To_Duration (T1 - T0));
   Put_Line ("all operations succeeded: " & Good'Image);
end Bench_P384;
