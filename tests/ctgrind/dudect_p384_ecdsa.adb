--  dudect timing-test on P-384 ECDSA Sign.
--
--  ctgrind flags Point_Add's early-return-on-infinity branches.
--  They fire predictably ONCE per Scalar_Mul (the first iteration
--  when R0 = O), regardless of K bits — so the *measurable* timing
--  shouldn't depend on K. This dudect harness confirms (or refutes)
--  that. If t < 4.5, the ctgrind flag is a structural false positive.

with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.P384.ECDSA;
with Dudect_Helpers;

procedure Dudect_P384_ECDSA is
   Hash : constant Bytes_48 := (others => 16#42#);
   D    : constant Byte_Seq (0 .. 47) := (others => 16#33#);

   --  Two distinct nonces for the timing comparison. K0 has the
   --  pattern that triggered ctgrind; K1 has the opposite bit
   --  pattern. If timing depends on K bits, t will be large.
   K0 : aliased Byte_Seq (0 .. 47) :=
     (16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#, 16#08#,
      16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#, 16#10#,
      16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#, 16#18#,
      16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#, 16#20#,
      16#21#, 16#22#, 16#23#, 16#24#, 16#25#, 16#26#, 16#27#, 16#28#,
      16#29#, 16#2A#, 16#2B#, 16#2C#, 16#2D#, 16#2E#, 16#2F#, 16#30#);
   K1 : aliased Byte_Seq (0 .. 47) :=
     (others => 16#A5#);

   R, S : Byte_Seq (0 .. 47);
   OK   : Boolean;

   procedure Sub_0 is
   begin
      SPARKTLSCrypto.P384.ECDSA.Sign (Hash, D, K0, R, S, OK);
   end Sub_0;

   procedure Sub_1 is
   begin
      SPARKTLSCrypto.P384.ECDSA.Sign (Hash, D, K1, R, S, OK);
   end Sub_1;
begin
   Dudect_Helpers.Time_Test
     (Name      => "P-384 ECDSA Sign (K=increasing vs K=all-A5)",
      Subject_0 => Sub_0'Access,
      Subject_1 => Sub_1'Access,
      N         => 1_000);
end Dudect_P384_ECDSA;
