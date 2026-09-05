--  dudect timing-test on P-256 ECDSA Sign.
--
--  Expectation: |t| < 4.5 (constant-time across two valid nonces).
--  Sign's precondition is "K in [1, n-1]" — the caller (RFC 6979)
--  guarantees this in production. We feed two distinct *valid* K's
--  with very different bit patterns; if the timing depends on K's
--  bits the t-statistic explodes.

with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.P256.ECDSA;
with Dudect_Helpers;

procedure Dudect_P256_ECDSA is
   Hash : constant Bytes_32 := (others => 16#42#);
   D    : constant SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half :=
     (others => 16#33#);

   --  K0 / K1: two valid nonces with very different bit patterns.
   K0 : aliased SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half :=
     (16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#, 16#08#,
      16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#, 16#10#,
      16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#, 16#18#,
      16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#, 16#20#);
   K1 : aliased SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half :=
     (16#A5#, 16#5A#, 16#A5#, 16#5A#, 16#A5#, 16#5A#, 16#A5#, 16#5A#,
      16#A5#, 16#5A#, 16#A5#, 16#5A#, 16#A5#, 16#5A#, 16#A5#, 16#5A#,
      16#A5#, 16#5A#, 16#A5#, 16#5A#, 16#A5#, 16#5A#, 16#A5#, 16#5A#,
      16#A5#, 16#5A#, 16#A5#, 16#5A#, 16#A5#, 16#5A#, 16#A5#, 16#01#);

   R, S : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
   OK   : Boolean;

   procedure Sub_0 is
   begin
      SPARKTLSCrypto.P256.ECDSA.Sign (Hash, D, K0, R, S, OK);
   end Sub_0;

   procedure Sub_1 is
   begin
      SPARKTLSCrypto.P256.ECDSA.Sign (Hash, D, K1, R, S, OK);
   end Sub_1;
begin
   Dudect_Helpers.Time_Test
     (Name      => "P-256 ECDSA Sign (K=ascending vs K=A5/5A pattern)",
      Subject_0 => Sub_0'Access,
      Subject_1 => Sub_1'Access,
      N         => 2_000);
end Dudect_P256_ECDSA;
