--  dudect timing-test on P-256 ECDSA Sign.
--
--  Expectation: this SHOULD show |t| > 4.5 because ctgrind already
--  found a non-constant-time `if Is_Zero(K) or not Less_Than_Order(K)`
--  guard. Even though that branch almost never fires for random K,
--  the early return gives the optimizer free rein to vary code
--  layout — which dudect can pick up. Use as a positive-control
--  cross-check for our analysis pipeline.
--
--  Note: even if the early-return branch is "almost never taken",
--  dudect won't necessarily light up unless we feed it the case
--  that triggers the branch. We use K0 = all zeros to FORCE the
--  early-return path on Subject_0. So this is really a validation
--  that dudect can detect the gross case.

with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.P256.ECDSA;
with Dudect_Helpers;

procedure Dudect_P256_ECDSA is
   Hash : constant Bytes_32 := (others => 16#42#);
   D    : constant SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half :=
     (others => 16#33#);

   --  K0 = all zeros → triggers Is_Zero check → early return path
   K0 : aliased SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half :=
     (others => 16#00#);
   --  K1 = a normal-looking nonce → goes through the full sign path
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
     (Name      => "P-256 ECDSA Sign (K=zeros vs K=normal)",
      Subject_0 => Sub_0'Access,
      Subject_1 => Sub_1'Access,
      N         => 2_000);
end Dudect_P256_ECDSA;
