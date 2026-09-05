--  dudect timing-test on X25519 scalar multiplication.
--
--  Expected: |t| < 4.5 (constant-time across two random scalars).
--  Run from outside valgrind for accurate cycle measurements.

with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.X25519;
with Dudect_Helpers;

procedure Dudect_X25519 is
   --  Two distinct scalars (the "secret" axis along which we test
   --  for timing dependence). Real dudect would randomize per
   --  iteration; for a tight test we just use two fixed extreme
   --  scalars (all-zero and all-ones) — if the impl branches on
   --  scalar bits, these maximally diverge.
   N0 : aliased Bytes_32 := (others => 16#00#);
   N1 : aliased Bytes_32 := (others => 16#FF#);
   P  : constant Bytes_32 :=
     (16#09#, others => 0);   -- standard basepoint x-coord
   Q  : aliased Bytes_32;

   procedure Sub_0 is
   begin
      SPARKTLSCrypto.X25519.Scalar_Mult (Q, N0, P);
   end Sub_0;

   procedure Sub_1 is
   begin
      SPARKTLSCrypto.X25519.Scalar_Mult (Q, N1, P);
   end Sub_1;
begin
   Dudect_Helpers.Time_Test
     (Name      => "X25519 Scalar_Mult (zeros vs all-ones scalar)",
      Subject_0 => Sub_0'Access,
      Subject_1 => Sub_1'Access,
      N         => 5_000);
end Dudect_X25519;
