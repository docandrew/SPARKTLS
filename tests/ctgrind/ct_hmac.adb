--  Constant-time check for HMAC-SHA-256 and HMAC-SHA-384 directly.
--
--  These are tested transitively via the HKDF, RFC 6979, and key
--  schedule harnesses, but a direct harness catches future
--  regressions in the HMAC primitive itself before they propagate
--  to dependents.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.MAC;
with SPARKTLSCrypto.HMAC384;
with SPARKTLSCrypto.Hashing.SHA256;
with Ctgrind;

procedure Ct_HMAC is
   --  Public message.
   M : constant Byte_Seq (0 .. 1023) := (others => 16#5A#);

   --  Secret HMAC key.
   K : Byte_Seq (0 .. 31) :=
     (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
      16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
      16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
      16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#);

   D256 : SPARKTLSCrypto.Hashing.SHA256.Digest;
   D384 : SPARKNaCl.Hashing.SHA384.Digest;
begin
   --  HMAC-SHA-256
   Ctgrind.Make_Undefined (K'Address, Interfaces.C.size_t (K'Length));
   SPARKTLSCrypto.MAC.HMAC_SHA_256 (D256, M, K);
   Ctgrind.Make_Defined (D256'Address, Interfaces.C.size_t (D256'Length));
   Ctgrind.Use_Output (D256'Address, Interfaces.C.size_t (D256'Length));

   --  HMAC-SHA-384
   Ctgrind.Make_Undefined (K'Address, Interfaces.C.size_t (K'Length));
   SPARKTLSCrypto.HMAC384.HMAC_SHA_384 (D384, M, K);
   Ctgrind.Make_Defined (D384'Address, Interfaces.C.size_t (D384'Length));
   Ctgrind.Use_Output (D384'Address, Interfaces.C.size_t (D384'Length));

   Put_Line ("ct_hmac: HMAC-SHA-256 + HMAC-SHA-384 completed");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_HMAC;
