--  Constant-time check for ECDSA-P-256 signing.
--
--  ECDSA's nonce K is the highest-leverage secret in the entire
--  signature scheme: a single bit of information about K (e.g. a
--  branch on its top bit) plus a few hundred signatures lets an
--  attacker recover the long-term private key D via lattice attacks.
--
--  We mark BOTH the long-term private key D AND the per-signature
--  nonce K as undefined. Any branch / load whose target depends on
--  either trips memcheck. The hash itself is public so we leave it
--  defined.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.P256.ECDSA;
with Ctgrind;

procedure Ct_P256_ECDSA is
   Hash : constant Bytes_32 :=
     (16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#, 16#66#, 16#77#,
      16#88#, 16#99#, 16#AA#, 16#BB#, 16#CC#, 16#DD#, 16#EE#, 16#FF#,
      16#01#, 16#23#, 16#45#, 16#67#, 16#89#, 16#AB#, 16#CD#, 16#EF#,
      16#FE#, 16#DC#, 16#BA#, 16#98#, 16#76#, 16#54#, 16#32#, 16#10#);

   --  Long-term private scalar D (secret).
   D : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half :=
     (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
      16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
      16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
      16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#);

   --  Per-signature nonce K (also secret — leak = key recovery).
   K : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half :=
     (16#20#, 16#21#, 16#22#, 16#23#, 16#24#, 16#25#, 16#26#, 16#27#,
      16#28#, 16#29#, 16#2A#, 16#2B#, 16#2C#, 16#2D#, 16#2E#, 16#2F#,
      16#30#, 16#31#, 16#32#, 16#33#, 16#34#, 16#35#, 16#36#, 16#37#,
      16#38#, 16#39#, 16#3A#, 16#3B#, 16#3C#, 16#3D#, 16#3E#, 16#3F#);

   R, S : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
   OK   : Boolean;
begin
   Ctgrind.Make_Undefined (D'Address, Interfaces.C.size_t (D'Length));
   Ctgrind.Make_Undefined (K'Address, Interfaces.C.size_t (K'Length));

   SPARKTLSCrypto.P256.ECDSA.Sign (Hash, D, K, R, S, OK);

   --  Outputs are public (signature) — re-define so any post-sign
   --  use isn't flagged.
   Ctgrind.Make_Defined (R'Address, Interfaces.C.size_t (R'Length));
   Ctgrind.Make_Defined (S'Address, Interfaces.C.size_t (S'Length));
   Ctgrind.Make_Defined (OK'Address, Interfaces.C.size_t (OK'Size / 8));
   Ctgrind.Use_Output (R'Address, Interfaces.C.size_t (R'Length));
   Ctgrind.Use_Output (S'Address, Interfaces.C.size_t (S'Length));

   Put_Line ("ct_p256_ecdsa: Sign completed (OK=" & OK'Image & ")");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_P256_ECDSA;
