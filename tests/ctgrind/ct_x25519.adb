--  Constant-time check for X25519 scalar multiplication.
--
--  X25519 is the highest-leverage primitive for side-channel issues:
--  it's used during every TLS handshake to derive the ECDHE shared
--  secret. A leak here gives the attacker the ECDH private key.
--
--  Marks both the scalar N (secret key) and the input point P (treat
--  as secret too — it's an attacker-supplied curve point in real
--  use) as undefined. Calls Scalar_Mult and checks valgrind for any
--  branch or memory access whose target depends on N or P.
--
--  The Montgomery ladder in this module is supposed to be a constant-
--  time conditional swap (cswap). If valgrind flags anything in
--  Scalar_Mult, the cswap is leaking.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.X25519;
with Ctgrind;

procedure Ct_X25519 is
   N : Bytes_32 :=
     (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
      16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
      16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
      16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#);
   P : Bytes_32 :=
     (16#20#, 16#21#, 16#22#, 16#23#, 16#24#, 16#25#, 16#26#, 16#27#,
      16#28#, 16#29#, 16#2A#, 16#2B#, 16#2C#, 16#2D#, 16#2E#, 16#2F#,
      16#30#, 16#31#, 16#32#, 16#33#, 16#34#, 16#35#, 16#36#, 16#37#,
      16#38#, 16#39#, 16#3A#, 16#3B#, 16#3C#, 16#3D#, 16#3E#, 16#3F#);
   Q : Bytes_32;
begin
   Ctgrind.Make_Undefined (N'Address, Interfaces.C.size_t (N'Length));
   Ctgrind.Make_Undefined (P'Address, Interfaces.C.size_t (P'Length));

   SPARKTLSCrypto.X25519.Scalar_Mult (Q, N, P);

   Ctgrind.Make_Defined (Q'Address, Interfaces.C.size_t (Q'Length));
   Ctgrind.Use_Output (Q'Address, Interfaces.C.size_t (Q'Length));

   Put_Line ("ct_x25519: Scalar_Mult completed");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_X25519;
