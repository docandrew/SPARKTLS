--  Constant-time check for AES-GCM Decrypt (AES-128 + AES-256).
--
--  This is the highest-historical-impact CT surface in TLS: decrypt
--  verifies an attacker-supplied tag against an attacker-supplied
--  ciphertext. A timing leak in the tag check or surrounding
--  decrypt logic gives the Lucky-13 / padding-oracle class of bug.
--
--  ChaCha20-Poly1305 decrypt goes through SPARKNaCl.Secretbox.Open,
--  which has a "branch on tag-validity, then either decrypt or zero
--  M" pattern. That branch leaks one bit equal to the publicly-
--  returned Status, so the information-theoretic leak is zero —
--  but ctgrind would still flag it. Since SPARKNaCl is upstream
--  and we don't want to fork it, the ChaCha20-Poly1305 decrypt
--  path is intentionally NOT exercised here.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM;
with Ctgrind;

procedure Ct_AEAD_Decrypt is
   --  Forged ciphertext + tag the attacker would submit.
   C   : Byte_Seq (0 .. 1023) := (others => 16#42#);
   AAD : constant Byte_Seq (0 .. 15) := (others => 16#BB#);
   Tag : constant Bytes_16 := (others => 16#FF#);

   --  Public nonce.
   N_Bytes : constant Bytes_12 :=
     (16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#,
      16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#);

   K_Bytes : Bytes_32 :=
     (16#00#, 16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#, 16#07#,
      16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#, 16#0D#, 16#0E#, 16#0F#,
      16#10#, 16#11#, 16#12#, 16#13#, 16#14#, 16#15#, 16#16#, 16#17#,
      16#18#, 16#19#, 16#1A#, 16#1B#, 16#1C#, 16#1D#, 16#1E#, 16#1F#);

   K_AES128 : SPARKNaCl.AES.AES128_Key;
   K_AES256 : SPARKNaCl.AES.AES256_Key;

   M      : Byte_Seq (0 .. 1023);
   Status : Boolean;
begin
   --  AES-128-GCM Decrypt path
   Ctgrind.Make_Undefined
     (K_Bytes (0)'Address, Interfaces.C.size_t (16));
   SPARKNaCl.AES.Construct (K_AES128, Bytes_16 (K_Bytes (0 .. 15)));
   SPARKTLSCrypto.AES_GCM.Decrypt
     (M => M, Status => Status, Tag => Tag, C => C,
      N => N_Bytes, K => K_AES128, AAD => AAD);
   Ctgrind.Make_Defined
     (Status'Address, Interfaces.C.size_t (Status'Size / 8));
   Ctgrind.Use_Output (M'Address, Interfaces.C.size_t (M'Length));

   --  AES-256-GCM Decrypt path
   Ctgrind.Make_Undefined
     (K_Bytes'Address, Interfaces.C.size_t (K_Bytes'Length));
   SPARKNaCl.AES.Construct (K_AES256, K_Bytes);
   SPARKTLSCrypto.AES_GCM.Decrypt_256
     (M => M, Status => Status, Tag => Tag, C => C,
      N => N_Bytes, K => K_AES256, AAD => AAD);
   Ctgrind.Make_Defined
     (Status'Address, Interfaces.C.size_t (Status'Size / 8));
   Ctgrind.Use_Output (M'Address, Interfaces.C.size_t (M'Length));

   Put_Line ("ct_aead_decrypt: AES-128-GCM + AES-256-GCM decrypt"
             & " completed");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_AEAD_Decrypt;
