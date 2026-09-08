--  Constant-time check for HKDF (HMAC-SHA256 internally).
--
--  HKDF-Extract takes a secret IKM (input keying material) and a
--  salt; HKDF-Expand takes the derived PRK (also secret) plus a
--  public Info string. Both operations should be constant-time —
--  HKDF is in the TLS 1.3 key schedule on every handshake.
--
--  We mark the IKM as undefined for Extract, then mark the
--  derived PRK as undefined and run Expand. Any branch / load
--  whose target depends on either trips memcheck.

with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces.C;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.HKDF;
with SPARKTLSCrypto.Hashing.SHA256;
with Ctgrind;

procedure Ct_HKDF is
   IKM  : Byte_Seq (0 .. 31) := (others => 16#A5#);
   Salt : constant Byte_Seq (0 .. 15) := (others => 16#5A#);
   Info : constant Byte_Seq (0 .. 7)  := (others => 16#42#);
   PRK  : SPARKTLSCrypto.Hashing.SHA256.Digest;
   OKM  : SPARKTLSCrypto.HKDF.OKM_Seq (0 .. 63);
begin
   Ctgrind.Make_Undefined (IKM'Address, Interfaces.C.size_t (IKM'Length));
   SPARKTLSCrypto.HKDF.Extract (PRK, IKM, Salt);

   --  PRK is derived from secret IKM, so it's also secret. Re-mark
   --  it explicitly so memcheck propagates undefined-ness through
   --  Expand.
   Ctgrind.Make_Undefined (PRK'Address, Interfaces.C.size_t (PRK'Length));
   SPARKTLSCrypto.HKDF.Expand (OKM, PRK, Info);

   Ctgrind.Make_Defined (OKM'Address, Interfaces.C.size_t (OKM'Length));
   Ctgrind.Use_Output (OKM'Address, Interfaces.C.size_t (OKM'Length));

   Put_Line ("ct_hkdf: Extract + Expand completed");
   Ada.Command_Line.Set_Exit_Status (0);
end Ct_HKDF;
