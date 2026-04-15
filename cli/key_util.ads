--  Key Generation and PKCS#8 Serialization

with X509; use type X509.N32;
with SPARKNaCl; use SPARKNaCl;

package Key_Util is

   type Key_Algorithm is (Algo_Ed25519, Algo_P256, Algo_P384);

   --  Generate a keypair and encode the private key as PKCS#8 DER.
   --  Also returns the public key in SubjectPublicKeyInfo DER format
   --  (needed for embedding in certificates).
   procedure Generate_Key
     (Algo      : Key_Algorithm;
      Priv_DER  : out X509.Byte_Seq;
      Priv_Len  : out X509.N32;
      SPKI_DER  : out X509.Byte_Seq;
      SPKI_Len  : out X509.N32;
      OK        : out Boolean)
   with Pre => Priv_DER'First = 0 and Priv_DER'Length >= 256
               and SPKI_DER'First = 0 and SPKI_DER'Length >= 256;

   --  Loaded private key material
   type Private_Key is record
      Algo     : Key_Algorithm := Algo_Ed25519;
      --  Ed25519: 64-byte expanded key (seed || public)
      --  P-256: 32-byte scalar
      --  P-384: 48-byte scalar
      Raw      : Byte_Seq (0 .. 63) := (others => 0);
      Raw_Len  : N32 := 0;
      --  SubjectPublicKeyInfo DER (for embedding in certs)
      SPKI     : X509.Byte_Seq (0 .. 255) := (others => 0);
      SPKI_Len : X509.N32 := 0;
      Valid    : Boolean := False;
   end record;

   --  Load a private key from a PEM file.
   --  Derives the public key and builds the SPKI.
   procedure Load_Private_Key
     (Path : String;
      Key  : out Private_Key);

end Key_Util;
