--  ===========================================================================
--  SPARKTLS.AEAD_InPlace  --  SPARK-Off overlay for in-place AEAD on RFLX bytes
--  ===========================================================================
--
--  gnatprove (FSF 14/15/16 alike) CRASHES translating a view conversion
--  Byte_Seq (Output.Storage (slice)) used as an in-out actual: Why3 keys array
--  theories by component subtype name, so SPARKNaCl.byte vs
--  rflx_builtin_types.byte -- the same Unsigned_8 representation since the
--  Phase-0 unification -- has no bridge (reproducer tls_proj/exp_conv/,
--  "type ...rflx...byte, expected ...sparknacl...byte"). Not a version
--  regression; not a flag.
--
--  These helpers overlay the ciphertext window of the RFLX storage as a
--  Byte_Seq and AEAD-encrypt it IN PLACE -- the working, BoGo-green,
--  zero-copy behaviour -- so the crashing conversion never appears in SPARK
--  code. The body is SPARK_Mode Off; the Pre carries the bounds the crypto
--  needs, and byte alignment is 1 so the overlay is always valid.
--
--  User-approved 2026-09-05 (option B, keep zero-copy) after downgrading to
--  GNAT 14/15 was shown not to avoid the crash. See [[rflx-borrow-inline-storage]].

with SPARKNaCl;      use SPARKNaCl;
with SPARKNaCl.AES;
with RFLX.RFLX_Builtin_Types;
package SPARKTLS.AEAD_InPlace with SPARK_Mode is

   package RBT renames RFLX.RFLX_Builtin_Types;
   use type RBT.Index;

   --  AES-128-GCM encrypt Storage (CT_First .. CT_Last) in place; Tag out.
   procedure GCM_Encrypt_128
     (Storage  : in out RBT.Bytes;
      CT_First : in     RBT.Index;
      CT_Last  : in     RBT.Index;
      Tag      :    out Bytes_16;
      Nonce    : in     Bytes_12;
      Key      : in     SPARKNaCl.AES.AES128_Key;
      AAD      : in     Byte_Seq)
   with
     Global => null,
     Pre    => CT_First in Storage'Range
               and then CT_Last in CT_First .. Storage'Last
               and then AAD'Last < N32'Last;

   --  AES-256-GCM encrypt Storage (CT_First .. CT_Last) in place; Tag out.
   procedure GCM_Encrypt_256
     (Storage  : in out RBT.Bytes;
      CT_First : in     RBT.Index;
      CT_Last  : in     RBT.Index;
      Tag      :    out Bytes_16;
      Nonce    : in     Bytes_12;
      Key      : in     SPARKNaCl.AES.AES256_Key;
      AAD      : in     Byte_Seq)
   with
     Global => null,
     Pre    => CT_First in Storage'Range
               and then CT_Last in CT_First .. Storage'Last
               and then AAD'Last < N32'Last;

end SPARKTLS.AEAD_InPlace;
