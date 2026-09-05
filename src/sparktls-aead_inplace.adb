with System;  pragma Unreferenced (System);
with SPARKTLSCrypto.AES_GCM;

--  Why this body is SPARK_Mode Off
--  --------------------------------
--  The ONLY reason is the gnatprove translation crash documented in the spec:
--  a Byte_Seq view of an RFLX Bytes slice, used as an in-out actual, aborts
--  Why3 (GNAT 14/15/16 alike). It is NOT that the work here is unverifiable.
--  Each body overlays the ciphertext window as a Byte_Seq and calls
--  SPARKTLSCrypto.AES_GCM, which has a SPARK_Mode On spec AND body and is
--  independently proven -- a proven callee, invoked from an Off caller.
--  What Off costs us is only the caller-side check of the crypto's
--  precondition at these two call sites; the spec's Pre mirrors that
--  precondition (the window gives Buf'First = 0, Buf'Length > 0,
--  Buf'Last < N32'Last; AAD'Last < N32'Last is required of callers), so the
--  bounds the crypto needs are still stated and discharged by callers in
--  SPARK. The overlay itself is sound: byte alignment is 1, so the storage
--  address is always a valid Byte_Seq base. See the spec header and
--  tls_proj/exp_conv/ for the reproducer.

package body SPARKTLS.AEAD_InPlace with SPARK_Mode => Off is

   procedure GCM_Encrypt_128
     (Storage  : in out RBT.Bytes;
      CT_First : in     RBT.Index;
      CT_Last  : in     RBT.Index;
      Tag      :    out Bytes_16;
      Nonce    : in     Bytes_12;
      Key      : in     SPARKNaCl.AES.AES128_Key;
      AAD      : in     Byte_Seq)
   is
      Buf : Byte_Seq (0 .. N32 (CT_Last) - N32 (CT_First))
        with Import, Address => Storage (CT_First)'Address;
   begin
      --  Proven (SPARK On) crypto, called from this Off body only to keep the
      --  in-place overlay out of Why3's crashing conversion path.
      SPARKTLSCrypto.AES_GCM.Encrypt_InPlace
        (Buf => Buf, Tag => Tag, N => Nonce, K => Key, AAD => AAD);
   end GCM_Encrypt_128;

   procedure GCM_Encrypt_256
     (Storage  : in out RBT.Bytes;
      CT_First : in     RBT.Index;
      CT_Last  : in     RBT.Index;
      Tag      :    out Bytes_16;
      Nonce    : in     Bytes_12;
      Key      : in     SPARKNaCl.AES.AES256_Key;
      AAD      : in     Byte_Seq)
   is
      Buf : Byte_Seq (0 .. N32 (CT_Last) - N32 (CT_First))
        with Import, Address => Storage (CT_First)'Address;
   begin
      --  Proven (SPARK On) crypto, called from this Off body only to keep the
      --  in-place overlay out of Why3's crashing conversion path.
      SPARKTLSCrypto.AES_GCM.Encrypt_InPlace_256
        (Buf => Buf, Tag => Tag, N => Nonce, K => Key, AAD => AAD);
   end GCM_Encrypt_256;

end SPARKTLS.AEAD_InPlace;
