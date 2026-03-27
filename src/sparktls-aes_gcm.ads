with SPARKNaCl;     use SPARKNaCl;
with SPARKNaCl.AES;

--  AES-GCM Authenticated Encryption with Associated Data
--
--  Implements AES-GCM (Galois/Counter Mode) per NIST SP 800-38D,
--  built on top of SPARKNaCl.AES block cipher.
--  Supports both AES-128 and AES-256 key sizes.
--  Nonce: 12 bytes (96 bits) as required by TLS 1.3.
--  Tag: 16 bytes (128 bits).
package SPARKTLS.AES_GCM with
   SPARK_Mode => On
is
   --================================================================
   --  AES-128-GCM
   --================================================================

   procedure Encrypt
     (C       :    out Byte_Seq;
      Tag     :    out Bytes_16;
      M       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES128_Key;
      AAD     : in     Byte_Seq)
   with Pre => M'First  = 0 and then
               C'First  = 0 and then
               AAD'First = 0 and then
               C'Last   = M'Last and then
               C'Length  = M'Length and then
               M'Last   < N32'Last and then
               AAD'Last < N32'Last;

   procedure Decrypt
     (M       :    out Byte_Seq;
      Status  :    out Boolean;
      Tag     : in     Bytes_16;
      C       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES128_Key;
      AAD     : in     Byte_Seq)
   with Pre => M'First  = 0 and then
               C'First  = 0 and then
               AAD'First = 0 and then
               M'Last   = C'Last and then
               M'Length  = C'Length and then
               C'Last   < N32'Last and then
               AAD'Last < N32'Last;

   --================================================================
   --  AES-256-GCM
   --================================================================

   procedure Encrypt_256
     (C       :    out Byte_Seq;
      Tag     :    out Bytes_16;
      M       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES256_Key;
      AAD     : in     Byte_Seq)
   with Pre => M'First  = 0 and then
               C'First  = 0 and then
               AAD'First = 0 and then
               C'Last   = M'Last and then
               C'Length  = M'Length and then
               M'Last   < N32'Last and then
               AAD'Last < N32'Last;

   procedure Decrypt_256
     (M       :    out Byte_Seq;
      Status  :    out Boolean;
      Tag     : in     Bytes_16;
      C       : in     Byte_Seq;
      N       : in     Bytes_12;
      K       : in     AES.AES256_Key;
      AAD     : in     Byte_Seq)
   with Pre => M'First  = 0 and then
               C'First  = 0 and then
               AAD'First = 0 and then
               M'Last   = C'Last and then
               M'Length  = C'Length and then
               C'Last   < N32'Last and then
               AAD'Last < N32'Last;

end SPARKTLS.AES_GCM;
