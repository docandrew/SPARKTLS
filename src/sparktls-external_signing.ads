--  Helpers for applications implementing SPARKTLS.Sign_Fn (an HSM, TPM,
--  smart card or signing process supplying the handshake signature). See
--  the external-signing design notes. Library code never depends on this package.
with SPARKTLS.Handshake;

package SPARKTLS.External_Signing with
  SPARK_Mode => On
is
   Max_ECDSA_DER_Len : constant := Handshake.Max_ECDSA_DER_Len;

   --  Convert a raw ECDSA signature r || s, as PKCS#11, TPM2 and secure
   --  elements return it, into the DER SEQUENCE { r, s } that TLS carries.
   --  Half_Len is 32 for P-256 and 48 for P-384; Raw'Length must be exactly
   --  2 * Half_Len, otherwise OK is False and DER_Len is 0.
   procedure ECDSA_Raw_To_DER
     (Raw      : in     Byte_Seq;
      Half_Len : in     N32;
      DER_Out  :    out Byte_Seq;
      DER_Len  :    out N32;
      OK       :    out Boolean)
   with
     Pre  => Raw'First = 0
             and then Raw'Length <= 96          --  r || s is at most 2 * 48
             and then Half_Len in 32 | 48
             and then DER_Out'First = 0
             and then DER_Out'Last >= Max_ECDSA_DER_Len - 1,
     Post => DER_Len <= Max_ECDSA_DER_Len and then (if not OK then DER_Len = 0);

end SPARKTLS.External_Signing;
