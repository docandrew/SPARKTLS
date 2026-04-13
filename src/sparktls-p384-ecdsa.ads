--  SPARKTLS ECDSA P-384 Signature Verification and Signing
--  Uses SPARK-proven BigNat for group order arithmetic.

with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.P384.ECDSA with
   SPARK_Mode => On,
   Abstract_State => Order_State
is
   function Verify
     (Hash : in Bytes_48;
      Qx   : in Byte_Seq;
      Qy   : in Byte_Seq;
      R    : in Byte_Seq;
      S    : in Byte_Seq) return Boolean
   with Global => (Input => Order_State);

   procedure Sign
     (Hash  : in     Bytes_48;
      D     : in     Byte_Seq;
      K     : in     Byte_Seq;
      R_Out :    out Byte_Seq;
      S_Out :    out Byte_Seq;
      OK    :    out Boolean)
   with Global => (In_Out => Order_State),
        Pre    => D'First = 0 and D'Length = 48
                  and K'First = 0 and K'Length = 48
                  and R_Out'First = 0 and R_Out'Length = 48
                  and S_Out'First = 0 and S_Out'Length = 48;

end SPARKTLS.P384.ECDSA;
