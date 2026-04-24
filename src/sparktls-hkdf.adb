--  SPARKTLS HKDF — HKDF-SHA-256 (body)
--
--  Derived from SPARKNaCl.HKDF (R. Chapman, MIT license).

with SPARKTLS.MAC;

package body SPARKTLS.HKDF with
   SPARK_Mode => On
is
   procedure Extract (PRK  :    out Hashing.SHA256.Digest;
                      IKM  : in     Byte_Seq;
                      Salt : in     Byte_Seq)
   is
   begin
      MAC.HMAC_SHA_256 (PRK, IKM, Salt);
   end Extract;

   procedure Expand (OKM  :    out OKM_Seq;
                     PRK  : in     Hashing.SHA256.Digest;
                     Info : in     Byte_Seq)
   is
      Ti : Bytes_32;
      B  : Byte := 1;
   begin
      MAC.HMAC_SHA_256 (Ti, Info & B, Byte_Seq (PRK));

      if OKM'Last <= Ti'Last then
         OKM := OKM_Seq (Ti (OKM'Range));
      else
         OKM (Ti'Range) := OKM_Seq (Ti);
         pragma Assert (OKM (Ti'Range)'Initialized);

         for I in Hash_Len .. OKM'Last loop
            if I mod Hash_Len = 0 then
               B := B + 1;
               MAC.HMAC_SHA_256 (Ti, Ti & Info & B, Byte_Seq (PRK));
            end if;
            OKM (I) := Ti (I mod Hash_Len);
            pragma Loop_Invariant (OKM (0 .. I)'Initialized);
         end loop;
      end if;
   end Expand;

end SPARKTLS.HKDF;
