with SPARKTLS.HMAC384;

package body SPARKTLS.HKDF384 with
   SPARK_Mode => On
is

   procedure Extract
     (PRK  :    out Digest_384;
      IKM  : in     Byte_Seq;
      Salt : in     Byte_Seq)
   is
   begin
      HMAC384.HMAC_SHA_384 (PRK, IKM, Salt);
   end Extract;

   procedure Expand
     (OKM  :    out OKM384_Seq;
      PRK  : in     Digest_384;
      Info : in     Byte_Seq)
   is
      Ti : Bytes_48;
      B  : Byte := 1;
   begin
      OKM := (others => 0);
      HMAC384.HMAC_SHA_384 (Ti, Info & B, PRK);

      if OKM'Last < Hash_Len then
         --  Only need first block
         for I in OKM'Range loop
            OKM (I) := Ti (I);
         end loop;
      else
         --  Fill first hash_len bytes
         for I in N32 range 0 .. Hash_Len - 1 loop
            OKM (OKM384_Index (I)) := Ti (Index_48 (I));
         end loop;

         for I in N32 range Hash_Len .. OKM'Last loop
            if I mod Hash_Len = 0 then
               B := B + 1;
               HMAC384.HMAC_SHA_384 (Ti, Ti & Info & B, PRK);
            end if;
            OKM (OKM384_Index (I)) := Ti (Index_48 (I mod Hash_Len));
         end loop;
      end if;
   end Expand;

end SPARKTLS.HKDF384;
