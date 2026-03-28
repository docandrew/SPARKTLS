with SPARKNaCl.Hashing;
with SPARKNaCl.Hashing.SHA384; use SPARKNaCl.Hashing.SHA384;

package body SPARKTLS.HMAC384 with
   SPARK_Mode => On
is
   --  SHA-384 block size is 128 bytes
   Block_Size : constant := 128;

   subtype Block_Index is N32 range 0 .. Block_Size - 1;
   subtype Block_Bytes is Byte_Seq (Block_Index);

   procedure HMAC_SHA_384
     (Output :    out Digest_384;
      M      : in     Byte_Seq;
      K      : in     Byte_Seq)
   is
      IPad : Block_Bytes := (others => 16#36#);
      OPad : Block_Bytes := (others => 16#5C#);
      Key  : Block_Bytes := (others => 0);
   begin
      --  If key > block size, hash it first
      if K'Length > Block_Size then
         Key (0 .. 47) := Hash (K);
      elsif K'Length > 0 then
         Key (0 .. N32 (K'Length) - 1) := K;
      end if;

      for I in Block_Index'Range loop
         IPad (I) := IPad (I) xor Key (I);
         OPad (I) := OPad (I) xor Key (I);
      end loop;

      Output := Hash (OPad & Hash (IPad & M));
   end HMAC_SHA_384;

end SPARKTLS.HMAC384;
