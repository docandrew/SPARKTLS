--  SPARKTLS MAC — HMAC-SHA-256 (body)
--
--  Derived from SPARKNaCl.MAC (R. Chapman, MIT license).
--  Uses streaming SHA-256 to avoid concatenation allocations.

package body SPARKTLS.MAC with
   SPARK_Mode => On
is
   procedure HMAC_SHA_256 (Output : out Hashing.SHA256.Digest;
                           M      : in  Byte_Seq;
                           K      : in  Byte_Seq)
   is
      use Hashing.SHA256;

      IPad : Bytes_64 := (others => 16#36#);
      OPad : Bytes_64 := (others => 16#5C#);
      Key  : Bytes_64 := (others => 0);
      Inner_Hash : Digest;
      Ctx : Context;
   begin
      --  Key longer than block size: hash it first
      if K'Length > 64 then
         Hash (Key (0 .. 31), K);
      elsif K'Length > 0 then
         Key (K'Range) := K;
      end if;

      for I in Index_64'Range loop
         IPad (I) := IPad (I) xor Key (I);
         OPad (I) := OPad (I) xor Key (I);
      end loop;

      --  Inner hash: H(ipad || message) — streaming avoids concat
      Init (Ctx);
      Update (Ctx, Byte_Seq (IPad));
      Update (Ctx, M);
      Final (Ctx, Inner_Hash);

      --  Outer hash: H(opad || inner_hash) — streaming avoids concat
      Init (Ctx);
      Update (Ctx, Byte_Seq (OPad));
      Update (Ctx, Byte_Seq (Inner_Hash));
      Final (Ctx, Output);

      pragma Assert (Output'Initialized);
   end HMAC_SHA_256;

end SPARKTLS.MAC;
