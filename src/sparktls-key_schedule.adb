with SPARKNaCl.Hashing;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLS.HMAC384;

package body SPARKTLS.Key_Schedule with
   SPARK_Mode => Off  --  TODO: enable incrementally
is
   --  Helper: convert string to byte sequence
   function To_Byte_Seq (S : String) return Byte_Seq is
      Result : Byte_Seq (0 .. N32 (S'Length) - 1);
   begin
      for I in S'Range loop
         Result (N32 (I - S'First)) := Byte (Character'Pos (S (I)));
      end loop;
      return Result;
   end To_Byte_Seq;

   --  Helper: 2-byte big-endian encoding
   function TS16 (U : Interfaces.Unsigned_16) return Byte_Seq is
      use Interfaces;
      X : Byte_Seq (0 .. 1);
   begin
      X (0) := Byte (U / 256);
      X (1) := Byte (U mod 256);
      return X;
   end TS16;

   procedure Expand_Label
     (OKM     :    out OKM_Seq;
      PRK     : in     Digest;
      Label   : in     String;
      Context : in     Byte_Seq)
   is
      use Interfaces;
      HKDF_Label : Byte_Seq :=
         TS16 (Unsigned_16 (OKM'Length)) &
         Byte (Label'Length + 6) &
         To_Byte_Seq ("tls13 " & Label) &
         Byte (Context'Length) &
         Context;
   begin
      SPARKNaCl.HKDF.Expand (OKM, PRK, HKDF_Label);
   end Expand_Label;

   procedure Derive_Early_Secret
     (Early : out Digest;
      PSK   : in  Bytes_32)
   is
      One_Zero : Byte_Seq (0 .. 0) := (others => 0);
   begin
      SPARKNaCl.HKDF.Extract
        (PRK  => Early,
         IKM  => PSK,
         Salt => One_Zero);
   end Derive_Early_Secret;

   procedure Derive_Handshake_Secret
     (HS_Secret    :    out Digest;
      Shared       : in     Byte_Seq;
      Early_Secret : in     Digest)
   is
      Empty      : Byte_Seq (1 .. 0) := (others => 0);
      Empty_Hash : Digest;
      Derived    : OKM_Seq (0 .. 31);
   begin
      Hash (Empty_Hash, Empty);
      Expand_Label (OKM     => Derived,
                    PRK     => Early_Secret,
                    Label   => "derived",
                    Context => Empty_Hash);
      SPARKNaCl.HKDF.Extract
        (PRK  => HS_Secret,
         IKM  => Shared,
         Salt => Byte_Seq (Derived));
   end Derive_Handshake_Secret;

   procedure Derive_HS_Traffic_Secrets
     (Client_HS_Secret :    out OKM_Seq;
      Server_HS_Secret :    out OKM_Seq;
      HS_Secret        : in     Digest;
      Hello_Hash       : in     Digest)
   is
   begin
      Expand_Label (OKM     => Client_HS_Secret,
                    PRK     => HS_Secret,
                    Label   => "c hs traffic",
                    Context => Hello_Hash);
      Expand_Label (OKM     => Server_HS_Secret,
                    PRK     => HS_Secret,
                    Label   => "s hs traffic",
                    Context => Hello_Hash);
   end Derive_HS_Traffic_Secrets;

   procedure Derive_Traffic_Key_IV
     (Key    :    out OKM_Seq;
      IV     :    out OKM_Seq;
      Secret : in     Byte_Seq)
   is
      Empty : Byte_Seq (1 .. 0) := (others => 0);
   begin
      Expand_Label (OKM     => Key,
                    PRK     => Digest (Secret),
                    Label   => "key",
                    Context => Empty);
      Expand_Label (OKM     => IV,
                    PRK     => Digest (Secret),
                    Label   => "iv",
                    Context => Empty);
   end Derive_Traffic_Key_IV;

   procedure Derive_Traffic_Key_IV_128
     (Key    :    out OKM_Seq;
      IV     :    out OKM_Seq;
      Secret : in     Byte_Seq)
   is
      Empty : Byte_Seq (1 .. 0) := (others => 0);
   begin
      Expand_Label (OKM     => Key,
                    PRK     => Digest (Secret),
                    Label   => "key",
                    Context => Empty);
      Expand_Label (OKM     => IV,
                    PRK     => Digest (Secret),
                    Label   => "iv",
                    Context => Empty);
   end Derive_Traffic_Key_IV_128;

   procedure Derive_Master_Secret
     (Master    :    out Digest;
      HS_Secret : in     Digest)
   is
      Empty      : Byte_Seq (1 .. 0) := (others => 0);
      Empty_Hash : Digest;
      Derived    : OKM_Seq (0 .. 31);
      All_Zeroes : Bytes_32 := (others => 0);
   begin
      Hash (Empty_Hash, Empty);
      Expand_Label (OKM     => Derived,
                    PRK     => HS_Secret,
                    Label   => "derived",
                    Context => Empty_Hash);
      SPARKNaCl.HKDF.Extract
        (PRK  => Master,
         IKM  => All_Zeroes,
         Salt => Byte_Seq (Derived));
   end Derive_Master_Secret;

   procedure Derive_App_Traffic_Secrets
     (Client_App_Secret :    out OKM_Seq;
      Server_App_Secret :    out OKM_Seq;
      Master            : in     Digest;
      Transcript_Hash   : in     Digest)
   is
   begin
      Expand_Label (OKM     => Client_App_Secret,
                    PRK     => Master,
                    Label   => "c ap traffic",
                    Context => Transcript_Hash);
      Expand_Label (OKM     => Server_App_Secret,
                    PRK     => Master,
                    Label   => "s ap traffic",
                    Context => Transcript_Hash);
   end Derive_App_Traffic_Secrets;

   procedure Derive_Finished_Key
     (Finished_Key :    out OKM_Seq;
      Base_Secret  : in     Byte_Seq)
   is
      Empty : Byte_Seq (1 .. 0) := (others => 0);
   begin
      Expand_Label (OKM     => Finished_Key,
                    PRK     => Digest (Base_Secret),
                    Label   => "finished",
                    Context => Empty);
   end Derive_Finished_Key;

   --================================================================
   --  SHA-384 variants
   --================================================================

   procedure Expand_Label_384
     (OKM     :    out HKDF384.OKM384_Seq;
      PRK     : in     Digest_384;
      Label   : in     String;
      Context : in     Byte_Seq)
   is
      use Interfaces;
      HKDF_Label : Byte_Seq :=
         TS16 (Unsigned_16 (OKM'Length)) &
         Byte (Label'Length + 6) &
         To_Byte_Seq ("tls13 " & Label) &
         Byte (Context'Length) &
         Context;
   begin
      HKDF384.Expand (OKM, PRK, HKDF_Label);
   end Expand_Label_384;

   procedure Derive_Early_Secret_384
     (Early : out Digest_384;
      PSK   : in  Bytes_48)
   is
      One_Zero : Byte_Seq (0 .. 0) := (others => 0);
   begin
      HKDF384.Extract (Early, PSK, One_Zero);
   end Derive_Early_Secret_384;

   procedure Derive_Handshake_Secret_384
     (HS_Secret    :    out Digest_384;
      Shared       : in     Byte_Seq;
      Early_Secret : in     Digest_384)
   is
      Empty      : Byte_Seq (1 .. 0) := (others => 0);
      Empty_Hash : Digest_384;
      Derived    : HKDF384.OKM384_Seq (0 .. 47);
   begin
      SPARKNaCl.Hashing.SHA384.Hash (Empty_Hash, Empty);
      Expand_Label_384
        (OKM     => Derived,
         PRK     => Early_Secret,
         Label   => "derived",
         Context => Empty_Hash);
      HKDF384.Extract (HS_Secret, Shared, Byte_Seq (Derived));
   end Derive_Handshake_Secret_384;

   procedure Derive_HS_Traffic_Secrets_384
     (Client_HS_Secret :    out HKDF384.OKM384_Seq;
      Server_HS_Secret :    out HKDF384.OKM384_Seq;
      HS_Secret        : in     Digest_384;
      Hello_Hash       : in     Digest_384)
   is
   begin
      Expand_Label_384
        (OKM     => Client_HS_Secret,
         PRK     => HS_Secret,
         Label   => "c hs traffic",
         Context => Hello_Hash);
      Expand_Label_384
        (OKM     => Server_HS_Secret,
         PRK     => HS_Secret,
         Label   => "s hs traffic",
         Context => Hello_Hash);
   end Derive_HS_Traffic_Secrets_384;

   procedure Derive_Traffic_Key_IV_256
     (Key    :    out HKDF384.OKM384_Seq;
      IV     :    out HKDF384.OKM384_Seq;
      Secret : in     Byte_Seq)
   is
      Empty : Byte_Seq (1 .. 0) := (others => 0);
   begin
      Expand_Label_384
        (OKM     => Key,
         PRK     => Digest_384 (Secret),
         Label   => "key",
         Context => Empty);
      Expand_Label_384
        (OKM     => IV,
         PRK     => Digest_384 (Secret),
         Label   => "iv",
         Context => Empty);
   end Derive_Traffic_Key_IV_256;

   procedure Derive_Master_Secret_384
     (Master    :    out Digest_384;
      HS_Secret : in     Digest_384)
   is
      Empty      : Byte_Seq (1 .. 0) := (others => 0);
      Empty_Hash : Digest_384;
      Derived    : HKDF384.OKM384_Seq (0 .. 47);
      All_Zeroes : Bytes_48 := (others => 0);
   begin
      SPARKNaCl.Hashing.SHA384.Hash (Empty_Hash, Empty);
      Expand_Label_384
        (OKM     => Derived,
         PRK     => HS_Secret,
         Label   => "derived",
         Context => Empty_Hash);
      HKDF384.Extract (Master, All_Zeroes, Byte_Seq (Derived));
   end Derive_Master_Secret_384;

   procedure Derive_App_Traffic_Secrets_384
     (Client_App_Secret :    out HKDF384.OKM384_Seq;
      Server_App_Secret :    out HKDF384.OKM384_Seq;
      Master            : in     Digest_384;
      Transcript_Hash   : in     Digest_384)
   is
   begin
      Expand_Label_384
        (OKM     => Client_App_Secret,
         PRK     => Master,
         Label   => "c ap traffic",
         Context => Transcript_Hash);
      Expand_Label_384
        (OKM     => Server_App_Secret,
         PRK     => Master,
         Label   => "s ap traffic",
         Context => Transcript_Hash);
   end Derive_App_Traffic_Secrets_384;

   procedure Derive_Finished_Key_384
     (Finished_Key :    out HKDF384.OKM384_Seq;
      Base_Secret  : in     Byte_Seq)
   is
      Empty : Byte_Seq (1 .. 0) := (others => 0);
   begin
      Expand_Label_384
        (OKM     => Finished_Key,
         PRK     => Digest_384 (Base_Secret),
         Label   => "finished",
         Context => Empty);
   end Derive_Finished_Key_384;

end SPARKTLS.Key_Schedule;
