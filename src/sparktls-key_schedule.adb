with SPARKNaCl.Hashing.SHA384;
with SPARKTLS.HMAC384;

package body SPARKTLS.Key_Schedule with
   SPARK_Mode => On
is
   --  Helper: convert string to byte sequence
   function To_Byte_Seq (S : String) return Byte_Seq
   with Pre  => S'Length > 0 and S'Length <= 255,
        Post => To_Byte_Seq'Result'First = 0
                and To_Byte_Seq'Result'Length = S'Length
   is
      Result : Byte_Seq (0 .. N32 (S'Length) - 1) := (others => 0);
   begin
      for I in S'Range loop
         Result (N32 (I - S'First)) := Byte (Character'Pos (S (I)));
      end loop;
      return Result;
   end To_Byte_Seq;

   --  Helper: 2-byte big-endian encoding
   function TS16 (U : Interfaces.Unsigned_16) return Byte_Seq
   with Post => TS16'Result'First = 0 and TS16'Result'Length = 2
   is
      use Interfaces;
      X : Byte_Seq (0 .. 1) := (others => 0);
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
      Full_Label : constant String := "tls13 " & Label;
      HKDF_Label : Byte_Seq (0 .. N32 (3 + Full_Label'Length + 1 +
                                        Context'Length) - 1) := (others => 0);
      Pos : N32 := 0;
   begin
      --  Build HKDF label manually to help the prover with bounds
      --  Length (2 bytes, big-endian)
      HKDF_Label (0) := Byte (Unsigned_16 (OKM'Length) / 256);
      HKDF_Label (1) := Byte (Unsigned_16 (OKM'Length) mod 256);
      Pos := 2;
      --  Label length (1 byte) + label
      HKDF_Label (Pos) := Byte (Full_Label'Length);
      Pos := Pos + 1;
      for I in Full_Label'Range loop
         pragma Loop_Invariant
           (Pos = 3 + N32 (I - Full_Label'First) and
            Pos <= HKDF_Label'Last);
         HKDF_Label (Pos) := Byte (Character'Pos (Full_Label (I)));
         Pos := Pos + 1;
      end loop;
      --  Context length (1 byte) + context
      HKDF_Label (Pos) := Byte (Context'Length);
      Pos := Pos + 1;
      pragma Assert (Pos = 4 + N32 (Full_Label'Length));
      if Context'Length > 0 then
         for I in Context'Range loop
            pragma Loop_Invariant
              (Pos = 4 + N32 (Full_Label'Length) + N32 (I - Context'First) and
               Pos <= HKDF_Label'Last);
            HKDF_Label (Pos) := Context (I);
            Pos := Pos + 1;
         end loop;
      end if;

      SPARKTLS.HKDF.Expand (OKM, PRK, HKDF_Label);
   end Expand_Label;

   procedure Derive_Early_Secret
     (Early : out Digest;
      PSK   : in  Bytes_32)
   is
      One_Zero : Byte_Seq (0 .. 0) := (others => 0);
   begin
      SPARKTLS.HKDF.Extract
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
      SPARKTLS.HKDF.Extract
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
      SPARKTLS.HKDF.Extract
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

   procedure Derive_Resumption_Master_Secret
     (Res_Master      :    out OKM_Seq;
      Master          : in     Digest;
      Transcript_Hash : in     Digest)
   is
   begin
      Expand_Label (OKM     => Res_Master,
                    PRK     => Master,
                    Label   => "res master",
                    Context => Transcript_Hash);
   end Derive_Resumption_Master_Secret;

   procedure Derive_PSK
     (PSK         :    out OKM_Seq;
      Res_Master  : in     Byte_Seq;
      Nonce       : in     Byte_Seq)
   is
   begin
      Expand_Label (OKM     => PSK,
                    PRK     => Digest (Res_Master),
                    Label   => "resumption",
                    Context => Nonce);
   end Derive_PSK;

   procedure Derive_Binder_Key
     (Binder_Key :    out OKM_Seq;
      PSK        : in     Bytes_32)
   is
      Early      : Digest;
      Empty      : Byte_Seq (1 .. 0) := (others => 0);
      Empty_Hash : Digest;
   begin
      Derive_Early_Secret (Early, PSK);
      SPARKTLS.Hashing.SHA256.Hash (Empty_Hash, Empty);
      Expand_Label (OKM     => Binder_Key,
                    PRK     => Early,
                    Label   => "res binder",
                    Context => Empty_Hash);
   end Derive_Binder_Key;

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
      Full_Label : constant String := "tls13 " & Label;
      HKDF_Label : Byte_Seq (0 .. N32 (3 + Full_Label'Length + 1 +
                                        Context'Length) - 1) := (others => 0);
      Pos : N32 := 0;
   begin
      HKDF_Label (0) := Byte (Unsigned_16 (OKM'Length) / 256);
      HKDF_Label (1) := Byte (Unsigned_16 (OKM'Length) mod 256);
      Pos := 2;
      HKDF_Label (Pos) := Byte (Full_Label'Length);
      Pos := Pos + 1;
      for I in Full_Label'Range loop
         pragma Loop_Invariant
           (Pos = 3 + N32 (I - Full_Label'First) and
            Pos <= HKDF_Label'Last);
         HKDF_Label (Pos) := Byte (Character'Pos (Full_Label (I)));
         Pos := Pos + 1;
      end loop;
      HKDF_Label (Pos) := Byte (Context'Length);
      Pos := Pos + 1;
      pragma Assert (Pos = 4 + N32 (Full_Label'Length));
      if Context'Length > 0 then
         for I in Context'Range loop
            pragma Loop_Invariant
              (Pos = 4 + N32 (Full_Label'Length) + N32 (I - Context'First) and
               Pos <= HKDF_Label'Last);
            HKDF_Label (Pos) := Context (I);
            Pos := Pos + 1;
         end loop;
      end if;

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

   procedure Derive_Resumption_Master_Secret_384
     (Res_Master      :    out HKDF384.OKM384_Seq;
      Master          : in     Digest_384;
      Transcript_Hash : in     Digest_384)
   is
   begin
      Expand_Label_384
        (OKM     => Res_Master,
         PRK     => Master,
         Label   => "res master",
         Context => Transcript_Hash);
   end Derive_Resumption_Master_Secret_384;

   procedure Derive_PSK_384
     (PSK         :    out HKDF384.OKM384_Seq;
      Res_Master  : in     Byte_Seq;
      Nonce       : in     Byte_Seq)
   is
   begin
      Expand_Label_384
        (OKM     => PSK,
         PRK     => Digest_384 (Res_Master),
         Label   => "resumption",
         Context => Nonce);
   end Derive_PSK_384;

   procedure Derive_Binder_Key_384
     (Binder_Key :    out HKDF384.OKM384_Seq;
      PSK        : in     Bytes_48)
   is
      Early      : Digest_384;
      Empty      : Byte_Seq (1 .. 0) := (others => 0);
      Empty_Hash : Digest_384;
   begin
      Derive_Early_Secret_384 (Early, PSK);
      SPARKNaCl.Hashing.SHA384.Hash (Empty_Hash, Empty);
      Expand_Label_384
        (OKM     => Binder_Key,
         PRK     => Early,
         Label   => "res binder",
         Context => Empty_Hash);
   end Derive_Binder_Key_384;

end SPARKTLS.Key_Schedule;
