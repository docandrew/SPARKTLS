--  Standards-vector tests for X25519 and Ed25519.
--
--  X25519: RFC 7748 §5.2 (single scalar mult) and §6.1 iterated test.
--  Ed25519: RFC 8032 §7.1 Tests 1, 2, 3 (sign + verify against fixed sigs).
--
--  These vectors are authoritative; any divergence indicates a real
--  cryptographic bug in our SPARK port. Run via ./tests/run_all.sh unit.

with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;           use Interfaces;
with SPARKNaCl;            use SPARKNaCl;
with SPARKTLSCrypto.X25519;
with SPARKTLSCrypto.Ed25519;
with SPARKNaCl.Sign;

procedure Test_25519_RFC is

   Total : Natural := 0;
   Fails : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if not OK then
         Put_Line ("  FAIL: " & Name);
         Fails := Fails + 1;
      end if;
   end Check;

   --  Hex-string helper for laying out RFC vectors readably.
   function Hex (S : String) return Bytes_32 is
      R : Bytes_32 := (others => 0);
      function HD (C : Character) return Natural is
        (case C is
            when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
            when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
            when 'A' .. 'F' => Character'Pos (C) - Character'Pos ('A') + 10,
            when others     => 0);
   begin
      for I in 0 .. 31 loop
         R (N32 (I)) := Byte (HD (S (S'First + 2 * I)) * 16
                              + HD (S (S'First + 2 * I + 1)));
      end loop;
      return R;
   end Hex;

   function Hex64 (S : String) return Bytes_64 is
      R : Bytes_64 := (others => 0);
      function HD (C : Character) return Natural is
        (case C is
            when '0' .. '9' => Character'Pos (C) - Character'Pos ('0'),
            when 'a' .. 'f' => Character'Pos (C) - Character'Pos ('a') + 10,
            when 'A' .. 'F' => Character'Pos (C) - Character'Pos ('A') + 10,
            when others     => 0);
   begin
      for I in 0 .. 63 loop
         R (N32 (I)) := Byte (HD (S (S'First + 2 * I)) * 16
                              + HD (S (S'First + 2 * I + 1)));
      end loop;
      return R;
   end Hex64;

begin
   Put_Line ("--- X25519 RFC 7748 §5.2 vectors ---");
   declare
      --  Vector 1
      K1 : constant Bytes_32 := Hex (
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
      U1 : constant Bytes_32 := Hex (
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
      Expected1 : constant Bytes_32 := Hex (
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

      --  Vector 2
      K2 : constant Bytes_32 := Hex (
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
      U2 : constant Bytes_32 := Hex (
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
      Expected2 : constant Bytes_32 := Hex (
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

      Q : Bytes_32;
   begin
      SPARKTLSCrypto.X25519.Scalar_Mult (Q, K1, U1);
      Check ("X25519 RFC 7748 §5.2 vector 1", Byte_Seq (Q) = Byte_Seq (Expected1));
      SPARKTLSCrypto.X25519.Scalar_Mult (Q, K2, U2);
      Check ("X25519 RFC 7748 §5.2 vector 2", Byte_Seq (Q) = Byte_Seq (Expected2));
   end;

   --  RFC 7748 §6.1 iterated test (after 1 and 1000 iterations).
   --  Skip 1,000,000 — too slow.
   Put_Line ("--- X25519 RFC 7748 §6.1 iterated ---");
   declare
      K : Bytes_32 := (9, others => 0);
      U : Bytes_32 := (9, others => 0);
      T : Bytes_32;
      Expected_1    : constant Bytes_32 := Hex (
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
      Expected_1000 : constant Bytes_32 := Hex (
        "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
   begin
      --  After 1 iteration
      SPARKTLSCrypto.X25519.Scalar_Mult (T, K, U);
      Check ("X25519 §6.1 after 1 iter",
             Byte_Seq (T) = Byte_Seq (Expected_1));

      --  After 1000 iterations
      K := (9, others => 0);
      U := (9, others => 0);
      for I in 1 .. 1000 loop
         SPARKTLSCrypto.X25519.Scalar_Mult (T, K, U);
         U := K;
         K := T;
      end loop;
      Check ("X25519 §6.1 after 1000 iter",
             Byte_Seq (K) = Byte_Seq (Expected_1000));
   end;

   --  RFC 8032 §7.1 Ed25519 vectors.
   Put_Line ("--- Ed25519 RFC 8032 §7.1 vectors ---");
   declare
      type Ed_Vector is record
         Seed     : Bytes_32;
         PK       : Bytes_32;
         Sig      : Bytes_64;
         Msg_Last : I32;     --  inclusive last index of Msg buffer; -1 = empty
         Msg      : Byte_Seq (0 .. 7);  --  generous buffer; only Msg_Last+1 bytes used
      end record;

      Vec1 : constant Ed_Vector := (
         Seed => Hex ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
         PK   => Hex ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
         Sig  => Hex64 ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
         Msg_Last => -1,
         Msg  => (others => 0));

      Vec2 : constant Ed_Vector := (
         Seed => Hex ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
         PK   => Hex ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
         Sig  => Hex64 ("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
         Msg_Last => 0,
         Msg  => (16#72#, others => 0));

      Vec3 : constant Ed_Vector := (
         Seed => Hex ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
         PK   => Hex ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
         Sig  => Hex64 ("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
         Msg_Last => 1,
         Msg  => (16#af#, 16#82#, others => 0));

      Vectors : constant array (1 .. 3) of Ed_Vector := (Vec1, Vec2, Vec3);

      procedure Run (Idx : Positive; V : Ed_Vector) is
         PK_Out : Bytes_32;
         SK_Out : Bytes_64;
         Msg_Len : constant I32 := V.Msg_Last + 1;
      begin
         SPARKTLSCrypto.Ed25519.Keypair (V.Seed, PK_Out, SK_Out);
         Check ("Ed25519 RFC 8032 vec" & Idx'Image & " PK",
                Byte_Seq (PK_Out) = Byte_Seq (V.PK));
         if Byte_Seq (PK_Out) /= Byte_Seq (V.PK) then
            Put ("    got PK : "); for I in N32 range 0 .. 31 loop Put (PK_Out (I)'Image); end loop; New_Line;
            Put ("    want PK: "); for I in N32 range 0 .. 31 loop Put (V.PK (I)'Image); end loop; New_Line;
            declare
               NaCl_PK : SPARKNaCl.Sign.Signing_PK;
               NaCl_SK : SPARKNaCl.Sign.Signing_SK;
               NPK_B   : Bytes_32;
            begin
               SPARKNaCl.Sign.Keypair (V.Seed, NaCl_PK, NaCl_SK);
               NPK_B := SPARKNaCl.Sign.Serialize (NaCl_PK);
               Put ("    NaCl PK: ");
               for I in N32 range 0 .. 31 loop Put (NPK_B (I)'Image); end loop;
               New_Line;
            end;
         end if;

         declare
            SM : Byte_Seq (0 .. 64 + Msg_Len - 1);
         begin
            SPARKTLSCrypto.Ed25519.Sign (SM, V.Msg (0 .. Msg_Len - 1), SK_Out);
            Check ("Ed25519 RFC 8032 vec" & Idx'Image & " Sign",
                   Byte_Seq (SM (0 .. 63)) = Byte_Seq (V.Sig));
         end;

         --  Verify by feeding the canonical (sig||msg) form to Open.
         declare
            SM    : Byte_Seq (0 .. 64 + Msg_Len - 1);
            M_Out : Byte_Seq (0 .. 64 + Msg_Len - 1);
            Valid : Boolean;
            Out_Len : I32;
         begin
            SM (0 .. 63)             := Byte_Seq (V.Sig);
            SM (64 .. SM'Last)       := V.Msg (0 .. Msg_Len - 1);
            SPARKTLSCrypto.Ed25519.Open (M_Out, Valid, Out_Len, SM, V.PK);
            Check ("Ed25519 RFC 8032 vec" & Idx'Image & " Verify",
                   Valid and then Out_Len = Msg_Len);
         end;
      end Run;
   begin
      Run (1, Vec1);
      Run (2, Vec2);
      Run (3, Vec3);
   end;

   New_Line;
   Put_Line ("Total checks:" & Total'Image
             & "  Failures:" & Fails'Image);
   if Fails > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_25519_RFC;
