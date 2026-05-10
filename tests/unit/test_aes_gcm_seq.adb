--  Sequenced AES-GCM test — encrypt 3 records back-to-back as
--  the TLS 1.3 mTLS client flight does (Cert, CV, Finished),
--  using the SAME key with successive nonces. Verifies that the
--  Nth call's (ciphertext, tag) is deterministic and matches what
--  a fresh single Encrypt would produce with the same nonce.
--
--  Confirms there is no leftover state from previous calls that
--  affects the current one — which would explain BoGo / OpenSSL's
--  bad_record_mac on the LAST encrypted record in our mTLS flight
--  (Cert/CV decrypt OK, Finished MAC fails).

with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;           use Interfaces;
with SPARKNaCl;            use SPARKNaCl;
with SPARKNaCl.AES;
with SPARKTLSCrypto.AES_GCM;

procedure Test_AES_GCM_Seq is
   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then
         Pass := Pass + 1;
         Put_Line ("  PASS: " & Name);
      else
         Fail := Fail + 1;
         Put_Line ("  FAIL: " & Name);
      end if;
   end Check;

   Key : constant Bytes_32 :=
     (16#fe#, 16#ff#, 16#e9#, 16#92#, 16#86#, 16#65#, 16#73#, 16#1c#,
      16#6d#, 16#6a#, 16#8f#, 16#94#, 16#67#, 16#30#, 16#83#, 16#08#,
      others => 0);
   AES_K : constant AES.AES128_Key := AES.Construct (Key (0 .. 15));
   IV  : constant Bytes_12 :=
     (16#ca#, 16#fe#, 16#ba#, 16#be#, 16#fa#, 16#ce#,
      16#db#, 16#ad#, 16#de#, 16#ca#, 16#f8#, 16#88#);

   --  Build TLS 1.3 nonce: IV XOR (counter padded to 12 bytes BE).
   function Make_Nonce (Counter : Unsigned_64) return Bytes_12 is
      N : Bytes_12 := IV;
   begin
      for I in 0 .. 7 loop
         N (Interfaces.Integer_32 (4 + I)) :=
            N (Interfaces.Integer_32 (4 + I)) xor
            Interfaces.Unsigned_8
              (Shift_Right (Counter,
                            (7 - I) * 8) and 16#FF#);
      end loop;
      return N;
   end Make_Nonce;

   --  Run a 3-record sequence (Cert/CV/Finished sizes mimicking
   --  the actual TLS bytes), comparing each record's output against
   --  a fresh single Encrypt with the same nonce.
   procedure Sequence_3 (Name : String;
                         L1, L2, L3 : N32) is
      AAD1 : constant Byte_Seq (0 .. 4) :=
        (16#17#, 16#03#, 16#03#,
         Byte (Shift_Right (Unsigned_16 (L1 + 17), 8) and 16#FF#),
         Byte (Unsigned_16 (L1 + 17) and 16#FF#));
      AAD2 : constant Byte_Seq (0 .. 4) :=
        (16#17#, 16#03#, 16#03#,
         Byte (Shift_Right (Unsigned_16 (L2 + 17), 8) and 16#FF#),
         Byte (Unsigned_16 (L2 + 17) and 16#FF#));
      AAD3 : constant Byte_Seq (0 .. 4) :=
        (16#17#, 16#03#, 16#03#,
         Byte (Shift_Right (Unsigned_16 (L3 + 17), 8) and 16#FF#),
         Byte (Unsigned_16 (L3 + 17) and 16#FF#));

      P1 : Byte_Seq (0 .. L1 - 1);
      P2 : Byte_Seq (0 .. L2 - 1);
      P3 : Byte_Seq (0 .. L3 - 1);

      --  Sequence outputs (in-place over plaintext).
      Buf1, Ref1, Ref1b : Byte_Seq (0 .. L1 - 1);
      Buf2, Ref2 : Byte_Seq (0 .. L2 - 1);
      Buf3, Ref3 : Byte_Seq (0 .. L3 - 1);
      T1, T2, T3, RT1, RT2, RT3, RT1b : Bytes_16;
   begin
      --  Distinct patterns
      for I in P1'Range loop P1 (I) := Byte ((I * 7) mod 256); end loop;
      for I in P2'Range loop P2 (I) := Byte ((I * 11) mod 256); end loop;
      for I in P3'Range loop P3 (I) := Byte ((I * 13) mod 256); end loop;

      --  The sequence: 3 calls with fresh nonces (counters 0, 1, 2).
      Buf1 := P1;
      SPARKTLSCrypto.AES_GCM.Encrypt_InPlace
        (Buf => Buf1, Tag => T1,
         N => Make_Nonce (0), K => AES_K, AAD => AAD1);
      Buf2 := P2;
      SPARKTLSCrypto.AES_GCM.Encrypt_InPlace
        (Buf => Buf2, Tag => T2,
         N => Make_Nonce (1), K => AES_K, AAD => AAD2);
      Buf3 := P3;
      SPARKTLSCrypto.AES_GCM.Encrypt_InPlace
        (Buf => Buf3, Tag => T3,
         N => Make_Nonce (2), K => AES_K, AAD => AAD3);

      --  Reference: fresh isolated calls.
      Ref1 := P1;
      SPARKTLSCrypto.AES_GCM.Encrypt_InPlace
        (Buf => Ref1, Tag => RT1,
         N => Make_Nonce (0), K => AES_K, AAD => AAD1);
      Ref2 := P2;
      SPARKTLSCrypto.AES_GCM.Encrypt_InPlace
        (Buf => Ref2, Tag => RT2,
         N => Make_Nonce (1), K => AES_K, AAD => AAD2);
      Ref3 := P3;
      SPARKTLSCrypto.AES_GCM.Encrypt_InPlace
        (Buf => Ref3, Tag => RT3,
         N => Make_Nonce (2), K => AES_K, AAD => AAD3);

      --  ALSO verify: re-running record #1 after #2 and #3 gives
      --  same output (no key/state corruption).
      Ref1b := P1;
      SPARKTLSCrypto.AES_GCM.Encrypt_InPlace
        (Buf => Ref1b, Tag => RT1b,
         N => Make_Nonce (0), K => AES_K, AAD => AAD1);

      Check (Name & " #1 ciphertext deterministic", Buf1 = Ref1);
      Check (Name & " #1 tag deterministic",        T1 = RT1);
      Check (Name & " #2 ciphertext deterministic", Buf2 = Ref2);
      Check (Name & " #2 tag deterministic",        T2 = RT2);
      Check (Name & " #3 ciphertext deterministic", Buf3 = Ref3);
      Check (Name & " #3 tag deterministic",        T3 = RT3);
      Check (Name & " #1 stable after #2/#3",       Buf1 = Ref1b);
   end Sequence_3;

begin
   Put_Line ("=== AES-GCM sequenced (mTLS-shape) test ===");

   --  Real mTLS shapes: empty Cert (8) + small CV (~125) + Finished (36)
   Sequence_3 ("mTLS NoCert (8/0/36)", 8, 1, 36);
   Sequence_3 ("mTLS RSA (8/125/36)",  8, 125, 36);
   Sequence_3 ("All small (9/13/37)",  9, 13, 37);

   New_Line;
   Put_Line ("=== Total" & Total'Image
             & "," & Pass'Image & " passed,"
             & Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_AES_GCM_Seq;
