with SPARKNaCl.Sign;
with SPARKNaCl.Sign.Utils;
with SPARKEntropy;
with SPARKTLS.P256.Point;
with SPARKTLS.P384.Point;
with SPARKTLS.PEM;
with DER_Builder; use DER_Builder;
with Ada.Text_IO;

package body Key_Util is
   use type X509.N32;
   use type X509.Byte;
   use type X509.Byte_Seq;

   --  Entropy state for key generation
   Entropy : SPARKEntropy.Entropy_State;
   Entropy_Ready : Boolean := False;

   procedure Ensure_Entropy is
      OK : Boolean;
   begin
      if not Entropy_Ready then
         SPARKEntropy.Init (Entropy, OK);
         if not OK then
            Ada.Text_IO.Put_Line ("Error: entropy source init failed");
            return;
         end if;
         Entropy_Ready := True;
      end if;
   end Ensure_Entropy;

   procedure Get_Random_Bytes (Output : out X509.Byte_Seq) is
      Buf : SPARKEntropy.Byte_Seq (0 .. Output'Length - 1);
      OK  : Boolean;
   begin
      SPARKEntropy.Generate (Entropy, Buf, OK);
      if not OK then
         Output := (others => 0);
         return;
      end if;
      for I in Output'Range loop
         Output (I) := X509.Byte (Buf (Natural (I - Output'First)));
      end loop;
   end Get_Random_Bytes;

   --  Encode Ed25519 private key as PKCS#8 DER.
   --  Structure: SEQUENCE { INTEGER(0), SEQUENCE { OID ed25519 },
   --             OCTET STRING { OCTET STRING { seed } } }
   procedure Encode_PKCS8_Ed25519
     (Seed     : Bytes_32;
      DER_Out  : out X509.Byte_Seq;
      DER_Len  : out X509.N32)
   is
      Buf : DER_Buffer := (others => 0);
      Pos : X509.N32 := 0;
      Outer, Algo : X509.N32;
      Seed_Bytes : X509.Byte_Seq (0 .. 31);
      Inner_Octet : X509.Byte_Seq (0 .. 33);
   begin
      DER_Out := (others => 0);

      --  Build the inner OCTET STRING (04 20 <seed>) manually
      Inner_Octet (0) := 16#04#;
      Inner_Octet (1) := 16#20#;
      for I in N32 range 0 .. 31 loop
         Seed_Bytes (X509.N32 (I)) := X509.Byte (Seed (I));
         Inner_Octet (X509.N32 (I) + 2) := X509.Byte (Seed (I));
      end loop;

      Start_Sequence (Buf, Pos, Outer);
      Put_Small_Integer (Buf, Pos, 0);  --  version
      Start_Sequence (Buf, Pos, Algo);
      Put_OID (Buf, Pos, X509.Byte_Seq (OID_Ed25519));
      End_Sequence (Buf, Pos, Algo);
      Put_Octet_String (Buf, Pos, Inner_Octet);
      End_Sequence (Buf, Pos, Outer);

      DER_Len := Pos;
      DER_Out (0 .. Pos - 1) := X509.Byte_Seq (Buf (0 .. Pos - 1));
   end Encode_PKCS8_Ed25519;

   --  Encode EC private key as PKCS#8 DER.
   --  Structure: SEQUENCE { INTEGER(0),
   --    SEQUENCE { OID ecPublicKey, OID curve },
   --    OCTET STRING { SEQUENCE { INTEGER(1), OCTET STRING scalar,
   --                              [1] BIT STRING pubkey } } }
   procedure Encode_PKCS8_EC
     (Scalar   : X509.Byte_Seq;
      PubKey   : X509.Byte_Seq;
      Curve_OID : X509.Byte_Seq;
      DER_Out  : out X509.Byte_Seq;
      DER_Len  : out X509.N32)
   is
      Buf : DER_Buffer := (others => 0);
      Pos : X509.N32 := 0;
      Outer, Algo, Inner, EC_Seq, PK_Ctx : X509.N32;
   begin
      DER_Out := (others => 0);

      Start_Sequence (Buf, Pos, Outer);
      Put_Small_Integer (Buf, Pos, 0);  --  version

      --  AlgorithmIdentifier { ecPublicKey, curve OID }
      Start_Sequence (Buf, Pos, Algo);
      Put_OID (Buf, Pos, X509.Byte_Seq (OID_EC_Public_Key));
      Put_OID (Buf, Pos, Curve_OID);
      End_Sequence (Buf, Pos, Algo);

      --  OCTET STRING wrapping ECPrivateKey SEQUENCE
      declare
         EC_Buf : DER_Buffer := (others => 0);
         EC_Pos : X509.N32 := 0;
         EC_Seq_Save : X509.N32;
         EC_PK_Ctx : X509.N32;
      begin
         Start_Sequence (EC_Buf, EC_Pos, EC_Seq_Save);
         Put_Small_Integer (EC_Buf, EC_Pos, 1);  --  version
         Put_Octet_String (EC_Buf, EC_Pos, Scalar);
         --  [1] EXPLICIT BIT STRING publicKey
         Start_Context (EC_Buf, EC_Pos, 1, EC_PK_Ctx);
         Put_Bit_String (EC_Buf, EC_Pos, PubKey);
         End_Context (EC_Buf, EC_Pos, EC_PK_Ctx);
         End_Sequence (EC_Buf, EC_Pos, EC_Seq_Save);

         Put_Octet_String (Buf, Pos,
            X509.Byte_Seq (EC_Buf (0 .. EC_Pos - 1)));
      end;

      End_Sequence (Buf, Pos, Outer);

      DER_Len := Pos;
      DER_Out (0 .. Pos - 1) := X509.Byte_Seq (Buf (0 .. Pos - 1));
   end Encode_PKCS8_EC;

   --  Build SubjectPublicKeyInfo DER
   procedure Build_SPKI
     (Algo_OIDs : X509.Byte_Seq;  --  pre-built AlgorithmIdentifier content
      PubKey    : X509.Byte_Seq;
      SPKI_DER  : out X509.Byte_Seq;
      SPKI_Len  : out X509.N32)
   is
      Buf : DER_Buffer := (others => 0);
      Pos : X509.N32 := 0;
      Outer, Algo : X509.N32;
   begin
      SPKI_DER := (others => 0);

      Start_Sequence (Buf, Pos, Outer);
      --  AlgorithmIdentifier is passed as pre-built content
      Put_Bytes (Buf, Pos, Algo_OIDs);
      --  Public key as BIT STRING
      Put_Bit_String (Buf, Pos, PubKey);
      End_Sequence (Buf, Pos, Outer);

      SPKI_Len := Pos;
      SPKI_DER (0 .. Pos - 1) := X509.Byte_Seq (Buf (0 .. Pos - 1));
   end Build_SPKI;

   --  Build the AlgorithmIdentifier SEQUENCE for a given algorithm
   procedure Build_Algo_Id
     (Algo     : Key_Algorithm;
      Algo_DER : out X509.Byte_Seq;
      Algo_Len : out X509.N32)
   is
      Buf : DER_Buffer := (others => 0);
      Pos : X509.N32 := 0;
      Seq : X509.N32;
   begin
      Algo_DER := (others => 0);
      Start_Sequence (Buf, Pos, Seq);
      case Algo is
         when Algo_Ed25519 =>
            Put_OID (Buf, Pos, X509.Byte_Seq (OID_Ed25519));
         when Algo_P256 =>
            Put_OID (Buf, Pos, X509.Byte_Seq (OID_EC_Public_Key));
            Put_OID (Buf, Pos, X509.Byte_Seq (OID_Secp256r1));
         when Algo_P384 =>
            Put_OID (Buf, Pos, X509.Byte_Seq (OID_EC_Public_Key));
            Put_OID (Buf, Pos, X509.Byte_Seq (OID_Secp384r1));
      end case;
      End_Sequence (Buf, Pos, Seq);

      Algo_Len := Pos;
      Algo_DER (0 .. Pos - 1) := X509.Byte_Seq (Buf (0 .. Pos - 1));
   end Build_Algo_Id;

   procedure Generate_Key
     (Algo      : Key_Algorithm;
      Priv_DER  : out X509.Byte_Seq;
      Priv_Len  : out X509.N32;
      SPKI_DER  : out X509.Byte_Seq;
      SPKI_Len  : out X509.N32;
      OK        : out Boolean)
   is
   begin
      Priv_DER := (others => 0);
      Priv_Len := 0;
      SPKI_DER := (others => 0);
      SPKI_Len := 0;
      OK := False;

      Ensure_Entropy;
      if not Entropy_Ready then return; end if;

      case Algo is
         when Algo_Ed25519 =>
            declare
               Seed : Bytes_32;
               SK   : SPARKNaCl.Sign.Signing_SK;
               PK   : SPARKNaCl.Sign.Signing_PK;
               PK_Bytes : Bytes_32;
               Seed_X : X509.Byte_Seq (0 .. 31);
               Algo_Id : X509.Byte_Seq (0 .. 255) := (others => 0);
               Algo_Id_Len : X509.N32;
            begin
               Get_Random_Bytes (Seed_X);
               for I in N32 range 0 .. 31 loop
                  Seed (I) := Byte (Seed_X (X509.N32 (I)));
               end loop;

               SPARKNaCl.Sign.Keypair (Seed, PK, SK);
               PK_Bytes := SPARKNaCl.Sign.Serialize (PK);

               Encode_PKCS8_Ed25519 (Seed, Priv_DER, Priv_Len);

               --  SPKI for Ed25519: SEQUENCE { SEQUENCE { OID }, BIT STRING { pk } }
               declare
                  PK_X : X509.Byte_Seq (0 .. 31);
               begin
                  for I in N32 range 0 .. 31 loop
                     PK_X (X509.N32 (I)) := X509.Byte (PK_Bytes (I));
                  end loop;
                  Build_Algo_Id (Algo_Ed25519, Algo_Id, Algo_Id_Len);
                  Build_SPKI (Algo_Id (0 .. Algo_Id_Len - 1),
                              PK_X, SPKI_DER, SPKI_Len);
               end;
               OK := True;
            end;

         when Algo_P256 =>
            declare
               use SPARKTLS.P256.Point;
               Scalar_X : X509.Byte_Seq (0 .. 31);
               Scalar_N : Byte_Seq (0 .. 31);
               PK_Jac   : P256_Jacobian;
               PK_Enc   : Byte_Seq (0 .. 64);  --  65 bytes uncompressed
               PK_X     : X509.Byte_Seq (0 .. 64);
               Algo_Id : X509.Byte_Seq (0 .. 255) := (others => 0);
               Algo_Id_Len : X509.N32;
               Valid_Scalar : Boolean := False;
            begin
               --  Generate scalar in [1, n-1] for P-256
               for Attempt in 1 .. 100 loop
                  Get_Random_Bytes (Scalar_X);
                  --  Check scalar < n and scalar /= 0
                  declare
                     Less : Boolean := False;
                     Zero : Boolean := True;
                  begin
                     for I in X509.N32 range 0 .. 31 loop
                        if Scalar_X (I) /= 0 then Zero := False; end if;
                        if not Less then
                           if Scalar_X (I) < P256_N (N32 (I)) then
                              Less := True;
                           elsif Scalar_X (I) > P256_N (N32 (I)) then
                              exit;  --  too big, retry
                           end if;
                        end if;
                     end loop;
                     if Less and not Zero then
                        Valid_Scalar := True;
                        exit;
                     end if;
                  end;
               end loop;

               if not Valid_Scalar then return; end if;

               for I in N32 range 0 .. 31 loop
                  Scalar_N (I) := Byte (Scalar_X (X509.N32 (I)));
               end loop;

               P256_Mulgen (PK_Jac, Scalar_N, 32);
               P256_To_Affine (PK_Jac);
               P256_Encode (PK_Enc, PK_Jac);

               for I in X509.N32 range 0 .. 64 loop
                  PK_X (I) := X509.Byte (PK_Enc (N32 (I)));
               end loop;

               Encode_PKCS8_EC (Scalar_X, PK_X,
                                X509.Byte_Seq (OID_Secp256r1),
                                Priv_DER, Priv_Len);

               Build_Algo_Id (Algo_P256, Algo_Id, Algo_Id_Len);
               Build_SPKI (Algo_Id (0 .. Algo_Id_Len - 1),
                           PK_X, SPKI_DER, SPKI_Len);
               OK := True;
            end;

         when Algo_P384 =>
            declare
               --  P-384 curve order n
               P384_N : constant Byte_Seq (0 .. 47) :=
                 (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
                  16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
                  16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
                  16#C7#, 16#63#, 16#4D#, 16#81#, 16#F4#, 16#37#, 16#2D#, 16#DF#,
                  16#58#, 16#1A#, 16#0D#, 16#B2#, 16#48#, 16#B0#, 16#A7#, 16#7A#,
                  16#EC#, 16#EC#, 16#19#, 16#6A#, 16#CC#, 16#C5#, 16#29#, 16#73#);
               Scalar_X : X509.Byte_Seq (0 .. 47);
               Scalar_N : Byte_Seq (0 .. 47);
               PK_Enc   : Byte_Seq (0 .. 96);  --  97 bytes uncompressed
               PK_X     : X509.Byte_Seq (0 .. 96);
               Algo_Id : X509.Byte_Seq (0 .. 255) := (others => 0);
               Algo_Id_Len : X509.N32;
               Valid_Scalar : Boolean := False;
            begin
               --  Generate scalar in [1, n-1] for P-384
               for Attempt in 1 .. 100 loop
                  Get_Random_Bytes (Scalar_X);
                  declare
                     Less : Boolean := False;
                     Zero : Boolean := True;
                  begin
                     for I in X509.N32 range 0 .. 47 loop
                        if Scalar_X (I) /= 0 then Zero := False; end if;
                        if not Less then
                           if Scalar_X (I) < P384_N (N32 (I)) then
                              Less := True;
                           elsif Scalar_X (I) > P384_N (N32 (I)) then
                              exit;
                           end if;
                        end if;
                     end loop;
                     if Less and not Zero then
                        Valid_Scalar := True;
                        exit;
                     end if;
                  end;
               end loop;

               if not Valid_Scalar then return; end if;

               for I in N32 range 0 .. 47 loop
                  Scalar_N (I) := Byte (Scalar_X (X509.N32 (I)));
               end loop;

               SPARKTLS.P384.Point.P384_Mulgen (PK_Enc, Scalar_N);

               for I in X509.N32 range 0 .. 96 loop
                  PK_X (I) := X509.Byte (PK_Enc (N32 (I)));
               end loop;

               Encode_PKCS8_EC (Scalar_X, PK_X,
                                X509.Byte_Seq (OID_Secp384r1),
                                Priv_DER, Priv_Len);

               Build_Algo_Id (Algo_P384, Algo_Id, Algo_Id_Len);
               Build_SPKI (Algo_Id (0 .. Algo_Id_Len - 1),
                           PK_X, SPKI_DER, SPKI_Len);
               OK := True;
            end;
      end case;
   end Generate_Key;

   --  Read a text file into a String
   function Read_Text_File (Path : String) return String is
      use Ada.Text_IO;
      F      : File_Type;
      Result : String (1 .. 65536) := (others => ' ');
      Len    : Natural := 0;
      Line   : String (1 .. 1024);
      Last   : Natural;
   begin
      Open (F, In_File, Path);
      while not End_Of_File (F) loop
         Get_Line (F, Line, Last);
         if Len + Last + 1 <= Result'Last then
            Result (Len + 1 .. Len + Last) := Line (1 .. Last);
            Len := Len + Last;
            Result (Len + 1) := ASCII.LF;
            Len := Len + 1;
         end if;
      end loop;
      Close (F);
      return Result (1 .. Len);
   exception
      when others => return "";
   end Read_Text_File;

   procedure Load_Private_Key
     (Path : String;
      Key  : out Private_Key)
   is
      use SPARKTLS.PEM;
      Text : constant String := Read_Text_File (Path);
      R    : Decode_Result;
   begin
      Key := (others => <>);

      if Text'Length = 0 then return; end if;

      Decode (Text, R);
      if not R.OK or else R.Label /= Label_Private_Key then return; end if;

      --  Use Extract_Key logic inline to detect algo and get raw bytes
      --  Check for Ed25519 OID: 06 03 2B 65 70
      if R.DER_Len >= 48
         and then R.DER (7) = 16#06#
         and then R.DER (8) = 16#03#
         and then R.DER (9) = 16#2B#
         and then R.DER (10) = 16#65#
         and then R.DER (11) = 16#70#
      then
         --  Ed25519: seed at offset 16, 32 bytes
         declare
            Seed : Bytes_32;
            SK   : SPARKNaCl.Sign.Signing_SK;
            PK   : SPARKNaCl.Sign.Signing_PK;
            Full : Bytes_64;
            PK_Bytes : Bytes_32;
            PK_X     : X509.Byte_Seq (0 .. 31);
            Algo_Id  : X509.Byte_Seq (0 .. 255) := (others => 0);
            Algo_Id_Len : X509.N32;
         begin
            for I in N32 range 0 .. 31 loop
               Seed (I) := Byte (R.DER (16 + X509.N32 (I)));
            end loop;
            SPARKNaCl.Sign.Keypair (Seed, PK, SK);
            Full := SPARKNaCl.Sign.Serialize (SK);
            PK_Bytes := SPARKNaCl.Sign.Serialize (PK);

            Key.Algo := Algo_Ed25519;
            Key.Raw_Len := 64;
            for I in N32 range 0 .. 63 loop
               Key.Raw (I) := Full (I);
            end loop;

            for I in N32 range 0 .. 31 loop
               PK_X (X509.N32 (I)) := X509.Byte (PK_Bytes (I));
            end loop;
            Build_Algo_Id (Algo_Ed25519, Algo_Id, Algo_Id_Len);
            Build_SPKI (Algo_Id (0 .. Algo_Id_Len - 1),
                        PK_X, Key.SPKI, Key.SPKI_Len);
            Key.Valid := True;
         end;
         return;
      end if;

      --  Check for P-256 OID: 2A 86 48 CE 3D 03 01 07
      declare
         P256_OID : constant X509.Byte_Seq (0 .. 7) :=
           (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#);
      begin
         for Start in X509.N32 range 0 .. R.DER_Len - 8 loop
            if R.DER (Start .. Start + 7) = P256_OID then
               --  Find OCTET STRING containing scalar: 04 20 <32 bytes>
               for J in Start + 8 .. R.DER_Len - 34 loop
                  if R.DER (J) = 16#04# and then R.DER (J + 1) = 16#20# then
                     declare
                        use SPARKTLS.P256.Point;
                        Scalar_N : Byte_Seq (0 .. 31);
                        PK_Jac   : P256_Jacobian;
                        PK_Enc   : Byte_Seq (0 .. 64);
                        PK_X     : X509.Byte_Seq (0 .. 64);
                        Algo_Id  : X509.Byte_Seq (0 .. 255) := (others => 0);
                        Algo_Id_Len : X509.N32;
                     begin
                        Key.Algo := Algo_P256;
                        Key.Raw_Len := 32;
                        for K in N32 range 0 .. 31 loop
                           Key.Raw (K) := Byte (R.DER (J + 2 + X509.N32 (K)));
                           Scalar_N (K) := Byte (R.DER (J + 2 + X509.N32 (K)));
                        end loop;

                        P256_Mulgen (PK_Jac, Scalar_N, 32);
                        P256_To_Affine (PK_Jac);
                        P256_Encode (PK_Enc, PK_Jac);

                        for K in X509.N32 range 0 .. 64 loop
                           PK_X (K) := X509.Byte (PK_Enc (N32 (K)));
                        end loop;

                        Build_Algo_Id (Algo_P256, Algo_Id, Algo_Id_Len);
                        Build_SPKI (Algo_Id (0 .. Algo_Id_Len - 1),
                                    PK_X, Key.SPKI, Key.SPKI_Len);
                        Key.Valid := True;
                     end;
                     return;
                  end if;
               end loop;
            end if;
         end loop;
      end;

      --  Check for P-384 OID: 2B 81 04 00 22
      declare
         P384_OID : constant X509.Byte_Seq (0 .. 4) :=
           (16#2B#, 16#81#, 16#04#, 16#00#, 16#22#);
      begin
         for Start in X509.N32 range 0 .. R.DER_Len - 5 loop
            if R.DER (Start .. Start + 4) = P384_OID then
               for J in Start + 5 .. R.DER_Len - 50 loop
                  if R.DER (J) = 16#04# and then R.DER (J + 1) = 16#30# then
                     declare
                        Scalar_N : Byte_Seq (0 .. 47);
                        PK_Enc   : Byte_Seq (0 .. 96);
                        PK_X     : X509.Byte_Seq (0 .. 96);
                        Algo_Id  : X509.Byte_Seq (0 .. 255) := (others => 0);
                        Algo_Id_Len : X509.N32;
                     begin
                        Key.Algo := Algo_P384;
                        Key.Raw_Len := 48;
                        for K in N32 range 0 .. 47 loop
                           Key.Raw (K) := Byte (R.DER (J + 2 + X509.N32 (K)));
                           Scalar_N (K) := Byte (R.DER (J + 2 + X509.N32 (K)));
                        end loop;

                        SPARKTLS.P384.Point.P384_Mulgen (PK_Enc, Scalar_N);

                        for K in X509.N32 range 0 .. 96 loop
                           PK_X (K) := X509.Byte (PK_Enc (N32 (K)));
                        end loop;

                        Build_Algo_Id (Algo_P384, Algo_Id, Algo_Id_Len);
                        Build_SPKI (Algo_Id (0 .. Algo_Id_Len - 1),
                                    PK_X, Key.SPKI, Key.SPKI_Len);
                        Key.Valid := True;
                     end;
                     return;
                  end if;
               end loop;
            end if;
         end loop;
      end;
   end Load_Private_Key;

end Key_Util;
