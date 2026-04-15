with Ada.Text_IO;
with SPARKNaCl;        use SPARKNaCl;
with SPARKNaCl.Sign;
with SPARKNaCl.Sign.Utils;
with X509;
use type X509.Byte_Seq;
with SPARKTLS.PEM;           use SPARKTLS.PEM;
with SPARKTLS.Cert_Verify;

package body SPARKTLS.Credentials with
   SPARK_Mode => Off
is
   --  Read entire file into a String
   function Read_File (Path : String) return String is
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
   end Read_File;

   --  Extract raw private key bytes from PKCS#8 DER.
   --
   --  Ed25519 PKCS#8: 30 2E 02 01 00 30 05 06 03 2B 65 70 04 22 04 20
   --    <32-byte seed>
   --  We derive the full 64-byte key using SPARKNaCl.Sign.Keypair.
   --
   --  ECDSA P-256 PKCS#8: OID 1.2.840.10045.3.1.7 (secp256r1)
   --    Key is a 32-byte scalar inside an OCTET STRING.
   --
   --  ECDSA P-384 PKCS#8: OID 1.3.132.0.34 (secp384r1)
   --    Key is a 48-byte scalar inside an OCTET STRING.
   procedure Extract_Key
     (DER     : X509.Byte_Seq;
      DER_Len : X509.N32;
      Key_Out : out Byte_Seq;
      Key_Len : out N32;
      OK      : out Boolean)
   is
      use type X509.N32;
      use type X509.Byte;
   begin
      Key_Out := (others => 0);
      Key_Len := 0;
      OK := False;

      if DER_Len < 20 then return; end if;

      --  Check for Ed25519 OID: 06 03 2B 65 70
      --  PKCS#8: SEQUENCE { INTEGER(0), SEQUENCE { OID }, OCTET STRING }
      --  DER layout: 30 2E 02 01 00 30 05 06 03 2B 65 70 04 22 04 20 <seed>
      --  OID tag at offset 7, seed at offset 16
      if DER_Len >= 48
         and then DER (7) = 16#06#
         and then DER (8) = 16#03#
         and then DER (9) = 16#2B#
         and then DER (10) = 16#65#
         and then DER (11) = 16#70#
      then
         --  Ed25519: extract 32-byte seed, derive 64-byte key
         declare
            Seed : Bytes_32;
            SK   : SPARKNaCl.Sign.Signing_SK;
            PK   : SPARKNaCl.Sign.Signing_PK;
            Full : Bytes_64;
         begin
            for I in N32 range 0 .. 31 loop
               Seed (I) := SPARKNaCl.Byte (DER (16 + X509.N32 (I)));
            end loop;
            SPARKNaCl.Sign.Keypair (Seed, PK, SK);
            Full := SPARKNaCl.Sign.Serialize (SK);
            if Key_Out'Length >= 64 then
               Key_Out (Key_Out'First .. Key_Out'First + 63) := Full;
               Key_Len := 64;
               OK := True;
            end if;
         end;
         return;
      end if;

      --  Check for P-256 OID: 06 08 2A 86 48 CE 3D 03 01 07
      --  The 32-byte scalar is in an OCTET STRING after the OID
      declare
         P256_OID : constant X509.Byte_Seq (0 .. 7) :=
           (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#);
      begin
         for Start in X509.N32 range 0 .. DER_Len - 8 loop
            if DER (Start .. Start + 7) = P256_OID then
               --  Find the OCTET STRING containing the key (tag 0x04)
               --  Search after the OID for 04 20 <32 bytes>
               for J in Start + 8 .. DER_Len - 34 loop
                  if DER (J) = 16#04# and then DER (J + 1) = 16#20# then
                     if Key_Out'Length >= 32 then
                        for K in N32 range 0 .. 31 loop
                           Key_Out (Key_Out'First + K) :=
                              SPARKNaCl.Byte (DER (J + 2 + X509.N32 (K)));
                        end loop;
                        Key_Len := 32;
                        OK := True;
                     end if;
                     return;
                  end if;
               end loop;
            end if;
         end loop;
      end;

      --  Check for P-384 OID: 06 05 2B 81 04 00 22
      declare
         P384_OID : constant X509.Byte_Seq (0 .. 4) :=
           (16#2B#, 16#81#, 16#04#, 16#00#, 16#22#);
      begin
         for Start in X509.N32 range 0 .. DER_Len - 5 loop
            if DER (Start .. Start + 4) = P384_OID then
               for J in Start + 5 .. DER_Len - 50 loop
                  if DER (J) = 16#04# and then DER (J + 1) = 16#30# then
                     if Key_Out'Length >= 48 then
                        for K in N32 range 0 .. 47 loop
                           Key_Out (Key_Out'First + K) :=
                              SPARKNaCl.Byte (DER (J + 2 + X509.N32 (K)));
                        end loop;
                        Key_Len := 48;
                        OK := True;
                     end if;
                     return;
                  end if;
               end loop;
            end if;
         end loop;
      end;

      --  Check for RSA OID: 06 09 2A 86 48 86 F7 0D 01 01 01
      --  PKCS#8: SEQUENCE { INT(0), SEQ { OID rsaEncryption, NULL },
      --    OCTET STRING { SEQ { INT(0), INT(n), INT(e), INT(d), ... } } }
      --  Output format: n_len(2 bytes big-endian) || n || d_len(2) || d || e(4)
      declare
         use type X509.N32;
         use type X509.Byte;
         RSA_OID : constant X509.Byte_Seq (0 .. 8) :=
           (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#,
            16#0D#, 16#01#, 16#01#, 16#01#);

         --  Parse ASN.1 length at Pos, return length value and advance Pos
         procedure Parse_ASN1_Length
           (Buf : X509.Byte_Seq;
            Pos : in out X509.N32;
            Len : out X509.N32;
            P_OK : out Boolean)
         is
         begin
            Len := 0;
            P_OK := False;
            if Pos > Buf'Last then return; end if;

            if Buf (Pos) < 16#80# then
               Len := X509.N32 (Buf (Pos));
               Pos := Pos + 1;
               P_OK := True;
            elsif Buf (Pos) = 16#81# then
               if Pos + 1 > Buf'Last then return; end if;
               Len := X509.N32 (Buf (Pos + 1));
               Pos := Pos + 2;
               P_OK := True;
            elsif Buf (Pos) = 16#82# then
               if Pos + 2 > Buf'Last then return; end if;
               Len := X509.N32 (Buf (Pos + 1)) * 256 +
                       X509.N32 (Buf (Pos + 2));
               Pos := Pos + 3;
               P_OK := True;
            end if;
         end Parse_ASN1_Length;

         --  Parse ASN.1 INTEGER, return pointer to value bytes and length
         --  Strips leading zero byte if present (sign padding)
         procedure Parse_ASN1_Integer
           (Buf     : X509.Byte_Seq;
            Pos     : in out X509.N32;
            Val_Pos : out X509.N32;
            Val_Len : out X509.N32;
            P_OK    : out Boolean)
         is
            Raw_Len : X509.N32;
         begin
            Val_Pos := 0;
            Val_Len := 0;
            P_OK := False;
            if Pos > Buf'Last or else Buf (Pos) /= 16#02# then return; end if;
            Pos := Pos + 1;
            Parse_ASN1_Length (Buf, Pos, Raw_Len, P_OK);
            if not P_OK or else Raw_Len = 0 then
               P_OK := False;
               return;
            end if;
            if Pos + Raw_Len - 1 > Buf'Last then
               P_OK := False;
               return;
            end if;
            Val_Pos := Pos;
            Val_Len := Raw_Len;
            --  Strip leading zero (sign padding)
            if Raw_Len > 1 and then Buf (Pos) = 0 then
               Val_Pos := Pos + 1;
               Val_Len := Raw_Len - 1;
            end if;
            Pos := Pos + Raw_Len;
            P_OK := True;
         end Parse_ASN1_Integer;
      begin
         for Start in X509.N32 range 0 .. DER_Len - 9 loop
            if DER (Start .. Start + 8) = RSA_OID then
               --  Found RSA OID. Find the inner RSA private key SEQUENCE.
               --  Skip past OID + NULL param to OCTET STRING containing the key.
               declare
                  Pos  : X509.N32 := Start + 9;
                  Len  : X509.N32;
                  P_OK : Boolean;
                  N_Pos, N_Len : X509.N32;
                  E_Pos, E_Len : X509.N32;
                  D_Pos, D_Len : X509.N32;
                  V_Pos, V_Len : X509.N32;  --  version
               begin
                  --  Skip NULL parameter (05 00) if present
                  if Pos + 1 <= DER'Last
                     and then DER (Pos) = 16#05#
                     and then DER (Pos + 1) = 16#00#
                  then
                     Pos := Pos + 2;
                  end if;

                  --  OCTET STRING tag (04)
                  if Pos > DER'Last or else DER (Pos) /= 16#04# then
                     goto RSA_Done;
                  end if;
                  Pos := Pos + 1;
                  Parse_ASN1_Length (DER, Pos, Len, P_OK);
                  if not P_OK then goto RSA_Done; end if;

                  --  Inner SEQUENCE tag (30)
                  if Pos > DER'Last or else DER (Pos) /= 16#30# then
                     goto RSA_Done;
                  end if;
                  Pos := Pos + 1;
                  Parse_ASN1_Length (DER, Pos, Len, P_OK);
                  if not P_OK then goto RSA_Done; end if;

                  --  version INTEGER (should be 0)
                  Parse_ASN1_Integer (DER, Pos, V_Pos, V_Len, P_OK);
                  if not P_OK then goto RSA_Done; end if;

                  --  modulus n
                  Parse_ASN1_Integer (DER, Pos, N_Pos, N_Len, P_OK);
                  if not P_OK or else N_Len < 64 or else N_Len > 512 then
                     goto RSA_Done;
                  end if;

                  --  public exponent e
                  Parse_ASN1_Integer (DER, Pos, E_Pos, E_Len, P_OK);
                  if not P_OK or else E_Len = 0 or else E_Len > 4 then
                     goto RSA_Done;
                  end if;

                  --  private exponent d
                  Parse_ASN1_Integer (DER, Pos, D_Pos, D_Len, P_OK);
                  if not P_OK or else D_Len < 64 or else D_Len > 512 then
                     goto RSA_Done;
                  end if;

                  --  Pack output: n_len(2) || n || d_len(2) || d || e(4)
                  declare
                     Total : constant N32 :=
                        2 + N32 (N_Len) + 2 + N32 (D_Len) + 4;
                     Out_Pos : N32 := Key_Out'First;
                  begin
                     if Total > N32 (Key_Out'Length) then
                        goto RSA_Done;
                     end if;

                     --  n_len (2 bytes big-endian)
                     Key_Out (Out_Pos) :=
                        SPARKNaCl.Byte (N_Len / 256);
                     Key_Out (Out_Pos + 1) :=
                        SPARKNaCl.Byte (N_Len mod 256);
                     Out_Pos := Out_Pos + 2;

                     --  n bytes
                     for I in X509.N32 range 0 .. N_Len - 1 loop
                        Key_Out (Out_Pos + N32 (I)) :=
                           SPARKNaCl.Byte (DER (N_Pos + I));
                     end loop;
                     Out_Pos := Out_Pos + N32 (N_Len);

                     --  d_len (2 bytes big-endian)
                     Key_Out (Out_Pos) :=
                        SPARKNaCl.Byte (D_Len / 256);
                     Key_Out (Out_Pos + 1) :=
                        SPARKNaCl.Byte (D_Len mod 256);
                     Out_Pos := Out_Pos + 2;

                     --  d bytes
                     for I in X509.N32 range 0 .. D_Len - 1 loop
                        Key_Out (Out_Pos + N32 (I)) :=
                           SPARKNaCl.Byte (DER (D_Pos + I));
                     end loop;
                     Out_Pos := Out_Pos + N32 (D_Len);

                     --  e (4 bytes big-endian, zero-padded)
                     Key_Out (Out_Pos .. Out_Pos + 3) := (others => 0);
                     for I in X509.N32 range 0 .. E_Len - 1 loop
                        Key_Out (Out_Pos + N32 (4 - E_Len) + N32 (I)) :=
                           SPARKNaCl.Byte (DER (E_Pos + I));
                     end loop;

                     Key_Len := N32 (Total);
                     OK := True;
                  end;
                  return;
               end;
            end if;
         end loop;
         <<RSA_Done>>
         null;
      end;
   end Extract_Key;

   procedure Load_Identity_PEM
     (Id       : out Identity;
      Cert_PEM : String;
      Key_PEM  : String;
      OK       : out Boolean)
   is
      Cert_Result : PEM.Decode_Result;
      Key_Result  : PEM.Decode_Result;
      Key_Buf     : Byte_Seq (0 .. 1099) := (others => 0);
      Key_Len     : N32;
      Key_OK      : Boolean;
      Set_OK      : Boolean;
      First_Cert  : Boolean := True;
      Pos         : Positive;
   begin
      Id := (others => <>);
      OK := False;

      --  Decode certs (first = leaf, rest = intermediates)
      Pos := Cert_PEM'First;
      while Pos <= Cert_PEM'Last loop
         declare
            Begin_Marker : constant String := "-----BEGIN ";
            Found : Boolean := False;
         begin
            while Pos + Begin_Marker'Length - 1 <= Cert_PEM'Last loop
               if Cert_PEM (Pos .. Pos + Begin_Marker'Length - 1) =
                  Begin_Marker
               then
                  Found := True;
                  exit;
               end if;
               Pos := Pos + 1;
            end loop;
            if not Found then exit; end if;
         end;

         PEM.Decode (Cert_PEM (Pos .. Cert_PEM'Last), Cert_Result);

         if Cert_Result.OK
            and then Cert_Result.Label = PEM.Label_Certificate
         then
            if First_Cert then
               --  This becomes the leaf; we'll set identity with key below
               First_Cert := False;
            else
               --  Intermediate
               declare
                  Int_OK : Boolean;
               begin
                  Cert_Verify.Add_Intermediate
                    (Id,
                     Cert_Result.DER (0 .. Cert_Result.DER_Len - 1),
                     Int_OK);
               end;
            end if;
         end if;

         --  Skip past END marker
         declare
            End_Marker : constant String := "-----END ";
         begin
            while Pos + End_Marker'Length - 1 <= Cert_PEM'Last loop
               if Cert_PEM (Pos .. Pos + End_Marker'Length - 1) =
                  End_Marker
               then
                  while Pos <= Cert_PEM'Last
                     and then Cert_PEM (Pos) /= ASCII.LF
                  loop
                     Pos := Pos + 1;
                  end loop;
                  exit;
               end if;
               Pos := Pos + 1;
            end loop;
         end;
         Pos := Pos + 1;
      end loop;

      --  Decode private key
      PEM.Decode (Key_PEM, Key_Result);
      if not Key_Result.OK
         or else Key_Result.Label /= PEM.Label_Private_Key
      then
         return;
      end if;

      --  Extract raw key bytes from PKCS#8 DER
      Extract_Key (Key_Result.DER, Key_Result.DER_Len,
                   Key_Buf, Key_Len, Key_OK);
      if not Key_OK or Key_Len = 0 then
         return;
      end if;

      --  Now decode the first cert again for Set_Identity
      PEM.Decode (Cert_PEM, Cert_Result);
      if not Cert_Result.OK then
         return;
      end if;

      Cert_Verify.Set_Identity
        (Id,
         Cert_Result.DER (0 .. Cert_Result.DER_Len - 1),
         Key_Buf (0 .. Key_Len - 1),
         Set_OK);

      OK := Set_OK;
   end Load_Identity_PEM;

   procedure Load_Identity
     (Id        : out Identity;
      Cert_Path : String;
      Key_Path  : String;
      OK        : out Boolean)
   is
      Cert_Text : constant String := Read_File (Cert_Path);
      Key_Text  : constant String := Read_File (Key_Path);
   begin
      Id := (others => <>);
      OK := False;

      if Cert_Text'Length = 0 or Key_Text'Length = 0 then
         return;
      end if;

      Load_Identity_PEM (Id, Cert_Text, Key_Text, OK);
   end Load_Identity;

end SPARKTLS.Credentials;
