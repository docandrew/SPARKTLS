with SPARKTLSCrypto.Ed25519;
use SPARKTLSCrypto;
with SPARKTLS.PEM; use SPARKTLS.PEM;
with SPARKTLS.Cert_Verify;

package body SPARKTLS.Credentials.Parsing
  with SPARK_Mode => On
is
   use type X509.N32;
   use type X509.Byte;
   use type X509.Byte_Seq;

   --  Parse ASN.1 length at Pos, return length value and advance Pos
   procedure Parse_ASN1_Length
     (Buf : X509.Byte_Seq; Pos : in out X509.N32; Len : out X509.N32; P_OK : out Boolean)
   with
     Pre => Buf'First = 0 and Buf'Last < X509.N32'Last,
     Post => (if P_OK then Pos in Pos'Old + 1 .. Buf'Last + 1 and Len <= 65535)
   is
   begin
      Len := 0;
      P_OK := False;
      if Pos > Buf'Last then
         return;
      end if;

      if Buf (Pos) < 16#80# then
         Len := X509.N32 (Buf (Pos));
         Pos := Pos + 1;
         P_OK := True;
      elsif Buf (Pos) = 16#81# then
         if Buf'Last - Pos < 1 then
            return;
         end if;
         Len := X509.N32 (Buf (Pos + 1));
         Pos := Pos + 2;
         P_OK := True;
      elsif Buf (Pos) = 16#82# then
         if Buf'Last - Pos < 2 then
            return;
         end if;
         Len := X509.N32 (Buf (Pos + 1)) * 256 + X509.N32 (Buf (Pos + 2));
         Pos := Pos + 3;
         P_OK := True;
      end if;
   end Parse_ASN1_Length;

   --  Parse ASN.1 INTEGER, return pointer to value bytes and length.
   --  Strips leading zero byte if present (sign padding).
   procedure Parse_ASN1_Integer
     (Buf     : X509.Byte_Seq;
      Pos     : in out X509.N32;
      Val_Pos : out X509.N32;
      Val_Len : out X509.N32;
      P_OK    : out Boolean)
   with
     Pre => Buf'First = 0 and Buf'Last < X509.N32'Last,
     Post =>
       (if P_OK
        then
          Val_Len > 0
          and Val_Pos in 0 .. Buf'Last
          and Val_Len <= Buf'Last - Val_Pos + 1
          and Pos <= Buf'Last + 1)
   is
      Raw_Len : X509.N32;
   begin
      Val_Pos := 0;
      Val_Len := 0;
      P_OK := False;
      if Pos > Buf'Last or else Buf (Pos) /= 16#02# then
         return;
      end if;
      Pos := Pos + 1;
      Parse_ASN1_Length (Buf, Pos, Raw_Len, P_OK);
      if not P_OK or else Raw_Len = 0 then
         P_OK := False;
         return;
      end if;
      if Pos > Buf'Last or else Buf'Last - Pos < Raw_Len - 1 then
         P_OK := False;
         return;
      end if;
      pragma Assert (Pos + Raw_Len <= Buf'Last + 1);
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

   --  Extract RSA key from PKCS#8 DER starting at OID match position.
   --  Separated to avoid goto  returns on any parse failure.
   procedure Extract_RSA_Key
     (DER     : X509.Byte_Seq;
      Start   : X509.N32;
      Key_Out : in out Byte_Seq;
      Key_Len : out N32;
      OK      : out Boolean)
   with
     Pre =>
       DER'First = 0
       and DER'Last < X509.N32'Last
       and Key_Out'First = 0
       and Key_Out'Last < N32'Last
       and Start + 9 <= DER'Last,
     Post => (if OK then Key_Len in 1 .. Key_Out'Last + 1)
   is
      Pos          : X509.N32 := Start + 9;
      Len          : X509.N32;
      P_OK         : Boolean;
      N_Pos, N_Len : X509.N32;
      E_Pos, E_Len : X509.N32;
      D_Pos, D_Len : X509.N32;
      V_Pos, V_Len : X509.N32;
   begin
      Key_Len := 0;
      OK := False;

      --  Skip NULL parameter (05 00) if present
      if Pos + 1 <= DER'Last and then DER (Pos) = 16#05# and then DER (Pos + 1) = 16#00# then
         Pos := Pos + 2;
      end if;

      --  OCTET STRING tag (04)
      if Pos > DER'Last or else DER (Pos) /= 16#04# then
         return;
      end if;
      Pos := Pos + 1;
      Parse_ASN1_Length (DER, Pos, Len, P_OK);
      if not P_OK then
         return;
      end if;
      if Len = 0 or else Pos > DER'Last or else Len > DER'Last - Pos + 1 then
         return;
      end if;

      --  Inner SEQUENCE tag (30)
      if Pos > DER'Last or else DER (Pos) /= 16#30# then
         return;
      end if;
      Pos := Pos + 1;
      Parse_ASN1_Length (DER, Pos, Len, P_OK);
      if not P_OK then
         return;
      end if;
      if Len = 0 or else Pos > DER'Last or else Len > DER'Last - Pos + 1 then
         return;
      end if;

      --  version INTEGER (should be 0)
      Parse_ASN1_Integer (DER, Pos, V_Pos, V_Len, P_OK);
      if not P_OK or else V_Len /= 1 or else DER (V_Pos) /= 0 then
         return;
      end if;

      --  modulus n
      Parse_ASN1_Integer (DER, Pos, N_Pos, N_Len, P_OK);
      if not P_OK or else N_Len < 64 or else N_Len > 512 then
         return;
      end if;

      --  public exponent e
      Parse_ASN1_Integer (DER, Pos, E_Pos, E_Len, P_OK);
      if not P_OK or else E_Len = 0 or else E_Len > 4 then
         return;
      end if;

      --  private exponent d
      declare
         Ignored_Pos : X509.N32 := Pos;
      begin
         Parse_ASN1_Integer (DER, Ignored_Pos, D_Pos, D_Len, P_OK);
      end;
      if not P_OK or else D_Len < 64 or else D_Len > 512 then
         return;
      end if;

      --  Pack output: n_len(2) || n || d_len(2) || d || e(4)
      declare
         Total   : constant N32 := 2 + N32 (N_Len) + 2 + N32 (D_Len) + 4;
         Out_Pos : N32 := Key_Out'First;
      begin
         if Total > N32 (Key_Out'Length) then
            return;
         end if;

         --  n_len (2 bytes big-endian)
         Key_Out (Out_Pos) := SPARKNaCl.Byte (N_Len / 256);
         Key_Out (Out_Pos + 1) := SPARKNaCl.Byte (N_Len mod 256);
         Out_Pos := Out_Pos + 2;

         --  n bytes
         for I in X509.N32 range 0 .. N_Len - 1 loop
            Key_Out (Out_Pos + N32 (I)) := SPARKNaCl.Byte (DER (N_Pos + I));
         end loop;
         Out_Pos := Out_Pos + N32 (N_Len);

         --  d_len (2 bytes big-endian)
         Key_Out (Out_Pos) := SPARKNaCl.Byte (D_Len / 256);
         Key_Out (Out_Pos + 1) := SPARKNaCl.Byte (D_Len mod 256);
         Out_Pos := Out_Pos + 2;

         --  d bytes
         for I in X509.N32 range 0 .. D_Len - 1 loop
            Key_Out (Out_Pos + N32 (I)) := SPARKNaCl.Byte (DER (D_Pos + I));
         end loop;
         Out_Pos := Out_Pos + N32 (D_Len);

         --  e (4 bytes big-endian, zero-padded)
         Key_Out (Out_Pos .. Out_Pos + 3) := (others => 0);
         for I in X509.N32 range 0 .. E_Len - 1 loop
            Key_Out (Out_Pos + N32 (4 - E_Len) + N32 (I)) := SPARKNaCl.Byte (DER (E_Pos + I));
         end loop;

         Key_Len := N32 (Total);
         OK := True;
      end;
   end Extract_RSA_Key;

   ----------------------------------------------------------------------------
   --  Extract_Key
   ----------------------------------------------------------------------------

   procedure Extract_Key
     (DER     : X509.Byte_Seq;
      DER_Len : X509.N32;
      Key_Out : out Byte_Seq;
      Key_Len : out N32;
      OK      : out Boolean) is
   begin
      Key_Out := (others => 0);
      Key_Len := 0;
      OK := False;

      if DER_Len < 20 then
         return;
      end if;

      --  Ed25519 OID: 06 03 2B 65 70
      if DER_Len >= 48
        and then DER (7) = 16#06#
        and then DER (8) = 16#03#
        and then DER (9) = 16#2B#
        and then DER (10) = 16#65#
        and then DER (11) = 16#70#
      then
         declare
            Seed       : Bytes_32;
            SK         : Bytes_64;
            Ignored_PK : Bytes_32;
         begin
            for I in N32 range 0 .. 31 loop
               Seed (I) := SPARKNaCl.Byte (DER (16 + X509.N32 (I)));
            end loop;
            SPARKTLSCrypto.Ed25519.Keypair (Seed, Ignored_PK, SK);
            if Key_Out'Length >= 64 then
               Key_Out (Key_Out'First .. Key_Out'First + 63) := SK;
               Key_Len := 64;
               OK := True;
            end if;
         end;
         return;
      end if;

      --  P-256 OID: 06 08 2A 86 48 CE 3D 03 01 07
      if DER_Len >= 34 then
         declare
            P256_OID : constant X509.Byte_Seq (0 .. 7) :=
              (16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#);
         begin
            for Start in X509.N32 range 0 .. DER_Len - 8 loop
               if DER (Start .. Start + 7) = P256_OID then
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
      end if;

      --  P-384 OID: 06 05 2B 81 04 00 22
      if DER_Len >= 50 then
         declare
            P384_OID : constant X509.Byte_Seq (0 .. 4) := (16#2B#, 16#81#, 16#04#, 16#00#, 16#22#);
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
      end if;

      --  RSA OID: 06 09 2A 86 48 86 F7 0D 01 01 01
      declare
         RSA_OID : constant X509.Byte_Seq (0 .. 8) :=
           (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#, 16#01#);
      begin
         for Start in X509.N32 range 0 .. DER_Len - 9 loop
            if DER (Start .. Start + 8) = RSA_OID then
               if Start + 9 <= DER'Last then
                  Extract_RSA_Key (DER, Start, Key_Out, Key_Len, OK);
               end if;
               return;
            end if;
         end loop;
      end;
   end Extract_Key;

   ----------------------------------------------------------------------------
   --  Load_Identity_PEM
   ----------------------------------------------------------------------------

   procedure Load_Identity_PEM
     (Id : out Identity; Cert_PEM : String; Key_PEM : String; OK : out Boolean)
   is
      Cert_Result : PEM.Decode_Result;
      Key_Result  : PEM.Decode_Result;
      Key_Buf     : Byte_Seq (0 .. 1099);
      Key_Len     : N32;
      Key_OK      : Boolean;
      Set_OK      : Boolean;
      Pos         : Positive;
   begin
      --  Set_Identity is the only entry point that fully initializes Id.
      --  We must call it BEFORE any Add_Intermediate so SPARK sees Id
      --  as initialized for the rest of the procedure. To do that we
      --  parse + decode in this order:
      --    1. Decode private key from Key_PEM
      --    2. Extract raw key bytes
      --    3. Decode the leaf cert (first PEM block) from Cert_PEM
      --    4. Set_Identity (Id, leaf_DER, key)  Id now Initialized
      --    5. Walk Cert_PEM picking up additional cert blocks and
      --       passing each to Add_Intermediate.
      OK := False;
      --  Initialize a fresh Identity locally and assign so SPARK sees
      --  every field as set on every return path.
      declare
         Default_Id : Identity;
      begin
         Id := Default_Id;
      end;

      if Cert_PEM'Length = 0 or Key_PEM'Length = 0 then
         return;
      end if;

      --  1+2: Decode key, extract raw bytes
      PEM.Decode (Key_PEM, Key_Result);
      if not Key_Result.OK or else Key_Result.Label /= PEM.Label_Private_Key then
         return;
      end if;
      Extract_Key (Key_Result.DER, Key_Result.DER_Len, Key_Buf, Key_Len, Key_OK);
      if not Key_OK or Key_Len = 0 then
         return;
      end if;

      --  3: Decode leaf cert (first PEM block of Cert_PEM)
      PEM.Decode (Cert_PEM, Cert_Result);
      if not Cert_Result.OK or else Cert_Result.Label /= PEM.Label_Certificate then
         return;
      end if;

      --  4: Initialize Id with leaf cert and key
      Cert_Verify.Set_Identity
        (Id, Cert_Result.DER (0 .. Cert_Result.DER_Len - 1), Key_Buf (0 .. Key_Len - 1), Set_OK);
      if not Set_OK then
         return;
      end if;

      --  5: Walk remaining cert blocks â Add_Intermediate.
      --  Find the first END marker so we skip the leaf cert we already
      --  consumed, then iterate.
      Pos := Cert_PEM'First;
      declare
         End_Marker : constant String := "-----END ";
      begin
         --  Skip past leaf's END marker line
         while Pos + End_Marker'Length - 1 <= Cert_PEM'Last loop
            pragma Loop_Invariant (Pos in Cert_PEM'First .. Cert_PEM'Last);
            if Cert_PEM (Pos .. Pos + End_Marker'Length - 1) = End_Marker then
               --  Skip to end of this line
               while Pos <= Cert_PEM'Last and then Cert_PEM (Pos) /= ASCII.LF loop
                  pragma Loop_Invariant (Pos in Cert_PEM'First .. Cert_PEM'Last);
                  if Pos = Cert_PEM'Last then
                     exit;
                  end if;
                  Pos := Pos + 1;
               end loop;
               exit;
            end if;
            if Pos = Cert_PEM'Last then
               exit;
            end if;
            Pos := Pos + 1;
         end loop;
      end;

      while Pos < Cert_PEM'Last loop
         pragma Loop_Invariant (Pos in Cert_PEM'First .. Cert_PEM'Last);
         Pos := Pos + 1;
         declare
            Begin_Marker : constant String := "-----BEGIN ";
            Found        : Boolean := False;
         begin
            while Pos + Begin_Marker'Length - 1 <= Cert_PEM'Last loop
               pragma Loop_Invariant (Pos in Cert_PEM'First .. Cert_PEM'Last);
               if Cert_PEM (Pos .. Pos + Begin_Marker'Length - 1) = Begin_Marker then
                  Found := True;
                  exit;
               end if;
               if Pos = Cert_PEM'Last then
                  exit;
               end if;
               Pos := Pos + 1;
            end loop;
            exit when not Found;
         end;

         PEM.Decode (Cert_PEM (Pos .. Cert_PEM'Last), Cert_Result);
         if Cert_Result.OK and then Cert_Result.Label = PEM.Label_Certificate then
            declare
               Ignored_Int_OK : Boolean;
            begin
               Cert_Verify.Add_Intermediate
                 (Id, Cert_Result.DER (0 .. Cert_Result.DER_Len - 1), Ignored_Int_OK);
            end;
         end if;

         --  Advance past this cert's END marker
         declare
            End_Marker : constant String := "-----END ";
         begin
            while Pos + End_Marker'Length - 1 <= Cert_PEM'Last loop
               pragma Loop_Invariant (Pos in Cert_PEM'First .. Cert_PEM'Last);
               if Cert_PEM (Pos .. Pos + End_Marker'Length - 1) = End_Marker then
                  while Pos <= Cert_PEM'Last and then Cert_PEM (Pos) /= ASCII.LF loop
                     pragma Loop_Invariant (Pos in Cert_PEM'First .. Cert_PEM'Last);
                     if Pos = Cert_PEM'Last then
                        exit;
                     end if;
                     Pos := Pos + 1;
                  end loop;
                  exit;
               end if;
               if Pos = Cert_PEM'Last then
                  exit;
               end if;
               Pos := Pos + 1;
            end loop;
         end;
      end loop;

      OK := True;
   end Load_Identity_PEM;

end SPARKTLS.Credentials.Parsing;
