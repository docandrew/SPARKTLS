with Ada.Calendar;
with SPARKNaCl.Sign;
with SPARKNaCl.Sign.Utils;
with SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P384.ECDSA;
with SPARKEntropy;

package body Cert_Builder is
   use type X509.Byte;
   use type SPARKNaCl.N32;
   use DER_Builder;

   --  Entropy for serial number and ECDSA nonce
   Entropy : SPARKEntropy.Entropy_State;
   Entropy_Ready : Boolean := False;

   procedure Ensure_Entropy is
      OK : Boolean;
   begin
      if not Entropy_Ready then
         SPARKEntropy.Init (Entropy, OK);
         Entropy_Ready := OK;
      end if;
   end Ensure_Entropy;

   procedure Get_Random (Output : out X509.Byte_Seq) is
      Buf : SPARKEntropy.Byte_Seq (0 .. Output'Length - 1);
      OK  : Boolean;
   begin
      SPARKEntropy.Generate (Entropy, Buf, OK);
      for I in Output'Range loop
         Output (I) := X509.Byte (Buf (Natural (I - Output'First)));
      end loop;
   end Get_Random;

   --  Get current time as X509.Date_Time
   function Now return X509.Date_Time is
      use Ada.Calendar;
      T : constant Time := Clock;
      Y : Year_Number;
      M : Month_Number;
      D : Day_Number;
      S : Day_Duration;
   begin
      Split (T, Y, M, D, S);
      return (Year   => Y, Month => M, Day => D,
              Hour   => Natural (S) / 3600,
              Minute => (Natural (S) mod 3600) / 60,
              Second => Natural (S) mod 60);
   end Now;

   --  Add days to a Date_Time (simplified, month-aware)
   function Add_Days (DT : X509.Date_Time; Days : Natural)
      return X509.Date_Time
   is
      type Month_Days is array (1 .. 12) of Natural;
      MD : constant Month_Days :=
        (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);
      R  : X509.Date_Time := DT;
      Remaining : Natural := Days;
   begin
      while Remaining > 0 loop
         declare
            Days_In_Month : Natural := MD (R.Month);
         begin
            --  Leap year February
            if R.Month = 2 and then
               (R.Year mod 4 = 0 and then
                (R.Year mod 100 /= 0 or else R.Year mod 400 = 0))
            then
               Days_In_Month := 29;
            end if;

            declare
               Left_In_Month : constant Natural :=
                  Days_In_Month - R.Day;
            begin
               if Remaining <= Left_In_Month then
                  R.Day := R.Day + Remaining;
                  Remaining := 0;
               else
                  Remaining := Remaining - Left_In_Month - 1;
                  R.Day := 1;
                  if R.Month = 12 then
                     R.Month := 1;
                     R.Year := R.Year + 1;
                  else
                     R.Month := R.Month + 1;
                  end if;
               end if;
            end;
         end;
      end loop;
      return R;
   end Add_Days;

   --  Write a DN (SEQUENCE of RDNs)
   procedure Put_DN
     (Buf : in out DER_Buffer;
      Pos : in out X509.N32;
      D   : DN)
   is
      Seq : X509.N32;
   begin
      Start_Sequence (Buf, Pos, Seq);
      if D.CN_Len > 0 then
         Put_RDN (Buf, Pos, X509.Byte_Seq (OID_Common_Name),
                  D.CN (1 .. D.CN_Len));
      end if;
      if D.Org_Len > 0 then
         Put_RDN (Buf, Pos, X509.Byte_Seq (OID_Organization),
                  D.Org (1 .. D.Org_Len));
      end if;
      End_Sequence (Buf, Pos, Seq);
   end Put_DN;

   --  Signature algorithm OID SEQUENCE for a given key type
   procedure Put_Sig_Algorithm
     (Buf  : in out DER_Buffer;
      Pos  : in out X509.N32;
      Algo : Key_Util.Key_Algorithm)
   is
      Seq : X509.N32;
   begin
      Start_Sequence (Buf, Pos, Seq);
      case Algo is
         when Key_Util.Algo_Ed25519 =>
            Put_OID (Buf, Pos, X509.Byte_Seq (OID_Ed25519_Sig));
         when Key_Util.Algo_P256 =>
            Put_OID (Buf, Pos, X509.Byte_Seq (OID_SHA256_With_ECDSA));
         when Key_Util.Algo_P384 =>
            Put_OID (Buf, Pos, X509.Byte_Seq (OID_SHA384_With_ECDSA));
      end case;
      End_Sequence (Buf, Pos, Seq);
   end Put_Sig_Algorithm;

   --  ECDSA signature (R, S) to DER SEQUENCE { INTEGER, INTEGER }
   procedure ECDSA_To_DER
     (R_Raw, S_Raw : Byte_Seq;
      Half_Len     : N32;
      DER_Out      : out X509.Byte_Seq;
      DER_Len      : out X509.N32)
   is
      procedure Write_Int
        (Src : Byte_Seq; Buf : in out DER_Buffer; Pos : in out X509.N32)
      is
         Skip : N32 := 0;
         Pad  : Boolean;
      begin
         while Skip < Half_Len - 1 and then Src (Src'First + Skip) = 0 loop
            Skip := Skip + 1;
         end loop;
         Pad := Src (Src'First + Skip) >= 128;
         Put_Byte (Buf, Pos, TAG_INTEGER);
         Put_Length (Buf, Pos, X509.N32 (Half_Len - Skip) + (if Pad then 1 else 0));
         if Pad then Put_Byte (Buf, Pos, 0); end if;
         for I in Skip .. N32 (Half_Len) - 1 loop
            Put_Byte (Buf, Pos, X509.Byte (Src (Src'First + I)));
         end loop;
      end Write_Int;

      Buf : DER_Buffer := (others => 0);
      Pos : X509.N32 := 0;
      Seq : X509.N32;
   begin
      DER_Out := (others => 0);
      Start_Sequence (Buf, Pos, Seq);
      Write_Int (R_Raw, Buf, Pos);
      Write_Int (S_Raw, Buf, Pos);
      End_Sequence (Buf, Pos, Seq);
      DER_Len := Pos;
      DER_Out (0 .. Pos - 1) := X509.Byte_Seq (Buf (0 .. Pos - 1));
   end ECDSA_To_DER;

   --  Parse a comma-separated SAN string and detect DNS vs IP
   function Is_IP_Address (S : String) return Boolean is
      Dots : Natural := 0;
      Colons : Natural := 0;
   begin
      for C of S loop
         if C = '.' then Dots := Dots + 1; end if;
         if C = ':' then Colons := Colons + 1; end if;
      end loop;
      --  IPv4: exactly 3 dots, all digits and dots
      if Dots = 3 then
         for C of S loop
            if C not in '0' .. '9' | '.' then return False; end if;
         end loop;
         return True;
      end if;
      --  IPv6: contains colons
      return Colons > 0;
   end Is_IP_Address;

   --  Parse IPv4 "a.b.c.d" to 4 bytes
   procedure Parse_IPv4
     (S    : String;
      Addr : out X509.Byte_Seq;
      OK   : out Boolean)
   is
      Pos : Natural := S'First;
      Octet : Natural := 0;
      Idx : X509.N32 := 0;
   begin
      Addr := (others => 0);
      OK := False;
      for I in S'Range loop
         if S (I) in '0' .. '9' then
            Octet := Octet * 10 + (Character'Pos (S (I)) - Character'Pos ('0'));
            if Octet > 255 then return; end if;
         elsif S (I) = '.' then
            if Idx > 2 then return; end if;
            Addr (Idx) := X509.Byte (Octet);
            Idx := Idx + 1;
            Octet := 0;
         else
            return;
         end if;
      end loop;
      if Idx = 3 then
         Addr (3) := X509.Byte (Octet);
         OK := True;
      end if;
   end Parse_IPv4;

   procedure Build_Certificate
     (Params   : Cert_Params;
      Cert_DER : out Cert_DER_Buf;
      Cert_Len : out X509.N32;
      OK       : out Boolean)
   is
      TBS_Buf : DER_Buffer := (others => 0);
      TBS_Pos : X509.N32 := 0;
      Cert_Buf : DER_Buffer := (others => 0);
      Cert_Pos : X509.N32 := 0;

      Not_Before : constant X509.Date_Time := Now;
      Not_After  : constant X509.Date_Time :=
         Add_Days (Not_Before, Params.Valid_Days);

      Serial : X509.Byte_Seq (0 .. 19) := (others => 0);
   begin
      Cert_DER := (others => 0);
      Cert_Len := 0;
      OK := False;

      if not Params.Key.Valid then return; end if;

      Ensure_Entropy;
      if not Entropy_Ready then return; end if;

      --  Generate random serial number (20 bytes, high bit clear)
      Get_Random (Serial);
      Serial (0) := Serial (0) and 16#7F#;  --  must be positive

      --  ====== Build TBSCertificate ======
      declare
         TBS_Seq   : X509.N32;
         Ver_Ctx   : X509.N32;
         Ext_Ctx   : X509.N32;
         Ext_Seq   : X509.N32;
         Val_Seq   : X509.N32;
      begin
         Start_Sequence (TBS_Buf, TBS_Pos, TBS_Seq);

         --  version [0] EXPLICIT INTEGER (2 = v3)
         Start_Context (TBS_Buf, TBS_Pos, 0, Ver_Ctx);
         Put_Small_Integer (TBS_Buf, TBS_Pos, 2);
         End_Context (TBS_Buf, TBS_Pos, Ver_Ctx);

         --  serialNumber INTEGER
         Put_Integer (TBS_Buf, TBS_Pos, Serial);

         --  signature AlgorithmIdentifier
         Put_Sig_Algorithm (TBS_Buf, TBS_Pos, Params.Key.Algo);

         --  issuer Name
         Put_DN (TBS_Buf, TBS_Pos, Params.Issuer);

         --  validity Validity { notBefore, notAfter }
         Start_Sequence (TBS_Buf, TBS_Pos, Val_Seq);
         if Not_Before.Year < 2050 then
            Put_UTC_Time (TBS_Buf, TBS_Pos, Not_Before);
         else
            Put_Generalized_Time (TBS_Buf, TBS_Pos, Not_Before);
         end if;
         if Not_After.Year < 2050 then
            Put_UTC_Time (TBS_Buf, TBS_Pos, Not_After);
         else
            Put_Generalized_Time (TBS_Buf, TBS_Pos, Not_After);
         end if;
         End_Sequence (TBS_Buf, TBS_Pos, Val_Seq);

         --  subject Name
         Put_DN (TBS_Buf, TBS_Pos, Params.Subject);

         --  subjectPublicKeyInfo (pre-built SPKI DER)
         Put_Bytes (TBS_Buf, TBS_Pos,
                    Params.SPKI (0 .. Params.SPKI_Len - 1));

         --  extensions [3] EXPLICIT SEQUENCE { ... }
         Start_Context (TBS_Buf, TBS_Pos, 3, Ext_Ctx);
         Start_Sequence (TBS_Buf, TBS_Pos, Ext_Seq);

         --  Basic Constraints (critical)
         declare
            Ext_S, Ext_V_Seq, BC_Seq : X509.N32;
            BC_Buf : DER_Buffer := (others => 0);
            BC_Pos : X509.N32 := 0;
         begin
            --  Build the BC value: SEQUENCE { BOOLEAN CA }
            Start_Sequence (BC_Buf, BC_Pos, BC_Seq);
            if Params.Is_CA then
               Put_Byte (BC_Buf, BC_Pos, 16#01#);  --  BOOLEAN tag
               Put_Byte (BC_Buf, BC_Pos, 16#01#);  --  length 1
               Put_Byte (BC_Buf, BC_Pos, 16#FF#);  --  TRUE
            end if;
            End_Sequence (BC_Buf, BC_Pos, BC_Seq);

            --  Extension SEQUENCE { OID, BOOLEAN critical, OCTET STRING value }
            Start_Sequence (TBS_Buf, TBS_Pos, Ext_S);
            Put_OID (TBS_Buf, TBS_Pos, X509.Byte_Seq (OID_Basic_Constraints));
            --  critical = TRUE
            Put_Byte (TBS_Buf, TBS_Pos, 16#01#);  --  BOOLEAN tag
            Put_Byte (TBS_Buf, TBS_Pos, 16#01#);  --  length 1
            Put_Byte (TBS_Buf, TBS_Pos, 16#FF#);  --  TRUE
            Put_Octet_String (TBS_Buf, TBS_Pos,
               X509.Byte_Seq (BC_Buf (0 .. BC_Pos - 1)));
            End_Sequence (TBS_Buf, TBS_Pos, Ext_S);
         end;

         --  Key Usage (critical) — always present.
         --  RFC 5280 §4.2.1.3 BIT STRING bit positions (MSB first):
         --    bit 0 = digitalSignature
         --    bit 5 = keyCertSign
         --    bit 6 = cRLSign
         --  Self-signed dev cert (Is_CA): digitalSignature +
         --  keyCertSign + cRLSign → byte 0x86, 1 unused bit. The
         --  leaf bit (digitalSignature) is required for TLS 1.3
         --  CertificateVerify; without it our own client rejects
         --  the cert with bad_certificate even with --skip-verify
         --  (RFC 8446 §4.4.2.4 / §9.4 mandates the check).
         --  Non-CA leaf: digitalSignature only → byte 0x80, 7
         --  unused bits.
         declare
            Ext_S    : X509.N32;
            KU_Value : constant X509.Byte_Seq (0 .. 3) :=
              (if Params.Is_CA
               then (16#03#, 16#02#, 16#01#, 16#86#)
               else (16#03#, 16#02#, 16#07#, 16#80#));
         begin
            Start_Sequence (TBS_Buf, TBS_Pos, Ext_S);
            Put_OID (TBS_Buf, TBS_Pos, X509.Byte_Seq (OID_Key_Usage));
            Put_Byte (TBS_Buf, TBS_Pos, 16#01#);  --  BOOLEAN tag
            Put_Byte (TBS_Buf, TBS_Pos, 16#01#);  --  length 1
            Put_Byte (TBS_Buf, TBS_Pos, 16#FF#);  --  critical = TRUE
            Put_Octet_String (TBS_Buf, TBS_Pos, KU_Value);
            End_Sequence (TBS_Buf, TBS_Pos, Ext_S);
         end;

         --  Subject Alternative Names (if any)
         if Params.SAN_Count > 0 then
            declare
               Ext_S : X509.N32;
               SAN_Buf : DER_Buffer := (others => 0);
               SAN_Pos : X509.N32 := 0;
               SAN_Seq : X509.N32;
            begin
               Start_Sequence (SAN_Buf, SAN_Pos, SAN_Seq);
               for I in 1 .. Params.SAN_Count loop
                  declare
                     S : SAN_Entry renames Params.SANs (I);
                  begin
                     if S.Is_IP then
                        --  iPAddress [7] IMPLICIT OCTET STRING
                        declare
                           Addr : X509.Byte_Seq (0 .. 3);
                           Addr_OK : Boolean;
                        begin
                           Parse_IPv4 (S.Name (1 .. S.Name_Len), Addr, Addr_OK);
                           if Addr_OK then
                              Put_Byte (SAN_Buf, SAN_Pos,
                                        16#87#);  --  context [7]
                              Put_Length (SAN_Buf, SAN_Pos, 4);
                              Put_Bytes (SAN_Buf, SAN_Pos, Addr);
                           end if;
                        end;
                     else
                        --  dNSName [2] IMPLICIT IA5String
                        Put_Byte (SAN_Buf, SAN_Pos, 16#82#);  --  context [2]
                        Put_Length (SAN_Buf, SAN_Pos,
                                   X509.N32 (S.Name_Len));
                        for J in 1 .. S.Name_Len loop
                           Put_Byte (SAN_Buf, SAN_Pos,
                                     X509.Byte (Character'Pos (S.Name (J))));
                        end loop;
                     end if;
                  end;
               end loop;
               End_Sequence (SAN_Buf, SAN_Pos, SAN_Seq);

               Start_Sequence (TBS_Buf, TBS_Pos, Ext_S);
               Put_OID (TBS_Buf, TBS_Pos, X509.Byte_Seq (OID_Subject_Alt_Name));
               Put_Octet_String (TBS_Buf, TBS_Pos,
                  X509.Byte_Seq (SAN_Buf (0 .. SAN_Pos - 1)));
               End_Sequence (TBS_Buf, TBS_Pos, Ext_S);
            end;
         end if;

         --  Extended Key Usage (serverAuth)
         if Params.Has_EKU_Server_Auth then
            declare
               Ext_S : X509.N32;
               --  SEQUENCE { OID id-kp-serverAuth (1.3.6.1.5.5.7.3.1) }
               EKU_Value : constant X509.Byte_Seq (0 .. 11) :=
                 (16#30#, 16#0A#,                          --  SEQUENCE, 10 bytes
                  16#06#, 16#08#,                          --  OID, 8 bytes
                  16#2B#, 16#06#, 16#01#, 16#05#,          --  1.3.6.1.
                  16#05#, 16#07#, 16#03#, 16#01#);         --  5.5.7.3.1
            begin
               Start_Sequence (TBS_Buf, TBS_Pos, Ext_S);
               Put_OID (TBS_Buf, TBS_Pos,
                  X509.Byte_Seq'(16#55#, 16#1D#, 16#25#));  --  OID 2.5.29.37 (EKU)
               Put_Octet_String (TBS_Buf, TBS_Pos, EKU_Value);
               End_Sequence (TBS_Buf, TBS_Pos, Ext_S);
            end;
         end if;

         --  Subject Key Identifier (RFC 5280 §4.2.1.2)
         --  Value = SHA-1 hash of the SPKI BIT STRING content.
         --  For simplicity, use first 20 bytes of SHA-256 of SPKI.
         if Params.SPKI_Len > 0 then
            declare
               use SPARKNaCl.Hashing.SHA256;
               Ext_S : X509.N32;
               SPKI_N : Byte_Seq (0 .. N32 (Params.SPKI_Len) - 1);
               Hash   : Digest;
               --  SKI value: OCTET STRING of 20 bytes (truncated SHA-256)
               SKI_Val : X509.Byte_Seq (0 .. 23) := (others => 0);
               SKI_Pos : X509.N32 := 0;
            begin
               --  Hash the SPKI
               for I in X509.N32 range 0 .. Params.SPKI_Len - 1 loop
                  SPKI_N (N32 (I)) := Byte (Params.SPKI (I));
               end loop;
               SPARKNaCl.Hashing.SHA256.Hash (Hash, SPKI_N);

               --  Build SKI value: OCTET STRING { 20 bytes }
               SKI_Val (0) := X509.Byte (16#04#);   --  OCTET STRING tag
               SKI_Val (1) := X509.Byte (16#14#);   --  length 20
               for I in 0 .. 19 loop
                  SKI_Val (X509.N32 (2 + I)) := X509.Byte (Hash (N32 (I)));
               end loop;
               SKI_Pos := 22;

               --  Extension SEQUENCE { OID, OCTET STRING value }
               Start_Sequence (TBS_Buf, TBS_Pos, Ext_S);
               Put_OID (TBS_Buf, TBS_Pos,
                  X509.Byte_Seq'(16#55#, 16#1D#, 16#0E#));  --  OID 2.5.29.14 (SKI)
               Put_Octet_String (TBS_Buf, TBS_Pos,
                  SKI_Val (0 .. SKI_Pos - 1));
               End_Sequence (TBS_Buf, TBS_Pos, Ext_S);

               --  Authority Key Identifier (RFC 5280 §4.2.1.1)
               --  For self-signed: AKI keyIdentifier = SKI value
               declare
                  AKI_S : X509.N32;
                  --  AKI value: SEQUENCE { [0] IMPLICIT keyIdentifier }
                  AKI_Val : X509.Byte_Seq (0 .. 25) := (others => 0);
                  AKI_Pos : X509.N32 := 0;
               begin
                  AKI_Val (0) := X509.Byte (16#30#);   --  SEQUENCE tag
                  AKI_Val (1) := X509.Byte (16#16#);   --  length 22
                  AKI_Val (2) := X509.Byte (16#80#);   --  [0] IMPLICIT tag
                  AKI_Val (3) := X509.Byte (16#14#);   --  length 20
                  for I in 0 .. 19 loop
                     AKI_Val (X509.N32 (4 + I)) :=
                        X509.Byte (Hash (N32 (I)));
                  end loop;
                  AKI_Pos := 24;

                  Start_Sequence (TBS_Buf, TBS_Pos, AKI_S);
                  Put_OID (TBS_Buf, TBS_Pos,
                     X509.Byte_Seq'(16#55#, 16#1D#, 16#23#));  --  OID 2.5.29.35 (AKI)
                  Put_Octet_String (TBS_Buf, TBS_Pos,
                     AKI_Val (0 .. AKI_Pos - 1));
                  End_Sequence (TBS_Buf, TBS_Pos, AKI_S);
               end;
            end;
         end if;

         End_Sequence (TBS_Buf, TBS_Pos, Ext_Seq);
         End_Context (TBS_Buf, TBS_Pos, Ext_Ctx);

         End_Sequence (TBS_Buf, TBS_Pos, TBS_Seq);
      end;

      --  ====== Sign the TBS ======
      declare
         TBS : constant X509.Byte_Seq := X509.Byte_Seq (TBS_Buf (0 .. TBS_Pos - 1));
         Sig_DER : X509.Byte_Seq (0 .. 255) := (others => 0);
         Sig_Len : X509.N32 := 0;
         Outer   : X509.N32;
      begin
         case Params.Key.Algo is
            when Key_Util.Algo_Ed25519 =>
               --  Ed25519: sign the raw TBS (no hash)
               declare
                  TBS_N : Byte_Seq (0 .. N32 (TBS'Length) - 1);
                  SM    : Byte_Seq (0 .. N32 (TBS'Length) + 63);
                  SK    : SPARKNaCl.Sign.Signing_SK;
               begin
                  for I in TBS'Range loop
                     TBS_N (N32 (I)) := Byte (TBS (I));
                  end loop;
                  SPARKNaCl.Sign.Utils.Construct (Bytes_64 (Params.Key.Raw), SK);
                  SPARKNaCl.Sign.Sign (SM, TBS_N, SK);
                  Sig_Len := 64;
                  for I in X509.N32 range 0 .. 63 loop
                     Sig_DER (I) := X509.Byte (SM (N32 (I)));
                  end loop;
               end;

            when Key_Util.Algo_P256 =>
               declare
                  use SPARKNaCl.Hashing.SHA256;
                  TBS_N : Byte_Seq (0 .. N32 (TBS'Length) - 1);
                  H     : Digest;
                  D     : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
                  K     : Bytes_32;
                  K_X   : X509.Byte_Seq (0 .. 31);
                  R_Out, S_Out : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
                  Sig_OK : Boolean;
               begin
                  for I in TBS'Range loop
                     TBS_N (N32 (I)) := Byte (TBS (I));
                  end loop;
                  Hash (H, TBS_N);

                  for I in N32 range 0 .. 31 loop
                     D (I) := Params.Key.Raw (I);
                  end loop;

                  --  Random nonce K
                  Get_Random (K_X);
                  for I in N32 range 0 .. 31 loop
                     K (I) := Byte (K_X (X509.N32 (I)));
                  end loop;

                  SPARKTLSCrypto.P256.ECDSA.Sign (H, D, Byte_Seq (K),
                                             R_Out, S_Out, Sig_OK);
                  if not Sig_OK then return; end if;

                  ECDSA_To_DER (Byte_Seq (R_Out), Byte_Seq (S_Out), 32,
                                Sig_DER, Sig_Len);
               end;

            when Key_Util.Algo_P384 =>
               declare
                  use SPARKNaCl.Hashing.SHA384;
                  TBS_N : Byte_Seq (0 .. N32 (TBS'Length) - 1);
                  H     : Digest;
                  D     : Byte_Seq (0 .. 47);
                  K     : Bytes_48;
                  K_X   : X509.Byte_Seq (0 .. 47);
                  R_Out, S_Out : Byte_Seq (0 .. 47);
                  Sig_OK : Boolean;
               begin
                  for I in TBS'Range loop
                     TBS_N (N32 (I)) := Byte (TBS (I));
                  end loop;
                  Hash (H, TBS_N);

                  for I in N32 range 0 .. 47 loop
                     D (I) := Params.Key.Raw (I);
                  end loop;

                  Get_Random (K_X);
                  for I in N32 range 0 .. 47 loop
                     K (I) := Byte (K_X (X509.N32 (I)));
                  end loop;

                  SPARKTLSCrypto.P384.ECDSA.Sign (H, D, Byte_Seq (K),
                                             R_Out, S_Out, Sig_OK);
                  if not Sig_OK then return; end if;

                  ECDSA_To_DER (R_Out, S_Out, 48, Sig_DER, Sig_Len);
               end;
         end case;

         if Sig_Len = 0 then return; end if;

         --  ====== Build outer Certificate SEQUENCE ======
         Start_Sequence (Cert_Buf, Cert_Pos, Outer);

         --  TBSCertificate
         Put_Bytes (Cert_Buf, Cert_Pos, X509.Byte_Seq (TBS_Buf (0 .. TBS_Pos - 1)));

         --  signatureAlgorithm
         Put_Sig_Algorithm (Cert_Buf, Cert_Pos, Params.Key.Algo);

         --  signatureValue BIT STRING
         Put_Bit_String (Cert_Buf, Cert_Pos, Sig_DER (0 .. Sig_Len - 1));

         End_Sequence (Cert_Buf, Cert_Pos, Outer);

         Cert_Len := Cert_Pos;
         Cert_DER (0 .. Cert_Pos - 1) := X509.Byte_Seq (Cert_Buf (0 .. Cert_Pos - 1));
         OK := True;
      end;
   end Build_Certificate;

end Cert_Builder;
