with Ada.Calendar;
with Ada.Calendar.Formatting;
with SPARKNaCl.Sign;
with SPARKNaCl.Sign.Utils;
with SPARKNaCl.Hashing.SHA256;
with SPARKTLSCrypto.Hashing.SHA1;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P384.ECDSA;
with SPARKTLSCrypto.RFC6979;
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

   --  OK = False means the entropy source failed its health test; the
   --  caller must abort, never use the (zeroed) output.
   procedure Get_Random (Output : out X509.Byte_Seq; OK : out Boolean) is
      Buf : SPARKEntropy.Byte_Seq (0 .. Output'Length - 1);
   begin
      Output := (others => 0);
      SPARKEntropy.Generate (Entropy, Buf, OK);
      if not OK then
         return;
      end if;
      for I in Output'Range loop
         Output (I) := X509.Byte (Buf (Natural (I - Output'First)));
      end loop;
   end Get_Random;

   --  Get current time as X509.Date_Time
   function Now return X509.Date_Time is
      use Ada.Calendar;
      Now : constant Time := Clock;
      Y   : Year_Number;
      M  : Month_Number;
      D   : Day_Number;
      Hr  : Ada.Calendar.Formatting.Hour_Number;
      Mn  : Ada.Calendar.Formatting.Minute_Number;
      Sc  : Ada.Calendar.Formatting.Second_Number;
      SS  : Ada.Calendar.Formatting.Second_Duration;
   begin
      --  Ada.Calendar.Split works in package Calendar's implementation-
      --  defined (local) time zone, RM 9.6. X.509 notBefore/notAfter are
      --  UTC, so a local split shifts every validity comparison by the
      --  host's UTC offset. Formatting.Split with Time_Zone => 0 is the
      --  UTC one.
      Ada.Calendar.Formatting.Split
        (Now, Y, M, D, Hr, Mn, Sc, SS, Time_Zone => 0);
      return (Year   => Y, Month => M, Day => D,
              Hour   => Hr, Minute => Mn, Second => Sc);
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

   --  Locate the subjectPublicKey BIT STRING content inside a DER
   --  SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }.
   --  The first content byte of the BIT STRING is the unused-bits count and
   --  is not part of the key. Lengths up to 65535 (short, 0x81 and 0x82 forms).
   procedure Public_Key_Bits
     (SPKI : X509.Byte_Seq; First : out X509.N32; Length : out X509.N32; OK : out Boolean)
   is
      P : X509.N32 := SPKI'First;
      procedure Read_Len (L : out X509.N32; Good : out Boolean) is
      begin
         L := 0; Good := False;
         if P > SPKI'Last then return; end if;
         if SPKI (P) < 16#80# then
            L := X509.N32 (SPKI (P)); P := P + 1; Good := True;
         elsif SPKI (P) = 16#81# and then P + 1 <= SPKI'Last then
            L := X509.N32 (SPKI (P + 1)); P := P + 2; Good := True;
         elsif SPKI (P) = 16#82# and then P + 2 <= SPKI'Last then
            L := X509.N32 (SPKI (P + 1)) * 256 + X509.N32 (SPKI (P + 2)); P := P + 3; Good := True;
         end if;
      end Read_Len;
      L    : X509.N32;
      Good : Boolean;
   begin
      First := SPKI'First; Length := 0; OK := False;
      if SPKI'Length < 4 or else SPKI (P) /= 16#30# then return; end if;
      P := P + 1; Read_Len (L, Good);
      if not Good or else P > SPKI'Last or else SPKI (P) /= 16#30# then return; end if;
      P := P + 1; Read_Len (L, Good);                    --  AlgorithmIdentifier
      if not Good or else L > SPKI'Last - P then return; end if;
      P := P + L;
      if P > SPKI'Last or else SPKI (P) /= 16#03# then return; end if;
      P := P + 1; Read_Len (L, Good);                    --  BIT STRING
      if not Good or else L < 2 or else L > SPKI'Last - P + 1 then return; end if;
      First := P + 1;                                    --  skip unused-bits byte
      Length := L - 1;
      OK := True;
   end Public_Key_Bits;

   procedure Set_Issuer_Key_ID
     (Params : in out Cert_Params; CA_DER : X509.Byte_Seq; CA : X509.Certificate)
   is
      SKID : constant X509.Span := X509.Subject_Key_ID (CA);
      Bits : constant X509.Span := X509.Subject_Public_Key_Bits (CA);
   begin
      Params.Issuer_Key_ID := (others => 0);
      Params.Issuer_Key_ID_Len := 0;
      if SKID.Present and then SKID.First <= SKID.Last
        and then SKID.First >= CA_DER'First and then SKID.Last <= CA_DER'Last
        and then SKID.Last - SKID.First < 32
      then
         Params.Issuer_Key_ID_Len := SKID.Last - SKID.First + 1;
         Params.Issuer_Key_ID (0 .. Params.Issuer_Key_ID_Len - 1) := CA_DER (SKID.First .. SKID.Last);
      elsif Bits.Present and then Bits.First <= Bits.Last
        and then Bits.First >= CA_DER'First and then Bits.Last <= CA_DER'Last
      then
         declare
            B : Byte_Seq (0 .. N32 (Bits.Last - Bits.First));
            H : SPARKTLSCrypto.Hashing.SHA1.Digest;
         begin
            for I in X509.N32 range 0 .. Bits.Last - Bits.First loop
               B (N32 (I)) := Byte (CA_DER (Bits.First + I));
            end loop;
            H := SPARKTLSCrypto.Hashing.SHA1.Hash (B);
            for I in 0 .. 19 loop
               Params.Issuer_Key_ID (X509.N32 (I)) := X509.Byte (H (N32 (I)));
            end loop;
            Params.Issuer_Key_ID_Len := 20;
         end;
      end if;
   end Set_Issuer_Key_ID;

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
      --  RFC 5280 4.1.2.5: notAfter must be representable (GeneralizedTime
      --  year <= 9999); 100 years is more than any policy allows.
      if Params.Valid_Days = 0 or else Params.Valid_Days > 36500 then return; end if;

      Ensure_Entropy;
      if not Entropy_Ready then return; end if;

      --  RFC 5280 4.1.2.2 / CA/Browser Forum: a positive, unique serial
      --  with at least 64 bits of entropy. 20 random bytes, high bit
      --  clear; an entropy failure aborts rather than issuing serial 0.
      declare
         R_OK : Boolean;
      begin
         Get_Random (Serial, R_OK);
         if not R_OK then return; end if;
      end;
      Serial (0) := Serial (0) and 16#7F#;  --  must be positive
      if (for all B of Serial => B = 0) then return; end if;

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
                           if not Addr_OK then
                              return;   --  unusable SAN: refuse, never drop it
                           end if;
                           Put_Byte (SAN_Buf, SAN_Pos,
                                     16#87#);  --  context [7]
                           Put_Length (SAN_Buf, SAN_Pos, 4);
                           Put_Bytes (SAN_Buf, SAN_Pos, Addr);
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

         --  Extended Key Usage (serverAuth + clientAuth)
         if Params.Has_EKU_Server_Auth then
            declare
               Ext_S : X509.N32;
               --  SEQUENCE {
               --    OID id-kp-serverAuth (1.3.6.1.5.5.7.3.1),
               --    OID id-kp-clientAuth (1.3.6.1.5.5.7.3.2)
               --  }
               EKU_Value : constant X509.Byte_Seq (0 .. 21) :=
                 (16#30#, 16#14#,                          --  SEQUENCE, 20 bytes
                  16#06#, 16#08#,                          --  OID, 8 bytes
                  16#2B#, 16#06#, 16#01#, 16#05#,          --  1.3.6.1.
                  16#05#, 16#07#, 16#03#, 16#01#,          --  5.5.7.3.1
                  16#06#, 16#08#,                          --  OID, 8 bytes
                  16#2B#, 16#06#, 16#01#, 16#05#,          --  1.3.6.1.
                  16#05#, 16#07#, 16#03#, 16#02#);         --  5.5.7.3.2
            begin
               Start_Sequence (TBS_Buf, TBS_Pos, Ext_S);
               Put_OID (TBS_Buf, TBS_Pos,
                  X509.Byte_Seq'(16#55#, 16#1D#, 16#25#));  --  OID 2.5.29.37 (EKU)
               Put_Octet_String (TBS_Buf, TBS_Pos, EKU_Value);
               End_Sequence (TBS_Buf, TBS_Pos, Ext_S);
            end;
         end if;

         --  Subject Key Identifier (RFC 5280 4.2.1.2, method 1): SHA-1 of
         --  the subjectPublicKey BIT STRING content, the convention OpenSSL
         --  and most CAs use, so identifiers match across tools.
         if Params.SPKI_Len > 0 then
            declare
               Ext_S   : X509.N32;
               Bits_First, Bits_Len : X509.N32;
               Bits_OK : Boolean;
               SKI     : SPARKTLSCrypto.Hashing.SHA1.Digest := (others => 0);
               --  SKI value: OCTET STRING { 20 bytes }
               SKI_Val : X509.Byte_Seq (0 .. 21) := (others => 0);
            begin
               Public_Key_Bits (Params.SPKI (0 .. Params.SPKI_Len - 1), Bits_First, Bits_Len, Bits_OK);
               if Bits_OK then
                  declare
                     Bits : Byte_Seq (0 .. N32 (Bits_Len) - 1);
                  begin
                     for I in X509.N32 range 0 .. Bits_Len - 1 loop
                        Bits (N32 (I)) := Byte (Params.SPKI (Bits_First + I));
                     end loop;
                     SKI := SPARKTLSCrypto.Hashing.SHA1.Hash (Bits);
                  end;
               end if;
               SKI_Val (0) := X509.Byte (16#04#);   --  OCTET STRING tag
               SKI_Val (1) := X509.Byte (16#14#);   --  length 20
               for I in 0 .. 19 loop
                  SKI_Val (X509.N32 (2 + I)) := X509.Byte (SKI (N32 (I)));
               end loop;

               Start_Sequence (TBS_Buf, TBS_Pos, Ext_S);
               Put_OID (TBS_Buf, TBS_Pos,
                  X509.Byte_Seq'(16#55#, 16#1D#, 16#0E#));  --  OID 2.5.29.14 (SKI)
               Put_Octet_String (TBS_Buf, TBS_Pos, SKI_Val);
               End_Sequence (TBS_Buf, TBS_Pos, Ext_S);

               --  Authority Key Identifier (RFC 5280 4.2.1.1): the ISSUER's
               --  key identifier. Self-signed: our own SKI.
               declare
                  AKI_S   : X509.N32;
                  Own     : constant Boolean := Params.Issuer_Key_ID_Len = 0;
                  KID_Len : constant X509.N32 :=
                    (if Own then 20 else X509.N32'Min (Params.Issuer_Key_ID_Len, 32));
                  --  AKI value: SEQUENCE { [0] IMPLICIT keyIdentifier }
                  AKI_Val : X509.Byte_Seq (0 .. 3 + KID_Len) := (others => 0);
               begin
                  AKI_Val (0) := X509.Byte (16#30#);              --  SEQUENCE
                  AKI_Val (1) := X509.Byte (2 + KID_Len);         --  length
                  AKI_Val (2) := X509.Byte (16#80#);              --  [0] IMPLICIT
                  AKI_Val (3) := X509.Byte (KID_Len);
                  for I in X509.N32 range 0 .. KID_Len - 1 loop
                     AKI_Val (4 + I) :=
                       (if Own then X509.Byte (SKI (N32 (I))) else Params.Issuer_Key_ID (I));
                  end loop;

                  Start_Sequence (TBS_Buf, TBS_Pos, AKI_S);
                  Put_OID (TBS_Buf, TBS_Pos,
                     X509.Byte_Seq'(16#55#, 16#1D#, 16#23#));  --  OID 2.5.29.35 (AKI)
                  Put_Octet_String (TBS_Buf, TBS_Pos, AKI_Val);
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
                  R_Out, S_Out : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
                  Sig_OK : Boolean;
                  Blind_X : X509.Byte_Seq (0 .. 39);   --  scalar/coordinate blinding
                  Blind   : Byte_Seq (0 .. 39);
                  B_OK    : Boolean;
               begin
                  for I in TBS'Range loop
                     TBS_N (N32 (I)) := Byte (TBS (I));
                  end loop;
                  Hash (H, TBS_N);

                  for I in N32 range 0 .. 31 loop
                     D (I) := Params.Key.Raw (I);
                  end loop;

                  --  Random nonce K
                  --  RFC 6979: deterministic nonce from the key and the
                  --  digest. No RNG in the signing path, and K is in range
                  --  by construction; Sign does not validate it.
                  SPARKTLSCrypto.RFC6979.Derive_K_P256
                    (Bytes_32 (D), Bytes_32 (H), K, Sig_OK);
                  if not Sig_OK then return; end if;
                  Get_Random (Blind_X, B_OK);
                  if not B_OK then return; end if;
                  for I in N32 range 0 .. 39 loop
                     Blind (I) := Byte (Blind_X (X509.N32 (I)));
                  end loop;
                  SPARKTLSCrypto.P256.ECDSA.Sign (H, D, Byte_Seq (K), Blind,
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
                  R_Out, S_Out : Byte_Seq (0 .. 47);
                  Sig_OK : Boolean;
                  Blind_X : X509.Byte_Seq (0 .. 55);   --  scalar/coordinate blinding
                  Blind   : Byte_Seq (0 .. 55);
                  B_OK    : Boolean;
               begin
                  for I in TBS'Range loop
                     TBS_N (N32 (I)) := Byte (TBS (I));
                  end loop;
                  Hash (H, TBS_N);

                  for I in N32 range 0 .. 47 loop
                     D (I) := Params.Key.Raw (I);
                  end loop;

                  SPARKTLSCrypto.RFC6979.Derive_K_P384
                    (Bytes_48 (D), Bytes_48 (H), K, Sig_OK);
                  if not Sig_OK then return; end if;
                  Get_Random (Blind_X, B_OK);
                  if not B_OK then return; end if;
                  for I in N32 range 0 .. 55 loop
                     Blind (I) := Byte (Blind_X (X509.N32 (I)));
                  end loop;
                  SPARKTLSCrypto.P384.ECDSA.Sign (H, D, Byte_Seq (K), Blind,
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
