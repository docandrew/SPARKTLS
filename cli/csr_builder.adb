with SPARKNaCl.Sign;
with SPARKNaCl.Sign.Utils;
with SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P384.ECDSA;
with SPARKTLSCrypto.Ed25519;
with SPARKTLSCrypto.RFC6979;
with SPARKEntropy;

package body CSR_Builder is
   use type X509.Byte;
   use type X509.Byte_Seq;
   use type SPARKNaCl.N32;
   use DER_Builder;

   --  Entropy for ECDSA nonce
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

   --  Write a DN
   procedure Put_DN
     (Buf : in out DER_Buffer;
      Pos : in out X509.N32;
      D   : Cert_Builder.DN)
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

   --  Signature algorithm OID SEQUENCE
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

   --  ECDSA (R, S) to DER
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
         for I in Skip .. Half_Len - 1 loop
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

   --  Sign raw bytes and return signature DER
   procedure Sign_Data
     (Data    : X509.Byte_Seq;
      Key     : Key_Util.Private_Key;
      Sig_DER : out X509.Byte_Seq;
      Sig_Len : out X509.N32;
      OK      : out Boolean)
   is
   begin
      Sig_DER := (others => 0);
      Sig_Len := 0;
      OK := False;

      case Key.Algo is
         when Key_Util.Algo_Ed25519 =>
            declare
               Data_N : Byte_Seq (0 .. N32 (Data'Length) - 1);
               SM     : Byte_Seq (0 .. N32 (Data'Length) + 63);
               SK     : SPARKNaCl.Sign.Signing_SK;
            begin
               for I in Data'Range loop
                  Data_N (N32 (I)) := Byte (Data (I));
               end loop;
               SPARKNaCl.Sign.Utils.Construct (Bytes_64 (Key.Raw), SK);
               SPARKNaCl.Sign.Sign (SM, Data_N, SK);
               Sig_Len := 64;
               for I in X509.N32 range 0 .. 63 loop
                  Sig_DER (I) := X509.Byte (SM (N32 (I)));
               end loop;
               OK := True;
            end;

         when Key_Util.Algo_P256 =>
            declare
               use SPARKNaCl.Hashing.SHA256;
               Data_N : Byte_Seq (0 .. N32 (Data'Length) - 1);
               H      : Digest;
               D      : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
               K      : Bytes_32;
               R_Out, S_Out : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
            begin
               for I in Data'Range loop
                  Data_N (N32 (I)) := Byte (Data (I));
               end loop;
               Hash (H, Data_N);
               for I in N32 range 0 .. 31 loop
                  D (I) := Key.Raw (I);
               end loop;
               --  RFC 6979 deterministic nonce (see cert_builder).
               SPARKTLSCrypto.RFC6979.Derive_K_P256
                 (Bytes_32 (D), Bytes_32 (H), K, OK);
               if OK then
                  SPARKTLSCrypto.P256.ECDSA.Sign (H, D, Byte_Seq (K),
                                             R_Out, S_Out, OK);
               end if;
               if OK then
                  ECDSA_To_DER (Byte_Seq (R_Out), Byte_Seq (S_Out), 32,
                                Sig_DER, Sig_Len);
               end if;
            end;

         when Key_Util.Algo_P384 =>
            declare
               use SPARKNaCl.Hashing.SHA384;
               Data_N : Byte_Seq (0 .. N32 (Data'Length) - 1);
               H      : Digest;
               D      : Byte_Seq (0 .. 47);
               K      : Bytes_48;
               R_Out, S_Out : Byte_Seq (0 .. 47);
            begin
               for I in Data'Range loop
                  Data_N (N32 (I)) := Byte (Data (I));
               end loop;
               Hash (H, Data_N);
               for I in N32 range 0 .. 47 loop
                  D (I) := Key.Raw (I);
               end loop;
               SPARKTLSCrypto.RFC6979.Derive_K_P384
                 (Bytes_48 (D), Bytes_48 (H), K, OK);
               if not OK then
                  return;
               end if;
SPARKTLSCrypto.P384.ECDSA.Sign (H, D, Byte_Seq (K),
                                          R_Out, S_Out, OK);
               if OK then
                  ECDSA_To_DER (R_Out, S_Out, 48, Sig_DER, Sig_Len);
               end if;
            end;
      end case;
   end Sign_Data;

   procedure Build_CSR
     (Key      : Key_Util.Private_Key;
      Subject  : Cert_Builder.DN;
      SANs     : Cert_Builder.SAN_Array;
      SAN_Count : Natural;
      CSR_DER  : out CSR_DER_Buf;
      CSR_Len  : out X509.N32;
      OK       : out Boolean)
   is
      CRI_Buf  : DER_Buffer := (others => 0);  --  CertificationRequestInfo
      CRI_Pos  : X509.N32 := 0;
      CSR_Buf  : DER_Buffer := (others => 0);
      CSR_Pos  : X509.N32 := 0;
   begin
      CSR_DER := (others => 0);
      CSR_Len := 0;
      OK := False;

      if not Key.Valid then return; end if;

      --  Build CertificationRequestInfo
      declare
         CRI_Seq, Attrs_Ctx : X509.N32;
      begin
         Start_Sequence (CRI_Buf, CRI_Pos, CRI_Seq);

         --  version INTEGER (0)
         Put_Small_Integer (CRI_Buf, CRI_Pos, 0);

         --  subject Name
         Put_DN (CRI_Buf, CRI_Pos, Subject);

         --  subjectPKInfo (pre-built SPKI)
         Put_Bytes (CRI_Buf, CRI_Pos, Key.SPKI (0 .. Key.SPKI_Len - 1));

         --  attributes [0] IMPLICIT SET { ... }
         --  For SANs, we need: SET { SEQUENCE { OID extensionRequest,
         --    SET { SEQUENCE { SEQUENCE { OID SAN, OCTET STRING { ... } } } } } }
         if SAN_Count > 0 then
            declare
               OID_Extension_Request : constant X509.Byte_Seq (0 .. 8) :=
                 (16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#,
                  16#0D#, 16#01#, 16#09#, 16#0E#);
               Attr_Seq, Ext_Set, Ext_Seq, Ext_Entry : X509.N32;
               SAN_Buf : DER_Buffer := (others => 0);
               SAN_Pos : X509.N32 := 0;
               SAN_Seq : X509.N32;
            begin
               --  Build SAN value
               Start_Sequence (SAN_Buf, SAN_Pos, SAN_Seq);
               for I in 1 .. SAN_Count loop
                  declare
                     S : Cert_Builder.SAN_Entry renames SANs (I);
                  begin
                     if S.Is_IP then
                        declare
                           Addr : X509.Byte_Seq (0 .. 3);
                           Addr_OK : Boolean;
                        begin
                           --  Simple IPv4 parse
                           Addr := (others => 0);
                           Addr_OK := False;
                           declare
                              Str : constant String := S.Name (1 .. S.Name_Len);
                              Octet : Natural := 0;
                              Idx : X509.N32 := 0;
                           begin
                              Addr_OK := True;
                              for C of Str loop
                                 if C in '0'..'9' then
                                    Octet := Octet * 10 +
                                       (Character'Pos (C) - Character'Pos ('0'));
                                    if Octet > 255 then
                                       Addr_OK := False;   --  "999.1.1.1"
                                       exit;
                                    end if;
                                 elsif C = '.' and then Idx < 3 then
                                    Addr (Idx) := X509.Byte (Octet);
                                    Idx := Idx + 1;
                                    Octet := 0;
                                 else
                                    Addr_OK := False;
                                    exit;
                                 end if;
                              end loop;
                              if Addr_OK and then Idx = 3 then
                                 Addr (3) := X509.Byte (Octet);
                              else
                                 Addr_OK := False;
                              end if;
                           end;
                           if not Addr_OK then
                              OK := False;   --  unusable SAN: refuse, never drop it
                              return;
                           end if;
                           Put_Byte (SAN_Buf, SAN_Pos, 16#87#);
                           Put_Length (SAN_Buf, SAN_Pos, 4);
                           Put_Bytes (SAN_Buf, SAN_Pos, Addr);
                        end;
                     else
                        Put_Byte (SAN_Buf, SAN_Pos, 16#82#);
                        Put_Length (SAN_Buf, SAN_Pos, X509.N32 (S.Name_Len));
                        for J in 1 .. S.Name_Len loop
                           Put_Byte (SAN_Buf, SAN_Pos,
                              X509.Byte (Character'Pos (S.Name (J))));
                        end loop;
                     end if;
                  end;
               end loop;
               End_Sequence (SAN_Buf, SAN_Pos, SAN_Seq);

               --  [0] IMPLICIT (context tag 0, constructed)
               Start_Context (CRI_Buf, CRI_Pos, 0, Attrs_Ctx);
               Start_Sequence (CRI_Buf, CRI_Pos, Attr_Seq);
               Put_OID (CRI_Buf, CRI_Pos, OID_Extension_Request);
               Start_Set (CRI_Buf, CRI_Pos, Ext_Set);
               Start_Sequence (CRI_Buf, CRI_Pos, Ext_Seq);
               --  Extension entry: SEQUENCE { OID SAN, OCTET STRING value }
               Start_Sequence (CRI_Buf, CRI_Pos, Ext_Entry);
               Put_OID (CRI_Buf, CRI_Pos,
                        X509.Byte_Seq (OID_Subject_Alt_Name));
               Put_Octet_String (CRI_Buf, CRI_Pos,
                  X509.Byte_Seq (SAN_Buf (0 .. SAN_Pos - 1)));
               End_Sequence (CRI_Buf, CRI_Pos, Ext_Entry);
               End_Sequence (CRI_Buf, CRI_Pos, Ext_Seq);
               End_Set (CRI_Buf, CRI_Pos, Ext_Set);
               End_Sequence (CRI_Buf, CRI_Pos, Attr_Seq);
               End_Context (CRI_Buf, CRI_Pos, Attrs_Ctx);
            end;
         else
            --  Empty attributes [0]
            Start_Context (CRI_Buf, CRI_Pos, 0, Attrs_Ctx);
            End_Context (CRI_Buf, CRI_Pos, Attrs_Ctx);
         end if;

         End_Sequence (CRI_Buf, CRI_Pos, CRI_Seq);
      end;

      --  Sign CRI and build outer CSR SEQUENCE
      declare
         CRI : constant X509.Byte_Seq :=
            X509.Byte_Seq (CRI_Buf (0 .. CRI_Pos - 1));
         Sig_DER : X509.Byte_Seq (0 .. 255) := (others => 0);
         Sig_Len : X509.N32 := 0;
         Sig_OK  : Boolean;
         Outer   : X509.N32;
      begin
         Sign_Data (CRI, Key, Sig_DER, Sig_Len, Sig_OK);
         if not Sig_OK or Sig_Len = 0 then return; end if;

         Start_Sequence (CSR_Buf, CSR_Pos, Outer);
         Put_Bytes (CSR_Buf, CSR_Pos, CRI);
         Put_Sig_Algorithm (CSR_Buf, CSR_Pos, Key.Algo);
         Put_Bit_String (CSR_Buf, CSR_Pos, Sig_DER (0 .. Sig_Len - 1));
         End_Sequence (CSR_Buf, CSR_Pos, Outer);

         CSR_Len := CSR_Pos;
         CSR_DER (0 .. CSR_Pos - 1) :=
            X509.Byte_Seq (CSR_Buf (0 .. CSR_Pos - 1));
         OK := True;
      end;
   end Build_CSR;

   procedure Parse_CSR
     (DER      : X509.Byte_Seq;
      Subject  : out Cert_Builder.DN;
      SPKI     : out X509.Byte_Seq;
      SPKI_Len : out X509.N32;
      OK       : out Boolean)
   is
      Pos : X509.N32 := 0;

      --  Simple ASN.1 length parser
      procedure Skip_Tag_Length
        (P       : in out X509.N32;
         Content : out X509.N32;
         Len     : out X509.N32;
         P_OK    : out Boolean)
      is
      begin
         Content := 0;
         Len := 0;
         P_OK := False;
         if P > DER'Last then return; end if;
         P := P + 1;  --  skip tag
         if P > DER'Last then return; end if;
         if DER (P) < 16#80# then
            Len := X509.N32 (DER (P));
            P := P + 1;
         elsif DER (P) = 16#81# then
            if P + 1 > DER'Last then return; end if;
            Len := X509.N32 (DER (P + 1));
            P := P + 2;
         elsif DER (P) = 16#82# then
            if P + 2 > DER'Last then return; end if;
            Len := X509.N32 (DER (P + 1)) * 256 + X509.N32 (DER (P + 2));
            P := P + 3;
         else
            return;
         end if;
         Content := P;
         P_OK := True;
      end Skip_Tag_Length;

      --  Find a UTF8String or PrintableString value after an OID
      function Find_RDN_Value
        (Start, Last : X509.N32;
         OID         : X509.Byte_Seq) return String
      is
         P : X509.N32 := Start;
      begin
         while P + X509.N32 (OID'Length) + 5 <= Last loop
            --  Look for OID tag (06) + length + OID bytes
            if DER (P) = 16#06#
               and then P + 1 <= Last
               and then X509.N32 (DER (P + 1)) = X509.N32 (OID'Length)
               and then P + 2 + X509.N32 (OID'Length) - 1 <= Last
               and then DER (P + 2 .. P + 1 + X509.N32 (OID'Length)) =
                        OID
            then
               --  Next should be a string type + length + value
               declare
                  VP : X509.N32 := P + 2 + X509.N32 (OID'Length);
                  VL : X509.N32;
               begin
                  if VP + 1 <= Last
                     and then DER (VP) in 16#0C# | 16#13# | 16#16#
                  then
                     VL := X509.N32 (DER (VP + 1));
                     if VP + 2 + VL - 1 <= Last then
                        declare
                           Result : String (1 .. Natural (VL));
                        begin
                           for I in X509.N32 range 0 .. VL - 1 loop
                              Result (Natural (I) + 1) :=
                                 Character'Val (DER (VP + 2 + I));
                           end loop;
                           return Result;
                        end;
                     end if;
                  end if;
               end;
            end if;
            P := P + 1;
         end loop;
         return "";
      end Find_RDN_Value;

   begin
      Subject := (others => <>);
      SPKI := (others => 0);
      SPKI_Len := 0;
      OK := False;

      if DER'Length < 10 then return; end if;

      --  Outer SEQUENCE
      declare
         Outer_Content, Outer_Len : X509.N32;
         P_OK : Boolean;
      begin
         if DER (0) /= 16#30# then return; end if;
         Skip_Tag_Length (Pos, Outer_Content, Outer_Len, P_OK);
         if not P_OK then return; end if;
      end;

      --  CertificationRequestInfo SEQUENCE
      declare
         CRI_Start : constant X509.N32 := Pos;
         CRI_Content, CRI_Len : X509.N32;
         P_OK : Boolean;
      begin
         if DER (Pos) /= 16#30# then return; end if;
         Skip_Tag_Length (Pos, CRI_Content, CRI_Len, P_OK);
         if not P_OK then return; end if;

         declare
            CRI_End : constant X509.N32 := CRI_Content + CRI_Len - 1;
         begin
            --  Skip version INTEGER
            if Pos > CRI_End or else DER (Pos) /= 16#02# then return; end if;
            declare
               V_Content, V_Len : X509.N32;
            begin
               Skip_Tag_Length (Pos, V_Content, V_Len, P_OK);
               if not P_OK then return; end if;
               Pos := V_Content + V_Len;
            end;

            --  Subject Name SEQUENCE
            if Pos > CRI_End or else DER (Pos) /= 16#30# then return; end if;
            declare
               Subj_Start : constant X509.N32 := Pos;
               Subj_Content, Subj_Len : X509.N32;
            begin
               Skip_Tag_Length (Pos, Subj_Content, Subj_Len, P_OK);
               if not P_OK then return; end if;
               declare
                  Subj_End : constant X509.N32 := Subj_Content + Subj_Len - 1;
               begin
                  --  Extract CN
                  declare
                     CN : constant String :=
                        Find_RDN_Value (Subj_Content, Subj_End,
                           X509.Byte_Seq (OID_Common_Name));
                     L : constant Natural :=
                        Natural'Min (CN'Length, Subject.CN'Length);
                  begin
                     if L > 0 then
                        Subject.CN (1 .. L) := CN (1 .. L);
                        Subject.CN_Len := L;
                     end if;
                  end;

                  --  Extract Org
                  declare
                     O : constant String :=
                        Find_RDN_Value (Subj_Content, Subj_End,
                           X509.Byte_Seq (OID_Organization));
                     L : constant Natural :=
                        Natural'Min (O'Length, Subject.Org'Length);
                  begin
                     if L > 0 then
                        Subject.Org (1 .. L) := O (1 .. L);
                        Subject.Org_Len := L;
                     end if;
                  end;

                  Pos := Subj_Content + Subj_Len;
               end;
            end;

            --  SubjectPublicKeyInfo SEQUENCE — copy the whole thing
            if Pos > CRI_End or else DER (Pos) /= 16#30# then return; end if;
            declare
               SPKI_Start : constant X509.N32 := Pos;
               SPKI_Content, SPKI_L : X509.N32;
            begin
               Skip_Tag_Length (Pos, SPKI_Content, SPKI_L, P_OK);
               if not P_OK then return; end if;
               Pos := SPKI_Content + SPKI_L;
               declare
                  Total : constant X509.N32 := Pos - SPKI_Start;
               begin
                  if Total > X509.N32 (SPKI'Length) then return; end if;
                  SPKI (0 .. Total - 1) := DER (SPKI_Start .. Pos - 1);
                  SPKI_Len := Total;
               end;
            end;
         end;
      end;

      OK := True;
   end Parse_CSR;


   procedure Verify_CSR (DER : X509.Byte_Seq; OK : out Boolean) is
      Pos : X509.N32 := 0;

      procedure TL (P : in out X509.N32; Tag : X509.Byte;
                    Content : out X509.N32; Len : out X509.N32; Good : out Boolean) is
      begin
         Content := 0; Len := 0; Good := False;
         if P > DER'Last or else DER (P) /= Tag then return; end if;
         P := P + 1;
         if P > DER'Last then return; end if;
         if DER (P) < 16#80# then
            Len := X509.N32 (DER (P)); P := P + 1;
         elsif DER (P) = 16#81# and then P + 1 <= DER'Last then
            Len := X509.N32 (DER (P + 1)); P := P + 2;
         elsif DER (P) = 16#82# and then P + 2 <= DER'Last then
            Len := X509.N32 (DER (P + 1)) * 256 + X509.N32 (DER (P + 2)); P := P + 3;
         else
            return;
         end if;
         if Len > DER'Last - P + 1 then return; end if;
         Content := P;
         Good := True;
      end TL;

      --  ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } into two
      --  fixed halves, right-aligned, leading zero stripped.
      procedure Split_Sig (Sig : X509.Byte_Seq; N : X509.N32;
                           R, S : out X509.Byte_Seq; Good : out Boolean) is
         P : X509.N32 := Sig'First;
         C, L : X509.N32;
         procedure Half (Out_H : out X509.Byte_Seq; G : out Boolean) is
            IC, IL : X509.N32;
         begin
            Out_H := (others => 0); G := False;
            if P > Sig'Last or else Sig (P) /= 16#02# then return; end if;
            P := P + 1;
            if P > Sig'Last then return; end if;
            IL := X509.N32 (Sig (P)); P := P + 1;
            if IL = 0 or else IL > Sig'Last - P + 1 then return; end if;
            IC := P; P := P + IL;
            while IL > 0 and then Sig (IC) = 0 loop
               IC := IC + 1; IL := IL - 1;
            end loop;
            if IL > N then return; end if;
            for I in 0 .. IL - 1 loop
               Out_H (Out_H'First + (N - IL) + I) := Sig (IC + I);
            end loop;
            G := True;
         end Half;
         G1, G2 : Boolean;
      begin
         R := (others => 0); S := (others => 0); Good := False;
         if P > Sig'Last or else Sig (P) /= 16#30# then return; end if;
         P := P + 1;
         if P > Sig'Last then return; end if;
         L := X509.N32 (Sig (P)); P := P + 1;
         if L > Sig'Last - P + 1 then return; end if;
         C := P;
         Half (R, G1); Half (S, G2);
         Good := G1 and G2 and P = C + L;
      end Split_Sig;

      Outer_C, Outer_L, CRI_C, CRI_L, Alg_C, Alg_L, Sig_C, Sig_L : X509.N32;
      G : Boolean;
      CRI_Start : X509.N32;
      SPKI      : X509.Byte_Seq (0 .. 511) := (others => 0);
      SPKI_Len  : X509.N32;
      Subject   : Cert_Builder.DN;
      Bits_First, Bits_Len : X509.N32;
      Bits_OK   : Boolean;
   begin
      OK := False;
      TL (Pos, 16#30#, Outer_C, Outer_L, G);
      if not G then return; end if;
      CRI_Start := Pos;
      TL (Pos, 16#30#, CRI_C, CRI_L, G);                    --  CertificationRequestInfo
      if not G then return; end if;
      Pos := CRI_C + CRI_L;
      TL (Pos, 16#30#, Alg_C, Alg_L, G);                    --  signatureAlgorithm
      if not G then return; end if;
      Pos := Alg_C + Alg_L;
      TL (Pos, 16#03#, Sig_C, Sig_L, G);                    --  signature BIT STRING
      if not G or else Sig_L < 2 or else DER (Sig_C) /= 0 then return; end if;

      Parse_CSR (DER, Subject, SPKI, SPKI_Len, G);
      if not G or else SPKI_Len = 0 then return; end if;
      Cert_Builder.Public_Key_Bits (SPKI (0 .. SPKI_Len - 1), Bits_First, Bits_Len, Bits_OK);
      if not Bits_OK then return; end if;

      declare
         CRI     : constant X509.Byte_Seq := DER (CRI_Start .. CRI_C + CRI_L - 1);
         Sig     : constant X509.Byte_Seq := DER (Sig_C + 1 .. Sig_C + Sig_L - 1);
         Key     : constant X509.Byte_Seq := SPKI (Bits_First .. Bits_First + Bits_Len - 1);
         Is_Ed   : constant Boolean :=
           (for some I in SPKI'First .. SPKI_Len - 5 =>
              SPKI (I .. I + 4) = X509.Byte_Seq'(16#06#, 16#03#, 16#2B#, 16#65#, 16#70#));
         Is_P256 : constant Boolean :=
           (for some I in SPKI'First .. SPKI_Len - 8 =>
              SPKI (I .. I + 7) = X509.Byte_Seq'(16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#03#, 16#01#, 16#07#));
         Is_P384 : constant Boolean :=
           (for some I in SPKI'First .. SPKI_Len - 5 =>
              SPKI (I .. I + 4) = X509.Byte_Seq'(16#2B#, 16#81#, 16#04#, 16#00#, 16#22#));
      begin
         if Is_Ed then
            if Key'Length /= 32 or else Sig'Length /= 64 then return; end if;
            declare
               SM_Len  : constant N32 := 64 + N32 (CRI'Length);
               SM      : Byte_Seq (0 .. SM_Len - 1) := (others => 0);
               M       : Byte_Seq (0 .. SM_Len - 1);
               PK      : Bytes_32;
               Msg_Len : I32;
            begin
               for I in 0 .. 63 loop
                  SM (N32 (I)) := Byte (Sig (Sig'First + X509.N32 (I)));
               end loop;
               for I in 0 .. CRI'Length - 1 loop
                  SM (64 + N32 (I)) := Byte (CRI (CRI'First + X509.N32 (I)));
               end loop;
               for I in 0 .. 31 loop
                  PK (N32 (I)) := Byte (Key (Key'First + X509.N32 (I)));
               end loop;
               SPARKTLSCrypto.Ed25519.Open (M, OK, Msg_Len, SM, PK);
            end;
         elsif Is_P256 then
            if Key'Length /= 65 or else Key (Key'First) /= 16#04# then return; end if;
            declare
               use SPARKNaCl.Hashing.SHA256;
               Data : Byte_Seq (0 .. N32 (CRI'Length) - 1);
               H    : Digest;
               R, S : X509.Byte_Seq (0 .. 31);
               Qx, Qy, RN, SN : Byte_Seq (0 .. 31);
            begin
               for I in Data'Range loop
                  Data (I) := Byte (CRI (CRI'First + X509.N32 (I)));
               end loop;
               Hash (H, Data);
               Split_Sig (Sig, 32, R, S, G);
               if not G then return; end if;
               for I in N32 range 0 .. 31 loop
                  Qx (I) := Byte (Key (Key'First + 1 + X509.N32 (I)));
                  Qy (I) := Byte (Key (Key'First + 33 + X509.N32 (I)));
                  RN (I) := Byte (R (X509.N32 (I)));
                  SN (I) := Byte (S (X509.N32 (I)));
               end loop;
               OK := SPARKTLSCrypto.P256.ECDSA.Verify (Bytes_32 (H), Qx, Qy, RN, SN);
            end;
         elsif Is_P384 then
            if Key'Length /= 97 or else Key (Key'First) /= 16#04# then return; end if;
            declare
               use SPARKNaCl.Hashing.SHA384;
               Data : Byte_Seq (0 .. N32 (CRI'Length) - 1);
               H    : Digest;
               R, S : X509.Byte_Seq (0 .. 47);
               Qx, Qy, RN, SN : Byte_Seq (0 .. 47);
            begin
               for I in Data'Range loop
                  Data (I) := Byte (CRI (CRI'First + X509.N32 (I)));
               end loop;
               Hash (H, Data);
               Split_Sig (Sig, 48, R, S, G);
               if not G then return; end if;
               for I in N32 range 0 .. 47 loop
                  Qx (I) := Byte (Key (Key'First + 1 + X509.N32 (I)));
                  Qy (I) := Byte (Key (Key'First + 49 + X509.N32 (I)));
                  RN (I) := Byte (R (X509.N32 (I)));
                  SN (I) := Byte (S (X509.N32 (I)));
               end loop;
               OK := SPARKTLSCrypto.P384.ECDSA.Verify (Bytes_48 (H), Qx, Qy, RN, SN);
            end;
         end if;
      end;
   exception
      when others =>
         OK := False;
   end Verify_CSR;

end CSR_Builder;
