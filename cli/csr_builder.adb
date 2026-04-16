with SPARKNaCl.Sign;
with SPARKNaCl.Sign.Utils;
with SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLS.P256.ECDSA;
with SPARKTLS.P384.ECDSA;
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
               D      : SPARKTLS.P256.ECDSA.ECDSA_Sig_Half;
               K      : Bytes_32;
               K_X    : X509.Byte_Seq (0 .. 31);
               R_Out, S_Out : SPARKTLS.P256.ECDSA.ECDSA_Sig_Half;
            begin
               for I in Data'Range loop
                  Data_N (N32 (I)) := Byte (Data (I));
               end loop;
               Hash (H, Data_N);
               for I in N32 range 0 .. 31 loop
                  D (I) := Key.Raw (I);
               end loop;
               Ensure_Entropy;
               Get_Random (K_X);
               for I in N32 range 0 .. 31 loop
                  K (I) := Byte (K_X (X509.N32 (I)));
               end loop;
               SPARKTLS.P256.ECDSA.Sign (H, D, Byte_Seq (K),
                                          R_Out, S_Out, OK);
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
               K_X    : X509.Byte_Seq (0 .. 47);
               R_Out, S_Out : Byte_Seq (0 .. 47);
            begin
               for I in Data'Range loop
                  Data_N (N32 (I)) := Byte (Data (I));
               end loop;
               Hash (H, Data_N);
               for I in N32 range 0 .. 47 loop
                  D (I) := Key.Raw (I);
               end loop;
               Ensure_Entropy;
               Get_Random (K_X);
               for I in N32 range 0 .. 47 loop
                  K (I) := Byte (K_X (X509.N32 (I)));
               end loop;
               SPARKTLS.P384.ECDSA.Sign (H, D, Byte_Seq (K),
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
                              for C of Str loop
                                 if C in '0'..'9' then
                                    Octet := Octet * 10 +
                                       (Character'Pos (C) - Character'Pos ('0'));
                                 elsif C = '.' and then Idx < 3 then
                                    Addr (Idx) := X509.Byte (Octet);
                                    Idx := Idx + 1;
                                    Octet := 0;
                                 end if;
                              end loop;
                              if Idx = 3 then
                                 Addr (3) := X509.Byte (Octet);
                                 Addr_OK := True;
                              end if;
                           end;
                           if Addr_OK then
                              Put_Byte (SAN_Buf, SAN_Pos, 16#87#);
                              Put_Length (SAN_Buf, SAN_Pos, 4);
                              Put_Bytes (SAN_Buf, SAN_Pos, Addr);
                           end if;
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

end CSR_Builder;
