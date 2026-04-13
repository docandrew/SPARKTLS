with Interfaces;                 use Interfaces;
with SPARKNaCl.Hashing;
with SPARKNaCl.Hashing.SHA256;   use SPARKNaCl.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKNaCl.MAC;              use SPARKNaCl.MAC;
with SPARKNaCl.Sign;
with SPARKNaCl.HKDF;             use SPARKNaCl.HKDF;

with SPARKTLS.Records;      use SPARKTLS.Records;
with SPARKTLS.Cert_Verify;  use SPARKTLS.Cert_Verify;
with SPARKTLS.Handshake;
with SPARKTLS.Key_Schedule;
with SPARKTLS.HMAC384;
with SPARKTLS.HKDF384;
with SPARKTLS.P256.ECDSA;
with SPARKTLS.P384.ECDSA;
with SPARKTLS.RSA;

with X509;
use type X509.Algorithm_ID;

package body SPARKTLS.Client with
   SPARK_Mode => On
is
   --  Forward declarations for internal procedures
   procedure Derive_Handshake_Keys (S : in out Session);
   procedure Send_Client_Certificate
     (S      : in out Session;
      Result :    out Action);
   procedure Derive_App_Keys_And_Send_Finished
     (S      : in out Session;
      Result :    out Action);
   procedure Process_Handshake_Message
     (S      : in out Session;
      Data   : in     Byte_Seq;
      Result :    out Action);
   procedure Process_Encrypted_Handshake
     (S      : in out Session;
      Result :    out Action);
   procedure Process_Connected
     (S      : in out Session;
      Result :    out Action);
   procedure Set_Traffic_Keys
     (TK     : in out Traffic_Keys;
      Secret : in     Bytes_48;
      Suite  : in     Unsigned_16);

   --  Append handshake message bytes to the transcript
   procedure Append_Transcript
     (S    : in out Session;
      Data : in     Byte_Seq)
   is
      Len : constant N32 := N32 (Data'Length);
   begin
      if S.Transcript_Len + Len <= S.Transcript'Length then
         S.Transcript (S.Transcript_Len ..
                        S.Transcript_Len + Len - 1) := Data;
         S.Transcript_Len := S.Transcript_Len + Len;
      end if;
   end Append_Transcript;

   function Transcript_Hash_256 (S : Session) return Digest is
      H : Digest;
   begin
      Hash (H, S.Transcript (0 .. S.Transcript_Len - 1));
      return H;
   end Transcript_Hash_256;

   function Transcript_Hash_384 (S : Session)
      return SPARKNaCl.Hashing.SHA384.Digest
   is
      H : SPARKNaCl.Hashing.SHA384.Digest;
   begin
      SPARKNaCl.Hashing.SHA384.Hash
        (H, S.Transcript (0 .. S.Transcript_Len - 1));
      return H;
   end Transcript_Hash_384;

   procedure Configure
     (S        : out Session;
      Hostname : String;
      Trust    : Trust_Store_Access;
      Random   : Random_Bytes_Fn;
      Clock    : Get_Time_Fn;
      Local    : Identity_Access := null)
   is
      Cfg : Config;
   begin
      Cfg.Random      := Random;
      Cfg.Trust       := Trust;
      Cfg.Local       := Local;
      Cfg.Skip_Verify := Trust = null;
      Cfg.Get_Time    := Clock;
      if Hostname'Length > 0
         and then Hostname'Length <= Max_Hostname_Len
      then
         Cfg.Server_Name.Data (1 .. Hostname'Length) := Hostname;
         Cfg.Server_Name.Len := Hostname'Length;
      end if;
      Init (S, Cfg);
   end Configure;

   procedure Init
     (S   :    out Session;
      Cfg : in     Config)
   is
      CH_Buf    : Byte_Seq (0 .. Handshake.Max_Client_Hello - 1);
      CH_Len    : N32;
      Rec_Out   : N32;
   begin
      S := (Cfg       => Cfg,
            State     => Client_Hello_Sent,
            Role => Role_Client,
            others    => <>);

      --  Build ClientHello handshake message
      Handshake.Build_Client_Hello (S, CH_Buf, CH_Len);

      if CH_Len = 0 then
         S.State := Error_State;
         S.Last_Error := Internal_Error;
         return;
      end if;

      --  Append to transcript (handshake message, no record header)
      Append_Transcript (S, CH_Buf (0 .. CH_Len - 1));

      --  Wrap in TLS record and write to output buffer
      Records.Build_Handshake_Record
        (Fragment  => CH_Buf (0 .. CH_Len - 1),
         Output    => S.Output,
         Bytes_Out => Rec_Out);

      if Rec_Out = 0 then
         S.State := Error_State;
         S.Last_Error := Insufficient_Buffer;
      end if;
   end Init;

   --  Process a decrypted handshake message during the handshake
   procedure Process_Handshake_Message
     (S      : in out Session;
      Data   : in     Byte_Seq;
      Result :    out Action)
   is
      Msg_Type : Byte;
      Msg_Len  : N32;
      Parse_OK : Boolean;
   begin
      Result := OK;

      Handshake.Parse_Handshake_Header (Data, Msg_Type, Msg_Len, Parse_OK);
      if not Parse_OK then
         S.Last_Error := Decode_Error;
         S.State := Error_State;
         Result := Error_Alert;
         return;
      end if;

      case Msg_Type is
         when Handshake.HT_Encrypted_Extensions =>
            --  For now, just record in transcript and move on.
            --  TODO: parse and validate extensions
            Append_Transcript (S, Data);
            S.State := Wait_Certificate;

         when Handshake.HT_Certificate_Request =>
            --  mTLS: server requests a client certificate.
            --  Record in transcript and set flag; we'll send our cert
            --  after the server's Finished message.
            Append_Transcript (S, Data);
            S.Cert_Request_Received := True;
            --  Stay in Wait_Certificate (server Certificate comes next)

         when Handshake.HT_Certificate =>
            Append_Transcript (S, Data);

            --  Parse Certificate message: extract leaf + intermediates.
            --  Format (past HS header at offset 4):
            --    request_context_len(1) + context +
            --    cert_list_len(3) + entries...
            --  Each entry: cert_len(3) + cert_DER + ext_len(2) + exts
            S.Peer_Cert_Valid := False;
            S.Peer_Int_Count := 0;
            if Msg_Len > 4 and then N32 (Data'Length) >= 4 + Msg_Len then
               declare
                  B   : constant N32 := 4;  --  past HS header
                  --  Skip request_context (1-byte len + content)
                  Ctx_Len : constant N32 := N32 (Data (B));
                  List_Start : constant N32 := B + 1 + Ctx_Len;
                  Pos : N32;
                  Cert_Idx : Natural := 0;  --  0 = leaf, 1+ = intermediates
               begin
                  if List_Start + 3 <= N32 (Data'Length) then
                     --  cert_list length (3 bytes)
                     Pos := List_Start + 3;

                     --  Walk each certificate entry
                     while Pos + 3 <= N32 (Data'Length)
                        and then Cert_Idx <= Max_Pool_Size
                     loop
                        declare
                           C_Len : constant N32 :=
                              N32 (Data (Pos)) * 65536 +
                              N32 (Data (Pos + 1)) * 256 +
                              N32 (Data (Pos + 2));
                        begin
                           Pos := Pos + 3;
                           exit when C_Len = 0
                              or else C_Len > N32 (Max_Cert_DER)
                              or else Pos + C_Len > N32 (Data'Length);

                           if Cert_Idx = 0 then
                              --  First entry is the leaf
                              S.Peer_Cert_DER_Len := C_Len;
                              S.Peer_Cert_DER (0 .. C_Len - 1) :=
                                 Data (Pos .. Pos + C_Len - 1);

                              declare
                                 Cert_X : X509.Byte_Seq
                                    (0 .. X509.N32 (C_Len) - 1);
                                 P_OK : Boolean;
                              begin
                                 for I in N32 range 0 .. C_Len - 1 loop
                                    Cert_X (X509.N32 (I)) :=
                                       X509.Byte (Data (Pos + I));
                                 end loop;
                                 X509.Parse (Cert_X, S.Peer_Cert, P_OK);
                                 S.Peer_Cert_Valid := P_OK
                                    and then X509.Is_Valid (S.Peer_Cert);
                              end;
                           else
                              --  Subsequent entries are intermediates
                              if S.Peer_Int_Count < Max_Pool_Size then
                                 declare
                                    Idx : constant Natural :=
                                       S.Peer_Int_Count;
                                    Int_X : X509.Byte_Seq
                                       (0 .. X509.N32 (C_Len) - 1);
                                    C   : X509.Certificate;
                                    P_OK : Boolean;
                                 begin
                                    for I in N32 range 0 .. C_Len - 1 loop
                                       Int_X (X509.N32 (I)) :=
                                          X509.Byte (Data (Pos + I));
                                    end loop;
                                    X509.Parse (Int_X, C, P_OK);
                                    if P_OK and then X509.Is_Valid (C) then
                                       S.Peer_Ints (Idx).Cert := C;
                                       for I in X509.N32 range
                                          0 .. X509.N32 (C_Len) - 1
                                       loop
                                          S.Peer_Ints (Idx).DER (I) :=
                                             X509.Byte (Data (Pos + N32 (I)));
                                       end loop;
                                       S.Peer_Ints (Idx).DER_Len :=
                                          X509.N32 (C_Len);
                                       S.Peer_Ints (Idx).Present := True;
                                       S.Peer_Int_Count :=
                                          S.Peer_Int_Count + 1;
                                    end if;
                                 end;
                              end if;
                           end if;

                           Pos := Pos + C_Len;
                           Cert_Idx := Cert_Idx + 1;

                           --  Skip per-cert extensions (2-byte length)
                           exit when Pos + 2 > N32 (Data'Length);
                           declare
                              Ext_Len : constant N32 :=
                                 N32 (Data (Pos)) * 256 +
                                 N32 (Data (Pos + 1));
                           begin
                              Pos := Pos + 2 + Ext_Len;
                           end;
                        end;
                     end loop;
                  end if;
               end;
            end if;

            --  Chain validation (if trust store is configured)
            if not S.Cfg.Skip_Verify
               and then S.Cfg.Trust /= null
               and then S.Cfg.Get_Time /= null
               and then S.Peer_Cert_Valid
            then
               declare
                  Cert_X : X509.Byte_Seq
                     (0 .. X509.N32 (S.Peer_Cert_DER_Len) - 1);
                  VR : Validation_Result;
               begin
                  --  Copy peer DER to X509.Byte_Seq for Validate_Chain
                  for I in N32 range 0 .. S.Peer_Cert_DER_Len - 1 loop
                     Cert_X (X509.N32 (I)) :=
                        X509.Byte (S.Peer_Cert_DER (I));
                  end loop;

                  VR := Validate_Chain
                    (Leaf_DER   => Cert_X,
                     Leaf       => S.Peer_Cert,
                     Ints       => S.Peer_Ints,
                     Int_Count  => S.Peer_Int_Count,
                     Roots      => S.Cfg.Trust.Roots,
                     Root_Count => S.Cfg.Trust.Root_Count,
                     Now        => S.Cfg.Get_Time.all,
                     Hostname   =>
                        S.Cfg.Server_Name.Data (1 .. S.Cfg.Server_Name.Len),
                     Purpose    => S.Cfg.Verify_Purpose,
                     Mode       => S.Cfg.Verify_Mode);

                  if VR /= Valid then
                     S.Last_Error := Bad_Certificate;
                     S.State := Error_State;
                     Result := Error_Alert;
                     return;
                  end if;
               end;
            end if;

            S.State := Wait_Certificate_Verify;

         when Handshake.HT_Certificate_Verify =>
            --  Verify CertificateVerify (RFC 8446 Section 4.4.3)
            declare
               --  Hash length depends on suite: 32 for SHA-256, 48 for SHA-384
               H_Len : constant N32 := S.Hash_Len;
               CV_Hash : Byte_Seq (0 .. H_Len - 1);
            begin
               case S.Negotiated_Suite is
                  when Suite_AES_256_GCM_SHA384 =>
                     CV_Hash := Transcript_Hash_384 (S);
                  when others =>
                     declare
                        H256 : constant Digest := Transcript_Hash_256 (S);
                     begin
                        CV_Hash := H256;
                     end;
               end case;

               Append_Transcript (S, Data);

               if S.Cfg.Skip_Verify then
                  --  -k mode: skip all signature verification
                  S.State := Wait_Server_Finished;
                  return;
               end if;

               if not S.Peer_Cert_Valid then
                  S.Last_Error := Certificate_Verify_Failed;
                  S.State := Error_State;
                  Result := Error_Alert;
                  return;
               end if;

               --  Build the signed content (same for all algorithms):
               --  64*0x20 + "TLS 1.3, server CertificateVerify" + 0x00 + hash
               declare
                  Context_Str : constant String :=
                     "TLS 1.3, server CertificateVerify";
                  Content_Len : constant N32 :=
                     64 + N32 (Context_Str'Length) + 1 + H_Len;
                  Content     : Byte_Seq (0 .. Content_Len - 1);
               begin
                  --  64 spaces
                  Content (0 .. 63) := (others => 16#20#);
                  --  Context string
                  for I in Context_Str'Range loop
                     Content (64 + N32 (I - Context_Str'First)) :=
                        Byte (Character'Pos (Context_Str (I)));
                  end loop;
                  --  Separator
                  Content (64 + N32 (Context_Str'Length)) := 16#00#;
                  --  Transcript hash
                  Content (64 + N32 (Context_Str'Length) + 1 ..
                           64 + N32 (Context_Str'Length) + H_Len) := CV_Hash;

                  if X509.PK_Algorithm (S.Peer_Cert) =
                        X509.Algo_Ed25519 and then
                     Msg_Len >= 68  --  algo(2) + sig_len(2) + sig(64)
                  then
                     --  Ed25519 verification
                     declare
                        SM_Len     : constant N32 := 64 + Content_Len;
                        SM         : Byte_Seq (0 .. SM_Len - 1);
                        M          : Byte_Seq (0 .. SM_Len - 1);
                        CV_PK      : SPARKNaCl.Sign.Signing_PK;
                        PK_Bytes   : Bytes_32;
                        Verify_OK  : Boolean;
                        Verify_Len : I32;
                     begin
                        --  Signature at Data(8..71)
                        SM (0 .. 63) := Data (8 .. 71);
                        SM (64 .. SM_Len - 1) := Content;

                        declare
                           PK : constant X509.Byte_Seq :=
                              X509.PK_Data (S.Peer_Cert);
                        begin
                           for I in 0 .. 31 loop
                              PK_Bytes (N32 (I)) :=
                                 SPARKNaCl.Byte (PK (X509.N32 (I)));
                           end loop;
                        end;
                        SPARKNaCl.Sign.PK_From_Bytes (PK_Bytes, CV_PK);

                        SPARKNaCl.Sign.Open
                          (M      => M,
                           Status => Verify_OK,
                           MLen   => Verify_Len,
                           SM     => SM,
                           PK     => CV_PK);

                        if not Verify_OK then
                           S.Last_Error := Certificate_Verify_Failed;
                           S.State := Error_State;
                           Result := Error_Alert;
                           return;
                        end if;
                     end;

                  elsif X509.PK_Algorithm (S.Peer_Cert) in
                           X509.Algo_EC_P256 |
                           X509.Algo_EC_P384 and then
                        Msg_Len >= 12  --  algo(2) + sig_len(2) + min DER(8)
                  then
                     --  ECDSA verification (P-256 or P-384 based on key size)
                     declare
                        Sig_Algo : constant Unsigned_16 :=
                           Unsigned_16 (Data (4)) * 256 +
                           Unsigned_16 (Data (5));
                        Sig_Len : constant N32 :=
                           N32 (Unsigned_16 (Data (6)) * 256 +
                                Unsigned_16 (Data (7)));
                        Sig_Start : constant N32 := 8;
                        EC_Size : constant N32 :=
                           N32 (X509.PK_Length (S.Peer_Cert));
                        Verify_OK : Boolean := False;
                     begin
                        --  Validate signature length
                        if Sig_Len < 8 or else
                           Sig_Start + Sig_Len > N32 (Msg_Len) + 4
                        then
                           S.Last_Error := Certificate_Verify_Failed;
                           S.State := Error_State;
                           Result := Error_Alert;
                           return;
                        end if;

                        if EC_Size = 97 and then Sig_Algo = 16#0503# then
                           --  P-384 ECDSA with SHA-384
                           declare
                              Qx    : Byte_Seq (0 .. 47);
                              Qy    : Byte_Seq (0 .. 47);
                              R_Val : Byte_Seq (0 .. 47) := (others => 0);
                              S_Val : Byte_Seq (0 .. 47) := (others => 0);
                              Hash_In : Bytes_48;
                              Coord_Len : constant N32 := 48;
                           begin
                              --  Parse DER signature
                              declare
                                 Idx : N32 := Sig_Start;
                                 R_Len, S_Len : N32;
                                 R_Off, S_Off : N32;
                              begin
                                 if Data (Idx) /= 16#30# then
                                    S.Last_Error := Certificate_Verify_Failed;
                                    S.State := Error_State;
                                    Result := Error_Alert;
                                    return;
                                 end if;
                                 Idx := Idx + 2;

                                 if Data (Idx) /= 16#02# then
                                    S.Last_Error := Certificate_Verify_Failed;
                                    S.State := Error_State;
                                    Result := Error_Alert;
                                    return;
                                 end if;
                                 Idx := Idx + 1;
                                 R_Len := N32 (Data (Idx));
                                 Idx := Idx + 1;
                                 R_Off := 0;
                                 if R_Len = 49 and then Data (Idx) = 0 then
                                    R_Off := 1;
                                    R_Len := 48;
                                 end if;
                                 if R_Len <= Coord_Len then
                                    for I in N32 range 0 .. R_Len - 1 loop
                                       R_Val (Coord_Len - R_Len + I) :=
                                          Data (Idx + R_Off + I);
                                    end loop;
                                 end if;
                                 Idx := Idx + R_Off + R_Len;

                                 if Data (Idx) /= 16#02# then
                                    S.Last_Error := Certificate_Verify_Failed;
                                    S.State := Error_State;
                                    Result := Error_Alert;
                                    return;
                                 end if;
                                 Idx := Idx + 1;
                                 S_Len := N32 (Data (Idx));
                                 Idx := Idx + 1;
                                 S_Off := 0;
                                 if S_Len = 49 and then Data (Idx) = 0 then
                                    S_Off := 1;
                                    S_Len := 48;
                                 end if;
                                 if S_Len <= Coord_Len then
                                    for I in N32 range 0 .. S_Len - 1 loop
                                       S_Val (Coord_Len - S_Len + I) :=
                                          Data (Idx + S_Off + I);
                                    end loop;
                                 end if;
                              end;

                              --  Extract EC public key (skip 0x04 prefix)
                              declare
                                 PK : constant X509.Byte_Seq :=
                                    X509.PK_Data (S.Peer_Cert);
                              begin
                                 for I in 0 .. 47 loop
                                    Qx (N32 (I)) :=
                                       Byte (PK (X509.N32 (1 + I)));
                                    Qy (N32 (I)) :=
                                       Byte (PK (X509.N32 (49 + I)));
                                 end loop;
                              end;

                              --  Hash the signed content with SHA-384
                              declare
                                 D : SPARKNaCl.Hashing.SHA384.Digest;
                              begin
                                 SPARKNaCl.Hashing.SHA384.Hash (D, Content);
                                 Hash_In := Bytes_48 (D);
                              end;

                              Verify_OK := SPARKTLS.P384.ECDSA.Verify
                                (Hash => Hash_In,
                                 Qx   => Qx,
                                 Qy   => Qy,
                                 R    => R_Val,
                                 S    => S_Val);
                           end;

                        elsif EC_Size = 65 then
                           --  P-256 ECDSA with SHA-256
                           declare
                              use SPARKTLS.P256.ECDSA;
                              Qx      : ECDSA_Sig_Half;
                              Qy      : ECDSA_Sig_Half;
                              R_Val   : ECDSA_Sig_Half := (others => 0);
                              S_Val   : ECDSA_Sig_Half := (others => 0);
                              Hash_In : Bytes_32;
                           begin
                              --  Parse DER signature
                              declare
                                 Idx : N32 := Sig_Start;
                                 R_Len, S_Len : N32;
                                 R_Off, S_Off : N32;
                              begin
                                 if Data (Idx) /= 16#30# then
                                    S.Last_Error := Certificate_Verify_Failed;
                                    S.State := Error_State;
                                    Result := Error_Alert;
                                    return;
                                 end if;
                                 Idx := Idx + 2;

                                 if Data (Idx) /= 16#02# then
                                    S.Last_Error := Certificate_Verify_Failed;
                                    S.State := Error_State;
                                    Result := Error_Alert;
                                    return;
                                 end if;
                                 Idx := Idx + 1;
                                 R_Len := N32 (Data (Idx));
                                 Idx := Idx + 1;
                                 R_Off := 0;
                                 if R_Len = 33 and then Data (Idx) = 0 then
                                    R_Off := 1;
                                    R_Len := 32;
                                 end if;
                                 if R_Len <= 32 then
                                    for I in N32 range 0 .. R_Len - 1 loop
                                       R_Val (32 - R_Len + I) :=
                                          Data (Idx + R_Off + I);
                                    end loop;
                                 end if;
                                 Idx := Idx + R_Off + R_Len;

                                 if Data (Idx) /= 16#02# then
                                    S.Last_Error := Certificate_Verify_Failed;
                                    S.State := Error_State;
                                    Result := Error_Alert;
                                    return;
                                 end if;
                                 Idx := Idx + 1;
                                 S_Len := N32 (Data (Idx));
                                 Idx := Idx + 1;
                                 S_Off := 0;
                                 if S_Len = 33 and then Data (Idx) = 0 then
                                    S_Off := 1;
                                    S_Len := 32;
                                 end if;
                                 if S_Len <= 32 then
                                    for I in N32 range 0 .. S_Len - 1 loop
                                       S_Val (32 - S_Len + I) :=
                                          Data (Idx + S_Off + I);
                                    end loop;
                                 end if;
                              end;

                              --  Extract EC public key (skip 0x04 prefix)
                              declare
                                 PK : constant X509.Byte_Seq :=
                                    X509.PK_Data (S.Peer_Cert);
                              begin
                                 for I in 0 .. 31 loop
                                    Qx (N32 (I)) :=
                                       Byte (PK (X509.N32 (1 + I)));
                                    Qy (N32 (I)) :=
                                       Byte (PK (X509.N32 (33 + I)));
                                 end loop;
                              end;

                              --  Hash the signed content with SHA-256
                              declare
                                 D : Digest;
                              begin
                                 Hash (D, Content);
                                 Hash_In := Bytes_32 (D);
                              end;

                              Verify_OK := SPARKTLS.P256.ECDSA.Verify
                                (Hash => Hash_In,
                                 Qx   => Qx,
                                 Qy   => Qy,
                                 R    => R_Val,
                                 S    => S_Val);
                           end;

                        else
                           S.Last_Error := Certificate_Verify_Failed;
                           S.State := Error_State;
                           Result := Error_Alert;
                           return;
                        end if;

                        if not Verify_OK then
                           S.Last_Error := Certificate_Verify_Failed;
                           S.State := Error_State;
                           Result := Error_Alert;
                           return;
                        end if;
                     end;

                  elsif X509.PK_Algorithm (S.Peer_Cert) =
                           X509.Algo_RSA and then
                        Msg_Len >= 8  --  algo(2) + sig_len(2) + min sig
                  then
                     --  RSA-PSS-RSAE verification (SHA-256/384/512)
                     declare
                        Sig_Algo : constant Unsigned_16 :=
                           Unsigned_16 (Data (4)) * 256 +
                           Unsigned_16 (Data (5));
                        Sig_Len : constant N32 :=
                           N32 (Unsigned_16 (Data (6)) * 256 +
                                Unsigned_16 (Data (7)));
                        Raw_Mod_Len : constant Natural :=
                           Natural (X509.PK_Length (S.Peer_Cert));
                        --  Strip leading zero byte from ASN.1 INTEGER
                        PK_Tmp : constant X509.Byte_Seq :=
                           (if Raw_Mod_Len > 0
                            then X509.PK_Data (S.Peer_Cert)
                            else X509.Byte_Seq'(0 => 0));
                        Mod_Skip : constant Natural :=
                           (if Raw_Mod_Len > 0 and then
                               PK_Tmp (0) = 0
                            then 1 else 0);
                        Mod_Len : constant Natural :=
                           Raw_Mod_Len - Mod_Skip;
                        Verify_OK : Boolean := False;
                        --  Determine hash variant from algorithm code
                        PSS_Alg  : SPARKTLS.RSA.PSS_Hash;
                        PSS_HLen : N32;
                     begin
                        case Sig_Algo is
                           when 16#0804# =>
                              PSS_Alg  := SPARKTLS.RSA.PSS_SHA256;
                              PSS_HLen := 32;
                           when 16#0805# =>
                              PSS_Alg  := SPARKTLS.RSA.PSS_SHA384;
                              PSS_HLen := 48;
                           when 16#0806# =>
                              PSS_Alg  := SPARKTLS.RSA.PSS_SHA512;
                              PSS_HLen := 64;
                           when others =>
                              S.Last_Error := Certificate_Verify_Failed;
                              S.State := Error_State;
                              Result := Error_Alert;
                              return;
                        end case;

                        --  Validate: sig fits in message, matches modulus
                        if Sig_Len < 64 or else
                           8 + Sig_Len > N32 (Msg_Len) + 4 or else
                           Natural (Sig_Len) /= Mod_Len or else
                           Mod_Len > SPARKTLS.RSA.Max_RSA_Bytes
                        then
                           S.Last_Error := Certificate_Verify_Failed;
                           S.State := Error_State;
                           Result := Error_Alert;
                           return;
                        end if;

                        --  Hash the signed content with appropriate hash
                        declare
                           M_Hash : Byte_Seq (0 .. PSS_HLen - 1);
                        begin
                           case PSS_Alg is
                              when SPARKTLS.RSA.PSS_SHA256 =>
                                 declare
                                    D : SPARKNaCl.Hashing.SHA256.Digest;
                                 begin
                                    SPARKNaCl.Hashing.SHA256.Hash
                                      (D, Content);
                                    M_Hash := Byte_Seq (D);
                                 end;
                              when SPARKTLS.RSA.PSS_SHA384 =>
                                 declare
                                    D : SPARKNaCl.Hashing.SHA384.Digest;
                                 begin
                                    SPARKNaCl.Hashing.SHA384.Hash
                                      (D, Content);
                                    M_Hash := Byte_Seq (D);
                                 end;
                              when SPARKTLS.RSA.PSS_SHA512 =>
                                 declare
                                    D : SPARKNaCl.Hashing.SHA512.Digest;
                                 begin
                                    SPARKNaCl.Hashing.SHA512.Hash
                                      (D, Content);
                                    M_Hash := Byte_Seq (D);
                                 end;
                           end case;

                           --  Extract modulus and signature, verify
                           declare
                              Mod_Bytes : Byte_Seq
                                 (0 .. N32 (Mod_Len) - 1);
                              Sig_Bytes : Byte_Seq (0 .. Sig_Len - 1);
                           begin
                              for I in 0 .. Mod_Len - 1 loop
                                 Mod_Bytes (N32 (I)) :=
                                    Byte (PK_Tmp (X509.N32
                                       (Mod_Skip + I)));
                              end loop;
                              Sig_Bytes :=
                                 Data (8 .. 8 + Sig_Len - 1);

                              Verify_OK :=
                                 SPARKTLS.RSA.Verify_PSS
                                   (M_Hash    => M_Hash,
                                    Hash_Len  => PSS_HLen,
                                    Hash_Alg  => PSS_Alg,
                                    Modulus   => Mod_Bytes,
                                    Mod_Len   => N32 (Mod_Len),
                                    Exponent  =>
                                       X509.RSA_Exponent
                                          (S.Peer_Cert),
                                    Signature => Sig_Bytes,
                                    Sig_Len   => Sig_Len);
                           end;
                        end;

                        if not Verify_OK then
                           S.Last_Error := Certificate_Verify_Failed;
                           S.State := Error_State;
                           Result := Error_Alert;
                           return;
                        end if;
                     end;

                  else
                     --  Unsupported signature algorithm
                     S.Last_Error := Certificate_Verify_Failed;
                     S.State := Error_State;
                     Result := Error_Alert;
                     return;
                  end if;
               end;
            end;

            S.State := Wait_Server_Finished;

         when Handshake.HT_Finished =>
            --  Verify server Finished (RFC 8446 Section 4.4.4)
            --  verify_data length = Hash.length (32 for SHA-256, 48 for SHA-384)
            declare
               H_Len : constant N32 := S.Hash_Len;
               Verified : Boolean := False;
            begin
               case S.Negotiated_Suite is
               when Suite_AES_256_GCM_SHA384 =>
                  declare
                     use HKDF384;
                     Pre_Hash : constant Key_Schedule.Digest_384 :=
                        Transcript_Hash_384 (S);
                     Fin_Key  : OKM384_Seq (0 .. 47);
                     Expected : Bytes_48;
                  begin
                     Append_Transcript (S, Data);
                     Key_Schedule.Derive_Finished_Key_384
                       (Fin_Key, S.Server_HS_Secret);
                     HMAC384.HMAC_SHA_384
                       (Output => Expected,
                        M      => Pre_Hash,
                        K      => Byte_Seq (Fin_Key));

                     if Msg_Len = 48 and then
                        N32 (Data'Length) >= 52
                     then
                        if Equal (Expected,
                                  Bytes_48 (Data (4 .. 51))) then
                           Verified := True;
                        end if;
                     end if;
                  end;
               when others =>
                  declare
                     Pre_Hash : constant Digest := Transcript_Hash_256 (S);
                     Fin_Key  : OKM_Seq (0 .. 31);
                     Expected : Digest;
                  begin
                     Append_Transcript (S, Data);
                     Key_Schedule.Derive_Finished_Key
                       (Fin_Key, S.Server_HS_Secret (0 .. 31));
                     HMAC_SHA_256
                       (Output => Expected,
                        M      => Pre_Hash,
                        K      => Byte_Seq (Fin_Key));

                     if Msg_Len = 32 and then
                        N32 (Data'Length) >= 36
                     then
                        if Equal (Expected,
                                  Bytes_32 (Data (4 .. 35))) then
                           Verified := True;
                        end if;
                     end if;
                  end;
               end case;

               if not Verified then
                  S.Last_Error := Handshake_Failure;
                  S.State := Error_State;
                  Result := Error_Alert;
                  return;
               end if;
            end;

            --  Server Finished verified. Now derive application keys
            --  and send Client Finished.
            Derive_App_Keys_And_Send_Finished (S, Result);

         when others =>
            --  Unknown handshake message, skip
            Append_Transcript (S, Data);
      end case;
   end Process_Handshake_Message;

   --  mTLS: send client Certificate + CertificateVerify if requested.
   --  Called before sending Client Finished.
   procedure Send_Client_Certificate
     (S      : in out Session;
      Result :    out Action)
   is
      Enc_Out : N32;
   begin
      Result := OK;

      if not S.Cert_Request_Received then
         return;
      end if;

      if S.Cfg.Local = null or else not S.Cfg.Local.Has_Identity then
         --  Server requested cert but we have none.
         --  Send empty Certificate message (allowed by RFC 8446 §4.4.2).
         declare
            Empty_Cert : Byte_Seq (0 .. 7);
         begin
            --  HS header: type=Certificate(0x0B), length=4
            Empty_Cert (0) := Handshake.HT_Certificate;
            Empty_Cert (1) := 0;
            Empty_Cert (2) := 0;
            Empty_Cert (3) := 4;
            --  Body: context_len=0, cert_list_len=0
            Empty_Cert (4) := 0;  --  context length
            Empty_Cert (5) := 0;  --  list length (3 bytes)
            Empty_Cert (6) := 0;
            Empty_Cert (7) := 0;

            Append_Transcript (S, Empty_Cert);
            Records.Build_Encrypted_Record
              (Plaintext  => Empty_Cert,
               Inner_Type => 16#16#,
               Keys       => S.Client_HS,
               Output     => S.Output,
               Bytes_Out  => Enc_Out);
         end;
         return;
      end if;

      --  Send our Certificate
      declare
         Cert_Buf : Byte_Seq (0 .. S.Cfg.Local.NaCl_Cert_Len + 15);
         Cert_Len : N32;
      begin
         Handshake.Build_Certificate
           (Cert_DER => S.Cfg.Local.NaCl_Cert_DER,
            Cert_Len => S.Cfg.Local.NaCl_Cert_Len,
            Result   => Cert_Buf,
            Len      => Cert_Len);

         if Cert_Len > 0 then
            Append_Transcript (S, Cert_Buf (0 .. Cert_Len - 1));
            Records.Build_Encrypted_Record
              (Plaintext  => Cert_Buf (0 .. Cert_Len - 1),
               Inner_Type => 16#16#,
               Keys       => S.Client_HS,
               Output     => S.Output,
               Bytes_Out  => Enc_Out);
         end if;
      end;

      --  Send CertificateVerify
      if S.Cfg.Local.Sign_Algo = Sign_Ed25519 then
         declare
            H_Len : constant N32 := S.Hash_Len;
            CV_Hash : Byte_Seq (0 .. H_Len - 1);
         begin
            case S.Negotiated_Suite is
               when Suite_AES_256_GCM_SHA384 =>
                  CV_Hash := Transcript_Hash_384 (S);
               when others =>
                  declare
                     H : constant Digest := Transcript_Hash_256 (S);
                  begin
                     CV_Hash := H;
                  end;
            end case;

            declare
               CV_Buf : Byte_Seq (0 .. 199);
               CV_Len : N32;
            begin
               Handshake.Build_Certificate_Verify
                 (Transcript_Hash => CV_Hash,
                  Id              => S.Cfg.Local.all,
                  Sig_Algo_Wire   => S.Negotiated_Sig_Algo,
                  Role            => Role_Client,
                  Random          => S.Cfg.Random,
                  Result          => CV_Buf,
                  Len             => CV_Len);

               if CV_Len > 0 then
                  Append_Transcript (S, CV_Buf (0 .. CV_Len - 1));
                  Records.Build_Encrypted_Record
                    (Plaintext  => CV_Buf (0 .. CV_Len - 1),
                     Inner_Type => 16#16#,
                     Keys       => S.Client_HS,
                     Output     => S.Output,
                     Bytes_Out  => Enc_Out);
               end if;
            end;
         end;
      end if;
   end Send_Client_Certificate;

   --  After verifying server Finished, derive app keys and send client Finished
   procedure Derive_App_Keys_And_Send_Finished
     (S      : in out Session;
      Result :    out Action)
   is
      Finished_Buf : Byte_Seq (0 .. 35);
      Finished_Len : N32;
      CCS_Out      : N32;
      Enc_Out      : N32;
      Verify_32    : Bytes_32;
      Cert_Result  : Action;
   begin
      Result := OK;

      --  mTLS: send client certificate before Finished if requested
      Send_Client_Certificate (S, Cert_Result);
      if Cert_Result = Error_Alert then
         Result := Error_Alert;
         return;
      end if;

      case S.Negotiated_Suite is
      when Suite_AES_256_GCM_SHA384 =>
         declare
            use HKDF384;
            TS_Hash : constant Key_Schedule.Digest_384 :=
               Transcript_Hash_384 (S);
            Finished_Key_384 : OKM384_Seq (0 .. 47);
            Verify_48        : Bytes_48;
            Master           : Key_Schedule.Digest_384;
            Client_App_Sec   : OKM384_Seq (0 .. 47);
            Server_App_Sec   : OKM384_Seq (0 .. 47);
         begin
            Key_Schedule.Derive_Finished_Key_384
              (Finished_Key_384, S.Client_HS_Secret);

            HMAC384.HMAC_SHA_384
              (Output => Verify_48,
               M      => TS_Hash,
               K      => Byte_Seq (Finished_Key_384));

            --  Build Finished: verify_data is 48 bytes for SHA-384
            --  but Build_Finished expects Bytes_32. We need a larger variant.
            --  For now, use only first 32 bytes - wait, that's wrong.
            --  TLS 1.3 finished verify_data length = Hash.length.
            --  For SHA-384, it's 48 bytes. Let me build it manually.
            Finished_Buf := (others => 0);
            Finished_Buf (0) := Handshake.HT_Finished;
            Finished_Buf (1) := 16#00#;
            Finished_Buf (2) := 16#00#;
            Finished_Buf (3) := 16#30#;  --  48 decimal = 0x30
            --  We need a bigger buffer for 48-byte verify data
            declare
               Big_Finished : Byte_Seq (0 .. 51);  -- 4 + 48
            begin
               Big_Finished (0) := Handshake.HT_Finished;
               Big_Finished (1) := 16#00#;
               Big_Finished (2) := 16#00#;
               Big_Finished (3) := 16#30#;  --  48
               Big_Finished (4 .. 51) := Verify_48;

               Records.Build_CCS_Record (S.Output, CCS_Out);
               Records.Build_Encrypted_Record
                 (Plaintext  => Big_Finished,
                  Inner_Type => 16#16#,
                  Keys       => S.Client_HS,
                  Output     => S.Output,
                  Bytes_Out  => Enc_Out);
            end;

            if Enc_Out = 0 then
               S.Last_Error := Insufficient_Buffer;
               S.State := Error_State;
               Result := Error_Alert;
               return;
            end if;

            Key_Schedule.Derive_Master_Secret_384
              (Master, Key_Schedule.Digest_384 (S.Handshake_Secret));

            Key_Schedule.Derive_App_Traffic_Secrets_384
              (Client_App_Sec, Server_App_Sec, Master, TS_Hash);

            S.Master_Secret := Bytes_48 (Master);

            --  Set app traffic keys
            S.Client_HS_Secret := Bytes_48 (Byte_Seq (Client_App_Sec));
            Set_Traffic_Keys (S.Client_App,
                              Bytes_48 (Byte_Seq (Client_App_Sec)),
                              S.Negotiated_Suite);
            Set_Traffic_Keys (S.Server_App,
                              Bytes_48 (Byte_Seq (Server_App_Sec)),
                              S.Negotiated_Suite);
         end;
      when others =>
         --  SHA-256 suites
         declare
            TS_Hash : constant Digest := Transcript_Hash_256 (S);
            Client_Finished_Key : OKM_Seq (0 .. 31);
            Client_Verify       : Digest;
            Master              : Digest;
            Client_App_Sec      : OKM_Seq (0 .. 31);
            Server_App_Sec      : OKM_Seq (0 .. 31);
         begin
            Key_Schedule.Derive_Finished_Key
              (Client_Finished_Key, S.Client_HS_Secret (0 .. 31));

            HMAC_SHA_256
              (Output => Client_Verify,
               M      => TS_Hash,
               K      => Byte_Seq (Client_Finished_Key));

            Handshake.Build_Finished
              (Client_Verify, Finished_Buf, Finished_Len);

            Records.Build_CCS_Record (S.Output, CCS_Out);
            Records.Build_Encrypted_Record
              (Plaintext  => Finished_Buf (0 .. Finished_Len - 1),
               Inner_Type => 16#16#,
               Keys       => S.Client_HS,
               Output     => S.Output,
               Bytes_Out  => Enc_Out);

            if Enc_Out = 0 then
               S.Last_Error := Insufficient_Buffer;
               S.State := Error_State;
               Result := Error_Alert;
               return;
            end if;

            Key_Schedule.Derive_Master_Secret
              (Master, Digest (S.Handshake_Secret (0 .. 31)));

            Key_Schedule.Derive_App_Traffic_Secrets
              (Client_App_Sec, Server_App_Sec,
               Master, TS_Hash);

            S.Master_Secret := (others => 0);
            S.Master_Secret (0 .. 31) := Bytes_32 (Digest (Master));

            declare
               CS48 : Bytes_48 := (others => 0);
               SS48 : Bytes_48 := (others => 0);
            begin
               CS48 (0 .. 31) := Bytes_32 (Byte_Seq (Client_App_Sec));
               SS48 (0 .. 31) := Bytes_32 (Byte_Seq (Server_App_Sec));
               Set_Traffic_Keys (S.Client_App, CS48, S.Negotiated_Suite);
               Set_Traffic_Keys (S.Server_App, SS48, S.Negotiated_Suite);
            end;
         end;
      end case;

      S.State := Client_Finished_Sent;
      Result := Has_Output;
   end Derive_App_Keys_And_Send_Finished;

   procedure Advance
     (S      : in out Session;
      Result :    out Action)
   is
   begin
      case S.State is
         when Client_Hello_Sent =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               S.State := Wait_Server_Hello;
               Result := Need_Input;
            end if;

         when Wait_Server_Hello =>
            if Input_Available (S) = 0 then
               Result := Need_Input;
               return;
            end if;

            --  Parse record from input
            declare
               Rec : Records.Parse_Result;
            begin
               Records.Parse_Record_Header
                 (Data  => S.Input.Data (S.Input.Read_Pos ..
                                          S.Input.Write_Pos - 1),
                  Avail => Available (S.Input),
                  Result => Rec);

               if not Rec.OK then
                  Result := Need_Input;
                  return;
               end if;

               case Rec.Content is
                  when Records.Content_Handshake =>
                     declare
                        Frag_Start : constant N32 :=
                           S.Input.Read_Pos + Rec.Fragment_Pos;
                        Frag : Byte_Seq renames
                           S.Input.Data (Frag_Start ..
                                          Frag_Start + Rec.Fragment_Len - 1);
                        Parse_OK : Boolean;
                     begin
                        Handshake.Parse_Server_Hello (S, Frag, Parse_OK);

                        if not Parse_OK then
                           S.Last_Error := Handshake_Failure;
                           S.State := Error_State;
                           Result := Error_Alert;
                           S.Input.Read_Pos :=
                              S.Input.Read_Pos + Rec.Record_Len;
                           return;
                        end if;

                        --  Add ServerHello to transcript
                        Append_Transcript (S, Frag);

                        --  Derive handshake secrets
                        Derive_Handshake_Keys (S);

                        S.Input.Read_Pos :=
                           S.Input.Read_Pos + Rec.Record_Len;
                        S.State := Wait_Encrypted_Extensions;
                        Result := OK;
                     end;

                  when others =>
                     --  Skip unexpected record
                     S.Input.Read_Pos :=
                        S.Input.Read_Pos + Rec.Record_Len;
                     Result := OK;
               end case;
            end;

         when Wait_Encrypted_Extensions
            | Wait_Certificate
            | Wait_Certificate_Verify
            | Wait_Server_Finished =>
            --  All these states expect encrypted handshake records
            Process_Encrypted_Handshake (S, Result);

         when Client_Finished_Sent =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               S.State := Connected;
               Result := Handshake_Done;
            end if;

         when Connected =>
            Process_Connected (S, Result);

         when Closing =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               S.State := Closed;
               Result := Shutdown;
            end if;

         when others =>
            S.Last_Error := Internal_Error;
            S.State := Error_State;
            Result := Error_Alert;
      end case;
   end Advance;

   --  Helper: derive key/IV and set Traffic_Keys based on suite
   procedure Set_Traffic_Keys
     (TK     : in out Traffic_Keys;
      Secret : in     Bytes_48;
      Suite  : in     Unsigned_16)
   is
   begin
      case Suite is
         when Suite_AES_256_GCM_SHA384 =>
            declare
               K384 : HKDF384.OKM384_Seq (0 .. 31);
               IV384 : HKDF384.OKM384_Seq (0 .. 11);
            begin
               Key_Schedule.Derive_Traffic_Key_IV_256
                 (K384, IV384, Secret);
               TK.Key := Bytes_32 (Byte_Seq (K384));
               TK.IV  := Bytes_12 (Byte_Seq (IV384));
            end;
         when Suite_AES_128_GCM_SHA256 =>
            declare
               K128 : OKM_Seq (0 .. 15);
               IV12 : OKM_Seq (0 .. 11);
            begin
               Key_Schedule.Derive_Traffic_Key_IV_128
                 (K128, IV12, Secret (0 .. 31));
               TK.Key := (others => 0);
               TK.Key (0 .. 15) := Bytes_16 (Byte_Seq (K128));
               TK.IV  := Bytes_12 (Byte_Seq (IV12));
            end;
         when others =>
            --  ChaCha20-Poly1305: 32-byte key
            declare
               K32 : OKM_Seq (0 .. 31);
               IV12 : OKM_Seq (0 .. 11);
            begin
               Key_Schedule.Derive_Traffic_Key_IV
                 (K32, IV12, Secret (0 .. 31));
               TK.Key := Bytes_32 (Byte_Seq (K32));
               TK.IV  := Bytes_12 (Byte_Seq (IV12));
            end;
      end case;
      TK.Counter := 0;
      TK.Suite := Suite;
   end Set_Traffic_Keys;

   --  Derive handshake traffic keys from shared secret
   procedure Derive_Handshake_Keys (S : in out Session) is
   begin
      case S.Negotiated_Suite is
      when Suite_AES_256_GCM_SHA384 =>
         declare
            use HKDF384;
            Hello_Hash : Key_Schedule.Digest_384 :=
               Transcript_Hash_384 (S);
            Early      : Key_Schedule.Digest_384;
            HS_Secret  : Key_Schedule.Digest_384;
            No_PSK     : Bytes_48 := (others => 0);
            Client_Sec : OKM384_Seq (0 .. 47);
            Server_Sec : OKM384_Seq (0 .. 47);
         begin
            Key_Schedule.Derive_Early_Secret_384 (Early, No_PSK);
            --  Use full 48 bytes if P-384 ECDHE, else first 32
            if S.Use_P384_KE then
               Key_Schedule.Derive_Handshake_Secret_384
                 (HS_Secret, Byte_Seq (S.Shared_Secret), Early);
            else
               Key_Schedule.Derive_Handshake_Secret_384
                 (HS_Secret, S.Shared_Secret (0 .. 31), Early);
            end if;

            S.Handshake_Secret := Bytes_48 (HS_Secret);
            S.Hash_Len := 48;

            Key_Schedule.Derive_HS_Traffic_Secrets_384
              (Client_Sec, Server_Sec, HS_Secret, Hello_Hash);

            S.Client_HS_Secret := Bytes_48 (Byte_Seq (Client_Sec));
            S.Server_HS_Secret := Bytes_48 (Byte_Seq (Server_Sec));

            Set_Traffic_Keys (S.Client_HS, S.Client_HS_Secret,
                              S.Negotiated_Suite);
            Set_Traffic_Keys (S.Server_HS, S.Server_HS_Secret,
                              S.Negotiated_Suite);
         end;
      when others =>
         --  SHA-256 suites (0x1301, 0x1303)
         declare
            Hello_Hash : Digest := Transcript_Hash_256 (S);
            Early      : Digest;
            HS_Secret  : Digest;
            No_PSK     : Bytes_32 := (others => 0);
            Client_Sec : OKM_Seq (0 .. 31);
            Server_Sec : OKM_Seq (0 .. 31);
         begin
            Key_Schedule.Derive_Early_Secret (Early, No_PSK);
            --  Pass full shared secret: 48 bytes for P-384, 32 for others
            if S.Use_P384_KE then
               Key_Schedule.Derive_Handshake_Secret
                 (HS_Secret, Byte_Seq (S.Shared_Secret), Early);
            else
               Key_Schedule.Derive_Handshake_Secret
                 (HS_Secret, S.Shared_Secret (0 .. 31), Early);
            end if;

            S.Handshake_Secret := (others => 0);
            S.Handshake_Secret (0 .. 31) := Bytes_32 (Digest (HS_Secret));
            S.Hash_Len := 32;

            Key_Schedule.Derive_HS_Traffic_Secrets
              (Client_Sec, Server_Sec, HS_Secret, Hello_Hash);

            S.Client_HS_Secret := (others => 0);
            S.Client_HS_Secret (0 .. 31) :=
               Bytes_32 (Byte_Seq (Client_Sec));
            S.Server_HS_Secret := (others => 0);
            S.Server_HS_Secret (0 .. 31) :=
               Bytes_32 (Byte_Seq (Server_Sec));

            Set_Traffic_Keys (S.Client_HS, S.Client_HS_Secret,
                              S.Negotiated_Suite);
            Set_Traffic_Keys (S.Server_HS, S.Server_HS_Secret,
                              S.Negotiated_Suite);
         end;
      end case;
   end Derive_Handshake_Keys;

   --  Process encrypted handshake records (post-ServerHello)
   procedure Process_Encrypted_Handshake
     (S      : in out Session;
      Result :    out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         return;
      end if;

      Records.Parse_Record_Header
        (Data  => S.Input.Data (S.Input.Read_Pos ..
                                 S.Input.Write_Pos - 1),
         Avail => Available (S.Input),
         Result => Rec);

      if not Rec.OK then
         Result := Need_Input;
         return;
      end if;

      case Rec.Content is
         when Records.Content_Change_Cipher_Spec =>
            --  CCS for middlebox compatibility, ignore
            S.CCS_Received := True;
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;

         when Records.Content_Application_Data =>
            --  This is an encrypted handshake record
            declare
               Frag_Start : constant N32 :=
                  S.Input.Read_Pos + Rec.Fragment_Pos;
               --  Copy to 0-indexed locals (Decrypt_Record requires
               --  0-indexed inputs)
               Encrypted  : Byte_Seq (0 .. Rec.Fragment_Len - 1) :=
                  S.Input.Data (Frag_Start ..
                                 Frag_Start + Rec.Fragment_Len - 1);
               Hdr        : Byte_Seq (0 .. 4) :=
                  S.Input.Data (S.Input.Read_Pos ..
                                 S.Input.Read_Pos + 4);
               Plaintext  : Byte_Seq (0 .. Rec.Fragment_Len - 1);
               Plain_Len  : N32;
               Inner_Type : Byte;
               Dec_Valid  : Boolean;
            begin
               if Rec.Fragment_Len <= Records.Tag_Size then
                  S.Last_Error := Decode_Error;
                  S.State := Error_State;
                  Result := Error_Alert;
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  return;
               end if;

               Records.Decrypt_Record
                 (Encrypted  => Encrypted,
                  Record_Hdr => Hdr,
                  Keys       => S.Server_HS,
                  Plaintext  => Plaintext,
                  Plain_Len  => Plain_Len,
                  Inner_Type => Inner_Type,
                  Valid      => Dec_Valid);

               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

               if not Dec_Valid then
                  S.Last_Error := Bad_Record_MAC;
                  S.State := Error_State;
                  Result := Error_Alert;
                  return;
               end if;

               --  Inner type should be handshake (0x16)
               --  A single encrypted record may contain multiple
               --  handshake messages; process them all.
               if Inner_Type = 16#16# then
                  declare
                     Pos : N32 := 0;
                  begin
                     while Pos + 4 <= Plain_Len loop
                        --  Each handshake message: type(1) + length(3)
                        declare
                           HS_Len : constant N32 :=
                              N32 (Plaintext (Pos + 1)) * 65536 +
                              N32 (Plaintext (Pos + 2)) * 256 +
                              N32 (Plaintext (Pos + 3));
                           Msg_End : constant N32 := Pos + 4 + HS_Len;
                        begin
                           if Msg_End > Plain_Len then
                              exit;  --  incomplete message
                           end if;
                           --  Rebase to 0-indexed since
                           --  Process_Handshake_Message assumes
                           --  Data'First = 0.
                           declare
                              Msg_Len_Loc : constant N32 :=
                                 Msg_End - Pos;
                              Msg_Copy : Byte_Seq (0 .. Msg_Len_Loc - 1);
                           begin
                              Msg_Copy := Plaintext (Pos .. Msg_End - 1);
                              Process_Handshake_Message
                                (S, Msg_Copy, Result);
                           end;
                           if Result = Error_Alert then
                              exit;
                           end if;
                           Pos := Msg_End;
                        end;
                     end loop;
                  end;
               elsif Inner_Type = 16#15# then
                  --  Alert
                  S.Last_Error := Unexpected_Message;
                  S.State := Error_State;
                  Result := Error_Alert;
               else
                  Result := OK;
               end if;
            end;

         when others =>
            --  Skip unexpected
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
      end case;
   end Process_Encrypted_Handshake;

   --  Process records in Connected state
   procedure Process_Connected
     (S      : in out Session;
      Result :    out Action)
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         if Output_Pending (S) > 0 then
            Result := Has_Output;
         else
            Result := Need_Input;
         end if;
         return;
      end if;

      Records.Parse_Record_Header
        (Data  => S.Input.Data (S.Input.Read_Pos ..
                                 S.Input.Write_Pos - 1),
         Avail => Available (S.Input),
         Result => Rec);

      if not Rec.OK then
         Result := Need_Input;
         return;
      end if;

      if Rec.Content /= Records.Content_Application_Data then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK;
         return;
      end if;

      declare
         Frag_Start : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Encrypted  : Byte_Seq (0 .. Rec.Fragment_Len - 1) :=
            S.Input.Data (Frag_Start ..
                           Frag_Start + Rec.Fragment_Len - 1);
         Hdr        : Byte_Seq (0 .. 4) :=
            S.Input.Data (S.Input.Read_Pos .. S.Input.Read_Pos + 4);
         Plaintext  : Byte_Seq (0 .. Rec.Fragment_Len - 1);
         Plain_Len  : N32;
         Inner_Type : Byte;
         Dec_Valid  : Boolean;
      begin
         if Rec.Fragment_Len <= Records.Tag_Size then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
            return;
         end if;

         Records.Decrypt_Record
           (Encrypted  => Encrypted,
            Record_Hdr => Hdr,
            Keys       => S.Server_App,
            Plaintext  => Plaintext,
            Plain_Len  => Plain_Len,
            Inner_Type => Inner_Type,
            Valid      => Dec_Valid);

         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

         if not Dec_Valid then
            S.Last_Error := Bad_Record_MAC;
            S.State := Error_State;
            Result := Error_Alert;
            return;
         end if;

         case Inner_Type is
            when 16#17# =>
               --  Application data
               if Plain_Len > 0 and then
                  S.App_Data_Len + Plain_Len <= S.App_Data'Length
               then
                  S.App_Data (S.App_Data_Len ..
                               S.App_Data_Len + Plain_Len - 1) :=
                     Plaintext (0 .. Plain_Len - 1);
                  S.App_Data_Len := S.App_Data_Len + Plain_Len;
                  Result := Plaintext_Ready;
               else
                  Result := OK;
               end if;

            when 16#16# =>
               --  Post-handshake message (NewSessionTicket, etc.)
               --  For now, just skip
               Result := OK;

            when 16#15# =>
               --  Alert
               if Plain_Len >= 2 and then Plaintext (1) = 0 then
                  --  close_notify
                  S.State := Closing;
                  Result := Shutdown;
               else
                  S.Last_Error := Unexpected_Message;
                  S.State := Error_State;
                  Result := Error_Alert;
               end if;

            when others =>
               Result := OK;
         end case;
      end;
   end Process_Connected;

   procedure Write_Plaintext
     (S              : in out Session;
      Plaintext      : in     Byte_Seq;
      Bytes_Written  :    out N32)
   is
      Enc_Out : N32;
   begin
      Records.Build_Encrypted_Record
        (Plaintext  => Plaintext,
         Inner_Type => 16#17#,  --  application_data
         Keys       => S.Client_App,
         Output     => S.Output,
         Bytes_Out  => Enc_Out);

      if Enc_Out > 0 then
         Bytes_Written := N32 (Plaintext'Length);
      else
         Bytes_Written := 0;
      end if;
   end Write_Plaintext;

   procedure Close_Notify (S : in out Session) is
      Alert_Out : N32;
   begin
      Records.Build_Alert_Record
        (Level     => 1,      --  warning
         Desc      => 0,      --  close_notify
         Keys      => S.Client_App,
         Output    => S.Output,
         Bytes_Out => Alert_Out);
      S.State := Closing;
   end Close_Notify;

end SPARKTLS.Client;
