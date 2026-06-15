with Ada.Unchecked_Deallocation;
with Interfaces;                 use Interfaces;
with SPARKNaCl;                  use SPARKNaCl;
with SPARKTLSCrypto.Hashing.SHA256;    use SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Scalar;
with SPARKTLS.Records;           use SPARKTLS.Records;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Client.TLS12.Packed;
with SPARKTLS.Key_Schedule_12;
with SPARKTLS.Cert_Verify;       use SPARKTLS.Cert_Verify;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.Point;
with SPARKTLSCrypto.P384.Field;
with SPARKTLSCrypto.P384.ECDSA;
use SPARKTLSCrypto;
with X509;
use type X509.Algorithm_ID;

with SPARKTLS.RFLX_Bridge;       use SPARKTLS.RFLX_Bridge;
with RFLX.RFLX_Builtin_Types;
with RFLX.TLS_Handshake.TLS_1_2_Certificate;
with RFLX.TLS_Handshake.TLS_1_2_Certificate_Entries;
with RFLX.TLS_Handshake.TLS_1_2_Certificate_Entry;

package body SPARKTLS.Client.TLS12 with
   SPARK_Mode => On
is
   use Handshake.TLS12;

   procedure Send_Alert_And_Error
     (S : in out Session; Err : Error_Code; Result : out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Alert_Desc (Err) /= 0
                and then Alert_Desc (Err) /= 90,
        Post => S.State = Error_State
                and then S.Last_Error = Err
                and then Result in Has_Output | Error_Alert
   is
      Dummy : N32;
   begin
      S.Last_Error := Err;
      Set_State (S, Error_State);
      Records.Build_Plaintext_Alert (2, Alert_Desc (Err), S.Output, Dummy);
      Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
   end Send_Alert_And_Error;

   procedure Append_Transcript (HC : in out Handshake_Context; Data : Byte_Seq)
   --  RFC 5246 §7.4.9 transcript-monotonicity: bytes already
   --  appended cannot be removed. The Post pins this; a future
   --  edit that resets HC.Transcript_Len in this proc would fail.
   with Pre  => (if Data'First <= Data'Last then
                    Data'Last - Data'First < Transcript_Capacity)
                and then HC.Transcript_Len <= Transcript_Capacity,
        Post => HC.Transcript_Len >= HC.Transcript_Len'Old
   is
   begin
      if Data'First <= Data'Last then
         declare
            Len : constant N32 := Data'Last - Data'First + 1;
         begin
            if HC.Transcript_Len <= HC.Transcript'Length - Len then
               HC.Transcript (HC.Transcript_Len ..
                                HC.Transcript_Len + Len - 1) := Data;
               HC.Transcript_Len := HC.Transcript_Len + Len;
            end if;
         end;
      end if;
   end Append_Transcript;

   --  Derive TLS 1.2 keys (same as server, shared secret → master → expand)
   --  Derive AEAD keys from an already-set HC.Master_Secret_12. Used
   --  by RFC 5077 abbreviated client handshake: master_secret was
   --  cached from the previous full handshake and copied into HC by
   --  the SH-parse resume-detection branch; we just need to expand
   --  it into traffic keys + IVs for this connection's randoms.
   procedure Derive_Keys_Resumed_12
     (S : in out Session; HC : in out Handshake_Context)
   with Pre  => Reasm_Coherent (HC),
        Post => Reasm_Coherent (HC)
                and then HC.Reasm_Len = HC.Reasm_Len'Old
                and then HC.Reasm_Need = HC.Reasm_Need'Old
                and then HC.Reasm_Hdr_Pending =
                  HC.Reasm_Hdr_Pending'Old
   is
      use Key_Schedule_12;
      Use_384 : constant Boolean :=
         S.Negotiated_Suite in Suite_ECDHE_RSA_AES256_GCM_SHA384
                             | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
      Key_Len : constant N32 :=
         (if S.Negotiated_Suite in Suite_ECDHE_RSA_AES128_GCM_SHA256
                                 | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
          then 16 else 32);
      IV_Len : constant N32 :=
         (if S.Negotiated_Suite in Suite_ECDHE_RSA_CHACHA20_SHA256
                                 | Suite_ECDHE_ECDSA_CHACHA20_SHA256
          then 12 else 4);
      CK : Byte_Seq (0 .. Key_Len - 1);
      SK : Byte_Seq (0 .. Key_Len - 1);
      CI : Byte_Seq (0 .. 11) := (others => 0);
      SI : Byte_Seq (0 .. 11) := (others => 0);
   begin
      Expand_Keys_12 (CK, SK, CI, SI, HC.Master_Secret_12,
                       HC.Server_Random, HC.Client_Random,
                       Key_Len, IV_Len, Use_384);
      declare
         Int_Suite : constant Unsigned_16 :=
           (case S.Negotiated_Suite is
               when Suite_ECDHE_RSA_AES128_GCM_SHA256
                  | Suite_ECDHE_ECDSA_AES128_GCM_SHA256 =>
                     Suite_AES_128_GCM_SHA256,
               when Suite_ECDHE_RSA_AES256_GCM_SHA384
                  | Suite_ECDHE_ECDSA_AES256_GCM_SHA384 =>
                     Suite_AES_256_GCM_SHA384,
               when others => Suite_CHACHA20_POLY1305_SHA256);
      begin
         S.Client_App := (Key => (others => 0), IV => (others => 0),
                          Counter => 0, Suite => Int_Suite);
         S.Client_App.Key (0 .. Key_Len - 1) := CK;
         S.Server_App := (Key => (others => 0), IV => (others => 0),
                          Counter => 0, Suite => Int_Suite);
         S.Server_App.Key (0 .. Key_Len - 1) := SK;
      end;
      HC.Client_Write_IV_12 := CI;
      HC.Server_Write_IV_12 := SI;
      HC.Client_Seq_12 := 0;
      HC.Server_Seq_12 := 0;
   end Derive_Keys_Resumed_12;

   procedure Derive_Keys_12 (S : in out Session; HC : in out Handshake_Context)
   with Pre => HC.Transcript_Len > 0
               and HC.Transcript_Len <= Transcript_Capacity
               and HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
               and S.Negotiated_Suite in
                  Suite_ECDHE_RSA_AES128_GCM_SHA256
                | Suite_ECDHE_RSA_AES256_GCM_SHA384
                | Suite_ECDHE_RSA_CHACHA20_SHA256
                | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                | Suite_ECDHE_ECDSA_CHACHA20_SHA256,
        Post => S.State = S.State'Old
                and S.Negotiated_Suite = S.Negotiated_Suite'Old
                and HC.Selected_Group = HC.Selected_Group'Old
                and HC.Transcript_Len = HC.Transcript_Len'Old
                and Records.TLS12.Nonce_Space_Available_12
                      (HC.Client_Seq_12)
                and Records.TLS12.Nonce_Space_Available_12
                      (HC.Server_Seq_12)
   is
      use Key_Schedule_12;
      Use_384 : constant Boolean :=
         S.Negotiated_Suite in Suite_ECDHE_RSA_AES256_GCM_SHA384
                             | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
      Key_Len : constant N32 :=
         (if S.Negotiated_Suite in Suite_ECDHE_RSA_AES128_GCM_SHA256
                                 | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
          then 16 else 32);
      --  RFC 5288 §3: AES-GCM IV salt is 4 bytes.
      --  RFC 7905 §2: ChaCha20-Poly1305 IV is 12 bytes.
      IV_Len : constant N32 :=
         (if S.Negotiated_Suite in Suite_ECDHE_RSA_CHACHA20_SHA256
                                 | Suite_ECDHE_ECDSA_CHACHA20_SHA256
          then 12 else 4);
      CK : Byte_Seq (0 .. Key_Len - 1);
      SK : Byte_Seq (0 .. Key_Len - 1);
      CI : Byte_Seq (0 .. 11) := (others => 0);
      SI : Byte_Seq (0 .. 11) := (others => 0);
      Shared_Len : constant N32 :=
         (if HC.Selected_Group = Group_Secp384r1 then 48 else 32);
   begin
      --  Master secret derivation
      --  Verify EMS label consistency at compile/prove time
      pragma Assert
        (EMS_Label_Consistent (True, "extended master secret"));
      pragma Assert
        (EMS_Label_Consistent (False, "master secret"));

      if HC.Use_EMS then
         --  RFC 7627: Extended Master Secret
         --  master_secret = PRF(pms, "extended master secret", Hash(hs_msgs))
         declare
            TH     : Digest;
            TH_384 : SPARKNaCl.Hashing.SHA384.Digest;
         begin
            if Use_384 then
               SPARKNaCl.Hashing.SHA384.Hash
                 (TH_384, HC.Transcript (0 .. HC.Transcript_Len - 1));
               PRF_SHA384 (Byte_Seq (HC.Master_Secret_12),
                           HC.Shared_Secret (0 .. Shared_Len - 1),
                           "extended master secret", Byte_Seq (TH_384));
            else
               Hash (TH, HC.Transcript (0 .. HC.Transcript_Len - 1));
               PRF_SHA256 (Byte_Seq (HC.Master_Secret_12),
                           HC.Shared_Secret (0 .. Shared_Len - 1),
                           "extended master secret", Byte_Seq (TH));
            end if;
         end;
         HC.MS_Derivation := Extended;
      else
         --  RFC 5246 §8.1: Standard master secret
         --  master_secret = PRF(pms, "master secret", CR || SR)
         Key_Schedule_12.Derive_Master_Secret_12
           (HC.Master_Secret_12,
            HC.Shared_Secret (0 .. Shared_Len - 1),
            HC.Client_Random, HC.Server_Random, Use_384);
         HC.MS_Derivation := Legacy;
      end if;

      Expand_Keys_12 (CK, SK, CI, SI, HC.Master_Secret_12,
                       HC.Server_Random, HC.Client_Random,
                       Key_Len, IV_Len, Use_384);

      declare
         Int_Suite : constant Unsigned_16 :=
           (case S.Negotiated_Suite is
               when Suite_ECDHE_RSA_AES128_GCM_SHA256
                  | Suite_ECDHE_ECDSA_AES128_GCM_SHA256 =>
                     Suite_AES_128_GCM_SHA256,
               when Suite_ECDHE_RSA_AES256_GCM_SHA384
                  | Suite_ECDHE_ECDSA_AES256_GCM_SHA384 =>
                     Suite_AES_256_GCM_SHA384,
               when others => Suite_CHACHA20_POLY1305_SHA256);
         pragma Assert
           (Int_Suite = Handshake.TLS12.Internal_Suite_For
                          (S.Negotiated_Suite));
      begin
         S.Client_App := (Key => (others => 0), IV => (others => 0),
                          Counter => 0, Suite => Int_Suite);
         S.Client_App.Key (0 .. Key_Len - 1) := CK;
         S.Server_App := (Key => (others => 0), IV => (others => 0),
                          Counter => 0, Suite => Int_Suite);
         S.Server_App.Key (0 .. Key_Len - 1) := SK;
      end;

      HC.Client_Write_IV_12 := CI;
      HC.Server_Write_IV_12 := SI;
      HC.Client_Seq_12 := 0;
      HC.Server_Seq_12 := 0;
   end Derive_Keys_12;

   ------------------------------------------------------------------
   --  Process_Server_Flight: parse Cert + SKE + SHD, then send CKE+CCS+Fin
   ------------------------------------------------------------------

   procedure Process_Server_Flight
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
      with Pre  => Reasm_Coherent (HC)
                   and then (S.State not in Idle | Closing | Closed | Error_State)
                   and then Warning_Alerts_Bounded_RFC_8446_6_1 (S)
                   and then HC.Cfg.Random /= null
                   and then HC.Selected_Group in
                     Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                   and then Valid_ECDHE_Group (HC.Selected_Group)
                   and then HC.Transcript_Len > 0
                   and then HC.Transcript_Len <= Transcript_Capacity
                   and then SPARKTLSCrypto.P384.Field.Initialized
                   and then SPARKTLSCrypto.P384.ECDSA.Initialized,
           Post => Reasm_Coherent (HC);

   --  RFC 5246 §7.4.2 Certificate (HS type 0x0B). Parses the on-wire
   --  cert_list_len(3) || {cert_len(3) || cert_data[cert_len]}* via
   --  RFLX TLS_1_2_Certificate, then runs the leaf through X509.Parse.
   --  Intermediates beyond Max_Pool_Size are silently dropped — chain
   --  validation will fail if the omitted entries were needed.
   --
   --  Mirrors Parse_Certificate_Chain_13 (TLS 1.3), but operates on
   --  the TLS 1.2 RFLX package which lacks per-cert extensions.
   procedure Parse_Cert_Chain_12
     (HC      : in out Handshake_Context;
      Frag    : in     Byte_Seq;
      Msg_Len : in     N32;
      OK      :    out Boolean)
         with Pre  => Msg_Len in 3 .. Max_HS_Msg - 4
                         and then Frag'First >= 0
                         and then Frag'Last < N32'Last - 4
                         and then Frag'First <= N32'Last - 4
                         and then Msg_Len <= N32'Last - Frag'First - 4
                         and then Frag'First + 3 + Msg_Len <= Frag'Last,
        Post => (if HC.Peer_Cert_Valid then
                    HC.Peer_Cert_DER_Len in 1 .. Max_Cert_DER_Len
                    and then X509.Spans_Valid
                      (HC.Peer_Cert, X509.N32 (HC.Peer_Cert_DER_Len) - 1));

   procedure Parse_Cert_Chain_12
     (HC      : in out Handshake_Context;
      Frag    : in     Byte_Seq;
      Msg_Len : in     N32;
      OK      :    out Boolean)
   is
      package C12 renames RFLX.TLS_Handshake.TLS_1_2_Certificate;
      package C12_Entries renames RFLX.TLS_Handshake.TLS_1_2_Certificate_Entries;
      package C12_Entry renames RFLX.TLS_Handshake.TLS_1_2_Certificate_Entry;
      package RBT renames RFLX.RFLX_Builtin_Types;
      procedure RFLX_Free_Local is new
        Ada.Unchecked_Deallocation
          (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
      Buf : RBT.Bytes_Ptr;
      Ctx : C12.Context;
      B   : constant N32 := Frag'First + 4;
      Body_Bytes : Byte_Seq (0 .. Msg_Len - 1);
      Cert_Idx : Natural := 0;
   begin
      HC.Peer_Cert_Valid := False;
      HC.Peer_Int_Count := 0;
      OK := False;

      if Msg_Len < 3 then
         return;
      end if;

      Body_Bytes := Frag (B .. B + Msg_Len - 1);

      Buf := new RBT.Bytes'(1 .. RBT.Index (Msg_Len) => 0);
      Buf.all := To_RFLX (Body_Bytes);
      C12.Initialize
        (Ctx, Buf,
         Written_Last => RBT.Bit_Length (Msg_Len * 8));
      C12.Verify_Message (Ctx);

      if not C12.Well_Formed_Message (Ctx) then
         C12.Take_Buffer (Ctx, Buf);
         RFLX_Free_Local (Buf);
         return;
      end if;

      declare
         use type RBT.Bit_Length;
      begin
         if C12.Field_Size (Ctx, C12.F_Certificate_List) > 0 then
            declare
                  Entries_Ctx : C12_Entries.Context;
               begin
                  if not C12.Has_Buffer (Ctx) then
                     C12.Take_Buffer (Ctx, Buf);
                     RFLX_Free_Local (Buf);
                     return;
                  end if;
                  if not
                    (C12.Valid_Next (Ctx, C12.F_Certificate_List)
                     and then C12.Field_First
                                (Ctx, C12.F_Certificate_List)
                              rem RBT.Byte'Size = 1
                     and then C12.Available_Space
                                (Ctx, C12.F_Certificate_List)
                              >= C12.Field_Size
                                   (Ctx, C12.F_Certificate_List)
                     and then C12.Field_Condition
                                (Ctx, C12.F_Certificate_List))
                  then
                     C12.Take_Buffer (Ctx, Buf);
                     RFLX_Free_Local (Buf);
                     return;
                  end if;
                  C12.Switch_To_Certificate_List (Ctx, Entries_Ctx);
                  while C12_Entries.Has_Element (Entries_Ctx)
                    and then Cert_Idx <= Max_Pool_Size
                  loop
                  pragma Loop_Invariant
                    (if HC.Peer_Cert_Valid
                     then HC.Peer_Cert_DER_Len
                          in 1 .. Max_Cert_DER_Len
                          and then X509.Spans_Valid
                            (HC.Peer_Cert,
                             X509.N32 (HC.Peer_Cert_DER_Len) - 1));
                     declare
                        E_Ctx : C12_Entry.Context;
                  begin
                     C12_Entries.Switch (Entries_Ctx, E_Ctx);
                     C12_Entry.Verify_Message (E_Ctx);
                     if C12_Entry.Well_Formed_Message (E_Ctx) then
                        declare
                           C_Len : constant N32 :=
                             N32 (C12_Entry.Get_Cert_Data_Length (E_Ctx));
                           Cert_RFLX : RBT.Bytes (1 .. RBT.Index (C_Len));
                        begin
                           if C_Len > 0 and C_Len <= N32 (Max_Cert_DER) then
                              C12_Entry.Get_Cert_Data (E_Ctx, Cert_RFLX);
                              if Cert_Idx = 0 then
                                 HC.Peer_Cert_DER_Len := C_Len;
                                 for I in N32 range 0 .. C_Len - 1 loop
                                    HC.Peer_Cert_DER (I) :=
                                       Byte (Cert_RFLX (RBT.Index (I + 1)));
                                 end loop;
                                 declare
                                    Cert_X : X509.Byte_Seq
                                      (0 .. X509.N32 (C_Len) - 1) :=
                                        (others => 0);
                                    P_OK : Boolean;
                                 begin
                                    for I in N32 range 0 .. C_Len - 1 loop
                                       Cert_X (X509.N32 (I)) :=
                                          X509.Byte
                                            (Cert_RFLX (RBT.Index (I + 1)));
                                       end loop;
                                       X509.Parse (Cert_X, HC.Peer_Cert, P_OK);
                                    if P_OK then
                                       pragma Assert
                                         (X509.Spans_Valid
                                            (HC.Peer_Cert,
                                             X509.N32 (C_Len) - 1));
                                       HC.Peer_Cert_Valid :=
                                         X509.Is_Valid (HC.Peer_Cert);
                                       pragma Assert
                                         (if HC.Peer_Cert_Valid
                                          then HC.Peer_Cert_DER_Len
                                               in 1 .. Max_Cert_DER_Len
                                               and then X509.Spans_Valid
                                                 (HC.Peer_Cert,
                                                  X509.N32
                                                    (HC.Peer_Cert_DER_Len)
                                                  - 1));
                                    else
                                       HC.Peer_Cert_Valid := False;
                                    end if;
                                    end;
                              elsif HC.Peer_Int_Count < Max_Pool_Size then
                                 declare
                                    Idx : constant Natural := HC.Peer_Int_Count;
                                    Int_X : X509.Byte_Seq
                                      (0 .. X509.N32 (C_Len) - 1) :=
                                        (others => 0);
                                    C    : X509.Certificate;
                                    P_OK : Boolean;
                                 begin
                                    for I in N32 range 0 .. C_Len - 1 loop
                                       Int_X (X509.N32 (I)) :=
                                          X509.Byte
                                            (Cert_RFLX (RBT.Index (I + 1)));
                                    end loop;
                                       X509.Parse (Int_X, C, P_OK);
                                       if P_OK and then X509.Is_Valid (C) then
                                          pragma Assert
                                            (X509.Spans_Valid
                                               (C, X509.N32 (C_Len) - 1));
                                          HC.Peer_Ints (Idx).Present := False;
                                          HC.Peer_Ints (Idx).Cert := C;
                                          for I in X509.N32 range
                                            0 .. X509.N32 (C_Len) - 1
                                       loop
                                          HC.Peer_Ints (Idx).DER (I) :=
                                             X509.Byte
                                               (Cert_RFLX
                                                  (RBT.Index (N32 (I) + 1)));
                                       end loop;
                                       HC.Peer_Ints (Idx).DER_Len :=
                                         X509.N32 (C_Len);
                                       HC.Peer_Ints (Idx).Present := True;
                                       HC.Peer_Int_Count :=
                                         HC.Peer_Int_Count + 1;
                                    end if;
                                 end;
                              end if;
                              Cert_Idx := Cert_Idx + 1;
                           end if;
                        end;
                     end if;
                     C12_Entries.Update (Entries_Ctx, E_Ctx);
                  end;
               end loop;
               C12.Update_Certificate_List (Ctx, Entries_Ctx);
            end;
         end if;
      end;

      C12.Take_Buffer (Ctx, Buf);
      RFLX_Free_Local (Buf);
      OK := True;
   end Parse_Cert_Chain_12;

   --  RFC 5246 §7.4.2 leaf-cert validation (TLS 1.2): keyUsage,
   --  cipher-suite ↔ cert-algorithm match, hostname binding, chain
   --  validation. Each gate emits its own alert and returns; on full
   --  success Result is left untouched by the caller.
   procedure Validate_Server_Cert_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre  => Reasm_Coherent (HC)
                and then S.State not in Idle | Closing | Closed | Error_State
                and then (if HC.Peer_Cert_Valid then
                            HC.Peer_Cert_DER_Len in 1 .. Max_Cert_DER_Len
                            and then X509.Spans_Valid
                              (HC.Peer_Cert,
                               X509.N32 (HC.Peer_Cert_DER_Len) - 1)),
        Post => Reasm_Coherent (HC)
                and (if Result = OK then
                       S.State not in Idle | Closing | Closed | Error_State);

   procedure Validate_Server_Cert_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
   begin
      Result := OK;
      if not HC.Peer_Cert_Valid then
         Send_Alert_And_Error (S, Decode_Error, Result);
         return;
      end if;
      if X509.Has_Key_Usage (HC.Peer_Cert)
        and then not X509.KU_Digital_Signature (HC.Peer_Cert)
      then
         Send_Alert_And_Error (S, Bad_Certificate, Result);
         return;
      end if;
      declare
         PK : constant X509.Algorithm_ID := X509.PK_Algorithm (HC.Peer_Cert);
         Suite_Needs_ECDSA : constant Boolean :=
            S.Negotiated_Suite in Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                                | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                                | Suite_ECDHE_ECDSA_CHACHA20_SHA256;
         Suite_Needs_RSA   : constant Boolean :=
            S.Negotiated_Suite in Suite_ECDHE_RSA_AES128_GCM_SHA256
                                | Suite_ECDHE_RSA_AES256_GCM_SHA384
                                | Suite_ECDHE_RSA_CHACHA20_SHA256;
         Cert_Is_ECDSA : constant Boolean :=
            PK = X509.Algo_EC_P256 or PK = X509.Algo_EC_P384;
         Cert_Is_RSA     : constant Boolean := PK = X509.Algo_RSA;
         Cert_Is_Ed25519 : constant Boolean := PK = X509.Algo_EC_Ed25519;
      begin
         if Suite_Needs_ECDSA
           and then not (Cert_Is_ECDSA or Cert_Is_Ed25519)
         then
            Send_Alert_And_Error (S, Bad_Certificate, Result);
            return;
         end if;
         if Suite_Needs_RSA and then not Cert_Is_RSA then
            Send_Alert_And_Error (S, Bad_Certificate, Result);
            return;
         end if;
      end;

      if HC.Cfg.Server_Name.Len > 0
        and then not HC.Cfg.Skip_Hostname_Verify
        and then HC.Peer_Cert_Valid
      then
         declare
            PCDL : constant N32 := HC.Peer_Cert_DER_Len;
            Cert_X : X509.Byte_Seq
               (0 .. X509.N32 (PCDL) - 1) := (others => 0);
         begin
            for I in N32 range 0 .. PCDL - 1 loop
               Cert_X (X509.N32 (I)) := X509.Byte (HC.Peer_Cert_DER (I));
            end loop;
            if not X509.Matches_Hostname
                    (HC.Peer_Cert, Cert_X,
                     HC.Cfg.Server_Name.Data
                       (1 .. HC.Cfg.Server_Name.Len))
            then
               Send_Alert_And_Error (S, Bad_Certificate, Result);
               return;
            end if;
         end;
      end if;

      if not HC.Cfg.Skip_Verify
         and then HC.Cfg.Trust /= null
         and then HC.Cfg.Get_Time /= null
         and then HC.Peer_Cert_Valid
      then
         declare
            PCDL : constant N32 := HC.Peer_Cert_DER_Len;
            Cert_X : X509.Byte_Seq
               (0 .. X509.N32 (PCDL) - 1) := (others => 0);
            VR : Validation_Result;
         begin
            for I in N32 range 0 .. PCDL - 1 loop
               Cert_X (X509.N32 (I)) := X509.Byte (HC.Peer_Cert_DER (I));
            end loop;
            VR := Validate_Chain
              (Leaf_DER   => Cert_X,
               Leaf       => HC.Peer_Cert,
               Ints       => HC.Peer_Ints,
               Int_Count  => HC.Peer_Int_Count,
               Roots      => HC.Cfg.Trust.Roots,
               Root_Count => HC.Cfg.Trust.Root_Count,
               Now        => HC.Cfg.Get_Time.all,
               Hostname   =>
                  HC.Cfg.Server_Name.Data
                    (1 .. HC.Cfg.Server_Name.Len),
               Purpose    => HC.Cfg.Verify_Purpose,
               Mode       => HC.Cfg.Verify_Mode);
            if VR /= Valid then
               Free_Byte_Seq (HC.Reasm_Buf);
               HC.Reasm_Len := 0; HC.Reasm_Need := 0;
               Send_Alert_And_Error (S, Bad_Certificate, Result);
               return;
            end if;
         end;
      end if;
   end Validate_Server_Cert_12;

   --  RFC 5246 §7.4.4 CertificateRequest (HS type 0x0D). Parses the
   --  three length-prefixed lists (cert_types, sig_algs, ca_dns), picks
   --  a sig_algs entry compatible with our local identity if mTLS is
   --  configured, and falls back to a canonical default per algorithm
   --  when the server's offer is unusable.
   procedure Handle_CertReq_12
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Frag    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   with Pre  => Msg_Len >= 0
                and Msg_Len <= Max_HS_Msg - 4
                and Frag'First >= 0
                and Frag'Last < N32'Last - 4
                and Msg_Len <= N32 (Frag'Length) - 4
                and S.State not in Idle | Closing | Closed | Error_State
                and Reasm_Coherent (HC),
        Post => Reasm_Coherent (HC)
                and (if Result = OK then
                       S.State not in Idle | Closing | Closed | Error_State);

   procedure Handle_CertReq_12
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Frag    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   is
      Body_OK : Boolean := False;
      B       : constant N32 := Frag'First + 4;
   begin
      Result := OK;
      --  Body-length structural validation.
      if B + 1 <= Frag'Last then
         declare
            CT_Len_D : constant N32 := N32 (Frag (B));
            SA_Off_D : constant N32 := B + 1 + CT_Len_D;
         begin
            if SA_Off_D + 1 <= Frag'Last then
               declare
                  SA_Len_D : constant N32 :=
                     N32 (Frag (SA_Off_D)) * 256
                     + N32 (Frag (SA_Off_D + 1));
                  CA_Off_D : constant N32 :=
                     SA_Off_D + 2 + SA_Len_D;
               begin
                  if CA_Off_D + 1 <= Frag'Last then
                     declare
                        CA_Len_D : constant N32 :=
                           N32 (Frag (CA_Off_D)) * 256
                           + N32 (Frag (CA_Off_D + 1));
                        Expected : constant N32 :=
                           1 + CT_Len_D + 2 + SA_Len_D + 2 + CA_Len_D;
                     begin
                        Body_OK := Msg_Len = Expected;
                     end;
                  end if;
               end;
            end if;
         end;
      end if;
      if not Body_OK then
         Free_Byte_Seq (HC.Reasm_Buf);
         HC.Reasm_Len := 0; HC.Reasm_Need := 0;
         HC.Reasm_Hdr_Pending := False;
         Send_Alert_And_Error (S, Decode_Error, Result);
         return;
      end if;
      HC.Cert_Request_Received := True;

      --  Sig-algs selection. Empty sig_algs list is malformed per
      --  RFC 5246 §7.4.1.4.1.
      declare
         Picked   : Unsigned_16 := 0;
         SA_Empty : Boolean := True;
      begin
         if B + 1 <= Frag'Last then
            declare
               CT_Len : constant N32 := N32 (Frag (B));
               SA_Off : constant N32 := B + 1 + CT_Len;
            begin
               if SA_Off + 1 <= Frag'Last then
                  declare
                     SA_Len : constant N32 :=
                        N32 (Frag (SA_Off)) * 256
                        + N32 (Frag (SA_Off + 1));
                  begin
                     if SA_Len >= 2
                       and SA_Off + 1 + SA_Len <= Frag'Last
                     then
                        SA_Empty := False;
                        if HC.Cfg.Local /= null then
                           declare
                              SA_Slice : constant Byte_Seq
                                 (0 .. SA_Len - 1) :=
                                 Frag (SA_Off + 2 ..
                                       SA_Off + 1 + SA_Len);
                           begin
                              Picked := Handshake.Pick_Sig_Algo
                                (SA_Slice,
                                 HC.Cfg.Local.Sign_Algo,
                                 Allow_PKCS1_v1_5 => True);
                           end;
                        end if;
                     end if;
                  end;
               end if;
            end;
         end if;
         if SA_Empty then
            Free_Byte_Seq (HC.Reasm_Buf);
            HC.Reasm_Len := 0; HC.Reasm_Need := 0;
            Send_Alert_And_Error (S, Decode_Error, Result);
            return;
         end if;
         if HC.Cfg.Local /= null then
            if Picked /= 0 then
               HC.Negotiated_Sig_Algo := Picked;
            else
               case HC.Cfg.Local.Sign_Algo is
                  when Sign_RSA_PSS =>
                     HC.Negotiated_Sig_Algo := 16#0804#;
                  when Sign_ECDSA_P256 =>
                     HC.Negotiated_Sig_Algo := 16#0403#;
                  when Sign_ECDSA_P384 =>
                     HC.Negotiated_Sig_Algo := 16#0503#;
                  when Sign_Ed25519 =>
                     HC.Negotiated_Sig_Algo := 16#0807#;
                  when Sign_None =>
                     null;
               end case;
            end if;
         end if;
      end;
      Append_Transcript (HC, Frag);
   end Handle_CertReq_12;

   --  RFC 5246 §7.4.3 ServerKeyExchange (HS type 0x0C). Length-validates
   --  the body shape first (curve_type/curve/pt_len/pt + sig_hash/alg/
   --  len/sig must sum to Msg_Len), then dispatches to
   --  Parse_Server_Key_Exchange which extracts ECDHE params + verifies
   --  the signature.
   procedure Handle_SKE_12
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Frag    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   with Pre  => Msg_Len >= 0
                and Msg_Len <= Max_HS_Msg - 4
                and Frag'First >= 0
                and Frag'Last < N32'Last - 4
                and Msg_Len <= N32 (Frag'Length) - 4
                and S.State not in Idle | Closing | Closed | Error_State
                and Reasm_Coherent (HC),
        Post => Reasm_Coherent (HC)
                and (if Result = OK then
                       S.State not in Idle | Closing | Closed | Error_State);

   procedure Handle_SKE_12
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Frag    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   is
      Body_Start : constant N32 := Frag'First + 4;
   begin
      Result := OK;
      if Msg_Len = 0 then
         Free_Byte_Seq (HC.Reasm_Buf);
         HC.Reasm_Len := 0; HC.Reasm_Need := 0;
         Send_Alert_And_Error (S, Decode_Error, Result);
         return;
      end if;

      declare
         Length_OK  : Boolean := False;
      begin
         if Msg_Len >= 8 then
            declare
               Pt_Len  : constant N32 := N32 (Frag (Body_Start + 3));
               Sig_Pos : constant N32 := Body_Start + 4 + Pt_Len + 2;
            begin
               if Sig_Pos + 1 < Frag'First + 4 + Msg_Len then
                  declare
                     Sig_Len : constant N32 :=
                        N32 (Frag (Sig_Pos)) * 256
                        + N32 (Frag (Sig_Pos + 1));
                  begin
                     Length_OK := Msg_Len = 8 + Pt_Len + Sig_Len;
                  end;
               end if;
            end;
         end if;
         if not Length_OK then
            Free_Byte_Seq (HC.Reasm_Buf);
            HC.Reasm_Len := 0; HC.Reasm_Need := 0;
            HC.Reasm_Hdr_Pending := False;
            Send_Alert_And_Error (S, Decode_Error, Result);
            return;
         end if;
      end;

      declare
         Body_Data : Byte_Seq (0 .. Msg_Len - 1);
         SKE_OK    : Boolean;
      begin
         Body_Data := Frag (Body_Start .. Body_Start + Msg_Len - 1);
         Parse_Server_Key_Exchange (HC, Body_Data, SKE_OK);
         if not SKE_OK then
            Free_Byte_Seq (HC.Reasm_Buf);
            HC.Reasm_Len := 0; HC.Reasm_Need := 0;
            Send_Alert_And_Error (S, Handshake_Failure, Result);
            return;
         end if;
      end;
      Append_Transcript (HC, Frag);
   end Handle_SKE_12;

   --  RFC 5246 §7.4.5 ServerHelloDone (HS type 0x0E). End of the
   --  server's pre-CCS flight. Computes the ECDHE shared secret,
   --  derives the AEAD keys, then builds and commits the entire
   --  client flight atomically: (optional Certificate + CKE +
   --  optional CertificateVerify + CCS + encrypted Finished) into a
   --  stack-scratch IO_Buffer, with HC.Client_Seq_12 rolled back on
   --  commit failure to keep AEAD nonces in sync with the peer.
   procedure Handle_SHD_12
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Frag    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   with Pre  => Msg_Len >= 0
                and then Msg_Len <= Max_HS_Msg - 4
                and then Frag'First >= 0
                and then Frag'Last < N32'Last - 4
                and then Frag'First <= N32'Last - 4
                and then Msg_Len <= N32'Last - Frag'First - 4
                and then Frag'First + 3 + Msg_Len <= Frag'Last
                and then Frag'First <= Frag'Last
                and then Frag'Last - Frag'First < Transcript_Capacity
                and then S.State not in Idle | Closing | Closed | Error_State
                and then Reasm_Coherent (HC)
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => Reasm_Coherent (HC)
                and (if Result = OK then
                       S.State not in Idle | Closing | Closed | Error_State);

   procedure Handle_SHD_12
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Frag    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   is
   begin
      Result := OK;
      if Msg_Len /= 0 then
         Free_Byte_Seq (HC.Reasm_Buf);
         HC.Reasm_Len := 0; HC.Reasm_Need := 0;
         HC.Reasm_Hdr_Pending := False;
         Send_Alert_And_Error (S, Decode_Error, Result);
         return;
      end if;
      if HC.Reasm_Len > HC.Reasm_Need then
         Free_Byte_Seq (HC.Reasm_Buf);
         HC.Reasm_Len := 0; HC.Reasm_Need := 0;
         HC.Reasm_Hdr_Pending := False;
         Send_Alert_And_Error (S, Unexpected_Message, Result);
         return;
      end if;
      Append_Transcript (HC, Frag);

      --  Compute ECDHE shared secret per Selected_Group.
      declare
         Gen : constant Random_Bytes_Fn := HC.Cfg.Random;
         SS_OK  : Boolean    := False;
         SS_Err : Error_Code := Handshake_Failure;
         begin
            pragma Assert (Gen /= null);
            case HC.Selected_Group is
            when Group_X25519 =>
               Gen (Byte_Seq (HC.Local_SK));
               HC.Shared_Secret (0 .. 31) :=
                  SPARKNaCl.Scalar.Mult (HC.Local_SK, HC.Peer_PK);
               SS_OK := Shared_Secret_Is_Acceptable_X25519
                          (HC.Shared_Secret (0 .. 31));
               if not SS_OK then SS_Err := Illegal_Parameter; end if;
            when Group_Secp256r1 =>
               Gen (Byte_Seq (HC.P256_Local_SK));
               declare
                  use SPARKTLSCrypto.P256.Point;
                  Pt : P256_Jacobian; V : SPARKNaCl.U32;
               begin
                  P256_Decode (Pt, HC.P256_Peer_PK, V);
                  if V /= 0 then
                     P256_Mul (Pt, HC.P256_Local_SK, 32);
                     P256_To_Affine (Pt);
                     declare E : Byte_Seq (0 .. 64);
                     begin
                        P256_Encode (E, Pt);
                        HC.Shared_Secret := (others => 0);
                        HC.Shared_Secret (0 .. 31) := E (1 .. 32);
                     end;
                     SS_OK := True;
                  else
                     SS_Err := Illegal_Parameter;
                  end if;
               end;
            when Group_Secp384r1 =>
               Gen (Byte_Seq (HC.P384_Local_SK));
               declare SS : Bytes_48; OK384 : Boolean;
               begin
                  SPARKTLSCrypto.P384.Point.P384_ECDHE
                    (SS, OK384, HC.P384_Local_SK, HC.P384_Peer_PK);
                  if OK384 then
                     HC.Shared_Secret := SS; SS_OK := True;
                  else
                     SS_Err := Illegal_Parameter;
                  end if;
               end;
            when others => null;
         end case;

         if not SS_OK then
            Free_Byte_Seq (HC.Reasm_Buf);
            HC.Reasm_Len := 0; HC.Reasm_Need := 0;
            Send_Alert_And_Error (S, SS_Err, Result);
            return;
         end if;
      end;

      --  Build + atomically commit the client flight.
      declare
         use Key_Schedule_12;
         use Records.TLS12;
         Scratch : IO_Buffer;
         CKE : Byte_Seq (0 .. Max_Client_Key_Exchange - 1);
         CKE_Len : N32;
         Rec_Out : N32;
         CCS_Out : N32;
         FB : Byte_Seq (0 .. Finished_12_Total_Len - 1);
         FL : N32; EO : N32;
         TH : Digest;
         TH4 : SPARKNaCl.Hashing.SHA384.Digest;
         Use_384 : constant Boolean :=
            S.Negotiated_Suite in Suite_ECDHE_RSA_AES256_GCM_SHA384
                               | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
         Saved_Seq : Unsigned_64;
      begin
         if HC.Cert_Request_Received then
            declare
               Cert_Buf : Byte_Seq (0 .. 4 + 3 + Max_Cert_DER - 1);
               Cert_Len : N32;
            begin
               if HC.Cfg.Local /= null
                 and then HC.Cfg.Local.Has_Identity
               then
                  Build_Certificate_Chain_12
                    (HC.Cfg.Local.all, Cert_Buf, Cert_Len);
               else
                  Cert_Buf := (others => 0);
                  Cert_Buf (0) := 16#0B#;
                  Cert_Buf (3) := 3;
                  Cert_Len := 7;
               end if;
               if Cert_Len > 0 then
                  Append_Transcript (HC, Cert_Buf (0 .. Cert_Len - 1));
                  Records.Build_Handshake_Record
                    (Cert_Buf (0 .. Cert_Len - 1), Scratch, Rec_Out);
                  if Rec_Out = 0 then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     Send_Alert_And_Error
                       (S, Insufficient_Buffer, Result);
                     return;
                  end if;
               end if;
            end;
         end if;

         Build_Client_Key_Exchange (HC, CKE, CKE_Len);
         if CKE_Len > 0 then
            Append_Transcript (HC, CKE (0 .. CKE_Len - 1));
            Records.Build_Handshake_Record
              (CKE (0 .. CKE_Len - 1), Scratch, Rec_Out);
            if Rec_Out = 0 then
               Free_Byte_Seq (HC.Reasm_Buf);
               HC.Reasm_Len := 0; HC.Reasm_Need := 0;
               Send_Alert_And_Error (S, Insufficient_Buffer, Result);
               return;
            end if;
         end if;

         if HC.Cert_Request_Received
           and then HC.Cfg.Local /= null
           and then HC.Cfg.Local.Has_Identity
         then
            declare
               CV_Buf : Byte_Seq (0 .. 523);
               CV_Len : N32;
               TH_CV  : Digest;
               TH4_CV : SPARKNaCl.Hashing.SHA384.Digest;
               TH5_CV : SPARKNaCl.Hashing.SHA512.Digest;
               Use_384_For_CV : constant Boolean :=
                  HC.Negotiated_Sig_Algo in 16#0503# | 16#0805# | 16#0501#;
               Use_512_For_CV : constant Boolean :=
                  HC.Negotiated_Sig_Algo in 16#0806# | 16#0601#;
               Use_Raw_For_CV : constant Boolean :=
                  HC.Negotiated_Sig_Algo = 16#0807#;
            begin
               if Use_Raw_For_CV then
                  Build_Certificate_Verify_12
                    (Transcript_Hash =>
                       HC.Transcript (0 .. HC.Transcript_Len - 1),
                     Id              => HC.Cfg.Local.all,
                     Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
                     Random          => HC.Cfg.Random,
                     Result          => CV_Buf,
                     Len             => CV_Len);
               elsif Use_512_For_CV then
                  SPARKNaCl.Hashing.SHA512.Hash
                    (TH5_CV,
                     HC.Transcript (0 .. HC.Transcript_Len - 1));
                  Build_Certificate_Verify_12
                    (Transcript_Hash => Byte_Seq (TH5_CV),
                     Id              => HC.Cfg.Local.all,
                     Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
                     Random          => HC.Cfg.Random,
                     Result          => CV_Buf,
                     Len             => CV_Len);
               elsif Use_384_For_CV then
                  SPARKNaCl.Hashing.SHA384.Hash
                    (TH4_CV,
                     HC.Transcript (0 .. HC.Transcript_Len - 1));
                  Build_Certificate_Verify_12
                    (Transcript_Hash => Byte_Seq (TH4_CV),
                     Id              => HC.Cfg.Local.all,
                     Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
                     Random          => HC.Cfg.Random,
                     Result          => CV_Buf,
                     Len             => CV_Len);
               else
                  Hash (TH_CV,
                        HC.Transcript (0 .. HC.Transcript_Len - 1));
                  Build_Certificate_Verify_12
                    (Transcript_Hash => Byte_Seq (TH_CV),
                     Id              => HC.Cfg.Local.all,
                     Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
                     Random          => HC.Cfg.Random,
                     Result          => CV_Buf,
                     Len             => CV_Len);
               end if;
               if CV_Len = 0 then
                  Free_Byte_Seq (HC.Reasm_Buf);
                  HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                  Send_Alert_And_Error (S, Internal_Error, Result);
                  return;
               end if;
               Append_Transcript (HC, CV_Buf (0 .. CV_Len - 1));
               Records.Build_Handshake_Record
                 (CV_Buf (0 .. CV_Len - 1), Scratch, Rec_Out);
               if Rec_Out = 0 then
                  Free_Byte_Seq (HC.Reasm_Buf);
                  HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                  Send_Alert_And_Error
                    (S, Insufficient_Buffer, Result);
                  return;
               end if;
            end;
         end if;

         Derive_Keys_12 (S, HC);

         Records.Build_CCS_Record (Scratch, CCS_Out);
         if CCS_Out = 0 then
            Free_Byte_Seq (HC.Reasm_Buf);
            HC.Reasm_Len := 0; HC.Reasm_Need := 0;
            Send_Alert_And_Error (S, Insufficient_Buffer, Result);
            return;
         end if;

         if Use_384 then
            SPARKNaCl.Hashing.SHA384.Hash
              (TH4, HC.Transcript (0 .. HC.Transcript_Len - 1));
            Build_Finished_12 (HC.Master_Secret_12,
                               Label_Client_Finished,
                               Byte_Seq (TH4), True, FB, FL);
         else
            Hash (TH, HC.Transcript (0 .. HC.Transcript_Len - 1));
            Build_Finished_12 (HC.Master_Secret_12,
                               Label_Client_Finished,
                               Byte_Seq (TH), False, FB, FL);
         end if;

         Append_Transcript (HC, FB (0 .. FL - 1));

         Saved_Seq := HC.Client_Seq_12;
         Build_Encrypted_Record_12
           (FB (0 .. FL - 1), 16#16#, S.Client_App,
            HC.Client_Write_IV_12, HC.Client_Seq_12,
            Scratch, EO);
         if EO = 0 then
            HC.Client_Seq_12 := Saved_Seq;
            Free_Byte_Seq (HC.Reasm_Buf);
            HC.Reasm_Len := 0; HC.Reasm_Need := 0;
            Send_Alert_And_Error (S, Insufficient_Buffer, Result);
            return;
         end if;

         if Free_Space (S.Output) < Scratch.Write_Pos then
            HC.Client_Seq_12 := Saved_Seq;
            Free_Byte_Seq (HC.Reasm_Buf);
            HC.Reasm_Len := 0; HC.Reasm_Need := 0;
            Send_Alert_And_Error (S, Insufficient_Buffer, Result);
            return;
         end if;
         S.Output.Data
           (S.Output.Write_Pos ..
            S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
            Scratch.Data (0 .. Scratch.Write_Pos - 1);
         S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;
      end;

      HC.CKE_Received_12 := True;
      Result := (if Output_Pending (S) > 0
                 then Has_Output else Need_Input);
   end Handle_SHD_12;

   --  RFC 5077 §3.3 NewSessionTicket (HS type 0x04). Two arrival times:
   --    * Abbreviated handshake (HC.TLS12_Resuming): right after SH,
   --      before server CCS+Finished. Cache, append transcript, derive
   --      AEAD keys from cached master_secret + this connection's
   --      randoms, flip CKE_Received_12 so the dispatcher advances.
   --    * Full handshake: after client CKE+CCS+Finished, before
   --      server CCS+Finished. The dispatcher routes to
   --      Process_Server_CCS at that point — handled there.
   --
   --  Frag is the reassembled HS message bytes (header + body), Msg_Len
   --  the declared body length from the HS header.
   procedure Handle_NST_12
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Frag    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   with Pre  => Msg_Len in 6 .. Max_HS_Msg - 4
                and Frag'First >= 0
                and Frag'Last < N32'Last - 4
                and Msg_Len <= N32 (Frag'Length) - 4
                and S.State not in Idle | Closing | Closed | Error_State
                and Reasm_Coherent (HC),
        Post => Reasm_Coherent (HC)
                and (if Result = OK then
                       S.State not in Idle | Closing | Closed | Error_State);

   procedure Handle_NST_12
     (S       : in out Session;
      HC      : in out Handshake_Context;
      Frag    : in     Byte_Seq;
      Msg_Len : in     N32;
      Result  :    out Action)
   is
      B          : constant N32 := Frag'First + 4;
      NST_Body   : constant Byte_Seq (0 .. Msg_Len - 1) :=
                     Frag (B .. B + Msg_Len - 1);
      Lifetime   : Unsigned_32;
      Ticket_Len : N32;
      Parse_OK   : Boolean;
   begin
      SPARKTLS.Handshake.TLS12.Parse_New_Session_Ticket_12
        (NST_Body      => NST_Body,
         Lifetime_Hint => Lifetime,
         Ticket_Len    => Ticket_Len,
         OK            => Parse_OK);
      if not Parse_OK or Ticket_Len > Max_TLS12_Ticket_Len then
         Free_Byte_Seq (HC.Reasm_Buf);
         HC.Reasm_Len := 0; HC.Reasm_Need := 0;
         Send_Alert_And_Error (S, Decode_Error, Result);
         return;
      end if;
      if Ticket_Len > 0 then
         S.TLS12_New_Ticket.Ticket (0 .. Ticket_Len - 1) :=
            NST_Body (6 .. 6 + Ticket_Len - 1);
      end if;
      S.TLS12_New_Ticket.Ticket_Len := Ticket_Len;
      S.TLS12_New_Ticket.Suite := S.Negotiated_Suite_12;
      S.TLS12_New_Ticket.Master_Secret := HC.Master_Secret_12;
      S.TLS12_New_Ticket.Lifetime_Hint := Lifetime;
      S.TLS12_New_Ticket.Server_Name := HC.Cfg.Server_Name;
      S.TLS12_New_Ticket.Valid := True;

      Append_Transcript (HC, Frag);

      if HC.TLS12_Resuming then
         Derive_Keys_Resumed_12 (S, HC);
         HC.CKE_Received_12 := True;
      end if;
      Result := OK;
   end Handle_NST_12;

   procedure Dispatch_Server_Flight_Message
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Msg_Type : in     Byte;
      Frag     : in     Byte_Seq;
      Msg_Len  : in     N32;
      Result   :    out Action)
   with Pre  => Msg_Len <= Max_HS_Msg - 4
                and then Frag'First >= 0
                and then Frag'Last < N32'Last - 4
                and then Msg_Len <= N32 (Frag'Length) - 4
                and then Frag'First + 3 + Msg_Len <= Frag'Last
                and then S.State not in Idle | Closing | Closed | Error_State
                and then Reasm_Coherent (HC)
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => Reasm_Coherent (HC)
                and then
                     (if Result = OK then
                        S.State not in Idle | Closing | Closed | Error_State
                        and then HC.Reasm_Buf /= null
                        and then HC.Reasm_Buf'First = 0
                        and then HC.Reasm_Buf'Length <= Max_HS_Msg
                        and then HC.Reasm_Need = HC.Reasm_Need'Old
                        and then HC.Reasm_Len = HC.Reasm_Len'Old
                        and then
                          HC.Reasm_Hdr_Pending = HC.Reasm_Hdr_Pending'Old
                        and then HC.Cfg.Random /= null
                        and then HC.Selected_Group in
                          Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                        and then Valid_ECDHE_Group (HC.Selected_Group)
                        and then HC.Transcript_Len > 0
                        and then HC.Transcript_Len <= Transcript_Capacity
                        and then SPARKTLSCrypto.P384.Field.Initialized
                        and then SPARKTLSCrypto.P384.ECDSA.Initialized);

   procedure Dispatch_Server_Flight_Message
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Msg_Type : in     Byte;
      Frag     : in     Byte_Seq;
      Msg_Len  : in     N32;
      Result   :    out Action)
   is
   begin
      case Msg_Type is
         when 16#0B# =>
            --  Certificate (RFC 5246 §7.4.2). Parsing happens in
            --  Parse_Cert_Chain_12; subsequent validation gates
            --  (keyUsage, suite<->cert algorithm match, hostname,
            --  chain) live in Validate_Server_Cert_12.
            if Msg_Len < 3 then
               Free_Byte_Seq (HC.Reasm_Buf);
               HC.Reasm_Len := 0; HC.Reasm_Need := 0;
               HC.Reasm_Hdr_Pending := False;
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;
            declare
               Parse_OK : Boolean;
            begin
               Parse_Cert_Chain_12 (HC, Frag, Msg_Len, Parse_OK);
               if not Parse_OK then
                  Free_Byte_Seq (HC.Reasm_Buf);
                  HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                  HC.Reasm_Hdr_Pending := False;
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;
            end;

            Validate_Server_Cert_12 (S, HC, Result);
            if Result /= OK then
               return;
            end if;

            Append_Transcript (HC, Frag);
            Result := OK;

         when 16#0D# =>
            Handle_CertReq_12 (S, HC, Frag, Msg_Len, Result);

         when HT_Server_Key_Exchange =>
            Handle_SKE_12 (S, HC, Frag, Msg_Len, Result);

         when HT_Server_Hello_Done =>
            Handle_SHD_12 (S, HC, Frag, Msg_Len, Result);

         when 16#04# =>
            Handle_NST_12 (S, HC, Frag, Msg_Len, Result);

         when others =>
            --  RFC 5246 §7.4: unknown handshake type during the
            --  flight is unexpected_message (BoGo WrongMessageType-*
            --  injects type+42). Pre-CCS so the alert is plaintext.
            Free_Byte_Seq (HC.Reasm_Buf);
            HC.Reasm_Len := 0; HC.Reasm_Need := 0;
            HC.Reasm_Hdr_Pending := False;
            Send_Alert_And_Error (S, Unexpected_Message, Result);
      end case;
   end Dispatch_Server_Flight_Message;

   procedure Drain_Packed_Server_Flight
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Msg_Type : in out Byte;
      Msg_Len  : in out N32;
      Result   :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Reasm_Coherent (HC)
                and then HC.Reasm_Buf /= null
                and then HC.Reasm_Buf'First = 0
                and then HC.Reasm_Buf'Length <= Max_HS_Msg
                and then not HC.Reasm_Hdr_Pending
                and then HC.Reasm_Need >= 4
                and then HC.Reasm_Need <= HC.Reasm_Len
                and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
                and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
                and then Msg_Len <= HC.Reasm_Need - 4
                and then Msg_Len <= Max_HS_Msg - 4
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => Reasm_Coherent (HC);

   procedure Drain_Packed_Server_Flight
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Msg_Type : in out Byte;
      Msg_Len  : in out N32;
      Result   :    out Action)
   is
      More_Packed : Boolean := True;
   begin
      Result := OK;
      while More_Packed loop
         pragma Loop_Variant
           (Decreases => HC.Reasm_Len);
         pragma Loop_Invariant
           (if More_Packed then Result = OK);
         pragma Loop_Invariant
           (Reasm_Coherent (HC));
         pragma Loop_Invariant
           (if More_Packed then
              HC.Reasm_Buf /= null
              and then HC.Reasm_Buf'First = 0
              and then HC.Reasm_Buf'Length <= Max_HS_Msg
              and then not HC.Reasm_Hdr_Pending
              and then HC.Reasm_Need >= 4
              and then HC.Reasm_Need <= HC.Reasm_Len
              and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
              and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
              and then Reasm_Coherent (HC)
              and then S.State not in Idle | Closing | Closed | Error_State
              and then Msg_Len <= HC.Reasm_Need - 4
              and then Msg_Len <= Max_HS_Msg - 4
              and then HC.Cfg.Random /= null
              and then HC.Selected_Group in
                Group_X25519 | Group_Secp256r1 | Group_Secp384r1
              and then Valid_ECDHE_Group (HC.Selected_Group)
              and then HC.Transcript_Len > 0
              and then HC.Transcript_Len <= Transcript_Capacity
              and then SPARKTLSCrypto.P384.Field.Initialized
              and then SPARKTLSCrypto.P384.ECDSA.Initialized);
         More_Packed := False;
         pragma Assert (Result = OK);
         declare
            RN : constant N32 := HC.Reasm_Need;
         begin
            pragma Assert (RN >= 4);
            pragma Assert (RN <= HC.Reasm_Len);
            pragma Assert (RN <= N32 (HC.Reasm_Buf'Length));
            pragma Assert (HC.Reasm_Buf'Last >= RN - 1);
            declare
               Frag : constant Byte_Seq :=
                  HC.Reasm_Buf (0 .. RN - 1);
            begin
               pragma Assert (Msg_Len <= Max_HS_Msg - 4);
               pragma Assert (Msg_Len <= RN - 4);
               pragma Assert (Frag'First = 0);
               pragma Assert (Frag'Last = RN - 1);
               pragma Assert (Frag'Last < N32'Last - 4);
               pragma Assert (Frag'First + 3 + Msg_Len <= Frag'Last);

               Dispatch_Server_Flight_Message
                 (S        => S,
                  HC       => HC,
                  Msg_Type => Msg_Type,
                  Frag     => Frag,
                  Msg_Len  => Msg_Len,
                  Result   => Result);
               if Result /= OK
                 and then Msg_Type /= HT_Server_Hello_Done
               then
                  pragma Assert (Reasm_Coherent (HC));
                  return;
               end if;
            end;
         end;

         --  PackHandshake (BoGo PackHandshakeFlight): one record may
         --  contain multiple back-to-back HS messages. After dispatching
         --  the first, shift trailing bytes to the front of Reasm_Buf,
         --  decode the next message header, and loop. Stop on error, on
         --  Has_Output (handler queued our flight), or when no more
         --  complete message remains.
         if Result = OK
           and HC.Reasm_Len > HC.Reasm_Need
           and HC.Reasm_Buf /= null
         then
            declare
               Bad_Next : Boolean;
            begin
               Packed.Shift_To_Next_Packed_Message
                 (Reasm_Buf         => HC.Reasm_Buf,
                  Reasm_Len         => HC.Reasm_Len,
                  Reasm_Need        => HC.Reasm_Need,
                  Reasm_Hdr_Pending => HC.Reasm_Hdr_Pending,
                  Msg_Type          => Msg_Type,
                  Msg_Len           => Msg_Len,
                  More_Packed       => More_Packed,
                  Bad_Next          => Bad_Next);
               if Bad_Next then
                  Send_Alert_And_Error
                    (S, Decode_Error, Result);
                  pragma Assert (Reasm_Coherent (HC));
                  return;
               end if;
               pragma Assert (Reasm_Coherent (HC));
            end;
         else
            pragma Assert (Reasm_Coherent (HC));
         end if;
         pragma Assert (Reasm_Coherent (HC));
      end loop;
      pragma Assert (Reasm_Coherent (HC));

      --  Free the reassembly buffer unless PackHandshake leftover bytes
      --  still need draining on the next call. Leftover exists when we
      --  successfully shifted bytes (Reasm_Len > 0) AND we still have a
      --  current-message size to fill (Reasm_Len < Reasm_Need or
      --  Hdr_Pending awaiting more bytes).
      if HC.Reasm_Buf /= null
        and (HC.Reasm_Len = 0
             or (HC.Reasm_Len >= HC.Reasm_Need
                 and not HC.Reasm_Hdr_Pending))
      then
         Free_Byte_Seq (HC.Reasm_Buf);
         HC.Reasm_Len := 0;
         HC.Reasm_Need := 0;
         HC.Reasm_Hdr_Pending := False;
         pragma Assert (Reasm_Coherent (HC));
      end if;
      pragma Assert (Reasm_Coherent (HC));
   end Drain_Packed_Server_Flight;

   procedure Read_Server_Flight_Record
     (S           : in out Session;
      HC          : in out Handshake_Context;
      Rec         :    out Records.Parse_Result;
      Have_Record :    out Boolean;
      Result      :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Reasm_Coherent (HC)
                and then Warning_Alerts_Bounded_RFC_8446_6_1 (S)
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => Reasm_Coherent (HC)
                and then HC.Reasm_Len = HC.Reasm_Len'Old
                and then HC.Reasm_Need = HC.Reasm_Need'Old
                and then HC.Reasm_Hdr_Pending =
                  HC.Reasm_Hdr_Pending'Old
                and then
                  (if Have_Record then
                     Result = OK
                     and then Rec.OK
                     and then Rec.Content = Records.Content_Handshake
                     and then Rec.Fragment_Pos <=
                       N32'Last - Rec.Fragment_Len
                     and then Rec.Record_Len =
                       Rec.Fragment_Pos + Rec.Fragment_Len
                     and then Rec.Record_Len <=
                       S.Input.Write_Pos - S.Input.Read_Pos
                     and then S.Input.Read_Pos <=
                       N32'Last - Rec.Record_Len
                     and then S.State not in Idle | Closing | Closed | Error_State
                     and then HC.Cfg.Random /= null
                     and then HC.Selected_Group in
                       Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                     and then Valid_ECDHE_Group (HC.Selected_Group)
                     and then HC.Transcript_Len > 0
                     and then HC.Transcript_Len <= Transcript_Capacity
                     and then SPARKTLSCrypto.P384.Field.Initialized
                     and then SPARKTLSCrypto.P384.ECDSA.Initialized);

   procedure Read_Server_Flight_Record
     (S           : in out Session;
      HC          : in out Handshake_Context;
      Rec         :    out Records.Parse_Result;
      Have_Record :    out Boolean;
      Result      :    out Action)
   is
   begin
      Rec :=
        (OK           => False,
         Overflow     => False,
         Bad_Version  => False,
         Content      => Records.Content_Unknown,
         Fragment_Pos => 0,
         Fragment_Len => 0,
         Record_Len   => 0);
      Have_Record := False;
      Result := OK;

      if Input_Available (S) = 0 then
         Result := Need_Input;
         pragma Assert (Reasm_Coherent (HC));
         return;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Available (S.Input), Rec);

      if Rec.Bad_Version then
         S.Last_Error := Protocol_Version;
         Set_State (S, Error_State);
         Result := Error_Alert;
         pragma Assert (Reasm_Coherent (HC));
         return;
      end if;
      if not Rec.OK then
         Result := Need_Input;
         pragma Assert (Reasm_Coherent (HC));
         return;
      end if;

      if Rec.Content = Records.Content_Alert then
         declare
            AS  : constant N32 :=
               S.Input.Read_Pos + Rec.Fragment_Pos;
            ALen : constant N32 := Rec.Fragment_Len;
            Lvl : constant Byte :=
               (if ALen >= 1 then S.Input.Data (AS) else 0);
            Dsc : constant Byte :=
               (if ALen >= 2 then S.Input.Data (AS + 1) else 0);
         begin
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if Lvl = 1 and Dsc /= 0 then
               S.Warning_Alerts_Recvd := S.Warning_Alerts_Recvd + 1;
               if S.Warning_Alerts_Recvd >= 5 then
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  pragma Assert (Reasm_Coherent (HC));
                  return;
               end if;
               Result := OK;
               pragma Assert (Reasm_Coherent (HC));
               return;
            elsif Lvl = 2 then
               S.Last_Error := Unexpected_Message;
               Set_State (S, Error_State);
               Result := Error_Alert;
               pragma Assert (Reasm_Coherent (HC));
               return;
            else
               Result := OK;
               pragma Assert (Reasm_Coherent (HC));
               return;
            end if;
         end;
      end if;

      if Rec.Content = Records.Content_Change_Cipher_Spec
        and then not HC.TLS12_Resuming
        and then HC.TLS12_Sent_Ticket_Ext
        and then HC.Cfg.TLS12_Resume_Ticket.Valid
        and then HC.Cfg.TLS12_Resume_Ticket.Suite = S.Negotiated_Suite_12
      then
         declare
            CCS_Pos     : constant N32 :=
               S.Input.Read_Pos + Rec.Fragment_Pos;
            CCS_Byte_OK : constant Boolean :=
               Rec.Fragment_Len = 1
               and then S.Input.Data (CCS_Pos) = 16#01#;
         begin
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if not CCS_Byte_OK then
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               pragma Assert (Reasm_Coherent (HC));
               return;
            end if;
         end;
         HC.TLS12_Resuming := True;
         HC.Master_Secret_12 :=
            HC.Cfg.TLS12_Resume_Ticket.Master_Secret;
         Derive_Keys_Resumed_12 (S, HC);
         HC.CKE_Received_12 := True;
         HC.CCS_Received    := True;
         Result := OK;
         pragma Assert (Reasm_Coherent (HC));
         return;
      end if;

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK;
         pragma Assert (Reasm_Coherent (HC));
         return;
      end if;

      Have_Record := True;
      Result := OK;
      pragma Assert (Reasm_Coherent (HC));
   end Read_Server_Flight_Record;

   procedure Copy_To_Reassembly_Buffer
     (Reasm_Buf : in out Byte_Seq_Access;
      Old_Len   : in     N32;
      Source    : in     Byte_Seq;
      Copy_Len  : in     N32;
      Required_Len : in N32;
      Was_Max   : in     Boolean)
   with Pre  => Reasm_Buf /= null
                and then Reasm_Buf'First = 0
                and then Reasm_Buf'Length <= Max_HS_Msg
                and then Was_Max = (Reasm_Buf'Length = Max_HS_Msg)
                and then Copy_Len > 0
                and then Source'Last < N32'Last
                and then Source'Length <= Max_HS_Msg
                and then Source'Length = Copy_Len
                and then Required_Len <= N32 (Reasm_Buf'Length)
                and then Old_Len <= N32'Last - Copy_Len
                and then Old_Len + Copy_Len <= N32 (Reasm_Buf'Length),
        Post => Reasm_Buf /= null
                and then Reasm_Buf'First = 0
                and then Reasm_Buf'Length <= Max_HS_Msg
                and then Required_Len <= N32 (Reasm_Buf'Length)
                and then (if Was_Max then Reasm_Buf'Length = Max_HS_Msg);

   procedure Copy_To_Reassembly_Buffer
     (Reasm_Buf : in out Byte_Seq_Access;
      Old_Len   : in     N32;
      Source    : in     Byte_Seq;
      Copy_Len  : in     N32;
      Required_Len : in N32;
      Was_Max   : in     Boolean)
   is
   begin
      for I in N32 range 0 .. Copy_Len - 1 loop
         pragma Loop_Invariant (I <= Copy_Len - 1);
         pragma Loop_Invariant (Reasm_Buf /= null);
         pragma Loop_Invariant (Reasm_Buf'First = 0);
         pragma Loop_Invariant (Reasm_Buf'Length <= Max_HS_Msg);
         pragma Loop_Invariant
           (Old_Len + Copy_Len <= N32 (Reasm_Buf'Length));
         pragma Loop_Invariant (Required_Len <= N32 (Reasm_Buf'Length));
         pragma Loop_Invariant (Source'Length = Copy_Len);
         Reasm_Buf (Old_Len + I) :=
            Source (Source'First + I);
      end loop;
   end Copy_To_Reassembly_Buffer;

   procedure Prepare_Leftover_Server_Flight_Message
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Msg_Type :    out Byte;
      Msg_Len  :    out N32;
      Ready    :    out Boolean;
      Result   :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Reasm_Coherent (HC)
                and then HC.Reasm_Buf /= null
                and then HC.Reasm_Buf'First = 0
                and then HC.Reasm_Buf'Length <= Max_HS_Msg
                and then HC.Reasm_Need > 0
                and then not HC.Reasm_Hdr_Pending
                and then HC.Reasm_Need <= HC.Reasm_Len
                and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
                and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => Reasm_Coherent (HC)
                and then
                  (if Ready then
                     Result = OK
                and then S.State not in Idle | Closing | Closed | Error_State
                and then HC.Reasm_Buf /= null
                and then HC.Reasm_Buf'First = 0
                and then HC.Reasm_Buf'Length = Max_HS_Msg
                     and then not HC.Reasm_Hdr_Pending
                     and then HC.Reasm_Need >= 4
                     and then HC.Reasm_Need <= HC.Reasm_Len
                     and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
                     and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
                     and then Msg_Len <= HC.Reasm_Need - 4
                     and then Msg_Len <= Max_HS_Msg - 4
                     and then HC.Cfg.Random /= null
                     and then HC.Selected_Group in
                       Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                     and then Valid_ECDHE_Group (HC.Selected_Group)
                     and then HC.Transcript_Len > 0
                     and then HC.Transcript_Len <= Transcript_Capacity
                     and then SPARKTLSCrypto.P384.Field.Initialized
                     and then SPARKTLSCrypto.P384.ECDSA.Initialized);

   procedure Prepare_Leftover_Server_Flight_Message
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Msg_Type :    out Byte;
      Msg_Len  :    out N32;
      Ready    :    out Boolean;
      Result   :    out Action)
   is
      Parse_OK : Boolean;
   begin
      Msg_Type := 0;
      Msg_Len := 0;
      Ready := False;
      Result := OK;

      Handshake.Parse_Handshake_Header
        (HC.Reasm_Buf (0 .. HC.Reasm_Need - 1),
         Msg_Type, Msg_Len, Parse_OK);
      if not Parse_OK then
         Free_Byte_Seq (HC.Reasm_Buf);
         HC.Reasm_Len := 0;
         HC.Reasm_Need := 0;
         HC.Reasm_Hdr_Pending := False;
         Send_Alert_And_Error (S, Decode_Error, Result);
         pragma Assert (Reasm_Coherent (HC));
         return;
      end if;
      pragma Assert (Msg_Len <= HC.Reasm_Need - 4);
      pragma Assert (Reasm_Coherent (HC));
      Ready := True;
      Result := OK;
   end Prepare_Leftover_Server_Flight_Message;

   procedure Decode_Pending_Reassembly_Header
     (HC     : in out Handshake_Context;
      Failed :    out Boolean)
   with Pre  => HC.Reasm_Buf /= null
                and then HC.Reasm_Buf'First = 0
                and then HC.Reasm_Buf'Length = Max_HS_Msg
                and then HC.Reasm_Hdr_Pending
                and then HC.Reasm_Need = 4
                and then HC.Reasm_Len >= 4
                and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => Reasm_Coherent (HC)
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized
                and then
                  (if not Failed then
                     HC.Reasm_Buf /= null
                     and then HC.Reasm_Buf'First = 0
                     and then HC.Reasm_Buf'Length = Max_HS_Msg
                     and then not HC.Reasm_Hdr_Pending
                     and then HC.Reasm_Need >= 4
                     and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
                     and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));

   procedure Decode_Pending_Reassembly_Header
     (HC     : in out Handshake_Context;
      Failed :    out Boolean)
   is
      B1 : constant Byte := HC.Reasm_Buf (1);
      B2 : constant Byte := HC.Reasm_Buf (2);
      B3 : constant Byte := HC.Reasm_Buf (3);
      HS_Total : constant N32 :=
         N32 (B1) * 65536 + N32 (B2) * 256 + N32 (B3) + 4;
   begin
      Failed := False;
      HC.Reasm_Hdr_Pending := False;
      if HS_Total < 4 or HS_Total > Max_HS_Msg then
         Free_Byte_Seq (HC.Reasm_Buf);
         HC.Reasm_Len := 0;
         HC.Reasm_Need := 0;
         HC.Reasm_Hdr_Pending := False;
         Failed := True;
         pragma Assert (Reasm_Coherent (HC));
         return;
      end if;

      HC.Reasm_Need := HS_Total;
      pragma Assert (Reasm_Coherent (HC));
   end Decode_Pending_Reassembly_Header;

   procedure Continue_Server_Flight_Reassembly
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Rec      : in     Records.Parse_Result;
      Msg_Type :    out Byte;
      Msg_Len  :    out N32;
      Ready    :    out Boolean;
      Result   :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Reasm_Coherent (HC)
                and then Rec.OK
                and then Rec.Content = Records.Content_Handshake
                and then Rec.Fragment_Pos <= N32'Last - Rec.Fragment_Len
                and then Rec.Record_Len =
                  Rec.Fragment_Pos + Rec.Fragment_Len
                and then Rec.Record_Len <=
                  S.Input.Write_Pos - S.Input.Read_Pos
                and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
                and then HC.Reasm_Buf /= null
                and then HC.Reasm_Buf'First = 0
                and then HC.Reasm_Buf'Length <= Max_HS_Msg
                and then HC.Reasm_Need > 0
                and then (HC.Reasm_Hdr_Pending
                          or else HC.Reasm_Len < HC.Reasm_Need)
                and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
                and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => Reasm_Coherent (HC)
                and then
                  (if Ready then
                     Result = OK
                     and then S.State not in Idle | Closing | Closed | Error_State
                     and then HC.Reasm_Buf /= null
                     and then HC.Reasm_Buf'First = 0
                     and then HC.Reasm_Buf'Length <= Max_HS_Msg
                     and then not HC.Reasm_Hdr_Pending
                     and then HC.Reasm_Need >= 4
                     and then HC.Reasm_Need <= HC.Reasm_Len
                     and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
                     and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
                     and then Msg_Len <= HC.Reasm_Need - 4
                     and then Msg_Len <= Max_HS_Msg - 4
                     and then HC.Cfg.Random /= null
                     and then HC.Selected_Group in
                       Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                     and then Valid_ECDHE_Group (HC.Selected_Group)
                     and then HC.Transcript_Len > 0
                     and then HC.Transcript_Len <= Transcript_Capacity
                     and then SPARKTLSCrypto.P384.Field.Initialized
                     and then SPARKTLSCrypto.P384.ECDSA.Initialized);

   procedure Continue_Server_Flight_Reassembly
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Rec      : in     Records.Parse_Result;
      Msg_Type :    out Byte;
      Msg_Len  :    out N32;
      Ready    :    out Boolean;
      Result   :    out Action)
   is
      FS       : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
      Frag_Len : constant N32 := Rec.Fragment_Len;
   begin
      Msg_Type := 0;
      Msg_Len := 0;
      Ready := False;
      Result := OK;

      declare
         Remaining : constant N32 := HC.Reasm_Need - HC.Reasm_Len;
         Copy_Len  : constant N32 := N32'Min (Frag_Len, Remaining);
         Old_Len   : constant N32 := HC.Reasm_Len;
      begin
         if Copy_Len > 0
           and then HC.Reasm_Len + Copy_Len <=
                      N32 (HC.Reasm_Buf'Length)
         then
            pragma Assert
              (Rec.Record_Len = Rec.Fragment_Pos + Rec.Fragment_Len);
            pragma Assert
              (Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos);
            pragma Assert (FS + Frag_Len <= S.Input.Write_Pos);
            pragma Assert (FS + Copy_Len <= S.Input.Write_Pos);
            declare
               Source : Byte_Seq renames
                  S.Input.Data (FS .. FS + Copy_Len - 1);
            begin
               Copy_To_Reassembly_Buffer
                 (Reasm_Buf => HC.Reasm_Buf,
                  Old_Len   => Old_Len,
                  Source    => Source,
                  Copy_Len  => Copy_Len,
                  Required_Len => HC.Reasm_Need,
                  Was_Max   => HC.Reasm_Buf'Length = Max_HS_Msg);
            end;
            HC.Reasm_Len := Old_Len + Copy_Len;
         end if;
      end;
      pragma Assert (HC.Reasm_Buf /= null);
      pragma Assert (HC.Reasm_Buf'First = 0);
      pragma Assert (HC.Reasm_Buf'Length <= Max_HS_Msg);
      pragma Assert (HC.Reasm_Need > 0);
      pragma Assert (HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length));
      pragma Assert (HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length));
      pragma Assert (Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos);
      pragma Assert (S.Input.Read_Pos <= N32'Last - Rec.Record_Len);
      S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

      if HC.Reasm_Hdr_Pending and then HC.Reasm_Len >= 4 then
         declare
            Failed : Boolean;
         begin
            Decode_Pending_Reassembly_Header
              (HC     => HC,
               Failed => Failed);
            if Failed then
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;
         end;
      end if;

      if HC.Reasm_Len < HC.Reasm_Need then
         Result := OK;
         if HC.Reasm_Hdr_Pending then
            pragma Assert (HC.Reasm_Buf'Length = Max_HS_Msg);
            pragma Assert (HC.Reasm_Need = 4);
            pragma Assert (HC.Reasm_Len < 4);
         end if;
         pragma Assert (Reasm_Coherent (HC));
         return;
      end if;
      pragma Assert (HC.Reasm_Len >= HC.Reasm_Need);
      if HC.Reasm_Hdr_Pending then
         pragma Assert (HC.Reasm_Buf'Length = Max_HS_Msg);
         pragma Assert (HC.Reasm_Need = 4);
         pragma Assert (HC.Reasm_Len < 4);
      end if;
      pragma Assert (Reasm_Coherent (HC));
      pragma Assert (not HC.Reasm_Hdr_Pending);
      pragma Assert (HC.Reasm_Need <= HC.Reasm_Len);

      Prepare_Leftover_Server_Flight_Message
        (S        => S,
         HC       => HC,
         Msg_Type => Msg_Type,
         Msg_Len  => Msg_Len,
         Ready    => Ready,
         Result   => Result);
   end Continue_Server_Flight_Reassembly;

   procedure Prepare_Fresh_Server_Flight_Message
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Rec      : in     Records.Parse_Result;
      Msg_Type :    out Byte;
      Msg_Len  :    out N32;
      Ready    :    out Boolean;
      Result   :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Reasm_Coherent (HC)
                and then Rec.OK
                and then Rec.Content = Records.Content_Handshake
                and then Rec.Fragment_Pos <= N32'Last - Rec.Fragment_Len
                and then Rec.Record_Len =
                  Rec.Fragment_Pos + Rec.Fragment_Len
                and then Rec.Record_Len <=
                  S.Input.Write_Pos - S.Input.Read_Pos
                and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
                and then (HC.Reasm_Buf = null or else HC.Reasm_Need = 0)
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => Reasm_Coherent (HC)
                and then
                  (if Ready then
                     Result = OK
                     and then S.State not in Idle | Closing | Closed | Error_State
                     and then HC.Reasm_Buf /= null
                     and then HC.Reasm_Buf'First = 0
                     and then HC.Reasm_Buf'Length <= Max_HS_Msg
                     and then not HC.Reasm_Hdr_Pending
                     and then HC.Reasm_Need >= 4
                     and then HC.Reasm_Need <= HC.Reasm_Len
                     and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
                     and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
                     and then Msg_Len <= HC.Reasm_Need - 4
                     and then Msg_Len <= Max_HS_Msg - 4
                     and then HC.Cfg.Random /= null
                     and then HC.Selected_Group in
                       Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                     and then Valid_ECDHE_Group (HC.Selected_Group)
                     and then HC.Transcript_Len > 0
                     and then HC.Transcript_Len <= Transcript_Capacity
                     and then SPARKTLSCrypto.P384.Field.Initialized
                     and then SPARKTLSCrypto.P384.ECDSA.Initialized);

   procedure Start_Fresh_Pending_Header_Reassembly
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Rec      : in     Records.Parse_Result;
      FS       : in     N32;
      Frag_Len : in     N32;
      Result   :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Reasm_Coherent (HC)
                and then Rec.OK
                and then Rec.Content = Records.Content_Handshake
                and then Rec.Fragment_Pos <= N32'Last - Rec.Fragment_Len
                and then Rec.Record_Len =
                  Rec.Fragment_Pos + Rec.Fragment_Len
                and then Rec.Record_Len <=
                  S.Input.Write_Pos - S.Input.Read_Pos
                and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
                and then Frag_Len = Rec.Fragment_Len
                and then Frag_Len in 1 .. 3
                and then FS = S.Input.Read_Pos + Rec.Fragment_Pos
                and then FS + Frag_Len <= S.Input.Write_Pos
                and then (HC.Reasm_Buf = null or else HC.Reasm_Need = 0)
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => Reasm_Coherent (HC)
                and then Result = OK
                and then S.State not in Idle | Closing | Closed | Error_State
                and then HC.Reasm_Buf /= null
                and then HC.Reasm_Buf'First = 0
                and then HC.Reasm_Buf'Length = Max_HS_Msg
                and then HC.Reasm_Need = 4
                and then HC.Reasm_Hdr_Pending
                and then HC.Reasm_Len = Frag_Len
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized;

   procedure Start_Fresh_Pending_Header_Reassembly
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Rec      : in     Records.Parse_Result;
      FS       : in     N32;
      Frag_Len : in     N32;
      Result   :    out Action)
   is
   begin
      HC.Reasm_Buf := new Byte_Seq'(0 .. Max_HS_Msg - 1 => 0);
      HC.Reasm_Need := 4;
      HC.Reasm_Hdr_Pending := True;
      HC.Reasm_Len := Frag_Len;
      for I in N32 range 0 .. Frag_Len - 1 loop
         pragma Loop_Invariant (I <= Frag_Len - 1);
         pragma Loop_Invariant (HC.Reasm_Buf /= null);
         pragma Loop_Invariant (HC.Reasm_Buf'First = 0);
         pragma Loop_Invariant (HC.Reasm_Buf'Length = Max_HS_Msg);
         pragma Loop_Invariant (FS + Frag_Len <= S.Input.Write_Pos);
         HC.Reasm_Buf (I) := S.Input.Data (FS + I);
      end loop;
      S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
      Result := OK;
      pragma Assert (Reasm_Coherent (HC));
   end Start_Fresh_Pending_Header_Reassembly;

   procedure Start_Fresh_Spanning_Reassembly
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Rec      : in     Records.Parse_Result;
      FS       : in     N32;
      Frag_Len : in     N32;
      Msg_Len  : in     N32;
      Result   :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Reasm_Coherent (HC)
                and then Rec.OK
                and then Rec.Content = Records.Content_Handshake
                and then Rec.Fragment_Pos <= N32'Last - Rec.Fragment_Len
                and then Rec.Record_Len =
                  Rec.Fragment_Pos + Rec.Fragment_Len
                and then Rec.Record_Len <=
                  S.Input.Write_Pos - S.Input.Read_Pos
                and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
                and then Frag_Len = Rec.Fragment_Len
                and then Frag_Len >= 4
                and then FS = S.Input.Read_Pos + Rec.Fragment_Pos
                and then FS + Frag_Len <= S.Input.Write_Pos
                and then Msg_Len <= Max_HS_Msg - 4
                and then Msg_Len + 4 > Frag_Len
                and then (HC.Reasm_Buf = null or else HC.Reasm_Need = 0)
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => Reasm_Coherent (HC)
                and then Result = OK
                and then S.State not in Idle | Closing | Closed | Error_State
                and then HC.Reasm_Buf /= null
                and then HC.Reasm_Buf'First = 0
                and then HC.Reasm_Buf'Length = Msg_Len + 4
                and then HC.Reasm_Need = Msg_Len + 4
                and then HC.Reasm_Len = Frag_Len
                and then not HC.Reasm_Hdr_Pending
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized;

   procedure Start_Fresh_Spanning_Reassembly
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Rec      : in     Records.Parse_Result;
      FS       : in     N32;
      Frag_Len : in     N32;
      Msg_Len  : in     N32;
      Result   :    out Action)
   is
      Total : constant N32 := Msg_Len + 4;
   begin
      HC.Reasm_Buf := new Byte_Seq'(0 .. Total - 1 => 0);
      HC.Reasm_Need := Total;
      HC.Reasm_Len := Frag_Len;
      HC.Reasm_Hdr_Pending := False;
      for I in N32 range 0 .. Frag_Len - 1 loop
         pragma Loop_Invariant (I <= Frag_Len - 1);
         pragma Loop_Invariant (HC.Reasm_Buf /= null);
         pragma Loop_Invariant (HC.Reasm_Buf'First = 0);
         pragma Loop_Invariant (HC.Reasm_Buf'Length = Total);
         pragma Loop_Invariant (Frag_Len <= Total);
         pragma Loop_Invariant (FS + Frag_Len <= S.Input.Write_Pos);
         HC.Reasm_Buf (I) := S.Input.Data (FS + I);
      end loop;
      S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
      Result := OK;
      pragma Assert (Reasm_Coherent (HC));
   end Start_Fresh_Spanning_Reassembly;

   procedure Start_Fresh_Complete_Message
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Rec      : in     Records.Parse_Result;
      FS       : in     N32;
      Frag_Len : in     N32;
      Msg_Len  : in     N32;
      Result   :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Reasm_Coherent (HC)
                and then Rec.OK
                and then Rec.Content = Records.Content_Handshake
                and then Rec.Fragment_Pos <= N32'Last - Rec.Fragment_Len
                and then Rec.Record_Len =
                  Rec.Fragment_Pos + Rec.Fragment_Len
                and then Rec.Record_Len <=
                  S.Input.Write_Pos - S.Input.Read_Pos
                and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
                and then Frag_Len = Rec.Fragment_Len
                and then Frag_Len >= 4
                and then Frag_Len <= Max_HS_Msg
                and then FS = S.Input.Read_Pos + Rec.Fragment_Pos
                and then FS + Frag_Len <= S.Input.Write_Pos
                and then Msg_Len <= Frag_Len - 4
                and then Msg_Len <= Max_HS_Msg - 4
                and then (HC.Reasm_Buf = null or else HC.Reasm_Need = 0)
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => Reasm_Coherent (HC)
                and then Result = OK
                and then S.State not in Idle | Closing | Closed | Error_State
                and then HC.Reasm_Buf /= null
                and then HC.Reasm_Buf'First = 0
                and then HC.Reasm_Buf'Length = Frag_Len
                and then HC.Reasm_Need = Msg_Len + 4
                and then HC.Reasm_Len = Frag_Len
                and then HC.Reasm_Need <= HC.Reasm_Len
                and then not HC.Reasm_Hdr_Pending
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized;

   procedure Start_Fresh_Complete_Message
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Rec      : in     Records.Parse_Result;
      FS       : in     N32;
      Frag_Len : in     N32;
      Msg_Len  : in     N32;
      Result   :    out Action)
   is
   begin
      HC.Reasm_Buf := new Byte_Seq'(0 .. Frag_Len - 1 => 0);
      HC.Reasm_Need := Msg_Len + 4;
      HC.Reasm_Len := Frag_Len;
      HC.Reasm_Hdr_Pending := False;
      for I in N32 range 0 .. Frag_Len - 1 loop
         pragma Loop_Invariant (I <= Frag_Len - 1);
         pragma Loop_Invariant (HC.Reasm_Buf /= null);
         pragma Loop_Invariant (HC.Reasm_Buf'First = 0);
         pragma Loop_Invariant (HC.Reasm_Buf'Length = Frag_Len);
         pragma Loop_Invariant (FS + Frag_Len <= S.Input.Write_Pos);
         HC.Reasm_Buf (I) := S.Input.Data (FS + I);
      end loop;
      S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
      Result := OK;
      pragma Assert (Reasm_Coherent (HC));
   end Start_Fresh_Complete_Message;

   procedure Prepare_Fresh_Server_Flight_Message
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Rec      : in     Records.Parse_Result;
      Msg_Type :    out Byte;
      Msg_Len  :    out N32;
      Ready    :    out Boolean;
      Result   :    out Action)
   is
      FS       : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
      Frag_Len : constant N32 := Rec.Fragment_Len;
      Parse_OK : Boolean;
   begin
      Msg_Type := 0;
      Msg_Len := 0;
      Ready := False;
      Result := OK;

      if Frag_Len < 4 then
         if Frag_Len = 0 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Decode_Error, Result);
            pragma Assert (Reasm_Coherent (HC));
            return;
         end if;
         Start_Fresh_Pending_Header_Reassembly
           (S        => S,
            HC       => HC,
            Rec      => Rec,
            FS       => FS,
            Frag_Len => Frag_Len,
            Result   => Result);
         return;
      end if;

      declare
         Frag : Byte_Seq renames
            S.Input.Data (FS .. FS + Frag_Len - 1);
      begin
         Handshake.Parse_Handshake_Header
           (Frag, Msg_Type, Msg_Len, Parse_OK);
      end;
      if not Parse_OK then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         declare
            Raw_Type : constant Byte :=
               (if Frag_Len >= 1 then S.Input.Data (FS) else 0);
            Is_Known : constant Boolean :=
               Raw_Type in 16#01# | 16#02# | 16#04# | 16#08# |
                           16#0B# | 16#0C# | 16#0D# | 16#0E# |
                           16#0F# | 16#10# | 16#14#;
         begin
            if Is_Known then
               Send_Alert_And_Error (S, Decode_Error, Result);
            else
               Send_Alert_And_Error
                 (S, Unexpected_Message, Result);
            end if;
         end;
         pragma Assert (Reasm_Coherent (HC));
         return;
      end if;
      pragma Assert (Msg_Len <= Frag_Len - 4);

      if Msg_Len + 4 > Frag_Len then
         if Msg_Len + 4 > Max_HS_Msg then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Decode_Error, Result);
            pragma Assert (Reasm_Coherent (HC));
            return;
         end if;
         Start_Fresh_Spanning_Reassembly
           (S        => S,
            HC       => HC,
            Rec      => Rec,
            FS       => FS,
            Frag_Len => Frag_Len,
            Msg_Len  => Msg_Len,
            Result   => Result);
         return;
      end if;

      Start_Fresh_Complete_Message
        (S        => S,
         HC       => HC,
         Rec      => Rec,
         FS       => FS,
         Frag_Len => Frag_Len,
         Msg_Len  => Msg_Len,
         Result   => Result);
      pragma Assert (Reasm_Coherent (HC));
      pragma Assert (HC.Reasm_Need <= HC.Reasm_Len);
      pragma Assert (not HC.Reasm_Hdr_Pending);
      pragma Assert (Msg_Len <= HC.Reasm_Need - 4);
      Ready := True;
      Result := OK;
   end Prepare_Fresh_Server_Flight_Message;

   procedure Prepare_Server_Flight_Message
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Msg_Type :    out Byte;
      Msg_Len  :    out N32;
      Ready    :    out Boolean;
      Result   :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and then Reasm_Coherent (HC)
                and then Warning_Alerts_Bounded_RFC_8446_6_1 (S)
                and then HC.Cfg.Random /= null
                and then HC.Selected_Group in
                  Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                and then Valid_ECDHE_Group (HC.Selected_Group)
                and then HC.Transcript_Len > 0
                and then HC.Transcript_Len <= Transcript_Capacity
                and then SPARKTLSCrypto.P384.Field.Initialized
                and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => Reasm_Coherent (HC)
                and then
                  (if Ready then
                     Result = OK
                     and then S.State not in Idle | Closing | Closed | Error_State
                     and then HC.Reasm_Buf /= null
                     and then HC.Reasm_Buf'First = 0
                     and then HC.Reasm_Buf'Length <= Max_HS_Msg
                     and then not HC.Reasm_Hdr_Pending
                     and then HC.Reasm_Need >= 4
                     and then HC.Reasm_Need <= HC.Reasm_Len
                     and then HC.Reasm_Need <= N32 (HC.Reasm_Buf'Length)
                     and then HC.Reasm_Len <= N32 (HC.Reasm_Buf'Length)
                     and then Msg_Len <= HC.Reasm_Need - 4
                     and then Msg_Len <= Max_HS_Msg - 4
                     and then HC.Cfg.Random /= null
                     and then HC.Selected_Group in
                       Group_X25519 | Group_Secp256r1 | Group_Secp384r1
                     and then Valid_ECDHE_Group (HC.Selected_Group)
                     and then HC.Transcript_Len > 0
                     and then HC.Transcript_Len <= Transcript_Capacity
                     and then SPARKTLSCrypto.P384.Field.Initialized
                     and then SPARKTLSCrypto.P384.ECDSA.Initialized);

   procedure Prepare_Server_Flight_Message
     (S        : in out Session;
      HC       : in out Handshake_Context;
      Msg_Type :    out Byte;
      Msg_Len  :    out N32;
      Ready    :    out Boolean;
      Result   :    out Action)
   is
      Rec : Records.Parse_Result;
      Have_Leftover_Msg : constant Boolean :=
        HC.Reasm_Buf /= null
        and then HC.Reasm_Need > 0
        and then not HC.Reasm_Hdr_Pending
        and then HC.Reasm_Len >= HC.Reasm_Need;
   begin
      Msg_Type := 0;
      Msg_Len := 0;
      Ready := False;
      Result := OK;

      if Have_Leftover_Msg then
         Prepare_Leftover_Server_Flight_Message
           (S        => S,
            HC       => HC,
            Msg_Type => Msg_Type,
            Msg_Len  => Msg_Len,
            Ready    => Ready,
            Result   => Result);
      else
         declare
            Have_Record : Boolean;
         begin
            Read_Server_Flight_Record
              (S           => S,
               HC          => HC,
               Rec         => Rec,
               Have_Record => Have_Record,
               Result      => Result);
            if not Have_Record then
               pragma Assert (Reasm_Coherent (HC));
               return;
            end if;
            pragma Assert (Reasm_Coherent (HC));
            pragma Assert (Rec.OK);
            pragma Assert (Rec.Content = Records.Content_Handshake);

            if HC.Reasm_Need > 0
              and then HC.Reasm_Buf /= null
              and then (HC.Reasm_Hdr_Pending
                        or else HC.Reasm_Len < HC.Reasm_Need)
            then
               Continue_Server_Flight_Reassembly
                 (S        => S,
                  HC       => HC,
                  Rec      => Rec,
                  Msg_Type => Msg_Type,
                  Msg_Len  => Msg_Len,
                  Ready    => Ready,
                  Result   => Result);
            elsif HC.Reasm_Need > 0
              and then HC.Reasm_Buf /= null
            then
               pragma Assert (not HC.Reasm_Hdr_Pending);
               pragma Assert (HC.Reasm_Need <= HC.Reasm_Len);
               Prepare_Leftover_Server_Flight_Message
                 (S        => S,
                  HC       => HC,
                  Msg_Type => Msg_Type,
                  Msg_Len  => Msg_Len,
                  Ready    => Ready,
                  Result   => Result);
            else
               pragma Assert (not Have_Leftover_Msg);
               pragma Assert (HC.Reasm_Buf = null or else HC.Reasm_Need = 0);
               Prepare_Fresh_Server_Flight_Message
                 (S        => S,
                  HC       => HC,
                  Rec      => Rec,
                  Msg_Type => Msg_Type,
                  Msg_Len  => Msg_Len,
                  Ready    => Ready,
                  Result   => Result);
            end if;
         end;
      end if;
      pragma Assert (Reasm_Coherent (HC));
   end Prepare_Server_Flight_Message;

   procedure Process_Server_Flight
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
      Msg_Type : Byte;
      Msg_Len  : N32;
      Ready    : Boolean;
   begin
      Prepare_Server_Flight_Message
        (S        => S,
         HC       => HC,
         Msg_Type => Msg_Type,
         Msg_Len  => Msg_Len,
         Ready    => Ready,
         Result   => Result);

      if not Ready then
         return;
      end if;

      Drain_Packed_Server_Flight
        (S        => S,
         HC       => HC,
         Msg_Type => Msg_Type,
         Msg_Len  => Msg_Len,
         Result   => Result);
   end Process_Server_Flight;

   ------------------------------------------------------------------
   --  Process_Server_CCS: receive CCS, activate server read keys
   ------------------------------------------------------------------

   procedure Process_Server_CCS
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   with Pre => S.State not in Idle | Closing | Closed | Error_State
   is
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then Result := Need_Input; return; end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Available (S.Input), Rec);

      if Rec.Bad_Version then
         S.Last_Error := Protocol_Version;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      if not Rec.OK then Result := Need_Input; return; end if;

      if Rec.Content = Records.Content_Change_Cipher_Spec then
         declare
            CCS_Pos    : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
            CCS_Byte_OK : constant Boolean :=
               Rec.Fragment_Len = 1
               and then S.Input.Data (CCS_Pos) = 16#01#;
         begin
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if CCS_Byte_OK then
               HC.CCS_Received := True;
               Result := OK;
            else
               --  RFC 5246 §7.1: ChangeCipherSpec payload MUST be the
               --  single byte 0x01. BoGo BadChangeCipherSpec-* sends
               --  other bytes / lengths → unexpected_message.
               Send_Alert_And_Error (S, Unexpected_Message, Result);
            end if;
         end;
      elsif Rec.Content = Records.Content_Handshake then
         --  RFC 5077 §3.3 full-handshake NewSessionTicket arrives
         --  AFTER client CCS+Finished but BEFORE server CCS. The
         --  dispatcher routes here (post-client-CKE-flight, waiting
         --  for server CCS) so we need to consume the NST here.
         --  Parse + cache + skip; dispatcher will call us again to
         --  read the actual CCS that follows.
         declare
            FS       : constant N32 :=
              S.Input.Read_Pos + Rec.Fragment_Pos;
            Frag_Len : constant N32 := Rec.Fragment_Len;
         begin
            --  Minimum: HS header(4) + lifetime(4) + ticket_len(2) = 10
            if Frag_Len < 10 then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;
            if S.Input.Data (FS) /= 16#04# then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               return;
            end if;
            declare
               Body_Len : constant N32 :=
                  N32 (S.Input.Data (FS + 1)) * 65536
                  + N32 (S.Input.Data (FS + 2)) * 256
                  + N32 (S.Input.Data (FS + 3));
            begin
               if 4 + Body_Len /= Frag_Len then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;
               declare
                  NST_Body   : constant Byte_Seq (0 .. Body_Len - 1) :=
                    S.Input.Data (FS + 4 .. FS + 4 + Body_Len - 1);
                  Lifetime   : Unsigned_32;
                  Ticket_Len : N32;
                  Parse_OK   : Boolean;
               begin
                  SPARKTLS.Handshake.TLS12.Parse_New_Session_Ticket_12
                    (NST_Body      => NST_Body,
                     Lifetime_Hint => Lifetime,
                     Ticket_Len    => Ticket_Len,
                     OK            => Parse_OK);
                  if not Parse_OK or Ticket_Len > Max_TLS12_Ticket_Len then
                     S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                     Send_Alert_And_Error (S, Decode_Error, Result);
                     return;
                  end if;
                  if Ticket_Len > 0 then
                     S.TLS12_New_Ticket.Ticket (0 .. Ticket_Len - 1) :=
                        NST_Body (6 .. 6 + Ticket_Len - 1);
                  end if;
                  S.TLS12_New_Ticket.Ticket_Len := Ticket_Len;
                  S.TLS12_New_Ticket.Suite := S.Negotiated_Suite_12;
                  S.TLS12_New_Ticket.Master_Secret :=
                     HC.Master_Secret_12;
                  S.TLS12_New_Ticket.Lifetime_Hint := Lifetime;
                  S.TLS12_New_Ticket.Server_Name := HC.Cfg.Server_Name;
                  S.TLS12_New_Ticket.Valid := True;

                  --  RFC 5077 §3.3 + RFC 5246 §7.4.9: NST is hashed
                  --  into the handshake transcript before server's
                  --  Finished, so client Finished verify_data uses
                  --  the same hash. Without this, server's Finished
                  --  fails to verify in the full-HS session-ticket
                  --  flow.
                  Append_Transcript
                    (HC, S.Input.Data (FS .. FS + Frag_Len - 1));
               end;
            end;
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Result := OK;
            --  Dispatcher will call us again to consume the CCS
            --  that follows the NST.
         end;
      else
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result);
      end if;
   end Process_Server_CCS;

   ------------------------------------------------------------------
   --  Process_Server_Finished: decrypt + verify server Finished
   ------------------------------------------------------------------

   procedure Send_Encrypted_Finished_Error_12
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Desc_Code : in     Byte;
      Err       : in     Error_Code;
      Result    :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and Reasm_Building (HC)
                and Desc_Code /= 0
                and Records.TLS12.Nonce_Space_Available_12
                      (HC.Client_Seq_12),
        Post => S.State = Error_State
                and Reasm_Building (HC)
                and Result in Has_Output | Error_Alert;

   procedure Send_Encrypted_Finished_Error_12
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Desc_Code : in     Byte;
      Err       : in     Error_Code;
      Result    :    out Action)
   is
      Saved_Seq : constant Unsigned_64 := HC.Client_Seq_12;
      Dummy     : N32;
   begin
      Records.TLS12.Build_Alert_Record_12
        (Level       => 2,
         Desc        => Desc_Code,
         Keys        => S.Client_App,
         Implicit_IV => HC.Client_Write_IV_12,
         Seq_Num     => HC.Client_Seq_12,
         Output      => S.Output,
         Bytes_Out   => Dummy);
      if Dummy = 0 then
         HC.Client_Seq_12 := Saved_Seq;
      end if;

      Free_Byte_Seq (HC.Reasm_Buf);
      HC.Reasm_Len := 0;
      HC.Reasm_Need := 0;
      S.Last_Error := Err;
      Set_State (S, Error_State);
      Result := (if Output_Pending (S) > 0
                 then Has_Output else Error_Alert);
   end Send_Encrypted_Finished_Error_12;

   procedure Ensure_Finished_Reasm_Buffer_12
     (HC : in out Handshake_Context)
   with Pre  => Reasm_Building (HC),
        Post => Reasm_Building (HC)
                and HC.Reasm_Buf /= null
                and HC.Reasm_Len <= HC.Reasm_Need;

   procedure Ensure_Finished_Reasm_Buffer_12
     (HC : in out Handshake_Context)
   is
   begin
      if HC.Reasm_Buf = null then
         HC.Reasm_Buf := new Byte_Seq'(0 .. Max_HS_Msg - 1 => 0);
         pragma Assert (HC.Reasm_Buf'First = 0);
         pragma Assert (HC.Reasm_Buf'Length = Max_HS_Msg);
         HC.Reasm_Need := 4;
         HC.Reasm_Hdr_Pending := True;
         HC.Reasm_Len := 0;
      end if;
   end Ensure_Finished_Reasm_Buffer_12;

   procedure Copy_Finished_Reasm_Bytes_12
     (HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      PL        : in     N32;
      P_Pos     : in out N32)
   with Pre  => Reasm_Building (HC)
                and HC.Reasm_Buf /= null
                and Plaintext'First = 0
                and PL > 0
                and PL - 1 <= Plaintext'Last
                and P_Pos <= PL
                and not HC.Reasm_Hdr_Pending,
        Post => Reasm_Building (HC)
                and HC.Reasm_Buf /= null
                and P_Pos >= P_Pos'Old
                and P_Pos <= PL
                and HC.Reasm_Len >= HC.Reasm_Len'Old
                and HC.Reasm_Len <= HC.Reasm_Need;

   procedure Copy_Finished_Reasm_Bytes_12
     (HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      PL        : in     N32;
      P_Pos     : in out N32)
   is
      Take : constant N32 :=
         N32'Min (HC.Reasm_Need - HC.Reasm_Len, PL - P_Pos);
   begin
      if Take > 0 then
         pragma Assert (P_Pos + Take <= PL);
         pragma Assert (P_Pos + Take - 1 <= Plaintext'Last);
         pragma Assert
           (HC.Reasm_Len + Take <= N32 (HC.Reasm_Buf'Length));
         HC.Reasm_Buf
           (HC.Reasm_Len .. HC.Reasm_Len + Take - 1) :=
           Plaintext (P_Pos .. P_Pos + Take - 1);
         HC.Reasm_Len := HC.Reasm_Len + Take;
         P_Pos := P_Pos + Take;
      end if;
   end Copy_Finished_Reasm_Bytes_12;

   procedure Accumulate_Finished_Plaintext_12
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      PL        : in     N32;
      Complete  :    out Boolean;
      Result    :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and Reasm_Building (HC)
                and Plaintext'First = 0
                and PL > 0
                and PL - 1 <= Plaintext'Last
                and Records.TLS12.Nonce_Space_Available_12
                      (HC.Client_Seq_12),
        Post => Reasm_Building (HC)
                and (if Complete then
                       Result = OK
                       and then HC.Reasm_Buf /= null
                       and then HC.Reasm_Len = HC.Reasm_Need)
                and (if Result = OK then
                       S.State not in Idle | Closing | Closed | Error_State
                       and then Records.TLS12.Nonce_Space_Available_12
                         (HC.Client_Seq_12));

   procedure Accumulate_Finished_Plaintext_12
     (S         : in out Session;
      HC        : in out Handshake_Context;
      Plaintext : in     Byte_Seq;
      PL        : in     N32;
      Complete  :    out Boolean;
      Result    :    out Action)
   is
   begin
      Complete := False;
      Result := OK;

      --  Append decrypted plaintext to HC.Reasm_Buf. Allocate the
      --  buffer on first chunk; size cap is Max_HS_Msg which
      --  trivially holds Finished's 16 bytes. Use Hdr_Pending
      --  while we still need 4 bytes to know the real HS_Total.
      Ensure_Finished_Reasm_Buffer_12 (HC);
      pragma Assert (Reasm_Building (HC));
      pragma Assert (HC.Reasm_Buf /= null);

      declare
         P_Pos : N32 := 0;  --  bytes consumed from Plaintext
      begin
         --  First-take bounded by current Reasm_Need (which may
         --  still be the Hdr_Pending sentinel of 4).
         if HC.Reasm_Hdr_Pending then
            declare
               Take : constant N32 :=
                  N32'Min (PL, 4 - HC.Reasm_Len);
            begin
               if Take > 0 then
                  pragma Assert (P_Pos + Take <= PL);
                  pragma Assert (P_Pos + Take - 1 <= Plaintext'Last);
                  pragma Assert
                    (HC.Reasm_Len + Take <=
                       N32 (HC.Reasm_Buf'Length));
                  HC.Reasm_Buf
                    (HC.Reasm_Len .. HC.Reasm_Len + Take - 1) :=
                    Plaintext (P_Pos .. P_Pos + Take - 1);
                  HC.Reasm_Len := HC.Reasm_Len + Take;
                  P_Pos := P_Pos + Take;
               end if;
            end;
         else
            Copy_Finished_Reasm_Bytes_12 (HC, Plaintext, PL, P_Pos);
         end if;

         if HC.Reasm_Hdr_Pending and then HC.Reasm_Len >= 4 then
            declare
               HS_Total : constant N32 :=
                  N32 (HC.Reasm_Buf (1)) * 65536
                  + N32 (HC.Reasm_Buf (2)) * 256
                  + N32 (HC.Reasm_Buf (3)) + 4;
            begin
               HC.Reasm_Hdr_Pending := False;
               if HS_Total < 4 or HS_Total > Max_HS_Msg then
                  Free_Byte_Seq (HC.Reasm_Buf);
                  HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;
               HC.Reasm_Need := HS_Total;
            end;
            --  Drain remaining plaintext bytes from this same
            --  record (non-split case: full Finished in one record).
            if P_Pos < PL and HC.Reasm_Len < HC.Reasm_Need then
               Copy_Finished_Reasm_Bytes_12 (HC, Plaintext, PL, P_Pos);
            end if;

            --  RFC 5246 §7.4.9: server Finished is the last server
            --  handshake message and must be the last thing in its
            --  TLS record. Any leftover plaintext after the Finished
            --  body is fatal unexpected_message (BoGo
            --  TrailingDataWithFinished-Client-TLS12). The alert is
            --  encrypted under client_write_key since we're post-CCS.
            if HC.Reasm_Len = HC.Reasm_Need and P_Pos < PL then
               Send_Encrypted_Finished_Error_12
                 (S, HC, 10, Unexpected_Message, Result);
               return;
            end if;
         end if;
      end;

      Complete := HC.Reasm_Len >= HC.Reasm_Need;
   end Accumulate_Finished_Plaintext_12;

   --  RFC 5077 §3.3 abbreviated handshake client flight: CCS plus
   --  encrypted Finished. In the resumed flow the CLIENT sends these
   --  AFTER the server's Finished (inverse of the full handshake order
   --  where they were already sent). Atomic flight assembly: build
   --  into Scratch first, roll back HC.Client_Seq_12 on commit fail.
   procedure Send_Abbreviated_Client_Flight_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and Reasm_Building (HC)
                and HC.Transcript_Len > 0
                and Records.TLS12.Nonce_Space_Available_12
                      (HC.Client_Seq_12),
        Post => Reasm_Building (HC)
                and (if Result = OK then
                       S.State not in Idle | Closing | Closed | Error_State);

   procedure Send_Abbreviated_Client_Flight_12
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Action)
   is
      use Records.TLS12;
      use Key_Schedule_12;
      Use_384 : constant Boolean :=
         S.Negotiated_Suite in Suite_ECDHE_RSA_AES256_GCM_SHA384
                            | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
      Scratch    : IO_Buffer;
      CCS_Out    : N32;
      FB         : Byte_Seq (0 .. Finished_12_Total_Len - 1);
      FL         : N32;
      TH         : Digest;
      TH4        : SPARKNaCl.Hashing.SHA384.Digest;
      EO         : N32;
      Saved_Seq  : Unsigned_64;
   begin
      Result := OK;
      Records.Build_CCS_Record (Scratch, CCS_Out);
      if CCS_Out = 0 then
         Send_Alert_And_Error (S, Insufficient_Buffer, Result);
         return;
      end if;
      if Use_384 then
         SPARKNaCl.Hashing.SHA384.Hash
           (TH4, HC.Transcript (0 .. HC.Transcript_Len - 1));
         Build_Finished_12 (HC.Master_Secret_12,
                            Label_Client_Finished,
                            Byte_Seq (TH4), True, FB, FL);
      else
         Hash (TH, HC.Transcript (0 .. HC.Transcript_Len - 1));
         Build_Finished_12 (HC.Master_Secret_12,
                            Label_Client_Finished,
                            Byte_Seq (TH), False, FB, FL);
      end if;
      Saved_Seq := HC.Client_Seq_12;
      Build_Encrypted_Record_12
        (FB (0 .. FL - 1), 16#16#, S.Client_App,
         HC.Client_Write_IV_12, HC.Client_Seq_12,
         Scratch, EO);
      if EO = 0 then
         HC.Client_Seq_12 := Saved_Seq;
         Send_Alert_And_Error (S, Insufficient_Buffer, Result);
         return;
      end if;
      if Free_Space (S.Output) < Scratch.Write_Pos then
         HC.Client_Seq_12 := Saved_Seq;
         Send_Alert_And_Error (S, Insufficient_Buffer, Result);
         return;
      end if;
      S.Output.Data
        (S.Output.Write_Pos ..
         S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
         Scratch.Data (0 .. Scratch.Write_Pos - 1);
      S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;
   end Send_Abbreviated_Client_Flight_12;

   procedure Process_Server_Finished
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   with Pre  => S.State not in Idle | Closing | Closed | Error_State
                and Reasm_Building (HC)
                and HC.Transcript_Len > 0
                and Records.TLS12.Nonce_Space_Available_12
                      (HC.Client_Seq_12)
                and Records.TLS12.Nonce_Space_Available_12
                      (HC.Server_Seq_12),
        Post => Reasm_Building (HC)
                and (if Result = OK then
                       S.State not in Idle | Closing | Closed | Error_State);

   procedure Process_Server_Finished
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
      use Records.TLS12;
      use Key_Schedule_12;
      Rec : Records.Parse_Result;
      Use_384 : constant Boolean :=
         S.Negotiated_Suite in Suite_ECDHE_RSA_AES256_GCM_SHA384
                             | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
   begin
      if Input_Available (S) = 0 then Result := Need_Input; return; end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Available (S.Input), Rec);

      if Rec.Bad_Version then
         S.Last_Error := Protocol_Version;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      if not Rec.OK then Result := Need_Input; return; end if;

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result); return;
      end if;

      --  Decrypt one encrypted record and append its plaintext to
      --  HC.Reasm_Buf. BoGo's MaxHandshakeRecordLength=1 fragments
      --  the encrypted Finished into 16+ tiny records (each
      --  separately AEAD-encrypted with its own seq counter); we
      --  drain them into the same HC reassembly buffer until the
      --  full Finished message is in.
      declare
         Frag_Len : constant N32 := Rec.Fragment_Len;
         FS : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Encrypted : Byte_Seq (0 .. Frag_Len - 1);
         Hdr : Byte_Seq (0 .. 4);
         Plaintext : Byte_Seq (0 .. Frag_Len - 1);
         PL : N32; DV : Boolean;
      begin
         for I in N32 range 0 .. Frag_Len - 1 loop
            Encrypted (I) := S.Input.Data (FS + I);
         end loop;
         for I in N32 range 0 .. 4 loop
            Hdr (I) := S.Input.Data (S.Input.Read_Pos + I);
         end loop;

         declare
            Min_Frag : constant N32 :=
              (if S.Server_App.Suite = Suite_CHACHA20_POLY1305_SHA256
               then GCM_Tag_Len + 1
               else Explicit_Nonce_Len + GCM_Tag_Len + 1);
         begin
            if Frag_Len > Max_Record_Plaintext + TLS12_Record_Overhead then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Decode_Error, Result); return;
            end if;
            if Frag_Len < Min_Frag then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Decode_Error, Result); return;
            end if;
         end;

         Decrypt_Record_12 (Encrypted, Hdr, S.Server_App,
                            HC.Server_Write_IV_12, HC.Server_Seq_12,
                            Plaintext, PL, DV);
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

         if not DV then
            Send_Alert_And_Error (S, Bad_Record_MAC, Result); return;
         end if;
         if PL = 0 then
            Send_Alert_And_Error (S, Decode_Error, Result); return;
         end if;

         declare
            Complete : Boolean;
         begin
            Accumulate_Finished_Plaintext_12
              (S, HC, Plaintext, PL, Complete, Result);
            if Result /= OK then
               return;
            end if;
            if not Complete then
               Result := OK;
               return;  --  more encrypted records to drain
            end if;
         end;

         if HC.Reasm_Len < HC.Reasm_Need then
            Result := OK;
            return;  --  more encrypted records to drain
         end if;

         --  Full Finished plaintext now in HC.Reasm_Buf (0 .. RN-1).
         declare
            RN : constant N32 := HC.Reasm_Need;
            Msg_Type : constant Byte := HC.Reasm_Buf (0);
            Msg_Len : constant N32 :=
               N32 (HC.Reasm_Buf (1)) * 65536
               + N32 (HC.Reasm_Buf (2)) * 256
               + N32 (HC.Reasm_Buf (3));
         begin
            if Msg_Type /= HT_Finished
              or RN < 4 + Finished_Verify_Len
            then
               --  Wrong type or short body. We're post-CCS so the
               --  alert MUST be encrypted (server expects encrypted
               --  records after CCS — sending plaintext yields
               --  bad_record_mac on the peer). BoGo
               --  WrongMessageType-ServerFinished expects
               --  unexpected_message; we treat short body as
               --  decode_error.
               declare
                  Desc_Code : constant Byte :=
                     (if Msg_Type /= HT_Finished then 10 else 50);
               begin
                  Send_Encrypted_Finished_Error_12
                    (S, HC, Desc_Code,
                     (if Msg_Type /= HT_Finished
                      then Unexpected_Message else Decode_Error),
                     Result);
               end;
               return;
            end if;
            if Msg_Len /= Finished_Verify_Len then
               --  Length mismatch on Finished — RFC 5246 §7.4.9 +
               --  RFC 8446 §6.2: decrypt_error (alert 51). We're
               --  post-CCS so the alert must be encrypted with our
               --  client_write_key, not plaintext.
               Send_Encrypted_Finished_Error_12
                 (S, HC, 51, Certificate_Verify_Failed, Result);
               return;
            end if;
            if RN /= 4 + Finished_Verify_Len then
               Send_Encrypted_Finished_Error_12
                 (S, HC, 51, Certificate_Verify_Failed, Result);
               return;
            end if;

            --  Verify server Finished
            declare
               Exp : Verify_Data_12;
               TH : Digest; TH4 : SPARKNaCl.Hashing.SHA384.Digest;
            begin
               if Use_384 then
                  SPARKNaCl.Hashing.SHA384.Hash
                    (TH4, HC.Transcript (0 .. HC.Transcript_Len - 1));
                  Compute_Finished_12 (Exp, HC.Master_Secret_12,
                                       Label_Server_Finished,
                                       Byte_Seq (TH4), True);
               else
                  Hash (TH, HC.Transcript (0 .. HC.Transcript_Len - 1));
                  Compute_Finished_12 (Exp, HC.Master_Secret_12,
                                       Label_Server_Finished,
                                       Byte_Seq (TH), False);
               end if;

               declare
                  Received : constant Verify_Data_12 :=
                     Verify_Data_12
                       (HC.Reasm_Buf
                          (4 .. 4 + Finished_Verify_Len - 1));
               begin
                  if not Equal (Byte_Seq (Received),
                                Byte_Seq (Exp))
                  then
                     Free_Byte_Seq (HC.Reasm_Buf);
                     HC.Reasm_Len := 0; HC.Reasm_Need := 0;
                     Send_Alert_And_Error (S, Handshake_Failure, Result);
                     return;
                  end if;
               end;
            end;
         end;

         --  Append server Finished plaintext to transcript so the
         --  client's own Finished verify_data (computed below in the
         --  abbreviated path) covers it. Copy into a local first —
         --  passing a slice of HC.Reasm_Buf alongside `in out HC`
         --  is a SPARK 6.4.2 aliasing violation.
         declare
            Fin_Snap : constant Byte_Seq :=
               HC.Reasm_Buf (0 .. HC.Reasm_Need - 1);
         begin
            pragma Assert (Fin_Snap'Length = Finished_12_Total_Len);
            Append_Transcript (HC, Fin_Snap);
         end;

         Free_Byte_Seq (HC.Reasm_Buf);
         HC.Reasm_Len := 0; HC.Reasm_Need := 0;
      end;

      --  RFC 5077 §3.3 abbreviated handshake: in the resumed flow the
      --  CLIENT sends CCS+Finished AFTER the server's. In the full-HS
      --  case both records were sent before the server's Finished
      --  arrived, so this is a no-op.
      if HC.TLS12_Resuming then
         Send_Abbreviated_Client_Flight_12 (S, HC, Result);
         if Result /= OK then return; end if;
      end if;

      --  Copy TLS 1.2 state to Session
      S.Negotiated_Version := TLS_1_2;
      S.Client_IV_12 := HC.Client_Write_IV_12;
      S.Server_IV_12 := HC.Server_Write_IV_12;
      S.Client_Seq_12 := HC.Client_Seq_12;
      S.Server_Seq_12 := HC.Server_Seq_12;

      Set_State (S, Connected);
      S.Handshake_Just_Done := True;
      Result := (if Output_Pending (S) > 0 then Has_Output else Handshake_Done);
      if Result = Handshake_Done then S.Handshake_Just_Done := False; end if;
   end Process_Server_Finished;

   ------------------------------------------------------------------
   --  Advance_Handshake_12: dispatch based on internal state
   ------------------------------------------------------------------

   procedure Advance_Handshake_12
     (S : in out Session; HC : in out Handshake_Context; Result : out Action)
   is
   begin
      if Output_Pending (S) > 0 then
         Result := Has_Output;
         return;
      end if;

      if not HC.CKE_Received_12 then
         --  Still processing server flight / sending client flight
         Process_Server_Flight (S, HC, Result);
      elsif not HC.CCS_Received then
         --  Waiting for server CCS
         Process_Server_CCS (S, HC, Result);
      else
         --  Waiting for server Finished
         Process_Server_Finished (S, HC, Result);
      end if;
   end Advance_Handshake_12;

   ------------------------------------------------------------------
   --  Process_Connected_12: identical to Server.TLS12.Process_Connected_12
   ------------------------------------------------------------------

   procedure Process_Connected_12 (S : in out Session; Result : out Action)
   is
      use Records.TLS12;
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := (if Output_Pending (S) > 0 then Has_Output else Need_Input);
         return;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1),
         Available (S.Input), Rec);

      if Rec.Bad_Version then
         S.Last_Error := Protocol_Version;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      if not Rec.OK then
         Result := Need_Input; return;
      end if;

      --  The record length bound below is from Parse_Record_Header's Post
      --  (Record_Len <= Avail = Write_Pos - Read_Pos). Pin it here while
      --  the call's Avail argument is still in syntactic scope, so later
      --  asserts about FS + Frag_Len can chain.
      pragma Assert
        (Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos);

      if Rec.Content = Records.Content_Change_Cipher_Spec then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK; return;
      end if;

      if Rec.Content not in Records.Content_Application_Data
                          | Records.Content_Alert
      then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK; return;
      end if;

      declare
         Frag_Len : constant N32 := Rec.Fragment_Len;
         FS : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
      begin
         --  Reject records exceeding the TLS 1.2 max ciphertext size.
         --  A 16384-byte plaintext encrypts to exactly 16408 bytes
         --  (16384 + 8 explicit nonce + 16 tag), so the bound is
         --  strict-greater-than, not greater-or-equal — and matches
         --  Decrypt_Record_12's Pre (`Encrypted'Last <
         --  Max_Record_Plaintext + TLS12_Record_Overhead`).
         if Frag_Len > Max_Record_Plaintext + TLS12_Record_Overhead then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Record_Overflow, Result);
            return;
         end if;
         --  FS + Frag_Len = Read_Pos + Fragment_Pos + Fragment_Len
         --                = Read_Pos + Record_Len   (Post: Record_Len =
         --                                            Fragment_Pos + Fragment_Len)
         --                <= Read_Pos + Avail
         --                = Read_Pos + (Write_Pos - Read_Pos)
         --                = Write_Pos.
         pragma Assert (FS + Frag_Len <= S.Input.Write_Pos);
         declare
            Encrypted : Byte_Seq (0 .. Frag_Len - 1);
            Hdr : Byte_Seq (0 .. 4);
            Plaintext : Byte_Seq (0 .. Frag_Len - 1);
            PL : N32; DV : Boolean;
         begin
            for I in N32 range 0 .. Frag_Len - 1 loop
               Encrypted (I) := S.Input.Data (FS + I);
            end loop;
            for I in N32 range 0 .. 4 loop
               Hdr (I) := S.Input.Data (S.Input.Read_Pos + I);
            end loop;

            declare
               Min_Frag : constant N32 :=
                 (if S.Server_App.Suite = Suite_CHACHA20_POLY1305_SHA256
                  then GCM_Tag_Len + 1
                  else Explicit_Nonce_Len + GCM_Tag_Len + 1);
            begin
               if Frag_Len < Min_Frag then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Result := OK; return;
               end if;
            end;

            --  RFC 5246 §6.1: "If a TLS implementation would need to
            --  wrap a sequence number, it must renegotiate instead."
            --  AEAD nonce uniqueness in GCM depends on the sequence
            --  number never wrapping; reuse would catastrophically
            --  leak the AEAD key. We don't support renegotiation, so
            --  abort the connection. Decrypt_Record_12's Pre also
            --  requires Seq_Num < Unsigned_64'Last so increment is
            --  safe. 2^64 records is practically unreachable.
            if S.Server_Seq_12 = Unsigned_64'Last then
               Send_Alert_And_Error (S, Internal_Error, Result);
               return;
            end if;

            Decrypt_Record_12 (Encrypted, Hdr, S.Server_App,
                               S.Server_IV_12, S.Server_Seq_12,
                               Plaintext, PL, DV);
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

            if not DV then
               Send_Alert_And_Error (S, Bad_Record_MAC, Result);
               return;
            end if;

            case Rec.Content is
               when Records.Content_Application_Data =>
                  if PL > 0
                    and then S.App_Data_Len <= S.App_Data'Length - PL
                  then
                     S.App_Data
                       (S.App_Data_Len .. S.App_Data_Len + PL - 1) :=
                        Plaintext (0 .. PL - 1);
                     S.App_Data_Len := S.App_Data_Len + PL;
                     Result := Plaintext_Ready;
                  else
                     Result := OK;
                  end if;
               when Records.Content_Alert =>
                  --  RFC 5246 §7.2: alerts have (level, description).
                  --  - close_notify (desc=0): peer is closing — initiate
                  --    Closing. Required regardless of level by §7.2.1.
                  --  - level=warning (1): MAY ignore. We ignore so BoGo
                  --    SendWarningAlerts-Pass /
                  --    AlternateEmptyRecordsAndWarningAlerts complete.
                  --  - level=fatal (2): connection MUST close. We just
                  --    record the error and stop reading; sending an
                  --    alert back would loop on every fatal we receive.
                  if PL >= 2 and then Plaintext (1) = 0 then
                     --  close_notify
                     if S.State = Connected then
                        Set_State (S, Closing);
                     end if;
                     Result := Shutdown;
                  elsif PL >= 1 and then Plaintext (0) = 1 then
                     --  warning (non-close_notify) — count + cap.
                     --  RFC 8446 §6.1 / BoGo SendWarningAlerts-TooMany:
                     --  more than 4 in a connection → fatal
                     --  decode_error.
                     S.Warning_Alerts_Recvd :=
                        S.Warning_Alerts_Recvd + 1;
                     if S.Warning_Alerts_Recvd >= 5 then
                        S.Last_Error := Decode_Error;
                        Set_State (S, Error_State);
                        Result := Error_Alert;
                     else
                        Result := OK;
                     end if;
                  else
                     --  fatal alert from peer — record + close.
                     S.Last_Error := Unexpected_Message;
                     if S.State = Connected then
                        Set_State (S, Closing);
                     end if;
                     Result := Shutdown;
                  end if;
               when others =>
                  Result := OK;
            end case;
         end;
      end;
   end Process_Connected_12;

end SPARKTLS.Client.TLS12;
