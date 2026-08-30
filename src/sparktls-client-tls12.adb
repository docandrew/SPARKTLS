with SPARKTLS.HS_Pool;
with Ada.Unchecked_Deallocation;
with Interfaces;                    use Interfaces;
with SPARKNaCl;                     use SPARKNaCl;
with SPARKTLSCrypto.Hashing.SHA256; use SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Scalar;
with SPARKTLS.Records;              use SPARKTLS.Records;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Handshake.Server_Msgs;
with SPARKTLS_Reassembly;           use SPARKTLS_Reassembly;
with SPARKTLS.Key_Schedule_12;
with SPARKTLS.Cert_Verify;          use SPARKTLS.Cert_Verify;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.Point;
with SPARKTLSCrypto.P384.Field;
with SPARKTLSCrypto.P384.ECDSA;
use SPARKTLSCrypto;
with X509;
use type X509.Algorithm_ID;
use type X509.Certificate;

with SPARKTLS.RFLX_Bridge; use SPARKTLS.RFLX_Bridge;
with RFLX.RFLX_Builtin_Types;
with RFLX.TLS_Handshake.TLS_1_2_Certificate;
with RFLX.TLS_Handshake.TLS_1_2_Certificate_Entries;
with RFLX.TLS_Handshake.TLS_1_2_Certificate_Entry;

with SPARKTLS_Transcript;
use type SPARKTLS_Transcript.Transcript_State;
with SPARKTLS.Handshake.Certs;

package body SPARKTLS.Client.TLS12
  with SPARK_Mode => On
is

   pragma Unevaluated_Use_Of_Old (Allow);
   use Handshake.TLS12;
   package RBT renames RFLX.RFLX_Builtin_Types;
   use type RBT.Index;
   use type RBT.Length;

   procedure Send_Alert_And_Error (S : in out Session; Err : Error_Code; Result : out Action)
   with
     Pre  => Alert_Desc (Err) /= 0 and then Alert_Desc (Err) /= 90,
     Post =>
       S.State = Error_State
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

   procedure Send_Encrypted_Alert_Connected_12
     (S : in out Session; Err : Error_Code; Result : out Action)
   with Pre => Alert_Desc (Err) /= 0 and Alert_Desc (Err) /= 90
   is
      Dummy : N32;
   begin
      Set_State (S, Error_State);
      S.Last_Error := Err;
      Records.TLS12.Build_Alert_Record_12
        (Level       => 2,
         Desc        => Alert_Desc (Err),
         Keys        => S.Client_App,
         Implicit_IV => S.Client_IV_12,
         Output      => S.Output,
         Bytes_Out   => Dummy);
      Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
   end Send_Encrypted_Alert_Connected_12;

   procedure Append_Transcript (TS : in out SPARKTLS_Transcript.Transcript_State; Data : Byte_Seq)
   with
     Pre  => Data'Last < N32'Last - 256,
     Post =>
       (if SPARKTLS_Transcript.Started (TS)'Old or else Data'First <= Data'Last
        then SPARKTLS_Transcript.Started (TS))
   is
   begin
      SPARKTLS_Transcript.Append (TS, Data);
   end Append_Transcript;

   --  Derive TLS 1.2 keys (same as server, shared secret -> master -> expand)
   --  Derive AEAD keys from an already-set S.HC.Master_Secret_12. Used
   --  by RFC 5077 abbreviated client handshake: master_secret was
   --  cached from the previous full handshake and copied into HC by
   --  the SH-parse resume-detection branch; we just need to expand
   --  it into traffic keys + IVs for this connection's randoms.
   procedure Derive_Keys_Resumed_12 (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data)
   with
     Post =>
       S.State = S.State'Old
       and then S.Negotiated_Suite = S.Negotiated_Suite'Old
       and then
         (if SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local'Old)
          then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local))
       and then S.HC.TS = S.HC.TS'Old
   is
      use Key_Schedule_12;
      Use_384 : constant Boolean :=
        S.Negotiated_Suite
        in Suite_ECDHE_RSA_AES256_GCM_SHA384 | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
      Key_Len : constant N32 :=
        (if S.Negotiated_Suite
            in Suite_ECDHE_RSA_AES128_GCM_SHA256 | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
         then 16
         else 32);
      IV_Len  : constant N32 :=
        (if S.Negotiated_Suite
            in Suite_ECDHE_RSA_CHACHA20_SHA256 | Suite_ECDHE_ECDSA_CHACHA20_SHA256
         then 12
         else 4);
      CK      : Byte_Seq (0 .. Key_Len - 1);
      SK      : Byte_Seq (0 .. Key_Len - 1);
      CI      : Byte_Seq (0 .. 11) := (others => 0);
      SI      : Byte_Seq (0 .. 11) := (others => 0);
   begin
      Expand_Keys_12
        (CK,
         SK,
         CI,
         SI,
         S.HC.Master_Secret_12,
         S.HC.Server_Random,
         S.HC.Client_Random,
         Key_Len,
         IV_Len,
         Use_384);
      declare
         Int_Suite : constant Supported_Suite :=
           (case S.Negotiated_Suite is
              when Suite_ECDHE_RSA_AES128_GCM_SHA256 | Suite_ECDHE_ECDSA_AES128_GCM_SHA256 =>
                Suite_AES_128_GCM_SHA256,
              when Suite_ECDHE_RSA_AES256_GCM_SHA384 | Suite_ECDHE_ECDSA_AES256_GCM_SHA384 =>
                Suite_AES_256_GCM_SHA384,
              when others                                                                  =>
                Suite_CHACHA20_POLY1305_SHA256);
      begin
         S.Client_App :=
           (Key => (others => 0), IV => (others => 0), Counter => 0, Suite => Int_Suite);
         S.Client_App.Key (0 .. Key_Len - 1) := CK;
         S.Server_App :=
           (Key => (others => 0), IV => (others => 0), Counter => 0, Suite => Int_Suite);
         S.Server_App.Key (0 .. Key_Len - 1) := SK;
      end;
      S.HC.Client_Write_IV_12 := CI;
      S.HC.Server_Write_IV_12 := SI;
      S.Exporter_Secret := S.HC.Master_Secret_12;
      S.Exporter_Secret_Len := 48;
      S.Exporter_Client_Random := S.HC.Client_Random;
      S.Exporter_Server_Random := S.HC.Server_Random;
   end Derive_Keys_Resumed_12;

   procedure Derive_Keys_12 (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data)
   with
     Pre  => S.Negotiated_Suite in TLS12_Suite,
     Post =>
       S.State = S.State'Old
       and then S.Negotiated_Suite = S.Negotiated_Suite'Old
       and then S.HC.TS = S.HC.TS'Old
       and then S.Client_App.Counter = 0
       and then S.Server_App.Counter = 0
   is
      use Key_Schedule_12;
      Use_384    : constant Boolean :=
        S.Negotiated_Suite
        in Suite_ECDHE_RSA_AES256_GCM_SHA384 | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
      Key_Len    : constant N32 :=
        (if S.Negotiated_Suite
            in Suite_ECDHE_RSA_AES128_GCM_SHA256 | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
         then 16
         else 32);
      --  RFC 5288 3: AES-GCM IV salt is 4 bytes.
      --  RFC 7905 2: ChaCha20-Poly1305 IV is 12 bytes.
      IV_Len     : constant N32 :=
        (if S.Negotiated_Suite
            in Suite_ECDHE_RSA_CHACHA20_SHA256 | Suite_ECDHE_ECDSA_CHACHA20_SHA256
         then 12
         else 4);
      CK         : Byte_Seq (0 .. Key_Len - 1);
      SK         : Byte_Seq (0 .. Key_Len - 1);
      CI         : Byte_Seq (0 .. 11) := (others => 0);
      SI         : Byte_Seq (0 .. 11) := (others => 0);
      Shared_Len : constant N32 := (if S.HC.KE.Curve = Group_Secp384r1 then 48 else 32);
   begin
      --  Master secret derivation
      --  Verify EMS label consistency at compile/prove time
      pragma Assert (EMS_Label_Consistent (True, "extended master secret"));
      pragma Assert (EMS_Label_Consistent (False, "master secret"));

      if S.HC.Use_EMS then
         --  RFC 7627: Extended Master Secret
         --  master_secret = PRF(pms, "extended master secret", Hash(hs_msgs))
         declare
            --  RFC 7627 session_hash: the transcript digest AT the CKE
            --  point. Under the streaming transcript it was DRAWN there
            --  (EMS_Session_Hash); if this path runs before a snapshot
            --  exists, the current digest IS the session hash.
            TH     : Digest;
            TH_384 : SPARKNaCl.Hashing.SHA384.Digest;
         begin
            if Use_384 then
               if S.HC.EMS_Hash_Taken then
                  TH_384 := SPARKNaCl.Hashing.SHA384.Digest (S.HC.EMS_Session_Hash);
               else
                  SPARKTLS_Transcript.Current_384 (S.HC.TS, TH_384);
               end if;
               PRF_SHA384
                 (Byte_Seq (S.HC.Master_Secret_12),
                  S.HC.KE.Shared (0 .. Shared_Len - 1),
                  "extended master secret",
                  Byte_Seq (TH_384));
            else
               if S.HC.EMS_Hash_Taken then
                  TH := Digest (S.HC.EMS_Session_Hash (0 .. 31));
               else
                  SPARKTLS_Transcript.Current_256 (S.HC.TS, TH);
               end if;
               PRF_SHA256
                 (Byte_Seq (S.HC.Master_Secret_12),
                  S.HC.KE.Shared (0 .. Shared_Len - 1),
                  "extended master secret",
                  Byte_Seq (TH));
            end if;
         end;
         S.HC.MS_Derivation := Extended;
      else
         --  RFC 5246 8.1: Standard master secret
         --  master_secret = PRF(pms, "master secret", CR || SR)
         Key_Schedule_12.Derive_Master_Secret_12
           (S.HC.Master_Secret_12,
            S.HC.KE.Shared (0 .. Shared_Len - 1),
            S.HC.Client_Random,
            S.HC.Server_Random,
            Use_384);
         S.HC.MS_Derivation := Legacy;
      end if;

      Expand_Keys_12
        (CK,
         SK,
         CI,
         SI,
         S.HC.Master_Secret_12,
         S.HC.Server_Random,
         S.HC.Client_Random,
         Key_Len,
         IV_Len,
         Use_384);

      declare
         Int_Suite : constant Supported_Suite :=
           (case S.Negotiated_Suite is
              when Suite_ECDHE_RSA_AES128_GCM_SHA256 | Suite_ECDHE_ECDSA_AES128_GCM_SHA256 =>
                Suite_AES_128_GCM_SHA256,
              when Suite_ECDHE_RSA_AES256_GCM_SHA384 | Suite_ECDHE_ECDSA_AES256_GCM_SHA384 =>
                Suite_AES_256_GCM_SHA384,
              when others                                                                  =>
                Suite_CHACHA20_POLY1305_SHA256);
         pragma Assert (Int_Suite = Handshake.TLS12.Internal_Suite_For (S.Negotiated_Suite));
      begin
         S.Client_App :=
           (Key => (others => 0), IV => (others => 0), Counter => 0, Suite => Int_Suite);
         S.Client_App.Key (0 .. Key_Len - 1) := CK;
         S.Server_App :=
           (Key => (others => 0), IV => (others => 0), Counter => 0, Suite => Int_Suite);
         S.Server_App.Key (0 .. Key_Len - 1) := SK;
      end;

      S.HC.Client_Write_IV_12 := CI;
      S.HC.Server_Write_IV_12 := SI;
      S.Exporter_Secret := S.HC.Master_Secret_12;
      S.Exporter_Secret_Len := 48;
      S.Exporter_Client_Random := S.HC.Client_Random;
      S.Exporter_Server_Random := S.HC.Server_Random;
   end Derive_Keys_12;

   ------------------------------------------------------------------
   --  Process_Server_Flight: parse Cert + SKE + SHD, then send CKE+CCS+Fin
   ------------------------------------------------------------------

   procedure Process_Server_Flight
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   with
     Pre =>
       Warning_Alerts_Bounded_RFC_8446_6_1 (S)
       and then
         (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
          then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local))
       and then
         (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
          then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local));

   procedure Append_Intermediate_12
     (D : in out SPARKTLS.HS_Pool.HS_Data; Idx : in Natural; PE : in Pool_Entry)
   with
     Pre  => Idx = D.Peer_Int_Count and then D.Peer_Int_Count < Max_Pool_Size and then PE.Present,
     Post => D.Peer_Int_Count = D.Peer_Int_Count'Old + 1 and then D.Peer_Leaf = D.Peer_Leaf'Old;

   procedure Append_Intermediate_12
     (D : in out SPARKTLS.HS_Pool.HS_Data; Idx : in Natural; PE : in Pool_Entry) is
   begin
      D.Peer_Ints (Idx) := PE;
      D.Peer_Int_Count := D.Peer_Int_Count + 1;
   end Append_Intermediate_12;

   procedure Reset_Peer_Cert_Chain_12 (D : in out SPARKTLS.HS_Pool.HS_Data)
   with Post => not D.Peer_Leaf.Present and then D.Peer_Int_Count = 0;

   procedure Reset_Peer_Cert_Chain_12 (D : in out SPARKTLS.HS_Pool.HS_Data) is
   begin
      D.Peer_Leaf.Present := False;
      D.Peer_Int_Count := 0;
   end Reset_Peer_Cert_Chain_12;

   procedure Set_Peer_Cert_12
     (D     : in out SPARKTLS.HS_Pool.HS_Data;
      Cert  : in X509.Certificate;
      C_Len : in N32;
      OK    : in Boolean)
   with
     Pre  =>
       C_Len in 1 .. Max_Cert_DER_Len
       and then D.Peer_Leaf.DER_Len = X509.N32 (C_Len)
       and then (if OK then X509.Spans_Valid (Cert, X509.N32 (C_Len) - 1)),
     Post => Used (D.Reasm) = Used (D.Reasm)'Old and then D.Peer_Leaf.Present = OK;

   procedure Set_Peer_Cert_12
     (D     : in out SPARKTLS.HS_Pool.HS_Data;
      Cert  : in X509.Certificate;
      C_Len : in N32;
      OK    : in Boolean) is
   begin
      if OK then
         D.Peer_Leaf.Present := False;  --  ordering discipline: clear first
         D.Peer_Leaf.Cert := Cert;
         D.Peer_Leaf.Present := True;
      else
         D.Peer_Leaf.Present := False;
      end if;
   end Set_Peer_Cert_12;

   --  RFC 5246 7.4.2 Certificate (HS type 0x0B). Parses the on-wire
   --  cert_list_len(3) || {cert_len(3) || cert_data[cert_len]}* via
   --  RFLX TLS_1_2_Certificate, then runs the leaf through X509.Parse.
   --  Intermediates beyond Max_Pool_Size are silently dropped  chain
   --  validation will fail if the omitted entries were needed.
   --
   --  Mirrors Parse_Certificate_Chain_13 (TLS 1.3), but operates on
   --  the TLS 1.2 RFLX package which lacks per-cert extensions.
   procedure Parse_Cert_Chain_12
     (HC      : in out Engaged_Context;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Frag    : in Byte_Seq;
      Msg_Len : in N32;
      OK      : out Boolean)
   with
     Pre =>
       Msg_Len in 3 .. Max_HS_Msg - 4
       --  256: transcript-append bound (see Handle_CertReq_12).
       and then Frag'Last < N32'Last - 256
       and then Frag'First <= N32'Last - 4
       --  LOOKS redundant -- it IS implied by the next conjunct together
       --  with Frag'Last < N32'Last - 4 -- but DO NOT REMOVE. With
       --  `and then`, THIS conjunct is what makes EVALUATING the next
       --  one (Frag'First + 3 + Msg_Len) overflow-safe. Implication is
       --  not redundancy when evaluation order matters.
       --  Removing all 6 occurrences was measured on 2026-08-20:
       --  exactly neutral, 56 -> 56 owned findings, trading two
       --  "N32'Last - Frag'First" overflow checks for two
       --  "Frag'First + 3 + Msg_Len" ones. No gain, one fact lost.
       and then Frag'First >= 0
       and then Msg_Len <= N32'Last - Frag'First - 4
       and then Frag'First + 3 + Msg_Len <= Frag'Last;

   procedure Parse_Cert_Chain_12
     (HC      : in out Engaged_Context;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Frag    : in Byte_Seq;
      Msg_Len : in N32;
      OK      : out Boolean)
   is
      package C12 renames RFLX.TLS_Handshake.TLS_1_2_Certificate;
      package C12_Entries renames RFLX.TLS_Handshake.TLS_1_2_Certificate_Entries;
      package C12_Entry renames RFLX.TLS_Handshake.TLS_1_2_Certificate_Entry;
      procedure RFLX_Free_Local is new
        Ada.Unchecked_Deallocation (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
      Buf                  : RBT.Bytes_Ptr;
      Ctx                  : C12.Context;
      B                    : constant N32 := Frag'First + 4;
      Body_Bytes           : Byte_Seq (0 .. Msg_Len - 1);
      Cert_Idx             : Natural := 0;
      Saved_Selected_Group : constant ECDHE_Group := HC.KE.Curve
      with Ghost;
   begin
      Reset_Peer_Cert_Chain_12 (D);
      OK := False;

      if Msg_Len < 3 then
         return;
      end if;

      declare
         List_Len : constant N32 :=
           N32 (Frag (B)) * 65536 + N32 (Frag (B + 1)) * 256 + N32 (Frag (B + 2));
      begin
         if List_Len /= Msg_Len - 3 then
            return;
         end if;
      end;

      Body_Bytes := Frag (B .. B + Msg_Len - 1);

      Buf := new RBT.Bytes'(1 .. RBT.Index (Msg_Len) => 0);
      Buf.all := To_RFLX (Body_Bytes);
      C12.Initialize (Ctx, Buf, Written_Last => RBT.Bit_Length (Msg_Len * 8));
      C12.Verify_Message (Ctx);

      if not C12.Well_Formed_Message (Ctx) then
         C12.Take_Buffer (Ctx, Buf);
         RFLX_Free_Local (Buf);
         return;
      end if;

      declare
         use type RBT.Bit_Length;
         use type RBT.Index;
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
               if not (C12.Valid_Next (Ctx, C12.F_Certificate_List)
                       and then C12.Field_First (Ctx, C12.F_Certificate_List) rem RBT.Byte'Size = 1
                       and then
                         C12.Available_Space (Ctx, C12.F_Certificate_List)
                         >= C12.Field_Size (Ctx, C12.F_Certificate_List)
                       and then C12.Field_Condition (Ctx, C12.F_Certificate_List))
               then
                  C12.Take_Buffer (Ctx, Buf);
                  RFLX_Free_Local (Buf);
                  return;
               end if;
               C12.Switch_To_Certificate_List (Ctx, Entries_Ctx);
               while C12_Entries.Has_Element (Entries_Ctx) and then Cert_Idx <= Max_Pool_Size loop
                  pragma Loop_Invariant (not C12.Has_Buffer (Ctx));
                  pragma Loop_Invariant (C12_Entries.Has_Buffer (Entries_Ctx));
                  pragma Loop_Invariant (C12_Entries.Valid (Entries_Ctx));
                  pragma
                    Loop_Invariant
                      (if D.Peer_Leaf.Present
                       then X509.Spans_Valid (D.Peer_Leaf.Cert, D.Peer_Leaf.DER_Len - 1));
                  pragma Loop_Invariant (if D.Peer_Leaf.Present then Cert_Idx > 0);
                  pragma Loop_Invariant (HC.KE.Curve = Saved_Selected_Group);
                  declare
                     E_Ctx : C12_Entry.Context;
                  begin
                     C12_Entries.Switch (Entries_Ctx, E_Ctx);
                     C12_Entry.Verify_Message (E_Ctx);
                     if C12_Entry.Well_Formed_Message (E_Ctx) then
                        declare
                           C_Len     : constant N32 :=
                             N32 (C12_Entry.Get_Cert_Data_Length (E_Ctx));
                           Cert_RFLX : RBT.Bytes (1 .. RBT.Index (C_Len));
                        begin
                           if C_Len > 0 and C_Len <= N32 (Max_Cert_DER) then
                              C12_Entry.Get_Cert_Data (E_Ctx, Cert_RFLX);
                              if Cert_Idx = 0 then
                                 SPARKTLS.Handshake.Certs.Copy_Cert_To_Peer_DER
                                   (Cert_RFLX, D, C_Len);
                                 declare
                                    C    : X509.Certificate;
                                    P_OK : Boolean;
                                 begin
                                    SPARKTLS.Handshake.Certs.Parse_X509_From_RFLX
                                      (Cert_RFLX, C_Len, C, P_OK);
                                    if P_OK then
                                       pragma Assert (X509.Spans_Valid (C, X509.N32 (C_Len) - 1));
                                       pragma Assert (D.Peer_Leaf.DER_Len = X509.N32 (C_Len));
                                       pragma
                                         Assert
                                           (X509.Spans_Valid
                                              (C, X509.N32 (D.Peer_Leaf.DER_Len) - 1));
                                       Set_Peer_Cert_12 (D, C, C_Len, P_OK);
                                       pragma
                                         Assert
                                           (if D.Peer_Leaf.Present
                                            then
                                              X509.Spans_Valid
                                                (D.Peer_Leaf.Cert,
                                                 X509.N32 (D.Peer_Leaf.DER_Len) - 1));
                                    else
                                       Set_Peer_Cert_12 (D, C, C_Len, P_OK);
                                    end if;
                                 end;
                              elsif D.Peer_Int_Count < Max_Pool_Size then
                                 declare
                                    Idx  : constant Natural := D.Peer_Int_Count;
                                    C    : X509.Certificate;
                                    Tmp  : Pool_Entry;
                                    P_OK : Boolean;
                                 begin
                                    SPARKTLS.Handshake.Certs.Parse_X509_From_RFLX
                                      (Cert_RFLX, C_Len, C, P_OK);
                                    if P_OK then
                                       SPARKTLS.Handshake.Certs.Store_Intermediate
                                         (Cert_RFLX, C, C_Len, Tmp);
                                       Append_Intermediate_12 (D, Idx, Tmp);
                                    end if;
                                 end;
                              end if;
                              Cert_Idx := Cert_Idx + 1;
                           end if;
                        end;
                     end if;
                     pragma
                       Assert
                         (if D.Peer_Leaf.Present
                          then X509.Spans_Valid (D.Peer_Leaf.Cert, D.Peer_Leaf.DER_Len - 1));
                     C12_Entries.Update (Entries_Ctx, E_Ctx);
                     pragma
                       Assert
                         (if D.Peer_Leaf.Present
                          then X509.Spans_Valid (D.Peer_Leaf.Cert, D.Peer_Leaf.DER_Len - 1));
                  end;
               end loop;
               C12_Entries.Take_Buffer (Entries_Ctx, Buf);
               RFLX_Free_Local (Buf);
               OK := True;
               return;
            end;
         end if;
      end;

      C12.Take_Buffer (Ctx, Buf);
      RFLX_Free_Local (Buf);
      pragma Assert (HC.KE.Curve = Saved_Selected_Group);
      OK := True;
   end Parse_Cert_Chain_12;

   --  RFC 5246 7.4.2 leaf-cert validation (TLS 1.2): keyUsage,
   --  cipher-suite â cert-algorithm match, hostname binding, chain
   --  validation. Each gate emits its own alert and returns; on full
   --  success Result is left untouched by the caller.
   procedure Validate_Server_Cert_12
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   with
     Pre  => S.Negotiated_Suite in TLS12_Suite,
     Post => (if Result = OK then S.Negotiated_Suite = S.Negotiated_Suite'Old);

   procedure Validate_Server_Cert_12
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action) is
   begin
      Result := OK;
      if not D.Peer_Leaf.Present then
         Send_Alert_And_Error (S, Decode_Error, Result);
         return;
      end if;
      if X509.Has_Key_Usage (D.Peer_Leaf.Cert)
        and then not X509.KU_Digital_Signature (D.Peer_Leaf.Cert)
      then
         Send_Alert_And_Error (S, Bad_Certificate, Result);
         return;
      end if;
      declare
         PK                : constant X509.Algorithm_ID := X509.PK_Algorithm (D.Peer_Leaf.Cert);
         Suite_Needs_ECDSA : constant Boolean :=
           S.Negotiated_Suite
           in Suite_ECDHE_ECDSA_AES128_GCM_SHA256
            | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
            | Suite_ECDHE_ECDSA_CHACHA20_SHA256;
         Suite_Needs_RSA   : constant Boolean :=
           S.Negotiated_Suite
           in Suite_ECDHE_RSA_AES128_GCM_SHA256
            | Suite_ECDHE_RSA_AES256_GCM_SHA384
            | Suite_ECDHE_RSA_CHACHA20_SHA256;
         Cert_Is_ECDSA     : constant Boolean := PK = X509.Algo_EC_P256 or PK = X509.Algo_EC_P384;
         Cert_Is_RSA       : constant Boolean := PK = X509.Algo_RSA;
         Cert_Is_Ed25519   : constant Boolean := PK in X509.Algo_Ed25519 | X509.Algo_EC_Ed25519;
      begin
         if Suite_Needs_ECDSA and then not (Cert_Is_ECDSA or Cert_Is_Ed25519) then
            Send_Alert_And_Error (S, Bad_Certificate, Result);
            return;
         end if;
         if Suite_Needs_RSA and then not Cert_Is_RSA then
            Send_Alert_And_Error (S, Bad_Certificate, Result);
            return;
         end if;

         --  RFC 8422 5.1.1: in TLS 1.2 the supported_groups extension
         --  also constrains the EC parameters accepted in an ECDSA server
         --  certificate. The default client advertises every supported
         --  group; a configured single-group offer must not accept a leaf
         --  on a different NIST curve.
         if Suite_Needs_ECDSA
           and then not ECDSA_Cert_Curve_Allowed_TLS12 (S.HC.Cfg.Client_Key_Share_Group, PK)
         then
            Send_Alert_And_Error (S, Bad_Certificate, Result);
            return;
         end if;
      end;

      if S.HC.Cfg.Server_Name.Len > 0
        and then not S.HC.Cfg.Skip_Hostname_Verify
        and then D.Peer_Leaf.Present
      then
         declare
            PCDL   : constant N32 := N32 (D.Peer_Leaf.DER_Len);
            Cert_X : X509.Byte_Seq (0 .. X509.N32 (PCDL) - 1) := (others => 0);
         begin
            for I in N32 range 0 .. PCDL - 1 loop
               Cert_X (X509.N32 (I)) := D.Peer_Leaf.DER (X509.N32 (I));
            end loop;
            if not X509.Matches_Hostname
                     (D.Peer_Leaf.Cert,
                      Cert_X,
                      S.HC.Cfg.Server_Name.Data (1 .. S.HC.Cfg.Server_Name.Len))
            then
               Send_Alert_And_Error (S, Bad_Certificate, Result);
               return;
            end if;
         end;
      end if;

      if not S.HC.Cfg.Skip_Verify and then D.Peer_Leaf.Present then
         if S.HC.Cfg.Trust = null or else S.HC.Cfg.Get_Time = null then
            Send_Alert_And_Error (S, Bad_Certificate, Result);
            return;
         end if;
         declare
            PCDL   : constant N32 := N32 (D.Peer_Leaf.DER_Len);
            Cert_X : X509.Byte_Seq (0 .. X509.N32 (PCDL) - 1) := (others => 0);
            VR     : Validation_Result;
         begin
            for I in N32 range 0 .. PCDL - 1 loop
               Cert_X (X509.N32 (I)) := D.Peer_Leaf.DER (X509.N32 (I));
            end loop;
            VR :=
              Validate_Chain
                (Leaf_DER   => Cert_X,
                 Leaf       => D.Peer_Leaf.Cert,
                 Ints       => D.Peer_Ints,
                 Int_Count  => D.Peer_Int_Count,
                 Roots      => S.HC.Cfg.Trust.Roots,
                 Root_Count => S.HC.Cfg.Trust.Root_Count,
                 Now        => S.HC.Cfg.Get_Time.all,
                 Hostname   => S.HC.Cfg.Server_Name.Data (1 .. S.HC.Cfg.Server_Name.Len),
                 Purpose    => S.HC.Cfg.Verify_Purpose,
                 Mode       => S.HC.Cfg.Verify_Mode);
            if VR /= Valid then
               Reset (D.Reasm);
               Send_Alert_And_Error (S, Bad_Certificate, Result);
               return;
            end if;
         end;
      end if;
   end Validate_Server_Cert_12;

   --  RFC 5246 7.4.4 CertificateRequest (HS type 0x0D). Parses the
   --  three length-prefixed lists (cert_types, sig_algs, ca_dns), picks
   --  a sig_algs entry compatible with our local identity if mTLS is
   --  configured, and falls back to a canonical default per algorithm
   --  when the server's offer is unusable.
   procedure Handle_CertReq_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Frag    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action)
   with
     Pre  =>
       Msg_Len <= Max_HS_Msg - 4
       and then
         Frag'First
         <= Frag'Last
            --  256, not 4: the transcript-append bound. Callers pass
            --  Message() slices ('Last <= Max_HS_Msg - 1), so this is
            --  free to prove there and feeds Append_Transcript here.
       and then Frag'Last < N32'Last - 256
       and then Frag'First <= N32'Last - 4
       and then Msg_Len <= N32'Last - Frag'First - 4
       and then Msg_Len <= N32 (Frag'Length) - 4
       and then Frag'First + 3 + Msg_Len <= Frag'Last
       and then Frag'Last - Frag'First < Transcript_Capacity
       and then S.Negotiated_Suite in TLS12_Suite
       and then
         (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
          then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)),
     Post =>
       (if Result = OK
        then
          (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
           then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)));

   procedure Handle_CertReq_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Frag    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action)
   is
      Body_OK                 : Boolean := False;
      B                       : constant N32 := Frag'First + 4;
      Transcript_Was_Nonempty : constant Boolean := SPARKTLS_Transcript.Started (S.HC.TS)
      with Ghost;
   begin
      Result := OK;
      --  Body-length structural validation.
      if B < Frag'Last then
         declare
            CT_Len_D : constant N32 := N32 (Frag (B));
         begin
            if CT_Len_D <= Frag'Last - B - 1 then
               declare
                  SA_Off_D : constant N32 := B + 1 + CT_Len_D;
               begin
                  if SA_Off_D < Frag'Last then
                     declare
                        SA_Len_D : constant N32 :=
                          N32 (Frag (SA_Off_D)) * 256 + N32 (Frag (SA_Off_D + 1));
                     begin
                        if SA_Len_D <= Frag'Last - SA_Off_D - 2 then
                           declare
                              CA_Off_D : constant N32 := SA_Off_D + 2 + SA_Len_D;
                           begin
                              if CA_Off_D < Frag'Last then
                                 declare
                                    CA_Len_D : constant N32 :=
                                      N32 (Frag (CA_Off_D)) * 256 + N32 (Frag (CA_Off_D + 1));
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
               end;
            end if;
         end;
      end if;
      if not Body_OK then
         Reset (D.Reasm);
         Send_Alert_And_Error (S, Decode_Error, Result);
         pragma Assert (Result /= OK);
         pragma Assert_And_Cut (Result /= OK and then S.State = Error_State);
         return;
      end if;
      S.HC.Cert_Request_Received := True;
      S.HC.T12.Client_Cert_Allowed := False;

      --  Sig-algs selection. Empty sig_algs list is malformed per
      --  RFC 5246 7.4.1.4.1.
      declare
         Picked   : Maybe_Sig_Scheme := Scheme_None;
         SA_Empty : Boolean := True;
         CT_OK    : Boolean := False;
      begin
         if B < Frag'Last then
            declare
               CT_Len : constant N32 := N32 (Frag (B));
            begin
               if CT_Len <= Frag'Last - B - 1 then
                  if S.HC.Cfg.Local /= null
                    and then S.HC.Cfg.Local.Has_Identity
                    and then CT_Len > 0
                  then
                     declare
                        Required_CT : constant Byte :=
                          (case S.HC.Cfg.Local.Sign_Algo is
                             when Sign_RSA_PSS                                     =>
                               1,   --  rsa_sign
                             when Sign_ECDSA_P256 | Sign_ECDSA_P384 | Sign_Ed25519 =>
                               64,  --  ecdsa_sign
                             when Sign_None                                        => 0);
                     begin
                        pragma Assert (B + CT_Len < Frag'Last);
                        CT_OK :=
                          Required_CT /= 0
                          and then (for some I in B + 1 .. B + CT_Len => Frag (I) = Required_CT);
                     end;
                  end if;
                  declare
                     SA_Off : constant N32 := B + 1 + CT_Len;
                  begin
                     if SA_Off < Frag'Last then
                        declare
                           SA_Len : constant N32 :=
                             N32 (Frag (SA_Off)) * 256 + N32 (Frag (SA_Off + 1));
                        begin
                           if SA_Len >= 2 and then SA_Len <= Frag'Last - SA_Off - 1 then
                              SA_Empty := False;
                              if S.HC.Cfg.Local /= null then
                                 declare
                                    SA_Slice : constant Byte_Seq (0 .. SA_Len - 1) :=
                                      Frag (SA_Off + 2 .. SA_Off + 1 + SA_Len);
                                 begin
                                    Picked :=
                                      Handshake.Pick_Sig_Algo_With_Prefs
                                        (SA_Slice,
                                         S.HC.Cfg.Local.Sign_Algo,
                                         S.HC.Cfg.Sign_Sig_Algos,
                                         S.HC.Cfg.Sign_Sig_Algo_Count,
                                         Allow_PKCS1_v1_5 => True);
                                 end;
                              end if;
                           end if;
                        end;
                     end if;
                  end;
               end if;
            end;
         end if;
         if SA_Empty then
            Reset (D.Reasm);
            Send_Alert_And_Error (S, Decode_Error, Result);
            pragma Assert (Result /= OK);
            pragma Assert_And_Cut (Result /= OK and then S.State = Error_State);
            return;
         end if;
         if S.HC.Cfg.Local /= null then
            if Picked /= Scheme_None then
               S.HC.Negotiated_Sig_Algo := Picked;
               S.HC.T12.Client_Cert_Allowed := CT_OK;
            else
               case S.HC.Cfg.Local.Sign_Algo is
                  when Sign_RSA_PSS    =>
                     S.HC.Negotiated_Sig_Algo := Sig_RSA_PSS_SHA256;

                  when Sign_ECDSA_P256 =>
                     S.HC.Negotiated_Sig_Algo := Sig_ECDSA_P256_SHA256;

                  when Sign_ECDSA_P384 =>
                     S.HC.Negotiated_Sig_Algo := Sig_ECDSA_P384_SHA384;

                  when Sign_Ed25519    =>
                     --  PureEdDSA cannot sign the streamed 1.2
                     --  transcript (two-pass over raw bytes); Ed25519
                     --  client auth is TLS 1.3-only. Decline auth --
                     --  the empty Certificate path is interoperable.
                     null;

                  when Sign_None       =>
                     null;
               end case;
            end if;
         end if;
         if S.HC.Cfg.Local /= null
           and then S.HC.Cfg.Local.Has_Identity
           and then not S.HC.T12.Client_Cert_Allowed
         then
            Reset (D.Reasm);
            Send_Alert_And_Error (S, Illegal_Parameter, Result);
            pragma Assert (Result /= OK);
            pragma Assert_And_Cut (Result /= OK and then S.State = Error_State);
            return;
         end if;
      end;
      Append_Transcript (S.HC.TS, Frag);
      pragma
        Assert_And_Cut
          ((if Transcript_Was_Nonempty then SPARKTLS_Transcript.Started (S.HC.TS))
           and then S.Negotiated_Suite in TLS12_Suite
           and then
             (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
              then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)));
   end Handle_CertReq_12;

   --  RFC 5246 7.4.3 ServerKeyExchange (HS type 0x0C). Length-validates
   --  the body shape first (curve_type/curve/pt_len/pt + sig_hash/alg/
   --  len/sig must sum to Msg_Len), then dispatches to
   --  Parse_Server_Key_Exchange which extracts ECDHE params + verifies
   --  the signature.
   procedure Handle_SKE_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Frag    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action)
   with
     Pre  =>
       Msg_Len <= Max_HS_Msg - 4
       and then
         Frag'First
         <= Frag'Last
            --  256, not 4: the transcript-append bound. Callers pass
            --  Message() slices ('Last <= Max_HS_Msg - 1), so this is
            --  free to prove there and feeds Append_Transcript here.
       and then Frag'Last < N32'Last - 256
       and then Frag'First <= N32'Last - 4
       and then Msg_Len <= N32'Last - Frag'First - 4
       and then Msg_Len <= N32 (Frag'Length) - 4
       and then Frag'First + 3 + Msg_Len <= Frag'Last
       and then Frag'Last - Frag'First < Transcript_Capacity
       and then S.Negotiated_Suite in TLS12_Suite
       and then
         (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
          then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)),
     Post =>
       (if Result = OK then S.State = S.State'Old and then S.Negotiated_Suite in TLS12_Suite);

   procedure Handle_SKE_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Frag    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action)
   is
      Body_Start : constant N32 := Frag'First + 4;
   begin
      Result := OK;
      if Msg_Len = 0 then
         Reset (D.Reasm);
         Send_Alert_And_Error (S, Decode_Error, Result);
         return;
      end if;

      declare
         Length_OK : Boolean := False;
      begin
         if Msg_Len >= 8 then
            declare
               Pt_Len : constant N32 := N32 (Frag (Body_Start + 3));
            begin
               if Pt_Len <= Msg_Len - 8 then
                  declare
                     Sig_Pos : constant N32 := Body_Start + 4 + Pt_Len + 2;
                  begin
                     if Sig_Pos < Frag'First + 4 + Msg_Len - 1 then
                        declare
                           Sig_Len : constant N32 :=
                             N32 (Frag (Sig_Pos)) * 256 + N32 (Frag (Sig_Pos + 1));
                        begin
                           Length_OK := Msg_Len = 8 + Pt_Len + Sig_Len;
                        end;
                     end if;
                  end;
               end if;
            end;
         end if;
         if not Length_OK or else Msg_Len < 10 or else Msg_Len > N32 (Max_Server_Key_Exchange) then
            Reset (D.Reasm);
            Send_Alert_And_Error (S, Decode_Error, Result);
            return;
         end if;
      end;

      declare
         Body_Data : Byte_Seq (0 .. Msg_Len - 1);
         SKE_OK    : Boolean;
      begin
         Body_Data := Frag (Body_Start .. Body_Start + Msg_Len - 1);
         Parse_Server_Key_Exchange (S.HC, D, Body_Data, SKE_OK);
         if not SKE_OK then
            Reset (D.Reasm);
            if S.HC.Ext_Parse_Err /= No_Error then
               Send_Alert_And_Error (S, S.HC.Ext_Parse_Err, Result);
            else
               Send_Alert_And_Error (S, Handshake_Failure, Result);
            end if;
            return;
         end if;

         if not Selected_Group_Allowed_TLS12 (S.HC.Cfg.Client_Key_Share_Group, S.HC.KE.Curve) then
            Reset (D.Reasm);
            Send_Alert_And_Error (S, Illegal_Parameter, Result);
            return;
         end if;
      end;
      Append_Transcript (S.HC.TS, Frag);
   end Handle_SKE_12;

   procedure Derive_Client_Shared_Secret_12
     (HC : in out Engaged_Context; OK : out Boolean; Err : out Error_Code)
   with
     Pre  => HC.Cfg.Random /= null,
     Post =>
       HC.TS = HC.TS'Old
       and then HC.Cert_Request_Received = HC.Cert_Request_Received'Old
       and then HC.T12.Client_Cert_Allowed = HC.T12.Client_Cert_Allowed'Old
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then
         (if SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (HC.Cfg.Local'Old)
          then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (HC.Cfg.Local))
       and then Err in No_Error | Illegal_Parameter | Handshake_Failure
       and then (if OK then Err = No_Error);

   procedure Derive_Client_Shared_Secret_12
     (HC : in out Engaged_Context; OK : out Boolean; Err : out Error_Code)
   is
      Gen : constant Random_Bytes_Fn := HC.Cfg.Random;
   begin
      OK := False;
      Err := Handshake_Failure;
      pragma Assert (Gen /= null);

      case HC.KE.Curve is
         when Group_X25519    =>
            Gen (Byte_Seq (HC.KE.Local_SK));
            HC.KE.Shared (0 .. 31) := SPARKNaCl.Scalar.Mult (HC.KE.Local_SK, HC.KE.Peer_PK);
            OK := Shared_Secret_Is_Acceptable_X25519 (HC.KE.Shared (0 .. 31));
            if OK then
               Err := No_Error;
            else
               Err := Illegal_Parameter;
            end if;

         when Group_Secp256r1 =>
            Gen (Byte_Seq (HC.KE.P256_SK));
            declare
               use SPARKTLSCrypto.P256.Point;
               Pt : P256_Jacobian;
               V  : SPARKNaCl.U32;
            begin
               P256_Decode (Pt, HC.KE.P256_PK, V);
               if V /= 0 then
                  P256_Mul (Pt, HC.KE.P256_SK, 32);
                  P256_To_Affine (Pt);
                  declare
                     E : Byte_Seq (0 .. 64);
                  begin
                     P256_Encode (E, Pt);
                     HC.KE.Shared := (others => 0);
                     HC.KE.Shared (0 .. 31) := E (1 .. 32);
                  end;
                  OK := True;
                  Err := No_Error;
               else
                  Err := Illegal_Parameter;
               end if;
            end;

         when Group_Secp384r1 =>
            Gen (Byte_Seq (HC.KE.P384_SK));
            declare
               SS    : Bytes_48;
               OK384 : Boolean;
            begin
               SPARKTLSCrypto.P384.Point.P384_ECDHE (SS, OK384, HC.KE.P384_SK, HC.KE.P384_PK);
               if OK384 then
                  HC.KE.Shared := SS;
                  OK := True;
                  Err := No_Error;
               else
                  Err := Illegal_Parameter;
               end if;
            end;

         when others          =>
            null;
      end case;
   end Derive_Client_Shared_Secret_12;

   procedure Append_Client_Certificate_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      Result  : out Action)
   with
     Pre  =>
       S.Negotiated_Suite in TLS12_Suite
       and then
         (if S.HC.Cert_Request_Received
            and then S.HC.Cfg.Local /= null
            and then S.HC.Cfg.Local.Has_Identity
            and then S.HC.T12.Client_Cert_Allowed
          then
            SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)
            and then S.HC.Cfg.Local.NaCl_Cert_Len <= N32 (Max_Cert_DER)),
     Post =>
       Result in OK | Has_Output | Error_Alert
       and then (if Result = OK then S.Negotiated_Suite in TLS12_Suite);

   procedure Send_Cleartext_Handshake_Error_12
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Err    : in Error_Code;
      Result : out Action)
   with
     Pre  => Alert_Desc (Err) /= 0 and then Alert_Desc (Err) /= 90,
     Post => S.State = Error_State and then Result in Has_Output | Error_Alert;

   procedure Send_Cleartext_Handshake_Error_12
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Err    : in Error_Code;
      Result : out Action) is
   begin
      Reset (D.Reasm);
      Send_Alert_And_Error (S, Err, Result);
      pragma Assert (Result /= OK);
      pragma Assert_And_Cut (S.State = Error_State and then Result in Has_Output | Error_Alert);
   end Send_Cleartext_Handshake_Error_12;

   procedure Append_TLS12_Client_Handshake_Record
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      Msg     : in Byte_Seq;
      Err     : in Error_Code;
      Result  : out Action)
   with
     Pre  =>
       Alert_Desc (Err) /= 0
       and then Alert_Desc (Err) /= 90
       and then Msg'First = 0
       and then Msg'Length > 0
       and then Msg'Length <= Max_Fragment
       and then Msg'Last - Msg'First < Transcript_Capacity,
     Post =>
       Result in OK | Has_Output | Error_Alert
       and then
         (if Result = OK
          then
            S.Negotiated_Suite = S.Negotiated_Suite'Old
            and then
              (if S.Negotiated_Suite'Old in TLS12_Suite then S.Negotiated_Suite in TLS12_Suite));

   procedure Append_TLS12_Client_Handshake_Record
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      Msg     : in Byte_Seq;
      Err     : in Error_Code;
      Result  : out Action)
   is
      Rec_Out     : N32;
      Saved_Suite : constant Supported_Suite := S.Negotiated_Suite
      with Ghost;
      Saved_Group : constant ECDHE_Group := S.HC.KE.Curve
      with Ghost;
   begin
      Result := OK;
      Append_Transcript (S.HC.TS, Msg);
      Records.Build_Handshake_Record (Msg, Scratch, Rec_Out);
      if Rec_Out = 0 then
         Send_Cleartext_Handshake_Error_12 (S, D, Err, Result);
         pragma Assert (Result in Has_Output | Error_Alert);
         return;
      end if;

      pragma
        Assert_And_Cut
          (Result = OK
           and then S.Negotiated_Suite = Saved_Suite
           and then (if Saved_Suite in TLS12_Suite then S.Negotiated_Suite in TLS12_Suite));
   end Append_TLS12_Client_Handshake_Record;

   procedure Append_Client_Certificate_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      Result  : out Action)
   is
      Cert_Buf : Byte_Seq (0 .. 4 + 3 + Max_Cert_DER - 1);
      Cert_Len : N32;
      Rec_Out  : N32;
   begin
      Result := OK;
      if not S.HC.Cert_Request_Received then
         pragma Assert_And_Cut (Result = OK and then S.Negotiated_Suite in TLS12_Suite);
         return;
      end if;

      if S.HC.Cfg.Local /= null
        and then S.HC.Cfg.Local.Has_Identity
        and then S.HC.T12.Client_Cert_Allowed
      then
         pragma Assert (SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local));
         pragma Assert (S.HC.Cfg.Local.NaCl_Cert_Len <= N32 (Max_Cert_DER));
         Build_Certificate_Chain_12 (S.HC.Cfg.Local.all, Cert_Buf, Cert_Len);
      else
         Cert_Buf := (others => 0);
         Cert_Buf (0) := 16#0B#;
         Cert_Buf (3) := 3;
         Cert_Len := 7;
      end if;

      if Cert_Len > 0 then
         Append_Transcript (S.HC.TS, Cert_Buf (0 .. Cert_Len - 1));
         Records.Build_Handshake_Record (Cert_Buf (0 .. Cert_Len - 1), Scratch, Rec_Out);
         if Rec_Out = 0 then
            Reset (D.Reasm);
            Send_Alert_And_Error (S, Insufficient_Buffer, Result);
            pragma Assert (Result /= OK and then Result in Has_Output | Error_Alert);
            return;
         end if;
      end if;
      pragma Assert (Result = OK and then S.Negotiated_Suite in TLS12_Suite);
   end Append_Client_Certificate_12;

   procedure Append_Client_Key_Exchange_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      Result  : out Action)
   with
     Pre  => S.Negotiated_Suite in TLS12_Suite,
     Post =>
       Result in OK | Has_Output | Error_Alert
       and then (if Result = OK then S.Negotiated_Suite in TLS12_Suite);

   procedure Append_Client_Key_Exchange_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      Result  : out Action)
   is
      CKE     : Byte_Seq (0 .. Max_Client_Key_Exchange - 1);
      CKE_Len : N32;
   begin
      Result := OK;
      Build_Client_Key_Exchange (S.HC, CKE, CKE_Len);
      pragma
        Assert_And_Cut
          (Result = OK
           and then CKE_Len <= Max_Client_Key_Exchange
           and then S.Negotiated_Suite in TLS12_Suite);
      if CKE_Len > 0 then
         Append_TLS12_Client_Handshake_Record
           (S, D, Scratch, CKE (0 .. CKE_Len - 1), Insufficient_Buffer, Result);
         if Result /= OK then
            return;
         end if;
         --  RFC 7627: capture session_hash = Hash(transcript) at the
         --  CKE point, under the negotiated PRF digest.
         if S.Negotiated_Suite
            in Suite_ECDHE_RSA_AES256_GCM_SHA384 | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
         then
            declare
               D : SPARKNaCl.Hashing.SHA384.Digest;
            begin
               SPARKTLS_Transcript.Current_384 (S.HC.TS, D);
               S.HC.EMS_Session_Hash := Bytes_48 (D);
            end;
         else
            declare
               D : Digest;
            begin
               SPARKTLS_Transcript.Current_256 (S.HC.TS, D);
               S.HC.EMS_Session_Hash := (others => 0);
               S.HC.EMS_Session_Hash (0 .. 31) := Byte_Seq (D);
            end;
         end if;
         S.HC.EMS_Hash_Taken := True;
         pragma
           Assert_And_Cut
             (Result = OK
              and then CKE_Len <= Max_Client_Key_Exchange
              and then S.Negotiated_Suite in TLS12_Suite);
      end if;
      pragma Assert_And_Cut (Result = OK and then S.Negotiated_Suite in TLS12_Suite);
   end Append_Client_Key_Exchange_12;

   procedure Build_Client_Certificate_Verify_12_Message
     (HC : in Engaged_Context; CV_Buf : out Byte_Seq; CV_Len : out N32)
   with
     Pre  =>
       CV_Buf'First = 0
       and then CV_Buf'Last >= 523
       and then HC.Cfg.Local /= null
       and then HC.Cfg.Local.Has_Identity
       and then HC.Cfg.Random /= null,
     Post => CV_Len <= 520;

   procedure Build_Client_Certificate_Verify_12_Message
     (HC : in Engaged_Context; CV_Buf : out Byte_Seq; CV_Len : out N32)
   is
      TH_CV          : Digest;
      TH4_CV         : SPARKNaCl.Hashing.SHA384.Digest;
      TH5_CV         : SPARKNaCl.Hashing.SHA512.Digest;
      Use_384_For_CV : constant Boolean :=
        HC.Negotiated_Sig_Algo
        in Sig_ECDSA_P384_SHA384 | Sig_RSA_PSS_SHA384 | Sig_RSA_PKCS1_SHA384;
      Use_512_For_CV : constant Boolean :=
        HC.Negotiated_Sig_Algo in Sig_RSA_PSS_SHA512 | Sig_RSA_PKCS1_SHA512;
      Use_Raw_For_CV : constant Boolean := HC.Negotiated_Sig_Algo = Sig_Ed25519;
   begin
      CV_Buf := (others => 0);
      --  Ed25519 (0x0807) is NOT offered for TLS 1.2 client auth
      --  (2026-08-25): PureEdDSA needs a second full pass over the raw
      --  transcript with a signing-time-derived prefix, which the
      --  streaming transcript cannot provide. Ed25519 client auth
      --  works in TLS 1.3, where CertificateVerify signs a fixed
      --  construction over the transcript HASH. The negotiation site
      --  no longer selects 0x0807 for 1.2, so Use_Raw_For_CV is a
      --  can't-happen; fail closed if it somehow occurs.
      if Use_Raw_For_CV then
         CV_Len := 0;
      elsif Use_512_For_CV then
         SPARKTLS_Transcript.Current_512 (HC.TS, TH5_CV);
         Build_Certificate_Verify_12
           (Transcript_Hash => Byte_Seq (TH5_CV),
            Id              => HC.Cfg.Local.all,
            Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
            Random          => HC.Cfg.Random,
            Result          => CV_Buf,
            Len             => CV_Len);
      elsif Use_384_For_CV then
         SPARKTLS_Transcript.Current_384 (HC.TS, TH4_CV);
         Build_Certificate_Verify_12
           (Transcript_Hash => Byte_Seq (TH4_CV),
            Id              => HC.Cfg.Local.all,
            Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
            Random          => HC.Cfg.Random,
            Result          => CV_Buf,
            Len             => CV_Len);
      else
         SPARKTLS_Transcript.Current_256 (HC.TS, TH_CV);
         Build_Certificate_Verify_12
           (Transcript_Hash => Byte_Seq (TH_CV),
            Id              => HC.Cfg.Local.all,
            Sig_Algo_Wire   => HC.Negotiated_Sig_Algo,
            Random          => HC.Cfg.Random,
            Result          => CV_Buf,
            Len             => CV_Len);
      end if;
   end Build_Client_Certificate_Verify_12_Message;

   procedure Append_Client_Certificate_Verify_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      Result  : out Action)
   with
     Pre  =>
       S.HC.Cfg.Local /= null
       and then S.HC.Cfg.Local.Has_Identity
       and then S.HC.T12.Client_Cert_Allowed
       and then S.Negotiated_Suite in TLS12_Suite,
     Post =>
       Result in OK | Has_Output | Error_Alert
       and then (if Result = OK then S.Negotiated_Suite = S.Negotiated_Suite'Old);

   procedure Append_Client_Certificate_Verify_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      Result  : out Action)
   is
      CV_Buf : Byte_Seq (0 .. 523);
      CV_Len : N32;
   begin
      Result := OK;

      --  Semantically unreachable (Random is validated at
      --  Configure), but the Cfg frame is not carried through
      --  the handshake web; fail closed as in Server.TLS12's
      --  Ready_Config membership guards.
      if S.HC.Cfg.Random = null then
         Send_Cleartext_Handshake_Error_12 (S, D, Internal_Error, Result);
         return;
      end if;

      Build_Client_Certificate_Verify_12_Message (S.HC, CV_Buf, CV_Len);
      pragma Assert (Result = OK and then CV_Len <= 520);

      if CV_Len = 0 then
         Send_Cleartext_Handshake_Error_12 (S, D, Internal_Error, Result);
         pragma Assert (Result in Has_Output | Error_Alert);
         return;
      end if;

      Append_TLS12_Client_Handshake_Record
        (S, D, Scratch, CV_Buf (0 .. CV_Len - 1), Insufficient_Buffer, Result);
      if Result /= OK then
         return;
      end if;

      pragma Assert (Result = OK);
   end Append_Client_Certificate_Verify_12;

   procedure Build_Client_Finished_12_Message (S : in Session; FB : out Byte_Seq; FL : out N32)
   with
     Pre  => FB'First = 0 and then FB'Last >= Finished_12_Total_Len - 1,
     Post => Valid_Finished_12_Len (FL);

   procedure Build_Client_Finished_12_Message (S : in Session; FB : out Byte_Seq; FL : out N32) is
      use Key_Schedule_12;
      TH      : Digest;
      TH4     : SPARKNaCl.Hashing.SHA384.Digest;
      Use_384 : constant Boolean :=
        S.Negotiated_Suite
        in Suite_ECDHE_RSA_AES256_GCM_SHA384 | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
   begin
      if Use_384 then
         SPARKTLS_Transcript.Current_384 (S.HC.TS, TH4);
         Build_Finished_12
           (S.HC.Master_Secret_12, Label_Client_Finished, Byte_Seq (TH4), True, FB, FL);
      else
         SPARKTLS_Transcript.Current_256 (S.HC.TS, TH);
         Build_Finished_12
           (S.HC.Master_Secret_12, Label_Client_Finished, Byte_Seq (TH), False, FB, FL);
      end if;
   end Build_Client_Finished_12_Message;

   procedure Encrypt_Client_Finished_Record_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      FB      : in Byte_Seq;
      FL      : in N32;
      Result  : out Action)
   with
     Pre  => FB'First = 0 and then Valid_Finished_12_Len (FL) and then FL - 1 <= FB'Last,
     Post =>
       Result in OK | Has_Output | Error_Alert
       and then (if Result = OK then SPARKTLS_Transcript.Started (S.HC.TS));

   procedure Encrypt_Client_Finished_Record_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      FB      : in Byte_Seq;
      FL      : in N32;
      Result  : out Action)
   is
      use Records.TLS12;
      EO : N32;
   begin
      Result := OK;
      Append_Transcript (S.HC.TS, FB (0 .. FL - 1));

      Build_Encrypted_Record_12
        (FB (0 .. FL - 1), 16#16#, S.Client_App, S.HC.Client_Write_IV_12, Scratch, EO);
      if EO = 0 then
         --  Fatal path -- no counter rewind; the burned nonce stays
         --  burned and the connection dies here.
         Send_Cleartext_Handshake_Error_12 (S, D, Insufficient_Buffer, Result);
         pragma Assert (Result in Has_Output | Error_Alert);
         return;
      end if;
      pragma Assert (Result = OK and then SPARKTLS_Transcript.Started (S.HC.TS));
   end Encrypt_Client_Finished_Record_12;

   procedure Commit_Client_Flight_Scratch_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in IO_Buffer;
      Result  : out Action)
   with
     Post =>
       Result in OK | Has_Output | Error_Alert
       and then
         (if (SPARKTLS_Transcript.Started (S.HC.TS)'Old and then Result = OK)
          then SPARKTLS_Transcript.Started (S.HC.TS));

   procedure Commit_Client_Flight_Scratch_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in IO_Buffer;
      Result  : out Action) is
   begin
      Result := OK;
      if Free_Space (S.Output) < Scratch.Write_Pos then
         --  Fatal path -- no counter rewind (the counter lives inside
         --  S.Client_App now); the connection dies here.
         Send_Cleartext_Handshake_Error_12 (S, D, Insufficient_Buffer, Result);
         pragma Assert (Result in Has_Output | Error_Alert);
         return;
      end if;

      S.Output.Data (S.Output.Write_Pos .. S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
        Scratch.Data (0 .. Scratch.Write_Pos - 1);
      S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;
      pragma Assert (Result = OK);
   end Commit_Client_Flight_Scratch_12;

   procedure Encrypt_And_Commit_Client_Finished_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      FB      : in Byte_Seq;
      FL      : in N32;
      Result  : out Action)
   with
     Pre  => FB'First = 0 and then Valid_Finished_12_Len (FL) and then FL - 1 <= FB'Last,
     Post =>
       Result in OK | Has_Output | Error_Alert
       and then (if Result = OK then SPARKTLS_Transcript.Started (S.HC.TS));

   procedure Encrypt_And_Commit_Client_Finished_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      FB      : in Byte_Seq;
      FL      : in N32;
      Result  : out Action) is
   begin
      Encrypt_Client_Finished_Record_12 (S, D, Scratch, FB, FL, Result);
      if Result /= OK then
         return;
      end if;
      Commit_Client_Flight_Scratch_12 (S, D, Scratch, Result);
   end Encrypt_And_Commit_Client_Finished_12;

   procedure Append_Client_CCS_And_Finished_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      Result  : out Action)
   with
     Pre  => S.Negotiated_Suite in TLS12_Suite,
     Post =>
       Result in OK | Has_Output | Error_Alert
       and then (if Result = OK then SPARKTLS_Transcript.Started (S.HC.TS));

   procedure Append_Client_CCS_And_Finished_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Scratch : in out IO_Buffer;
      Result  : out Action)
   is
      CCS_Out : N32;
      FB      : Byte_Seq (0 .. Finished_12_Total_Len - 1);
      FL      : N32;
   begin
      Derive_Keys_12 (S, D);

      Records.Build_CCS_Record (Scratch, CCS_Out);
      if CCS_Out = 0 then
         Send_Cleartext_Handshake_Error_12 (S, D, Insufficient_Buffer, Result);
         return;
      end if;

      Build_Client_Finished_12_Message (S, FB, FL);
      Encrypt_And_Commit_Client_Finished_12 (S, D, Scratch, FB, FL, Result);
   end Append_Client_CCS_And_Finished_12;

   procedure Build_Client_Flight_12
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   with
     Pre  =>
       S.Negotiated_Suite in TLS12_Suite
       and then
         (if S.HC.Cert_Request_Received
            and then S.HC.Cfg.Local /= null
            and then S.HC.Cfg.Local.Has_Identity
            and then S.HC.T12.Client_Cert_Allowed
          then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)),
     Post =>
       Result in OK | Has_Output | Error_Alert
       and then (if Result = OK then SPARKTLS_Transcript.Started (S.HC.TS));

   procedure Build_Client_Flight_12
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   is
      Scratch : IO_Buffer;
   begin
      Append_Client_Certificate_12 (S, D, Scratch, Result);
      if Result /= OK then
         return;
      end if;

      Append_Client_Key_Exchange_12 (S, D, Scratch, Result);
      if Result /= OK then
         return;
      end if;

      if S.HC.Cert_Request_Received
        and then S.HC.Cfg.Local /= null
        and then S.HC.Cfg.Local.Has_Identity
        and then S.HC.T12.Client_Cert_Allowed
      then
         Append_Client_Certificate_Verify_12 (S, D, Scratch, Result);
         if Result /= OK then
            return;
         end if;
      end if;

      Append_Client_CCS_And_Finished_12 (S, D, Scratch, Result);
      if Result /= OK then
         return;
      end if;

   end Build_Client_Flight_12;

   --  RFC 5246 7.4.5 ServerHelloDone (HS type 0x0E). End of the
   --  server's pre-CCS flight. Computes the ECDHE shared secret,
   --  derives the AEAD keys, then builds and commits the entire
   --  client flight atomically: (optional Certificate + CKE +
   --  optional CertificateVerify + CCS + encrypted Finished) into a
   --  stack-scratch IO_Buffer; the channel counter is not rolled back on
   --  commit failure to keep AEAD nonces in sync with the peer.
   procedure Handle_SHD_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Frag    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action)
   with
     Pre  =>
       Msg_Len <= Max_HS_Msg - 4
       and then S.HC.Cfg.Random /= null
       --  256: transcript-append bound (see Handle_CertReq_12).
       and then Frag'Last < N32'Last - 256
       and then Frag'First <= N32'Last - 4
       and then Msg_Len <= N32'Last - Frag'First - 4
       and then Frag'First + 3 + Msg_Len <= Frag'Last
       and then Frag'First <= Frag'Last
       and then Frag'Last - Frag'First < Transcript_Capacity
       and then S.Negotiated_Suite in TLS12_Suite,
     Post =>
       True
       --  ServerHelloDone never yields OK: the body ends with
       --  Result := (if Output_Pending > 0 then Has_Output
       --  else Need_Input) and asserts Result /= OK three
       --  times. Stating it lets the caller discharge the
       --  HT_Server_Hello_Done arm of the dispatch cut
       --  instead of re-deriving it.
       and then Result /= OK
       and then
         (if Result = OK
          then
            S.State not in Idle | Closing | Closed | Error_State
            and then S.Negotiated_Suite in TLS12_Suite);

   procedure Handle_SHD_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Frag    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action)
   is
      Saved_Local              : constant Valid_Identity_Access := S.HC.Cfg.Local;
      Saved_Local_Config_Valid : constant Boolean :=
        Saved_Local /= null
        and then Saved_Local.Has_Identity
        and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (Saved_Local)
      with Ghost;
   begin
      if Msg_Len /= 0 then
         Reset (D.Reasm);
         Send_Alert_And_Error (S, Decode_Error, Result);
         pragma Assert (Result /= OK);
         return;
      end if;
      Append_Transcript (S.HC.TS, Frag);
      --  Compute ECDHE shared secret per Selected_Group.
      declare
         SS_OK  : Boolean;
         SS_Err : Error_Code;
      begin
         Derive_Client_Shared_Secret_12 (S.HC, SS_OK, SS_Err);
         if not SS_OK then
            Reset (D.Reasm);
            Send_Alert_And_Error (S, SS_Err, Result);
            pragma Assert (Result /= OK);
            return;
         end if;
      end;

      --  Build + atomically commit the client flight.
      S.HC.Cfg.Local := Saved_Local;
      pragma
        Assert
          (if Saved_Local_Config_Valid
           then
             S.HC.Cfg.Local /= null
             and then S.HC.Cfg.Local.Has_Identity
             and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local));
      pragma
        Assert
          (if S.HC.Cert_Request_Received
             and then S.HC.Cfg.Local /= null
             and then S.HC.Cfg.Local.Has_Identity
             and then S.HC.T12.Client_Cert_Allowed
           then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local));
      Build_Client_Flight_12 (S, D, Result);
      if Result /= OK then
         return;
      end if;

      S.HC.CKE_Received_12 := True;
      Result := (if Output_Pending (S) > 0 then Has_Output else Need_Input);
      pragma Assert (Result /= OK);
   end Handle_SHD_12;

   --  RFC 5077 3.3 NewSessionTicket (HS type 0x04). Two arrival times:
   --    * Abbreviated handshake (S.HC.T12.Resuming): right after SH,
   --      before server CCS+Finished. Cache, append transcript, derive
   --      AEAD keys from cached master_secret + this connection's
   --      randoms, flip CKE_Received_12 so the dispatcher advances.
   --    * Full handshake: after client CKE+CCS+Finished, before
   --      server CCS+Finished. The dispatcher routes to
   --      Process_Server_CCS at that point  handled there.
   --
   --  Frag is the reassembled HS message bytes (header + body), Msg_Len
   --  the declared body length from the HS header.
   procedure Send_Encrypted_Finished_Error_12
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Desc_Code : in Byte;
      Err       : in Error_Code;
      Result    : out Action)
   with
     Pre  => Desc_Code /= 0,
     Post =>
       S.State = Error_State
       and Used (D.Reasm) = 0
       and S.Last_Error = Err
       and Result in Has_Output | Error_Alert;

   procedure Reject_New_Session_Ticket_12
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   with Post => S.State = Error_State and then Result in Has_Output | Error_Alert;

   procedure Reject_New_Session_Ticket_12
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action) is
   begin
      Reset (D.Reasm);
      if S.HC.T12.Resuming then
         Send_Alert_And_Error (S, Decode_Error, Result);
      else
         Send_Encrypted_Finished_Error_12 (S, D, 50, Decode_Error, Result);
      end if;
      pragma Assert_And_Cut (S.State = Error_State and then Result in Has_Output | Error_Alert);
   end Reject_New_Session_Ticket_12;

   procedure Cache_New_Session_Ticket_12
     (S          : in out Session;
      D          : in SPARKTLS.HS_Pool.HS_Data;
      NST_Body   : in Byte_Seq;
      Ticket_Len : in N32;
      Lifetime   : in Unsigned_32)
   with
     Pre  =>
       NST_Body'First = 0
       and then NST_Body'Last < Max_HS_Msg
       and then Ticket_Len <= Max_TLS12_Ticket_Len
       and then Ticket_Len + 6 = N32 (NST_Body'Length),
     Post =>
       S.State = S.State'Old
       and then S.Negotiated_Suite = S.Negotiated_Suite'Old
       and then S.TLS12_New_Ticket.Valid;

   procedure Cache_New_Session_Ticket_12
     (S          : in out Session;
      D          : in SPARKTLS.HS_Pool.HS_Data;
      NST_Body   : in Byte_Seq;
      Ticket_Len : in N32;
      Lifetime   : in Unsigned_32) is
   begin
      if Ticket_Len > 0 then
         S.TLS12_New_Ticket.Ticket (0 .. Ticket_Len - 1) := NST_Body (6 .. 6 + Ticket_Len - 1);
      end if;
      S.TLS12_New_Ticket.Ticket_Len := Ticket_Len;
      S.TLS12_New_Ticket.Suite := Wire_Of (S.Negotiated_Suite);
      S.TLS12_New_Ticket.Master_Secret := S.HC.Master_Secret_12;
      S.TLS12_New_Ticket.Lifetime_Hint := Lifetime;
      S.TLS12_New_Ticket.Server_Name := S.HC.Cfg.Server_Name;
      --  RFC 7627 s5.3: record whether THIS session negotiated EMS so a
      --  later resumption using this ticket can be checked against it.
      S.TLS12_New_Ticket.EMS := (if S.HC.Use_EMS then EMS_Negotiated else EMS_Absent);
      S.TLS12_New_Ticket.Valid := True;
   end Cache_New_Session_Ticket_12;

   procedure Handle_NST_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Frag    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action)
   with
     Pre  =>
       Msg_Len in 6 .. Max_HS_Msg - 4
       and then
         Frag'First
         <= Frag'Last
            --  256: transcript-append bound (see Handle_CertReq_12).
       and then Frag'Last < N32'Last - 256
       and then Frag'First <= N32'Last - 4
       and then Msg_Len <= N32'Last - Frag'First - 4
       and then Msg_Len <= N32 (Frag'Length) - 4
       and then Frag'First + 3 + Msg_Len <= Frag'Last
       and then Frag'Last - Frag'First < Transcript_Capacity
       and then S.Negotiated_Suite in TLS12_Suite,
     Post =>
       (if Result = OK
        then
          (if SPARKTLS_Transcript.Started (S.HC.TS)'Old then SPARKTLS_Transcript.Started (S.HC.TS))
          and then S.Negotiated_Suite in TLS12_Suite);

   procedure Handle_NST_12
     (S       : in out Session;
      D       : in out SPARKTLS.HS_Pool.HS_Data;
      Frag    : in Byte_Seq;
      Msg_Len : in N32;
      Result  : out Action)
   is
      B          : constant N32 := Frag'First + 4;
      NST_Body   : constant Byte_Seq (0 .. Msg_Len - 1) := Frag (B .. B + Msg_Len - 1);
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
         Reject_New_Session_Ticket_12 (S, D, Result);
         return;
      end if;

      Cache_New_Session_Ticket_12 (S, D, NST_Body, Ticket_Len, Lifetime);

      Append_Transcript (S.HC, Frag);

      if S.HC.T12.Resuming then
         Derive_Keys_Resumed_12 (S, D);
         S.HC.CKE_Received_12 := True;
      end if;
      Result := OK;
   end Handle_NST_12;

   procedure Dispatch_Server_Flight_Message
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Msg_Type : in Maybe_HS_Msg;
      Frag     : in Byte_Seq;
      Msg_Len  : in N32;
      Result   : out Action)
   with
     Pre  =>
       Msg_Len <= Max_HS_Msg - 4
       and then
         Frag'First
         <= Frag'Last
            --  256, not 4: the transcript-append bound. Callers pass
            --  Message() slices ('Last <= Max_HS_Msg - 1), so this is
            --  free to prove there and feeds Append_Transcript here.
       and then Frag'Last < N32'Last - 256
       and then Frag'First <= N32'Last - 4
       and then Msg_Len <= N32'Last - Frag'First - 4
       and then Msg_Len <= N32 (Frag'Length) - 4
       and then Frag'First + 3 + Msg_Len <= Frag'Last
       and then Frag'Last - Frag'First < Transcript_Capacity,
     Post =>
       (if Result = OK
        then
          (if Msg_Type = HT_Server_Hello_Done then Result /= OK)
          and then
            (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
             then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)));

   procedure Dispatch_Server_Flight_Message
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Msg_Type : in Maybe_HS_Msg;
      Frag     : in Byte_Seq;
      Msg_Len  : in N32;
      Result   : out Action) is
   begin
      --  Fail-closed: the negotiated suite was checked against the six
      --  implemented ECDHE suites at ServerHello. Re-establishing it
      --  here grounds the handler preconditions locally instead of
      --  threading the fact through every caller of the drain loop.
      if S.Negotiated_Suite not in TLS12_Suite then
         Reset (D.Reasm);
         Send_Alert_And_Error (S, Internal_Error, Result);
         return;
      end if;

      case Msg_Type is
         when HT_Certificate         =>
            --  Certificate (RFC 5246 7.4.2). Parsing happens in
            --  Parse_Cert_Chain_12; subsequent validation gates
            --  (keyUsage, suite<->cert algorithm match, hostname,
            --  chain) live in Validate_Server_Cert_12.
            if Msg_Len < 3 then
               Reset (D.Reasm);
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;
            declare
               Parse_OK : Boolean;
            begin
               Parse_Cert_Chain_12 (S.HC, D, Frag, Msg_Len, Parse_OK);
               if not Parse_OK then
                  Reset (D.Reasm);
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;
            end;

            Validate_Server_Cert_12 (S, D, Result);
            if Result /= OK then
               return;
            end if;

            Append_Transcript (S.HC, Frag);
            Result := OK;

         when HT_Certificate_Request =>
            --  RFC 5246 7.4: in an ECDHE flight ServerKeyExchange is
            --  mandatory and precedes CertificateRequest. Selected_Group
            --  is only set (to a valid group) by a successfully processed
            --  SKE, so a zero group here means the peer sent this message
            --  out of order.
            if not S.HC.KE.Negotiated then
               Reset (D.Reasm);
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               return;
            end if;
            Handle_CertReq_12 (S, D, Frag, Msg_Len, Result);

         when HT_Server_Key_Exchange =>
            Handle_SKE_12 (S, D, Frag, Msg_Len, Result);

         when HT_Server_Hello_Done   =>
            --  RFC 5246 7.4: ServerHelloDone before a valid
            --  ServerKeyExchange is an out-of-order flight (SKE is
            --  mandatory for ECDHE).
            if not S.HC.KE.Negotiated then
               Reset (D.Reasm);
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               return;
            end if;
            pragma
              Assert
                (if S.HC.Cert_Request_Received
                   and then S.HC.Cfg.Local /= null
                   and then S.HC.Cfg.Local.Has_Identity
                   and then S.HC.T12.Client_Cert_Allowed
                 then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local));
            Handle_SHD_12 (S, D, Frag, Msg_Len, Result);

         when HT_New_Session_Ticket  =>
            --  RFC 5077 3.3: NewSessionTicket belongs after the key
            --  exchange; SKE is mandatory for ECDHE, so a zero group
            --  here means the flight is out of order.
            if not S.HC.KE.Negotiated then
               Reset (D.Reasm);
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               return;
            end if;
            if Msg_Len < 6 then
               Reset (D.Reasm);
               if S.HC.CKE_Received_12 then
                  Send_Encrypted_Finished_Error_12 (S, D, 50, Decode_Error, Result);
               else
                  Send_Alert_And_Error (S, Decode_Error, Result);
               end if;
               return;
            end if;
            Handle_NST_12 (S, D, Frag, Msg_Len, Result);

         when others                 =>
            --  RFC 5246 7.4: unknown handshake type during the
            --  flight is unexpected_message (BoGo WrongMessageType-*
            --  injects type+42). After the client CCS+Finished flight,
            --  the peer expects encrypted alerts.
            Reset (D.Reasm);
            if S.HC.CKE_Received_12 then
               Send_Encrypted_Finished_Error_12 (S, D, 10, Unexpected_Message, Result);
            else
               Send_Alert_And_Error (S, Unexpected_Message, Result);
            end if;
      end case;
      pragma
        Assert_And_Cut
          ((if Result = OK
            then
              (if Msg_Type = HT_Server_Hello_Done then Result /= OK)
              and then
                (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
                 then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local))));
   end Dispatch_Server_Flight_Message;

   procedure Drain_Packed_Server_Flight
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Msg_Type : in out Maybe_HS_Msg;
      Msg_Len  : in out N32;
      Result   : out Action)
     --  No reassembly preconditions. The buffer's own operations carry what
     --  used to be five conjuncts here: Has_Message decides whether there is
     --  anything to dispatch, Message_Length >= 4 comes from its postcondition,
     --  and Msg_Type/Msg_Len are derived from the message rather than supplied
     --  by the caller and required to agree with it.
   with
     Pre =>
       (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
        then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local))
       and then
         (if S.HC.Cert_Request_Received
            and then S.HC.Cfg.Local /= null
            and then S.HC.Cfg.Local.Has_Identity
            and then S.HC.T12.Client_Cert_Allowed
          then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local));

   procedure Drain_Packed_Server_Flight
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Msg_Type : in out Maybe_HS_Msg;
      Msg_Len  : in out N32;
      Result   : out Action) is
   begin
      Result := OK;

      --  PackHandshake (BoGo PackHandshakeFlight): one record may carry
      --  several back-to-back handshake messages. Has_Message stays true
      --  across Consume while whole messages remain, so a packed flight and
      --  a single-message flight are the SAME loop. There is no "leftover"
      --  concept, no shift subprogram and no second set of length fields --
      --  that was the entire content of the deleted Client.TLS12.Packed.
      loop
         --  Peer-controlled declared size. Checked every iteration because
         --  each message carries its own header.
         if Message_Too_Large (D.Reasm) then
            Reset (D.Reasm);
            Send_Alert_And_Error (S, Decode_Error, Result);
            return;
         end if;

         --  INVARIANT FIRST, THEN THE EXIT. A Loop_Invariant is a CUT: past
         --  it the prover knows only what the invariant states. With the exit
         --  above the cut, the Has_Message fact it establishes was discarded
         --  and the Message (...) call below could not discharge its
         --  precondition -- a single-line proof of it exhausted the prover
         --  even in isolation. Ordered this way the cut happens first and the
         --  exit's fact survives to its use, with nothing added to either.
         pragma
           Loop_Invariant
             (Result = OK
              and then
                (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
                 then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)));

         exit when not Has_Message (D.Reasm);

         pragma
           Assert
             (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
              then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local));

         declare
            --  Message_Length >= 4 by its postcondition, so Msg_Len below
            --  cannot underflow. The type carries it; nothing to assert.
            Frag : constant Message_Bytes := Message (D.Reasm);
         begin
            if Frag'Length - 1 >= Transcript_Capacity then
               Reset (D.Reasm);
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;

            --  Both derived from the one buffer rather than carried in
            --  parallel out-parameters that could disagree with it.
            Msg_Type := HS_Msg_From_Wire (Frag (0));
            Msg_Len := Frag'Length - 4;

            --  RFC 5246 7.4.6: ServerHelloDone is the last message of the
            --  server's flight, so nothing may trail it. Residue here is
            --  excess handshake data, NOT the head of a later message that
            --  a further record will complete -- which is what Consume
            --  otherwise assumes (BoGo appends one stray NST type byte in
            --  PartialNewSessionTicketWithServerHelloDone).
            --
            --  Checked BEFORE dispatch on purpose: the handler queues our
            --  CCS+Finished and switches write keys, after which a plaintext
            --  alert would be wrong.
            if Msg_Type = HT_Server_Hello_Done and then Used (D.Reasm) > Frag'Length then
               Reset (D.Reasm);
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               return;
            end if;

            Dispatch_Server_Flight_Message
              (S        => S,
               D        => D,
               Msg_Type => Msg_Type,
               Frag     => Byte_Seq (Frag),
               Msg_Len  => Msg_Len,
               Result   => Result);

            if Result /= OK and then Msg_Type /= HT_Server_Hello_Done then
               Reset (D.Reasm);
               return;
            end if;

            if not Has_Message (D.Reasm) then
               return;
            end if;
         end;

         Consume (D.Reasm);

         --  A handler that queued our flight (ServerHelloDone) stops the
         --  drain; anything still buffered is discarded below, as before.
         exit when Result /= OK;
      end loop;

      --  A COMPLETE message still here was left undispatched because a
      --  handler stopped us -- the old tail discarded it too. A PARTIAL
      --  message is different: it must survive to the next Advance call,
      --  and Consume already left it at offset 0.
      if Has_Message (D.Reasm) then
         Reset (D.Reasm);
      end if;
   end Drain_Packed_Server_Flight;

   procedure Read_Server_Flight_Record
     (S           : in out Session;
      D           : in out SPARKTLS.HS_Pool.HS_Data;
      Rec         : out Records.Parse_Result;
      Have_Record : out Boolean;
      Result      : out Action)
   with
     Pre  => Warning_Alerts_Bounded_RFC_8446_6_1 (S),
     Post =>
       (if SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local'Old)
        then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local))
       and then
         (if Have_Record
          then
            Result = OK
            and then Rec.OK
            and then Rec.Content = Records.Content_Handshake
            and then Rec.Fragment_Pos <= N32'Last - Rec.Fragment_Len
            and then Rec.Record_Len = Rec.Fragment_Pos + Rec.Fragment_Len
            and then Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos
            and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len);

   procedure Read_Server_Flight_Record
     (S           : in out Session;
      D           : in out SPARKTLS.HS_Pool.HS_Data;
      Rec         : out Records.Parse_Result;
      Have_Record : out Boolean;
      Result      : out Action) is
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
         return;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1), Available (S.Input), Rec);

      if Rec.Bad_Version then
         S.Last_Error := Protocol_Version;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      if not Rec.OK then
         Result := Need_Input;
         return;
      end if;

      if Rec.Content = Records.Content_Alert then
         declare
            AS   : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
            ALen : constant N32 := Rec.Fragment_Len;
            Lvl  : constant Byte := (if ALen >= 1 then S.Input.Data (AS) else 0);
            Dsc  : constant Byte := (if ALen >= 2 then S.Input.Data (AS + 1) else 0);
         begin
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if Lvl = 1 and Dsc /= 0 then
               --  Check BEFORE incrementing: the counter then never exceeds the
               --  cap, so the bound holds BY CONSTRUCTION rather than being
               --  asserted. Behaviour is identical (the same alert/record
               --  triggers the error either way) and it is what makes the
               --  narrowed field subtype and its AoRTE check provable.
               if S.Warning_Alerts_Recvd >= Max_Warning_Alerts then
                  Send_Alert_And_Error (S, Decode_Error, Result);
                  return;
               end if;
               S.Warning_Alerts_Recvd := S.Warning_Alerts_Recvd + 1;
               Result := OK;
               return;
            elsif Lvl = 2 then
               S.Last_Error := Unexpected_Message;
               Set_State (S, Error_State);
               Result := Error_Alert;
               return;
            else
               Result := OK;
               return;
            end if;
         end;
      end if;

      if Rec.Content = Records.Content_Change_Cipher_Spec
        and then not S.HC.T12.Resuming
        and then S.HC.T12.Sent_Ticket_Ext
        and then S.HC.Cfg.TLS12_Resume_Ticket.Valid
        and then S.HC.Cfg.TLS12_Resume_Ticket.Suite = Wire_Of (S.Negotiated_Suite)
      then
         declare
            CCS_Pos     : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
            CCS_Byte_OK : constant Boolean :=
              Rec.Fragment_Len = 1 and then S.Input.Data (CCS_Pos) = 16#01#;
         begin
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if not CCS_Byte_OK then
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               return;
            end if;
         end;
         --  RFC 7627 s5.3: the resumed session's EMS state MUST match the
         --  original session's. Resuming a session that did NOT negotiate
         --  EMS as one that does (or the reverse) is precisely the
         --  triple-handshake attack path EMS exists to close, so a
         --  mismatch is a fatal handshake_failure -- NOT a silent
         --  fall-back to a full handshake.
         --  BoGo ExtendedMasterSecret-{NoToYes,YesToNo}-Client.
         if S.HC.Cfg.TLS12_Resume_Ticket.EMS
           /= (if S.HC.Use_EMS then EMS_Negotiated else EMS_Absent)
         then
            Send_Alert_And_Error (S, Handshake_Failure, Result);
            return;
         end if;
         S.HC.T12.Resuming := True;
         S.HC.Master_Secret_12 := S.HC.Cfg.TLS12_Resume_Ticket.Master_Secret;
         Derive_Keys_Resumed_12 (S, D);
         S.HC.CKE_Received_12 := True;
         S.HC.CCS_Received := True;
         Result := OK;
         return;
      end if;

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK;
         return;
      end if;

      Have_Record := True;
      Result := OK;
   end Read_Server_Flight_Record;

   procedure Prepare_Leftover_Server_Flight_Message
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Msg_Type : out Maybe_HS_Msg;
      Msg_Len  : out N32;
      Ready    : out Boolean;
      Result   : out Action)
   with
     Pre  => SPARKTLS_Transcript.Started (S.HC.TS) and then Has_Message (D.Reasm),
     Post =>
       (if Ready
        then
          Result = OK
          and then Msg_Len <= Max_HS_Msg - 4
          and then
            (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
             then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local))
          and then
            (if SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local'Old)
             then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)));

   procedure Prepare_Leftover_Server_Flight_Message
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Msg_Type : out Maybe_HS_Msg;
      Msg_Len  : out N32;
      Ready    : out Boolean;
      Result   : out Action)
   is
      Parse_OK : Boolean;
   begin
      Msg_Type := HT_Unknown;
      Msg_Len := 0;
      Ready := False;
      pragma Assert (Has_Message (D.Reasm));  --  PROBE-T8
      Result := OK;

      Handshake.Parse_Handshake_Header (Byte_Seq (Message (D.Reasm)), Msg_Type, Msg_Len, Parse_OK);
      if not Parse_OK then
         declare
            Raw_Type : constant Byte := Message (D.Reasm) (0);
            Is_Known : constant Boolean :=
              Raw_Type
              in 16#01#
               | 16#02#
               | 16#04#
               | 16#08#
               | 16#0B#
               | 16#0C#
               | 16#0D#
               | 16#0E#
               | 16#0F#
               | 16#10#
               | 16#14#;
            Err      : constant Error_Code :=
              (if Is_Known then Decode_Error else Unexpected_Message);
            Desc     : constant Byte := (if Is_Known then 50 else 10);
         begin
            Reset (D.Reasm);
            if S.HC.CKE_Received_12 then
               Send_Encrypted_Finished_Error_12 (S, D, Desc, Err, Result);
            else
               Send_Alert_And_Error (S, Err, Result);
            end if;
         end;
         return;
      end if;
      if Message_Length (D.Reasm) > Transcript_Capacity then
         Reset (D.Reasm);
         Send_Alert_And_Error (S, Decode_Error, Result);
         return;
      end if;
      Ready := True;
      Result := OK;
   end Prepare_Leftover_Server_Flight_Message;

   procedure Decode_Pending_Reassembly_Header
     (D : in out SPARKTLS.HS_Pool.HS_Data; Failed : out Boolean)
   with Post => (if Failed then Used (D.Reasm) = 0);

   procedure Decode_Pending_Reassembly_Header
     (D : in out SPARKTLS.HS_Pool.HS_Data; Failed : out Boolean) is
   begin
      --  Nothing to decode into stored state: the buffer derives the declared
      --  size from its own header bytes. Only the peer-controlled bound check
      --  survives, and it is a protocol decision, not accounting.
      Failed := Message_Too_Large (D.Reasm);
      if Failed then
         Reset (D.Reasm);
      end if;
   end Decode_Pending_Reassembly_Header;

   procedure Continue_Server_Flight_Reassembly
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Rec      : in Records.Parse_Result;
      Msg_Type : out Maybe_HS_Msg;
      Msg_Len  : out N32;
      Ready    : out Boolean;
      Result   : out Action)
   with
     Pre  =>
       Rec.OK
       and then Rec.Content = Records.Content_Handshake
       and then Rec.Fragment_Pos <= N32'Last - Rec.Fragment_Len
       and then Rec.Record_Len = Rec.Fragment_Pos + Rec.Fragment_Len
       and then Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos
       and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
       and then not Has_Message (D.Reasm),
     Post => (if Ready then Result = OK and then Msg_Len <= Max_HS_Msg - 4);

   procedure Continue_Server_Flight_Reassembly
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Rec      : in Records.Parse_Result;
      Msg_Type : out Maybe_HS_Msg;
      Msg_Len  : out N32;
      Ready    : out Boolean;
      Result   : out Action)
   is
      FS       : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
      Frag_Len : constant N32 := Rec.Fragment_Len;
   begin
      Msg_Type := HT_Unknown;
      Msg_Len := 0;
      Ready := False;
      Result := OK;

      declare
         Copy_Len : constant HS_Msg_Len :=
           N32'Min (N32'Min (Wanted (D.Reasm), Frag_Len), Free_Space (D.Reasm));
      begin
         if Copy_Len > 0 then
            Append (D.Reasm, S.Input.Data (FS .. FS + Copy_Len - 1));
         end if;
      end;
      pragma Assert (Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos);
      pragma Assert (S.Input.Read_Pos <= N32'Last - Rec.Record_Len);
      S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

      if Header_Ready (D.Reasm) then
         declare
            Failed : Boolean;
         begin
            Decode_Pending_Reassembly_Header (D => D, Failed => Failed);
            if Failed then
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;
         end;
      end if;

      if not Has_Message (D.Reasm) then
         Result := OK;
         return;
      end if;

      Prepare_Leftover_Server_Flight_Message
        (S        => S,
         D        => D,
         Msg_Type => Msg_Type,
         Msg_Len  => Msg_Len,
         Ready    => Ready,
         Result   => Result);
   end Continue_Server_Flight_Reassembly;

   procedure Prepare_Fresh_Server_Flight_Message
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Rec      : in Records.Parse_Result;
      Msg_Type : out Maybe_HS_Msg;
      Msg_Len  : out N32;
      Ready    : out Boolean;
      Result   : out Action)
   with
     Pre  =>
       Rec.OK
       and then Rec.Content = Records.Content_Handshake
       and then Rec.Fragment_Pos <= N32'Last - Rec.Fragment_Len
       and then Rec.Record_Len = Rec.Fragment_Pos + Rec.Fragment_Len
       and then Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos
       and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len,
     Post => (if Ready then Result = OK and then Msg_Len <= Max_HS_Msg - 4);

   procedure Start_Fresh_Pending_Header_Reassembly
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Rec      : in Records.Parse_Result;
      FS       : in N32;
      Frag_Len : in N32;
      Result   : out Action)
   with
     Pre  =>
       Rec.OK
       and then Rec.Content = Records.Content_Handshake
       and then Rec.Fragment_Pos <= N32'Last - Rec.Fragment_Len
       and then Rec.Record_Len = Rec.Fragment_Pos + Rec.Fragment_Len
       and then Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos
       and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
       and then Frag_Len = Rec.Fragment_Len
       and then Frag_Len in 1 .. 3
       and then FS = S.Input.Read_Pos + Rec.Fragment_Pos
       and then FS + Frag_Len <= S.Input.Write_Pos,
     Post => Result = OK;

   procedure Start_Fresh_Pending_Header_Reassembly
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Rec      : in Records.Parse_Result;
      FS       : in N32;
      Frag_Len : in N32;
      Result   : out Action) is
   begin
      Reset (D.Reasm);
      Append (D.Reasm, S.Input.Data (FS .. FS + Frag_Len - 1));
      S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
      Result := OK;
   end Start_Fresh_Pending_Header_Reassembly;

   procedure Start_Fresh_Spanning_Reassembly
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Rec      : in Records.Parse_Result;
      FS       : in N32;
      Frag_Len : in N32;
      Msg_Len  : in N32;
      Result   : out Action)
   with
     Pre  =>
       Rec.OK
       and then Rec.Content = Records.Content_Handshake
       and then Rec.Fragment_Pos <= N32'Last - Rec.Fragment_Len
       and then Rec.Record_Len = Rec.Fragment_Pos + Rec.Fragment_Len
       and then Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos
       and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
       and then Frag_Len = Rec.Fragment_Len
       and then Frag_Len >= 4
       and then FS = S.Input.Read_Pos + Rec.Fragment_Pos
       and then FS + Frag_Len <= S.Input.Write_Pos
       and then Msg_Len <= Max_HS_Msg - 4
       and then Msg_Len + 4 > Frag_Len,
     Post => Result = OK;

   procedure Start_Fresh_Spanning_Reassembly
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Rec      : in Records.Parse_Result;
      FS       : in N32;
      Frag_Len : in N32;
      Msg_Len  : in N32;
      Result   : out Action)
   is
      Total : constant N32 := Msg_Len + 4;
   begin
      Reset (D.Reasm);
      Append (D.Reasm, S.Input.Data (FS .. FS + Frag_Len - 1));
      S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
      Result := OK;
   end Start_Fresh_Spanning_Reassembly;

   procedure Start_Fresh_Complete_Message
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Rec      : in Records.Parse_Result;
      FS       : in N32;
      Frag_Len : in N32;
      Msg_Len  : in N32;
      Result   : out Action)
   with
     Pre  =>
       Rec.OK
       and then Rec.Content = Records.Content_Handshake
       and then Rec.Fragment_Pos <= N32'Last - Rec.Fragment_Len
       and then Rec.Record_Len = Rec.Fragment_Pos + Rec.Fragment_Len
       and then Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos
       and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
       and then Frag_Len = Rec.Fragment_Len
       and then Frag_Len >= 4
       and then Frag_Len <= Max_HS_Msg
       and then FS = S.Input.Read_Pos + Rec.Fragment_Pos
       and then FS + Frag_Len <= S.Input.Write_Pos
       and then Msg_Len <= Frag_Len - 4
       and then Msg_Len <= Max_HS_Msg - 4,
     Post => Result = OK;

   procedure Start_Fresh_Complete_Message
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Rec      : in Records.Parse_Result;
      FS       : in N32;
      Frag_Len : in N32;
      Msg_Len  : in N32;
      Result   : out Action) is
   begin
      Reset (D.Reasm);
      Append (D.Reasm, S.Input.Data (FS .. FS + Frag_Len - 1));
      S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
      Result := OK;
   end Start_Fresh_Complete_Message;

   procedure Prepare_Fresh_Server_Flight_Message
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Rec      : in Records.Parse_Result;
      Msg_Type : out Maybe_HS_Msg;
      Msg_Len  : out N32;
      Ready    : out Boolean;
      Result   : out Action)
   is
      FS       : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
      Frag_Len : constant N32 := Rec.Fragment_Len;
      Parse_OK : Boolean;
   begin
      Msg_Type := HT_Unknown;
      Msg_Len := 0;
      Ready := False;
      Result := OK;

      if Frag_Len < 4 then
         if Frag_Len = 0 then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Alert_And_Error (S, Decode_Error, Result);
            return;
         end if;
         Start_Fresh_Pending_Header_Reassembly
           (S => S, D => D, Rec => Rec, FS => FS, Frag_Len => Frag_Len, Result => Result);
         return;
      end if;

      declare
         Frag : Byte_Seq renames S.Input.Data (FS .. FS + Frag_Len - 1);
      begin
         Handshake.Parse_Handshake_Header (Frag, Msg_Type, Msg_Len, Parse_OK);
      end;
      if not Parse_OK then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         declare
            Raw_Type : constant Byte := (if Frag_Len >= 1 then S.Input.Data (FS) else 0);
            Is_Known : constant Boolean :=
              Raw_Type
              in 16#01#
               | 16#02#
               | 16#04#
               | 16#08#
               | 16#0B#
               | 16#0C#
               | 16#0D#
               | 16#0E#
               | 16#0F#
               | 16#10#
               | 16#14#;
            Err      : constant Error_Code :=
              (if Is_Known then Decode_Error else Unexpected_Message);
            Desc     : constant Byte := (if Is_Known then 50 else 10);
         begin
            if S.HC.CKE_Received_12 then
               Send_Encrypted_Finished_Error_12 (S, D, Desc, Err, Result);
            else
               Send_Alert_And_Error (S, Err, Result);
            end if;
         end;
         return;
      end if;
      pragma Assert (Msg_Len <= Frag_Len - 4);

      if Msg_Len + 4 > Frag_Len then
         if Msg_Len + 4 > Max_HS_Msg then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if S.HC.CKE_Received_12 then
               Send_Encrypted_Finished_Error_12 (S, D, 50, Decode_Error, Result);
            else
               Send_Alert_And_Error (S, Decode_Error, Result);
            end if;
            return;
         end if;
         Start_Fresh_Spanning_Reassembly
           (S        => S,
            D        => D,
            Rec      => Rec,
            FS       => FS,
            Frag_Len => Frag_Len,
            Msg_Len  => Msg_Len,
            Result   => Result);
         return;
      end if;

      if Msg_Len + 4 > Transcript_Capacity then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         if S.HC.CKE_Received_12 then
            Send_Encrypted_Finished_Error_12 (S, D, 50, Decode_Error, Result);
         else
            Send_Alert_And_Error (S, Decode_Error, Result);
         end if;
         return;
      end if;

      Start_Fresh_Complete_Message
        (S        => S,
         D        => D,
         Rec      => Rec,
         FS       => FS,
         Frag_Len => Frag_Len,
         Msg_Len  => Msg_Len,
         Result   => Result);
      Ready := True;
      Result := OK;
   end Prepare_Fresh_Server_Flight_Message;

   procedure Prepare_Server_Flight_Message
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Msg_Type : out Maybe_HS_Msg;
      Msg_Len  : out N32;
      Ready    : out Boolean;
      Result   : out Action)
   with
     Pre  =>
       Warning_Alerts_Bounded_RFC_8446_6_1 (S)
       and then
         (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
          then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)),
     Post =>
       (if Ready
        then
          Result = OK
          and then Msg_Len <= Max_HS_Msg - 4
          and then Has_Message (D.Reasm)
          and then
            (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
             then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)));

   procedure Prepare_Server_Flight_Message
     (S        : in out Session;
      D        : in out SPARKTLS.HS_Pool.HS_Data;
      Msg_Type : out Maybe_HS_Msg;
      Msg_Len  : out N32;
      Ready    : out Boolean;
      Result   : out Action)
   is
      Rec               : Records.Parse_Result;
      Have_Leftover_Msg : constant Boolean := Has_Message (D.Reasm);
   begin
      Msg_Type := HT_Unknown;
      Msg_Len := 0;
      Ready := False;
      Result := OK;

      --  A declared size past the cap is a protocol error, not something to
      --  carry forward: the buffer can never hold the message it promises.
      if Message_Too_Large (D.Reasm) then
         Reset (D.Reasm);
         Send_Alert_And_Error (S, Decode_Error, Result);
         return;
      end if;

      if Have_Leftover_Msg then
         Prepare_Leftover_Server_Flight_Message
           (S        => S,
            D        => D,
            Msg_Type => Msg_Type,
            Msg_Len  => Msg_Len,
            Ready    => Ready,
            Result   => Result);
      else
         declare
            Have_Record : Boolean;
         begin
            Read_Server_Flight_Record
              (S => S, D => D, Rec => Rec, Have_Record => Have_Record, Result => Result);
            if not Have_Record then
               return;
            end if;
            pragma Assert (Rec.OK);
            pragma Assert (Rec.Content = Records.Content_Handshake);

            if Used (D.Reasm) > 0 and then not Has_Message (D.Reasm) then
               Continue_Server_Flight_Reassembly
                 (S        => S,
                  D        => D,
                  Rec      => Rec,
                  Msg_Type => Msg_Type,
                  Msg_Len  => Msg_Len,
                  Ready    => Ready,
                  Result   => Result);
            elsif Used (D.Reasm) > 0 then
               Prepare_Leftover_Server_Flight_Message
                 (S        => S,
                  D        => D,
                  Msg_Type => Msg_Type,
                  Msg_Len  => Msg_Len,
                  Ready    => Ready,
                  Result   => Result);
            else
               pragma Assert (not Have_Leftover_Msg);
               Reset (D.Reasm);
               Prepare_Fresh_Server_Flight_Message
                 (S        => S,
                  D        => D,
                  Rec      => Rec,
                  Msg_Type => Msg_Type,
                  Msg_Len  => Msg_Len,
                  Ready    => Ready,
                  Result   => Result);
            end if;
         end;
      end if;
   end Prepare_Server_Flight_Message;

   procedure Process_Server_Flight
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   is
      Msg_Type : Maybe_HS_Msg;
      Msg_Len  : N32;
      Ready    : Boolean;
   begin
      pragma
        Assert
          (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
           then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local));
      Prepare_Server_Flight_Message
        (S        => S,
         D        => D,
         Msg_Type => Msg_Type,
         Msg_Len  => Msg_Len,
         Ready    => Ready,
         Result   => Result);

      if not Ready then
         return;
      end if;

      Drain_Packed_Server_Flight
        (S => S, D => D, Msg_Type => Msg_Type, Msg_Len => Msg_Len, Result => Result);
   end Process_Server_Flight;

   ------------------------------------------------------------------
   --  Process_Server_CCS: receive CCS, activate server read keys
   ------------------------------------------------------------------

   procedure Process_Server_CCS
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   with
     Pre  =>
       Warning_Alerts_Bounded_RFC_8446_6_1 (S)
       and then
         (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
          then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local)),
     Post => True
   is
      Rec : Records.Parse_Result;

      procedure Consume_Reassembled_NST (Msg_Len : in N32; Result : out Action)
      with Pre => Msg_Len <= Max_HS_Msg - 4 and then Has_Message (D.Reasm);

      procedure Consume_Reassembled_NST (Msg_Len : in N32; Result : out Action) is
         pragma Assert (Has_Message (D.Reasm));  --  PROBE-T8
         NST_Msg : constant Message_Bytes := Message (D.Reasm);
      begin
         if NST_Msg (0) /= 16#04# or else Msg_Len < 6 then
            Send_Encrypted_Finished_Error_12
              (S,
               D,
               (if NST_Msg (0) = 16#04# then 50 else 10),
               (if NST_Msg (0) = 16#04# then Decode_Error else Unexpected_Message),
               Result);
            return;
         end if;

         declare
            NST_Body   : constant Byte_Seq (0 .. Msg_Len - 1) :=
              Byte_Seq (NST_Msg (4 .. 4 + Msg_Len - 1));
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
               Send_Encrypted_Finished_Error_12 (S, D, 50, Decode_Error, Result);
               return;
            end if;
            if Ticket_Len > 0 then
               S.TLS12_New_Ticket.Ticket (0 .. Ticket_Len - 1) :=
                 NST_Body (6 .. 6 + Ticket_Len - 1);
            end if;
            S.TLS12_New_Ticket.Ticket_Len := Ticket_Len;
            S.TLS12_New_Ticket.Suite := Wire_Of (S.Negotiated_Suite);
            S.TLS12_New_Ticket.Master_Secret := S.HC.Master_Secret_12;
            S.TLS12_New_Ticket.Lifetime_Hint := Lifetime;
            S.TLS12_New_Ticket.Server_Name := S.HC.Cfg.Server_Name;
            --  RFC 7627 s5.3: record whether THIS session negotiated EMS so a
            --  later resumption using this ticket can be checked against it.
            S.TLS12_New_Ticket.EMS := (if S.HC.Use_EMS then EMS_Negotiated else EMS_Absent);
            S.TLS12_New_Ticket.Valid := True;

            Append_Transcript (S.HC, Byte_Seq (NST_Msg));
            Reset (D.Reasm);
            Result := OK;
         end;
      end Consume_Reassembled_NST;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         return;
      end if;

      if Used (D.Reasm) > 0 then
         declare
            Msg_Type : Maybe_HS_Msg;
            Msg_Len  : N32;
            Ready    : Boolean;
         begin
            pragma
              Assert
                (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
                 then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local));
            Prepare_Server_Flight_Message
              (S        => S,
               D        => D,
               Msg_Type => Msg_Type,
               Msg_Len  => Msg_Len,
               Ready    => Ready,
               Result   => Result);
            if Result /= OK or else not Ready then
               return;
            end if;
            if Msg_Type /= HT_New_Session_Ticket then
               Send_Encrypted_Finished_Error_12 (S, D, 10, Unexpected_Message, Result);
               return;
            end if;
            Consume_Reassembled_NST (Msg_Len, Result);
            return;
         end;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1), Available (S.Input), Rec);

      if Rec.Bad_Version then
         S.Last_Error := Protocol_Version;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      if not Rec.OK then
         Result := Need_Input;
         return;
      end if;

      if Rec.Content = Records.Content_Change_Cipher_Spec then
         declare
            CCS_Pos     : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
            CCS_Byte_OK : constant Boolean :=
              Rec.Fragment_Len = 1 and then S.Input.Data (CCS_Pos) = 16#01#;
         begin
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            if S.HC.T12.Server_Will_Issue
              and then not S.HC.T12.Resuming
              and then not S.TLS12_New_Ticket.Valid
            then
               --  RFC 5077 3.3: if the server echoed the empty
               --  session_ticket extension in ServerHello, it MUST send
               --  NewSessionTicket before its ChangeCipherSpec.
               Send_Alert_And_Error (S, Unexpected_Message, Result);
               return;
            end if;
            if CCS_Byte_OK then
               S.HC.CCS_Received := True;
               Result := OK;
            else
               --  RFC 5246 7.1: ChangeCipherSpec payload MUST be the
               --  single byte 0x01. BoGo BadChangeCipherSpec-* sends
               --  other bytes / lengths â unexpected_message.
               Send_Alert_And_Error (S, Unexpected_Message, Result);
            end if;
         end;
      elsif Rec.Content = Records.Content_Handshake then
         --  RFC 5077 3.3 full-handshake NewSessionTicket arrives
         --  AFTER client CCS+Finished but BEFORE server CCS. The
         --  dispatcher routes here (post-client-CKE-flight, waiting
         --  for server CCS) so we need to consume the NST here. BoGo
         --  MaxHandshakeRecordLength=1 can split the NST across many
         --  handshake records, so reuse the server-flight reassembler
         --  rather than assuming the whole message is in this record.
         declare
            Msg_Type : Maybe_HS_Msg;
            Msg_Len  : N32;
            Ready    : Boolean;
         begin
            pragma
              Assert
                (if S.HC.Cfg.Local /= null and then S.HC.Cfg.Local.Has_Identity
                 then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (S.HC.Cfg.Local));
            Prepare_Server_Flight_Message
              (S        => S,
               D        => D,
               Msg_Type => Msg_Type,
               Msg_Len  => Msg_Len,
               Ready    => Ready,
               Result   => Result);
            if Result /= OK or else not Ready then
               return;
            end if;
            if Msg_Type /= HT_New_Session_Ticket then
               Send_Encrypted_Finished_Error_12 (S, D, 10, Unexpected_Message, Result);
               return;
            end if;
            Consume_Reassembled_NST (Msg_Len, Result);
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
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Desc_Code : in Byte;
      Err       : in Error_Code;
      Result    : out Action)
   is
      Dummy : N32;
   begin
      Records.TLS12.Build_Alert_Record_12
        (Level       => 2,
         Desc        => Desc_Code,
         Keys        => S.Client_App,
         Implicit_IV => S.HC.Client_Write_IV_12,
         Output      => S.Output,
         Bytes_Out   => Dummy);
      --  No rewind on Dummy = 0: this path sets Error_State below
      --  unconditionally, so the advanced counter is never used again.

      Reset (D.Reasm);
      S.Last_Error := Err;
      Set_State (S, Error_State);
      Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
   end Send_Encrypted_Finished_Error_12;

   procedure Copy_Finished_Reasm_Bytes_12
     (D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      PL        : in N32;
      P_Pos     : in out N32)
   with
     Pre  =>
       Plaintext'First = 0
       and then Plaintext'Last < IO_Buffer_Capacity
       and then PL > 0
       and then PL - 1 <= Plaintext'Last
       and then P_Pos <= PL,
     Post => P_Pos >= P_Pos'Old and P_Pos <= PL;

   procedure Copy_Finished_Reasm_Bytes_12
     (D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      PL        : in N32;
      P_Pos     : in out N32)
   is
      --  HS_Msg_Len, not N32: Take is bounded by Wanted and Free_Space, both
      --  of which are HS_Msg_Len. Declaring it N32 would throw that away and
      --  make every downstream bound re-derive it.
      Take : constant HS_Msg_Len :=
        N32'Min (N32'Min (Wanted (D.Reasm), PL - P_Pos), Free_Space (D.Reasm));
   begin
      if Take > 0 then
         Append (D.Reasm, Plaintext (P_Pos .. P_Pos + Take - 1));
         P_Pos := P_Pos + Take;
      end if;
   end Copy_Finished_Reasm_Bytes_12;

   procedure Accumulate_Finished_Plaintext_12
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      PL        : in N32;
      Complete  : out Boolean;
      Result    : out Action)
   with
     Pre  =>
       Plaintext'First = 0
       and then Plaintext'Last < IO_Buffer_Capacity
       and then PL > 0
       and then PL - 1 <= Plaintext'Last,
     Post =>
       (if Result = OK
        then S.State = S.State'Old and then (if Complete then Has_Message (D.Reasm)));

   procedure Accumulate_Finished_Plaintext_12
     (S         : in out Session;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      Plaintext : in Byte_Seq;
      PL        : in N32;
      Complete  : out Boolean;
      Result    : out Action)
   is
      P_Pos : N32 := 0;  --  bytes consumed from Plaintext
   begin
      Complete := False;
      Result := OK;

      --  First take completes the 4-byte header, which is what makes the
      --  declared size readable; the second takes as much of the body as
      --  this record carries.
      Copy_Finished_Reasm_Bytes_12 (D, Plaintext, PL, P_Pos);

      if Message_Too_Large (D.Reasm) then
         Reset (D.Reasm);
         Send_Alert_And_Error (S, Decode_Error, Result);
         return;
      end if;

      Copy_Finished_Reasm_Bytes_12 (D, Plaintext, PL, P_Pos);
      Complete := Has_Message (D.Reasm);

      --  RFC 5246 7.4.9: server Finished is the last server
      --  handshake message and must be the last thing in its
      --  TLS record. Any leftover plaintext after the Finished
      --  body is fatal unexpected_message (BoGo
      --  TrailingDataWithFinished-Client-TLS12). In the full
      --  handshake the client already sent CCS before waiting for
      --  the server Finished, so the alert is encrypted. In the
      --  abbreviated resume flow the client sends CCS after the
      --  server Finished, so the alert is still plaintext.
      if Complete and then P_Pos < PL then
         if S.HC.T12.Resuming then
            Send_Alert_And_Error (S, Unexpected_Message, Result);
         else
            Send_Encrypted_Finished_Error_12 (S, D, 10, Unexpected_Message, Result);
         end if;
         return;
      end if;
   end Accumulate_Finished_Plaintext_12;

   --  RFC 5077 3.3 abbreviated handshake client flight: CCS plus
   --  encrypted Finished. In the resumed flow the CLIENT sends these
   --  AFTER the server's Finished (inverse of the full handshake order
   --  where they were already sent). Atomic flight assembly: build
   --  into Scratch first; commit-fail paths are fatal (no rollback).
   procedure Send_Abbreviated_Client_Flight_12
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   with Post => (if Result = OK then S.State = S.State'Old);

   procedure Send_Abbreviated_Client_Flight_12
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   is
      use Records.TLS12;
      use Key_Schedule_12;
      Use_384 : constant Boolean :=
        S.Negotiated_Suite
        in Suite_ECDHE_RSA_AES256_GCM_SHA384 | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
      Scratch : IO_Buffer;
      CCS_Out : N32;
      FB      : Byte_Seq (0 .. Finished_12_Total_Len - 1);
      FL      : N32;
      TH      : Digest;
      TH4     : SPARKNaCl.Hashing.SHA384.Digest;
      EO      : N32;
   begin
      Result := OK;
      Records.Build_CCS_Record (Scratch, CCS_Out);
      if CCS_Out = 0 then
         Send_Alert_And_Error (S, Insufficient_Buffer, Result);
         return;
      end if;
      if Use_384 then
         SPARKTLS_Transcript.Current_384 (S.HC.TS, TH4);
         Build_Finished_12
           (S.HC.Master_Secret_12, Label_Client_Finished, Byte_Seq (TH4), True, FB, FL);
      else
         SPARKTLS_Transcript.Current_256 (S.HC.TS, TH);
         Build_Finished_12
           (S.HC.Master_Secret_12, Label_Client_Finished, Byte_Seq (TH), False, FB, FL);
      end if;
      Build_Encrypted_Record_12
        (FB (0 .. FL - 1), 16#16#, S.Client_App, S.HC.Client_Write_IV_12, Scratch, EO);
      --  Both failure paths below are fatal (Error_State): no counter
      --  rewind, the burned nonce stays burned.
      if EO = 0 then
         Send_Alert_And_Error (S, Insufficient_Buffer, Result);
         return;
      end if;
      if Free_Space (S.Output) < Scratch.Write_Pos then
         Send_Alert_And_Error (S, Insufficient_Buffer, Result);
         return;
      end if;
      S.Output.Data (S.Output.Write_Pos .. S.Output.Write_Pos + Scratch.Write_Pos - 1) :=
        Scratch.Data (0 .. Scratch.Write_Pos - 1);
      S.Output.Write_Pos := S.Output.Write_Pos + Scratch.Write_Pos;
   end Send_Abbreviated_Client_Flight_12;

   procedure Process_Server_Finished
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   is
      use Records.TLS12;
      use Key_Schedule_12;
      Rec     : Records.Parse_Result;
      Use_384 : constant Boolean :=
        S.Negotiated_Suite
        in Suite_ECDHE_RSA_AES256_GCM_SHA384 | Suite_ECDHE_ECDSA_AES256_GCM_SHA384;
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         return;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1), Available (S.Input), Rec);

      if Rec.Bad_Version then
         S.Last_Error := Protocol_Version;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      if not Rec.OK then
         Result := Need_Input;
         return;
      end if;

      if Rec.Content /= Records.Content_Handshake then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Send_Alert_And_Error (S, Unexpected_Message, Result);
         return;
      end if;

      --  Decrypt one encrypted record and append its plaintext to
      --  the reassembly buffer. BoGo's MaxHandshakeRecordLength=1 fragments
      --  the encrypted Finished into 16+ tiny records (each
      --  separately AEAD-encrypted with its own seq counter); we
      --  drain them into the same HC reassembly buffer until the
      --  full Finished message is in.
      declare
         Frag_Len  : constant N32 := Rec.Fragment_Len;
         FS        : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
         Encrypted : Byte_Seq (0 .. Frag_Len - 1);
         Hdr       : Byte_Seq (0 .. 4);
         Plaintext : Byte_Seq (0 .. Frag_Len - 1);
         PL        : N32;
         DV        : Boolean;
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
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;
            if Frag_Len < Min_Frag then
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               Send_Alert_And_Error (S, Decode_Error, Result);
               return;
            end if;
         end;

         Decrypt_Record_12
           (Encrypted, Hdr, S.Server_App, S.HC.Server_Write_IV_12, Plaintext, PL, DV);
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

         if not DV then
            Send_Alert_And_Error (S, Bad_Record_MAC, Result);
            return;
         end if;
         if PL = 0 then
            Send_Alert_And_Error (S, Decode_Error, Result);
            return;
         end if;

         declare
            Complete : Boolean;
         begin
            Accumulate_Finished_Plaintext_12 (S, D, Plaintext, PL, Complete, Result);
            if Result /= OK then
               return;
            end if;
            if not Complete then
               Result := OK;
               return;  --  more encrypted records to drain

            end if;
         end;

         if not Has_Message (D.Reasm) then
            Result := OK;
            return;  --  more encrypted records to drain

         end if;

         declare
            Fin      : constant Message_Bytes := Message (D.Reasm);
            RN       : constant N32 := Fin'Length;
            Msg_Type : constant Maybe_HS_Msg := HS_Msg_From_Wire (Fin (0));
            Msg_Len  : constant N32 := RN - 4;
         begin
            if Msg_Type /= HT_Finished or RN < 4 + Finished_Verify_Len then
               --  Wrong type or short body. We're post-CCS so the
               --  alert MUST be encrypted (server expects encrypted
               --  records after CCS  sending plaintext yields
               --  bad_record_mac on the peer). BoGo
               --  WrongMessageType-ServerFinished expects
               --  unexpected_message; we treat short body as
               --  decode_error.
               declare
                  Desc_Code : constant Byte :=
                    (if Msg_Type /= HT_Finished then AD_Unexpected_Message else AD_Decode_Error);
               begin
                  Send_Encrypted_Finished_Error_12
                    (S,
                     D,
                     Desc_Code,
                     (if Msg_Type /= HT_Finished then Unexpected_Message else Decode_Error),
                     Result);
               end;
               return;
            end if;
            if Msg_Len /= Finished_Verify_Len then
               --  Length mismatch on Finished  RFC 5246 7.4.9 +
               --  RFC 8446 6.2: decrypt_error (alert 51). We're
               --  post-CCS so the alert must be encrypted with our
               --  client_write_key, not plaintext.
               Send_Encrypted_Finished_Error_12 (S, D, 51, Certificate_Verify_Failed, Result);
               return;
            end if;
            --  Verify server Finished
            declare
               Exp : Verify_Data_12;
               TH  : Digest;
               TH4 : SPARKNaCl.Hashing.SHA384.Digest;
            begin
               if Use_384 then
                  SPARKTLS_Transcript.Current_384 (S.HC.TS, TH4);
                  Compute_Finished_12
                    (Exp, S.HC.Master_Secret_12, Label_Server_Finished, Byte_Seq (TH4), True);
               else
                  SPARKTLS_Transcript.Current_256 (S.HC.TS, TH);
                  Compute_Finished_12
                    (Exp, S.HC.Master_Secret_12, Label_Server_Finished, Byte_Seq (TH), False);
               end if;

               declare
                  Received : constant Verify_Data_12 :=
                    Verify_Data_12 (Fin (4 .. 4 + Finished_Verify_Len - 1));
               begin
                  if not Equal (Byte_Seq (Received), Byte_Seq (Exp)) then
                     Reset (D.Reasm);
                     Send_Alert_And_Error (S, Handshake_Failure, Result);
                     return;
                  end if;
               end;
            end;
         end;

         --  Append server Finished plaintext to transcript so the
         --  client's own Finished verify_data (computed below in the
         --  abbreviated path) covers it. Copy into a local first
         --  passing a slice of the reassembly buffer alongside `in out HC`
         --  is a SPARK 6.4.2 aliasing violation.
         declare
            Fin_Snap : constant Message_Bytes := Message (D.Reasm);
         begin
            pragma Assert (Fin_Snap'Length = Finished_12_Total_Len);
            Append_Transcript (S.HC, Byte_Seq (Fin_Snap));
         end;

         Reset (D.Reasm);
      end;

      --  RFC 5077 3.3 abbreviated handshake: in the resumed flow the
      --  CLIENT sends CCS+Finished AFTER the server's. In the full-HS
      --  case both records were sent before the server's Finished
      --  arrived, so this is a no-op.
      if S.HC.T12.Resuming then
         Send_Abbreviated_Client_Flight_12 (S, D, Result);
         if Result /= OK then
            return;
         end if;
      end if;

      --  Copy TLS 1.2 record state to Session.
      S.Client_IV_12 := S.HC.Client_Write_IV_12;
      S.Server_IV_12 := S.HC.Server_Write_IV_12;
      --  Sequence counters no longer mirrored: they live inside
      --  S.Client_App / S.Server_App, which are already Session state.

      Set_State (S, Connected);
      S.Handshake_Just_Done := True;
      Result := (if Output_Pending (S) > 0 then Has_Output else Handshake_Done);
      if Result = Handshake_Done then
         S.Handshake_Just_Done := False;
      end if;
   end Process_Server_Finished;

   ------------------------------------------------------------------
   --  Advance_Handshake_12: dispatch based on internal state
   ------------------------------------------------------------------

   procedure Advance_Handshake_12
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action) is
   begin
      --  Fail closed: Advance is public API and may be called in any
      --  state; the handshake machine must not run once the session is
      --  terminal. Reporting Error_Alert idempotently mirrors the Closed
      --  arm's idempotent Shutdown in Advance_Client_Non_Handshake.
      if S.State in Idle | Closing | Closed | Error_State then
         S.Last_Error := Internal_Error;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;

      if Output_Pending (S) > 0 then
         Result := Has_Output;
         return;
      end if;

      if not S.HC.CKE_Received_12 then
         --  Still processing server flight / sending client flight
         Process_Server_Flight (S, D, Result);
      elsif not S.HC.CCS_Received then
         --  Waiting for server CCS
         Process_Server_CCS (S, D, Result);
      else
         --  Waiting for server Finished
         Process_Server_Finished (S, D, Result);
      end if;
   end Advance_Handshake_12;

   ------------------------------------------------------------------
   --  Process_Connected_12: identical to Server.TLS12.Process_Connected_12
   ------------------------------------------------------------------

   procedure Process_Connected_12 (S : in out Session; Result : out Action) is
      use Records.TLS12;
      Rec : Records.Parse_Result;
   begin
      if Input_Available (S) = 0 then
         Result := (if Output_Pending (S) > 0 then Has_Output else Need_Input);
         return;
      end if;

      Records.Parse_Record_Header
        (S.Input.Data (S.Input.Read_Pos .. S.Input.Write_Pos - 1), Available (S.Input), Rec);

      if Rec.Bad_Version then
         S.Last_Error := Protocol_Version;
         Set_State (S, Error_State);
         Result := Error_Alert;
         return;
      end if;
      if not Rec.OK then
         Result := Need_Input;
         return;
      end if;

      --  The record length bound below is from Parse_Record_Header's Post
      --  (Record_Len <= Avail = Write_Pos - Read_Pos). Pin it here while
      --  the call's Avail argument is still in syntactic scope, so later
      --  asserts about FS + Frag_Len can chain.
      pragma Assert (Rec.Record_Len <= S.Input.Write_Pos - S.Input.Read_Pos);

      if Rec.Content = Records.Content_Change_Cipher_Spec then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK;
         return;
      end if;

      if Rec.Content not in Records.Content_Application_Data | Records.Content_Alert then
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
         Result := OK;
         return;
      end if;

      declare
         Frag_Len : constant N32 := Rec.Fragment_Len;
         FS       : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
      begin
         --  Reject records exceeding the TLS 1.2 max ciphertext size.
         --  A 16384-byte plaintext encrypts to exactly 16408 bytes
         --  (16384 + 8 explicit nonce + 16 tag), so the bound is
         --  strict-greater-than, not greater-or-equal  and matches
         --  Decrypt_Record_12's Pre (`Encrypted'Last <
         --  Max_Record_Plaintext + TLS12_Record_Overhead`).
         if Frag_Len > Max_Record_Plaintext + TLS12_Record_Overhead then
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
            Send_Encrypted_Alert_Connected_12 (S, Record_Overflow, Result);
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
            Hdr       : Byte_Seq (0 .. 4);
            Plaintext : Byte_Seq (0 .. Frag_Len - 1);
            PL        : N32;
            DV        : Boolean;
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
                  then GCM_Tag_Len
                  else Explicit_Nonce_Len + GCM_Tag_Len);
            begin
               if Frag_Len < Min_Frag then
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  Result := OK;
                  return;
               end if;
            end;

            --  RFC 5246 6.1: "If a TLS implementation would need to
            --  wrap a sequence number, it must renegotiate instead."
            --  We don't support renegotiation. Counter exhaustion now
            --  fails closed INSIDE Decrypt_Record_12 (Valid = False ->
            --  fatal alert below); the old pre-guard here tested
            --  = Unsigned_64'Last, which Record_Counter cannot even
            --  reach -- the #46 dead guard, deleted with the port.
            Decrypt_Record_12 (Encrypted, Hdr, S.Server_App, S.Server_IV_12, Plaintext, PL, DV);
            S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

            if not DV then
               Send_Encrypted_Alert_Connected_12 (S, Bad_Record_MAC, Result);
               return;
            end if;

            case Rec.Content is
               when Records.Content_Application_Data =>
                  if S.State = Closing and then PL > 0 then
                     Send_Encrypted_Alert_Connected_12 (S, Unexpected_Message, Result);
                  elsif PL > 0 and then S.App_Data_Len <= S.App_Data'Length - PL then
                     S.App_Data (S.App_Data_Len .. S.App_Data_Len + PL - 1) :=
                       Plaintext (0 .. PL - 1);
                     S.App_Data_Len := S.App_Data_Len + PL;
                     S.Empty_Records_Recvd := 0;
                     Result := Plaintext_Ready;
                  else
                     --  Check BEFORE incrementing: the counter then never exceeds the
                     --  cap, so the bound holds BY CONSTRUCTION rather than being
                     --  asserted. Behaviour is identical (the same alert/record
                     --  triggers the error either way) and it is what makes the
                     --  narrowed field subtype and its AoRTE check provable.
                     if S.Empty_Records_Recvd >= Max_Empty_Records then
                        S.Last_Error := Unexpected_Message;
                        Set_State (S, Error_State);
                        Result := Error_Alert;
                     else
                        S.Empty_Records_Recvd := S.Empty_Records_Recvd + 1;
                        Result := OK;
                     end if;
                     pragma Assert (Empty_Records_Bounded_RFC_8446_5_2 (S));
                  end if;

               when Records.Content_Alert            =>
                  --  RFC 5246 7.2: alerts have (level, description).
                  --  - close_notify (desc=0): peer is closing  initiate
                  --    Closing. Required regardless of level by 7.2.1.
                  --  - level=warning (1): MAY ignore. We ignore so BoGo
                  --    SendWarningAlerts-Pass /
                  --    AlternateEmptyRecordsAndWarningAlerts complete.
                  --  - level=fatal (2): connection MUST close. We just
                  --    record the error and stop reading; sending an
                  --    alert back would loop on every fatal we receive.
                  if PL >= 2 and then Plaintext (1) = 0 then
                     --  close_notify. RFC 8446 6.1 / RFC 5246 7.2.1:
                     --  record that the peer closed in an orderly way,
                     --  so the application can tell a finished stream
                     --  from one an attacker truncated. Also what lets
                     --  the Closing branch know the close is complete.
                     S.Peer_Closed_Cleanly := True;
                     if S.State = Connected then
                        Set_State (S, Closing);
                     end if;
                     Result := Shutdown;
                  elsif PL >= 1 and then Plaintext (0) = 1 then
                     --  warning (non-close_notify)  count + cap.
                     --  RFC 8446 6.1 / BoGo SendWarningAlerts-TooMany:
                     --  more than 4 in a connection â fatal
                     --  decode_error.
                     --  Check BEFORE incrementing: the counter then never exceeds the
                     --  cap, so the bound holds BY CONSTRUCTION rather than being
                     --  asserted. Behaviour is identical (the same alert/record
                     --  triggers the error either way) and it is what makes the
                     --  narrowed field subtype and its AoRTE check provable.
                     if S.Warning_Alerts_Recvd >= Max_Warning_Alerts then
                        S.Last_Error := Decode_Error;
                        Set_State (S, Error_State);
                        Result := Error_Alert;
                     else
                        S.Warning_Alerts_Recvd := S.Warning_Alerts_Recvd + 1;
                        Result := OK;
                     end if;
                  else
                     --  fatal alert from peer  record + close.
                     S.Last_Error := Unexpected_Message;
                     if S.State = Connected then
                        Set_State (S, Closing);
                     end if;
                     Result := Shutdown;
                  end if;

               when others                           =>
                  --  RFC 5246 s6 / RFC 8446 s5.1: an unrecognised record
                  --  content type is unexpected_message, not something to
                  --  skip. Silently returning OK let a peer feed us
                  --  records we neither processed nor rejected.
                  S.Last_Error := Unexpected_Message;
                  Set_State (S, Error_State);
                  Result := Error_Alert;
            end case;
         end;
      end;
   end Process_Connected_12;

end SPARKTLS.Client.TLS12;
