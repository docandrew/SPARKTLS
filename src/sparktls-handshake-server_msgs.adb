with Ada.Unchecked_Deallocation;
with Interfaces; use Interfaces;
with SPARKNaCl.Cryptobox;
with SPARKNaCl.Scalar;
with SPARKTLS.RFLX_Bridge;           use SPARKTLS.RFLX_Bridge;
with RFLX.TLS_Handshake.Client_Hello;
with RFLX.TLS_Handshake.Server_Hello;
with RFLX.TLS_Handshake.SH_Extensions_TLS;
with RFLX.TLS_Handshake.SH_Extension_TLS;
with RFLX.TLS_Handshake.CH_Extensions_TLS;
with RFLX.TLS_Handshake.CH_Extension_TLS;
with RFLX.TLS_Handshake.Key_Share_SH;
with RFLX.TLS_Handshake.Key_Share_CH;
with RFLX.TLS_Handshake.Key_Share_Entries;
with RFLX.TLS_Handshake.Key_Share_Entry;
with RFLX.TLS_Handshake.Cipher_Suites_TLS;
with RFLX.TLS_Handshake.Cipher_Suite_TLS;
with RFLX.TLS_Common;
with RFLX.TLS_Handshake.Encrypted_Extensions;
with RFLX.TLS_Handshake.TLS_Handshake;
with RFLX.TLS_Handshake.Certificate_Request;
with RFLX.TLS_Handshake.CR_Extensions;
with RFLX.TLS_Handshake.CR_Extension;
with RFLX.Tls_Parameters;
with RFLX.Tls_Extensiontype_Values;
with SPARKTLS.P256.Point;
with SPARKTLS.P384.Point;

package body SPARKTLS.Handshake.Server_Msgs with
   SPARK_Mode => On
is
   use type RBT.Length;
   use type RBT.Index;
   use type RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values_Enum;
   use type RFLX.Tls_Parameters.TLS_Supported_Groups_Enum;

   --  Deallocate an RFLX buffer.
   --  Body is SPARK_Mode Off (Unchecked_Deallocation of 'access all').
   --  Spec is On so SPARK can verify call sites.
   use type RBT.Bytes_Ptr;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr)
   with Post => Buf = null;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr)
   with SPARK_Mode => Off
   is
      procedure Dealloc is new Ada.Unchecked_Deallocation
        (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
   begin
      Dealloc (Buf);
   end RFLX_Free;

   procedure Parse_Client_Hello
     (S    : in out Session;
      HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   is
      use RFLX.TLS_Handshake.Client_Hello;
      Body_Len : N32;
      Buf      : RBT.Bytes_Ptr;
      Ctx      : Context;
   begin
      OK := False;

      if Data'Length < 39 then
         S.Last_Error := Decode_Error;
         return;
      end if;

      if Data (Data'First) /= HT_Client_Hello then
         S.Last_Error := Decode_Error;
         return;
      end if;

      --  Skip 4-byte handshake header, pass body to Client_Hello context
      Body_Len := N32 (Data'Length) - 4;

      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      Buf.all := To_RFLX (Data (Data'First + 4 .. Data'Last));
      Initialize (Ctx, Buf,
                  Written_Last => RBT.Bit_Length (RBT.Length (Body_Len) * 8));
      Verify_Message (Ctx);

      if not Well_Formed_Message (Ctx) then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         --  Check if the failure is due to wrong legacy_version.
         --  ClientHello body: legacy_version(2) at offset Data'First+4..+5.
         --  RFC 8446 §4.1.2: legacy_version MUST be 0x0303.
         if Data'Length >= 6 and then
            (Data (Data'First + 4) /= 16#03# or Data (Data'First + 5) /= 16#03#)
         then
            S.Last_Error := Protocol_Version;
         else
            S.Last_Error := Decode_Error;
         end if;
         return;
      end if;

      --  Extract client random (32 bytes)
      declare
         Random_Bytes : RBT.Bytes (1 .. 32);
      begin
         Get_Random (Ctx, Random_Bytes);
         HC.Client_Random := To_NaCl (Random_Bytes);
      end;

      --  Extract legacy session ID
      declare
         SID_Len : constant N32 :=
            N32 (Get_Legacy_Session_ID_Length (Ctx));
      begin
         HC.Legacy_Session_ID := (others => 0);
         if SID_Len > 0 and SID_Len <= 32 then
            declare
               SID : RBT.Bytes (1 .. RBT.Index (SID_Len));
            begin
               Get_Legacy_Session_ID (Ctx, SID);
               HC.Legacy_Session_ID (0 .. SID_Len - 1) := To_NaCl (SID);
            end;
         end if;
      end;

      --  Iterate cipher suites to find one we support
      --  Store best TLS 1.3 suite and best TLS 1.2 suite separately.
      --  Version negotiation later picks the right one.
      S.Negotiated_Suite := 0;
      S.Negotiated_Suite_12 := 0;

      if Well_Formed (Ctx, F_Cipher_Suites_TLS) then
         declare
            Suites_Ctx : RFLX.TLS_Handshake.Cipher_Suites_TLS.Context;
         begin
            Switch_To_Cipher_Suites_TLS (Ctx, Suites_Ctx);

            while RFLX.TLS_Handshake.Cipher_Suites_TLS.Has_Element
                    (Suites_Ctx)
            loop
               declare
                  Suite_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
               begin
                  RFLX.TLS_Handshake.Cipher_Suites_TLS.Switch
                    (Suites_Ctx, Suite_Ctx);
                  RFLX.TLS_Handshake.Cipher_Suite_TLS.Verify_Message
                    (Suite_Ctx);

                  if RFLX.TLS_Handshake.Cipher_Suite_TLS.Well_Formed_Message
                       (Suite_Ctx)
                  then
                     declare
                        Suite : constant
                           RFLX.Tls_Parameters.TLS_Cipher_Suites :=
                           RFLX.TLS_Handshake.Cipher_Suite_TLS.Get_Suite
                             (Suite_Ctx);
                        Val   : Unsigned_16;
                     begin
                        Val := Unsigned_16
                                 (RFLX.Tls_Parameters.To_Base_Integer
                                    (Suite));
                        --  TLS 1.3 suites (0x13xx)
                        if S.Negotiated_Suite = 0 and then
                           Val in Suite_AES_256_GCM_SHA384
                                | Suite_AES_128_GCM_SHA256
                                | Suite_CHACHA20_POLY1305_SHA256
                        then
                           S.Negotiated_Suite := Val;
                        end if;

                        --  TLS 1.2 suites (0xC0xx/0xCCxx)
                        if S.Negotiated_Suite_12 = 0 and then
                           Val in Suite_ECDHE_RSA_AES128_GCM_SHA256
                                | Suite_ECDHE_RSA_AES256_GCM_SHA384
                                | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                                | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                                | Suite_ECDHE_RSA_CHACHA20_SHA256
                                | Suite_ECDHE_ECDSA_CHACHA20_SHA256
                        then
                           S.Negotiated_Suite_12 := Val;
                        end if;
                     end;
                  end if;

                  RFLX.TLS_Handshake.Cipher_Suites_TLS.Update
                    (Suites_Ctx, Suite_Ctx);
               end;
            end loop;

            Update_Cipher_Suites_TLS (Ctx, Suites_Ctx);
         end;
      end if;

      --  Need at least one matching suite (either TLS 1.3 or 1.2)
      if S.Negotiated_Suite = 0 and S.Negotiated_Suite_12 = 0 then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         return;
      end if;

      --  Iterate extensions to find key_share (using RFLX)
      if Well_Formed (Ctx, F_Extensions_TLS) then
         declare
            Exts_Ctx : RFLX.TLS_Handshake.CH_Extensions_TLS.Context;
         begin
            Switch_To_Extensions_TLS (Ctx, Exts_Ctx);

            while RFLX.TLS_Handshake.CH_Extensions_TLS.Has_Element
                    (Exts_Ctx)
            loop
               declare
                  Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
               begin
                  RFLX.TLS_Handshake.CH_Extensions_TLS.Switch
                    (Exts_Ctx, Ext_Ctx);
                  RFLX.TLS_Handshake.CH_Extension_TLS.Verify_Message
                    (Ext_Ctx);

                  if RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message
                       (Ext_Ctx)
                  then
                     declare
                        Tag : constant
                           RFLX.Tls_Extensiontype_Values
                              .TLS_ExtensionType_Values :=
                           RFLX.TLS_Handshake.CH_Extension_TLS.Get_Tag
                             (Ext_Ctx);
                     begin
                        if Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values.Key_Share
                        then
                           --  Parse key share via Key_Share_CH
                           declare
                              DLen    : constant N32 := N32
                                 (RFLX.TLS_Handshake.CH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                              KS_Buf  : RBT.Bytes_Ptr;
                              KS_Ctx  : RFLX.TLS_Handshake
                                           .Key_Share_CH.Context;
                           begin
                              --  ClientHello key_share: max ~210 bytes
                              --  (x25519 + P-256 + P-384). Reject 0 or
                              --  unreasonably large values.
                              if DLen not in Wire_Key_Share_Len then
                                 null;  --  skip malformed key_share
                              else
                              declare
                                 VLen : constant Wire_Key_Share_Len := DLen;
                              begin
                              KS_Buf := new RBT.Bytes'(1 .. RBT.Index (VLen) => 0);
                              RFLX.TLS_Handshake.CH_Extension_TLS
                                .Get_Data (Ext_Ctx, KS_Buf.all);
                              RFLX.TLS_Handshake.Key_Share_CH.Initialize
                                (KS_Ctx, KS_Buf,
                                 Written_Last =>
                                    RBT.Bit_Length
                                       (RBT.Length (VLen) * 8));
                              RFLX.TLS_Handshake.Key_Share_CH
                                .Verify_Message (KS_Ctx);

                              if RFLX.TLS_Handshake.Key_Share_CH
                                   .Well_Formed_Message (KS_Ctx)
                              then
                                 --  Iterate key share entries
                                 declare
                                    Shares_Ctx :
                                       RFLX.TLS_Handshake
                                          .Key_Share_Entries.Context;
                                 begin
                                    RFLX.TLS_Handshake.Key_Share_CH
                                      .Switch_To_Shares
                                        (KS_Ctx, Shares_Ctx);

                                    while RFLX.TLS_Handshake
                                            .Key_Share_Entries
                                            .Has_Element (Shares_Ctx)
                                    loop
                                       declare
                                          E_Ctx :
                                             RFLX.TLS_Handshake
                                                .Key_Share_Entry.Context;
                                       begin
                                          RFLX.TLS_Handshake
                                            .Key_Share_Entries.Switch
                                              (Shares_Ctx, E_Ctx);
                                          RFLX.TLS_Handshake
                                            .Key_Share_Entry
                                            .Verify_Message (E_Ctx);

                                          if RFLX.TLS_Handshake
                                               .Key_Share_Entry
                                               .Well_Formed_Message (E_Ctx)
                                          then
                                             declare
                                                Grp : constant
                                                   RFLX.Tls_Parameters
                                                      .TLS_Supported_Groups
                                                   :=
                                                   RFLX.TLS_Handshake
                                                     .Key_Share_Entry
                                                     .Get_Group (E_Ctx);
                                             begin
                                                if Grp.Known then
                                                   if Grp.Enum =
                                                      RFLX.Tls_Parameters
                                                         .X25519
                                                   then
                                                      declare
                                                         KB : RBT.Bytes
                                                                (1 .. 32);
                                                      begin
                                                         RFLX.TLS_Handshake
                                                           .Key_Share_Entry
                                                           .Get_Key_Exchange
                                                             (E_Ctx, KB);
                                                         HC.Peer_PK :=
                                                            To_NaCl (KB);
                                                         HC.Client_Has_X25519
                                                            := True;
                                                      end;
                                                   elsif Grp.Enum =
                                                      RFLX.Tls_Parameters
                                                         .Secp256r1
                                                   then
                                                      declare
                                                         KLen : constant N32 :=
                                                            N32 (RFLX.TLS_Handshake
                                                               .Key_Share_Entry
                                                               .Get_Length
                                                                  (E_Ctx));
                                                      begin
                                                         if KLen = 65 then
                                                            declare
                                                               KB : RBT.Bytes (1 .. 65);
                                                            begin
                                                               RFLX.TLS_Handshake
                                                                 .Key_Share_Entry
                                                                 .Get_Key_Exchange
                                                                   (E_Ctx, KB);
                                                               for I in N32 range 0 .. 64 loop
                                                                  HC.P256_Peer_PK (I) :=
                                                                     Byte (KB (RBT.Index (I + 1)));
                                                               end loop;
                                                               HC.Client_Has_P256
                                                                  := True;
                                                            end;
                                                         end if;
                                                      end;
                                                   elsif Grp.Enum =
                                                      RFLX.Tls_Parameters
                                                         .Secp384r1
                                                   then
                                                      declare
                                                         KLen : constant N32 :=
                                                            N32 (RFLX.TLS_Handshake
                                                               .Key_Share_Entry
                                                               .Get_Length
                                                                  (E_Ctx));
                                                      begin
                                                         if KLen = 97 then
                                                            declare
                                                               KB : RBT.Bytes (1 .. 97);
                                                            begin
                                                               RFLX.TLS_Handshake
                                                                 .Key_Share_Entry
                                                                 .Get_Key_Exchange
                                                                   (E_Ctx, KB);
                                                               for I in N32 range 0 .. 96 loop
                                                                  HC.P384_Peer_PK (I) :=
                                                                     Byte (KB (RBT.Index (I + 1)));
                                                               end loop;
                                                               HC.Client_Has_P384
                                                                  := True;
                                                            end;
                                                         end if;
                                                      end;
                                                   end if;
                                                end if;
                                             end;
                                          end if;

                                          RFLX.TLS_Handshake
                                            .Key_Share_Entries.Update
                                              (Shares_Ctx, E_Ctx);
                                       end;
                                    end loop;

                                    RFLX.TLS_Handshake.Key_Share_CH
                                      .Update_Shares
                                        (KS_Ctx, Shares_Ctx);
                                 end;
                              end if;

                              RFLX.TLS_Handshake.Key_Share_CH
                                .Take_Buffer (KS_Ctx, KS_Buf);
                              RFLX_Free (KS_Buf);
                              end;  --  VLen declare
                              end if;  --  DLen validation
                           end;

                        elsif Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values
                                 .Signature_Algorithms
                        then
                           declare
                              DLen : constant N32 := N32
                                 (RFLX.TLS_Handshake.CH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                           begin
                              --  Validate internal list_length:
                              --  Must have list_len(2) + at least one algo(2),
                              --  list_len must equal DLen - 2 and be even.
                              if DLen not in Wire_Ext_Len or else DLen < 4 then
                                 Take_Buffer (Ctx, Buf);
                                 RFLX_Free (Buf);
                                 S.Last_Error := Decode_Error;
                                 return;
                              end if;

                              --  Heap-allocate to avoid stack overflow
                              --  on large sig_algs lists (32K+ entries).
                              declare
                                 VLen   : constant Wire_Ext_Len := DLen;
                                 SA_Buf : RBT.Bytes_Ptr :=
                                    new RBT.Bytes'(1 .. RBT.Index (VLen) => 0);
                                 Pos : RBT.Index := 3;
                                 List_Len : N32;
                              begin
                                 RFLX.TLS_Handshake.CH_Extension_TLS
                                   .Get_Data (Ext_Ctx, SA_Buf.all);
                                 List_Len :=
                                    N32 (SA_Buf (1)) * 256 +
                                    N32 (SA_Buf (2));
                                 if List_Len /= DLen - 2 or else
                                    List_Len mod 2 /= 0 or else
                                    List_Len = 0
                                 then
                                    RFLX_Free (SA_Buf);
                                    Take_Buffer (Ctx, Buf);
                                    RFLX_Free (Buf);
                                    S.Last_Error := Decode_Error;
                                    return;
                                 end if;
                                 while Pos + 1 <= RBT.Index (DLen) loop
                                    declare
                                       Algo : constant Unsigned_16 :=
                                          Unsigned_16 (SA_Buf (Pos)) * 256 +
                                          Unsigned_16 (SA_Buf (Pos + 1));
                                    begin
                                       --  Only store algorithms we support,
                                       --  so the array never overflows
                                       --  regardless of client list size.
                                       if Algo in 16#0807# |  --  Ed25519
                                                  16#0403# |  --  ECDSA-P256
                                                  16#0503# |  --  ECDSA-P384
                                                  16#0804# |  --  RSA-PSS-256
                                                  16#0805# |  --  RSA-PSS-384
                                                  16#0806#    --  RSA-PSS-512
                                          and then HC.Peer_Sig_Algo_Count <
                                                      Max_Sig_Algos
                                       then
                                          HC.Peer_Sig_Algos
                                            (HC.Peer_Sig_Algo_Count) := Algo;
                                          HC.Peer_Sig_Algo_Count :=
                                             HC.Peer_Sig_Algo_Count + 1;
                                       end if;
                                    end;
                                    Pos := Pos + 2;
                                 end loop;
                                 RFLX_Free (SA_Buf);
                              end;
                           end;

                        --  supported_groups extension (0x000A)
                        --  Used by TLS 1.2 to signal supported ECDHE curves
                        --  (TLS 1.3 also uses this alongside key_share)
                        elsif Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values.Supported_Groups
                        then
                           declare
                              DLen : constant N32 := N32
                                 (RFLX.TLS_Handshake.CH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                           begin
                              --  supported_groups: max ~100 groups = 202 bytes
                              if DLen in Wire_Small_Ext_Len and then DLen >= 4 then
                                 declare
                                    VLen   : constant Wire_Small_Ext_Len := DLen;
                                    SG_Buf : RBT.Bytes_Ptr :=
                                       new RBT.Bytes'
                                         (1 .. RBT.Index (VLen) => 0);
                                    List_Len : N32;
                                    Pos : N32;
                                 begin
                                    RFLX.TLS_Handshake.CH_Extension_TLS
                                      .Get_Data (Ext_Ctx, SG_Buf.all);
                                    List_Len :=
                                       N32 (SG_Buf (1)) * 256 +
                                       N32 (SG_Buf (2));
                                    Pos := 3;
                                    while Pos + 1 <= N32 (DLen)
                                       and then Pos < 3 + List_Len
                                    loop
                                       declare
                                          Grp : constant Unsigned_16 :=
                                             Unsigned_16 (SG_Buf (RBT.Index (Pos))) * 256 +
                                             Unsigned_16 (SG_Buf (RBT.Index (Pos + 1)));
                                       begin
                                          if Grp = 16#001D# then
                                             HC.Client_Supports_X25519 := True;
                                          elsif Grp = 16#0017# then
                                             HC.Client_Supports_P256 := True;
                                          elsif Grp = 16#0018# then
                                             HC.Client_Supports_P384 := True;
                                          end if;
                                       end;
                                       Pos := Pos + 2;
                                    end loop;
                                    RFLX_Free (SG_Buf);
                                 end;
                              end if;
                           end;

                        --  pre_shared_key extension (0x0029)
                        elsif Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values.Pre_Shared_Key
                        then
                           --  Parse PSK identities to find a ticket we recognize
                           declare
                              DLen : constant N32 := N32
                                 (RFLX.TLS_Handshake.CH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                              --  Cap at 1024 to prevent stack overflow
                              --  on pathological inputs.
                              Max_PSK_Ext : constant N32 := 1024;
                           begin
                              if DLen >= 6 and then DLen <= Max_PSK_Ext then
                                 declare
                                    ED : aliased RBT.Bytes
                                       (1 .. RBT.Index (DLen));
                                    Ext_Data : Byte_Seq (0 .. DLen - 1);
                                 begin
                                    RFLX.TLS_Handshake.CH_Extension_TLS
                                       .Get_Data (Ext_Ctx, ED);
                                    Ext_Data := To_NaCl (ED);

                                 --  identities_len(2) + first identity
                                 declare
                                    IDs_Len : constant N32 :=
                                       N32 (Ext_Data (0)) * 256 +
                                       N32 (Ext_Data (1));
                                    P : N32 := 2;
                                 begin
                                    if P + 2 <= DLen and then
                                       IDs_Len > 0
                                    then
                                       --  First identity: len(2) + ticket + age(4)
                                       declare
                                          Tick_Len : constant N32 :=
                                             N32 (Ext_Data (P)) * 256 +
                                             N32 (Ext_Data (P + 1));
                                       begin
                                          P := P + 2;
                                          if P + Tick_Len + 4 <= DLen
                                             and then Tick_Len = Ticket_ID_Len
                                          then
                                             HC.PSK_Ticket_ID :=
                                                Ext_Data (P .. P + Tick_Len - 1);
                                             HC.PSK_Offered := True;

                                             --  Skip to binders list
                                             --  (past all identities: 2 + IDs_Len)
                                             declare
                                                Binders_Start : constant N32 :=
                                                   2 + IDs_Len;
                                             begin
                                                if Binders_Start + 2 < DLen then
                                                   declare
                                                      Binders_Len : constant N32 :=
                                                         N32 (Ext_Data (Binders_Start)) * 256 +
                                                         N32 (Ext_Data (Binders_Start + 1));
                                                      B_Pos : constant N32 := Binders_Start + 2;
                                                   begin
                                                      if B_Pos < DLen then
                                                         declare
                                                            B_Len : constant N32 :=
                                                               N32 (Ext_Data (B_Pos));
                                                         begin
                                                            if B_Len in 32 | 48
                                                               and then B_Pos + 1 + B_Len <= DLen
                                                            then
                                                               for I in N32 range 0 .. B_Len - 1 loop
                                                                  HC.PSK_Binder (I) :=
                                                                     Ext_Data (B_Pos + 1 + I);
                                                               end loop;
                                                               HC.PSK_Binder_Len := B_Len;
                                                               --  Record binders offset relative
                                                               --  to the extension data start
                                                               HC.PSK_Binders_Offset := Binders_Start;
                                                            end if;
                                                         end;
                                                      end if;
                                                   end;
                                                end if;
                                             end;
                                          end if;
                                       end;
                                    end if;
                                 end;
                                 end;
                              end if;
                           end;

                        --  supported_versions extension (0x002B)
                        --  RFC 8446 §4.2.1: list_len(1) || version(2)...
                        elsif Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values.Supported_Versions
                        then
                           declare
                              DLen : constant N32 := N32
                                 (RFLX.TLS_Handshake.CH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                           begin
                              --  supported_versions: max ~50 versions = 101 bytes
                              if DLen in Wire_Small_Ext_Len and then DLen >= 3 then
                                 declare
                                    VLen   : constant Wire_Small_Ext_Len := DLen;
                                    SV_Buf : RBT.Bytes_Ptr :=
                                       new RBT.Bytes'
                                         (1 .. RBT.Index (VLen) => 0);
                                    List_Len : N32;
                                    Pos : N32;
                                 begin
                                    RFLX.TLS_Handshake.CH_Extension_TLS
                                      .Get_Data (Ext_Ctx, SV_Buf.all);
                                    List_Len := N32 (SV_Buf (1));
                                    Pos := 2;
                                    while Pos + 1 <= N32 (DLen)
                                       and then Pos < 2 + List_Len
                                    loop
                                       if N32 (SV_Buf (RBT.Index (Pos))) = 3
                                          and then N32 (SV_Buf (RBT.Index (Pos + 1))) = 4
                                       then
                                          HC.Has_TLS_1_3 := True;
                                       end if;
                                       Pos := Pos + 2;
                                    end loop;
                                    RFLX_Free (SV_Buf);
                                 end;
                              end if;
                           end;

                        --  ALPN extension (0x0010)
                        elsif Tag.Known and then
                           Tag.Enum =
                              RFLX.Tls_Extensiontype_Values
                                .Application_Layer_Protocol_Negotiation
                        then
                           declare
                              DLen : constant N32 := N32
                                 (RFLX.TLS_Handshake.CH_Extension_TLS
                                    .Get_Data_Length (Ext_Ctx));
                           begin
                              if DLen in Wire_Small_Ext_Len and then DLen >= 4 then
                                 declare
                                    VLen : constant Wire_Small_Ext_Len := DLen;
                                    AB   : RBT.Bytes_Ptr :=
                                       new RBT.Bytes'
                                         (1 .. RBT.Index (VLen) => 0);
                                 begin
                                    RFLX.TLS_Handshake.CH_Extension_TLS
                                      .Get_Data (Ext_Ctx, AB.all);
                                    declare
                                       PL : constant Natural :=
                                          Natural (AB (3));
                                    begin
                                       if PL > 0
                                          and PL <= Max_Hostname_Len
                                          and N32 (PL + 3) <= DLen
                                       then
                                          HC.Client_ALPN.Len := PL;
                                          for I in 1 .. PL loop
                                             HC.Client_ALPN.Data (I) :=
                                                Character'Val
                                                  (AB (RBT.Index (3 + I)));
                                          end loop;
                                       end if;
                                    end;
                                    RFLX_Free (AB);
                                 end;
                              end if;
                           end;

                        end if;
                     end;
                  end if;

                  RFLX.TLS_Handshake.CH_Extensions_TLS.Update
                    (Exts_Ctx, Ext_Ctx);
               end;
            end loop;

            Update_Extensions_TLS (Ctx, Exts_Ctx);
         end;
      end if;

      Take_Buffer (Ctx, Buf);
      RFLX_Free (Buf);

      --  Set version based on supported_versions parsing.
      --  If the client offered TLS 1.3 (0x0304), use it.
      --  Otherwise fall back to TLS 1.2.
      if HC.Has_TLS_1_3 then
         HC.Version := TLS_1_3;
      else
         HC.Version := TLS_1_2;
      end if;

      --  Shared secret computation deferred to Build_Server_Hello
      --  where we know which group to select.

      OK := True;
   end Parse_Client_Hello;

   --================================================================
   --  Server-side build procedures
   --================================================================

   procedure Build_Server_Hello
     (S      : in out Session;
      HC     : in out Handshake_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
      use RFLX.TLS_Handshake.Server_Hello;
      use RFLX.TLS_Common;

      SK : SPARKNaCl.Cryptobox.Secret_Key;
      PK : SPARKNaCl.Cryptobox.Public_Key;

      procedure Gen_Random (Output : out Byte_Seq) renames HC.Cfg.Random.all;

      function To_Suite_Enum (Val : Unsigned_16)
         return RFLX.Tls_Parameters.TLS_Cipher_Suites_Enum
      is
      begin
         case Val is
            when Suite_AES_128_GCM_SHA256 =>
               return RFLX.Tls_Parameters.TLS_AES_128_GCM_SHA256;
            when Suite_AES_256_GCM_SHA384 =>
               return RFLX.Tls_Parameters.TLS_AES_256_GCM_SHA384;
            when others =>
               return RFLX.Tls_Parameters.TLS_CHACHA20_POLY1305_SHA256;
         end case;
      end To_Suite_Enum;

      SV_Data_Len : constant := 2;

      --  Key share data: varies by selected group
      KS_Raw     : Byte_Seq (0 .. 103) := (others => 0);  --  max P-384: 4+97
      KS_Raw_Len : N32 := 0;

      KS_Data_Len : N32;
      Ext_Total   : N32;
      SH_Body_Len : N32;
      SH_Msg_Len  : N32;

      Buf      : RBT.Bytes_Ptr;
      Ctx      : Context;
   begin
      Result := (others => 0);
      Len    := 0;

      --  Generate server random
      Gen_Random (HC.Server_Random);

      --  Select key exchange group (prefer x25519 > P-256 > P-384)
      HC.Shared_Secret := (others => 0);
      if HC.Client_Has_X25519 then
         HC.Selected_Group := 16#001D#;
         declare
            PK_X : SPARKNaCl.Cryptobox.Public_Key;
         begin
            Gen_Random (HC.Local_SK);
            SPARKNaCl.Cryptobox.Keypair (HC.Local_SK, PK_X, SK);
            HC.Shared_Secret (0 .. 31) :=
               SPARKNaCl.Scalar.Mult (HC.Local_SK, HC.Peer_PK);
            declare
               PK_Bytes : constant Bytes_32 :=
                  SPARKNaCl.Cryptobox.Serialize (PK_X);
            begin
               --  group(2) + key_len(2) + key(32) = 36
               KS_Raw (0) := 0; KS_Raw (1) := 16#1D#;  --  x25519
               KS_Raw (2) := 0; KS_Raw (3) := 32;
               for I in N32 range 0 .. 31 loop
                  KS_Raw (4 + I) := PK_Bytes (I);
               end loop;
               KS_Raw_Len := 36;
            end;
         end;

      elsif HC.Client_Has_P256 then
         HC.Selected_Group := 16#0017#;
         declare
            use SPARKTLS.P256.Point;
            PK_Jac  : P256_Jacobian;
            PK_Enc  : Byte_Seq (0 .. 64);
            Peer_Pt : P256_Jacobian;
            Valid   : SPARKNaCl.U32;
         begin
            Gen_Random (HC.P256_Local_SK);
            --  Our public key
            P256_Mulgen (PK_Jac, HC.P256_Local_SK, 32);
            P256_To_Affine (PK_Jac);
            P256_Encode (PK_Enc, PK_Jac);
            --  Shared secret: x-coord of [our_sk] * peer_pk
            P256_Decode (Peer_Pt, HC.P256_Peer_PK, Valid);
            if Valid = 0 then return; end if;
            P256_Mul (Peer_Pt, HC.P256_Local_SK, 32);
            P256_To_Affine (Peer_Pt);
            declare
               Enc : Byte_Seq (0 .. 64);
            begin
               P256_Encode (Enc, Peer_Pt);
               HC.Shared_Secret := (others => 0);
               HC.Shared_Secret (0 .. 31) := Enc (1 .. 32);
            end;
            --  group(2) + key_len(2) + key(65) = 69
            KS_Raw (0) := 0; KS_Raw (1) := 16#17#;
            KS_Raw (2) := 0; KS_Raw (3) := 65;
            for I in N32 range 0 .. 64 loop
               KS_Raw (4 + I) := PK_Enc (I);
            end loop;
            KS_Raw_Len := 69;
         end;

      elsif HC.Client_Has_P384 then
         HC.Selected_Group := 16#0018#;
         declare
            PK_Enc : Byte_Seq (0 .. 96);
            SS     : Bytes_48;
            SS_OK  : Boolean;
         begin
            Gen_Random (Byte_Seq (HC.P384_Local_SK));
            SPARKTLS.P384.Point.P384_Mulgen (PK_Enc, HC.P384_Local_SK);
            SPARKTLS.P384.Point.P384_ECDHE
              (Secret  => SS,
               OK      => SS_OK,
               SK      => HC.P384_Local_SK,
               Peer_PK => HC.P384_Peer_PK);
            if not SS_OK then return; end if;
            HC.Shared_Secret := SS;
            --  group(2) + key_len(2) + key(97) = 101
            KS_Raw (0) := 0; KS_Raw (1) := 16#18#;
            KS_Raw (2) := 0; KS_Raw (3) := 97;
            for I in N32 range 0 .. 96 loop
               KS_Raw (4 + I) := PK_Enc (I);
            end loop;
            KS_Raw_Len := 101;
         end;

      else
         --  No common key exchange group.
         --  Set Len = 0; caller will send handshake_failure alert.
         Len := 0;
         return;
      end if;

      KS_Data_Len := KS_Raw_Len;
      Ext_Total := (4 + KS_Data_Len) + (4 + SV_Data_Len);
      SH_Body_Len := 72 + Ext_Total;  --  version(2)+random(32)+sid_len(1)+sid(32)+suite(2)+comp(1)+ext_len(2)
      SH_Msg_Len := 4 + SH_Body_Len;

      --  Allocate buffer for ServerHello body
      Buf := new RBT.Bytes'(1 .. RBT.Index (RFLX_Main_Size) => 0);
      Initialize (Ctx, Buf);

      --  Set ServerHello fields via RFLX
      Set_Legacy_Version (Ctx, TLS_1_2);
      Set_Random (Ctx, To_RFLX (HC.Server_Random));
      Set_Legacy_Session_ID_Length (Ctx, 32);
      Set_Legacy_Session_ID (Ctx, To_RFLX (HC.Legacy_Session_ID));
      Set_Cipher_Suite_TLS_Suite (Ctx, To_Suite_Enum (S.Negotiated_Suite));
      Set_Legacy_Compression_Method (Ctx, 0);
      Set_Extensions_Length
        (Ctx, RFLX.TLS_Handshake.Server_Hello_Extensions_Length (Ext_Total));

      --  Build extensions sequence
      declare
         Exts_Ctx : RFLX.TLS_Handshake.SH_Extensions_TLS.Context;
      begin
         Switch_To_Extensions_TLS (Ctx, Exts_Ctx);

         --  Extension 1: key_share (0x0033)
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
         begin
            --  KS_Raw already populated with the selected group's key share

            Ext_Buf := new RBT.Bytes'(1 .. RBT.Index (4 + KS_Data_Len) => 0);
            RFLX.TLS_Handshake.SH_Extension_TLS.Initialize (Ext_Ctx, Ext_Buf);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Tag
              (Ext_Ctx, RFLX.Tls_Extensiontype_Values.Key_Share);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data_Length
              (Ext_Ctx, RFLX.TLS_Handshake.Data_Length (KS_Data_Len));
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data
              (Ext_Ctx, To_RFLX (KS_Raw (0 .. KS_Raw_Len - 1)));

            RFLX.TLS_Handshake.SH_Extensions_TLS.Append_Element
              (Exts_Ctx, Ext_Ctx);

            RFLX.TLS_Handshake.SH_Extension_TLS.Take_Buffer
              (Ext_Ctx, Ext_Buf);
            RFLX_Free (Ext_Buf);
         end;

         --  Extension 2: supported_versions (0x002B)
         declare
            Ext_Buf : RBT.Bytes_Ptr;
            Ext_Ctx : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
            SV_Raw  : Byte_Seq (0 .. SV_Data_Len - 1);
         begin
            SV_Raw (0) := 16#03#;
            SV_Raw (1) := 16#04#;  --  TLS 1.3

            Ext_Buf := new RBT.Bytes'(1 .. RBT.Index (4 + SV_Data_Len) => 0);
            RFLX.TLS_Handshake.SH_Extension_TLS.Initialize (Ext_Ctx, Ext_Buf);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Tag
              (Ext_Ctx, RFLX.Tls_Extensiontype_Values.Supported_Versions);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data_Length
              (Ext_Ctx, SV_Data_Len);
            RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data
              (Ext_Ctx, To_RFLX (SV_Raw));

            RFLX.TLS_Handshake.SH_Extensions_TLS.Append_Element
              (Exts_Ctx, Ext_Ctx);

            RFLX.TLS_Handshake.SH_Extension_TLS.Take_Buffer
              (Ext_Ctx, Ext_Buf);
            RFLX_Free (Ext_Buf);
         end;

         Update_Extensions_TLS (Ctx, Exts_Ctx);
      end;

      --  Extract serialized body and prepend handshake header
      Take_Buffer (Ctx, Buf);

      if SH_Msg_Len > N32 (Result'Length) then
         RFLX_Free (Buf);
         return;
      end if;

      Result (0) := HT_Server_Hello;
      Result (1) := Byte (SH_Body_Len / 65536);
      Result (2) := Byte ((SH_Body_Len / 256) mod 256);
      Result (3) := Byte (SH_Body_Len mod 256);
      Result (4 .. 4 + SH_Body_Len - 1) :=
         To_NaCl (Buf.all (1 .. RBT.Index (SH_Body_Len)));

      RFLX_Free (Buf);
      Len := SH_Msg_Len;

      --  If using PSK, append pre_shared_key extension to ServerHello.
      --  Format: tag(2) + data_len(2) + selected_identity(2) = 6 bytes.
      if HC.Using_PSK and then Len > 0 then
         declare
            PSK_Ext_Len : constant N32 := 6;
            New_Len     : constant N32 := Len + PSK_Ext_Len;
            --  Extension list length offset: after handshake header(4) +
            --  version(2) + random(32) + sid_len(1) + sid(32) + suite(2) +
            --  comp(1) = 74
            Ext_Len_Offset : constant N32 := 4 + 2 + 32 + 1 + 32 + 2 + 1;
            Old_Ext_Len : N32;
            P : N32;
         begin
            if New_Len <= N32 (Result'Length) then
               Old_Ext_Len := N32 (Result (Ext_Len_Offset)) * 256 +
                               N32 (Result (Ext_Len_Offset + 1));

               P := Len;
               --  pre_shared_key tag (0x0029)
               Result (P) := 0; Result (P + 1) := 16#29#;
               --  data_len (2)
               Result (P + 2) := 0; Result (P + 3) := 2;
               --  selected_identity (0 = first PSK)
               Result (P + 4) := 0; Result (P + 5) := 0;
               P := P + PSK_Ext_Len;

               --  Patch extensions length
               declare
                  New_Ext_Len : constant N32 := Old_Ext_Len + PSK_Ext_Len;
               begin
                  Result (Ext_Len_Offset) := Byte (New_Ext_Len / 256);
                  Result (Ext_Len_Offset + 1) := Byte (New_Ext_Len mod 256);
               end;

               --  Patch handshake body length
               declare
                  New_Body_Len : constant N32 := P - 4;
               begin
                  Result (1) := Byte (New_Body_Len / 65536);
                  Result (2) := Byte ((New_Body_Len / 256) mod 256);
                  Result (3) := Byte (New_Body_Len mod 256);
               end;

               Len := P;
            end if;
         end;
      end if;
   end Build_Server_Hello;

   procedure Build_Encrypted_Extensions
     (HC     : in     Handshake_Context;
      S      : in out Session;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
      --  Check if ALPN should be included
      ALPN_Match : constant Boolean :=
         HC.Client_ALPN.Len > 0
         and then HC.Cfg.ALPN.Len > 0
         and then HC.Client_ALPN.Data (1 .. HC.Client_ALPN.Len) =
                  HC.Cfg.ALPN.Data (1 .. HC.Cfg.ALPN.Len);
      ALPN_PL : constant Natural :=
         (if ALPN_Match then HC.Cfg.ALPN.Len else 0);
      --  ALPN ext: tag(2) + len(2) + list_len(2) + proto_len(1) + proto(N)
      ALPN_Ext_Len : constant N32 :=
         (if ALPN_Match then N32 (7 + ALPN_PL) else 0);

      Ext_Len : constant N32 := ALPN_Ext_Len;
      Body_Len : constant N32 := 2 + Ext_Len;  --  ext_list_len(2) + exts
      Msg_Len  : constant N32 := 4 + Body_Len;
      Pos : N32;
   begin
      Result := (others => 0);
      Len := 0;

      --  Handshake header
      Result (0) := HT_Encrypted_Extensions;
      Result (1) := Byte (Body_Len / 65536);
      Result (2) := Byte ((Body_Len / 256) mod 256);
      Result (3) := Byte (Body_Len mod 256);

      --  Extensions list length
      Result (4) := Byte (Ext_Len / 256);
      Result (5) := Byte (Ext_Len mod 256);

      Pos := 6;

      --  ALPN extension (if matched)
      if ALPN_Match then
         --  Extension type (0x0010)
         Result (Pos) := 0;
         Result (Pos + 1) := 16#10#;
         --  Extension data length
         declare
            DL : constant N32 := N32 (3 + ALPN_PL);
         begin
            Result (Pos + 2) := Byte (DL / 256);
            Result (Pos + 3) := Byte (DL mod 256);
         end;
         --  Protocol list length
         Result (Pos + 4) := Byte ((ALPN_PL + 1) / 256);
         Result (Pos + 5) := Byte ((ALPN_PL + 1) mod 256);
         --  Protocol name length
         Result (Pos + 6) := Byte (ALPN_PL);
         --  Protocol name
         for I in 1 .. ALPN_PL loop
            Result (Pos + N32 (6 + I)) :=
               Byte (Character'Pos (HC.Cfg.ALPN.Data (I)));
         end loop;
         Pos := Pos + ALPN_Ext_Len;

         S.Negotiated_ALPN := HC.Cfg.ALPN;
      end if;

      Len := Msg_Len;
   end Build_Encrypted_Extensions;

   procedure Build_Certificate_Request
     (Result :    out Byte_Seq;
      Len    :    out N32)
   is
      use RFLX.TLS_Handshake.Certificate_Request;
      use RFLX.Tls_Extensiontype_Values;

      --  signature_algorithms extension data:
      --    algo_list_length(2) + Ed25519(2) + P256-SHA256(2) + P384-SHA384(2) = 8
      Sig_Algo_Data : constant RBT.Bytes (1 .. 8) :=
        (1 => 0, 2 => 6,           --  algo list length = 6
         3 => 16#08#, 4 => 16#07#,  --  Ed25519
         5 => 16#04#, 6 => 16#03#,  --  ECDSA-P256-SHA256
         7 => 16#05#, 8 => 16#03#); --  ECDSA-P384-SHA384

      --  Extension: type(2) + data_len(2) + data(8) = 12
      Ext_Len   : constant N32 := 12;
      --  Body: context_len(1) + ext_list_len(2) + extension(12) = 15
      Body_Len  : constant N32 := 1 + 2 + Ext_Len;
      Msg_Len   : constant N32 := 4 + Body_Len;
      Ctx : Context;
   begin
      Result := (others => 0);
      Len := 0;

      if Msg_Len > N32 (Result'Length) then
         return;
      end if;

      declare
         Buf : RBT.Bytes_Ptr := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      begin
         Initialize (Ctx, Buf);

         --  Empty certificate_request_context
         Set_Certificate_Request_Context_Length (Ctx, 0);
         Set_Certificate_Request_Context_Empty (Ctx);

         --  Extensions
         Set_Extensions_Length
           (Ctx, RFLX.TLS_Handshake.Certificate_Request_Extensions_Length
                    (Ext_Len));

         declare
            Ext_Seq_Ctx : RFLX.TLS_Handshake.CR_Extensions.Context;
         begin
            Switch_To_Extensions (Ctx, Ext_Seq_Ctx);

            --  Build signature_algorithms extension
            declare
               E_Buf : RBT.Bytes_Ptr :=
                  new RBT.Bytes'(1 .. RBT.Index (Ext_Len) => 0);
               E_Ctx : RFLX.TLS_Handshake.CR_Extension.Context;
            begin
               RFLX.TLS_Handshake.CR_Extension.Initialize (E_Ctx, E_Buf);
               RFLX.TLS_Handshake.CR_Extension.Set_Tag
                 (E_Ctx, Signature_Algorithms);
               RFLX.TLS_Handshake.CR_Extension.Set_Data_Length
                 (E_Ctx, RFLX.TLS_Handshake.Data_Length
                            (Sig_Algo_Data'Length));
               RFLX.TLS_Handshake.CR_Extension.Set_Data
                 (E_Ctx, Sig_Algo_Data);
               RFLX.TLS_Handshake.CR_Extensions.Append_Element
                 (Ext_Seq_Ctx, E_Ctx);
               RFLX.TLS_Handshake.CR_Extension.Take_Buffer
                 (E_Ctx, E_Buf);
               RFLX_Free (E_Buf);
            end;

            Update_Extensions (Ctx, Ext_Seq_Ctx);
         end;

         Take_Buffer (Ctx, Buf);

         --  Prepend handshake header
         Result (0) := HT_Certificate_Request;
         Result (1) := Byte (Body_Len / 65536);
         Result (2) := Byte ((Body_Len / 256) mod 256);
         Result (3) := Byte (Body_Len mod 256);
         Result (4 .. 4 + Body_Len - 1) :=
            To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));
         RFLX_Free (Buf);
      end;

      Len := Msg_Len;
   end Build_Certificate_Request;

end SPARKTLS.Handshake.Server_Msgs;
