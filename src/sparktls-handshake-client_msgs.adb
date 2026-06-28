with Ada.Unchecked_Deallocation;
with Interfaces; use Interfaces;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.HKDF384;
with SPARKTLSCrypto.HMAC384;
with SPARKTLSCrypto.X25519;
with SPARKTLSCrypto.HKDF;    use SPARKTLSCrypto.HKDF;
with SPARKTLSCrypto.MAC;     use SPARKTLSCrypto.MAC;
with SPARKTLS.RFLX_Bridge;           use SPARKTLS.RFLX_Bridge;
with SPARKTLS.Key_Schedule;
with RFLX.TLS_Handshake.Client_Hello;
with RFLX.TLS_Handshake.Server_Hello;
with RFLX.TLS_Handshake.SH_Extensions_TLS;
with RFLX.TLS_Handshake.SH_Extension_TLS;
with RFLX.TLS_Handshake.CH_Extensions_TLS;
with RFLX.TLS_Handshake.CH_Extension_TLS;
with RFLX.TLS_Handshake.Key_Share_SH;
with RFLX.TLS_Handshake.Cipher_Suites_TLS;
with RFLX.TLS_Handshake.Cipher_Suite_TLS;
with RFLX.TLS_Common;
with RFLX.RFLX_Types;
with RFLX.Tls_Parameters;
with RFLX.Tls_Extensiontype_Values;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.Point;
use SPARKTLSCrypto;

package body SPARKTLS.Handshake.Client_Msgs with
   SPARK_Mode => On
is
   use type RBT.Length;
   use type RBT.Index;
   use type RBT.Bit_Length;
   use type RFLX.RFLX_Types.Length;
   use type RFLX.RFLX_Types.Index;
   use type RFLX.RFLX_Types.Bit_Index;
   use type RFLX.RFLX_Types.Bit_Length;
   use type RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values_Enum;
   use type RFLX.Tls_Parameters.TLS_Supported_Groups_Enum;

   --  RFC 8446 §4.1.4: SHA-256("HelloRetryRequest") — the magic
   --  ServerHello.random value that marks a record as a
   --  HelloRetryRequest rather than a real ServerHello.
   HRR_Sentinel : constant Byte_Seq (0 .. 31) :=
     (16#CF#, 16#21#, 16#AD#, 16#74#, 16#E5#, 16#9A#, 16#61#, 16#11#,
      16#BE#, 16#1D#, 16#8C#, 16#02#, 16#1E#, 16#65#, 16#B8#, 16#91#,
      16#C2#, 16#A2#, 16#11#, 16#16#, 16#7A#, 16#BB#, 16#8C#, 16#5E#,
      16#07#, 16#9E#, 16#09#, 16#E2#, 16#C8#, 16#A8#, 16#33#, 16#9C#);

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

   ----------------------------------------------------------------------------
   --  Build procedures (keep manual serialization for simple output)
   ----------------------------------------------------------------------------

   --  Append a 2-byte cipher_suite entry to the in-flight RFLX
   --  CipherSuites sequence. Encapsulates the buffer-init / set /
   --  append / take-buffer / free dance so each callsite is a
   --  single line.
   procedure Append_Cipher_Suite
     (Suites_Ctx : in out RFLX.TLS_Handshake.Cipher_Suites_TLS.Context;
      Suite      : in     RFLX.Tls_Parameters.TLS_Cipher_Suites_Enum;
      Required_After : in RBT.Bit_Length)
   with Pre  => RFLX.TLS_Handshake.Cipher_Suites_TLS.Has_Buffer
                  (Suites_Ctx)
                and then RFLX.TLS_Handshake.Cipher_Suites_TLS.Valid
                  (Suites_Ctx)
                and then Required_After <= RBT.Bit_Length'Last - 16
                and then RFLX.TLS_Handshake.Cipher_Suites_TLS
                  .Available_Space (Suites_Ctx) >= Required_After + 16,
        Post => RFLX.TLS_Handshake.Cipher_Suites_TLS.Has_Buffer
                  (Suites_Ctx)
                and then RFLX.TLS_Handshake.Cipher_Suites_TLS.Valid
                  (Suites_Ctx)
                and then Suites_Ctx.Buffer_First =
                  Suites_Ctx.Buffer_First'Old
                and then Suites_Ctx.Buffer_Last =
                  Suites_Ctx.Buffer_Last'Old
                and then Suites_Ctx.First = Suites_Ctx.First'Old
                and then Suites_Ctx.Last = Suites_Ctx.Last'Old
                and then RFLX.TLS_Handshake.Cipher_Suites_TLS
                  .Available_Space (Suites_Ctx)
                    >= Required_After;

   procedure Append_Cipher_Suite
     (Suites_Ctx : in out RFLX.TLS_Handshake.Cipher_Suites_TLS.Context;
      Suite      : in     RFLX.Tls_Parameters.TLS_Cipher_Suites_Enum;
      Required_After : in RBT.Bit_Length)
   is
      S_Buf : RBT.Bytes_Ptr;
      S_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
   begin
      S_Buf := new RBT.Bytes'(1 .. 4 => 0);
      RFLX.TLS_Handshake.Cipher_Suite_TLS.Initialize (S_Ctx, S_Buf);
      RFLX.TLS_Handshake.Cipher_Suite_TLS.Set_Suite (S_Ctx, Suite);
      RFLX.TLS_Handshake.Cipher_Suites_TLS.Append_Element
         (Suites_Ctx, S_Ctx);
      RFLX.TLS_Handshake.Cipher_Suite_TLS.Take_Buffer (S_Ctx, S_Buf);
      RFLX_Free (S_Buf);
   end Append_Cipher_Suite;

   --  Append a generic CH extension (tag + opaque data) to the
   --  in-flight RFLX CH_Extensions sequence. Same shape as
   --  Append_Cipher_Suite: hides the per-call buffer allocation and
   --  cleanup so the cipher-suite/extension matrix in
   --  Build_Client_Hello becomes a flat list of one-liners.
   procedure Append_CH_Extension
     (Exts_Ctx : in out RFLX.TLS_Handshake.CH_Extensions_TLS.Context;
      Tag      : in     RFLX.Tls_Extensiontype_Values
                          .TLS_ExtensionType_Values_Enum;
      Data     : in     Byte_Seq)
   with Pre  => Data'Length <= 4096
                and then Data'Last < N32 (Natural'Last)
                and then RFLX.TLS_Handshake.CH_Extensions_TLS.Has_Buffer
                  (Exts_Ctx)
                and then RFLX.TLS_Handshake.CH_Extensions_TLS.Valid
                  (Exts_Ctx)
                and then RFLX.TLS_Handshake.CH_Extensions_TLS
                  .Available_Space (Exts_Ctx)
                    >= RBT.Bit_Length (8) *
                       (RBT.Bit_Length (4) +
                        RBT.Bit_Length (Data'Length)),
        Post => RFLX.TLS_Handshake.CH_Extensions_TLS.Has_Buffer
                  (Exts_Ctx)
                and then RFLX.TLS_Handshake.CH_Extensions_TLS.Valid
                  (Exts_Ctx)
                and then Exts_Ctx.Buffer_First = Exts_Ctx.Buffer_First'Old
                and then Exts_Ctx.Buffer_Last = Exts_Ctx.Buffer_Last'Old
                and then Exts_Ctx.First = Exts_Ctx.First'Old
                and then Exts_Ctx.Last = Exts_Ctx.Last'Old;

   procedure Append_CH_Extension
     (Exts_Ctx : in out RFLX.TLS_Handshake.CH_Extensions_TLS.Context;
      Tag      : in     RFLX.Tls_Extensiontype_Values
                          .TLS_ExtensionType_Values_Enum;
      Data     : in     Byte_Seq)
   is
      Ext_Buf : RBT.Bytes_Ptr;
      Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
   begin
      --  RFLX CH_Extension data fields require a buffer at least
      --  (4 + Data'Length) bytes — header + opaque payload.
      Ext_Buf := new RBT.Bytes'
                       (1 .. RBT.Index (4 + N32 (Data'Length)) => 0);
      RFLX.TLS_Handshake.CH_Extension_TLS.Initialize (Ext_Ctx, Ext_Buf);
      RFLX.TLS_Handshake.CH_Extension_TLS.Set_Tag (Ext_Ctx, Tag);
      RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data_Length
        (Ext_Ctx,
         RFLX.TLS_Handshake.Data_Length (Data'Length));
      if Data'Length = 0 then
         RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data_Empty (Ext_Ctx);
      else
         RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data
           (Ext_Ctx, To_RFLX (Data));
      end if;
      RFLX.TLS_Handshake.CH_Extensions_TLS.Append_Element
        (Exts_Ctx, Ext_Ctx);
      RFLX.TLS_Handshake.CH_Extension_TLS.Take_Buffer
        (Ext_Ctx, Ext_Buf);
      RFLX_Free (Ext_Buf);
   end Append_CH_Extension;

   --  RFC 8446 §4.2.11 / §4.2.11.2 post-RFLX pre_shared_key extension
   --  append. The PSK extension MUST be the last extension on the
   --  wire, and its binder must be computed over the truncated
   --  ClientHello (everything up to but not including the binders
   --  list). We append manually after the RFLX-built body, then
   --  patch the handshake-length and extensions_length fields and
   --  finally compute the binder over the rolled-back transcript.
   --  Spec'd separately so Build_Client_Hello doesn't carry this
   --  140-line block in its proof footprint.
   procedure Append_PSK_Extension
     (S         : in     Session;
      HC        : in out Handshake_Context;
      Retry_Mode : in    Boolean;
      Result    : in out Byte_Seq;
      Len       : in out N32)
	   with Pre  => Result'First = 0
	                and then Result'Last <= N32'Last - 1
	                and then Result'Length >= 600
	                and then Len > 0
	                and then Len <= N32 (Result'Length)
	                and then Reasm_Building (HC),
	        Post => (if HC.Cfg.Random'Old /= null then HC.Cfg.Random /= null)
	                and then HC.Transcript_Len = HC.Transcript_Len'Old
	                and then HC.HRR_Cookie_Len = HC.HRR_Cookie_Len'Old
	                and then HC.Sent_HRR_CCS = HC.Sent_HRR_CCS'Old
	                and then Reasm_Building (HC);

   procedure Append_PSK_Extension
     (S         : in     Session;
      HC        : in out Handshake_Context;
      Retry_Mode : in    Boolean;
      Result    : in out Byte_Seq;
      Len       : in out N32)
   is
      use SPARKTLSCrypto.Hashing.SHA256;
   begin
      if not (S.Ticket.Valid
              and then S.Ticket.PSK_Len in 32 | 48)
      then
         return;
      end if;
      HC.PSK_Offered := True;
      if S.Ticket.Ticket_Len > Max_Ticket_Len
        or else Len > N32 (Result'Length) - 319
      then
         return;
      end if;
      if Retry_Mode then
         if Len > Transcript_Capacity - 316
           or else HC.Transcript_Len > Transcript_Capacity - 316 - Len
         then
            return;
         end if;
      end if;
      declare
         Tick_Len : constant N32 := S.Ticket.Ticket_Len;
         ID_Entry_Len : constant N32 := 2 + Tick_Len + 4;
         IDs_Len : constant N32 := 2 + ID_Entry_Len;
         Binder_Size : constant N32 :=
            (if S.Ticket.PSK_Len = 48 then 48 else 32);
         Binder_Entry_Len : constant N32 := 1 + Binder_Size;
         Binders_Len : constant N32 := 2 + Binder_Entry_Len;
         PSK_Ext_Len : constant N32 := 4 + IDs_Len + Binders_Len;
         New_Len     : constant N32 := Len + PSK_Ext_Len;

         --  CH body layout — see comments in Build_Client_Hello.
         Sid_Len_Off    : constant N32 := 4 + 2 + 32;
         Sid_Len_Read   : constant N32 := N32 (Result (Sid_Len_Off));
      begin
         if New_Len > N32 (Result'Length)
           or else New_Len > 16#00FF_FFFF# + 4
           or else Sid_Len_Read > 32
         then
            return;
         end if;
         declare
            Suites_Len_Off : constant N32 :=
              Sid_Len_Off + 1 + Sid_Len_Read;
         begin
            if Suites_Len_Off + 1 > Result'Last then
               return;
            end if;
            declare
               Suites_Len_Read : constant N32 :=
                 N32 (Result (Suites_Len_Off)) * 256 +
                 N32 (Result (Suites_Len_Off + 1));
            begin
               if Suites_Len_Read > 18 then
                  return;
               end if;
               declare
                  Comp_Len_Off : constant N32 :=
                    Suites_Len_Off + 2 + Suites_Len_Read;
               begin
                  if Comp_Len_Off > Result'Last then
                     return;
                  end if;
                  declare
                     Comp_Len_Read : constant N32 :=
                       N32 (Result (Comp_Len_Off));
                  begin
                     if Comp_Len_Read > 1 then
                        return;
                     end if;
                     declare
                        Ext_Len_Offset : constant N32 :=
                          Comp_Len_Off + 1 + Comp_Len_Read;
                     begin
                        if Ext_Len_Offset + 1 > Result'Last then
                           return;
                        end if;
                        declare
                           Old_Ext_Len : constant N32 :=
                             N32 (Result (Ext_Len_Offset)) * 256 +
                             N32 (Result (Ext_Len_Offset + 1));
                        begin
                           if Old_Ext_Len > 16#FFFF# - PSK_Ext_Len then
                              return;
                           end if;
                           declare
                              New_Ext_Len : constant N32 :=
                                Old_Ext_Len + PSK_Ext_Len;
                              P : N32 := Len;
                           begin

                              Result (P) := 0; Result (P + 1) := 16#29#;
                              P := P + 2;
                              Result (P) :=
                                Byte ((IDs_Len + Binders_Len) / 256);
                              Result (P + 1) :=
                                Byte ((IDs_Len + Binders_Len) mod 256);
                              P := P + 2;
                              Result (P) := Byte (ID_Entry_Len / 256);
                              Result (P + 1) :=
                                Byte (ID_Entry_Len mod 256);
                              P := P + 2;
                              Result (P) := Byte (Tick_Len / 256);
                              Result (P + 1) := Byte (Tick_Len mod 256);
                              P := P + 2;
                              Result (P .. P + Tick_Len - 1) :=
                                S.Ticket.Ticket (0 .. Tick_Len - 1);
                              P := P + Tick_Len;
                              declare
                                 A : constant Unsigned_32 := S.Ticket.Age_Add;
                              begin
                                 Result (P)     := Byte (A / 2**24 mod 256);
                                 Result (P + 1) := Byte (A / 2**16 mod 256);
                                 Result (P + 2) := Byte (A / 2**8 mod 256);
                                 Result (P + 3) := Byte (A mod 256);
                              end;
                              P := P + 4;
                              Result (P) := Byte (Binder_Entry_Len / 256);
                              Result (P + 1) :=
                                Byte (Binder_Entry_Len mod 256);
                              P := P + 2;
                              Result (P) := Byte (Binder_Size);
                              P := P + 1;
                              declare
                                 Binder_Offset : constant N32 := P;
                              begin
                                 Result (P .. P + Binder_Size - 1) :=
                                   (others => 0);
                                 P := P + Binder_Size;

                                 --  Patch handshake length
                                 declare
                                    New_Body_Len : constant N32 := P - 4;
                                 begin
                                    Result (1) := Byte (New_Body_Len / 65536);
                                    Result (2) :=
                                      Byte ((New_Body_Len / 256) mod 256);
                                    Result (3) := Byte (New_Body_Len mod 256);
                                 end;
                                 Result (Ext_Len_Offset) :=
                                   Byte (New_Ext_Len / 256);
                                 Result (Ext_Len_Offset + 1) :=
                                   Byte (New_Ext_Len mod 256);

                                 --  Compute binder per RFC 8446 §4.2.11.2.
                                 declare
                                    Trunc_Len : constant N32 :=
                                      Binder_Offset - 3;
                                    Pre_Len   : constant N32 :=
                                      (if Retry_Mode
                                       then HC.Transcript_Len
                                       else 0);
                                    Trans_In  : constant Byte_Seq
                                      (0 .. Pre_Len + Trunc_Len - 1) :=
                                      HC.Transcript (0 .. Pre_Len - 1)
                                      & Result (0 .. Trunc_Len - 1);
                                 begin
                                    if S.Ticket.PSK_Len = 48 then
                                       declare
                                          Trunc_Hash384 :
                                            SPARKNaCl.Hashing.SHA384.Digest;
                                          Binder_Key48  :
                                            SPARKTLSCrypto.HKDF384.OKM384_Seq
                                              (0 .. 47);
                                          Finished_K48  :
                                            SPARKTLSCrypto.HKDF384.OKM384_Seq
                                              (0 .. 47);
                                          Binder_V48    : Bytes_48;
                                       begin
                                          SPARKNaCl.Hashing.SHA384.Hash
                                            (Trunc_Hash384, Trans_In);
                                          Key_Schedule.Derive_Binder_Key_384
                                            (Binder_Key48, S.Ticket.PSK);
                                          Key_Schedule.Derive_Finished_Key_384
                                            (Finished_K48,
                                             Byte_Seq (Binder_Key48));
                                          SPARKTLSCrypto.HMAC384.HMAC_SHA_384
                                            (Output => Binder_V48,
                                             M      => Byte_Seq
                                                        (Trunc_Hash384),
                                             K      => Byte_Seq
                                                        (Finished_K48));
                                          Result (Binder_Offset ..
                                                    Binder_Offset + 47) :=
                                            Binder_V48;
                                       end;
                                    else
                                       declare
                                          Trunc_Hash   : Digest;
                                          Binder_Key   : OKM_Seq (0 .. 31);
                                          Finished_Key : OKM_Seq (0 .. 31);
                                          Binder_Val   : Digest;
                                       begin
                                          Hash (Trunc_Hash, Trans_In);
                                          Key_Schedule.Derive_Binder_Key
                                            (Binder_Key,
                                             Bytes_32
                                               (S.Ticket.PSK (0 .. 31)));
                                          Key_Schedule.Derive_Finished_Key
                                            (Finished_Key,
                                             Byte_Seq (Binder_Key));
                                          HMAC_SHA_256
                                            (Output => Binder_Val,
                                             M      => Trunc_Hash,
                                             K      => Byte_Seq
                                                        (Finished_Key));
                                          Result (Binder_Offset ..
                                                    Binder_Offset + 31) :=
                                            Binder_Val;
                                       end;
                                    end if;
                                 end;
                              end;

                              Len := P;
                           end;
                        end;
                     end;
                  end;
               end;
            end;
         end;
      end;
   end Append_PSK_Extension;

   procedure Build_Client_Hello
     (S          : in     Session;
      HC         : in out Handshake_Context;
      Result     :    out Byte_Seq;
      Len        :    out N32;
      Retry_Mode : in     Boolean := False)
   is
      use RFLX.TLS_Handshake.Client_Hello;
      use RFLX.TLS_Common;

      procedure Gen_Random (Output : out Byte_Seq) renames HC.Cfg.Random.all;

      --  Retry CH2 with a server-selected group: only that group's
      --  share goes in key_share. Server-chose-no-group ⇒
      --  HC.HRR_Selected_Group = 0 ⇒ same key_share as CH1.
      Retry_KS_Single : constant Boolean :=
         Retry_Mode and then HC.HRR_Selected_Group /= 0;
      --  Single-entry shares_len, in bytes:
      --   X25519:   group(2)+key_len(2)+key(32) = 36
      --   secp256r1: group(2)+key_len(2)+key(65) = 69
      --   secp384r1: group(2)+key_len(2)+key(97) = 101
      Retry_KS_Entry : constant N32 :=
        (if HC.HRR_Selected_Group = 16#001D# then 36
         elsif HC.HRR_Selected_Group = 16#0017# then 69
         elsif HC.HRR_Selected_Group = 16#0018# then 101
         else 0);

      --  Extension data sizes
      Host_Len : constant N32 := N32 (HC.Cfg.Server_Name.Len);
      --  SNI data: sni_list_len(2) + host_type(1) + host_len(2) + host
      SNI_Data_Len : constant N32 := 5 + Host_Len;
      --  supported_groups data: list_len(2) + group(2) * 3
      SG_Data_Len  : constant N32 := 8;
      --  signature_algorithms data: list_len(2) + alg(2) * 6
      SA_Data_Len  : constant N32 := 14;
      --  key_share data: shares_len(2) + entries.
      --
      --  CH1 strategy (RFC 8446 §9.1 + standard browser practice):
      --  send key_share only for X25519. supported_groups still
      --  advertises all three (X25519, secp256r1, secp384r1) so the
      --  server can request HRR to switch to another curve. This
      --  matches Chrome/Firefox/curl: it keeps CH1 small (38 vs 208
      --  bytes), skips two ECC scalar-mults, and triggers proper HRR
      --  flow when the server prefers a non-X25519 group. BoGo tests
      --  with `ExpectMissingKeyShare: true` rely on this behavior.
      --
      --  Retry with selected group: 2 + Retry_KS_Entry (36/69/101).
      --  Retry with no curve change (cookie-only HRR): same as CH1
      --  = X25519 single share = 38 bytes.
      KS_Data_Len  : constant N32 :=
        (if Retry_KS_Single then 2 + Retry_KS_Entry else 38);
      --  psk_key_exchange_modes data: list_len(1) + mode(1)
      PSK_Data_Len : constant N32 := 2;
      --  supported_versions data: list_len(1) + version(2) * N.
      --  RFC 8446 §4.2.1 / RFC 5246: branch on Cfg.Versions so we
      --  only offer the versions our policy permits. Otherwise
      --  servers honoring our offer can negotiate a version we
      --  refuse later.
      SV_Data_Len  : constant N32 :=
        (case HC.Cfg.Versions is
            when Allow_Both => 5,   --  list_len + 2 versions
            when TLS_1_3_Only
               | TLS_1_2_Only => 3);  --  list_len + 1 version
      --  ec_point_formats data (RFC 8422 §5.1.2): list_len(1) +
      --  format(1)=uncompressed. Required by BoGo for any TLS 1.2
      --  ECDHE suite (server's `ellipticOk` is false without it).
      EPF_Data_Len : constant N32 := 2;

      --  ALPN data: protocol_list_len(2) + proto_len(1) + proto(N)
      ALPN_Len : constant Natural := HC.Cfg.ALPN.Len;
      ALPN_Data_Len : constant N32 :=
         (if ALPN_Len > 0 then N32 (3 + ALPN_Len) else 0);
      ALPN_Ext_Len : constant N32 :=
         (if ALPN_Len > 0 then 4 + ALPN_Data_Len else 0);

      --  Cookie extension (RFC 8446 §4.2.2) — only in CH2 when the
      --  HRR carried one. Body: cookie_len(2) + cookie<cookie_len>.
      Cookie_Bytes_Len : constant N32 :=
        (if Retry_Mode and then HC.HRR_Cookie_Len > 0
         then HC.HRR_Cookie_Len else 0);
      Cookie_Data_Len  : constant N32 :=
        (if Cookie_Bytes_Len > 0 then 2 + Cookie_Bytes_Len else 0);
      Cookie_Ext_Len   : constant N32 :=
        (if Cookie_Bytes_Len > 0 then 4 + Cookie_Data_Len else 0);

      --  RFC 5077 session_ticket (TLS 1.2) — emit on the wire.
      --  CH_Extension_TLS is unconstrained on tag (see specs/
      --  CHANGES_FROM_UPSTREAM.md), so Append_Element with tag 0x0023
      --  produces the correct bytes. Empty data on initial CH
      --  ("I support tickets but have none yet"); on resumption, the
      --  previously-issued ticket bytes go in the data field.
      Offer_TLS12_Ticket : constant Boolean :=
        HC.Cfg.Versions in TLS_1_2_Only | Allow_Both;
      TLS12_Ticket_Data_Len : constant N32 :=
        (if Offer_TLS12_Ticket
           and then HC.Cfg.TLS12_Resume_Ticket.Valid
         then HC.Cfg.TLS12_Resume_Ticket.Ticket_Len
         else 0);
      TLS12_Ticket_Ext_Len : constant N32 :=
        (if Offer_TLS12_Ticket then 4 + TLS12_Ticket_Data_Len else 0);

      --  Each extension: tag(2) + data_length(2) + data
      Ext_Total : constant N32 :=
         (4 + SNI_Data_Len) + (4 + SG_Data_Len) + (4 + SA_Data_Len) +
         (4 + KS_Data_Len) + (4 + PSK_Data_Len) + (4 + SV_Data_Len) +
         (4 + EPF_Data_Len) +
         ALPN_Ext_Len +
         Cookie_Ext_Len +
         TLS12_Ticket_Ext_Len;

      --  ClientHello body: version(2) + random(32) + sid_len(1) +
      --  sid(0 | 32) + suites_len(2) + suites(18) + comp_len(1) +
      --  comp(1) + ext_len(2) + extensions. TLS_1_2_Only sends an
      --  empty session_id (RFC 8446 §D.4 middlebox-compat trick is
      --  TLS 1.3-specific; sending the random 32 bytes from a TLS
      --  1.2-only client leaks "speaks TLS 1.3"). BoGo
      --  TLS12NoSessionID-TLS13.
      Session_ID_Len : constant N32 :=
        (if HC.Cfg.Versions = TLS_1_2_Only then 0 else 32);

      --  RFC 7685: F5 firewall workaround. If the CH would otherwise
      --  land in the 256..511 "danger zone", append a padding
      --  extension (tag 0x0015) to push it to >= 512 bytes. BoGo
      --  ClientHelloPadding sets RequireClientHelloSize=512.
      Pre_Pad_Msg_Len : constant N32 :=
        4 + 59 + Session_ID_Len + Ext_Total;
      Need_Pad : constant Boolean := Pre_Pad_Msg_Len in 256 .. 511;
      --  Inside the danger zone, pad to exactly 512 when possible
      --  (Pre_Pad_Msg_Len <= 508 leaves >= 4 bytes for the ext
      --  header). For 509..511 the minimum-size 4-byte ext header
      --  alone pushes us past 512 — acceptable.
      Pad_Ext_Total : constant N32 :=
        (if Need_Pad
         then (if Pre_Pad_Msg_Len <= 508
               then 512 - Pre_Pad_Msg_Len
               else 4)
         else 0);
      Pad_Data_Len : constant N32 :=
        (if Pad_Ext_Total >= 4 then Pad_Ext_Total - 4 else 0);

      Ext_Total_All : constant N32 := Ext_Total + Pad_Ext_Total;
      CH_Body_Len : constant N32 := 59 + Session_ID_Len + Ext_Total_All;
      CH_Msg_Len  : constant N32 := 4 + CH_Body_Len;

      Buf      : RBT.Bytes_Ptr;
      Ctx      : Context;
      PK_Bytes    : Byte_Seq (0 .. 31);   --  X25519 public key
      P256_PK_Enc : Byte_Seq (0 .. 64);   --  P-256 public key (uncompressed)
      P384_PK_Enc : Byte_Seq (0 .. 96);   --  P-384 public key (uncompressed)
   begin
      Result := (others => 0);
      Len    := 0;

      --  Generate ephemeral X25519 keypair (Fiat X25519).
      --  In retry mode (CH2 for HRR), reuse the CH1 SK so the server
      --  still recognises the share if the selected_group matches.
      declare
         Tmp_X25519 : Bytes_32;
      begin
         if not Retry_Mode then
            Gen_Random (Byte_Seq (Tmp_X25519));
            HC.Local_SK := Tmp_X25519;
         end if;
         declare
            Basepoint : constant Bytes_32 := (9, others => 0);
         begin
            SPARKTLSCrypto.X25519.Scalar_Mult (PK_Bytes, HC.Local_SK, Basepoint);
         end;
      end;

      --  Generate ephemeral P-256 keypair (reused in retry mode).
      declare
         P256_Pt    : SPARKTLSCrypto.P256.Point.P256_Jacobian;
         Tmp_P256   : Bytes_32;
      begin
         if not Retry_Mode then
            Gen_Random (Byte_Seq (Tmp_P256));
            HC.P256_Local_SK := Tmp_P256;
         end if;
         SPARKTLSCrypto.P256.Point.P256_Mulgen
           (P256_Pt, HC.P256_Local_SK, 32);
         SPARKTLSCrypto.P256.Point.P256_To_Affine (P256_Pt);
         SPARKTLSCrypto.P256.Point.P256_Encode (P256_PK_Enc, P256_Pt);
      end;

      --  Generate ephemeral P-384 keypair (reused in retry mode).
      declare
         Tmp_P384 : Bytes_48;
      begin
         if not Retry_Mode then
            Gen_Random (Byte_Seq (Tmp_P384));
            HC.P384_Local_SK := Tmp_P384;
         end if;
         SPARKTLSCrypto.P384.Point.P384_Mulgen (P384_PK_Enc, HC.P384_Local_SK);
      end;

      --  Generate client random (retain CH1's random across HRR).
      declare
         Tmp_CR : Bytes_32;
      begin
         if not Retry_Mode then
            Gen_Random (Byte_Seq (Tmp_CR));
            HC.Client_Random := Tmp_CR;
         end if;
      end;

      --  Generate 32-byte legacy session ID for middlebox compatibility
      --  (RFC 8446 §D.4 / §4.1.2). TLS-1.2-only clients have no
      --  middlebox concern, so they SHOULD send an empty session_id;
      --  doing otherwise leaks "client speaks TLS 1.3" to a real
      --  TLS 1.2 server. BoGo TLS12NoSessionID-TLS13 exercises this.
      --  In retry mode, reuse the CH1 session_id verbatim.
      declare
         Legacy_Session_ID : Byte_Seq (0 .. 31);
      begin
         if not Retry_Mode then
            if HC.Cfg.Versions = TLS_1_2_Only then
               Legacy_Session_ID := (others => 0);
            else
               Gen_Random (Legacy_Session_ID);
            end if;
            HC.Legacy_Session_ID := Legacy_Session_ID;
         end if;
      end;

      --  PK_Bytes already set by X25519.Scalar_Mult above

      --  Allocate buffer for ClientHello body
      Buf := new RBT.Bytes'(1 .. RBT.Index (RFLX_Main_Size) => 0);
      Initialize (Ctx, Buf);

      --  Set ClientHello fields via RFLX
      Set_Legacy_Version (Ctx, TLS_1_2);  --  0x0303 per RFC 8446
      Set_Random (Ctx, To_RFLX (HC.Client_Random));
      if HC.Cfg.Versions = TLS_1_2_Only then
         Set_Legacy_Session_ID_Length (Ctx, 0);
         Set_Legacy_Session_ID_Empty (Ctx);
      else
         Set_Legacy_Session_ID_Length (Ctx, 32);
         Set_Legacy_Session_ID (Ctx, To_RFLX (HC.Legacy_Session_ID));
      end if;
      --  TLS version routes past cookie fields to cipher_suites_length
      --  9 suites: 3 TLS 1.3 + 3 TLS 1.2 ECDHE-RSA + 3 TLS 1.2
      --  ECDHE-ECDSA = 18 bytes
      Set_Cipher_Suites_Length
        (Ctx, RFLX.TLS_Handshake.Cipher_Suites_Length (18));

      --  Build cipher suite sequence
      declare
         Suites_Ctx : RFLX.TLS_Handshake.Cipher_Suites_TLS.Context;
      begin
         Switch_To_Cipher_Suites_TLS (Ctx, Suites_Ctx);
         Append_Cipher_Suite
           (Suites_Ctx, RFLX.Tls_Parameters.TLS_AES_128_GCM_SHA256, 128);
         Append_Cipher_Suite
           (Suites_Ctx, RFLX.Tls_Parameters.TLS_CHACHA20_POLY1305_SHA256,
            112);
         Append_Cipher_Suite
           (Suites_Ctx, RFLX.Tls_Parameters.TLS_AES_256_GCM_SHA384, 96);
         Append_Cipher_Suite
           (Suites_Ctx,
            RFLX.Tls_Parameters.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 80);
         Append_Cipher_Suite
           (Suites_Ctx,
            RFLX.Tls_Parameters.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 64);
         Append_Cipher_Suite
           (Suites_Ctx,
            RFLX.Tls_Parameters.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            48);
         Append_Cipher_Suite
           (Suites_Ctx,
            RFLX.Tls_Parameters.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 32);
         Append_Cipher_Suite
           (Suites_Ctx,
            RFLX.Tls_Parameters.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 16);
         Append_Cipher_Suite
           (Suites_Ctx,
            RFLX.Tls_Parameters.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            0);
         Update_Cipher_Suites_TLS (Ctx, Suites_Ctx);
      end;

      Set_Legacy_Compression_Methods_Length (Ctx, 1);
      Set_Legacy_Compression_Methods
        (Ctx, To_RFLX (Byte_Seq'(0 => 16#00#)));
      Set_Extensions_Length
        (Ctx,
         RFLX.TLS_Handshake.Client_Hello_Extensions_Length (Ext_Total_All));

      --  Build extensions sequence
      declare
         Exts_Ctx : RFLX.TLS_Handshake.CH_Extensions_TLS.Context;
      begin
         Switch_To_Extensions_TLS (Ctx, Exts_Ctx);

         --  Extension 1: server_name (0x0000)
         declare
            SNI_Raw : Byte_Seq (0 .. SNI_Data_Len - 1) := (others => 0);
         begin
            --  SNI list: list_len(2) + type(1) + name_len(2) + name
            SNI_Raw (0) := Byte ((Host_Len + 3) / 256);
            SNI_Raw (1) := Byte ((Host_Len + 3) mod 256);
            SNI_Raw (2) := 16#00#;  --  host_name type
            SNI_Raw (3) := Byte (Host_Len / 256);
            SNI_Raw (4) := Byte (Host_Len mod 256);
            for I in 1 .. HC.Cfg.Server_Name.Len loop
               SNI_Raw (4 + N32 (I)) :=
                  Byte (Character'Pos (HC.Cfg.Server_Name.Data (I)));
            end loop;
            Append_CH_Extension
              (Exts_Ctx,
               RFLX.Tls_Extensiontype_Values.Server_Name,
               SNI_Raw);
         end;

         --  Extension 2: supported_groups (0x000A)
         declare
            SG_Raw : constant Byte_Seq (0 .. SG_Data_Len - 1) :=
               (16#00#, 16#06#,          --  list_len=6 (3 groups)
                16#00#, 16#1D#,          --  X25519
                16#00#, 16#17#,          --  secp256r1
                16#00#, 16#18#);         --  secp384r1
         begin
            Append_CH_Extension
              (Exts_Ctx,
               RFLX.Tls_Extensiontype_Values.Supported_Groups,
               SG_Raw);
         end;

         --  Extension 3: signature_algorithms (0x000D)
         declare
            SA_Raw : constant Byte_Seq (0 .. SA_Data_Len - 1) :=
               (16#00#, 16#0C#,          --  list_len=12 (6 algorithms)
                16#04#, 16#03#,          --  ecdsa_secp256r1_sha256
                16#05#, 16#03#,          --  ecdsa_secp384r1_sha384
                16#08#, 16#04#,          --  rsa_pss_rsae_sha256
                16#08#, 16#05#,          --  rsa_pss_rsae_sha384
                16#08#, 16#06#,          --  rsa_pss_rsae_sha512
                16#08#, 16#07#);         --  ed25519
         begin
            Append_CH_Extension
              (Exts_Ctx,
               RFLX.Tls_Extensiontype_Values.Signature_Algorithms,
               SA_Raw);
         end;

         --  Extension 4: key_share (0x0033).
         --  CH1 / retry-no-group-change: three KeyShareEntry (X25519
         --  36, secp256r1 69, secp384r1 101). Retry with selected
         --  group: a single entry for that group only.
         declare
            KS_Raw : Byte_Seq (0 .. KS_Data_Len - 1) := (others => 0);
         begin
            if Retry_KS_Single then
               --  Single-entry retry key_share.
               KS_Raw (0) := Byte (Retry_KS_Entry / 256);
               KS_Raw (1) := Byte (Retry_KS_Entry mod 256);
               if HC.HRR_Selected_Group = 16#001D# then
                  KS_Raw (2) := 16#00#;
                  KS_Raw (3) := 16#1D#;  --  X25519
                  KS_Raw (4) := 16#00#;
                  KS_Raw (5) := 16#20#;
                  KS_Raw (6 .. 37) := PK_Bytes;
               elsif HC.HRR_Selected_Group = 16#0017# then
                  KS_Raw (2) := 16#00#;
                  KS_Raw (3) := 16#17#;  --  secp256r1
                  KS_Raw (4) := 16#00#;
                  KS_Raw (5) := 16#41#;
                  KS_Raw (6 .. 70) := P256_PK_Enc;
               elsif HC.HRR_Selected_Group = 16#0018# then
                  KS_Raw (2) := 16#00#;
                  KS_Raw (3) := 16#18#;  --  secp384r1
                  KS_Raw (4) := 16#00#;
                  KS_Raw (5) := 16#61#;
                  KS_Raw (6 .. 102) := P384_PK_Enc;
               end if;
            else
               --  CH1 / cookie-only retry: single X25519 entry.
               --  shares_len(2) = 36
               KS_Raw (0) := 16#00#;
               KS_Raw (1) := 16#24#;
               KS_Raw (2) := 16#00#;
               KS_Raw (3) := 16#1D#;
               KS_Raw (4) := 16#00#;
               KS_Raw (5) := 16#20#;
               KS_Raw (6 .. 37) := PK_Bytes;
            end if;
            Append_CH_Extension
              (Exts_Ctx,
               RFLX.Tls_Extensiontype_Values.Key_Share,
               KS_Raw);
         end;

         --  Extension 4.5 (retry only): cookie (0x002C) — echo back
         --  the cookie the server sent in HRR. RFC 8446 §4.2.2.
         if Cookie_Bytes_Len > 0 then
            declare
               Cookie_Raw : Byte_Seq (0 .. Cookie_Data_Len - 1) :=
                  (others => 0);
            begin
               Cookie_Raw (0) := Byte (Cookie_Bytes_Len / 256);
               Cookie_Raw (1) := Byte (Cookie_Bytes_Len mod 256);
               for I in 0 .. Cookie_Bytes_Len - 1 loop
                  Cookie_Raw (2 + I) := HC.HRR_Cookie (I);
               end loop;
               Append_CH_Extension
                 (Exts_Ctx,
                  RFLX.Tls_Extensiontype_Values.Cookie,
                  Cookie_Raw);
            end;
         end if;

         --  Extension 5: psk_key_exchange_modes (0x002D)
         declare
            PSK_Raw : constant Byte_Seq (0 .. PSK_Data_Len - 1) :=
               (16#01#, 16#01#);  --  list_len=1, psk_dhe_ke
         begin
            Append_CH_Extension
              (Exts_Ctx,
               RFLX.Tls_Extensiontype_Values.Psk_Key_Exchange_Modes,
               PSK_Raw);
         end;

         --  Extension 6: supported_versions (0x002B).
         declare
            SV_Raw : constant Byte_Seq (0 .. SV_Data_Len - 1) :=
              (case HC.Cfg.Versions is
                  when Allow_Both =>
                     Byte_Seq'(16#04#,
                               16#03#, 16#04#,
                               16#03#, 16#03#),
                  when TLS_1_3_Only =>
                     Byte_Seq'(16#02#,
                               16#03#, 16#04#),
                  when TLS_1_2_Only =>
                     Byte_Seq'(16#02#,
                               16#03#, 16#03#));
         begin
            Append_CH_Extension
              (Exts_Ctx,
               RFLX.Tls_Extensiontype_Values.Supported_Versions,
               SV_Raw);
         end;

         --  Extension 7: ec_point_formats (0x000B) — RFC 8422 §5.1.2.
         declare
            EPF_Raw : constant Byte_Seq (0 .. EPF_Data_Len - 1) :=
               (16#01#, 16#00#);
         begin
            Append_CH_Extension
              (Exts_Ctx,
               RFLX.Tls_Extensiontype_Values.Ec_Point_Formats,
               EPF_Raw);
         end;

         --  Extension 8: ALPN (0x0010) — if configured
         if ALPN_Len > 0 then
            declare
               ALPN_Raw : Byte_Seq (0 .. ALPN_Data_Len - 1)
                             := (others => 0);
            begin
               ALPN_Raw (0) := Byte ((ALPN_Len + 1) / 256);
               ALPN_Raw (1) := Byte ((ALPN_Len + 1) mod 256);
               ALPN_Raw (2) := Byte (ALPN_Len);
               for I in 1 .. ALPN_Len loop
                  ALPN_Raw (N32 (2 + I)) :=
                     Byte (Character'Pos (HC.Cfg.ALPN.Data (I)));
               end loop;
               Append_CH_Extension
                 (Exts_Ctx,
                  RFLX.Tls_Extensiontype_Values
                    .Application_Layer_Protocol_Negotiation,
                  ALPN_Raw);
            end;
         end if;

         --  Extension 8b (conditional): RFC 5077 session_ticket (0x0023).
         --  Empty data on initial CH; resume ticket bytes when resuming.
         if Offer_TLS12_Ticket then
            if TLS12_Ticket_Data_Len > 0 then
               Append_CH_Extension
                 (Exts_Ctx,
                  RFLX.Tls_Extensiontype_Values.Session_Ticket,
                  HC.Cfg.TLS12_Resume_Ticket.Ticket
                    (0 .. TLS12_Ticket_Data_Len - 1));
            else
               --  Empty body: Append_CH_Extension's Data is zero-len.
               declare
                  Empty : constant Byte_Seq (1 .. 0) := (others => 0);
               begin
                  Append_CH_Extension
                    (Exts_Ctx,
                     RFLX.Tls_Extensiontype_Values.Session_Ticket,
                     Empty);
               end;
            end if;
            HC.TLS12_Sent_Ticket_Ext := True;
         end if;

         --  Extension 9 (conditional): padding (RFC 7685, tag 0x0015).
         if Pad_Ext_Total > 0 then
            declare
               Pad_Raw : constant Byte_Seq (0 .. Pad_Data_Len - 1) :=
                 (others => 0);
            begin
               Append_CH_Extension
                 (Exts_Ctx,
                  RFLX.Tls_Extensiontype_Values.Padding,
                  Pad_Raw);
            end;
         end if;

         Update_Extensions_TLS (Ctx, Exts_Ctx);
      end;

      --  Extract serialized body and prepend handshake header
      Take_Buffer (Ctx, Buf);

	      if CH_Msg_Len > N32 (Result'Length) then
	         RFLX_Free (Buf);
	         pragma Assert (HC.Cfg.Random /= null);
	         return;
	      end if;

      Result (0) := HT_Client_Hello;
      Result (1) := Byte (CH_Body_Len / 65536);
      Result (2) := Byte ((CH_Body_Len / 256) mod 256);
      Result (3) := Byte (CH_Body_Len mod 256);
      Result (4 .. 4 + CH_Body_Len - 1) :=
         To_NaCl (Buf.all (1 .. RBT.Index (CH_Body_Len)));

      RFLX_Free (Buf);
      Len := CH_Msg_Len;

      --  0-RTT (RFC 8446 §4.2.10) intentionally not offered — see
      --  the Cfg.Resume_Ticket comment in sparktls.ads for the
      --  rationale. We never write the early_data extension into
      --  CH; HC.Early_Data_Offered on the client side stays False.

      --  If we have a cached session ticket, append pre_shared_key
      --  extension. This MUST be the last extension per RFC 8446
      --  §4.2.11. We patch the extensions list length and
      --  handshake length after.
      --
      --  Binder hash matches the ticket's hash: PSK_Len=32 → SHA-256;
      --  PSK_Len=48 → SHA-384. Both paths share the same wire
      --  layout (only the binder VALUE size differs).
	      if Len > 0 then
	         Append_PSK_Extension (S, HC, Retry_Mode, Result, Len);
	      end if;
	      pragma Assert (HC.Cfg.Random /= null);

	   end Build_Client_Hello;

   ----------------------------------------------------------------------------
   --  Parse procedures (using RecordFlux-generated parsers)
   ----------------------------------------------------------------------------

   --  Pre-RFLX byte walk of the SH extensions block. Detects
   --  duplicates, unsolicited extensions, and malformed SNI / ALPN
   --  bodies that RFLX's strict TLS-1.3 schema either silently
   --  rejects (Saw_Rflx_Rejected branch, never escalated for TLS 1.2)
   --  or accepts without per-RFC body validation.
   --
   --  Sets S.Last_Error and OK := False on rejection; OK := True
   --  means the caller may continue with the RFLX parse.
   --
   --  RFC anchors:
   --    RFC 8446 §4.2    duplicate extensions → decode_error
   --    RFC 5246 §7.4.1.4 / RFC 8446 §4.2 SH may only echo offered
   --    RFC 6066 §3      SNI ack body MUST be empty
   --    RFC 8446 §4.2.11 pre_shared_key in SH iff client offered PSK
   --    RFC 7301 §3.1    ALPN body = list_len(2)+proto_len(1)+proto
   --  Is_HRR_Msg: True when the SH currently being parsed is itself
   --  an HelloRetryRequest (sentinel matches). Distinct from
   --  HC.Got_HRR which latches across the SH1+SH2 pair (used only for
   --  double-HRR rejection in the second SH). Pre_Scan uses
   --  Is_HRR_Msg for: extension-Where dispatch (E_HRR vs E_SH13),
   --  duplicate-ext error (illegal_parameter vs decode_error), and
   --  HRR-specific body extraction (selected_group / cookie).
   procedure Pre_Scan_SH_Extensions
     (Data       : in     Byte_Seq;
      HC         : in out Handshake_Context;
      S          : in out Session;
      Is_HRR_Msg : in     Boolean;
      OK         :    out Boolean)
   with Pre => Data'Length in 39 .. Max_HS_Msg
	               and then Data'Last < N32 (Natural'Last),
        Post => (if HC.Cfg.Random'Old /= null then HC.Cfg.Random /= null);

   procedure Pre_Scan_SH_Extensions
     (Data       : in     Byte_Seq;
      HC         : in out Handshake_Context;
      S          : in out Session;
      Is_HRR_Msg : in     Boolean;
      OK         :    out Boolean)
   is
      B    : constant N32 := Data'First + 4;  --  body start
      P    : N32;
      Sid_Len, Ext_Total : N32;
      type SH_Ext_Entry is record
         Tag    : Unsigned_16;
         E_Len  : N32;
         Offset : N32;          --  start of body bytes in Data
      end record;
      Exts  : array (1 .. 32) of SH_Ext_Entry :=
                (others => (0, 0, 0));
      N_Ext : Natural := 0;
   begin
      OK := True;

      --  Caller has already verified Data'Length >= 39. SH body
      --  minimum is version(2)+random(32)+sid_len(1) = 35 bytes
      --  past the 4-byte handshake header.
      if N32 (Data'Length) - 4 < 35 then
         return;
      end if;

	      Sid_Len := N32 (Data (B + 34));
	      if Sid_Len > 32 then
	         S.Last_Error := Decode_Error;
	         OK := False;
	         return;
	      end if;
	      pragma Assert (Sid_Len <= 32);
	      if B > N32'Last - 38
	        or else Sid_Len > N32'Last - B - 38
	      then
	         return;
	      end if;
	      P := B + 38 + Sid_Len;  --  past sid + cipher + comp
	      if P > Data'Last - 2 then
	         return;
	      end if;

      --  RFC 8446 §4.1.4 / §4.1.3: in TLS 1.3 ServerHello + HRR,
      --  legacy_compression_method MUST be 0. The TLS 1.2 parser
      --  enforces this for SH12 with `illegal_parameter`. For HRR we
      --  need decode_error per BoGo
      --  TLS13-HRR-InvalidCompressionMethod. We only have the
      --  Is_HRR_Msg signal here; the SH13/SH12 dispatch happens
      --  later, so apply the HRR check up-front and let TLS 1.2
      --  handle SH compression as before.
      if Is_HRR_Msg
        and then Data (B + 35 + Sid_Len + 2) /= 0
      then
         S.Last_Error := Decode_Error;
         OK := False;
         return;
      end if;

      Ext_Total := N32 (Data (P)) * 256 + N32 (Data (P + 1));
      P := P + 2;
      if Ext_Total > Data'Last - P + 1 then
         S.Last_Error := Decode_Error;
         OK := False;
         return;
      end if;

      declare
         Ext_End : constant N32 := P + Ext_Total;
      begin
         --  RFC 8446 §4: HS message MUST end exactly at its declared
         --  length. BoGo TrailingMessageData-ServerHello.
         if Ext_End /= Data'Last + 1 then
            S.Last_Error := Decode_Error;
            OK := False;
            return;
         end if;

         --  Pass 1: walk bytes, dup-check, collect (tag, len, off)
         --  into Exts, decide TLS-1.3-vs-1.2 from supported_versions.
	         pragma Assert (N_Ext <= Exts'Last);
	         while P <= Ext_End - 4 loop
            pragma Loop_Invariant (N_Ext <= Exts'Last);
            pragma Loop_Invariant (P >= Data'First);
	            pragma Loop_Invariant (P <= Ext_End);
	            pragma Loop_Invariant (Ext_End = Data'Last + 1);
            pragma Loop_Invariant
              (for all J in 1 .. N_Ext =>
                 Exts (J).Offset >= Data'First
                 and then Exts (J).Offset <= Data'Last + 1
                 and then Exts (J).E_Len <=
	                   Data'Last + 1 - Exts (J).Offset);
	            declare
                  pragma Assert (P <= Data'Last - 3);
	               Tag_U16 : constant Unsigned_16 :=
	                  Unsigned_16 (Data (P)) * 256
                  + Unsigned_16 (Data (P + 1));
               E_Len : constant N32 :=
                  N32 (Data (P + 2)) * 256 + N32 (Data (P + 3));
            begin
               if E_Len > Ext_End - P - 4 then
                  S.Last_Error := Decode_Error;
                  OK := False;
                  return;
               end if;
               for I in 1 .. N_Ext loop
                  pragma Loop_Invariant
                    (if HC.Cfg.Random'Loop_Entry /= null
                     then HC.Cfg.Random /= null);
                  if Exts (I).Tag = Tag_U16 then
                     --  RFC 8446 §4.2: duplicate ext in SH/EE →
                     --  decode_error. In HRR specifically BoringSSL
                     --  expects illegal_parameter
                     --  (HelloRetryRequest-DuplicateCookie /
                     --  DuplicateCurve).
                     S.Last_Error :=
                        (if Is_HRR_Msg then Illegal_Parameter
                         else Decode_Error);
                     OK := False;
                     return;
                  end if;
               end loop;
               if N_Ext < Exts'Last then
                  N_Ext := N_Ext + 1;
                  Exts (N_Ext) := (Tag_U16, E_Len, P + 4);
               end if;
               if Tag_U16 = 16#002B# then
                  --  RFC 8446 §4.2.1: in SH/HRR, body is exactly the
                  --  selected_version (2 bytes), MUST be 0x0304 for
                  --  TLS 1.3. Accept only that exact value as the
                  --  TLS 1.3 marker so a corrupted body (BoGo
                  --  SecondServerHelloWrongVersion-TLS13 sends 0x1234)
                  --  doesn't get classified as TLS 1.3.
                  if E_Len = 2
                    and then P + 5 <= Ext_End
                    and then Data (P + 4) = 16#03#
                    and then Data (P + 5) = 16#04#
                  then
                     HC.Has_TLS_1_3 := True;
                  end if;
               end if;
               P := P + 4 + E_Len;
            end;
         end loop;
      end;

      --  Pass 2: matrix policy + per-tag body validation. Single
      --  loop over the collected Exts. Matrix runs first
      --  (unsupported_extension / decode_error for empty-echo
      --  violations); body validators run only on matrix-OK entries.
      declare
         Where : constant Ext_Where :=
           (if Is_HRR_Msg then E_HRR
            elsif HC.Has_TLS_1_3 then E_SH13
            else E_SH12);
      begin
         pragma Assert (N_Ext <= Exts'Last);
         for I in 1 .. N_Ext loop
            pragma Loop_Invariant
              (N_Ext <= Exts'Last);
            pragma Loop_Invariant
              (if HC.Cfg.Random'Loop_Entry /= null
               then HC.Cfg.Random /= null);
            pragma Loop_Invariant
              (for all J in 1 .. N_Ext =>
                 Exts (J).Offset >= Data'First
                 and then Exts (J).Offset <= Data'Last + 1
                 and then Exts (J).E_Len <=
                   Data'Last + 1 - Exts (J).Offset);
            declare
               V_OK  : Boolean;
               V_Err : Error_Code;
            begin
               Validate_Server_Ext
                 (Where    => Where,
                  Tag      => Exts (I).Tag,
                  Body_Len => Exts (I).E_Len,
                  HC       => HC,
                  OK       => V_OK,
                  Err      => V_Err);
               if not V_OK then
                  S.Last_Error := V_Err;
                  OK := False;
                  return;
               end if;

               --  Per-tag body validation (RFC 7301 ALPN — shared
               --  helper, same wire shape used in TLS 1.3 EE).
               if Exts (I).Tag = 16#0010#
                 and then Exts (I).Offset + Exts (I).E_Len <=
                            Data'Last + 1
               then
                  Validate_ALPN_Echo_Body
                    (Data       => Data,
                     Body_Start => Exts (I).Offset,
                     E_Len      => Exts (I).E_Len,
                     HC         => HC,
                     S          => S,
                     OK         => V_OK,
                     Err        => V_Err);
                  if not V_OK then
                     S.Last_Error := V_Err;
                     OK := False;
                     return;
                  end if;
               end if;

               --  RFC 8446 §4.1.4 HRR-specific body extraction.
               --  In HRR, key_share body is just `selected_group(2)`
               --  (no key_exchange); cookie body is `cookie_len(2) +
               --  cookie<cookie_len>` (RFC 8446 §4.2.2). Stash both
               --  in HC for the caller's CH2-rebuild step.
	               if Is_HRR_Msg
	                 and then Exts (I).Tag = 16#0033#  --  key_share
	                 and then Exts (I).Offset <= Data'Last - 1
	                 and then Exts (I).E_Len = 2
	               then
                  HC.HRR_Selected_Group :=
                     Unsigned_16 (Data (Exts (I).Offset)) * 256
                     + Unsigned_16 (Data (Exts (I).Offset + 1));
               end if;
               --  RFC 8446 §4.2.11: pre_shared_key in SH (not HRR)
               --  carries `selected_identity` (uint16). We offer
               --  exactly one PSK identity (S.Ticket), so the only
               --  valid selected_identity value is 0; anything else
               --  is illegal_parameter. The matrix has already
               --  rejected pre_shared_key in SH if we did not
               --  offer it (Requires_Offer => True).
	               if not Is_HRR_Msg
	                 and then Exts (I).Tag = 16#0029#  --  pre_shared_key
	                 and then Exts (I).Offset <= Data'Last - 1
	                 and then Exts (I).E_Len = 2
	               then
                  declare
                     Sel : constant Unsigned_16 :=
                       Unsigned_16 (Data (Exts (I).Offset)) * 256 +
                       Unsigned_16 (Data (Exts (I).Offset + 1));
                  begin
                     if Sel /= 0 then
                        S.Last_Error := Illegal_Parameter;
                        OK := False;
                        return;
                     end if;
                     HC.Using_PSK := True;
                  end;
               end if;
               if Is_HRR_Msg
                 and then Exts (I).Tag = 16#002C#  --  cookie
                 and then Exts (I).E_Len >= 2
                 and then Exts (I).Offset + Exts (I).E_Len
                            <= Data'Last + 1
               then
                  declare
                     C_Len : constant N32 :=
                        N32 (Data (Exts (I).Offset)) * 256
                        + N32 (Data (Exts (I).Offset + 1));
                  begin
                     --  RFC 8446 §4.2.2: cookie is the wire shape
                     --  cookie<1..2^16-1>, so empty cookie body is
                     --  illegal_parameter. BoGo
                     --  HelloRetryRequest-EmptyCookie-TLS13.
                     if C_Len = 0
                       or else 2 + C_Len /= Exts (I).E_Len
                     then
                        S.Last_Error := Illegal_Parameter;
                        OK := False;
                        return;
                     end if;
                     if C_Len <= N32 (HC.HRR_Cookie'Length) then
                        HC.HRR_Cookie_Len := C_Len;
                        for K in 0 .. C_Len - 1 loop
                           HC.HRR_Cookie (K) :=
                              Data (Exts (I).Offset + 2 + K);
                        end loop;
                     end if;
                  end;
               end if;
            end;
         end loop;
      end;
   end Pre_Scan_SH_Extensions;

   --  RFC 8446 §4.2.8 ServerHello key_share: a single KeyShareEntry
   --     group(2) + key_exchange_length(2) + key_exchange(key_exchange_length)
   --  Allocates a scratch buffer, copies the SH_Extension_TLS body,
   --  validates the wire-length, runs RFLX Verify_Message, dispatches
   --  on group to populate HC.Peer_PK / HC.P256_Peer_PK / HC.P384_Peer_PK
   --  and the Use_*_KE flags. On length mismatch the routine sets
   --  HC.Ext_Parse_Err := Decode_Error.
   --
   --  BoGo TrailingKeyShareData / unknown-group cases are exercised
   --  through this path.
   procedure Apply_SH_Key_Share
     (Ext_Ctx : in     RFLX.TLS_Handshake.SH_Extension_TLS.Context;
      HC      : in out Handshake_Context)
   with Pre => RFLX.TLS_Handshake.SH_Extension_TLS.Has_Buffer (Ext_Ctx)
               and then RFLX.TLS_Handshake.SH_Extension_TLS.Valid
                 (Ext_Ctx, RFLX.TLS_Handshake.SH_Extension_TLS.F_Data_Length)
               and then RFLX.TLS_Handshake.SH_Extension_TLS.Well_Formed
                 (Ext_Ctx, RFLX.TLS_Handshake.SH_Extension_TLS.F_Data)
               and then RFLX.TLS_Handshake.SH_Extension_TLS.Valid_Next
                 (Ext_Ctx, RFLX.TLS_Handshake.SH_Extension_TLS.F_Data),
        Post => (if HC.Cfg.Random'Old /= null then HC.Cfg.Random /= null);

   procedure Apply_SH_Key_Share
     (Ext_Ctx : in     RFLX.TLS_Handshake.SH_Extension_TLS.Context;
      HC      : in out Handshake_Context)
   is
      DLen : constant N32 := N32
        (RFLX.TLS_Handshake.SH_Extension_TLS.Get_Data_Length (Ext_Ctx));
      KS_Buf : RBT.Bytes_Ptr;
      KS_Ctx : RFLX.TLS_Handshake.Key_Share_SH.Context;
   begin
      if DLen not in Wire_Key_Share_Len then
         return;  --  silently skip malformed; never fatal
      end if;

      declare
         VLen : constant Wire_Key_Share_Len := DLen;
      begin
         KS_Buf := new RBT.Bytes'(1 .. RBT.Index (VLen) => 0);
         RFLX.TLS_Handshake.SH_Extension_TLS.Get_Data (Ext_Ctx, KS_Buf.all);

         --  Reject trailing bytes after the key_exchange field. RFC
         --  8446 §4.2.8: extension_data == 4 + key_exchange_length.
         if VLen >= 4 then
            declare
               KL : constant N32 :=
                  N32 (KS_Buf (3)) * 256 + N32 (KS_Buf (4));
            begin
               if 4 + KL /= N32 (VLen) then
                  HC.Ext_Parse_Err := Decode_Error;
               end if;
            end;
         end if;

         RFLX.TLS_Handshake.Key_Share_SH.Initialize
           (KS_Ctx, KS_Buf,
            Written_Last => RBT.Bit_Length (RBT.Length (DLen) * 8));
         RFLX.TLS_Handshake.Key_Share_SH.Verify_Message (KS_Ctx);

         if HC.Ext_Parse_Err = No_Error and then
            RFLX.TLS_Handshake.Key_Share_SH.Well_Formed_Message (KS_Ctx)
         then
            declare
               Grp : constant RFLX.Tls_Parameters.TLS_Supported_Groups :=
                  RFLX.TLS_Handshake.Key_Share_SH.Get_Group (KS_Ctx);
            begin
               if Grp.Known and then
                  Grp.Enum = RFLX.Tls_Parameters.X25519
                  and then RFLX.RFLX_Types.To_Length
                    (RFLX.TLS_Handshake.Key_Share_SH.Field_Size
                       (KS_Ctx,
                        RFLX.TLS_Handshake.Key_Share_SH.F_Key_Exchange)) = 32
               then
                  declare
                     KB : RBT.Bytes (1 .. 32);
                  begin
                     RFLX.TLS_Handshake.Key_Share_SH.Get_Key_Exchange
                       (KS_Ctx, KB);
                     HC.Peer_PK := To_NaCl (KB);
                     HC.Use_P256_KE := False;
                  end;
               elsif Grp.Known and then
                  Grp.Enum = RFLX.Tls_Parameters.Secp256r1
                  and then RFLX.RFLX_Types.To_Length
                    (RFLX.TLS_Handshake.Key_Share_SH.Field_Size
                       (KS_Ctx,
                        RFLX.TLS_Handshake.Key_Share_SH.F_Key_Exchange)) = 65
               then
                  declare
                     KB : RBT.Bytes (1 .. 65);
                  begin
                     RFLX.TLS_Handshake.Key_Share_SH.Get_Key_Exchange
                       (KS_Ctx, KB);
                     for I in 0 .. 64 loop
                        HC.P256_Peer_PK (N32 (I)) :=
                           Byte (KB (RBT.Index (I + 1)));
                     end loop;
                     HC.Use_P256_KE := True;
                     HC.Use_P384_KE := False;
                  end;
               elsif Grp.Known and then
                  Grp.Enum = RFLX.Tls_Parameters.Secp384r1
                  and then RFLX.RFLX_Types.To_Length
                    (RFLX.TLS_Handshake.Key_Share_SH.Field_Size
                       (KS_Ctx,
                        RFLX.TLS_Handshake.Key_Share_SH.F_Key_Exchange)) = 97
               then
                  declare
                     KB : RBT.Bytes (1 .. 97);
                  begin
                     RFLX.TLS_Handshake.Key_Share_SH.Get_Key_Exchange
                       (KS_Ctx, KB);
                     for I in 0 .. 96 loop
                        HC.P384_Peer_PK (N32 (I)) :=
                           Byte (KB (RBT.Index (I + 1)));
                     end loop;
                     HC.Use_P384_KE := True;
                     HC.Use_P256_KE := False;
                  end;
               end if;
            end;
         end if;

         RFLX.TLS_Handshake.Key_Share_SH.Take_Buffer (KS_Ctx, KS_Buf);
         RFLX_Free (KS_Buf);
      end;
   end Apply_SH_Key_Share;

   procedure Parse_Server_Hello
     (S    : in out Session;
      HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   is
      use RFLX.TLS_Handshake.Server_Hello;
      Body_Len : N32;
      Buf      : RBT.Bytes_Ptr;
      Ctx      : Context;
      --  True iff the SH currently being parsed has the HRR sentinel
      --  random. Distinct from HC.Got_HRR, which latches across the
      --  CH1/HRR/CH2/SH2 pair. Used to gate HRR-specific code paths
      --  in this single call (Pre_Scan dispatch, body extraction,
      --  early return) so the same Parse_Server_Hello body handles
      --  both HRR and the post-HRR SH2 correctly.
      Curr_Is_HRR : Boolean := False;
   begin
      OK := False;

      if Data'Length < 39 then
         return;
      end if;

      if Data'Last >= N32 (Natural'Last) then
         return;
      end if;

      if Data'Length > Max_HS_Msg then
         return;
      end if;

      --  Check handshake type byte
      if Data (Data'First) /= HT_Server_Hello then
         return;
      end if;

      --  RFC 5246 §7.4.1.2 / RFC 8446 §4.1.3: legacy_session_id
      --  length field is 0..32. The full ServerHello body is
      --  version(2) + random(32) + sid_len(1) + sid(0..32) + ...
      --  Catch over-long sid early — RFLX rejects the message but
      --  we'd otherwise fall through to the TLS 1.2 parser and emit
      --  Handshake_Failure instead of the correct Decode_Error
      --  (BoGo's Client-TooLongSessionID test).
      if N32 (Data'Length) - 4 >= 35
        and then N32 (Data (Data'First + 4 + 34)) > 32
      then
         S.Last_Error := Decode_Error;
         return;
      end if;

      --  RFC 8446 §4.1.4: HelloRetryRequest is on-wire a ServerHello
      --  with a magic random value. Compare here so the SH parser
      --  can apply HRR-specific extension policy
      --  (Where_Allowed = E_HRR, dup → illegal_parameter not
      --  decode_error, must contain key_share or cookie). Random is
      --  at offset 6..37 in Data (4-byte HS hdr + 2-byte
      --  legacy_version).
      if N32 (Data'Length) >= 38 then
         declare
            Sentinel_Match : Boolean := True;
         begin
            for I in N32 range 0 .. 31 loop
               if Data (Data'First + 6 + I) /= HRR_Sentinel (I) then
                  Sentinel_Match := False;
                  exit;
               end if;
            end loop;
            if Sentinel_Match then
               --  RFC 8446 §4.1.4: a server MUST send at most one
               --  HRR. A second HRR is unexpected_message.
               if HC.Got_HRR then
                  S.Last_Error := Unexpected_Message;
                  return;
               end if;
               HC.Got_HRR  := True;
               Curr_Is_HRR := True;
            end if;
         end;
      end if;

      declare
         Pre_OK : Boolean;
      begin
         Pre_Scan_SH_Extensions
           (Data, HC, S, Is_HRR_Msg => Curr_Is_HRR, OK => Pre_OK);
         if not Pre_OK then
            return;
         end if;
      end;

      --  RFC 8446 §4.1.4: a valid HRR must contain at least one of
      --  key_share or cookie. An HRR with neither is empty →
      --  illegal_parameter. BoGo HelloRetryRequest-Empty-TLS13.
      if Curr_Is_HRR
        and then HC.HRR_Selected_Group = 0
        and then HC.HRR_Cookie_Len = 0
      then
         S.Last_Error := Illegal_Parameter;
         return;
      end if;

      --  RFC 8446 §4.1.4: "Clients MUST abort the handshake with an
      --  'illegal_parameter' alert if the HelloRetryRequest would
      --  not result in any change in the ClientHello." Concretely,
      --  if HRR.selected_group names a group we already offered in
      --  CH1's key_share, the HRR is unnecessary. CH1 carries only
      --  X25519 (0x001D), so a HRR selecting X25519 is rejected.
      --  BoGo UnnecessaryHelloRetryRequest-TLS13.
      if Curr_Is_HRR
        and then HC.HRR_Selected_Group = 16#001D#
      then
         S.Last_Error := Illegal_Parameter;
         return;
      end if;

      --  HRR is well-formed. Return OK := True; the caller in
      --  sparktls-client.adb sees HC.Got_HRR and runs the retry
      --  flow (transcript message_hash replacement → CH2 build →
      --  send → wait for the real ServerHello).
      if Curr_Is_HRR then
         --  Stash HRR cipher suite for the CH2 build's transcript
         --  + the cipher-mismatch check on the second SH (RFC
         --  8446 §4.1.4: cipher_suite from HRR and SH MUST match).
         declare
            Sid_Len : constant N32 := N32 (Data (Data'First + 4 + 34));
         begin
            if N32 (Data'Length) >= 41 + Sid_Len then
               declare
                  Cs_Off  : constant N32 := Data'First + 39 + Sid_Len;
               begin
                  pragma Assert (Cs_Off + 1 <= Data'Last);
               HC.HRR_Cipher_Suite :=
                  Unsigned_16 (Data (Cs_Off)) * 256
                  + Unsigned_16 (Data (Cs_Off + 1));
               end;
            end if;
         end;
         OK := True;
         return;
      end if;

      --  Skip 4-byte handshake header, pass body to Server_Hello context
      Body_Len := N32 (Data'Length) - 4;

      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      Buf.all := To_RFLX (Data (Data'First + 4 .. Data'Last));
      Initialize (Ctx, Buf,
                  Written_Last => RBT.Bit_Length (RBT.Length (Body_Len) * 8));
      Verify_Message (Ctx);

      if not Well_Formed_Message (Ctx) then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         return;
      end if;

      --  Extract server random (32 bytes)
      declare
         Random_Bytes : RBT.Bytes (1 .. 32);
      begin
         Get_Random (Ctx, Random_Bytes);
         HC.Server_Random := To_NaCl (Random_Bytes);
      end;

      --  Extract and validate cipher suite
      if not Well_Formed (Ctx, F_Cipher_Suite_TLS_Suite) then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         return;
      end if;

      declare
         Suite     : constant RFLX.Tls_Parameters.TLS_Cipher_Suites :=
            Get_Cipher_Suite_TLS_Suite (Ctx);
         Suite_Val : constant Unsigned_16 :=
            Unsigned_16 (RFLX.Tls_Parameters.To_Base_Integer (Suite));
      begin
         --  Accept TLS 1.3 and TLS 1.2 AEAD suites
         if Suite_Val not in Suite_CHACHA20_POLY1305_SHA256
                           | Suite_AES_128_GCM_SHA256
                           | Suite_AES_256_GCM_SHA384
                           | Suite_ECDHE_RSA_AES128_GCM_SHA256
                           | Suite_ECDHE_RSA_AES256_GCM_SHA384
                           | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                           | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                           | Suite_ECDHE_RSA_CHACHA20_SHA256
                           | Suite_ECDHE_ECDSA_CHACHA20_SHA256
         then
            Take_Buffer (Ctx, Buf);
            RFLX_Free (Buf);
            return;
         end if;
         --  RFC 8446 §4.1.4: after HRR, the cipher_suite in SH2 MUST
         --  match the cipher_suite the server chose in HRR. BoGo
         --  HelloRetryRequest-CipherChange-TLS13.
         if HC.Got_HRR
           and then HC.HRR_Cipher_Suite /= 0
           and then Suite_Val /= HC.HRR_Cipher_Suite
         then
            Take_Buffer (Ctx, Buf);
            RFLX_Free (Buf);
            S.Last_Error := Illegal_Parameter;
            return;
         end if;
         S.Negotiated_Suite := Suite_Val;
      end;

      --  Iterate extensions to find key_share
      if Well_Formed (Ctx, F_Extensions_TLS) then
         declare
            Exts_Ctx : RFLX.TLS_Handshake.SH_Extensions_TLS.Context;
            Ctx_First : constant RFLX.RFLX_Types.Index := Ctx.Buffer_First;
            Ctx_Last  : constant RFLX.RFLX_Types.Index := Ctx.Buffer_Last;
            Exts_First : constant RFLX.RFLX_Types.Bit_Index :=
              Field_First (Ctx, F_Extensions_TLS);
            Exts_Last  : constant RFLX.RFLX_Types.Bit_Length :=
              Field_Last (Ctx, F_Extensions_TLS);
         begin
            Switch_To_Extensions_TLS (Ctx, Exts_Ctx);

            declare
            begin
               while RFLX.TLS_Handshake.SH_Extensions_TLS.Has_Element
                       (Exts_Ctx)
               loop
                  pragma Loop_Invariant
                    (not RFLX.TLS_Handshake.Server_Hello.Has_Buffer (Ctx));
                  pragma Loop_Invariant
                    (RFLX.TLS_Handshake.Server_Hello.Present
                       (Ctx, F_Extensions_TLS));
                  pragma Loop_Invariant
                    (RFLX.TLS_Handshake.SH_Extensions_TLS.Has_Buffer
                       (Exts_Ctx));
                  pragma Loop_Invariant
                    (RFLX.TLS_Handshake.SH_Extensions_TLS.Valid
                       (Exts_Ctx));
                  pragma Loop_Invariant
                    (Exts_Ctx.First = Exts_First
                     and then Exts_Ctx.Last = Exts_Last);
	                  pragma Loop_Invariant
	                    (Ctx.Buffer_First = Ctx_First
	                     and then Ctx.Buffer_Last = Ctx_Last
	                     and then Exts_Ctx.Buffer_First = Ctx_First
	                     and then Exts_Ctx.Buffer_Last = Ctx_Last);
	                  pragma Loop_Invariant
	                    (if HC.Cfg.Random'Loop_Entry /= null
	                     then HC.Cfg.Random /= null);
                  declare
                     Ext_Ctx : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
                  begin
                     RFLX.TLS_Handshake.SH_Extensions_TLS.Switch
                       (Exts_Ctx, Ext_Ctx);
                     RFLX.TLS_Handshake.SH_Extension_TLS.Verify_Message
                       (Ext_Ctx);

                     --  Policy (Where_Allowed, Requires_Offer, body
                     --  empty) and structural checks (duplicates, ALPN
                     --  body shape + proto match, SNI body empty,
                     --  Has_TLS_1_3 detection, Negotiated_ALPN copy) all
                     --  ran in Pre_Scan_SH_Extensions. This loop is the
                     --  only RFLX-backed step that remains: key_share
                     --  body decoding (group dispatch +
                     --  Get_Key_Exchange). ALPN body extraction stays in
                     --  Pre_Scan (TLS 1.2) / Extract_ALPN_From_EE (TLS
                     --  1.3 EE); the TLS 1.3 SH itself carries no ALPN.
                     if RFLX.TLS_Handshake.SH_Extension_TLS.Well_Formed_Message
                          (Ext_Ctx)
                       and then RFLX.TLS_Handshake.SH_Extension_TLS.Get_Tag
                                 (Ext_Ctx).Known
                       and then RFLX.TLS_Handshake.SH_Extension_TLS.Get_Tag
                                 (Ext_Ctx).Enum =
                                  RFLX.Tls_Extensiontype_Values.Key_Share
                     then
                        Apply_SH_Key_Share (Ext_Ctx, HC);
                     end if;

                     RFLX.TLS_Handshake.SH_Extensions_TLS.Update
                       (Exts_Ctx, Ext_Ctx);
                  end;
               end loop;

               Update_Extensions_TLS (Ctx, Exts_Ctx);
            end;

            --  All dup / unsolicited / body-empty / ALPN-shape checks
            --  ran in Pre_Scan_SH_Extensions above; any failure there
            --  short-circuited the parse. Nothing else to do here.
         end;
      end if;

      --  Set version based on supported_versions extension
      if HC.Has_TLS_1_3 then
         HC.Version := TLS_1_3;
      else
         HC.Version := TLS_1_2;
      end if;

      --  RFC 8446 §4.1.3: TLS 1.3 server's legacy_session_id_echo
      --  MUST be byte-for-byte equal to the client's
      --  legacy_session_id. We always send a 32-byte SID (unless
      --  TLS_1_2_Only), so when the server picked TLS 1.3 the echo
      --  must also be 32 bytes and match. In TLS 1.2, by contrast,
      --  the server may assign a new SID for a full handshake, so
      --  this check is gated on HC.Has_TLS_1_3. BoGo
      --  EchoTLS13CompatibilitySessionID-style mismatches that
      --  reach a TLS 1.3 SH (e.g. via supported_versions).
      if HC.Has_TLS_1_3
        and then HC.Cfg.Versions /= TLS_1_2_Only
        and then Data'Length >= 4 + 35 + 32
      then
         declare
            SH_SID_Off : constant N32 := Data'First + 4 + 35;
            SH_SID_Len : constant N32 :=
               N32 (Data (Data'First + 4 + 34));
            Mismatch : Boolean := SH_SID_Len /= 32;
         begin
            if not Mismatch then
               for I in N32 range 0 .. 31 loop
                  if Data (SH_SID_Off + I)
                       /= HC.Legacy_Session_ID (I)
                  then
                     Mismatch := True;
                  end if;
               end loop;
            end if;
            if Mismatch then
               Take_Buffer (Ctx, Buf);
               RFLX_Free (Buf);
               S.Last_Error := Illegal_Parameter;
               OK := False;
               return;
            end if;
         end;
      end if;

      --  RFC 8446 §4.1.4: after a HelloRetryRequest, the second SH
      --  MUST select the same version as the HRR (TLS 1.3, indicated
      --  by supported_versions). A 2nd SH without TLS 1.3 in supported
      --  _versions is a SECOND_SERVERHELLO_VERSION_MISMATCH and MUST
      --  trigger an illegal_parameter alert. BoGo
      --  SecondServerHelloWrongVersion-TLS13.
      if HC.Got_HRR and then not HC.Has_TLS_1_3 then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         S.Last_Error := Illegal_Parameter;
         OK := False;
         return;
      end if;

      --  RFC 8446 §4.2.1: enforce our Cfg.Versions policy on the
      --  server's choice. -min-version / -max-version / -no-tlsN may
      --  have constrained the policy below what's in the supported_
      --  versions extension we sent; if the server still picks a
      --  version outside our allowed set, reject with
      --  protocol_version (alert 70). BoGo's MinimumVersion-Client2-
      --  TLS13-TLS12 / -Server2-TLS13-TLS12 exercise this.
      if (HC.Version = TLS_1_2 and HC.Cfg.Versions = TLS_1_3_Only)
        or else
         (HC.Version = TLS_1_3 and HC.Cfg.Versions = TLS_1_2_Only)
      then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         S.Last_Error := Protocol_Version;
         OK := False;
         return;
      end if;

      --  RFC 8446 §4.1.3: Downgrade-sentinel check, independent of
      --  the negotiated version. The server MUST NOT set these
      --  markers when negotiating TLS 1.3, so a marker on a TLS 1.3
      --  SH is itself a signal to abort (BoringSSL convention; BoGo
      --  Client-RejectJDK11DowngradeRandom). On a TLS 1.2 SH the
      --  marker is the canonical RFC 8446 downgrade indicator.
      --
      --  Three sentinels:
      --   * "DOWNGRD" + 0x01 — TLS 1.3 → TLS 1.2 (RFC 8446 §4.1.3)
      --   * "DOWNGRD" + 0x00 — TLS 1.3 → TLS 1.0/1.1 (same RFC)
      --   * 0xED 0xBF 0xB4 0xA8 0xC2 0x47 0x10 0xFF — JDK 11 marker.
      declare
         R : Byte_Seq renames HC.Server_Random;
         type Sentinel_T is array (N32 range 0 .. 7) of Byte;
         S13 : constant Sentinel_T :=
           (16#44#, 16#4F#, 16#57#, 16#4E#,
            16#47#, 16#52#, 16#44#, 16#01#);
         S12 : constant Sentinel_T :=
           (16#44#, 16#4F#, 16#57#, 16#4E#,
            16#47#, 16#52#, 16#44#, 16#00#);
         S_JDK : constant Sentinel_T :=
           (16#ED#, 16#BF#, 16#B4#, 16#A8#,
            16#C2#, 16#47#, 16#10#, 16#FF#);
         M13, M12, MJ : Boolean := True;
      begin
         for I in N32 range 0 .. 7 loop
            if R (24 + I) /= S13 (I)   then M13 := False; end if;
            if R (24 + I) /= S12 (I)   then M12 := False; end if;
            if R (24 + I) /= S_JDK (I) then MJ  := False; end if;
         end loop;
         if M13 or M12 or MJ then
            S.Last_Error := Illegal_Parameter;
            Take_Buffer (Ctx, Buf);
            RFLX_Free (Buf);
            return;
         end if;
      end;

      --  For TLS 1.2, skip ECDHE shared secret here
      --  (it's computed after ServerKeyExchange)
      if HC.Version = TLS_1_2 then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         OK := True;
         return;
      end if;

      --  Compute shared secret (TLS 1.3 only — key_share in ServerHello)
      if HC.Use_P384_KE then
         --  P-384 ECDHE: shared_secret = x-coordinate of [sk] * peer_PK
         declare
            Secret_384 : Bytes_48;
            P384_OK    : Boolean;
         begin
            SPARKTLSCrypto.P384.Point.P384_ECDHE
              (Secret  => Secret_384,
               OK      => P384_OK,
               SK      => HC.P384_Local_SK,
               Peer_PK => HC.P384_Peer_PK);
            if not P384_OK then
               OK := False;
               Take_Buffer (Ctx, Buf);
               RFLX_Free (Buf);
               return;
            end if;
            HC.Shared_Secret := Secret_384;
         end;
      elsif HC.Use_P256_KE then
         --  P-256 ECDHE: shared_secret = x-coordinate of [sk] * peer_PK
         declare
            Peer_Pt : SPARKTLSCrypto.P256.Point.P256_Jacobian;
            Valid   : SPARKNaCl.U32;
            X_Bytes : Byte_Seq (0 .. 31);
         begin
            SPARKTLSCrypto.P256.Point.P256_Decode
              (Peer_Pt, HC.P256_Peer_PK, Valid);
            if Valid = 0 then
               OK := False;
               Take_Buffer (Ctx, Buf);
               RFLX_Free (Buf);
               return;
            end if;
            --  Multiply peer's public key by our private scalar
            SPARKTLSCrypto.P256.Point.P256_Mul
              (Peer_Pt, HC.P256_Local_SK, 32);
            SPARKTLSCrypto.P256.Point.P256_To_Affine (Peer_Pt);
            --  Encode to get x-coordinate (bytes 1..32 of uncompressed point)
            declare
               Encoded : Byte_Seq (0 .. 64);
            begin
               SPARKTLSCrypto.P256.Point.P256_Encode (Encoded, Peer_Pt);
               X_Bytes := Encoded (1 .. 32);
            end;
            HC.Shared_Secret := (others => 0);
            HC.Shared_Secret (0 .. 31) := X_Bytes;
         end;
      else
         --  X25519 ECDHE
         HC.Shared_Secret := (others => 0);
         SPARKTLSCrypto.X25519.Scalar_Mult
           (HC.Shared_Secret (0 .. 31), HC.Local_SK, HC.Peer_PK);
         --  RFC 7748 §6.1: small-subgroup defence. The helper has
         --  a SPARK-proven Post that ties its result to the byte-
         --  sequence existential. RFC 8446 §6.2: invalid peer share
         --  is illegal_parameter, not the generic handshake_failure
         --  the caller would otherwise pick.
         if not Shared_Secret_Is_Acceptable_X25519
                  (HC.Shared_Secret (0 .. 31))
         then
            S.Last_Error := Illegal_Parameter;
            Take_Buffer (Ctx, Buf);
            RFLX_Free (Buf);
            OK := False;
            return;
         end if;
      end if;

      Take_Buffer (Ctx, Buf);
      RFLX_Free (Buf);

      --  Bubble up extension-specific protocol errors (e.g. RFC 7301
      --  empty ALPN name → illegal_parameter). The caller's `if not
      --  Parse_OK` arm reads S.Last_Error to pick the alert.
      if HC.Ext_Parse_Err /= No_Error then
         S.Last_Error := HC.Ext_Parse_Err;
         OK := False;
         return;
      end if;

      OK := True;
   end Parse_Server_Hello;

end SPARKTLS.Handshake.Client_Msgs;
