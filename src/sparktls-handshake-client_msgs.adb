with Ada.Unchecked_Deallocation;
with Interfaces;           use Interfaces;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.HKDF384;
with SPARKTLSCrypto.HMAC384;
with SPARKTLSCrypto.X25519;
with SPARKTLSCrypto.HKDF;  use SPARKTLSCrypto.HKDF;
with SPARKTLSCrypto.MAC;   use SPARKTLSCrypto.MAC;
with SPARKTLS.RFLX_Bridge; use SPARKTLS.RFLX_Bridge;
with SPARKTLS.Key_Schedule;
with SPARKTLS.Tickets_12;
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
with SPARKTLS_Transcript;
use type SPARKTLS_Transcript.Transcript_State;
use SPARKTLSCrypto;

package body SPARKTLS.Handshake.Client_Msgs
  with SPARK_Mode => On
is
   pragma Unevaluated_Use_Of_Old (Allow);

   use type RBT.Length;
   use type RBT.Index;
   use type RBT.Bit_Length;
   use type RFLX.RFLX_Types.Length;
   use type RFLX.RFLX_Types.Index;
   use type RFLX.RFLX_Types.Bit_Index;
   use type RFLX.RFLX_Types.Bit_Length;
   use type RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values_Enum;
   use type RFLX.Tls_Parameters.TLS_Supported_Groups_Enum;

   --  RFC 8446 4.1.4: SHA-256("HelloRetryRequest")  the magic
   --  ServerHello.random value that marks a record as a
   --  HelloRetryRequest rather than a real ServerHello.
   HRR_Sentinel : constant Byte_Seq (0 .. 31) :=
     (16#CF#,
      16#21#,
      16#AD#,
      16#74#,
      16#E5#,
      16#9A#,
      16#61#,
      16#11#,
      16#BE#,
      16#1D#,
      16#8C#,
      16#02#,
      16#1E#,
      16#65#,
      16#B8#,
      16#91#,
      16#C2#,
      16#A2#,
      16#11#,
      16#16#,
      16#7A#,
      16#BB#,
      16#8C#,
      16#5E#,
      16#07#,
      16#9E#,
      16#09#,
      16#E2#,
      16#C8#,
      16#A8#,
      16#33#,
      16#9C#);

   --  Deallocate an RFLX buffer.
   --  Body is SPARK_Mode Off (Unchecked_Deallocation of 'access all').
   --  Spec is On so SPARK can verify call sites.
   use type RBT.Bytes_Ptr;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr)
   with Post => Buf = null;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr) with SPARK_Mode => Off is
      procedure Dealloc is new
        Ada.Unchecked_Deallocation (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
   begin
      Dealloc (Buf);
   end RFLX_Free;

   subtype P384_Public_Key_Seq is Byte_Seq (0 .. 96);

   procedure Compute_P384_Shared_Secret
     (Secret : out Bytes_48; OK : out Boolean; SK : in Bytes_48; Peer_PK : in P384_Public_Key_Seq);

   procedure Compute_P384_Shared_Secret
     (Secret : out Bytes_48; OK : out Boolean; SK : in Bytes_48; Peer_PK : in P384_Public_Key_Seq)
   is
   begin
      SPARKTLSCrypto.P384.Point.P384_ECDHE
        (Secret => Secret, OK => OK, SK => SK, Peer_PK => Peer_PK);
   end Compute_P384_Shared_Secret;

   function Effective_ALPN_Count (Cfg : Config) return Natural
   is (if Cfg.ALPN_Count > 0 then Cfg.ALPN_Count elsif Cfg.ALPN.Len > 0 then 1 else 0);

   function ALPN_List_Prefix_Len (Cfg : Config; Count : Natural) return N32
   with
     Pre => Count <= Max_Config_ALPN_Protocols,
     Post =>
       ALPN_List_Prefix_Len'Result >= 2 + N32 (Count)
       and then ALPN_List_Prefix_Len'Result <= 2 + N32 (Count * (Max_Hostname_Len + 1));

   function ALPN_List_Prefix_Len (Cfg : Config; Count : Natural) return N32 is
      Total : N32 := 2;
      I     : Natural := 1;
   begin
      while I <= Count loop
         pragma Loop_Invariant (I in 1 .. Count + 1);
         pragma Loop_Invariant (Total >= 2 + N32 (I - 1));
         pragma Loop_Invariant (Total <= 2 + N32 ((I - 1) * (Max_Hostname_Len + 1)));
         pragma Loop_Variant (Increases => I);
         pragma Assert (I in ALPN_Index);
         Total := Total + 1 + N32 (Cfg.ALPN_List (ALPN_Index (I)).Len);
         I := I + 1;
      end loop;
      pragma Assert (I = Count + 1);
      pragma Assert (Total <= 2 + N32 (Count * (Max_Hostname_Len + 1)));
      return Total;
   end ALPN_List_Prefix_Len;

   function Effective_ALPN_Data_Len (Cfg : Config) return N32
   with
     Post =>
       Effective_ALPN_Data_Len'Result
       <= 2 + N32 (Max_Config_ALPN_Protocols * (Max_Hostname_Len + 1))
       and then (if Effective_ALPN_Count (Cfg) > 0 then Effective_ALPN_Data_Len'Result >= 3)
       and then (if Cfg.ALPN_Count > 0
                 then Effective_ALPN_Data_Len'Result = ALPN_List_Prefix_Len (Cfg, Cfg.ALPN_Count))
       and then (if Cfg.ALPN_Count = 0 and then Cfg.ALPN.Len > 0
                 then Effective_ALPN_Data_Len'Result = 3 + N32 (Cfg.ALPN.Len));

   function Effective_ALPN_Data_Len (Cfg : Config) return N32 is
      Count : constant Natural := Effective_ALPN_Count (Cfg);
      Total : N32;
   begin
      if Count = 0 then
         return 0;
      end if;

      if Cfg.ALPN_Count > 0 then
         Total := ALPN_List_Prefix_Len (Cfg, Cfg.ALPN_Count);
      else
         Total := 3 + N32 (Cfg.ALPN.Len);
      end if;
      pragma Assert (Total >= 3);
      return Total;
   end Effective_ALPN_Data_Len;

   procedure Build_ALPN_Extension_Data (Cfg : in Config; Result : in out Byte_Seq)
   with
     Pre =>
       Result'First = 0
       and then Effective_ALPN_Count (Cfg) > 0
       and then Result'Last = Effective_ALPN_Data_Len (Cfg) - 1;

   procedure Build_ALPN_Extension_Data (Cfg : in Config; Result : in out Byte_Seq) is
      P        : N32 := 2;
      List_Len : constant N32 := N32 (Result'Length) - 2;
   begin
      Result (0) := Byte (List_Len / 256);
      Result (1) := Byte (List_Len mod 256);

      if Cfg.ALPN_Count > 0 then
         for J in ALPN_Index loop
            exit when J > Cfg.ALPN_Count;
            pragma Loop_Invariant (P >= 2);
            pragma Loop_Invariant (P <= Result'Last + 1);
            declare
               Proto_Len : constant Natural := Cfg.ALPN_List (J).Len;
            begin
               if P > Result'Last or else N32 (Proto_Len) > Result'Last - P then
                  return;
               end if;
               Result (P) := Byte (Proto_Len);
               for I in 1 .. Proto_Len loop
                  pragma Assert (P + N32 (I) <= Result'Last);
                  Result (P + N32 (I)) := Byte (Character'Pos (Cfg.ALPN_List (J).Data (I)));
               end loop;
               P := P + 1 + N32 (Proto_Len);
            end;
         end loop;
      else
         pragma Assert (P <= Result'Last);
         pragma Assert (P + N32 (Cfg.ALPN.Len) <= Result'Last);
         Result (P) := Byte (Cfg.ALPN.Len);
         for I in 1 .. Cfg.ALPN.Len loop
            pragma Assert (P + N32 (I) <= Result'Last);
            Result (P + N32 (I)) := Byte (Character'Pos (Cfg.ALPN.Data (I)));
         end loop;
      end if;
   end Build_ALPN_Extension_Data;

   function Effective_Sig_Algo_Count (Cfg : Config) return Sig_Algo_Count
   is (if Cfg.Verify_Sig_Algo_Count > 0 then Cfg.Verify_Sig_Algo_Count else 9);

   ----------------------------------------------------------------------------
   --  Build procedures
   ----------------------------------------------------------------------------

   --  Append a 2-byte cipher_suite entry to the in-flight RFLX
   --  CipherSuites sequence. Encapsulates the buffer-init / set /
   --  append / take-buffer / free dance so each callsite is a
   --  single line.
   procedure Append_Cipher_Suite
     (Suites_Ctx : in out RFLX.TLS_Handshake.Cipher_Suites_TLS.Context;
      Suite      : in RFLX.Tls_Parameters.TLS_Cipher_Suites_Enum)
   with
     Pre =>
       RFLX.TLS_Handshake.Cipher_Suites_TLS.Has_Buffer (Suites_Ctx)
       and then RFLX.TLS_Handshake.Cipher_Suites_TLS.Valid (Suites_Ctx)
       and then RFLX.TLS_Handshake.Cipher_Suites_TLS.Available_Space (Suites_Ctx) >= 16,
     Post =>
       RFLX.TLS_Handshake.Cipher_Suites_TLS.Has_Buffer (Suites_Ctx)
       and then RFLX.TLS_Handshake.Cipher_Suites_TLS.Valid (Suites_Ctx)
       and then Suites_Ctx.Buffer_First = Suites_Ctx.Buffer_First'Old
       and then Suites_Ctx.Buffer_Last = Suites_Ctx.Buffer_Last'Old
       and then Suites_Ctx.First = Suites_Ctx.First'Old
       and then Suites_Ctx.Last = Suites_Ctx.Last'Old
       and then RFLX.TLS_Handshake.Cipher_Suites_TLS.Available_Space (Suites_Ctx)
                = RFLX.TLS_Handshake.Cipher_Suites_TLS.Available_Space (Suites_Ctx)'Old - 16;

   procedure Append_Cipher_Suite
     (Suites_Ctx : in out RFLX.TLS_Handshake.Cipher_Suites_TLS.Context;
      Suite      : in RFLX.Tls_Parameters.TLS_Cipher_Suites_Enum)
   is
      S_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
   begin
      --  Idiomatic RecordFlux element build (see dccp msg_write.adb):
      --  Switch builds the element in place in the sequence's own
      --  buffer, Update commits it. No scratch allocation, no copy.
      RFLX.TLS_Handshake.Cipher_Suites_TLS.Switch (Suites_Ctx, S_Ctx);
      RFLX.TLS_Handshake.Cipher_Suite_TLS.Set_Suite (S_Ctx, Suite);
      RFLX.TLS_Handshake.Cipher_Suites_TLS.Update (Suites_Ctx, S_Ctx);
   end Append_Cipher_Suite;

   --  Append a generic CH extension (tag + opaque data) to the
   --  in-flight RFLX CH_Extensions sequence. Same shape as
   --  Append_Cipher_Suite: hides the per-call buffer allocation and
   --  cleanup so the cipher-suite/extension matrix in
   --  Build_Client_Hello becomes a flat list of one-liners.
   procedure Append_CH_Extension
     (Exts_Ctx : in out RFLX.TLS_Handshake.CH_Extensions_TLS.Context;
      Tag      : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values_Enum;
      Data     : in Byte_Seq)
   with
     Pre =>
       Data'Length <= 4096
       and then Data'Last < N32 (Natural'Last)
       and then RFLX.TLS_Handshake.CH_Extensions_TLS.Has_Buffer (Exts_Ctx)
       and then RFLX.TLS_Handshake.CH_Extensions_TLS.Valid (Exts_Ctx)
       and then RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                >= RBT.Bit_Length (8) * (RBT.Bit_Length (4) + RBT.Bit_Length (Data'Length)),
     Post =>
       RFLX.TLS_Handshake.CH_Extensions_TLS.Has_Buffer (Exts_Ctx)
       and then RFLX.TLS_Handshake.CH_Extensions_TLS.Valid (Exts_Ctx)
       and then Exts_Ctx.Buffer_First = Exts_Ctx.Buffer_First'Old
       and then Exts_Ctx.Buffer_Last = Exts_Ctx.Buffer_Last'Old
       and then Exts_Ctx.First = Exts_Ctx.First'Old
       and then Exts_Ctx.Last = Exts_Ctx.Last'Old
       and then RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                = RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)'Old
                  - RBT.Bit_Length (8) * (RBT.Bit_Length (4) + RBT.Bit_Length (Data'Length));

   procedure Append_CH_Extension
     (Exts_Ctx : in out RFLX.TLS_Handshake.CH_Extensions_TLS.Context;
      Tag      : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values_Enum;
      Data     : in Byte_Seq)
   is
      Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
   begin
      --  Idiomatic RecordFlux element build (see RecordFlux
      --  examples/apps/dccp msg_write.adb, the Options loop): Switch
      --  borrows the sequence's own buffer to build the element IN
      --  PLACE, the fields are set, and Update commits it back. No
      --  scratch allocation and no copy -- the element is written
      --  directly where it belongs in the extensions sequence.
      RFLX.TLS_Handshake.CH_Extensions_TLS.Switch (Exts_Ctx, Ext_Ctx);
      RFLX.TLS_Handshake.CH_Extension_TLS.Set_Tag (Ext_Ctx, Tag);
      RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data_Length
        (Ext_Ctx, RFLX.TLS_Handshake.Data_Length (Data'Length));
      if Data'Length = 0 then
         RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data_Empty (Ext_Ctx);
      else
         RFLX.TLS_Handshake.CH_Extension_TLS.Set_Data (Ext_Ctx, To_RFLX (Data));
      end if;
      RFLX.TLS_Handshake.CH_Extensions_TLS.Update (Exts_Ctx, Ext_Ctx);
   end Append_CH_Extension;

   --  RFC 8446 4.2.11 / 4.2.11.2 post-RFLX pre_shared_key extension
   --  append. The PSK extension MUST be the last extension on the
   --  wire, and its binder must be computed over the truncated
   --  ClientHello (everything up to but not including the binders
   --  list). We append manually after the RFLX-built body, then
   --  patch the handshake-length and extensions_length fields and
   --  finally compute the binder over the rolled-back transcript.
   --  Spec'd separately so Build_Client_Hello doesn't carry this
   --  140-line block in its proof footprint.
   procedure Append_PSK_Extension
     (Ticket     : in Session_Ticket;
      Get_Time   : in Get_Time_Fn;
      HC         : in out Handshake_Context;
      Retry_Mode : in Boolean;
      Result     : in out Byte_Seq;
      Len        : in out N32)
   with
     Pre =>
       Result'First = 0
       and then Result'Last <= N32'Last - 1
       and then Result'Length >= 600
       and then Len > 0
       and then Len <= N32 (Result'Length),
     Post =>
       HC.HRR_Cookie_Len = HC.HRR_Cookie_Len'Old
       and then HC.Sent_HRR_CCS = HC.Sent_HRR_CCS'Old
       and then Len <= N32 (Result'Length);

   procedure Append_PSK_Extension
     (Ticket     : in Session_Ticket;
      Get_Time   : in Get_Time_Fn;
      HC         : in out Handshake_Context;
      Retry_Mode : in Boolean;
      Result     : in out Byte_Seq;
      Len        : in out N32)
   is
      use SPARKTLSCrypto.Hashing.SHA256;
   begin
      if not (Ticket.Valid and then Ticket.PSK_Len in 32 | 48) then
         return;
      end if;
      if Retry_Mode and then HC.HRR_Cipher_Suite /= 0 then
         declare
            Needed_PSK_Len : constant N32 :=
              (if HC.HRR_Cipher_Suite = Wire_Suite_AES_256_GCM_SHA384 then 48 else 32);
         begin
            if Ticket.PSK_Len /= Needed_PSK_Len then
               return;
            end if;
         end;
      end if;
      HC.PSK.Offered := True;
      if Ticket.Ticket_Len > Max_Ticket_Len or else Len > N32 (Result'Length) - 319 then
         return;
      end if;
      --  (Old transcript-capacity guard deleted with the buffer: the
      --  streaming transcript has no size limit to protect.)

      declare
         Tick_Len         : constant N32 := Ticket.Ticket_Len;
         ID_Entry_Len     : constant N32 := 2 + Tick_Len + 4;
         IDs_Len          : constant N32 := 2 + ID_Entry_Len;
         Binder_Size      : constant N32 := (if Ticket.PSK_Len = 48 then 48 else 32);
         Binder_Entry_Len : constant N32 := 1 + Binder_Size;
         Binders_Len      : constant N32 := 2 + Binder_Entry_Len;
         PSK_Ext_Len      : constant N32 := 4 + IDs_Len + Binders_Len;
         New_Len          : constant N32 := Len + PSK_Ext_Len;

         --  CH body layout  see comments in Build_Client_Hello.
         Sid_Len_Off  : constant N32 := 4 + 2 + 32;
         Sid_Len_Read : constant N32 := N32 (Result (Sid_Len_Off));
      begin
         if New_Len > N32 (Result'Length)
           or else New_Len > 16#00FF_FFFF# + 4
           or else Sid_Len_Read > 32
         then
            return;
         end if;
         declare
            Suites_Len_Off : constant N32 := Sid_Len_Off + 1 + Sid_Len_Read;
         begin
            if Suites_Len_Off + 1 > Result'Last then
               return;
            end if;
            declare
               Suites_Len_Read : constant N32 :=
                 N32 (Result (Suites_Len_Off)) * 256 + N32 (Result (Suites_Len_Off + 1));
            begin
               if Suites_Len_Read > 18 then
                  return;
               end if;
               declare
                  Comp_Len_Off : constant N32 := Suites_Len_Off + 2 + Suites_Len_Read;
               begin
                  if Comp_Len_Off > Result'Last then
                     return;
                  end if;
                  declare
                     Comp_Len_Read : constant N32 := N32 (Result (Comp_Len_Off));
                  begin
                     if Comp_Len_Read > 1 then
                        return;
                     end if;
                     declare
                        Ext_Len_Offset : constant N32 := Comp_Len_Off + 1 + Comp_Len_Read;
                     begin
                        if Ext_Len_Offset + 1 > Result'Last then
                           return;
                        end if;
                        declare
                           Old_Ext_Len : constant N32 :=
                             N32 (Result (Ext_Len_Offset)) * 256
                             + N32 (Result (Ext_Len_Offset + 1));
                        begin
                           if Old_Ext_Len > 16#FFFF# - PSK_Ext_Len then
                              return;
                           end if;
                           declare
                              New_Ext_Len : constant N32 := Old_Ext_Len + PSK_Ext_Len;
                              P           : N32 := Len;
                           begin

                              Result (P) := 0;
                              Result (P + 1) := 16#29#;
                              P := P + 2;
                              Result (P) := Byte ((IDs_Len + Binders_Len) / 256);
                              Result (P + 1) := Byte ((IDs_Len + Binders_Len) mod 256);
                              P := P + 2;
                              Result (P) := Byte (ID_Entry_Len / 256);
                              Result (P + 1) := Byte (ID_Entry_Len mod 256);
                              P := P + 2;
                              Result (P) := Byte (Tick_Len / 256);
                              Result (P + 1) := Byte (Tick_Len mod 256);
                              P := P + 2;
                              Result (P .. P + Tick_Len - 1) := Ticket.Ticket (0 .. Tick_Len - 1);
                              P := P + Tick_Len;
                              declare
                                 Age_MS : Unsigned_64 := 0;
                              begin
                                 if Get_Time /= null and then Ticket.Received_At /= 0 then
                                    declare
                                       Now : constant Unsigned_64 :=
                                         Tickets_12.To_Unix_Seconds (Get_Time.all);
                                    begin
                                       if Now >= Ticket.Received_At
                                         and then Now - Ticket.Received_At
                                                  <= Unsigned_64'Last / 1000
                                       then
                                          Age_MS := (Now - Ticket.Received_At) * 1000;
                                       end if;
                                    end;
                                 end if;

                                 declare
                                    Age_Mod : constant Unsigned_32 :=
                                      Unsigned_32 (Age_MS mod 2 ** 32);
                                    A       : constant Unsigned_32 := Ticket.Age_Add + Age_Mod;
                                 begin
                                    Result (P) := Byte (A / 2 ** 24 mod 256);
                                    Result (P + 1) := Byte (A / 2 ** 16 mod 256);
                                    Result (P + 2) := Byte (A / 2 ** 8 mod 256);
                                    Result (P + 3) := Byte (A mod 256);
                                 end;
                              end;
                              P := P + 4;
                              Result (P) := Byte (Binder_Entry_Len / 256);
                              Result (P + 1) := Byte (Binder_Entry_Len mod 256);
                              P := P + 2;
                              Result (P) := Byte (Binder_Size);
                              P := P + 1;
                              declare
                                 Binder_Offset : constant N32 := P;
                              begin
                                 Result (P .. P + Binder_Size - 1) := (others => 0);
                                 P := P + Binder_Size;

                                 --  Patch handshake length
                                 declare
                                    New_Body_Len : constant N32 := P - 4;
                                 begin
                                    Result (1) := Byte (New_Body_Len / 65536);
                                    Result (2) := Byte ((New_Body_Len / 256) mod 256);
                                    Result (3) := Byte (New_Body_Len mod 256);
                                 end;
                                 Result (Ext_Len_Offset) := Byte (New_Ext_Len / 256);
                                 Result (Ext_Len_Offset + 1) := Byte (New_Ext_Len mod 256);

                                 --  Compute binder per RFC 8446 4.2.11.2.
                                 declare
                                    Trunc_Len : constant N32 := Binder_Offset - 3;
                                    --  Binder basis (phase carve): the
                                    --  initial CH has no transcript yet
                                    --  (Setup) -- the binder covers only
                                    --  the truncated CH, i.e. a fresh
                                    --  stream. The post-HRR CH2 (Engaged)
                                    --  covers CH1+HRR as before.
                                    --  Fresh CH1: the stream is empty, so
                                    --  Basis = TS covers both that and the
                                    --  post-HRR CH2 (stream holds CH1+HRR).
                                    Basis     : constant SPARKTLS_Transcript.Transcript_State :=
                                      HC.TS;
                                 begin
                                    --  Binder transcript = running
                                    --  transcript (empty for CH1;
                                    --  CH1+HRR in retry mode -- the
                                    --  stream holds exactly that) plus
                                    --  the truncated CH under
                                    --  construction: Suffix_* below.

                                    if Ticket.PSK_Len = 48 then
                                       declare
                                          Trunc_Hash384 : SPARKNaCl.Hashing.SHA384.Digest;
                                          Binder_Key48  :
                                            SPARKTLSCrypto.HKDF384.OKM384_Seq (0 .. 47);
                                          Finished_K48  :
                                            SPARKTLSCrypto.HKDF384.OKM384_Seq (0 .. 47);
                                          Binder_V48    : Bytes_48;
                                       begin
                                          SPARKTLS_Transcript.Suffix_384
                                            (Basis, Result (0 .. Trunc_Len - 1), Trunc_Hash384);
                                          Key_Schedule.Derive_Binder_Key_384
                                            (Binder_Key48, Ticket.PSK);
                                          Key_Schedule.Derive_Finished_Key_384
                                            (Finished_K48, Byte_Seq (Binder_Key48));
                                          SPARKTLSCrypto.HMAC384.HMAC_SHA_384
                                            (Output => Binder_V48,
                                             M      => Byte_Seq (Trunc_Hash384),
                                             K      => Byte_Seq (Finished_K48));
                                          Result (Binder_Offset .. Binder_Offset + 47) :=
                                            Binder_V48;
                                       end;
                                    else
                                       declare
                                          Trunc_Hash   : Digest;
                                          Binder_Key   : OKM_Seq (0 .. 31);
                                          Finished_Key : OKM_Seq (0 .. 31);
                                          Binder_Val   : Digest;
                                       begin
                                          SPARKTLS_Transcript.Suffix_256
                                            (Basis, Result (0 .. Trunc_Len - 1), Trunc_Hash);
                                          Key_Schedule.Derive_Binder_Key
                                            (Binder_Key, Bytes_32 (Ticket.PSK (0 .. 31)));
                                          Key_Schedule.Derive_Finished_Key
                                            (Finished_Key, Byte_Seq (Binder_Key));
                                          HMAC_SHA_256
                                            (Output => Binder_Val,
                                             M      => Trunc_Hash,
                                             K      => Byte_Seq (Finished_Key));
                                          Result (Binder_Offset .. Binder_Offset + 31) :=
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

   --  Extension payload builders.
   --
   --  Each constructs one extension's opaque payload and nothing else: no
   --  Session, no Handshake_Context, no RFLX context, no ghost state. They
   --  therefore carry no frame conditions at all. The bounds facts that had
   --  to be restated inline as loop invariants (SNI_Raw'First = 0,
   --  SNI_Raw'Last = 4 + Host_Len) are trivial here because the function
   --  owns the array, so they collapse to a Post the caller can use.
   --
   --  The emission quadruple stays at the call site: it updates the Ghost
   --  Remaining_Ext_Bits, and a ghost entity cannot be passed to a
   --  non-ghost subprogram.

   --  RFC 6066 3: list_len(2) + type(1) + name_len(2) + name.
   --  Name.Len may be 0: the caller emits server_name unconditionally,
   --  so this must handle the no-SNI case. (That the extension is sent at
   --  all with an empty host_name is questionable under RFC 6066 3, but
   --  it is the caller's existing behaviour and not changed here.)
   function Build_SNI_Raw (Name : Hostname_Buf) return Byte_Seq
   with
     Post => Build_SNI_Raw'Result'First = 0 and then Build_SNI_Raw'Result'Last = 4 + N32 (Name.Len);

   function Build_SNI_Raw (Name : Hostname_Buf) return Byte_Seq is
      Host_Len : constant N32 := N32 (Name.Len);
      R        : Byte_Seq (0 .. 4 + Host_Len) := (others => 0);
   begin
      R (0) := Byte ((Host_Len + 3) / 256);
      R (1) := Byte ((Host_Len + 3) mod 256);
      R (2) := 16#00#;  --  host_name type
      R (3) := Byte (Host_Len / 256);
      R (4) := Byte (Host_Len mod 256);
      for I in 1 .. Name.Len loop
         pragma Loop_Invariant (I in 1 .. Name.Len);
         R (4 + N32 (I)) := Byte (Character'Pos (Name.Data (I)));
      end loop;
      return R;
   end Build_SNI_Raw;

   --  RFC 8422 5.1.1 supported_groups. Either the single group the server
   --  selected in an HRR, or the full offered set.
   function Build_SG_Raw (Restrict : Boolean; Group : ECDHE_Group) return Byte_Seq
   with
     Post =>
       Build_SG_Raw'Result'First = 0
       and then Build_SG_Raw'Result'Last = (if Restrict then 3 else 7);

   function Build_SG_Raw (Restrict : Boolean; Group : ECDHE_Group) return Byte_Seq is
      Count : constant N32 := (if Restrict then 1 else 3);
      Wire  : constant Unsigned_16 := ECDHE_Group_Wire (Group);
      R     : Byte_Seq (0 .. 1 + 2 * Count) := (others => 0);
   begin
      R (0) := Byte ((2 * Count) / 256);
      R (1) := Byte ((2 * Count) mod 256);
      if Restrict then
         R (2) := Byte (Wire / 256);
         R (3) := Byte (Wire mod 256);
      else
         R (2) := 16#00#;
         R (3) := 16#1D#;  --  X25519
         R (4) := 16#00#;
         R (5) := 16#17#;  --  secp256r1
         R (6) := 16#00#;
         R (7) := 16#18#;  --  secp384r1
      end if;
      return R;
   end Build_SG_Raw;

   --  signature_algorithms payload (RFC 8446 4.2.3 / RFC 5246 7.4.1.4.1):
   --  the configured verify list when present, else the built-in
   --  9-algorithm preference order. SA_Raw'Last must be
   --  1 + 2 * Effective_Sig_Algo_Count (Cfg).
   procedure Fill_SA_Raw (Cfg : in Config; SA_Raw : out Byte_Seq)
   with
     Pre =>
       SA_Raw'First = 0
       and then SA_Raw'Last = 1 + 2 * N32 (Effective_Sig_Algo_Count (Cfg))
   is
      P : N32 := 2;
   begin
      SA_Raw := (others => 0);
      SA_Raw (0) := Byte ((SA_Raw'Length - 2) / 256);
      SA_Raw (1) := Byte ((SA_Raw'Length - 2) mod 256);
      if Cfg.Verify_Sig_Algo_Count > 0 then
         for J in Sig_Algo_Index loop
            exit when J >= Cfg.Verify_Sig_Algo_Count;
            SA_Raw (P) := Byte (Sig_Scheme_Wire (Cfg.Verify_Sig_Algos (J)) / 256);
            SA_Raw (P + 1) := Byte (Sig_Scheme_Wire (Cfg.Verify_Sig_Algos (J)) mod 256);
            P := P + 2;
         end loop;
      else
         --  Preference order: the server picks the first entry it
         --  can satisfy, so PSS/ECDSA/Ed25519 come before PKCS#1.
         --
         --  rsa_pkcs1_* are listed LAST but must be listed. TLS 1.2
         --  (RFC 5246 7.4.1.4.1) allows them for ServerKeyExchange
         --  and most RSA deployments still use them; omitting them
         --  made every such server unreachable -- the server signs
         --  with rsa_pkcs1 regardless and a conforming client then
         --  rejects a signature type it never offered (observed
         --  against badssl.com, 2026-08-16: OpenSSL fails the same
         --  way when restricted to our old list). We can already
         --  verify all three: see Cert_Verify.Verify_Signature,
         --  covered by the Wycheproof rsa_pkcs1_sha256/384/512
         --  vectors.
         --
         --  Listing them here is RFC 8446 4.2.3 conformant: in TLS
         --  1.3 rsa_pkcs1_* apply to signatures in CERTIFICATES and
         --  must not be accepted for CertificateVerify. That
         --  restriction belongs to the TLS 1.3 CV path, not to what
         --  we advertise.
         SA_Raw :=
           (16#00#,
            16#12#,          --  list_len=18 (9 algorithms)
            16#04#,
            16#03#,          --  ecdsa_secp256r1_sha256
            16#05#,
            16#03#,          --  ecdsa_secp384r1_sha384
            16#08#,
            16#04#,          --  rsa_pss_rsae_sha256
            16#08#,
            16#05#,          --  rsa_pss_rsae_sha384
            16#08#,
            16#06#,          --  rsa_pss_rsae_sha512
            16#08#,
            16#07#,          --  ed25519
            16#04#,
            16#01#,          --  rsa_pkcs1_sha256  (TLS 1.2)
            16#05#,
            16#01#,          --  rsa_pkcs1_sha384  (TLS 1.2)
            16#06#,
            16#01#);         --  rsa_pkcs1_sha512  (TLS 1.2)
      end if;
   end Fill_SA_Raw;

   --  key_share payload (RFC 8446 4.2.8). Retry_Single selects the
   --  single-entry CH2 shape for the HRR-selected group; otherwise the
   --  single configured initial entry. KS_Raw'Length must match the
   --  entry accounting done by the caller (KS_Data_Len).
   procedure Fill_KS_Raw
     (Retry_Single : in Boolean;
      Retry_Group  : in Maybe_ECDHE_Group;
      Retry_Entry  : in N32;
      Init_Group   : in ECDHE_Group;
      Init_Entry   : in N32;
      PK_Bytes     : in Byte_Seq;
      P256_PK_Enc  : in Byte_Seq;
      P384_PK_Enc  : in Byte_Seq;
      KS_Raw       : out Byte_Seq)
   is
      Retry_Group_A : constant Byte := Byte (ECDHE_Group_Wire (Retry_Group) / 256);
      Retry_Group_B : constant Byte := Byte (ECDHE_Group_Wire (Retry_Group) mod 256);
      Init_Group_A  : constant Byte := Byte (ECDHE_Group_Wire (Init_Group) / 256);
      Init_Group_B  : constant Byte := Byte (ECDHE_Group_Wire (Init_Group) mod 256);
   begin
      KS_Raw := (others => 0);
      if Retry_Single then
         --  Single-entry retry key_share.
         KS_Raw (0) := Byte (Retry_Entry / 256);
         KS_Raw (1) := Byte (Retry_Entry mod 256);

         case Retry_Group is
            when Group_X25519 =>
               KS_Raw (2) := Retry_Group_A;
               KS_Raw (3) := Retry_Group_B;
               KS_Raw (4) := 16#00#;
               KS_Raw (5) := 16#20#;
               KS_Raw (6 .. 37) := PK_Bytes;
            when Group_Secp256r1 =>
               KS_Raw (2) := Retry_Group_A;
               KS_Raw (3) := Retry_Group_B;
               KS_Raw (4) := 16#00#;
               KS_Raw (5) := 16#41#;
               KS_Raw (6 .. 70) := P256_PK_Enc;
            when Group_Secp384r1 =>
               KS_Raw (2) := Retry_Group_A;
               KS_Raw (3) := Retry_Group_B;
               KS_Raw (4) := 16#00#;
               KS_Raw (5) := 16#61#;
               KS_Raw (6 .. 102) := P384_PK_Enc;
            when Group_None =>
               null;
         end case;
      else
         --  CH1 / cookie-only retry: single configured initial entry.
         KS_Raw (0) := Byte (Init_Entry / 256);
         KS_Raw (1) := Byte (Init_Entry mod 256);

         case Init_Group is
            when Group_X25519 =>
               KS_Raw (2) := Init_Group_A;
               KS_Raw (3) := Init_Group_B;
               KS_Raw (4) := 16#00#;
               KS_Raw (5) := 16#20#;
               KS_Raw (6 .. 37) := PK_Bytes;
            when Group_Secp256r1 =>
               KS_Raw (2) := Init_Group_A;
               KS_Raw (3) := Init_Group_B;
               KS_Raw (4) := 16#00#;
               KS_Raw (5) := 16#41#;
               KS_Raw (6 .. 70) := P256_PK_Enc;
            when Group_Secp384r1 =>
               KS_Raw (2) := Init_Group_A;
               KS_Raw (3) := Init_Group_B;
               KS_Raw (4) := 16#00#;
               KS_Raw (5) := 16#61#;
               KS_Raw (6 .. 102) := P384_PK_Enc;
         end case;
      end if;
   end Fill_KS_Raw;

   --  Ephemeral key material for a ClientHello: X25519/P-256/P-384
   --  keypairs, client random, and the legacy session ID. In retry mode
   --  (CH2 after HRR) every value is REUSED from CH1 -- the server must
   --  recognise the share and the randoms must not change -- so only the
   --  public encodings are recomputed.
   procedure Generate_CH_Ephemerals
     (Cfg           : in Config;
      KE            : in out KE_State;
      Client_Random : in out Bytes_32;
      Session_ID    : in out Bytes_32;
      Retry_Mode    : in Boolean;
      PK_Bytes      : out Byte_Seq;
      P256_PK_Enc   : out Byte_Seq;
      P384_PK_Enc   : out Byte_Seq)
   with
     Pre =>
       PK_Bytes'First = 0
       and then PK_Bytes'Last = 31
       and then P256_PK_Enc'First = 0
       and then P256_PK_Enc'Last = 64
       and then P384_PK_Enc'First = 0
       and then P384_PK_Enc'Last = 96
   is
      procedure Gen_Random (Output : out Byte_Seq) renames Cfg.Random.all;
   begin
      --  Generate ephemeral X25519 keypair (Fiat X25519).
      --  In retry mode (CH2 for HRR), reuse the CH1 SK so the server
      --  still recognises the share if the selected_group matches.
      declare
         Tmp_X25519 : Bytes_32;
      begin
         if not Retry_Mode then
            Gen_Random (Byte_Seq (Tmp_X25519));
            KE.Local_SK := Tmp_X25519;
         end if;
         declare
            Basepoint : constant Bytes_32 := (9, others => 0);
         begin
            SPARKTLSCrypto.X25519.Scalar_Mult (PK_Bytes, KE.Local_SK, Basepoint);
         end;
      end;

      --  Generate ephemeral P-256 keypair (reused in retry mode).
      declare
         P256_Pt  : SPARKTLSCrypto.P256.Point.P256_Jacobian;
         Tmp_P256 : Bytes_32;
      begin
         if not Retry_Mode then
            Gen_Random (Byte_Seq (Tmp_P256));
            KE.P256_SK := Tmp_P256;
         end if;
         SPARKTLSCrypto.P256.Point.P256_Mulgen (P256_Pt, KE.P256_SK, 32);
         SPARKTLSCrypto.P256.Point.P256_To_Affine (P256_Pt);
         SPARKTLSCrypto.P256.Point.P256_Encode (P256_PK_Enc, P256_Pt);
      end;

      --  Generate ephemeral P-384 keypair (reused in retry mode).
      declare
         Tmp_P384 : Bytes_48;
      begin
         if not Retry_Mode then
            Gen_Random (Byte_Seq (Tmp_P384));
            KE.P384_SK := Tmp_P384;
         end if;
         SPARKTLSCrypto.P384.Point.P384_Mulgen (P384_PK_Enc, KE.P384_SK);
      end;

      --  Generate client random (retain CH1's random across HRR).
      declare
         Tmp_CR : Bytes_32;
      begin
         if not Retry_Mode then
            Gen_Random (Byte_Seq (Tmp_CR));
            Client_Random := Tmp_CR;
         end if;
      end;

      --  Generate 32-byte legacy session ID for middlebox compatibility
      --  (RFC 8446 D.4 / 4.1.2). TLS-1.2-only clients have no
      --  middlebox concern, so they SHOULD send an empty session_id;
      --  doing otherwise leaks "client speaks TLS 1.3" to a real
      --  TLS 1.2 server. BoGo TLS12NoSessionID-TLS13 exercises this.
      --  In retry mode, reuse the CH1 session_id verbatim.
      declare
         Legacy_Session_ID : Byte_Seq (0 .. 31);
      begin
         if not Retry_Mode then
            if Cfg.Versions = TLS_1_2_Only then
               Legacy_Session_ID := (others => 0);
            else
               Gen_Random (Legacy_Session_ID);
            end if;
            Session_ID := Legacy_Session_ID;
         end if;
      end;
   end Generate_CH_Ephemerals;

   type Shares_Len_Array is array (Maybe_ECDHE_Group) of N32;

   --  Single-entry shares_len, in bytes:
   --   secp256r1: group(2)+key_len(2)+key(65) = 69
   --   secp384r1: group(2)+key_len(2)+key(97) = 101
   --   X25519:    group(2)+key_len(2)+key(32) = 36
   Shares_Len : constant Shares_Len_Array := [
      Group_None      => 0,
      Group_Secp256r1 => 69,
      Group_Secp384r1 => 101,
      Group_X25519    => 36
   ];

   procedure Build_Client_Hello
     (Ticket     : in Session_Ticket;
      Get_Time   : in Get_Time_Fn;
      HC         : in out Handshake_Context;
      Result     : out Byte_Seq;
      Len        : out N32;
      Retry_Mode : in Boolean := False)
   is
      use RFLX.TLS_Handshake.Client_Hello;
      use RFLX.TLS_Common;

      --  Retry CH2 with a server-selected group: only that group's
      --  share goes in key_share. Server-chose-no-group =
      --  HC.HRR_Selected_Group = Group_None, same key_share as CH1.
      Retry_KS_Single         : constant Boolean :=
        Retry_Mode and then HC.HRR_Selected_Group /= Group_None;

      Retry_KS_Entry          : constant N32 := Shares_Len (HC.HRR_Selected_Group);
      Initial_Key_Share_Group : constant ECDHE_Group :=
        (if HC.Cfg.Client_Key_Share_Group = Group_None then Group_X25519
         else HC.Cfg.Client_Key_Share_Group);

      Initial_KS_Entry        : constant N32 := Shares_Len (Initial_Key_Share_Group);
      Restrict_Groups         : constant Boolean := HC.Cfg.Client_Key_Share_Group /= Group_None;
      SG_Group_Count          : constant N32 := (if Restrict_Groups then 1 else 3);

      --  Extension data sizes
      Host_Len     : constant N32 := N32 (HC.Cfg.Server_Name.Len);
      --  SNI data: sni_list_len(2) + host_type(1) + host_len(2) + host
      SNI_Data_Len : constant N32 := 5 + Host_Len;
      --  supported_groups data: list_len(2) + group(2) * count.
      SG_Data_Len  : constant N32 := 2 + 2 * SG_Group_Count;
      --  signature_algorithms data: list_len(2) + alg(2) * N
      SA_Count     : constant Sig_Algo_Count := Effective_Sig_Algo_Count (HC.Cfg);
      SA_Data_Len  : constant N32 := 2 + 2 * N32 (SA_Count);
      --  key_share data: shares_len(2) + entries.
      --
      --  CH1 strategy (RFC 8446 9.1 + standard browser practice):
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
        (if Retry_KS_Single then 2 + Retry_KS_Entry else 2 + Initial_KS_Entry);
      --  psk_key_exchange_modes data: list_len(1) + mode(1)
      PSK_Data_Len : constant N32 := 2;
      --  supported_versions data: list_len(1) + version(2) * N.
      --  RFC 8446 4.2.1 / RFC 5246: branch on Cfg.Versions so we
      --  only offer the versions our policy permits. Otherwise
      --  servers honoring our offer can negotiate a version we
      --  refuse later.
      SV_Data_Len  : constant N32 :=
        (case HC.Cfg.Versions is
           when Allow_Both => 5,   --  list_len + 2 versions
           when TLS_1_3_Only | TLS_1_2_Only => 3);  --  list_len + 1 version
      --  ec_point_formats data (RFC 8422 5.1.2): list_len(1) +
      --  format(1)=uncompressed. Required by BoGo for any TLS 1.2
      --  ECDHE suite (server's `ellipticOk` is false without it).
      EPF_Data_Len : constant N32 := 2;

      --  ALPN data: protocol_list_len(2) +
      --  (proto_len(1) + proto(N))*
      ALPN_Count    : constant Natural := Effective_ALPN_Count (HC.Cfg);
      ALPN_Data_Len : constant N32 := Effective_ALPN_Data_Len (HC.Cfg);
      ALPN_Ext_Len  : constant N32 := (if ALPN_Count > 0 then 4 + ALPN_Data_Len else 0);

      --  Cookie extension (RFC 8446 4.2.2)  only in CH2 when the
      --  HRR carried one. Body: cookie_len(2) + cookie<cookie_len>.
      Cookie_Bytes_Len : constant N32 :=
        (if Retry_Mode and then HC.HRR_Cookie_Len > 0 then HC.HRR_Cookie_Len else 0);
      Cookie_Data_Len  : constant N32 := (if Cookie_Bytes_Len > 0 then 2 + Cookie_Bytes_Len else 0);
      Cookie_Ext_Len   : constant N32 := (if Cookie_Bytes_Len > 0 then 4 + Cookie_Data_Len else 0);

      --  RFC 5077 session_ticket (TLS 1.2)  emit on the wire.
      --  CH_Extension_TLS is unconstrained on tag (see specs/
      --  CHANGES_FROM_UPSTREAM.md), so appending with tag 0x0023
      --  produces the correct bytes. Empty data on initial CH
      --  ("I support tickets but have none yet"); on resumption, the
      --  previously-issued ticket bytes go in the data field.
      Offer_TLS12_Ticket : constant Boolean := HC.Cfg.Versions in TLS_1_2_Only | Allow_Both;
      --  The bound comes from Build_Client_Hello's Pre (see the spec:
      --  "if TLS12_Resume_Ticket.Valid then Ticket_Len <=
      --  Max_TLS12_Ticket_Len"). Carrying it in the type keeps it available
      --  at every later use without re-deriving it through ~530 lines of
      --  RFLX calls.
      subtype TLS12_Ticket_Data_Len_Range is N32 range 0 .. Max_TLS12_Ticket_Len;

      TLS12_Ticket_Data_Len : constant TLS12_Ticket_Data_Len_Range :=
        (if Offer_TLS12_Ticket and then HC.Cfg.TLS12_Resume_Ticket.Valid
         then HC.Cfg.TLS12_Resume_Ticket.Ticket_Len
         else 0);
      TLS12_Ticket_Ext_Len  : constant N32 :=
        (if Offer_TLS12_Ticket then 4 + TLS12_Ticket_Data_Len else 0);

      --  extended_master_secret (0x0017, RFC 7627). Empty body, so the
      --  whole extension is tag(2) + length(2) = 4 bytes.
      --
      --  Offered only when TLS 1.2 is actually on the table. EMS is a
      --  TLS 1.2 mechanism: 1.3 always binds the key schedule to the
      --  transcript, so the extension is meaningless there and a 1.3
      --  server must not echo it (BoGo EMS-Forbidden-TLS13 checks that we
      --  reject an echo when 1.3 was negotiated). Sending it from a
      --  1.3-only client would be pure noise.
      Offer_EMS   : constant Boolean := HC.Cfg.Versions /= TLS_1_3_Only;
      EMS_Ext_Len : constant N32 := (if Offer_EMS then 4 else 0);

      --  Each extension: tag(2) + data_length(2) + data
      Ext_Total : constant N32 :=
        (4 + SNI_Data_Len) + (4 + SG_Data_Len) + (4 + SA_Data_Len) + (4 + KS_Data_Len)
        + (4 + PSK_Data_Len)
        + (4 + SV_Data_Len)
        + (4 + EPF_Data_Len)
        + ALPN_Ext_Len
        + Cookie_Ext_Len
        + TLS12_Ticket_Ext_Len
        + EMS_Ext_Len;

      --  ClientHello body: version(2) + random(32) + sid_len(1) +
      --  sid(0 | 32) + suites_len(2) + suites(18) + comp_len(1) +
      --  comp(1) + ext_len(2) + extensions. TLS_1_2_Only sends an
      --  empty session_id (RFC 8446 D.4 middlebox-compat trick is
      --  TLS 1.3-specific; sending the random 32 bytes from a TLS
      --  1.2-only client leaks "speaks TLS 1.3"). BoGo
      --  TLS12NoSessionID-TLS13.
      Session_ID_Len : constant N32 := (if HC.Cfg.Versions = TLS_1_2_Only then 0 else 32);

      --  RFC 7685: F5 firewall workaround. If the CH would otherwise
      --  land in the 256..511 "danger zone", append a padding
      --  extension (tag 0x0015) to push it to >= 512 bytes. BoGo
      --  ClientHelloPadding sets RequireClientHelloSize=512.
      Pre_Pad_Msg_Len : constant N32 := 4 + 59 + Session_ID_Len + Ext_Total;
      Need_Pad        : constant Boolean := Pre_Pad_Msg_Len in 256 .. 511;
      --  Inside the danger zone, pad to exactly 512 when possible
      --  (Pre_Pad_Msg_Len <= 508 leaves >= 4 bytes for the ext
      --  header). For 509..511 the minimum-size 4-byte ext header
      --  alone pushes us past 512  acceptable.
      Pad_Ext_Total   : constant N32 :=
        (if Need_Pad then (if Pre_Pad_Msg_Len <= 508 then 512 - Pre_Pad_Msg_Len else 4) else 0);
      Pad_Data_Len    : constant N32 := (if Pad_Ext_Total >= 4 then Pad_Ext_Total - 4 else 0);

      --  Mirrors RFLX Client_Hello_Extensions_Length (8 .. 2**16 - 1) so
      --  the wire conversion below is range-trivial: the bound is
      --  discharged ONCE here from the per-extension size constants,
      --  instead of being an unprovable N32 -> 16-bit conversion.
      subtype CH_Extensions_Total is N32 range 8 .. 2**16 - 1;
      Ext_Total_All : constant CH_Extensions_Total := Ext_Total + Pad_Ext_Total;
      CH_Body_Len   : constant N32 := 59 + Session_ID_Len + Ext_Total_All;
      CH_Msg_Len    : constant N32 := 4 + CH_Body_Len;

      Buf         : RBT.Bytes_Ptr := null;
      Ctx         : Context;
      PK_Bytes    : Byte_Seq (0 .. 31);   --  X25519 public key
      P256_PK_Enc : Byte_Seq (0 .. 64);   --  P-256 public key (uncompressed)
      P384_PK_Enc : Byte_Seq (0 .. 96);   --  P-384 public key (uncompressed)
   begin
      Result := (others => 0);
      Len := 0;
      HC.PSK.Offered := False;
      HC.Using_PSK := False;

      Generate_CH_Ephemerals
        (HC.Cfg, HC.KE, HC.Client_Random, HC.Legacy_Session_ID,
         Retry_Mode, PK_Bytes, P256_PK_Enc, P384_PK_Enc);

      --  PK_Bytes already set by X25519.Scalar_Mult above

      --  Bound the message BEFORE writing any of it. The equivalent check
      --  used to run only after Take_Buffer, which meant nothing told the
      --  prover the accumulated extensions fit the scratch buffer -- the
      --  Available_Space preconditions on the Set_* calls below were
      --  therefore unprovable. Ext_Total_All is config-driven (SNI, ALPN,
      --  HRR cookie up to 1024, TLS 1.2 ticket up to 2048, PSK), so this is
      --  a genuine input-dependent bound, not a check that can never fire.
      --  Failing here is identical in effect to failing at the old site:
      --  Len stays 0 and the caller sees no ClientHello.
      if CH_Msg_Len > N32 (Result'Length) then
         return;
      end if;

      --  Allocate a fixed, generously-oversized scratch buffer, the way
      --  RecordFlux's own examples build messages (ping: 1024 for an
      --  84-byte message; dccp/msg_write: 4096 for every packet). Because
      --  the buffer statically dwarfs any possible ClientHello, the RFLX
      --  field-setter Available_Space preconditions discharge from the
      --  type-level field-size maxima -- no per-field size accounting. The
      --  message occupies only CH_Body_Len bytes; the final copy below
      --  takes exactly that prefix, so the oversize is pure scratch, freed
      --  at Take_Buffer. (Sizing this exactly to CH_Body_Len is what forced
      --  the intractable accounting chain we removed.)
      Buf := new RBT.Bytes'(1 .. RBT.Index (Max_HS_Msg) => 0);
      Initialize (Ctx, Buf);

      --  Size-accounting chain, anchored at Initialize. Each step states
      --  the space remaining before the next field is written, so the
      --  whole CH_Body_Len = 59 + Session_ID_Len + Ext_Total_All formula
      --  is machine-checked against what the writes actually consume.
      --  A future edit that breaks a term fails here instead of emitting
      --  a malformed ClientHello (production builds use -gnatp, so this
      --  proof is the only backstop).

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
      Set_Cipher_Suites_Length (Ctx, RFLX.TLS_Handshake.Cipher_Suites_Length (18));

      --  Build cipher suite sequence
      declare
         Suites_Ctx : RFLX.TLS_Handshake.Cipher_Suites_TLS.Context;
      begin
         Switch_To_Cipher_Suites_TLS (Ctx, Suites_Ctx);
         Append_Cipher_Suite (Suites_Ctx, RFLX.Tls_Parameters.TLS_AES_128_GCM_SHA256);
         Append_Cipher_Suite (Suites_Ctx, RFLX.Tls_Parameters.TLS_CHACHA20_POLY1305_SHA256);
         Append_Cipher_Suite (Suites_Ctx, RFLX.Tls_Parameters.TLS_AES_256_GCM_SHA384);
         Append_Cipher_Suite (Suites_Ctx, RFLX.Tls_Parameters.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
         Append_Cipher_Suite (Suites_Ctx, RFLX.Tls_Parameters.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
         Append_Cipher_Suite (Suites_Ctx, RFLX.Tls_Parameters.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
         Append_Cipher_Suite (Suites_Ctx, RFLX.Tls_Parameters.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
         Append_Cipher_Suite (Suites_Ctx, RFLX.Tls_Parameters.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
         Append_Cipher_Suite (Suites_Ctx, RFLX.Tls_Parameters.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
         Update_Cipher_Suites_TLS (Ctx, Suites_Ctx);
      end;

      Set_Legacy_Compression_Methods_Length (Ctx, 1);
      --  Field_Size of the compression-methods field is data-dependent:
      --  it follows from the length field just written (1 byte = 8 bits).
      Set_Legacy_Compression_Methods (Ctx, To_RFLX (Byte_Seq'(0 => 16#00#)));
      Set_Extensions_Length
        (Ctx, RFLX.TLS_Handshake.Client_Hello_Extensions_Length (Ext_Total_All));
      --  Likewise: the extensions field size follows from the length
      --  field just written.
      --  One more link in the accounting chain, which previously stopped at
      --  F_Extensions_Length. That write consumes 2 bytes (57 -> 59), so the
      --  space remaining for the extensions field itself is
      --  CH_Body_Len - (59 + Session_ID_Len). Since
      --  CH_Body_Len = 59 + Session_ID_Len + Ext_Total_All, that is exactly
      --  8 * Ext_Total_All -- i.e. Field_Size of the field, which is the
      --  Sufficient_Space conjunct Switch_To_Extensions_TLS requires.
      --  Rung: CH_Body_Len is DEFINED as 59 + Session_ID_Len + Ext_Total_All,
      --  so this subtraction is definitional. Stated separately so the
      --  prover discharges the arithmetic on its own instead of doing it
      --  inside the Available_Space goal below, which timed out.

      --  Build extensions sequence
      declare
         Exts_Ctx           : RFLX.TLS_Handshake.CH_Extensions_TLS.Context;
         Remaining_Ext_Bits : RBT.Bit_Length := RBT.Bit_Length (8) * RBT.Bit_Length (Ext_Total_All)
         with Ghost;
      begin
         --  Byte-alignment of the extensions field start, which
         --  Switch_To_Extensions_TLS demands as a precondition.
         --
         --  RFLX generates "Post => True" for Field_First (and silences
         --  the resulting warning), so the start position carries no
         --  published contract. It does publish "rem Byte'Size = 0" for
         --  both Field_Size and Field_Last on this field. Since
         --  Last = First + Size - 1, that pins First: with Last and Size
         --  both byte-aligned, First rem 8 = 1 -- bit indices are
         --  1-based, so an aligned start is 1 where an aligned end is 0.
         --
         --  Derived here rather than by patching the generated contract:
         --  giving Field_First an explicit postcondition replaces the
         --  expression-function definition GNATprove already uses, which
         --  loses the field's *value* and costs more proofs than it buys
         --  (measured; see generated/README.md "REJECTED").

         --  Byte-aligned start of the extensions field: a
         --  Switch_To_Extensions_TLS precondition.
         pragma
           Assert
             (RFLX.TLS_Handshake.Client_Hello.Field_First
                (Ctx, RFLX.TLS_Handshake.Client_Hello.F_Extensions_TLS)
                rem RBT.Byte'Size
                = 1);
         Switch_To_Extensions_TLS (Ctx, Exts_Ctx);
         --  Chain anchor: the fresh sequence's free space is the tally.
         pragma
           Assert
             (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx) = Remaining_Ext_Bits);
         --  Walk the sequence context's free space back to the field
         --  size we already pinned above. Switch_To_Extensions_TLS
         --  publishes all three links: the sequence spans exactly the
         --  extensions field, and starts empty.
         --  Last - First + 1 = Field_Size, and Available_Space is
         --  Last - Sequence_Last, so the two coincide when the sequence
         --  is empty -- which the Switch postcondition guarantees.

         --  Extension 1: server_name (0x0000)
         declare
            SNI_Raw : constant Byte_Seq := Build_SNI_Raw (HC.Cfg.Server_Name);
         begin
            Append_CH_Extension (Exts_Ctx, RFLX.Tls_Extensiontype_Values.Server_Name, SNI_Raw);
            Remaining_Ext_Bits :=
              Remaining_Ext_Bits
              - RBT.Bit_Length (8) * (RBT.Bit_Length (4) + RBT.Bit_Length (SNI_Raw'Length));
            pragma
              Assert
                (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                   = Remaining_Ext_Bits);
         end;

         --  Extension 2: supported_groups (0x000A)
         declare
            SG_Raw : constant Byte_Seq := Build_SG_Raw (Restrict_Groups, Initial_Key_Share_Group);
         begin
            Append_CH_Extension (Exts_Ctx, RFLX.Tls_Extensiontype_Values.Supported_Groups, SG_Raw);
            Remaining_Ext_Bits :=
              Remaining_Ext_Bits
              - RBT.Bit_Length (8) * (RBT.Bit_Length (4) + RBT.Bit_Length (SG_Raw'Length));
            pragma
              Assert
                (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                   = Remaining_Ext_Bits);
         end;

         --  Extension 3: signature_algorithms (0x000D)
         declare
            SA_Raw : Byte_Seq (0 .. SA_Data_Len - 1);
         begin
            Fill_SA_Raw (HC.Cfg, SA_Raw);
            Append_CH_Extension
              (Exts_Ctx, RFLX.Tls_Extensiontype_Values.Signature_Algorithms, SA_Raw);
            Remaining_Ext_Bits :=
              Remaining_Ext_Bits
              - RBT.Bit_Length (8) * (RBT.Bit_Length (4) + RBT.Bit_Length (SA_Raw'Length));
            pragma
              Assert
                (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                   = Remaining_Ext_Bits);
         end;

         --  Extension 4: key_share (0x0033).
         --  CH1 / retry-no-group-change: three KeyShareEntry (X25519
         --  36, secp256r1 69, secp384r1 101). Retry with selected
         --  group: a single entry for that group only.
         declare
            KS_Raw : Byte_Seq (0 .. KS_Data_Len - 1);
         begin
            Fill_KS_Raw
              (Retry_KS_Single,
               HC.HRR_Selected_Group,
               Retry_KS_Entry,
               Initial_Key_Share_Group,
               Initial_KS_Entry,
               PK_Bytes,
               P256_PK_Enc,
               P384_PK_Enc,
               KS_Raw);
            Append_CH_Extension (Exts_Ctx, RFLX.Tls_Extensiontype_Values.Key_Share, KS_Raw);
            Remaining_Ext_Bits :=
              Remaining_Ext_Bits
              - RBT.Bit_Length (8) * (RBT.Bit_Length (4) + RBT.Bit_Length (KS_Raw'Length));
            pragma
              Assert
                (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                   = Remaining_Ext_Bits);
         end;

         --  Extension 4.5 (retry only): cookie (0x002C)  echo back
         --  the cookie the server sent in HRR. RFC 8446 4.2.2.
         if Cookie_Bytes_Len > 0 then
            declare
               Cookie_Raw : Byte_Seq (0 .. Cookie_Data_Len - 1) := (others => 0);
            begin
               Cookie_Raw (0) := Byte (Cookie_Bytes_Len / 256);
               Cookie_Raw (1) := Byte (Cookie_Bytes_Len mod 256);
               for I in 0 .. Cookie_Bytes_Len - 1 loop
                  Cookie_Raw (2 + I) := HC.HRR_Cookie (I);
               end loop;
               Append_CH_Extension (Exts_Ctx, RFLX.Tls_Extensiontype_Values.Cookie, Cookie_Raw);
               Remaining_Ext_Bits :=
                 Remaining_Ext_Bits
                 - RBT.Bit_Length (8) * (RBT.Bit_Length (4) + RBT.Bit_Length (Cookie_Raw'Length));
               pragma
                 Assert
                   (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                      = Remaining_Ext_Bits);
            end;
         end if;

         --  Extension 5: psk_key_exchange_modes (0x002D)
         declare
            PSK_Raw : constant Byte_Seq (0 .. PSK_Data_Len - 1) :=
              (16#01#, 16#01#);  --  list_len=1, psk_dhe_ke
         begin
            Append_CH_Extension
              (Exts_Ctx, RFLX.Tls_Extensiontype_Values.Psk_Key_Exchange_Modes, PSK_Raw);
            Remaining_Ext_Bits :=
              Remaining_Ext_Bits
              - RBT.Bit_Length (8) * (RBT.Bit_Length (4) + RBT.Bit_Length (PSK_Raw'Length));
            pragma
              Assert
                (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                   = Remaining_Ext_Bits);
         end;

         --  Extension 6: supported_versions (0x002B).
         declare
            SV_Raw : constant Byte_Seq (0 .. SV_Data_Len - 1) :=
              (case HC.Cfg.Versions is
                 when Allow_Both => Byte_Seq'(16#04#, 16#03#, 16#04#, 16#03#, 16#03#),
                 when TLS_1_3_Only => Byte_Seq'(16#02#, 16#03#, 16#04#),
                 when TLS_1_2_Only => Byte_Seq'(16#02#, 16#03#, 16#03#));
         begin
            Append_CH_Extension
              (Exts_Ctx, RFLX.Tls_Extensiontype_Values.Supported_Versions, SV_Raw);
            Remaining_Ext_Bits :=
              Remaining_Ext_Bits
              - RBT.Bit_Length (8) * (RBT.Bit_Length (4) + RBT.Bit_Length (SV_Raw'Length));
            pragma
              Assert
                (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                   = Remaining_Ext_Bits);
         end;

         --  Extension 7: ec_point_formats (0x000B)  RFC 8422 5.1.2.
         declare
            EPF_Raw : constant Byte_Seq (0 .. EPF_Data_Len - 1) := (16#01#, 16#00#);
         begin
            Append_CH_Extension (Exts_Ctx, RFLX.Tls_Extensiontype_Values.Ec_Point_Formats, EPF_Raw);
            Remaining_Ext_Bits :=
              Remaining_Ext_Bits
              - RBT.Bit_Length (8) * (RBT.Bit_Length (4) + RBT.Bit_Length (EPF_Raw'Length));
            pragma
              Assert
                (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                   = Remaining_Ext_Bits);
         end;

         --  Extension 9: ALPN (0x0010)  if configured
         if ALPN_Count > 0 then
            declare
               ALPN_Raw : Byte_Seq (0 .. ALPN_Data_Len - 1) := (others => 0);
            begin
               Build_ALPN_Extension_Data (HC.Cfg, ALPN_Raw);
               Append_CH_Extension
                 (Exts_Ctx,
                  RFLX.Tls_Extensiontype_Values.Application_Layer_Protocol_Negotiation,
                  ALPN_Raw);
               Remaining_Ext_Bits :=
                 Remaining_Ext_Bits
                 - RBT.Bit_Length (8) * (RBT.Bit_Length (4) + RBT.Bit_Length (ALPN_Raw'Length));
               pragma
                 Assert
                   (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                      = Remaining_Ext_Bits);
            end;
         end if;

         --  Extension 9b (conditional): RFC 5077 session_ticket (0x0023).
         --  Empty data on initial CH; resume ticket bytes when resuming.
         if Offer_TLS12_Ticket then
            if TLS12_Ticket_Data_Len > 0 then
               --  Link the slice length back to the bounded
               --  constant; without it the Available_Space fact
               --  below cannot reach Data'Length in
               --  Append_CH_Extension's precondition.
               Append_CH_Extension
                 (Exts_Ctx,
                  RFLX.Tls_Extensiontype_Values.Session_Ticket,
                  HC.Cfg.TLS12_Resume_Ticket.Ticket (0 .. TLS12_Ticket_Data_Len - 1));
               Remaining_Ext_Bits :=
                 Remaining_Ext_Bits
                 - RBT.Bit_Length (8)
                   * (RBT.Bit_Length (4) + RBT.Bit_Length (TLS12_Ticket_Data_Len));
               pragma
                 Assert
                   (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                      = Remaining_Ext_Bits);
            else
               --  Empty body: Append_CH_Extension's Data is zero-len.
               declare
                  Empty : constant Byte_Seq (1 .. 0) := (others => 0);
               begin
                  Append_CH_Extension
                    (Exts_Ctx, RFLX.Tls_Extensiontype_Values.Session_Ticket, Empty);
                  Remaining_Ext_Bits :=
                    Remaining_Ext_Bits - RBT.Bit_Length (8) * RBT.Bit_Length (4);
                  pragma
                    Assert
                      (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                         = Remaining_Ext_Bits);
               end;
            end if;
            HC.T12.Sent_Ticket_Ext := True;
         end if;

         --  extended_master_secret (RFC 7627, tag 0x0017). Empty body.
         --
         --  RFC 7627 5.1: the client offers it; a 1.2 server that also
         --  supports it echoes the extension, and BOTH sides then derive
         --  master_secret = PRF(pms, "extended master secret",
         --  session_hash) instead of using the two randoms as the seed.
         --  Our derivation for both roles is already implemented and
         --  gated on HC.Use_EMS (client: sparktls-client-tls12.adb ~356,
         --  server: sparktls-server-tls12.adb ~1100); until now nothing
         --  ever set that flag on the client, because the offer was
         --  never sent -- so the server had nothing to echo.
         --
         --  Not offered by a 1.3-only client (see Offer_EMS): TLS 1.3
         --  binds its key schedule to the transcript unconditionally, so
         --  the extension is meaningless there and a 1.3 server must not
         --  echo it.
         if Offer_EMS then
            declare
               Empty : constant Byte_Seq (1 .. 0) := (others => 0);
            begin
               Append_CH_Extension
                 (Exts_Ctx, RFLX.Tls_Extensiontype_Values.Extended_Master_Secret, Empty);
               Remaining_Ext_Bits := Remaining_Ext_Bits - RBT.Bit_Length (8) * RBT.Bit_Length (4);
               pragma
                 Assert
                   (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                      = Remaining_Ext_Bits);
            end;
         end if;

         --  Extension 9 (conditional): padding (RFC 7685, tag 0x0015).
         if Pad_Ext_Total > 0 then
            declare
               Pad_Raw : constant Byte_Seq (0 .. Pad_Data_Len - 1) := (others => 0);
            begin
               Append_CH_Extension (Exts_Ctx, RFLX.Tls_Extensiontype_Values.Padding, Pad_Raw);
               Remaining_Ext_Bits :=
                 Remaining_Ext_Bits
                 - RBT.Bit_Length (8) * (RBT.Bit_Length (4) + RBT.Bit_Length (Pad_Raw'Length));
               pragma
                 Assert
                   (RFLX.TLS_Handshake.CH_Extensions_TLS.Available_Space (Exts_Ctx)
                      = Remaining_Ext_Bits);
            end;
         end if;

         Update_Extensions_TLS (Ctx, Exts_Ctx);
      end;

      --  Extract serialized body and prepend handshake header
      Take_Buffer (Ctx, Buf);

      if CH_Msg_Len > N32 (Result'Length) then
         RFLX_Free (Buf);
         return;
      end if;

      Result (0) := HS_Msg_Wire (HT_Client_Hello);
      Result (1) := Byte (CH_Body_Len / 65536);
      Result (2) := Byte ((CH_Body_Len / 256) mod 256);
      Result (3) := Byte (CH_Body_Len mod 256);
      Result (4 .. 4 + CH_Body_Len - 1) := To_NaCl (Buf.all (1 .. RBT.Index (CH_Body_Len)));

      RFLX_Free (Buf);
      Len := CH_Msg_Len;

      --  0-RTT (RFC 8446 4.2.10) intentionally not offered  see
      --  the Cfg.Resume_Ticket comment in sparktls.ads for the
      --  rationale. We never write the early_data extension into
      --  CH; HC.Early_Data_Offered on the client side stays False.

      --  If we have a cached session ticket, append pre_shared_key
      --  extension. This MUST be the last extension per RFC 8446
      --  4.2.11. We patch the extensions list length and
      --  handshake length after.
      --
      --  Binder hash matches the ticket's hash: PSK_Len=32 -> SHA-256;
      --  PSK_Len=48 -> SHA-384. Both paths share the same wire
      --  layout (only the binder VALUE size differs).
      --  Proof decomposition: the prover cannot re-establish the whole
      --  predicate in one step after the HC component writes above.
      --  Each conjunct is discharged separately, then used as a lemma.
      if Len > 0 then
         Append_PSK_Extension (Ticket, Get_Time, HC, Retry_Mode, Result, Len);
      end if;

   end Build_Client_Hello;

   ----------------------------------------------------------------------------
   --  Parse procedures (using RecordFlux-generated parsers)
   ----------------------------------------------------------------------------

   --  E2 (#131): ServerHello extension pre-scan collection. Entry
   --  record and array live at package-body level so the collector's
   --  Post and the pass-2 driver can name the same fact.
   type SH_Ext_Entry is record
      Tag    : Unsigned_16;
      E_Len  : N32;
      Offset : N32;          --  start of body bytes in Data
   end record;
   subtype SH_Ext_Index is Positive range 1 .. 32;
   type SH_Ext_Array is array (SH_Ext_Index) of SH_Ext_Entry;

   --  Every collected entry's body window lies inside First .. Last.
   function Exts_Well_Formed
     (Exts  : SH_Ext_Array;
      N_Ext : Natural;
      First : N32;
      Last  : N32) return Boolean
   is (N_Ext <= Exts'Last
       and then (for all J in 1 .. N_Ext
                 => Exts (J).Offset >= First
                 and then Exts (J).Offset <= Last + 1
                 and then Exts (J).E_Len <= Last + 1 - Exts (J).Offset))
   with Ghost, Pre => Last < N32'Last;

   --  Pass 1 of the pre-scan: byte-walk the extensions block
   --  (Ext_Start .. Data'Last), reject oversize or duplicate
   --  extensions, collect (tag, len, off) into Exts, and detect the
   --  RFC 8446 4.2.1 supported_versions TLS 1.3 marker. No HC formal:
   --  the TLS 1.3 marker is an out Boolean the caller applies.
   procedure Collect_SH_Extensions
     (Data       : in Byte_Seq;
      Ext_Start  : in N32;
      Is_HRR_Msg : in Boolean;
      Exts       : out SH_Ext_Array;
      N_Ext      : out Natural;
      Has_TLS13  : out Boolean;
      OK         : out Boolean;
      Err        : out Error_Code)
   with
     Pre  =>
       Data'Length in 39 .. Max_HS_Msg
       and then Data'Last < N32 (Natural'Last)
       and then Ext_Start >= Data'First
       and then Ext_Start <= Data'Last + 1,
     Post =>
       (if OK then Exts_Well_Formed (Exts, N_Ext, Data'First, Data'Last))
   is
      Ext_End : constant N32 := Data'Last + 1;
      P       : N32 := Ext_Start;
   begin
      Exts      := (others => (0, 0, 0));
      N_Ext     := 0;
      Has_TLS13 := False;
      OK        := True;
      Err       := No_Error;

      while P <= Ext_End - 4 loop
         pragma Loop_Invariant (N_Ext <= Exts'Last);
         pragma Loop_Invariant (P >= Data'First);
         pragma Loop_Invariant (P <= Ext_End);
         pragma
           Loop_Invariant
             (for all J in 1 .. N_Ext
              => Exts (J).Offset >= Data'First
              and then Exts (J).Offset <= Data'Last + 1
              and then Exts (J).E_Len <= Data'Last + 1 - Exts (J).Offset);
         declare
            pragma Assert (P <= Data'Last - 3);
            Tag_U16 : constant Unsigned_16 :=
              Unsigned_16 (Data (P)) * 256 + Unsigned_16 (Data (P + 1));
            E_Len   : constant N32 := N32 (Data (P + 2)) * 256 + N32 (Data (P + 3));
         begin
            if E_Len > Ext_End - P - 4 then
               Err := Decode_Error;
               OK := False;
               return;
            end if;
            for I in 1 .. N_Ext loop
               if Exts (I).Tag = Tag_U16 then
                  --  RFC 8446 4.2: duplicate ext in SH/EE ->
                  --  decode_error. In HRR specifically BoringSSL
                  --  expects illegal_parameter
                  --  (HelloRetryRequest-DuplicateCookie /
                  --  DuplicateCurve).
                  Err := (if Is_HRR_Msg then Illegal_Parameter else Decode_Error);
                  OK := False;
                  return;
               end if;
            end loop;
            if N_Ext < Exts'Last then
               N_Ext := N_Ext + 1;
               Exts (N_Ext) := (Tag_U16, E_Len, P + 4);
            end if;
            if Tag_U16 = 16#002B# then
               --  RFC 8446 4.2.1: in SH/HRR, body is exactly the
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
                  Has_TLS13 := True;
               end if;
            end if;
            P := P + 4 + E_Len;
         end;
      end loop;
   end Collect_SH_Extensions;

   --  E3a (#131): HRR cookie extension body (RFC 8446 4.2.2), wire
   --  shape cookie<1..2^16-1>. The caller guards tag, E_Len >= 2 and
   --  the Data window; this owns length parse, the empty-cookie
   --  rejection (illegal_parameter; BoGo
   --  HelloRetryRequest-EmptyCookie-TLS13) and the byte copy. An
   --  oversize cookie is ignored (Cookie and Cookie_Len unchanged),
   --  matching the inline original. Cookie/Cookie_Len are the
   --  caller's HC fields passed as formals, so the cookie invariant
   --  that used to thread the whole 420-line body is now this Post.
   procedure Extract_HRR_Cookie
     (Data       : in Byte_Seq;
      Off        : in N32;
      E_Len      : in N32;
      Cookie     : in out Byte_Seq;
      Cookie_Len : in out N32;
      OK         : out Boolean;
      Err        : out Error_Code)
   with
     Pre  =>
       Data'Last < N32 (Natural'Last)
       and then E_Len >= 2
       and then Off >= Data'First
       and then Off + E_Len <= Data'Last + 1
       and then Cookie'First = 0
       and then Cookie'Length = 1024
       and then Cookie_Len <= N32 (Cookie'Length),
     Post =>
       Cookie_Len <= N32 (Cookie'Length)
   is
      C_Len : constant N32 :=
        N32 (Data (Off)) * 256 + N32 (Data (Off + 1));
   begin
      OK  := True;
      Err := No_Error;
      if C_Len = 0 or else 2 + C_Len /= E_Len then
         Err := Illegal_Parameter;
         OK := False;
         return;
      end if;
      if C_Len <= N32 (Cookie'Length) then
         Cookie_Len := C_Len;
         for K in 0 .. C_Len - 1 loop
            pragma Loop_Invariant (Cookie_Len <= N32 (Cookie'Length));
            Cookie (K) := Data (Off + 2 + K);
         end loop;
      end if;
   end Extract_HRR_Cookie;

   --  E3b (#131): TLS 1.2 ec_point_formats extension body, RFC 8422
   --  5.1.2: the vector must be well-formed and include
   --  uncompressed(0), the only point format this implementation
   --  accepts. The caller guards Where = E_SH12, the tag and the Data
   --  window; empty body, bad list length or an unacceptable list ->
   --  decode_error. Pure function of Data.
   procedure Check_EC_Point_Formats_Body
     (Data  : in Byte_Seq;
      Off   : in N32;
      E_Len : in N32;
      OK    : out Boolean;
      Err   : out Error_Code)
   with
     Pre  =>
       Data'Last < N32 (Natural'Last)
       and then Off >= Data'First
       and then Off + E_Len <= Data'Last + 1
   is
   begin
      OK  := True;
      Err := No_Error;
      if E_Len = 0 then
         Err := Decode_Error;
         OK  := False;
         return;
      end if;
      declare
         List_Len : constant N32 := N32 (Data (Off));
      begin
         if List_Len = 0 or else List_Len /= E_Len - 1 then
            Err := Decode_Error;
            OK  := False;
            return;
         end if;
         pragma Assert (E_Len >= 2);
         pragma Assert (Off + E_Len - 1 <= Data'Last);
         if not EC_Point_Formats_Acceptable (Data (Off + 1 .. Off + E_Len - 1)) then
            Err := Decode_Error;
            OK  := False;
            return;
         end if;
      end;
   end Check_EC_Point_Formats_Body;

   --  E3c (#131): HRR key_share body -- in HRR it is just
   --  `selected_group(2)`, no key_exchange (RFC 8446 4.1.4). The
   --  HRR's selected_group MUST be one the client offered -- and we
   --  only ever offer the three in Maybe_ECDHE_Group. Unknown wire
   --  values map to Group_None; the caller rejects those with
   --  illegal_parameter HERE rather than at the CH2-rebuild step,
   --  which is the earlier RFC-correct alert. Pure function of Data;
   --  the caller guards tag, E_Len = 2 and the window, and owns the
   --  HC writes.
   function Extract_HRR_Key_Share
     (Data : Byte_Seq;
      Off  : N32) return Maybe_ECDHE_Group
   is (Group_From_Wire
         (Unsigned_16 (Data (Off)) * 256 + Unsigned_16 (Data (Off + 1))))
   with
     Pre => Off >= Data'First and then Off <= Data'Last - 1;

   --  E3d (#131): SH pre_shared_key body check. RFC 8446 4.2.11: in
   --  SH (not HRR) the body is `selected_identity` (uint16). We offer
   --  exactly one PSK identity (Ticket), so the only valid value is
   --  0; the caller rejects anything else with illegal_parameter and
   --  latches Using_PSK on success. The matrix has already rejected
   --  pre_shared_key in SH if we did not offer it
   --  (Requires_Offer => True). Caller guards tag, E_Len = 2 and the
   --  window.
   function PSK_Selected_Identity_Is_Zero
     (Data : Byte_Seq;
      Off  : N32) return Boolean
   is (Unsigned_16 (Data (Off)) * 256 + Unsigned_16 (Data (Off + 1)) = 0)
   with
     Pre => Off >= Data'First and then Off <= Data'Last - 1;

   --  E4b (#131): pass 2 of the pre-scan -- matrix policy plus
   --  per-tag body validation over the collected entries. The only
   --  pre-scan constituent with an HC formal; its writes are the
   --  single-field latches (Use_EMS, Using_PSK, HRR_Selected_Group,
   --  Ext_Parse_Err) plus the cookie stash via Extract_HRR_Cookie,
   --  which is what makes the frame Post a 4-write argument instead
   --  of a 400-line path analysis.
   procedure Apply_SH_Extension_Bodies
     (Data       : in Byte_Seq;
      Exts       : in SH_Ext_Array;
      N_Ext      : in Natural;
      Is_HRR_Msg : in Boolean;
      HC         : in out Engaged_Context;
      ALPN       : in out Hostname_Buf;
      OK         : out Boolean;
      Err        : out Error_Code)
   with
     Pre  =>
       Data'Length in 39 .. Max_HS_Msg
       and then Data'Last < N32 (Natural'Last)
       and then Exts_Well_Formed (Exts, N_Ext, Data'First, Data'Last)
       and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length),
     Post =>
       HC.TS = HC.TS'Old
       and then (if HC.Got_HRR'Old then HC.Got_HRR)
       and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
   is
      Saved_TS      : constant SPARKTLS_Transcript.Transcript_State := HC.TS
      with Ghost;
      Saved_Got_HRR : constant Boolean := HC.Got_HRR
      with Ghost;
   begin
      OK  := True;
      Err := No_Error;

      --  Pass 2: matrix policy + per-tag body validation. Single
      --  loop over the collected Exts. Matrix runs first
      --  (unsupported_extension / decode_error for empty-echo
      --  violations); body validators run only on matrix-OK entries.
      declare
         Where : constant Ext_Where :=
           (if Is_HRR_Msg then E_HRR elsif HC.Has_TLS_1_3 then E_SH13 else E_SH12);
      begin
         pragma Assert (N_Ext <= Exts'Last);
         for I in 1 .. N_Ext loop
            pragma Loop_Invariant (N_Ext <= Exts'Last);
            pragma Loop_Invariant (HC.TS = HC.TS'Loop_Entry);
            pragma Loop_Invariant (if Saved_Got_HRR then HC.Got_HRR);
            pragma Loop_Invariant (HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length));

            pragma
              Loop_Invariant
                (for all J in 1 .. N_Ext
                 => Exts (J).Offset >= Data'First
                 and then Exts (J).Offset <= Data'Last + 1
                 and then Exts (J).E_Len <= Data'Last + 1 - Exts (J).Offset);
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
                  Err := V_Err;
                  OK := False;
                  pragma
                    Assert
                      (HC.TS = Saved_TS
                       and then (if Saved_Got_HRR then HC.Got_HRR));
                  return;
               end if;

               --  Per-tag body validation (RFC 7301 ALPN  shared
               --  helper, same wire shape used in TLS 1.3 EE).
               if Exts (I).Tag = 16#0010# and then Exts (I).Offset + Exts (I).E_Len <= Data'Last + 1
               then
                  Validate_ALPN_Echo_Body
                    (Data       => Data,
                     Body_Start => Exts (I).Offset,
                     E_Len      => Exts (I).E_Len,
                     HC         => HC,
                     ALPN       => ALPN,
                     OK         => V_OK,
                     Err        => V_Err);
                  if not V_OK then
                     Err := V_Err;
                     OK := False;
                     pragma
                       Assert
                         (HC.TS = Saved_TS
                          and then (if Saved_Got_HRR then HC.Got_HRR));
                     return;
                  end if;
               end if;

               --  RFC 8422 5.1.2: if a TLS 1.2 server sends
               --  ec_point_formats, the vector must be well-formed and
               --  include uncompressed(0), the only point format this
               --  implementation accepts.
               if Where = E_SH12
                 and then Exts (I).Tag = 16#000B#
                 and then Exts (I).Offset + Exts (I).E_Len <= Data'Last + 1
               then
                  Check_EC_Point_Formats_Body
                    (Data  => Data,
                     Off   => Exts (I).Offset,
                     E_Len => Exts (I).E_Len,
                     OK    => V_OK,
                     Err   => V_Err);
                  if not V_OK then
                     Err := V_Err;
                     OK := False;
                     pragma
                       Assert
                         (HC.TS = Saved_TS
                          and then (if Saved_Got_HRR then HC.Got_HRR));
                     return;
                  end if;
               end if;

               --  RFC 8446 4.1.4 HRR-specific body extraction.
               --  In HRR, key_share body is just `selected_group(2)`
               --  (no key_exchange); cookie body is `cookie_len(2) +
               --  cookie<cookie_len>` (RFC 8446 4.2.2). Stash both
               --  in HC for the caller's CH2-rebuild step.
               if Is_HRR_Msg
                 and then Exts (I).Tag = 16#0033#  --  key_share
                 and then Exts (I).Offset <= Data'Last - 1
                 and then Exts (I).E_Len = 2
               then
                  declare
                     KS_Group : constant Maybe_ECDHE_Group :=
                       Extract_HRR_Key_Share (Data, Exts (I).Offset);
                  begin
                     if KS_Group /= Group_None then
                        HC.HRR_Selected_Group := KS_Group;
                     else
                        HC.Ext_Parse_Err := Illegal_Parameter;
                     end if;
                  end;
               end if;
               --  RFC 8446 4.2.11: pre_shared_key in SH (not HRR)
               --  carries `selected_identity` (uint16). We offer
               --  exactly one PSK identity (Ticket), so the only
               --  valid selected_identity value is 0; anything else
               --  is illegal_parameter. The matrix has already
               --  rejected pre_shared_key in SH if we did not
               --  offer it (Requires_Offer => True).
               if not Is_HRR_Msg
                 and then Exts (I).Tag = 16#0029#  --  pre_shared_key
                 and then Exts (I).Offset <= Data'Last - 1
                 and then Exts (I).E_Len = 2
               then
                  if PSK_Selected_Identity_Is_Zero (Data, Exts (I).Offset) then
                     HC.Using_PSK := True;
                  else
                     Err := Illegal_Parameter;
                     OK := False;
                     pragma
                       Assert
                         (HC.TS = Saved_TS
                          and then (if Saved_Got_HRR then HC.Got_HRR));
                     return;
                  end if;
               end if;
               if Is_HRR_Msg
                 and then Exts (I).Tag = 16#002C#  --  cookie
                 and then Exts (I).E_Len >= 2
                 and then Exts (I).Offset + Exts (I).E_Len <= Data'Last + 1
               then
                  Extract_HRR_Cookie
                    (Data       => Data,
                     Off        => Exts (I).Offset,
                     E_Len      => Exts (I).E_Len,
                     Cookie     => HC.HRR_Cookie,
                     Cookie_Len => HC.HRR_Cookie_Len,
                     OK         => V_OK,
                     Err        => V_Err);
                  if not V_OK then
                     Err := V_Err;
                     OK := False;
                     pragma
                       Assert
                         (HC.TS = Saved_TS
                          and then (if Saved_Got_HRR then HC.Got_HRR));
                     return;
                  end if;
               end if;
               --  RFC 7627 s5.1: record the server's
               --  extended_master_secret echo. BOTH this and the
               --  Tag_Is_Offered arm for 16#0017# (sparktls.ads) are
               --  required, and neither alone is enough:
               --    * without the Tag_Is_Offered arm, Requires_Offer
               --      rejects the server's legitimate echo with
               --      unsupported_extension and the handshake dies
               --      before this flag matters;
               --    * without this scan, the handshake completes but
               --      HC.Use_EMS stays False, so the client derives
               --      with the legacy label while the server used
               --      "extended master secret", and Finished
               --      verification fails.
               --  Handshake.TLS12.Parse_Server_Hello_12 also sets
               --  Use_EMS, but it runs only as a fallback when this
               --  parser fails (sparktls-client.adb ~4015), so it
               --  cannot be relied on.
               --  Verified by BoGo ExtendedMasterSecret-TLS12-Client:
               --  reverting either change alone puts that test back in
               --  the failing set.
               --  E4a (#131): folded here from the former third loop;
               --  per-entry setting is equivalent because any pass-2
               --  failure sets OK False and the caller aborts the
               --  handshake, so Use_EMS ordering on failure paths is
               --  moot.
               if Exts (I).Tag = 16#0017# then
                  HC.Use_EMS := True;
               end if;
            end;
         end loop;
      end;
   end Apply_SH_Extension_Bodies;

   --  E1 (#131): P0 of the ServerHello extension pre-scan -- the
   --  fixed-header walk. Pure function of Data (no HC formal), so
   --  every early exit leaves the caller's frame facts trivially
   --  intact; the seven exit-fact frames the inline version
   --  carried become plain returns.
   --  Outcomes: Scan_OK -> extensions block is Ext_Start .. Data'Last
   --            and ends exactly at the declared length;
   --            not Scan_OK and Malformed -> reject, decode_error;
   --            not Scan_OK and not Malformed -> skip the pre-scan
   --            without error (defensive shapes the strict RFLX parse
   --            adjudicates on its own, as before the extraction).
   procedure Scan_SH_Fixed_Header
     (Data       : in Byte_Seq;
      Is_HRR_Msg : in Boolean;
      Ext_Start  : out N32;
      Scan_OK    : out Boolean;
      Malformed  : out Boolean)
   with
     Pre  =>
       Data'Length in 39 .. Max_HS_Msg
       and then Data'Last < N32 (Natural'Last),
     Post =>
       (if Scan_OK then
          Ext_Start >= Data'First + 44
          and then Ext_Start <= Data'Last + 1)
   is
      B                  : constant N32 := Data'First + 4;  --  body start
      P                  : N32;
      Sid_Len, Ext_Total : N32;
   begin
      Ext_Start := Data'First;
      Scan_OK   := False;
      Malformed := False;

      --  Caller has already verified Data'Length >= 39. SH body
      --  minimum is version(2)+random(32)+sid_len(1) = 35 bytes
      --  past the 4-byte handshake header.
      if N32 (Data'Length) - 4 < 35 then
         return;
      end if;

      Sid_Len := N32 (Data (B + 34));
      if Sid_Len > 32 then
         Malformed := True;
         return;
      end if;
      pragma Assert (Sid_Len <= 32);
      if B > N32'Last - 38 or else Sid_Len > N32'Last - B - 38 then
         return;
      end if;
      P := B + 38 + Sid_Len;  --  past sid + cipher + comp
      if P > Data'Last - 2 then
         return;
      end if;

      --  RFC 8446 4.1.4 / 4.1.3: in TLS 1.3 ServerHello + HRR,
      --  legacy_compression_method MUST be 0. The TLS 1.2 parser
      --  enforces this for SH12 with `illegal_parameter`. For HRR we
      --  need decode_error per BoGo
      --  TLS13-HRR-InvalidCompressionMethod. We only have the
      --  Is_HRR_Msg signal here; the SH13/SH12 dispatch happens
      --  later, so apply the HRR check up-front and let TLS 1.2
      --  handle SH compression as before.
      if Is_HRR_Msg and then Data (B + 35 + Sid_Len + 2) /= 0 then
         Malformed := True;
         return;
      end if;

      Ext_Total := N32 (Data (P)) * 256 + N32 (Data (P + 1));
      P := P + 2;
      if Ext_Total > Data'Last - P + 1 then
         Malformed := True;
         return;
      end if;

      --  RFC 8446 4: HS message MUST end exactly at its declared
      --  length. BoGo TrailingMessageData-ServerHello.
      if P + Ext_Total /= Data'Last + 1 then
         Malformed := True;
         return;
      end if;

      Ext_Start := P;
      Scan_OK   := True;
   end Scan_SH_Fixed_Header;

   --  Pre-RFLX byte walk of the SH extensions block. Detects
   --  duplicates, unsolicited extensions, and malformed SNI / ALPN
   --  bodies that RFLX's strict TLS-1.3 schema either silently
   --  rejects (Saw_Rflx_Rejected branch, never escalated for TLS 1.2)
   --  or accepts without per-RFC body validation.
   --
   --  Sets Last_Err and OK := False on rejection; OK := True
   --  means the caller may continue with the RFLX parse.
   --
   --  RFC anchors:
   --    RFC 8446 4.2    duplicate extensions -> decode_error
   --    RFC 5246 7.4.1.4 / RFC 8446 4.2 SH may only echo offered
   --    RFC 6066 3      SNI ack body MUST be empty
   --    RFC 8446 4.2.11 pre_shared_key in SH iff client offered PSK
   --    RFC 7301 3.1    ALPN body = list_len(2)+proto_len(1)+proto
   --  Is_HRR_Msg: True when the SH currently being parsed is itself
   --  an HelloRetryRequest (sentinel matches). Distinct from
   --  HC.Got_HRR which latches across the SH1+SH2 pair (used only for
   --  double-HRR rejection in the second SH). Pre_Scan uses
   --  Is_HRR_Msg for: extension-Where dispatch (E_HRR vs E_SH13),
   --  duplicate-ext error (illegal_parameter vs decode_error), and
   --  HRR-specific body extraction (selected_group / cookie).
   procedure Pre_Scan_SH_Extensions
     (Data       : in Byte_Seq;
      HC         : in out Engaged_Context;
      Last_Err   : in out Error_Code;
      ALPN       : in out Hostname_Buf;
      Is_HRR_Msg : in Boolean;
      OK         : out Boolean)
   with
     Pre =>
       Data'Length in 39 .. Max_HS_Msg
       and then Data'Last < N32 (Natural'Last)
       and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length),
     Post =>
       HC.TS = HC.TS'Old
       and then (if HC.Got_HRR'Old then HC.Got_HRR)
       and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length);

   procedure Pre_Scan_SH_Extensions
     (Data       : in Byte_Seq;
      HC         : in out Engaged_Context;
      Last_Err   : in out Error_Code;
      ALPN       : in out Hostname_Buf;
      Is_HRR_Msg : in Boolean;
      OK         : out Boolean)
   is
      P                  : N32;
      Scan_OK, Malformed : Boolean;
      Exts               : SH_Ext_Array;
      N_Ext              : Natural;
      Found_TLS13        : Boolean;
      Coll_OK, Drv_OK    : Boolean;
      Coll_Err, Drv_Err  : Error_Code;

      Saved_TS           : constant SPARKTLS_Transcript.Transcript_State := HC.TS
      with Ghost;
      Saved_Got_HRR      : constant Boolean := HC.Got_HRR
      with Ghost;
   begin
      OK := True;

      Scan_SH_Fixed_Header (Data, Is_HRR_Msg, P, Scan_OK, Malformed);
      if not Scan_OK then
         --  HC untouched: the Post frame facts hold trivially here.
         if Malformed then
            Last_Err := Decode_Error;
            OK := False;
         end if;
         return;
      end if;

      --  Pass 1 (E2, #131): collect (tag, len, off) into Exts with
      --  duplicate detection; the TLS-1.3 marker comes back as a
      --  Boolean so the collector needs no HC formal.
      Collect_SH_Extensions
        (Data, P, Is_HRR_Msg, Exts, N_Ext, Found_TLS13, Coll_OK, Coll_Err);
      if not Coll_OK then
         --  HC untouched so far: the Post frame facts hold trivially.
         Last_Err := Coll_Err;
         OK := False;
         return;
      end if;
      if Found_TLS13 then
         HC.Has_TLS_1_3 := True;
      end if;

      --  Pass 2 (E4b, #131): matrix + per-tag body validation.
      Apply_SH_Extension_Bodies
        (Data, Exts, N_Ext, Is_HRR_Msg, HC, ALPN, Drv_OK, Drv_Err);
      if not Drv_OK then
         Last_Err := Drv_Err;
         OK := False;
         pragma
           Assert
             (HC.TS = Saved_TS
              and then (if Saved_Got_HRR then HC.Got_HRR));
         return;
      end if;




      pragma
        Assert
          (HC.TS = Saved_TS
           and then (if Saved_Got_HRR then HC.Got_HRR)
           and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length));
   end Pre_Scan_SH_Extensions;

   --  RFC 8446 4.2.8 ServerHello key_share: a single KeyShareEntry
   --     group(2) + key_exchange_length(2) + key_exchange(key_exchange_length)
   --  Allocates a scratch buffer, copies the SH_Extension_TLS body,
   --  validates the wire-length, runs RFLX Verify_Message, dispatches
   --  on group to populate HC.KE.Peer_PK / HC.KE.P256_PK / HC.KE.P384_PK
   --  and the Use_*_KE flags. On length mismatch the routine sets
   --  HC.Ext_Parse_Err := Decode_Error.
   --
   --  BoGo TrailingKeyShareData / unknown-group cases are exercised
   --  through this path.
   procedure Apply_SH_Key_Share
     (Ext_Ctx : in RFLX.TLS_Handshake.SH_Extension_TLS.Context; HC : in out Engaged_Context)
   with
     Pre =>
       RFLX.TLS_Handshake.SH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.SH_Extension_TLS.Valid
                  (Ext_Ctx, RFLX.TLS_Handshake.SH_Extension_TLS.F_Data_Length)
       and then RFLX.TLS_Handshake.SH_Extension_TLS.Well_Formed
                  (Ext_Ctx, RFLX.TLS_Handshake.SH_Extension_TLS.F_Data)
       and then RFLX.TLS_Handshake.SH_Extension_TLS.Valid_Next
                  (Ext_Ctx, RFLX.TLS_Handshake.SH_Extension_TLS.F_Data),
     Post =>
       HC.TS = HC.TS'Old
       and then HC.HRR_Cookie_Len = HC.HRR_Cookie_Len'Old;

   procedure Apply_SH_Key_Share
     (Ext_Ctx : in RFLX.TLS_Handshake.SH_Extension_TLS.Context; HC : in out Engaged_Context)
   is
      DLen   : constant N32 := N32 (RFLX.TLS_Handshake.SH_Extension_TLS.Get_Data_Length (Ext_Ctx));
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
         --  8446 4.2.8: extension_data == 4 + key_exchange_length.
         if VLen >= 4 then
            declare
               KL : constant N32 := N32 (KS_Buf (3)) * 256 + N32 (KS_Buf (4));
            begin
               if 4 + KL /= N32 (VLen) then
                  HC.Ext_Parse_Err := Decode_Error;
               end if;
            end;
         end if;

         RFLX.TLS_Handshake.Key_Share_SH.Initialize
           (KS_Ctx, KS_Buf, Written_Last => RBT.Bit_Length (RBT.Length (DLen) * 8));
         RFLX.TLS_Handshake.Key_Share_SH.Verify_Message (KS_Ctx);

         if HC.Ext_Parse_Err = No_Error
           and then RFLX.TLS_Handshake.Key_Share_SH.Well_Formed_Message (KS_Ctx)
         then
            declare
               Grp : constant RFLX.Tls_Parameters.TLS_Supported_Groups :=
                 RFLX.TLS_Handshake.Key_Share_SH.Get_Group (KS_Ctx);
            begin
               if Grp.Known
                 and then Grp.Enum = RFLX.Tls_Parameters.X25519
                 and then RFLX.RFLX_Types.To_Length
                            (RFLX.TLS_Handshake.Key_Share_SH.Field_Size
                               (KS_Ctx, RFLX.TLS_Handshake.Key_Share_SH.F_Key_Exchange))
                          = 32
               then
                  declare
                     KB : RBT.Bytes (1 .. 32);
                  begin
                     RFLX.TLS_Handshake.Key_Share_SH.Get_Key_Exchange (KS_Ctx, KB);
                     HC.KE.Peer_PK := To_NaCl (KB);
                     HC.KE.Curve := Group_X25519;
                     HC.KE.Negotiated := True;
                  end;
               elsif Grp.Known
                 and then Grp.Enum = RFLX.Tls_Parameters.Secp256r1
                 and then RFLX.RFLX_Types.To_Length
                            (RFLX.TLS_Handshake.Key_Share_SH.Field_Size
                               (KS_Ctx, RFLX.TLS_Handshake.Key_Share_SH.F_Key_Exchange))
                          = 65
               then
                  declare
                     KB : RBT.Bytes (1 .. 65);
                  begin
                     RFLX.TLS_Handshake.Key_Share_SH.Get_Key_Exchange (KS_Ctx, KB);
                     for I in 0 .. 64 loop
                        HC.KE.P256_PK (N32 (I)) := Byte (KB (RBT.Index (I + 1)));
                     end loop;
                     HC.KE.Curve := Group_Secp256r1;
                     HC.KE.Negotiated := True;
                  end;
               elsif Grp.Known
                 and then Grp.Enum = RFLX.Tls_Parameters.Secp384r1
                 and then RFLX.RFLX_Types.To_Length
                            (RFLX.TLS_Handshake.Key_Share_SH.Field_Size
                               (KS_Ctx, RFLX.TLS_Handshake.Key_Share_SH.F_Key_Exchange))
                          = 97
               then
                  declare
                     KB : RBT.Bytes (1 .. 97);
                  begin
                     RFLX.TLS_Handshake.Key_Share_SH.Get_Key_Exchange (KS_Ctx, KB);
                     for I in 0 .. 96 loop
                        HC.KE.P384_PK (N32 (I)) := Byte (KB (RBT.Index (I + 1)));
                     end loop;
                     HC.KE.Curve := Group_Secp384r1;
                     HC.KE.Negotiated := True;
                  end;
               end if;
            end;
         end if;

         RFLX.TLS_Handshake.Key_Share_SH.Take_Buffer (KS_Ctx, KS_Buf);
         RFLX_Free (KS_Buf);
      end;
   end Apply_SH_Key_Share;

   --  R1 (#131): the ONLY RFLX-buffer-owning step of the ServerHello
   --  parse -- allocate, verify, extract (server random, cipher suite,
   --  key_share), release. The buffer's lifetime begins and ends here,
   --  which is what turned Parse_Server_Hello's goto-Cleanup lattice
   --  into plain returns: nothing after this call touches the buffer.
   --  Outcomes: OK False, Err No_Error   -> not well-formed (caller falls
   --            back to the TLS 1.2 parser); OK False, Err /= No_Error ->
   --            protocol error to alert;   OK True -> Negotiated + HC set.
   procedure Parse_SH_RFLX_Core
     (Negotiated : in out Supported_Suite;
      Err        : out Error_Code;
      HC         : in out Engaged_Context;
      Data       : in Byte_Seq;
      OK         : out Boolean)
   with
     Pre  =>
       Data'Length in 39 .. Max_HS_Msg
       and then Data'Last < N32 (Natural'Last),
     Post =>
       HC.TS = HC.TS'Old
       and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
   is
      use RFLX.TLS_Handshake.Server_Hello;
      Body_Len : constant N32 := N32 (Data'Length) - 4;
      Buf      : RBT.Bytes_Ptr;
      Ctx      : Context;
      Suite_OK : Boolean := False;
   begin
      Err := No_Error;
      OK := False;

      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      Buf.all := To_RFLX (Data (Data'First + 4 .. Data'Last));
      Initialize (Ctx, Buf, Written_Last => RBT.Bit_Length (RBT.Length (Body_Len) * 8));
      Verify_Message (Ctx);

      if Well_Formed_Message (Ctx) then
         --  Extract server random (32 bytes)
         declare
            Random_Bytes : RBT.Bytes (1 .. 32);
         begin
            Get_Random (Ctx, Random_Bytes);
            HC.Server_Random := To_NaCl (Random_Bytes);
         end;

         --  Extract and validate cipher suite: TLS 1.3 + TLS 1.2 AEAD only
         if Well_Formed (Ctx, F_Cipher_Suite_TLS_Suite) then
            declare
               Suite     : constant RFLX.Tls_Parameters.TLS_Cipher_Suites :=
                 Get_Cipher_Suite_TLS_Suite (Ctx);
               Suite_Val : constant Unsigned_16 :=
                 Unsigned_16 (RFLX.Tls_Parameters.To_Base_Integer (Suite));
            begin
               --  Single source of truth: To_Suite is TOTAL (unknown wire
               --  values map to Suite_None), so its domain IS the supported
               --  set -- no second hand-maintained wire-literal list.
               declare
                  Candidate : constant Supported_Suite := To_Suite (Suite_Val);
               begin
                  if Candidate /= Suite_None then
                     --  RFC 8446 4.1.4: after HRR, the cipher_suite in SH2
                     --  MUST match the HRR's choice. BoGo
                     --  HelloRetryRequest-CipherChange-TLS13.
                     if HC.Got_HRR
                       and then HC.HRR_Cipher_Suite /= 0
                       and then Suite_Val /= HC.HRR_Cipher_Suite
                     then
                        Err := Illegal_Parameter;
                     else
                        Negotiated := Candidate;
                        Suite_OK := True;
                     end if;
                  end if;
               end;
            end;
         end if;

         if Suite_OK then
         --  Iterate extensions to find key_share
         if Present (Ctx, F_Extensions_TLS) and then Well_Formed (Ctx, F_Extensions_TLS) then
            pragma Assert (Present (Ctx, F_Extensions_TLS));
            pragma Assert (Well_Formed (Ctx, F_Extensions_TLS));
            declare
               Exts_Ctx : RFLX.TLS_Handshake.SH_Extensions_TLS.Context;
            begin
               Switch_To_Extensions_TLS (Ctx, Exts_Ctx);

               declare
                  Ctx_First  : constant RFLX.RFLX_Types.Index := Ctx.Buffer_First;
                  Ctx_Last   : constant RFLX.RFLX_Types.Index := Ctx.Buffer_Last;
                  Exts_First : constant RFLX.RFLX_Types.Bit_Index := Exts_Ctx.First;
                  Exts_Last  : constant RFLX.RFLX_Types.Bit_Length := Exts_Ctx.Last;
               begin
                  while RFLX.TLS_Handshake.SH_Extensions_TLS.Has_Element (Exts_Ctx) loop
                     pragma Loop_Invariant (not RFLX.TLS_Handshake.Server_Hello.Has_Buffer (Ctx));
                     pragma
                       Loop_Invariant
                         (RFLX.TLS_Handshake.Server_Hello.Present (Ctx, F_Extensions_TLS));
                     pragma
                       Loop_Invariant (RFLX.TLS_Handshake.SH_Extensions_TLS.Has_Buffer (Exts_Ctx));
                     pragma Loop_Invariant (RFLX.TLS_Handshake.SH_Extensions_TLS.Valid (Exts_Ctx));
                     pragma
                       Loop_Invariant
                         (Exts_Ctx.First = Exts_First and then Exts_Ctx.Last = Exts_Last);
                     pragma
                       Loop_Invariant
                         (Ctx.Buffer_First = Ctx_First
                            and then Ctx.Buffer_Last = Ctx_Last
                            and then Exts_Ctx.Buffer_First = Ctx_First
                            and then Exts_Ctx.Buffer_Last = Ctx_Last);

                     pragma Loop_Invariant (HC.TS = HC.TS'Loop_Entry);
                     pragma Loop_Invariant (HC.HRR_Cookie_Len = HC.HRR_Cookie_Len'Loop_Entry);
                     declare
                        Ext_Ctx : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
                     begin
                        RFLX.TLS_Handshake.SH_Extensions_TLS.Switch (Exts_Ctx, Ext_Ctx);
                        RFLX.TLS_Handshake.SH_Extension_TLS.Verify_Message (Ext_Ctx);

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
                        if RFLX.TLS_Handshake.SH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
                          and then RFLX.TLS_Handshake.SH_Extension_TLS.Get_Tag (Ext_Ctx).Known
                          and then RFLX.TLS_Handshake.SH_Extension_TLS.Get_Tag (Ext_Ctx).Enum
                                   = RFLX.Tls_Extensiontype_Values.Key_Share
                        then
                           Apply_SH_Key_Share (Ext_Ctx, HC);
                        end if;

                        RFLX.TLS_Handshake.SH_Extensions_TLS.Update (Exts_Ctx, Ext_Ctx);
                     end;
                  end loop;

                  Update_Extensions_TLS (Ctx, Exts_Ctx);
               end;

               --  All dup / unsolicited / body-empty / ALPN-shape checks
               --  ran in Pre_Scan_SH_Extensions above; any failure there
               --  short-circuited the parse. Nothing else to do here.
            end;
         end if;
            OK := True;
         end if;
      end if;

      --  Single release point: every path converges here. Buf goes null
      --  at Initialize (ownership moves into Ctx); the extensions loop
      --  borrows and returns the buffer, so Ctx owns it again on exit.
      if Buf /= null then
         RFLX_Free (Buf);
      end if;
      if Has_Buffer (Ctx) then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
      end if;
   end Parse_SH_RFLX_Core;

   --  R4 (#131): HelloRetryRequest arm. RFC 8446 4.1.4. Bundles the
   --  three HRR-specific checks the caller ran inline: (1) a valid HRR
   --  must carry key_share or cookie (empty -> illegal_parameter; BoGo
   --  HelloRetryRequest-Empty-TLS13); (2) it MUST change the
   --  ClientHello, so an HRR naming a group we already offered is
   --  unnecessary -> illegal_parameter (UnnecessaryHelloRetryRequest-
   --  TLS13); (3) stash the HRR cipher suite (which MUST be a TLS 1.3
   --  suite) for the CH2 transcript and the SH2 cipher-match check.
   --  The Post carries the strong exit facts the inline 6-conjunct cut
   --  stated: TS and Got_HRR untouched, cookie bound preserved, and
   --  Version pinned to TLS 1.3 on success.
   procedure Parse_HRR
     (Data       : in     Byte_Seq;
      HC         : in out Engaged_Context;
      Negotiated : in out Supported_Suite;
      Version    : in out TLS_Version;
      OK         :    out Boolean;
      Err        :    out Error_Code)
   with
     Pre  => Data'Length in 39 .. Max_HS_Msg
             and then Data'Last < N32 (Natural'Last)
             and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length),
     Post => HC.TS = HC.TS'Old
             and then HC.Got_HRR = HC.Got_HRR'Old
             and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
             and then (if OK then Version = TLS_1_3)
   is
   begin
      OK  := True;
      Err := No_Error;

      --  (1) empty HRR (neither key_share nor cookie).
      if HC.HRR_Selected_Group = Group_None and then HC.HRR_Cookie_Len = 0 then
         Err := Illegal_Parameter;
         OK  := False;
         return;
      end if;

      --  (2) unnecessary HRR. In the default profile CH1 carries only
      --  X25519; when Client_Key_Share_Group is set, CH1 carries only
      --  that configured group, so any HRR is a real change.
      if (if HC.Cfg.Client_Key_Share_Group /= Group_None then True
          else HC.HRR_Selected_Group = Group_X25519)
      then
         Err := Illegal_Parameter;
         OK  := False;
         return;
      end if;

      --  (3) stash HRR cipher suite (RFC 8446 4.1.4: HRR and SH2
      --  cipher_suite MUST match; the suite MUST be a TLS 1.3 suite).
      declare
         Sid_Len : constant N32 := N32 (Data (Data'First + 4 + 34));
      begin
         if N32 (Data'Length) < 41 + Sid_Len then
            Err := Decode_Error;
            OK  := False;
            return;
         end if;
         declare
            Cs_Off    : constant N32 := Data'First + 39 + Sid_Len;
            Suite_Val : constant Unsigned_16 :=
              Unsigned_16 (Data (Cs_Off)) * 256 + Unsigned_16 (Data (Cs_Off + 1));
         begin
            pragma Assert (Cs_Off + 1 <= Data'Last);
            --  Enum-subtype membership, not wire literals: To_Suite is
            --  total and TLS13_Suite is the type-level fact (#121).
            if To_Suite (Suite_Val) not in TLS13_Suite then
               Err := Illegal_Parameter;
               OK  := False;
               return;
            end if;
            HC.HRR_Cipher_Suite := Suite_Val;
            Negotiated := To_Suite (Suite_Val);
            Version := TLS_1_3;
         end;
      end;
   end Parse_HRR;

   --  R5 (#131): ServerHello version selection and policy checks.
   --  Pure over narrow formals (no HC): picks Version from the
   --  supported_versions signal, then enforces the TLS 1.3 suite set,
   --  the legacy_session_id_echo match (RFC 8446 4.1.3), the
   --  post-HRR same-version rule (4.1.4) and the Cfg.Versions policy
   --  (4.2.1). The Post pins Version to a real version on success --
   --  this is where Parse_Server_Hello's own Version Post is earned.
   procedure Check_SH_Policy
     (Data              : in Byte_Seq;
      Has_TLS_1_3       : in Boolean;
      Got_HRR           : in Boolean;
      Cfg_Versions      : in Version_Policy;
      Legacy_Session_ID : in Bytes_32;
      Negotiated        : in Supported_Suite;
      Version           : out TLS_Version;
      OK                : out Boolean;
      Err               : out Error_Code)
   with
     Pre  => Data'Length in 39 .. Max_HS_Msg,
     Post => (if OK then Version in TLS_1_2 | TLS_1_3)
   is
   begin
      OK  := True;
      Err := No_Error;

      --  Select version based on supported_versions extension.
      if Has_TLS_1_3 then
         Version := TLS_1_3;
      else
         Version := TLS_1_2;
      end if;
      if Version = TLS_1_3
        and then Negotiated not in
                   Suite_AES_128_GCM_SHA256
                   | Suite_AES_256_GCM_SHA384
                   | Suite_CHACHA20_POLY1305_SHA256
      then
         Err := Illegal_Parameter;
         OK := False;
         return;
      end if;

      --  RFC 8446 4.1.3: TLS 1.3 server's legacy_session_id_echo
      --  MUST be byte-for-byte equal to the client's
      --  legacy_session_id. We always send a 32-byte SID (unless
      --  TLS_1_2_Only), so when the server picked TLS 1.3 the echo
      --  must also be 32 bytes and match. In TLS 1.2, by contrast,
      --  the server may assign a new SID for a full handshake, so
      --  this check is gated on Has_TLS_1_3. BoGo
      --  EchoTLS13CompatibilitySessionID-style mismatches that
      --  reach a TLS 1.3 SH (e.g. via supported_versions).
      if Has_TLS_1_3
        and then Cfg_Versions /= TLS_1_2_Only
        and then Data'Length >= 4 + 35 + 32
      then
         declare
            SH_SID_Off : constant N32 := Data'First + 4 + 35;
            SH_SID_Len : constant N32 := N32 (Data (Data'First + 4 + 34));
            Mismatch   : Boolean := SH_SID_Len /= 32;
         begin
            if not Mismatch then
               for I in N32 range 0 .. 31 loop
                  if Data (SH_SID_Off + I) /= Legacy_Session_ID (I) then
                     Mismatch := True;
                  end if;
               end loop;
            end if;
            if Mismatch then
               Err := Illegal_Parameter;
               OK := False;
               return;
            end if;
         end;
      end if;

      --  RFC 8446 4.1.4: after a HelloRetryRequest, the second SH
      --  MUST select the same version as the HRR (TLS 1.3, indicated
      --  by supported_versions). A 2nd SH without TLS 1.3 in supported
      --  _versions is a SECOND_SERVERHELLO_VERSION_MISMATCH and MUST
      --  trigger an illegal_parameter alert. BoGo
      --  SecondServerHelloWrongVersion-TLS13.
      if Got_HRR and then not Has_TLS_1_3 then
         Err := Illegal_Parameter;
         OK := False;
         return;
      end if;

      --  RFC 8446 4.2.1: enforce our Cfg.Versions policy on the
      --  server's choice. -min-version / -max-version / -no-tlsN may
      --  have constrained the policy below what's in the supported_
      --  versions extension we sent; if the server still picks a
      --  version outside our allowed set, reject with
      --  protocol_version (alert 70). BoGo's MinimumVersion-Client2-
      --  TLS13-TLS12 / -Server2-TLS13-TLS12 exercise this.
      if (Version = TLS_1_2 and Cfg_Versions = TLS_1_3_Only)
        or else (Version = TLS_1_3 and Cfg_Versions = TLS_1_2_Only)
      then
         Err := Protocol_Version;
         OK := False;
         return;
      end if;

   end Check_SH_Policy;

   --  R7 (#131): TLS 1.3 ECDHE shared-secret computation. Takes KE
   --  only, so the transcript (HC.TS) frame is not implicated and the
   --  two SH_Parse_Frame probes bracketing the P-384 call are gone.
   --  Dispatches on the negotiated curve (P-384 / P-256 / X25519) and
   --  writes KE.Shared. Failure: OK False; Err carries the alert
   --  (RFC 8446 6.2 invalid peer share -> illegal_parameter for
   --  X25519; the P-256/P-384 decode failures leave Err No_Error so
   --  the caller picks the generic alert, as before).
   procedure Compute_SH_Shared_Secret
     (KE  : in out KE_State;
      OK  : out Boolean;
      Err : out Error_Code)
   is
   begin
      OK  := True;
      Err := No_Error;

      --  Compute shared secret (TLS 1.3 only  key_share in ServerHello)
      if (KE.Negotiated and then KE.Curve = Group_Secp384r1) then
         --  P-384 ECDHE: shared_secret = x-coordinate of [sk] * peer_PK
         declare
            Secret_384 : Bytes_48;
            P384_OK    : Boolean;
         begin
            Compute_P384_Shared_Secret
              (Secret  => Secret_384,
               OK      => P384_OK,
               SK      => KE.P384_SK,
               Peer_PK => KE.P384_PK);
            if not P384_OK then
               OK := False;
               return;
            end if;
            KE.Shared := Secret_384;
         end;
      elsif (KE.Negotiated and then KE.Curve = Group_Secp256r1) then
         --  P-256 ECDHE: shared_secret = x-coordinate of [sk] * peer_PK
         declare
            Peer_Pt : SPARKTLSCrypto.P256.Point.P256_Jacobian;
            Valid   : SPARKNaCl.U32;
            X_Bytes : Byte_Seq (0 .. 31);
         begin
            SPARKTLSCrypto.P256.Point.P256_Decode (Peer_Pt, KE.P256_PK, Valid);
            if Valid = 0 then
               OK := False;
               return;
            end if;
            --  Multiply peer's public key by our private scalar
            SPARKTLSCrypto.P256.Point.P256_Mul (Peer_Pt, KE.P256_SK, 32);
            SPARKTLSCrypto.P256.Point.P256_To_Affine (Peer_Pt);
            --  Encode to get x-coordinate (bytes 1..32 of uncompressed point)
            declare
               Encoded : Byte_Seq (0 .. 64);
            begin
               SPARKTLSCrypto.P256.Point.P256_Encode (Encoded, Peer_Pt);
               X_Bytes := Encoded (1 .. 32);
            end;
            KE.Shared := (others => 0);
            KE.Shared (0 .. 31) := X_Bytes;
         end;
      else
         --  X25519 ECDHE
         KE.Shared := (others => 0);
         SPARKTLSCrypto.X25519.Scalar_Mult
           (KE.Shared (0 .. 31), KE.Local_SK, KE.Peer_PK);
         --  RFC 7748 6.1: small-subgroup defence. The helper has
         --  a SPARK-proven Post that ties its result to the byte-
         --  sequence existential. RFC 8446 6.2: invalid peer share
         --  is illegal_parameter, not the generic handshake_failure
         --  the caller would otherwise pick.
         if not Shared_Secret_Is_Acceptable_X25519 (KE.Shared (0 .. 31)) then
            Err := Illegal_Parameter;
            OK := False;
            return;
         end if;
      end if;
   end Compute_SH_Shared_Secret;

   --  R6 (#131): RFC 8446 4.1.3 downgrade-sentinel detection over the
   --  last 8 bytes of ServerRandom, independent of negotiated version
   --  (a server MUST NOT set these markers when negotiating TLS 1.3,
   --  so a marker on a TLS 1.3 SH is itself an abort signal --
   --  BoringSSL convention). Three sentinels:
   --    * "DOWNGRD" + 0x01  TLS 1.3 -> TLS 1.2 (RFC 8446 4.1.3)
   --    * "DOWNGRD" + 0x00  TLS 1.3 -> TLS 1.0/1.1 (same RFC)
   --    * 0xED 0xBF 0xB4 0xA8 0xC2 0x47 0x10 0xFF  JDK 11 marker.
   --  BoGo Client-RejectJDK11DowngradeRandom.
   function Downgrade_Sentinel_Present (R : Bytes_32) return Boolean is
      type Sentinel_T is array (N32 range 0 .. 7) of Byte;
      S13   : constant Sentinel_T :=
        (16#44#, 16#4F#, 16#57#, 16#4E#, 16#47#, 16#52#, 16#44#, 16#01#);
      S12   : constant Sentinel_T :=
        (16#44#, 16#4F#, 16#57#, 16#4E#, 16#47#, 16#52#, 16#44#, 16#00#);
      S_JDK : constant Sentinel_T :=
        (16#ED#, 16#BF#, 16#B4#, 16#A8#, 16#C2#, 16#47#, 16#10#, 16#FF#);
   begin
      return
        (for all I in N32 range 0 .. 7 => R (24 + I) = S13 (I))
        or else (for all I in N32 range 0 .. 7 => R (24 + I) = S12 (I))
        or else (for all I in N32 range 0 .. 7 => R (24 + I) = S_JDK (I));
   end Downgrade_Sentinel_Present;

   --  R3 (#131): HelloRetryRequest detection. RFC 8446 4.1.4: an HRR
   --  is on-wire a ServerHello whose random equals the magic
   --  HRR_Sentinel. Random is at offset 6 .. 37 in Data (4-byte HS
   --  header + 2-byte legacy_version). Pure function of Data; the
   --  caller guards Data'Length >= 38 and owns the Got_HRR/Curr_Is_HRR
   --  writes and the double-HRR (unexpected_message) rejection.
   function Is_HRR_Random (Data : Byte_Seq) return Boolean
   is (for all I in N32 range 0 .. 31 =>
         Data (Data'First + 6 + I) = HRR_Sentinel (I))
   with
     Pre => Data'Length in 39 .. Max_HS_Msg
            and then Data'Last < N32 (Natural'Last);

   --  R2 (#131): ServerHello preliminaries -- the shape checks that
   --  must pass before any parsing. Pure function of Data. Outcomes:
   --  OK -> proceed (Post carries the bounds every downstream Pre
   --  needs); not OK and Err = No_Error -> silent no-parse (caller
   --  falls back to the TLS 1.2 parser as before); not OK and
   --  Err /= No_Error -> reject.
   procedure Check_SH_Preliminaries
     (Data : in Byte_Seq;
      OK   : out Boolean;
      Err  : out Error_Code)
   with
     Post =>
       (if OK then
          Data'Length in 39 .. Max_HS_Msg
          and then Data'Last < N32 (Natural'Last))
   is
   begin
      OK  := False;
      Err := No_Error;

      --  Shape checks -- silent no-parse on any failure: the caller
      --  falls back to the TLS 1.2 parser exactly as before.
      if Data'Length < 39
        or else Data'Last >= N32 (Natural'Last)
        or else Data'Length > Max_HS_Msg
        or else Data (Data'First) /= HS_Msg_Wire (HT_Server_Hello)  --  not a ServerHello
      then
         return;
      end if;

      --  RFC 5246 7.4.1.2 / RFC 8446 4.1.3: legacy_session_id
      --  length field is 0..32. The full ServerHello body is
      --  version(2) + random(32) + sid_len(1) + sid(0..32) + ...
      --  Catch over-long sid early  RFLX rejects the message but
      --  we'd otherwise fall through to the TLS 1.2 parser and emit
      --  Handshake_Failure instead of the correct Decode_Error
      --  (BoGo's Client-TooLongSessionID test).
      if N32 (Data'Length) - 4 >= 35 and then N32 (Data (Data'First + 4 + 34)) > 32 then
         Err := Decode_Error;
         return;
      end if;

      OK := True;
   end Check_SH_Preliminaries;

   procedure Parse_Server_Hello
     (Negotiated : in out Supported_Suite;
      Last_Err   : in out Error_Code;
      ALPN       : in out Hostname_Buf;
      HC         : in out Engaged_Context;
      Data       : in Byte_Seq;
      Version    : out TLS_Version;
      OK         : out Boolean)
   is
      use RFLX.TLS_Handshake.Server_Hello;
      --  True iff the SH currently being parsed has the HRR sentinel
      --  random. Distinct from HC.Got_HRR, which latches across the
      --  CH1/HRR/CH2/SH2 pair. Used to gate HRR-specific code paths
      --  in this single call (Pre_Scan dispatch, body extraction,
      --  early return) so the same Parse_Server_Hello body handles
      --  both HRR and the post-HRR SH2 correctly.
      Curr_Is_HRR      : Boolean := False;
      Prelim_OK        : Boolean;
      Prelim_Err       : Error_Code;
      Pol_OK           : Boolean;
      Pol_Err          : Error_Code;
      HRR_OK           : Boolean;
      HRR_Err          : Error_Code;
      TS_At_Entry      : constant SPARKTLS_Transcript.Transcript_State := HC.TS with Ghost;
      Got_HRR_At_Entry : constant Boolean := HC.Got_HRR with Ghost;

      function SH_Parse_Frame return Boolean
      is (HC.TS = TS_At_Entry and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)) with Ghost;
   begin
      Version := TLS_Undetermined;
      OK := False;

      --  R2 (#131): Q0 preliminaries.
      Check_SH_Preliminaries (Data, Prelim_OK, Prelim_Err);
      if not Prelim_OK then
         if Prelim_Err /= No_Error then
            Last_Err := Prelim_Err;
         end if;
         --  HC untouched on every preliminary exit.
         pragma Assert (SH_Parse_Frame);
         return;
      end if;

      --  RFC 8446 4.1.4: HelloRetryRequest is on-wire a ServerHello
      --  with a magic random value. Compare here so the SH parser
      --  can apply HRR-specific extension policy
      --  (Where_Allowed = E_HRR, dup -> illegal_parameter not
      --  decode_error, must contain key_share or cookie). Random is
      --  at offset 6..37 in Data (4-byte HS hdr + 2-byte
      --  legacy_version).
      if N32 (Data'Length) >= 38 and then Is_HRR_Random (Data) then
         --  RFC 8446 4.1.4: a server MUST send at most one HRR. A
         --  second HRR is unexpected_message.
         if HC.Got_HRR then
            Last_Err := Unexpected_Message;
            pragma Assert (if OK or else Last_Err = No_Error then SH_Parse_Frame);
            return;
         end if;
         HC.Got_HRR := True;
         Curr_Is_HRR := True;
         pragma Assert (not Got_HRR_At_Entry);
      end if;

      declare
         Pre_OK : Boolean;
      begin
         Pre_Scan_SH_Extensions (Data, HC, Last_Err, ALPN, Is_HRR_Msg => Curr_Is_HRR, OK => Pre_OK);
         if not Pre_OK then
            pragma Assert (if OK or else Last_Err = No_Error then SH_Parse_Frame);
            return;
         end if;
      end;

      if Curr_Is_HRR then
         --  HRR arm (R4, #131): empty/unnecessary checks + cipher
         --  stash. On success the caller sees HC.Got_HRR and runs the
         --  retry flow (transcript message_hash replacement -> CH2
         --  build -> send -> wait for the real ServerHello).
         Parse_HRR (Data, HC, Negotiated, Version, HRR_OK, HRR_Err);
         if not HRR_OK then
            Last_Err := HRR_Err;
            pragma Assert (if OK or else Last_Err = No_Error then SH_Parse_Frame);
            return;
         end if;
         OK := True;
         pragma Assert (HC.Got_HRR);
         pragma Assert (not Got_HRR_At_Entry);
         pragma
           Assert
             (OK
                and then HC.Got_HRR
                and then not Got_HRR_At_Entry
                and then Version = TLS_1_3
                and then HC.TS = TS_At_Entry
                and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length));
         return;
      end if;

      --  RFLX-owning core (R1, #131): the parse buffer's entire lifetime
      --  is inside this call; nothing below touches it, so every failure
      --  from here on is a plain return.
      declare
         Core_OK  : Boolean;
         Core_Err : Error_Code;
      begin
         Parse_SH_RFLX_Core (Negotiated, Core_Err, HC, Data, Core_OK);
         if not Core_OK then
            if Core_Err /= No_Error then
               Last_Err := Core_Err;
            end if;
            pragma Assert (if OK or else Last_Err = No_Error then SH_Parse_Frame);
            return;
         end if;
      end;

         --  Version selection + policy (R5, #131).
         Check_SH_Policy
           (Data              => Data,
            Has_TLS_1_3       => HC.Has_TLS_1_3,
            Got_HRR           => HC.Got_HRR,
            Cfg_Versions      => HC.Cfg.Versions,
            Legacy_Session_ID => HC.Legacy_Session_ID,
            Negotiated        => Negotiated,
            Version           => Version,
            OK                => Pol_OK,
            Err               => Pol_Err);
         if not Pol_OK then
            Last_Err := Pol_Err;
            OK := False;
            return;
         end if;

         --  RFC 8446 4.1.3: downgrade-sentinel check (see
         --  Downgrade_Sentinel_Present). Independent of the negotiated
         --  version; on a TLS 1.2 SH the marker is the canonical RFC
         --  8446 downgrade indicator, on a TLS 1.3 SH it is an abort
         --  signal in its own right.
         if Downgrade_Sentinel_Present (HC.Server_Random) then
            Last_Err := Illegal_Parameter;
            return;
         end if;

         --  For TLS 1.2, skip ECDHE shared secret here
         --  (it's computed after ServerKeyExchange)
         if Version = TLS_1_2 then
            pragma
              Assert
                (HC.TS = TS_At_Entry
                   and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length));
            OK := True;
            return;
         end if;

         --  Compute shared secret (TLS 1.3 only) -- R7 (#131).
         declare
            SS_OK  : Boolean;
            SS_Err : Error_Code;
         begin
            Compute_SH_Shared_Secret (HC.KE, SS_OK, SS_Err);
            if not SS_OK then
               if SS_Err /= No_Error then
                  Last_Err := SS_Err;
               end if;
               OK := False;
               return;
            end if;
         end;

         --  Bubble up extension-specific protocol errors (e.g. RFC 7301
         --  empty ALPN name -> illegal_parameter). The caller's `if not
         --  Parse_OK` arm reads Last_Err to pick the alert.
         if HC.Ext_Parse_Err /= No_Error then
            Last_Err := HC.Ext_Parse_Err;
            OK := False;
            return;
         end if;

         pragma
           Assert
             (HC.TS = TS_At_Entry
                and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length));
         OK := True;
   end Parse_Server_Hello;

end SPARKTLS.Handshake.Client_Msgs;
