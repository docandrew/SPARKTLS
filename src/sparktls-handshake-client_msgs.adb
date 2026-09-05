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
with RFLX.TLS_Handshake.Key_Share_HRR;
with RFLX.TLS_Handshake.Hello_Retry_Request;
with RFLX.TLS_Handshake.HRR_Extensions_TLS;
with RFLX.TLS_Handshake.HRR_Extension_TLS;
with RFLX.TLS_Handshake.Cookie;
with RFLX.TLS_Handshake.Supported_Version;
with RFLX.TLS_Handshake.Pre_Shared_Key_SH;
with RFLX.TLS_Handshake.Contains;
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
use type RFLX.TLS_Common.Protocol_Version;
use type RFLX.TLS_Handshake.Identity_Index;
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
      Set_Legacy_Version (Ctx, 16#0303#);  --  RFC 8446 4.1.2: legacy_version = 0x0303
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

   ----------------------------------------------------------------------------
   --  ServerHello and HelloRetryRequest (RFC 8446 4.1.3 / 4.1.4, RFC 5246
   --  7.4.1.3). Each is parsed with its RecordFlux message: Server_Hello for
   --  the ServerHello of either version, Hello_Retry_Request when Random is
   --  the HRR sentinel. Extension policy -- which tags may appear where,
   --  whether they were offered, empty echoes -- is Validate_Server_Ext; the
   --  spec accepts any tag so that a violation gets the RFC's
   --  unsupported_extension alert instead of a parse failure. Extension
   --  bodies are read through the spec's refinements: Copy_Data into one
   --  scratch buffer per parse, so the element sequence keeps its buffer
   --  and the walk continues (Switch_To_Data would hand it over).
   ----------------------------------------------------------------------------

   --  RFC 8446 4.2: an extension MUST NOT appear twice in one block. Tags
   --  are compared on the wire value. More than 32 extensions in a
   --  ServerHello is not a message any server sends; fail closed.
   subtype Seen_Index is Positive range 1 .. 32;
   type Seen_Tags is array (Seen_Index) of Unsigned_16;

   procedure Note_Tag
     (Seen   : in out Seen_Tags;
      N_Seen : in out Natural;
      Tag    : in Unsigned_16;
      Dup    : out Boolean;
      Full   : out Boolean)
   with
     Pre  => N_Seen <= Seen'Last,
     Post => N_Seen <= Seen'Last
   is
   begin
      Dup  := False;
      Full := False;
      for I in 1 .. N_Seen loop
         if Seen (I) = Tag then
            Dup := True;
            return;
         end if;
      end loop;
      if N_Seen = Seen'Last then
         Full := True;
         return;
      end if;
      N_Seen := N_Seen + 1;
      Seen (N_Seen) := Tag;
   end Note_Tag;

   --  One scratch buffer per parse for the refinement copies. The largest
   --  body read here is a cookie: 2 + the 1024 bytes HC.HRR_Cookie keeps.
   Body_Scratch_Len : constant := 1100;

   function Tag_Wire
     (T : RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values) return Unsigned_16
   is (Unsigned_16 (RFLX.Tls_Extensiontype_Values.To_Base_Integer (T)));

   function Group_Wire
     (G : RFLX.Tls_Parameters.TLS_Supported_Groups) return Unsigned_16
   is (Unsigned_16 (RFLX.Tls_Parameters.To_Base_Integer (G)));

   function Suite_Wire
     (S : RFLX.Tls_Parameters.TLS_Cipher_Suites) return Unsigned_16
   is (Unsigned_16 (RFLX.Tls_Parameters.To_Base_Integer (S)));

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

   --  RFC 8446 4.1.4: a HelloRetryRequest is on the wire a ServerHello whose
   --  Random is HRR_Sentinel. Random is at offset 6 .. 37 (4-byte handshake
   --  header + 2-byte legacy_version). The caller guards the length.
   function Is_HRR_Random (Data : Byte_Seq) return Boolean
   is (for all I in N32 range 0 .. 31 =>
         Data (Data'First + 6 + I) = HRR_Sentinel (I))
   with
     Pre => Data'Length in 39 .. Max_HS_Msg
            and then Data'Last < N32 (Natural'Last);


   ----------------------------------------------------------------------------
   --  HelloRetryRequest
   ----------------------------------------------------------------------------

   --  One HRR extension element: duplicate check, E_HRR policy, then the
   --  body through its refinement. key_share carries only selected_group
   --  (RFC 8446 4.1.4), cookie is cookie<1..2^16-1> (4.2.2), and
   --  supported_versions is the selected version (4.2.1). Fail /= No_Error
   --  aborts the message with that alert; HC.Ext_Parse_Err carries the
   --  softer verdicts the caller reads after the retry flow.
   procedure Process_HRR_Extension
     (E         : in RFLX.TLS_Handshake.HRR_Extension_TLS.Context;
      HC        : in out Engaged_Context;
      Scratch   : in out RBT.Bytes_Ptr;
      Seen      : in out Seen_Tags;
      N_Seen    : in out Natural;
      Has_TLS13 : in out Boolean;
      Fail      : out Error_Code)
   with
     Pre  =>
       RFLX.TLS_Handshake.HRR_Extension_TLS.Has_Buffer (E)
       and then RFLX.TLS_Handshake.HRR_Extension_TLS.Well_Formed_Message (E)
       and then Scratch /= null
       and then Scratch'First = 1
       and then Scratch'Last = Body_Scratch_Len
       and then N_Seen <= Seen'Last
       and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length),
     Post =>
       Scratch /= null
       and then Scratch'First = 1
       and then Scratch'Last = Body_Scratch_Len
       and then N_Seen <= Seen'Last
       and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
   is
      use RFLX.TLS_Handshake.HRR_Extension_TLS;
      Tag  : constant Unsigned_16 := Tag_Wire (Get_Tag (E));
      DLen : constant N32 := N32 (Get_Data_Length (E));
      Dup, Full, V_OK : Boolean;
   begin
      Fail := No_Error;

      --  Duplicates in an HRR are illegal_parameter (BoGo
      --  HelloRetryRequest-DuplicateCookie / -DuplicateCurve).
      Note_Tag (Seen, N_Seen, Tag, Dup, Full);
      if Dup then
         Fail := Illegal_Parameter;
         return;
      end if;
      if Full then
         Fail := Decode_Error;
         return;
      end if;

      Validate_Server_Ext (E_HRR, Tag, DLen, HC, V_OK, Fail);
      if not V_OK then
         return;
      end if;
      Fail := No_Error;

      if DLen > Body_Scratch_Len then
         --  No HRR extension body we read is that large.
         Fail := Decode_Error;
         return;
      end if;

      if RFLX.TLS_Handshake.Contains.Key_Share_HRR_In_HRR_Extension_TLS_Data (E) then
         declare
            KS : RFLX.TLS_Handshake.Key_Share_HRR.Context;
         begin
            RFLX.TLS_Handshake.Key_Share_HRR.Initialize (KS, Scratch);
            RFLX.TLS_Handshake.Contains.Copy_Data (E, KS);
            RFLX.TLS_Handshake.Key_Share_HRR.Verify_Message (KS);
            if DLen = 2
              and then RFLX.TLS_Handshake.Key_Share_HRR.Well_Formed_Message (KS)
            then
               declare
                  G : constant Maybe_ECDHE_Group :=
                    Group_From_Wire
                      (Group_Wire (RFLX.TLS_Handshake.Key_Share_HRR.Get_Selected_Group (KS)));
               begin
                  if G /= Group_None then
                     HC.HRR_Selected_Group := G;
                  else
                     --  A group we never offered: illegal_parameter, decided
                     --  here rather than at the CH2 rebuild.
                     HC.Ext_Parse_Err := Illegal_Parameter;
                  end if;
               end;
            else
               Fail := Decode_Error;
            end if;
            RFLX.TLS_Handshake.Key_Share_HRR.Take_Buffer (KS, Scratch);
         end;

      elsif RFLX.TLS_Handshake.Contains.Cookie_In_HRR_Extension_TLS_Data (E) then
         declare
            CK : RFLX.TLS_Handshake.Cookie.Context;
         begin
            RFLX.TLS_Handshake.Cookie.Initialize (CK, Scratch);
            RFLX.TLS_Handshake.Contains.Copy_Data (E, CK);
            RFLX.TLS_Handshake.Cookie.Verify_Message (CK);
            if RFLX.TLS_Handshake.Cookie.Well_Formed_Message (CK)
              and then 2 + N32 (RFLX.TLS_Handshake.Cookie.Get_Length (CK)) = DLen
            then
               declare
                  C_Len : constant N32 := N32 (RFLX.TLS_Handshake.Cookie.Get_Length (CK));
               begin
                  if C_Len <= N32 (HC.HRR_Cookie'Length) then
                     declare
                        CB : RBT.Bytes (1 .. RBT.Index (C_Len));
                     begin
                        RFLX.TLS_Handshake.Cookie.Get_Cookie (CK, CB);
                        HC.HRR_Cookie (0 .. C_Len - 1) := To_NaCl (CB);
                        HC.HRR_Cookie_Len := C_Len;
                     end;
                  end if;
               end;
            else
               --  An empty cookie (0 is outside Cookie_Length) or a length
               --  that does not fill the body: illegal_parameter (BoGo
               --  HelloRetryRequest-EmptyCookie-TLS13).
               Fail := Illegal_Parameter;
            end if;
            RFLX.TLS_Handshake.Cookie.Take_Buffer (CK, Scratch);
         end;

      elsif RFLX.TLS_Handshake.Contains.Supported_Version_In_HRR_Extension_TLS_Data (E) then
         declare
            SV : RFLX.TLS_Handshake.Supported_Version.Context;
         begin
            RFLX.TLS_Handshake.Supported_Version.Initialize (SV, Scratch);
            RFLX.TLS_Handshake.Contains.Copy_Data (E, SV);
            RFLX.TLS_Handshake.Supported_Version.Verify_Message (SV);
            --  Only the exact value 0x0304 is the TLS 1.3 marker.
            if DLen = 2
              and then RFLX.TLS_Handshake.Supported_Version.Well_Formed_Message (SV)
              and then RFLX.TLS_Handshake.Supported_Version.Get_Version (SV) = RFLX.TLS_Common.TLS_1_3
            then
               Has_TLS13 := True;
            end if;
            RFLX.TLS_Handshake.Supported_Version.Take_Buffer (SV, Scratch);
         end;
      end if;
   end Process_HRR_Extension;

   --  Everything between Initialize and Take_Buffer of the HRR context.
   --  Failures set Err and return; the extension walk itself never returns
   --  early, so the sequence buffer always comes back to Ctx.
   procedure Check_HRR
     (Ctx        : in out RFLX.TLS_Handshake.Hello_Retry_Request.Context;
      Scratch    : in out RBT.Bytes_Ptr;
      HC         : in out Engaged_Context;
      Negotiated : in out Supported_Suite;
      Version    : in out TLS_Version;
      OK         : out Boolean;
      Err        : out Error_Code)
   with
     Pre  =>
       RFLX.TLS_Handshake.Hello_Retry_Request.Has_Buffer (Ctx)
       and then Scratch /= null
       and then Scratch'First = 1
       and then Scratch'Last = Body_Scratch_Len
       and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length),
     Post =>
       RFLX.TLS_Handshake.Hello_Retry_Request.Has_Buffer (Ctx)
       and then Scratch /= null
       and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
       and then (if OK then Version = TLS_1_3)
   is
      use RFLX.TLS_Handshake.Hello_Retry_Request;
      Seen      : Seen_Tags := (others => 0);
      N_Seen    : Natural := 0;
      Has_TLS13 : Boolean := False;
      Sid_Len   : N32;
   begin
      OK  := False;
      Err := No_Error;

      if not Well_Formed_Message (Ctx) then
         --  Including legacy_compression_method /= 0 (the spec's range is
         --  0 .. 0): decode_error, BoGo TLS13-HRR-InvalidCompressionMethod.
         Err := Decode_Error;
         return;
      end if;

      --  RFC 8446 4.1.4 -> 4.1.3: legacy_session_id_echo MUST equal the
      --  session_id we sent (32 bytes unless TLS_1_2_Only, which never
      --  reaches an HRR).
      Sid_Len := N32 (Get_Legacy_Session_ID_Length (Ctx));
      if HC.Cfg.Versions /= TLS_1_2_Only then
         if Sid_Len /= 32 then
            Err := Illegal_Parameter;
            return;
         end if;
         declare
            Echo : RBT.Bytes (1 .. 32);
         begin
            Get_Legacy_Session_ID (Ctx, Echo);
            if To_NaCl (Echo) /= Byte_Seq (HC.Legacy_Session_ID) then
               Err := Illegal_Parameter;
               return;
            end if;
         end;
      end if;

      --  RFC 8446 4.1.4: cipher_suite MUST be a TLS 1.3 suite; kept for the
      --  SH2 match (BoGo HelloRetryRequest-CipherChange-TLS13).
      declare
         Wire : constant Unsigned_16 := Suite_Wire (Get_Cipher_Suite_TLS_Suite (Ctx));
      begin
         if To_Suite (Wire) not in TLS13_Suite then
            Err := Illegal_Parameter;
            return;
         end if;
         HC.HRR_Cipher_Suite := Wire;
         Negotiated := To_Suite (Wire);
      end;

      declare
         Exts : RFLX.TLS_Handshake.HRR_Extensions_TLS.Context;
         Fail : Error_Code := No_Error;
      begin
         Switch_To_Extensions_TLS (Ctx, Exts);
         while Fail = No_Error
           and then RFLX.TLS_Handshake.HRR_Extensions_TLS.Has_Element (Exts)
         loop
            declare
               E : RFLX.TLS_Handshake.HRR_Extension_TLS.Context;
            begin
               RFLX.TLS_Handshake.HRR_Extensions_TLS.Switch (Exts, E);
               RFLX.TLS_Handshake.HRR_Extension_TLS.Verify_Message (E);
               if RFLX.TLS_Handshake.HRR_Extension_TLS.Well_Formed_Message (E) then
                  Process_HRR_Extension (E, HC, Scratch, Seen, N_Seen, Has_TLS13, Fail);
               else
                  Fail := Decode_Error;
               end if;
               RFLX.TLS_Handshake.HRR_Extensions_TLS.Update (Exts, E);
            end;
         end loop;
         Update_Extensions_TLS (Ctx, Exts);
         if Fail /= No_Error then
            Err := Fail;
            return;
         end if;
      end;

      if Has_TLS13 then
         HC.Has_TLS_1_3 := True;
      end if;

      --  RFC 8446 4.1.4: an HRR must ask for a change -- key_share or
      --  cookie (BoGo HelloRetryRequest-Empty-TLS13) ...
      if HC.HRR_Selected_Group = Group_None and then HC.HRR_Cookie_Len = 0 then
         Err := Illegal_Parameter;
         return;
      end if;
      --  ... and the change must be real: CH1 already offered X25519 in
      --  the default profile, or exactly the configured group.
      if (if HC.Cfg.Client_Key_Share_Group /= Group_None then True
          else HC.HRR_Selected_Group = Group_X25519)
      then
         Err := Illegal_Parameter;
         return;
      end if;

      Version := TLS_1_3;
      OK := True;
   end Check_HRR;

   procedure Parse_HRR_Message
     (Data       : in Byte_Seq;
      HC         : in out Engaged_Context;
      Negotiated : in out Supported_Suite;
      Version    : in out TLS_Version;
      OK         : out Boolean;
      Err        : out Error_Code)
   with
     Pre  =>
       Data'Length in 42 .. Max_HS_Msg
       and then Data'Last < N32 (Natural'Last)
       and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length),
     Post =>
       HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
       and then (if OK then Version = TLS_1_3)
   is
      use RFLX.TLS_Handshake.Hello_Retry_Request;
      Body_Len : constant N32 := N32 (Data'Length) - 4;
      Buf      : RBT.Bytes_Ptr;
      Scratch  : RBT.Bytes_Ptr;
      Ctx      : Context;
   begin
      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      Buf.all := To_RFLX (Data (Data'First + 4 .. Data'Last));
      Scratch := new RBT.Bytes'(1 .. Body_Scratch_Len => 0);
      Initialize (Ctx, Buf, Written_Last => RBT.Bit_Length (RBT.Length (Body_Len) * 8));
      Verify_Message (Ctx);
      Check_HRR (Ctx, Scratch, HC, Negotiated, Version, OK, Err);
      Take_Buffer (Ctx, Buf);
      RFLX_Free (Buf);
      RFLX_Free (Scratch);
   end Parse_HRR_Message;

   ----------------------------------------------------------------------------
   --  ServerHello
   ----------------------------------------------------------------------------

   --  Pass 1 over one element: duplicates (decode_error in a ServerHello)
   --  and the supported_versions marker. RFC 8446 4.2.1: the extension,
   --  not legacy_version, says the server selected TLS 1.3, and only the
   --  exact value 0x0304 counts (BoGo SecondServerHelloWrongVersion-TLS13
   --  sends 0x1234).
   procedure Scan_SH_Extension
     (E         : in RFLX.TLS_Handshake.SH_Extension_TLS.Context;
      Scratch   : in out RBT.Bytes_Ptr;
      Seen      : in out Seen_Tags;
      N_Seen    : in out Natural;
      Has_TLS13 : in out Boolean;
      Fail      : out Error_Code)
   with
     Pre  =>
       RFLX.TLS_Handshake.SH_Extension_TLS.Has_Buffer (E)
       and then RFLX.TLS_Handshake.SH_Extension_TLS.Well_Formed_Message (E)
       and then Scratch /= null
       and then Scratch'First = 1
       and then Scratch'Last = Body_Scratch_Len
       and then N_Seen <= Seen'Last,
     Post =>
       Scratch /= null
       and then Scratch'First = 1
       and then Scratch'Last = Body_Scratch_Len
       and then N_Seen <= Seen'Last
   is
      use RFLX.TLS_Handshake.SH_Extension_TLS;
      Tag  : constant Unsigned_16 := Tag_Wire (Get_Tag (E));
      DLen : constant N32 := N32 (Get_Data_Length (E));
      Dup, Full : Boolean;
   begin
      Fail := No_Error;
      Note_Tag (Seen, N_Seen, Tag, Dup, Full);
      if Dup or else Full then
         Fail := Decode_Error;
         return;
      end if;
      if DLen = 2
        and then RFLX.TLS_Handshake.Contains.Supported_Version_In_SH_Extension_TLS_Data (E)
      then
         declare
            SV : RFLX.TLS_Handshake.Supported_Version.Context;
         begin
            RFLX.TLS_Handshake.Supported_Version.Initialize (SV, Scratch);
            RFLX.TLS_Handshake.Contains.Copy_Data (E, SV);
            RFLX.TLS_Handshake.Supported_Version.Verify_Message (SV);
            if RFLX.TLS_Handshake.Supported_Version.Well_Formed_Message (SV)
              and then RFLX.TLS_Handshake.Supported_Version.Get_Version (SV) = RFLX.TLS_Common.TLS_1_3
            then
               Has_TLS13 := True;
            end if;
            RFLX.TLS_Handshake.Supported_Version.Take_Buffer (SV, Scratch);
         end;
      end if;
   end Scan_SH_Extension;

   --  RFC 8446 4.2.8 ServerHello key_share: one KeyShareEntry, group +
   --  key_exchange. Dispatches on the group to HC.KE. A key_exchange that
   --  does not fill the body (BoGo TrailingKeyShareData) or a malformed
   --  entry is decode_error through HC.Ext_Parse_Err; a group or length
   --  we do not know leaves KE un-negotiated and the shared-secret step
   --  answers illegal_parameter, as before.
   procedure Apply_SH_Key_Share
     (E       : in RFLX.TLS_Handshake.SH_Extension_TLS.Context;
      Scratch : in out RBT.Bytes_Ptr;
      HC      : in out Engaged_Context)
   with
     Pre  =>
       RFLX.TLS_Handshake.SH_Extension_TLS.Has_Buffer (E)
       and then RFLX.TLS_Handshake.SH_Extension_TLS.Well_Formed_Message (E)
       and then RFLX.TLS_Handshake.Contains.Key_Share_SH_In_SH_Extension_TLS_Data (E)
       and then N32 (RFLX.TLS_Handshake.SH_Extension_TLS.Get_Data_Length (E)) <= Body_Scratch_Len
       and then Scratch /= null
       and then Scratch'First = 1
       and then Scratch'Last = Body_Scratch_Len,
     Post =>
       Scratch /= null
       and then Scratch'First = 1
       and then Scratch'Last = Body_Scratch_Len
       and then HC.HRR_Cookie_Len = HC.HRR_Cookie_Len'Old
   is
      DLen : constant N32 := N32 (RFLX.TLS_Handshake.SH_Extension_TLS.Get_Data_Length (E));
      KS   : RFLX.TLS_Handshake.Key_Share_SH.Context;
   begin
      RFLX.TLS_Handshake.Key_Share_SH.Initialize (KS, Scratch);
      RFLX.TLS_Handshake.Contains.Copy_Data (E, KS);
      RFLX.TLS_Handshake.Key_Share_SH.Verify_Message (KS);

      if not RFLX.TLS_Handshake.Key_Share_SH.Well_Formed_Message (KS)
        or else 4 + N32 (RFLX.TLS_Handshake.Key_Share_SH.Get_Length (KS)) /= DLen
      then
         HC.Ext_Parse_Err := Decode_Error;
      else
         declare
            Grp    : constant RFLX.Tls_Parameters.TLS_Supported_Groups :=
              RFLX.TLS_Handshake.Key_Share_SH.Get_Group (KS);
            KX_Len : constant N32 := N32 (RFLX.TLS_Handshake.Key_Share_SH.Get_Length (KS));
         begin
            if Grp.Known and then Grp.Enum = RFLX.Tls_Parameters.X25519 and then KX_Len = 32 then
               declare
                  KB : RBT.Bytes (1 .. 32);
               begin
                  RFLX.TLS_Handshake.Key_Share_SH.Get_Key_Exchange (KS, KB);
                  HC.KE.Peer_PK := To_NaCl (KB);
                  HC.KE.Curve := Group_X25519;
                  HC.KE.Negotiated := True;
               end;
            elsif Grp.Known and then Grp.Enum = RFLX.Tls_Parameters.Secp256r1 and then KX_Len = 65 then
               declare
                  KB : RBT.Bytes (1 .. 65);
               begin
                  RFLX.TLS_Handshake.Key_Share_SH.Get_Key_Exchange (KS, KB);
                  for I in 0 .. 64 loop
                     HC.KE.P256_PK (N32 (I)) := Byte (KB (RBT.Index (I + 1)));
                  end loop;
                  HC.KE.Curve := Group_Secp256r1;
                  HC.KE.Negotiated := True;
               end;
            elsif Grp.Known and then Grp.Enum = RFLX.Tls_Parameters.Secp384r1 and then KX_Len = 97 then
               declare
                  KB : RBT.Bytes (1 .. 97);
               begin
                  RFLX.TLS_Handshake.Key_Share_SH.Get_Key_Exchange (KS, KB);
                  for I in 0 .. 96 loop
                     HC.KE.P384_PK (N32 (I)) := Byte (KB (RBT.Index (I + 1)));
                  end loop;
                  HC.KE.Curve := Group_Secp384r1;
                  HC.KE.Negotiated := True;
               end;
            end if;
         end;
      end if;

      RFLX.TLS_Handshake.Key_Share_SH.Take_Buffer (KS, Scratch);
   end Apply_SH_Key_Share;

   --  Pass 2 over one element, with the version known: the policy matrix,
   --  then the body checks each tag needs.
   --    key_share (SH13)         RFC 8446 4.2.8   -> Apply_SH_Key_Share
   --    pre_shared_key (SH13)    RFC 8446 4.2.11  selected_identity must be 0,
   --                             the only identity we offer
   --    ALPN (SH12)              RFC 7301 3.1     shape + must be one we offered
   --    ec_point_formats (SH12)  RFC 8422 5.1.2   must include uncompressed(0)
   --    extended_master_secret   RFC 7627 5.1     latch HC.Use_EMS
   --    session_ticket (SH12)    RFC 5077 3.3     empty body: a ticket follows
   --  supported_versions was read in pass 1; everything else is policy only.
   procedure Apply_SH_Extension
     (E       : in RFLX.TLS_Handshake.SH_Extension_TLS.Context;
      Where   : in Ext_Where;
      HC      : in out Engaged_Context;
      ALPN    : in out Hostname_Buf;
      Scratch : in out RBT.Bytes_Ptr;
      Fail    : out Error_Code)
   with
     Pre  =>
       RFLX.TLS_Handshake.SH_Extension_TLS.Has_Buffer (E)
       and then RFLX.TLS_Handshake.SH_Extension_TLS.Well_Formed_Message (E)
       and then Scratch /= null
       and then Scratch'First = 1
       and then Scratch'Last = Body_Scratch_Len,
     Post =>
       Scratch /= null
       and then Scratch'First = 1
       and then Scratch'Last = Body_Scratch_Len
       and then HC.HRR_Cookie_Len = HC.HRR_Cookie_Len'Old
   is
      use RFLX.TLS_Handshake.SH_Extension_TLS;
      Tag  : constant Unsigned_16 := Tag_Wire (Get_Tag (E));
      DLen : constant N32 := N32 (Get_Data_Length (E));
      V_OK : Boolean;
   begin
      Validate_Server_Ext (Where, Tag, DLen, HC, V_OK, Fail);
      if not V_OK then
         return;
      end if;
      Fail := No_Error;

      if RFLX.TLS_Handshake.Contains.Key_Share_SH_In_SH_Extension_TLS_Data (E) then
         if DLen > Body_Scratch_Len then
            Fail := Decode_Error;
            return;
         end if;
         Apply_SH_Key_Share (E, Scratch, HC);

      elsif RFLX.TLS_Handshake.Contains.Pre_Shared_Key_SH_In_SH_Extension_TLS_Data (E) then
         if DLen /= 2 then
            Fail := Decode_Error;
            return;
         end if;
         declare
            PS : RFLX.TLS_Handshake.Pre_Shared_Key_SH.Context;
            Identity_OK : Boolean := False;
         begin
            RFLX.TLS_Handshake.Pre_Shared_Key_SH.Initialize (PS, Scratch);
            RFLX.TLS_Handshake.Contains.Copy_Data (E, PS);
            RFLX.TLS_Handshake.Pre_Shared_Key_SH.Verify_Message (PS);
            if RFLX.TLS_Handshake.Pre_Shared_Key_SH.Well_Formed_Message (PS)
              and then RFLX.TLS_Handshake.Pre_Shared_Key_SH.Get_Selected_Identity (PS) = 0
            then
               Identity_OK := True;
            end if;
            RFLX.TLS_Handshake.Pre_Shared_Key_SH.Take_Buffer (PS, Scratch);
            if Identity_OK then
               HC.Using_PSK := True;
            else
               Fail := Illegal_Parameter;
               return;
            end if;
         end;

      elsif Tag = 16#0010# then
         --  RFC 7301: list_len(2) + proto_len(1) + proto, one protocol.
         if DLen < 4 or else DLen > 258 then
            Fail := Decode_Error;
            return;
         end if;
         declare
            Raw : RBT.Bytes (1 .. RBT.Index (DLen));
         begin
            Get_Data (E, Raw);
            Validate_ALPN_Echo_Body
              (Data       => To_NaCl (Raw),
               Body_Start => 0,
               E_Len      => DLen,
               HC         => HC,
               ALPN       => ALPN,
               OK         => V_OK,
               Err        => Fail);
            if not V_OK then
               return;
            end if;
            Fail := No_Error;
         end;

      elsif Where = E_SH12 and then Tag = 16#000B# then
         --  RFC 8422 5.1.2: list_len(1) + formats.
         if DLen = 0 or else DLen > 256 then
            Fail := Decode_Error;
            return;
         end if;
         declare
            Raw : RBT.Bytes (1 .. RBT.Index (DLen));
         begin
            Get_Data (E, Raw);
            Check_EC_Point_Formats_Body
              (Data  => To_NaCl (Raw),
               Off   => 0,
               E_Len => DLen,
               OK    => V_OK,
               Err   => Fail);
            if not V_OK then
               return;
            end if;
            Fail := No_Error;
         end;

      elsif Tag = 16#0017# then
         --  RFC 7627 5.1: the server agreed to the extended master secret.
         --  Both this latch and the Tag_Is_Offered arm for 0x0017 are
         --  needed (BoGo ExtendedMasterSecret-TLS12-Client).
         HC.Use_EMS := True;

      elsif Where = E_SH12 and then Tag = 16#0023# and then DLen = 0 then
         --  RFC 5077 3.3: the server will send NewSessionTicket.
         HC.T12.Server_Will_Issue := True;
      end if;
   end Apply_SH_Extension;

   --  Everything between Initialize and Take_Buffer of the ServerHello
   --  context. Two walks over the extensions: the first finds the version
   --  (and duplicates), the second applies that version's policy and reads
   --  the bodies. Failures set Err and return; the walks never return
   --  early, so the sequence buffer always comes back to Ctx.
   --  Classify a ServerHello that RFLX would not accept, from the raw
   --  bytes, exactly as the former hand parser did. This is the only alert
   --  selection the RFLX Well_Formed_Message verdict cannot make on its
   --  own, because it does not distinguish the reasons for rejection.
   --    legacy_version /= 0x0303       -> No_Error (caller: handshake_failure)
   --    legacy_compression_method /= 0 -> Illegal_Parameter (RFC 5246 6.2.2,
   --                                      BoGo InvalidCompressionMethod)
   --    anything else                  -> Decode_Error (truncated fields,
   --                                      over-long session_id, ...)
   function Classify_Bad_SH (Data : Byte_Seq) return Error_Code
   with
     Pre => Data'Length in 42 .. Max_HS_Msg and then Data'Last < N32 (Natural'Last)
   is
      BS      : constant N32 := Data'First + 4;
      Sid_Len : N32;
      P       : N32;
   begin
      if Data (BS) /= 16#03# or else Data (BS + 1) /= 16#03# then
         return No_Error;
      end if;
      Sid_Len := N32 (Data (BS + 34));
      if Sid_Len > 32 then
         return Decode_Error;
      end if;
      --  version(2)+random(32)+sid_len(1)+sid+suite(2) -> compression byte.
      P := BS + 35 + Sid_Len + 2;
      if P <= Data'Last and then Data (P) /= 0 then
         return Illegal_Parameter;
      end if;
      return Decode_Error;
   end Classify_Bad_SH;

   procedure Check_SH
     (Ctx        : in out RFLX.TLS_Handshake.Server_Hello.Context;
      Data       : in Byte_Seq;
      Scratch    : in out RBT.Bytes_Ptr;
      HC         : in out Engaged_Context;
      ALPN       : in out Hostname_Buf;
      Negotiated : in out Supported_Suite;
      Version    : out TLS_Version;
      OK         : out Boolean;
      Err        : out Error_Code)
   with
     Pre  =>
       RFLX.TLS_Handshake.Server_Hello.Has_Buffer (Ctx)
       and then Data'Length in 42 .. Max_HS_Msg
       and then Data'Last < N32 (Natural'Last)
       and then Scratch /= null
       and then Scratch'First = 1
       and then Scratch'Last = Body_Scratch_Len
       and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length),
     Post =>
       RFLX.TLS_Handshake.Server_Hello.Has_Buffer (Ctx)
       and then Scratch /= null
       and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
       and then (if OK then Version in TLS_1_2 | TLS_1_3)
   is
      use RFLX.TLS_Handshake.Server_Hello;
      Seen      : Seen_Tags := (others => 0);
      N_Seen    : Natural := 0;
      Has_TLS13 : Boolean := False;
      Sid_Len   : N32;
      Where     : Ext_Where;
   begin
      Version := TLS_Undetermined;
      OK  := False;
      Err := No_Error;

      if not Well_Formed_Message (Ctx) then
         Err := Classify_Bad_SH (Data);
         return;
      end if;

      --  RFC 8446 4 / RFC 5246 7.4: the message MUST end exactly at its
      --  declared length. A ServerHello that parses but leaves trailing
      --  bytes is decode_error (BoGo TrailingMessageData-ServerHello).
      if Message_Last (Ctx) /= RBT.Bit_Length (RBT.Length (N32 (Data'Length) - 4) * 8) then
         Err := Decode_Error;
         return;
      end if;

      declare
         Random_Bytes : RBT.Bytes (1 .. 32);
      begin
         Get_Random (Ctx, Random_Bytes);
         HC.Server_Random := To_NaCl (Random_Bytes);
      end;

      --  Cipher suite: To_Suite is total (unknown -> Suite_None), so its
      --  domain is the supported set. RFC 8446 4.1.4: after an HRR the
      --  suite MUST match (BoGo HelloRetryRequest-CipherChange-TLS13).
      declare
         Wire      : constant Unsigned_16 := Suite_Wire (Get_Cipher_Suite_TLS_Suite (Ctx));
         Candidate : constant Supported_Suite := To_Suite (Wire);
      begin
         if Candidate = Suite_None then
            return;
         end if;
         if HC.Got_HRR and then HC.HRR_Cipher_Suite /= 0 and then Wire /= HC.HRR_Cipher_Suite then
            Err := Illegal_Parameter;
            return;
         end if;
         Negotiated := Candidate;
      end;

      --  Pass 1: duplicates and the version marker.
      if Present (Ctx, F_Extensions_TLS) then
         declare
            Exts : RFLX.TLS_Handshake.SH_Extensions_TLS.Context;
            Fail : Error_Code := No_Error;
         begin
            Switch_To_Extensions_TLS (Ctx, Exts);
            while Fail = No_Error
              and then RFLX.TLS_Handshake.SH_Extensions_TLS.Has_Element (Exts)
            loop
               declare
                  E : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
               begin
                  RFLX.TLS_Handshake.SH_Extensions_TLS.Switch (Exts, E);
                  RFLX.TLS_Handshake.SH_Extension_TLS.Verify_Message (E);
                  if RFLX.TLS_Handshake.SH_Extension_TLS.Well_Formed_Message (E) then
                     Scan_SH_Extension (E, Scratch, Seen, N_Seen, Has_TLS13, Fail);
                  else
                     Fail := Decode_Error;
                  end if;
                  RFLX.TLS_Handshake.SH_Extensions_TLS.Update (Exts, E);
               end;
            end loop;
            Update_Extensions_TLS (Ctx, Exts);
            if Fail /= No_Error then
               Err := Fail;
               return;
            end if;
         end;
      end if;

      if Has_TLS13 then
         HC.Has_TLS_1_3 := True;
         Version := TLS_1_3;
         Where := E_SH13;
      else
         HC.Has_TLS_1_3 := False;
         Version := TLS_1_2;
         Where := E_SH12;
      end if;

      --  RFC 8446 4.1.4: after an HRR the ServerHello MUST select TLS 1.3
      --  too (BoGo SecondServerHelloWrongVersion-TLS13).
      if HC.Got_HRR and then Version /= TLS_1_3 then
         Err := Illegal_Parameter;
         return;
      end if;
      --  The suite must belong to the selected version.
      if Version = TLS_1_3 and then Negotiated not in TLS13_Suite then
         Err := Illegal_Parameter;
         return;
      end if;
      if Version = TLS_1_2 and then Negotiated not in TLS12_Suite then
         return;
      end if;

      --  RFC 8446 4.1.3: the TLS 1.3 legacy_session_id_echo MUST equal our
      --  session_id, 32 bytes unless TLS_1_2_Only.
      Sid_Len := N32 (Get_Legacy_Session_ID_Length (Ctx));
      if Version = TLS_1_3 and then HC.Cfg.Versions /= TLS_1_2_Only then
         if Sid_Len /= 32 then
            Err := Illegal_Parameter;
            return;
         end if;
         declare
            Echo : RBT.Bytes (1 .. 32);
         begin
            Get_Legacy_Session_ID (Ctx, Echo);
            if To_NaCl (Echo) /= Byte_Seq (HC.Legacy_Session_ID) then
               Err := Illegal_Parameter;
               return;
            end if;
         end;
      end if;

      --  RFC 8446 4.2.1: our own version policy (BoGo MinimumVersion-*).
      if (Version = TLS_1_2 and then HC.Cfg.Versions = TLS_1_3_Only)
        or else (Version = TLS_1_3 and then HC.Cfg.Versions = TLS_1_2_Only)
      then
         Err := Protocol_Version;
         return;
      end if;

      --  RFC 8446 4.1.3 downgrade sentinels, for a client that offered
      --  TLS 1.3 (a TLS_1_2_Only client did not, so the JDK 11 marker is
      --  not a signal for it).
      if HC.Cfg.Versions /= TLS_1_2_Only
        and then Downgrade_Sentinel_Present (HC.Server_Random)
      then
         Err := Illegal_Parameter;
         return;
      end if;

      --  Pass 2: policy and bodies.
      if Present (Ctx, F_Extensions_TLS) then
         declare
            Exts : RFLX.TLS_Handshake.SH_Extensions_TLS.Context;
            Fail : Error_Code := No_Error;
         begin
            Switch_To_Extensions_TLS (Ctx, Exts);
            while Fail = No_Error
              and then RFLX.TLS_Handshake.SH_Extensions_TLS.Has_Element (Exts)
            loop
               declare
                  E : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
               begin
                  RFLX.TLS_Handshake.SH_Extensions_TLS.Switch (Exts, E);
                  RFLX.TLS_Handshake.SH_Extension_TLS.Verify_Message (E);
                  if RFLX.TLS_Handshake.SH_Extension_TLS.Well_Formed_Message (E) then
                     Apply_SH_Extension (E, Where, HC, ALPN, Scratch, Fail);
                  else
                     Fail := Decode_Error;
                  end if;
                  RFLX.TLS_Handshake.SH_Extensions_TLS.Update (Exts, E);
               end;
            end loop;
            Update_Extensions_TLS (Ctx, Exts);
            if Fail /= No_Error then
               Err := Fail;
               return;
            end if;
         end;
      end if;

      if Version = TLS_1_2 then
         --  RFC 5077 3.4: a server accepts ticket resumption by echoing the
         --  exact session_id the client sent. A different or empty echo means
         --  a full handshake, even when the server will issue a fresh ticket
         --  (Server_Will_Issue). The caller keys the abbreviated-flight
         --  decision off this flag; without it, Server_Will_Issue alone would
         --  mistake a resume-rejected full handshake for resumption
         --  (BoGo Resume-Client-NoResume-TLS12).
         declare
            Client_Sid_Len : constant N32 := N32 (HC.Legacy_Session_ID_Len);
            Echoed         : Boolean := Sid_Len > 0 and then Sid_Len = Client_Sid_Len;
         begin
            if Echoed then
               declare
                  --  SPARK (E0007): the array bound must be a constant, not
                  --  a variable, so bind it before the object declaration.
                  SL  : constant RBT.Index := RBT.Index (Sid_Len);
                  Srv : RBT.Bytes (1 .. SL);
               begin
                  Get_Legacy_Session_ID (Ctx, Srv);
                  Echoed :=
                    To_NaCl (Srv) = Byte_Seq (HC.Legacy_Session_ID (0 .. Sid_Len - 1));
               end;
            end if;
            HC.T12.Server_Echoed_SID := Echoed;
         end;

         --  RFC 5246 7.4.1.3: in TLS 1.2 the server may assign a new
         --  session_id; keep it, as the TLS 1.2 parser always did.
         HC.Legacy_Session_ID := (others => 0);
         if Sid_Len > 0 then
            declare
               SL  : constant RBT.Index := RBT.Index (Sid_Len);
               Sid : RBT.Bytes (1 .. SL);
            begin
               Get_Legacy_Session_ID (Ctx, Sid);
               HC.Legacy_Session_ID (0 .. Sid_Len - 1) := To_NaCl (Sid);
            end;
         end if;
         OK := True;
         return;
      end if;

      --  TLS 1.3: ECDHE shared secret from the key_share.
      declare
         SS_OK  : Boolean;
         SS_Err : Error_Code;
      begin
         Compute_SH_Shared_Secret (HC.KE, SS_OK, SS_Err);
         if not SS_OK then
            Err := SS_Err;
            return;
         end if;
      end;

      --  Body verdicts recorded on the way (key_share shape, ...).
      if HC.Ext_Parse_Err /= No_Error then
         Err := HC.Ext_Parse_Err;
         return;
      end if;

      OK := True;
   end Check_SH;

   procedure Parse_SH_Message
     (Data       : in Byte_Seq;
      HC         : in out Engaged_Context;
      ALPN       : in out Hostname_Buf;
      Negotiated : in out Supported_Suite;
      Version    : out TLS_Version;
      OK         : out Boolean;
      Err        : out Error_Code)
   with
     Pre  =>
       Data'Length in 42 .. Max_HS_Msg
       and then Data'Last < N32 (Natural'Last)
       and then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length),
     Post =>
       HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length)
       and then (if OK then Version in TLS_1_2 | TLS_1_3)
   is
      use RFLX.TLS_Handshake.Server_Hello;
      Body_Len : constant N32 := N32 (Data'Length) - 4;
      Buf      : RBT.Bytes_Ptr;
      Scratch  : RBT.Bytes_Ptr;
      Ctx      : Context;
   begin
      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      Buf.all := To_RFLX (Data (Data'First + 4 .. Data'Last));
      Scratch := new RBT.Bytes'(1 .. Body_Scratch_Len => 0);
      Initialize (Ctx, Buf, Written_Last => RBT.Bit_Length (RBT.Length (Body_Len) * 8));
      Verify_Message (Ctx);
      Check_SH (Ctx, Data, Scratch, HC, ALPN, Negotiated, Version, OK, Err);
      Take_Buffer (Ctx, Buf);
      RFLX_Free (Buf);
      RFLX_Free (Scratch);
   end Parse_SH_Message;

   procedure Parse_Server_Hello
     (Negotiated : in out Supported_Suite;
      Last_Err   : in out Error_Code;
      ALPN       : in out Hostname_Buf;
      HC         : in out Engaged_Context;
      Data       : in Byte_Seq;
      Version    : out TLS_Version;
      OK         : out Boolean)
   is
      Err : Error_Code := No_Error;
   begin
      Version := TLS_Undetermined;
      OK := False;

      --  Shape: a ServerHello handshake message with at least the fixed
      --  fields (RFC 5246 7.4.1.3: 38 body bytes with an empty
      --  session_id). Anything else is not parsed here and the caller
      --  answers handshake_failure, as before.
      if Data'Length < 42
        or else Data'Length > Max_HS_Msg
        or else Data'Last >= N32 (Natural'Last)
        or else Data (Data'First) /= HS_Msg_Wire (HT_Server_Hello)
      then
         return;
      end if;

      if Is_HRR_Random (Data) then
         --  RFC 8446 4.1.4: a server MUST send at most one HRR.
         if HC.Got_HRR then
            Last_Err := Unexpected_Message;
            return;
         end if;
         HC.Got_HRR := True;
         Parse_HRR_Message (Data, HC, Negotiated, Version, OK, Err);
      else
         Parse_SH_Message (Data, HC, ALPN, Negotiated, Version, OK, Err);
      end if;

      if not OK and then Err /= No_Error then
         Last_Err := Err;
      end if;
   end Parse_Server_Hello;

end SPARKTLS.Handshake.Client_Msgs;
