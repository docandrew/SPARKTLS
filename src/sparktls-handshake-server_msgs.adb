with Ada.Unchecked_Deallocation;
with Interfaces; use Interfaces;
with SPARKTLSCrypto.X25519;
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
with RFLX.RFLX_Types;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.Field;
with SPARKTLSCrypto.P384.Point;
use SPARKTLSCrypto;

package body SPARKTLS.Handshake.Server_Msgs with
   SPARK_Mode => On
is
   use type RBT.Length;
   use type RBT.Index;
   use type RBT.Bit_Length;
   use type RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values_Enum;
   use type RFLX.Tls_Parameters.TLS_Supported_Groups_Enum;
   use type RFLX.TLS_Handshake.Data_Length;

   --  Deallocate an RFLX buffer.
   --  Body is SPARK_Mode Off (Unchecked_Deallocation of 'access all').
   --  Spec is On so SPARK can verify call sites.
   use type RBT.Bytes_Ptr;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr)
   with Post => Buf = null;

   --  RFC 8446 §4.1.3: HelloRetryRequest sentinel for ServerHello.Random.
   --  Real ServerHello.Random must NOT collide with this value, otherwise
   --  the client interprets the message as HRR. Used to discharge RFLX's
   --  Field_Condition for F_Extensions_TLS.
   HRR_Sentinel : constant Bytes_32 :=
     (16#CF#, 16#21#, 16#AD#, 16#74#, 16#E5#, 16#9A#, 16#61#, 16#11#,
      16#BE#, 16#1D#, 16#8C#, 16#02#, 16#1E#, 16#65#, 16#B8#, 16#91#,
      16#C2#, 16#A2#, 16#11#, 16#16#, 16#7A#, 16#BB#, 16#8C#, 16#5E#,
      16#07#, 16#9E#, 16#09#, 16#E2#, 16#C8#, 16#A8#, 16#33#, 16#9C#);

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr)
   with SPARK_Mode => Off
   is
      procedure Dealloc is new Ada.Unchecked_Deallocation
        (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
   begin
      Dealloc (Buf);
   end RFLX_Free;

   --================================================================
   --  Per-extension helpers extracted from Parse_Client_Hello
   --  to keep each piece small enough for SPARK to discharge.
   --
   --  The caller (Parse_Client_Hello's extensions loop) owns the
   --  outer CH_Extension_TLS context (Ext_Ctx); each helper consumes
   --  its data via Get_Data / Get_Data_Length.
   --================================================================

   --  Handle a single Key_Share_Entry: dispatch on Group, populate
   --  HC.Peer_PK / HC.P256_Peer_PK / HC.P384_Peer_PK and the matching
   --  Client_Has_* flag.
   procedure Apply_KS_Entry
     (E_Ctx : in     RFLX.TLS_Handshake.Key_Share_Entry.Context;
      HC    : in out Handshake_Context)
   with Pre => RFLX.TLS_Handshake.Key_Share_Entry.Has_Buffer (E_Ctx)
              and then RFLX.TLS_Handshake.Key_Share_Entry
                         .Well_Formed_Message (E_Ctx);

   procedure Apply_KS_Entry
     (E_Ctx : in     RFLX.TLS_Handshake.Key_Share_Entry.Context;
      HC    : in out Handshake_Context)
   is
      use RFLX.TLS_Handshake.Key_Share_Entry;
      Grp : constant RFLX.Tls_Parameters.TLS_Supported_Groups :=
              Get_Group (E_Ctx);
   begin
      if not Grp.Known then
         return;
      end if;
      if Grp.Enum = RFLX.Tls_Parameters.X25519 then
         declare
            KLen : constant N32 := N32 (Get_Length (E_Ctx));
         begin
            if KLen = 32 then
               declare
                  KB : RBT.Bytes (1 .. 32);
               begin
                  Get_Key_Exchange (E_Ctx, KB);
                  HC.Peer_PK := To_NaCl (KB);
                  HC.Client_Has_X25519 := True;
               end;
            end if;
         end;
      elsif Grp.Enum = RFLX.Tls_Parameters.Secp256r1 then
         declare
            KLen : constant N32 := N32 (Get_Length (E_Ctx));
         begin
            if KLen = 65 then
               declare
                  KB : RBT.Bytes (1 .. 65);
               begin
                  Get_Key_Exchange (E_Ctx, KB);
                  for I in N32 range 0 .. 64 loop
                     HC.P256_Peer_PK (I) := Byte (KB (RBT.Index (I + 1)));
                  end loop;
                  HC.Client_Has_P256 := True;
               end;
            end if;
         end;
      elsif Grp.Enum = RFLX.Tls_Parameters.Secp384r1 then
         declare
            KLen : constant N32 := N32 (Get_Length (E_Ctx));
         begin
            if KLen = 97 then
               declare
                  KB : RBT.Bytes (1 .. 97);
               begin
                  Get_Key_Exchange (E_Ctx, KB);
                  for I in N32 range 0 .. 96 loop
                     HC.P384_Peer_PK (I) := Byte (KB (RBT.Index (I + 1)));
                  end loop;
                  HC.Client_Has_P384 := True;
               end;
            end if;
         end;
      end if;
   end Apply_KS_Entry;

   --  Parse the key_share extension data (CH variant): allocate a
   --  scratch buffer, initialize Key_Share_CH, iterate the entries
   --  and dispatch each to Apply_KS_Entry.
   procedure Parse_KS_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in     Wire_Key_Share_Len;
      HC      : in out Handshake_Context)
   with Pre => RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
              and then RFLX.TLS_Handshake.CH_Extension_TLS
                         .Well_Formed_Message (Ext_Ctx)
              and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length
                         (Ext_Ctx)
                       = RFLX.TLS_Handshake.Data_Length (DLen);

   procedure Parse_KS_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in     Wire_Key_Share_Len;
      HC      : in out Handshake_Context)
   is
      KS_Buf : RBT.Bytes_Ptr :=
                 new RBT.Bytes'(1 .. RBT.Index (DLen) => 0);
      KS_Ctx : RFLX.TLS_Handshake.Key_Share_CH.Context;
   begin
      RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, KS_Buf.all);
      RFLX.TLS_Handshake.Key_Share_CH.Initialize
        (KS_Ctx, KS_Buf,
         Written_Last => RBT.Bit_Length (RBT.Length (DLen) * 8));
      RFLX.TLS_Handshake.Key_Share_CH.Verify_Message (KS_Ctx);

      --  Switch_To_Shares requires Field_Size F_Shares > 0
      --  (= Get_Length * 8). If client sent an empty shares list,
      --  there's nothing to iterate.
      if RFLX.TLS_Handshake.Key_Share_CH.Well_Formed_Message (KS_Ctx)
        and then RFLX.TLS_Handshake.Key_Share_CH.Field_Size
                   (KS_Ctx, RFLX.TLS_Handshake.Key_Share_CH.F_Shares) > 0
      then
         declare
            Shares_Ctx : RFLX.TLS_Handshake.Key_Share_Entries.Context;
         begin
            RFLX.TLS_Handshake.Key_Share_CH.Switch_To_Shares
              (KS_Ctx, Shares_Ctx);

            while RFLX.TLS_Handshake.Key_Share_Entries.Has_Element
                    (Shares_Ctx)
            loop
               --  Invariants needed across iterations:
               --    Switch (...) Pre   : Has_Buffer (Shares_Ctx)
               --    Update_Shares Pre  : KS_Ctx.Buffer_* = Shares_Ctx.Buffer_*
               --                       and Shares_Ctx.First = Field_First
               --                                       (KS_Ctx, F_Shares)
               pragma Loop_Invariant
                 (RFLX.TLS_Handshake.Key_Share_Entries.Has_Buffer
                    (Shares_Ctx)
                  and then RFLX.TLS_Handshake.Key_Share_Entries.Valid
                    (Shares_Ctx)
                  and then KS_Ctx.Buffer_First = Shares_Ctx.Buffer_First
                  and then KS_Ctx.Buffer_Last  = Shares_Ctx.Buffer_Last
                  and then RFLX.TLS_Handshake.Key_Share_CH.Valid_Next
                             (KS_Ctx,
                              RFLX.TLS_Handshake.Key_Share_CH.F_Shares)
                  and then Shares_Ctx.First =
                             RFLX.TLS_Handshake.Key_Share_CH.Field_First
                               (KS_Ctx,
                                RFLX.TLS_Handshake.Key_Share_CH.F_Shares)
                  and then Shares_Ctx.Last =
                             RFLX.TLS_Handshake.Key_Share_CH.Field_Last
                               (KS_Ctx,
                                RFLX.TLS_Handshake.Key_Share_CH.F_Shares));
               declare
                  E_Ctx : RFLX.TLS_Handshake.Key_Share_Entry.Context;
               begin
                  RFLX.TLS_Handshake.Key_Share_Entries.Switch
                    (Shares_Ctx, E_Ctx);
                  RFLX.TLS_Handshake.Key_Share_Entry.Verify_Message (E_Ctx);

                  if RFLX.TLS_Handshake.Key_Share_Entry.Well_Formed_Message
                       (E_Ctx)
                  then
                     Apply_KS_Entry (E_Ctx, HC);
                  end if;

                  RFLX.TLS_Handshake.Key_Share_Entries.Update
                    (Shares_Ctx, E_Ctx);
               end;
            end loop;

            RFLX.TLS_Handshake.Key_Share_CH.Update_Shares
              (KS_Ctx, Shares_Ctx);
         end;
      end if;

      RFLX.TLS_Handshake.Key_Share_CH.Take_Buffer (KS_Ctx, KS_Buf);
      RFLX_Free (KS_Buf);
   end Parse_KS_Extension;

   --  Parse the signature_algorithms extension data: a 2-byte list_len
   --  followed by 2-byte algorithm codes. We only store algorithms we
   --  support (Peer_Sig_Algos array is fixed-size). On structural error
   --  (list_len mismatch, odd, or zero), OK is set to False and the
   --  outer parser aborts with Decode_Error.
   procedure Parse_Sig_Algs_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in     Wire_Ext_Len;
      HC      : in out Handshake_Context;
      OK      :    out Boolean)
   with Pre  => DLen >= 4
              --  RFLX Data_Length is 16-bit; Wire_Ext_Len allows larger
              --  reassembled values, but the Get_Data_Length read at the
              --  call site is always within Data_Length's range.
              and then DLen <= N32 (RFLX.TLS_Handshake.Data_Length'Last)
              and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer
                         (Ext_Ctx)
              and then RFLX.TLS_Handshake.CH_Extension_TLS
                         .Well_Formed_Message (Ext_Ctx)
              and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length
                         (Ext_Ctx)
                       = RFLX.TLS_Handshake.Data_Length (DLen);

   procedure Parse_Sig_Algs_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in     Wire_Ext_Len;
      HC      : in out Handshake_Context;
      OK      :    out Boolean)
   is
      SA_Buf   : RBT.Bytes_Ptr :=
                   new RBT.Bytes'(1 .. RBT.Index (DLen) => 0);
      Pos      : RBT.Index := 3;
      List_Len : N32;
   begin
      OK := True;
      RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, SA_Buf.all);
      List_Len := N32 (SA_Buf (1)) * 256 + N32 (SA_Buf (2));
      if List_Len /= DLen - 2 or else List_Len mod 2 /= 0
        or else List_Len = 0
      then
         RFLX_Free (SA_Buf);
         OK := False;
         return;
      end if;
      while Pos + 1 <= RBT.Index (DLen) loop
         declare
            Algo : constant Unsigned_16 :=
                     Unsigned_16 (SA_Buf (Pos)) * 256
                     + Unsigned_16 (SA_Buf (Pos + 1));
         begin
            if Algo in 16#0807#  --  Ed25519
                     | 16#0403#  --  ECDSA-P256
                     | 16#0503#  --  ECDSA-P384
                     | 16#0804#  --  RSA-PSS-256
                     | 16#0805#  --  RSA-PSS-384
                     | 16#0806#  --  RSA-PSS-512
              and then HC.Peer_Sig_Algo_Count < Max_Sig_Algos
            then
               HC.Peer_Sig_Algos (HC.Peer_Sig_Algo_Count) := Algo;
               HC.Peer_Sig_Algo_Count := HC.Peer_Sig_Algo_Count + 1;
            end if;
         end;
         Pos := Pos + 2;
      end loop;
      RFLX_Free (SA_Buf);
   end Parse_Sig_Algs_Extension;

   --  Parse the supported_groups extension data: 2-byte list_len
   --  followed by 2-byte group codes. Sets the matching
   --  HC.Client_Supports_* flag for x25519/P-256/P-384.
   procedure Parse_Supported_Groups_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in     Wire_Small_Ext_Len;
      HC      : in out Handshake_Context)
   with Pre => DLen >= 4
              and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer
                         (Ext_Ctx)
              and then RFLX.TLS_Handshake.CH_Extension_TLS
                         .Well_Formed_Message (Ext_Ctx)
              and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length
                         (Ext_Ctx)
                       = RFLX.TLS_Handshake.Data_Length (DLen);

   procedure Parse_Supported_Groups_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in     Wire_Small_Ext_Len;
      HC      : in out Handshake_Context)
   is
      SG_Buf   : RBT.Bytes_Ptr :=
                   new RBT.Bytes'(1 .. RBT.Index (DLen) => 0);
      List_Len : N32;
      Pos      : N32;
   begin
      RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, SG_Buf.all);
      List_Len := N32 (SG_Buf (1)) * 256 + N32 (SG_Buf (2));
      Pos := 3;
      while Pos + 1 <= N32 (DLen) and then Pos < 3 + List_Len loop
         pragma Loop_Invariant (Pos >= 3);
         declare
            Grp : constant Unsigned_16 :=
                    Unsigned_16 (SG_Buf (RBT.Index (Pos))) * 256
                    + Unsigned_16 (SG_Buf (RBT.Index (Pos + 1)));
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
   end Parse_Supported_Groups_Extension;

   --  Parse the supported_versions extension data (CH variant):
   --  1-byte list_len followed by 2-byte version codes. Sets
   --  HC.Has_TLS_1_3 if 0x0304 appears.
   procedure Parse_Supported_Versions_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in     Wire_Small_Ext_Len;
      HC      : in out Handshake_Context)
   with Pre => DLen >= 3
              and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer
                         (Ext_Ctx)
              and then RFLX.TLS_Handshake.CH_Extension_TLS
                         .Well_Formed_Message (Ext_Ctx)
              and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length
                         (Ext_Ctx)
                       = RFLX.TLS_Handshake.Data_Length (DLen);

   procedure Parse_Supported_Versions_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in     Wire_Small_Ext_Len;
      HC      : in out Handshake_Context)
   is
      SV_Buf   : RBT.Bytes_Ptr :=
                   new RBT.Bytes'(1 .. RBT.Index (DLen) => 0);
      List_Len : N32;
      Pos      : N32;
   begin
      RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, SV_Buf.all);
      List_Len := N32 (SV_Buf (1));
      Pos := 2;
      while Pos + 1 <= N32 (DLen) and then Pos < 2 + List_Len loop
         pragma Loop_Invariant (Pos >= 2);
         if N32 (SV_Buf (RBT.Index (Pos))) = 3
           and then N32 (SV_Buf (RBT.Index (Pos + 1))) = 4
         then
            HC.Has_TLS_1_3 := True;
         end if;
         Pos := Pos + 2;
      end loop;
      RFLX_Free (SV_Buf);
   end Parse_Supported_Versions_Extension;

   --  Parse the ALPN extension data: 2-byte list_len followed by
   --  pascal-style protocol strings (1-byte length + bytes). Stores
   --  the FIRST protocol in HC.Client_ALPN.
   procedure Parse_ALPN_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in     Wire_Small_Ext_Len;
      HC      : in out Handshake_Context)
   with Pre => DLen >= 4
              and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer
                         (Ext_Ctx)
              and then RFLX.TLS_Handshake.CH_Extension_TLS
                         .Well_Formed_Message (Ext_Ctx)
              and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length
                         (Ext_Ctx)
                       = RFLX.TLS_Handshake.Data_Length (DLen);

   procedure Parse_ALPN_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in     Wire_Small_Ext_Len;
      HC      : in out Handshake_Context)
   is
      AB : RBT.Bytes_Ptr :=
             new RBT.Bytes'(1 .. RBT.Index (DLen) => 0);
   begin
      RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, AB.all);
      declare
         PL : constant Natural := Natural (AB (3));
      begin
         if PL > 0 and PL <= Max_Hostname_Len and N32 (PL + 3) <= DLen
         then
            HC.Client_ALPN.Len := PL;
            for I in 1 .. PL loop
               HC.Client_ALPN.Data (I) :=
                 Character'Val (AB (RBT.Index (3 + I)));
            end loop;
         end if;
      end;
      RFLX_Free (AB);
   end Parse_ALPN_Extension;

   --  Parse the pre_shared_key extension data:
   --    identities_len(2) || identity { len(2) || ticket || age(4) }+
   --    || binders_len(2) || binder { len(1) || binder_bytes }+
   --  Stores the FIRST identity's ticket ID (if length matches), the
   --  first binder, and the binders-list offset. Tolerates malformed
   --  data: any structural error just skips, leaving HC unchanged.
   subtype Wire_PSK_Ext_Len is N32 range 6 .. 1024;
   procedure Parse_PSK_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in     Wire_PSK_Ext_Len;
      HC      : in out Handshake_Context)
   with Pre => RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
              and then RFLX.TLS_Handshake.CH_Extension_TLS
                         .Well_Formed_Message (Ext_Ctx)
              and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length
                         (Ext_Ctx)
                       = RFLX.TLS_Handshake.Data_Length (DLen);

   procedure Parse_PSK_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in     Wire_PSK_Ext_Len;
      HC      : in out Handshake_Context)
   is
      ED       : RBT.Bytes (1 .. RBT.Index (DLen));
      Ext_Data : Byte_Seq (0 .. DLen - 1);
   begin
      RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, ED);
      Ext_Data := To_NaCl (ED);

      --  identities_len(2) + first identity
      declare
         IDs_Len : constant N32 :=
                     N32 (Ext_Data (0)) * 256 + N32 (Ext_Data (1));
         P : N32 := 2;
         --  Single-identity wire size: tick_len(2) + ticket + age(4).
         Single_ID_Size : constant N32 := 2 + N32 (Ticket_ID_Len) + 4;
      begin
         if P + 2 > DLen or else IDs_Len = 0 then
            return;
         end if;
         --  Reject multi-identity PSK extensions. RFC 8446 §4.2.11
         --  permits multiple identities (server picks one) but our
         --  parser handles only the single-identity / single-binder
         --  shape today. Mis-parsing a multi-identity offer would
         --  bind the wrong binder to the wrong identity, which is a
         --  protocol-correctness issue (Bug #1 class). Bailing out
         --  silently here causes the server to fall back to a full
         --  handshake — safe, just no resumption.
         if IDs_Len /= Single_ID_Size then
            return;
         end if;
         --  First identity: len(2) + ticket + age(4)
         declare
            Tick_Len : constant N32 :=
                         N32 (Ext_Data (P)) * 256 + N32 (Ext_Data (P + 1));
         begin
            P := P + 2;
            if P + Tick_Len + 4 > DLen or else Tick_Len /= Ticket_ID_Len then
               return;
            end if;
            HC.PSK_Ticket_ID := Ext_Data (P .. P + Tick_Len - 1);
            HC.PSK_Offered := True;

            --  Skip to binders list (past all identities: 2 + IDs_Len)
            declare
               Binders_Start : constant N32 := 2 + IDs_Len;
            begin
               if Binders_Start + 2 >= DLen then
                  return;
               end if;
               declare
                  B_Pos : constant N32 := Binders_Start + 2;
               begin
                  if B_Pos >= DLen then
                     return;
                  end if;
                  declare
                     B_Len : constant N32 := N32 (Ext_Data (B_Pos));
                  begin
                     if B_Len in 32 | 48
                       and then B_Pos + 1 + B_Len <= DLen
                     then
                        for I in N32 range 0 .. B_Len - 1 loop
                           HC.PSK_Binder (I) := Ext_Data (B_Pos + 1 + I);
                        end loop;
                        HC.PSK_Binder_Len := B_Len;
                        --  Binders offset relative to the extension
                        --  data start (used later by HMAC computation).
                        HC.PSK_Binders_Offset := Binders_Start;
                     end if;
                  end;
               end;
            end;
         end;
      end;
   end Parse_PSK_Extension;

   --  Apply one parsed cipher suite to the session's negotiation state:
   --  pick the best TLS 1.3 suite (preferring ChaCha20) and the first
   --  TLS 1.2 ECDHE suite we recognize.
   procedure Apply_Cipher_Suite
     (Suite_Ctx : in     RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
      S         : in out Session;
      HC        : in out Handshake_Context)
   with Pre =>
     RFLX.TLS_Handshake.Cipher_Suite_TLS.Has_Buffer (Suite_Ctx)
     and then RFLX.TLS_Handshake.Cipher_Suite_TLS.Well_Formed_Message
                (Suite_Ctx);

   procedure Apply_Cipher_Suite
     (Suite_Ctx : in     RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
      S         : in out Session;
      HC        : in out Handshake_Context)
   is
      Suite : constant RFLX.Tls_Parameters.TLS_Cipher_Suites :=
                RFLX.TLS_Handshake.Cipher_Suite_TLS.Get_Suite (Suite_Ctx);
      --  TLS_Cipher_Suites_Enum has Size=>16; Raw is 16-bit wire value.
      --  Both branches fit in Unsigned_16 — guard with Valid predicate
      --  to make it explicit for the prover.
      Suite_Code : constant RFLX.RFLX_Types.Base_Integer :=
                     RFLX.Tls_Parameters.To_Base_Integer (Suite);
      Val   : Unsigned_16;
      --  Cert algorithm gating (RFC 5246 §7.4.2 / RFC 8422 §5.4).
      --  ECDHE_ECDSA and ECDHE_RSA require certs of the matching
      --  signature type. Picking a suite our cert can't sign blocks
      --  the client side ("ECDHE_ECDSA requires ECDSA / Ed25519
      --  server public key" or equivalent). Was: any TLS 1.2 suite
      --  in the offered list was accepted, regardless of cert.
      Cert_Is_ECDSA : constant Boolean :=
         HC.Cfg.Local /= null
         and then HC.Cfg.Local.Sign_Algo in
                    Sign_ECDSA_P256 | Sign_ECDSA_P384;
      Cert_Is_RSA : constant Boolean :=
         HC.Cfg.Local /= null
         and then HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS;
   begin
      if not RFLX.Tls_Parameters.Valid_TLS_Cipher_Suites (Suite_Code) then
         return;
      end if;
      Val := Unsigned_16 (Suite_Code);
      --  TLS 1.3 suites (0x13xx). Prefer ChaCha20 over AES-GCM.
      --  TLS 1.3 cipher selection is independent of cert type
      --  (signature comes from signature_algorithms extension).
      if Val in Suite_AES_256_GCM_SHA384
              | Suite_AES_128_GCM_SHA256
              | Suite_CHACHA20_POLY1305_SHA256
      then
         if S.Negotiated_Suite = 0 then
            S.Negotiated_Suite := Val;
         elsif Val = Suite_CHACHA20_POLY1305_SHA256 then
            S.Negotiated_Suite := Val;
         end if;
      end if;

      --  When no cert is configured (unit-test path or pre-configure),
      --  fall back to the original "accept any TLS 1.2 ECDHE suite"
      --  behaviour so the suite is recorded for later inspection.
      if HC.Cfg.Local = null then
         if S.Negotiated_Suite_12 = 0
           and then Val in Suite_ECDHE_RSA_AES128_GCM_SHA256
                          | Suite_ECDHE_RSA_AES256_GCM_SHA384
                          | Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                          | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                          | Suite_ECDHE_RSA_CHACHA20_SHA256
                          | Suite_ECDHE_ECDSA_CHACHA20_SHA256
         then
            S.Negotiated_Suite_12 := Val;
         end if;
         return;
      end if;

      --  TLS 1.2 ECDHE_ECDSA suites (0xC02B / 0xC02C / 0xCCA9):
      --  cert must be ECDSA.
      if S.Negotiated_Suite_12 = 0
        and then Cert_Is_ECDSA
        and then Val in Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                       | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                       | Suite_ECDHE_ECDSA_CHACHA20_SHA256
      then
         S.Negotiated_Suite_12 := Val;
      end if;

      --  TLS 1.2 ECDHE_RSA suites (0xC02F / 0xC030 / 0xCCA8):
      --  cert must be RSA.
      if S.Negotiated_Suite_12 = 0
        and then Cert_Is_RSA
        and then Val in Suite_ECDHE_RSA_AES128_GCM_SHA256
                       | Suite_ECDHE_RSA_AES256_GCM_SHA384
                       | Suite_ECDHE_RSA_CHACHA20_SHA256
      then
         S.Negotiated_Suite_12 := Val;
      end if;
   end Apply_Cipher_Suite;

   --  Dispatch a single CH extension by Tag and update HC accordingly.
   --  Records the extension in the order-fingerprint hash (skipping
   --  cookie which is added after HRR).
   --
   --  OK = False signals the outer parser to abort with Decode_Error.
   --  Currently only the signature_algorithms branch with a malformed
   --  inner length triggers this; other malformed extensions are
   --  silently skipped (RFC 8446 doesn't require strict per-ext error).
   procedure Apply_CH_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      :    out Boolean)
   with Pre => RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
              and then RFLX.TLS_Handshake.CH_Extension_TLS
                         .Well_Formed_Message (Ext_Ctx);

   procedure Apply_CH_Extension
     (Ext_Ctx : in     RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      :    out Boolean)
   is
      Tag : constant
        RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values :=
        RFLX.TLS_Handshake.CH_Extension_TLS.Get_Tag (Ext_Ctx);
      DLen : constant N32 :=
        N32 (RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx));
   begin
      OK := True;

      --  Record extension order fingerprint (rolling polynomial hash).
      --  Skip cookie (0x002C) — it's added after HRR.
      declare
         Code : constant Unsigned_32 :=
           Unsigned_32
             (RFLX.Tls_Extensiontype_Values.To_Base_Integer (Tag));
      begin
         --  RFC 8446 §4.2: duplicate extension types in CH MUST be
         --  rejected. BoGo's DuplicateExtension test exercises this.
         for I in 1 .. HC.Seen_Ext_Count loop
            if HC.Seen_Ext_Tags (I) = Code then
               OK := False;
               return;
            end if;
         end loop;
         if HC.Seen_Ext_Count < HC.Seen_Ext_Tags'Last then
            HC.Seen_Ext_Count := HC.Seen_Ext_Count + 1;
            HC.Seen_Ext_Tags (HC.Seen_Ext_Count) := Code;
         end if;
         if Code /= 16#002C# then
            HC.CH_Ext_Hash := HC.CH_Ext_Hash * 31 xor Code;
            --  Saturating increment: the loop bound (max ~16K extensions
            --  in a 64K extensions field) is far below Natural'Last but
            --  the prover doesn't see that without an invariant.
            if HC.CH_Ext_Count < Natural'Last then
               HC.CH_Ext_Count := HC.CH_Ext_Count + 1;
            end if;
         end if;
      end;

      if not Tag.Known then
         return;
      end if;

      case Tag.Enum is
         when RFLX.Tls_Extensiontype_Values.Key_Share =>
            if DLen in Wire_Key_Share_Len then
               Parse_KS_Extension (Ext_Ctx, DLen, HC);
            end if;

         when RFLX.Tls_Extensiontype_Values.Signature_Algorithms =>
            if DLen not in Wire_Ext_Len or else DLen < 4
              or else DLen > N32 (RFLX.TLS_Handshake.Data_Length'Last)
            then
               OK := False;
               return;
            end if;
            declare
               SA_OK : Boolean;
            begin
               Parse_Sig_Algs_Extension (Ext_Ctx, DLen, HC, SA_OK);
               if not SA_OK then
                  OK := False;
                  return;
               end if;
            end;

         when RFLX.Tls_Extensiontype_Values.Supported_Groups =>
            if DLen in Wire_Small_Ext_Len and then DLen >= 4 then
               Parse_Supported_Groups_Extension (Ext_Ctx, DLen, HC);
            end if;

         when RFLX.Tls_Extensiontype_Values.Pre_Shared_Key =>
            if DLen in Wire_PSK_Ext_Len then
               Parse_PSK_Extension (Ext_Ctx, DLen, HC);
            end if;

         when RFLX.Tls_Extensiontype_Values.Supported_Versions =>
            if DLen in Wire_Small_Ext_Len and then DLen >= 3 then
               Parse_Supported_Versions_Extension (Ext_Ctx, DLen, HC);
            end if;

         when RFLX.Tls_Extensiontype_Values
                .Application_Layer_Protocol_Negotiation =>
            if DLen in Wire_Small_Ext_Len and then DLen >= 4 then
               Parse_ALPN_Extension (Ext_Ctx, DLen, HC);
            end if;

         when RFLX.Tls_Extensiontype_Values.Renegotiation_Info =>
            --  RFC 5746: client offered the renegotiation_info
            --  extension. We echo it in ServerHello only when this
            --  flag (or the SCSV signal) is set.
            HC.Saw_Reneg_Info := True;

         when RFLX.Tls_Extensiontype_Values.Extended_Master_Secret =>
            --  RFC 7627: extended_master_secret extension. Empty body
            --  (DLen = 0). When the client sends it, the server
            --  derives master_secret using the EMS PRF and echoes the
            --  extension in ServerHello. When the client doesn't send
            --  it, the server MUST use the original RFC 5246 PRF.
            --  Without tracking this, every TLS-1.2 client that
            --  doesn't request EMS produces a master-secret mismatch
            --  (TLS-Anvil's HappyFlow tests fail in 12/12 such
            --  combinations).
            if DLen = 0 then
               HC.Use_EMS := True;
            end if;

         when RFLX.Tls_Extensiontype_Values.Ec_Point_Formats =>
            --  RFC 8422 §5.1.2: only point format 0 (uncompressed)
            --  may appear in this list — formats 1 and 2 are
            --  deprecated and MUST NOT be supported. We delegate to
            --  EC_Point_Formats_Acceptable, whose Post is formally
            --  proven by SPARK to match the RFC exactly.
            if DLen >= 2 and then DLen in Wire_Small_Ext_Len then
               declare
                  ED        : RBT.Bytes (1 .. RBT.Index (DLen));
                  Ext_Data  : Byte_Seq (0 .. DLen - 1);
                  List_Len  : N32;
               begin
                  RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, ED);
                  Ext_Data := To_NaCl (ED);
                  List_Len := N32 (Ext_Data (0));
                  if List_Len > 0 and then List_Len <= DLen - 1 then
                     if not EC_Point_Formats_Acceptable
                              (Ext_Data (1 .. List_Len))
                     then
                        OK := False;
                        return;
                     end if;
                  end if;
               end;
            end if;

         when others =>
            null;
      end case;
   end Apply_CH_Extension;

   --  Iterate the F_Extensions_TLS list and call Apply_CH_Extension on
   --  each well-formed entry. Mirrors Parse_CH_Cipher_Suites: same
   --  Switch_To/Switch/Update/Update_Outer pattern with the same
   --  Loop_Invariant set for the Has_Buffer / Buffer_First/Last /
   --  Field_First/Last alignment across iterations.
   --
   --  OK = False if any extension dispatcher returned False (currently
   --  only sig_algs malformed). On that path we still drain the loop
   --  with Update + Update_Extensions_TLS so Ctx regains the buffer
   --  and the caller can Take_Buffer + RFLX_Free cleanly.
   procedure Parse_CH_Extensions
     (Ctx : in out RFLX.TLS_Handshake.Client_Hello.Context;
      HC  : in out Handshake_Context;
      OK  :    out Boolean)
   with Pre =>
     not Ctx'Constrained
     and then RFLX.TLS_Handshake.Client_Hello.Has_Buffer (Ctx)
     and then RFLX.TLS_Handshake.Client_Hello.Well_Formed
                (Ctx, RFLX.TLS_Handshake.Client_Hello.F_Extensions_TLS),
     Post =>
       RFLX.TLS_Handshake.Client_Hello.Has_Buffer (Ctx)
       and Ctx.Buffer_First = Ctx.Buffer_First'Old
       and Ctx.Buffer_Last  = Ctx.Buffer_Last'Old;

   procedure Parse_CH_Extensions
     (Ctx : in out RFLX.TLS_Handshake.Client_Hello.Context;
      HC  : in out Handshake_Context;
      OK  :    out Boolean)
   is
      use RFLX.TLS_Handshake.Client_Hello;
      Aborting : Boolean := False;
   begin
      OK := True;
      if Field_Size (Ctx, F_Extensions_TLS) = 0 then
         return;
      end if;

      declare
         Exts_Ctx : RFLX.TLS_Handshake.CH_Extensions_TLS.Context;
      begin
         Switch_To_Extensions_TLS (Ctx, Exts_Ctx);

         while RFLX.TLS_Handshake.CH_Extensions_TLS.Has_Element (Exts_Ctx)
         loop
            pragma Loop_Invariant
              (RFLX.TLS_Handshake.CH_Extensions_TLS.Has_Buffer (Exts_Ctx)
               and then RFLX.TLS_Handshake.CH_Extensions_TLS.Valid
                          (Exts_Ctx)
               and then Ctx.Buffer_First = Exts_Ctx.Buffer_First
               and then Ctx.Buffer_Last  = Exts_Ctx.Buffer_Last
               and then Valid_Next (Ctx, F_Extensions_TLS)
               and then Exts_Ctx.First =
                          Field_First (Ctx, F_Extensions_TLS)
               and then Exts_Ctx.Last  =
                          Field_Last  (Ctx, F_Extensions_TLS));
            declare
               Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
            begin
               RFLX.TLS_Handshake.CH_Extensions_TLS.Switch
                 (Exts_Ctx, Ext_Ctx);
               RFLX.TLS_Handshake.CH_Extension_TLS.Verify_Message (Ext_Ctx);

               if not Aborting
                 and then RFLX.TLS_Handshake.CH_Extension_TLS
                            .Well_Formed_Message (Ext_Ctx)
               then
                  declare
                     Sub_OK : Boolean;
                  begin
                     Apply_CH_Extension (Ext_Ctx, HC, Sub_OK);
                     if not Sub_OK then
                        Aborting := True;
                     end if;
                  end;
               end if;

               RFLX.TLS_Handshake.CH_Extensions_TLS.Update
                 (Exts_Ctx, Ext_Ctx);
            end;
         end loop;

         Update_Extensions_TLS (Ctx, Exts_Ctx);
      end;

      if Aborting then
         OK := False;
      end if;
   end Parse_CH_Extensions;

   --  Iterate the F_Cipher_Suites_TLS list and call Apply_Cipher_Suite
   --  on each well-formed entry. Mirrors Parse_KS_Extension's inner
   --  loop pattern: Switch_To, while Has_Element loop with Switch /
   --  Verify / Update, Update_Outer.
   procedure Parse_CH_Cipher_Suites
     (Ctx : in out RFLX.TLS_Handshake.Client_Hello.Context;
      S   : in out Session;
      HC  : in out Handshake_Context)
   with Pre =>
     not Ctx'Constrained
     and then RFLX.TLS_Handshake.Client_Hello.Has_Buffer (Ctx)
     and then RFLX.TLS_Handshake.Client_Hello.Well_Formed
                (Ctx,
                 RFLX.TLS_Handshake.Client_Hello.F_Cipher_Suites_TLS),
     Post =>
       RFLX.TLS_Handshake.Client_Hello.Has_Buffer (Ctx)
       and Ctx.Buffer_First = Ctx.Buffer_First'Old
       and Ctx.Buffer_Last  = Ctx.Buffer_Last'Old;

   procedure Parse_CH_Cipher_Suites
     (Ctx : in out RFLX.TLS_Handshake.Client_Hello.Context;
      S   : in out Session;
      HC  : in out Handshake_Context)
   is
      use RFLX.TLS_Handshake.Client_Hello;
   begin
      if Field_Size (Ctx, F_Cipher_Suites_TLS) = 0 then
         return;
      end if;

      declare
         Suites_Ctx : RFLX.TLS_Handshake.Cipher_Suites_TLS.Context;
      begin
         Switch_To_Cipher_Suites_TLS (Ctx, Suites_Ctx);

         while RFLX.TLS_Handshake.Cipher_Suites_TLS.Has_Element
                 (Suites_Ctx)
         loop
            pragma Loop_Invariant
              (RFLX.TLS_Handshake.Cipher_Suites_TLS.Has_Buffer (Suites_Ctx)
               and then RFLX.TLS_Handshake.Cipher_Suites_TLS.Valid
                          (Suites_Ctx)
               and then Ctx.Buffer_First = Suites_Ctx.Buffer_First
               and then Ctx.Buffer_Last  = Suites_Ctx.Buffer_Last
               and then Valid_Next (Ctx, F_Cipher_Suites_TLS)
               and then Suites_Ctx.First =
                          Field_First (Ctx, F_Cipher_Suites_TLS)
               and then Suites_Ctx.Last  =
                          Field_Last  (Ctx, F_Cipher_Suites_TLS));
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
                  Apply_Cipher_Suite (Suite_Ctx, S, HC);
               end if;
               RFLX.TLS_Handshake.Cipher_Suites_TLS.Update
                 (Suites_Ctx, Suite_Ctx);
            end;
         end loop;

         Update_Cipher_Suites_TLS (Ctx, Suites_Ctx);
      end;
   end Parse_CH_Cipher_Suites;

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
         --  RFC 8446 §6: a handshake message of an inappropriate
         --  type for the current state must be rejected with
         --  unexpected_message, not decode_error. The message is
         --  structurally well-formed (we read its 4-byte header to
         --  reach this point); the type byte just identifies a
         --  different message that doesn't belong here.
         S.Last_Error := Unexpected_Message;
         return;
      end if;

      --  Skip 4-byte handshake header, pass body to Client_Hello context
      Body_Len := N32 (Data'Length) - 4;

      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      Buf.all := To_RFLX (Data (Data'First + 4 .. Data'Last));
      Initialize (Ctx, Buf,
                  Written_Last => RBT.Bit_Length (RBT.Length (Body_Len) * 8));
      Verify_Message (Ctx);

      --  Strict trailing-data check: the parsed CH structure must
      --  consume the entire body. RFC 8446 §4.1.2 / RFC 5246 §7.4.1.2
      --  do not permit trailing data after the extensions block.
      --  BoGo's `SendTrailingMessageData` test appends a stray byte
      --  inside the handshake length; if RFLX's structural fields
      --  all parse but the byte count exceeds Message_Last, reject
      --  with decode_error rather than silently accepting.
      if Well_Formed_Message (Ctx)
        and then Message_Last (Ctx) /=
                   RBT.Bit_Length (RBT.Length (Body_Len) * 8)
      then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         S.Last_Error := Decode_Error;
         return;
      end if;

      if not Well_Formed_Message (Ctx) then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         --  Distinguish failure modes for the right alert:
         --    legacy_version != 0x0303      → protocol_version
         --    legacy_compression_methods    → illegal_parameter
         --       != single 0x00 byte
         --    other                         → decode_error
         --
         --  ClientHello body layout (RFC 8446 §4.1.2):
         --    legacy_version(2) | random(32) | session_id_len(1) |
         --    session_id(0..32) | cipher_suites_len(2) |
         --    cipher_suites    | compression_methods_len(1) |
         --    compression_methods(1..255) | extensions...
         if Data'Length >= 6 and then
            (Data (Data'First + 4) /= 16#03# or Data (Data'First + 5) /= 16#03#)
         then
            S.Last_Error := Protocol_Version;
         else
            --  Walk to legacy_compression_methods to check it's
            --  exactly the single byte 0x00. RFC 8446 §4.1.2 +
            --  §6.2.1: any other compression list is illegal_parameter.
            declare
               BS  : constant N32 := Data'First + 4;  --  past HS hdr
               P   : N32;
               OK  : Boolean := False;
               Sid_Len, Cs_Len, Cm_Len : N32;
            begin
               --  Need at least: version(2)+random(32)+sid_len(1) = 35
               if N32 (Data'Length) >= 4 + 35 then
                  Sid_Len := N32 (Data (BS + 34));
                  P := BS + 35 + Sid_Len;
                  if P + 2 <= N32 (Data'Last) - N32 (Data'First) + 1
                              + N32 (Data'First)
                  then
                     Cs_Len := N32 (Data (P)) * 256 + N32 (Data (P + 1));
                     P := P + 2 + Cs_Len;
                     if P + 1 <= Data'Last then
                        Cm_Len := N32 (Data (P));
                        if Cm_Len /= 1
                          or else (P + 1 <= Data'Last
                                   and then Data (P + 1) /= 0)
                        then
                           OK := True;  --  found bad compression
                        end if;
                     end if;
                  end if;
               end if;
               if OK then
                  S.Last_Error := Illegal_Parameter;
               else
                  S.Last_Error := Decode_Error;
               end if;
            end;
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

      --  Extract legacy session ID. RFC 8446 §4.1.3: server MUST
      --  echo the exact bytes (and length) the client sent. Track
      --  both so Build_Server_Hello can echo accurately.
      declare
         SID_Len : constant N32 :=
            N32 (Get_Legacy_Session_ID_Length (Ctx));
      begin
         HC.Legacy_Session_ID := (others => 0);
         HC.Legacy_Session_ID_Len := SID_Len;
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
         Parse_CH_Cipher_Suites (Ctx, S, HC);
      end if;

      --  Need at least one matching suite (either TLS 1.3 or 1.2)
      if S.Negotiated_Suite = 0 and S.Negotiated_Suite_12 = 0 then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         return;
      end if;

      --  Iterate extensions to find key_share / sig_algs / etc.
      if Well_Formed (Ctx, F_Extensions_TLS) then
         declare
            Ext_OK : Boolean;
         begin
            Parse_CH_Extensions (Ctx, HC, Ext_OK);
            if not Ext_OK then
               --  Sig_algs malformed. Parse_CH_Extensions has already
               --  closed Exts_Ctx back to Ctx, so Take_Buffer is safe.
               Take_Buffer (Ctx, Buf);
               RFLX_Free (Buf);
               S.Last_Error := Decode_Error;
               return;
            end if;
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

   --================================================================
   --  Helpers extracted from Build_Server_Hello so each piece is
   --  small enough for SPARK's SMT solvers to discharge.
   --
   --  KS_Raw layout: 4-byte TLS NamedGroupEntry header (group(2) +
   --  key_len(2)) followed by the encoded public key bytes.
   --================================================================

   subtype KS_Raw_Buffer is Byte_Seq (0 .. 103);  --  max P-384: 4 + 97
   --  Wire representation of a single TLS 1.3 KeyShareEntry.

   --  X25519 key share generation (RFC 8446 §4.2.8.2).
   --  Always succeeds.
   procedure Generate_KS_X25519
     (HC         : in out Handshake_Context;
      KS_Raw     :    out KS_Raw_Buffer;
      KS_Raw_Len :    out N32;
      OK         :    out Boolean)
   with Pre  => HC.Cfg.Random /= null,
        Post => (if OK then KS_Raw_Len = 36 else KS_Raw_Len = 0)
   is
      procedure Gen_Random (Output : out Byte_Seq)
        renames HC.Cfg.Random.all;
      PK_Bytes  : Bytes_32;
      Basepoint : constant Bytes_32 := (9, others => 0);
      Tmp_SK    : Bytes_32;
   begin
      KS_Raw := (others => 0);

      Gen_Random (Byte_Seq (Tmp_SK));
      HC.Local_SK := Tmp_SK;
      SPARKTLSCrypto.X25519.Scalar_Mult (PK_Bytes, HC.Local_SK, Basepoint);
      SPARKTLSCrypto.X25519.Scalar_Mult
        (HC.Shared_Secret (0 .. 31), HC.Local_SK, HC.Peer_PK);

      --  RFC 7748 §6.1 / RFC 8422 §5.10: reject all-zero shared
      --  secret (small-subgroup attack defense). The X25519 spec
      --  permits this output for points of small order (orders 1,
      --  2, 4, 8 — eight specific 32-byte strings). Without this
      --  check, an attacker who feeds such a point can predict
      --  the master secret. The helper's Post is formally proven.
      if not Shared_Secret_Is_Acceptable_X25519
               (HC.Shared_Secret (0 .. 31))
      then
         HC.Shared_Secret := (others => 0);
         KS_Raw_Len := 0;
         OK := False;
         return;
      end if;

      --  group(2) + key_len(2) + key(32) = 36
      KS_Raw (0) := 0; KS_Raw (1) := 16#1D#;  --  x25519
      KS_Raw (2) := 0; KS_Raw (3) := 32;
      for I in N32 range 0 .. 31 loop
         KS_Raw (4 + I) := PK_Bytes (I);
      end loop;
      KS_Raw_Len := 36;
      OK := True;
   end Generate_KS_X25519;

   --  P-256 key share generation (RFC 8446 §4.2.8.2 + RFC 8422 §5).
   --  OK = False if HC.P256_Peer_PK is not a valid point.
   procedure Generate_KS_P256
     (HC         : in out Handshake_Context;
      KS_Raw     :    out KS_Raw_Buffer;
      KS_Raw_Len :    out N32;
      OK         :    out Boolean)
   with Pre  => HC.Cfg.Random /= null,
        Post => (if OK then KS_Raw_Len = 69 else KS_Raw_Len = 0)
   is
      use SPARKTLSCrypto.P256.Point;
      procedure Gen_Random (Output : out Byte_Seq)
        renames HC.Cfg.Random.all;
      PK_Jac  : P256_Jacobian;
      PK_Enc  : Byte_Seq (0 .. 64);
      Peer_Pt : P256_Jacobian;
      Valid   : SPARKNaCl.U32;
      Tmp_SK  : Bytes_32;
   begin
      KS_Raw     := (others => 0);
      KS_Raw_Len := 0;
      OK         := False;

      Gen_Random (Byte_Seq (Tmp_SK));
      HC.P256_Local_SK := Tmp_SK;
      --  Our public key
      P256_Mulgen (PK_Jac, HC.P256_Local_SK, 32);
      P256_To_Affine (PK_Jac);
      P256_Encode (PK_Enc, PK_Jac);
      --  Shared secret: x-coord of [our_sk] * peer_pk
      P256_Decode (Peer_Pt, HC.P256_Peer_PK, Valid);
      if Valid = 0 then
         return;  --  invalid peer pubkey
      end if;
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
      OK := True;
   end Generate_KS_P256;

   --  P-384 key share generation.
   --  OK = False if P384_ECDHE rejects HC.P384_Peer_PK.
   procedure Generate_KS_P384
     (HC         : in out Handshake_Context;
      KS_Raw     :    out KS_Raw_Buffer;
      KS_Raw_Len :    out N32;
      OK         :    out Boolean)
   with Pre  => HC.Cfg.Random /= null
                and SPARKTLSCrypto.P384.Field.Initialized,
        Post => (if OK then KS_Raw_Len = 101 else KS_Raw_Len = 0)
   is
      procedure Gen_Random (Output : out Byte_Seq)
        renames HC.Cfg.Random.all;
      PK_Enc : Byte_Seq (0 .. 96);
      SS     : Bytes_48;
      SS_OK  : Boolean;
      Tmp_SK : Bytes_48;
   begin
      KS_Raw     := (others => 0);
      KS_Raw_Len := 0;
      OK         := False;

      Gen_Random (Byte_Seq (Tmp_SK));
      HC.P384_Local_SK := Tmp_SK;
      SPARKTLSCrypto.P384.Point.P384_Mulgen (PK_Enc, HC.P384_Local_SK);
      SPARKTLSCrypto.P384.Point.P384_ECDHE
        (Secret  => SS,
         OK      => SS_OK,
         SK      => HC.P384_Local_SK,
         Peer_PK => HC.P384_Peer_PK);
      if not SS_OK then
         return;
      end if;
      HC.Shared_Secret := SS;
      --  group(2) + key_len(2) + key(97) = 101
      KS_Raw (0) := 0; KS_Raw (1) := 16#18#;
      KS_Raw (2) := 0; KS_Raw (3) := 97;
      for I in N32 range 0 .. 96 loop
         KS_Raw (4 + I) := PK_Enc (I);
      end loop;
      KS_Raw_Len := 101;
      OK := True;
   end Generate_KS_P384;

   --  Append one ServerHello extension to an open extensions sequence.
   --  Allocates a temp buffer, initializes an SH_Extension_TLS context,
   --  fills tag + data, appends to Exts_Ctx, frees.
   --
   --  Tag must be one of the enum values RFLX's SH_Extension_TLS
   --  Field_Condition for F_Tag accepts (RFC 8446 §4.2 extension
   --  types valid in ServerHello).
   procedure Append_SH_Extension
     (Exts_Ctx : in out RFLX.TLS_Handshake.SH_Extensions_TLS.Context;
      Tag      : in     RFLX.Tls_Extensiontype_Values
                          .TLS_ExtensionType_Values_Enum;
      Data     : in     Byte_Seq)
   with Pre  => Data'First = 0
                --  Practical extension bound: KS_Raw is 101 B (P-384),
                --  SV is 2 B; ALPN+SNI in EE are small. Cap at 200 B.
                and Data'Last in 0 .. 199
                and Tag in
                      RFLX.Tls_Extensiontype_Values.Key_Share
                    | RFLX.Tls_Extensiontype_Values.Supported_Versions
                    | RFLX.Tls_Extensiontype_Values.Pre_Shared_Key
                    | RFLX.Tls_Extensiontype_Values.Password_Salt
                    | RFLX.Tls_Extensiontype_Values
                        .Tls_Cert_With_Extern_Psk
                and RFLX.TLS_Handshake.SH_Extensions_TLS.Has_Buffer
                      (Exts_Ctx)
                and RFLX.TLS_Handshake.SH_Extensions_TLS.Valid (Exts_Ctx)
                and RFLX.TLS_Handshake.SH_Extensions_TLS.Available_Space
                      (Exts_Ctx)
                    >= RBT.Bit_Length (8) *
                       (RBT.Bit_Length (4) +
                        RBT.Bit_Length (Data'Length)),
        Post => RFLX.TLS_Handshake.SH_Extensions_TLS.Has_Buffer
                  (Exts_Ctx)
                and RFLX.TLS_Handshake.SH_Extensions_TLS.Valid (Exts_Ctx)
                and Exts_Ctx.Buffer_First = Exts_Ctx.Buffer_First'Old
                and Exts_Ctx.Buffer_Last  = Exts_Ctx.Buffer_Last'Old
                and Exts_Ctx.First        = Exts_Ctx.First'Old
                and Exts_Ctx.Last         = Exts_Ctx.Last'Old
                and RFLX.TLS_Handshake.SH_Extensions_TLS.Available_Space
                      (Exts_Ctx)
                    = RFLX.TLS_Handshake.SH_Extensions_TLS.Available_Space
                        (Exts_Ctx)'Old
                      - RBT.Bit_Length (8) *
                        (RBT.Bit_Length (4) +
                         RBT.Bit_Length (Data'Length));
   --  Element size of one SH_Extension_TLS message:
   --    Tag(16) + Data_Length(16) + Data(8*Data'Length) bits
   --    = 8 * (4 + Data'Length) bits.

   procedure Append_SH_Extension
     (Exts_Ctx : in out RFLX.TLS_Handshake.SH_Extensions_TLS.Context;
      Tag      : in     RFLX.Tls_Extensiontype_Values
                          .TLS_ExtensionType_Values_Enum;
      Data     : in     Byte_Seq)
   is
      Data_Len : constant N32 := N32 (Data'Length);
      Ext_Buf  : RBT.Bytes_Ptr;
      Ext_Ctx  : RFLX.TLS_Handshake.SH_Extension_TLS.Context;
   begin
      Ext_Buf := new RBT.Bytes'(1 .. RBT.Index (4 + Data_Len) => 0);
      RFLX.TLS_Handshake.SH_Extension_TLS.Initialize (Ext_Ctx, Ext_Buf);
      RFLX.TLS_Handshake.SH_Extension_TLS.Set_Tag (Ext_Ctx, Tag);
      RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data_Length
        (Ext_Ctx, RFLX.TLS_Handshake.Data_Length (Data_Len));
      RFLX.TLS_Handshake.SH_Extension_TLS.Set_Data
        (Ext_Ctx, To_RFLX (Data));
      RFLX.TLS_Handshake.SH_Extensions_TLS.Append_Element
        (Exts_Ctx, Ext_Ctx);
      RFLX.TLS_Handshake.SH_Extension_TLS.Take_Buffer (Ext_Ctx, Ext_Buf);
      RFLX_Free (Ext_Buf);
   end Append_SH_Extension;

   procedure Build_Server_Hello
     (S      : in     Session;
      HC     : in out Handshake_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   is
      use RFLX.TLS_Handshake.Server_Hello;
      use RFLX.TLS_Common;
      use type RFLX.RFLX_Builtin_Types.Bit_Length;

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
      KS_Raw     : KS_Raw_Buffer;
      KS_Raw_Len : N32;

      KS_Data_Len : N32;
      Ext_Total   : N32;
      SH_Body_Len : N32;
      SH_Msg_Len  : N32;

      Buf      : RBT.Bytes_Ptr;
      Ctx      : Context;
   begin
      Result := (others => 0);
      Len    := 0;

      --  Generate server random (use temp to avoid SPARK aliasing).
      --  RFC 8446 §4.1.3: regenerate on the astronomical collision with
      --  the HRR sentinel; RFLX's Field_Condition for F_Extensions_TLS
      --  requires Random /= HRR_Sentinel.
      declare
         Tmp_SR : Bytes_32;
      begin
         loop
            Gen_Random (Byte_Seq (Tmp_SR));
            exit when Tmp_SR /= HRR_Sentinel;
         end loop;
         pragma Assert (Tmp_SR /= HRR_Sentinel);
         HC.Server_Random := Tmp_SR;
      end;

      --  Select key exchange group (prefer x25519 > P-256 > P-384).
      --  RFC 8446 §4.2.8: the selected_group MUST come from a group
      --  the client offered. Each branch below conditions on the
      --  matching Client_Has_* flag so the per-branch pragma Assert
      --  proves the cross-reference.
      HC.Shared_Secret := (others => 0);
      if HC.Client_Has_X25519 then
         HC.Selected_Group := 16#001D#;
         pragma Assert (Selected_Group_Was_Offered_RFC_8446_4_2_8 (HC));
         declare
            X25_OK : Boolean;
         begin
            Generate_KS_X25519 (HC, KS_Raw, KS_Raw_Len, X25_OK);
            if not X25_OK then
               --  RFC 7748 §6.1: peer sent a small-order point.
               --  Set Len = 0; caller sends handshake_failure.
               Len := 0;
               return;
            end if;
         end;
      elsif HC.Client_Has_P256 then
         HC.Selected_Group := 16#0017#;
         pragma Assert (Selected_Group_Was_Offered_RFC_8446_4_2_8 (HC));
         declare
            P256_OK : Boolean;
         begin
            Generate_KS_P256 (HC, KS_Raw, KS_Raw_Len, P256_OK);
            if not P256_OK then return; end if;
         end;
      elsif HC.Client_Has_P384 then
         HC.Selected_Group := 16#0018#;
         pragma Assert (Selected_Group_Was_Offered_RFC_8446_4_2_8 (HC));
         declare
            P384_OK : Boolean;
         begin
            Generate_KS_P384 (HC, KS_Raw, KS_Raw_Len, P384_OK);
            if not P384_OK then return; end if;
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

      --  Set ServerHello fields via RFLX.
      --  RFC 8446 §4.1.3: legacy_version = 0x0303 even for TLS 1.3.
      --  The real version is in supported_versions extension below.
      pragma Assert (ServerHello_Legacy_Version_RFC_8446_4_1_3 (TLS_1_2));
      Set_Legacy_Version (Ctx, TLS_1_2);
      pragma Assert (Random_Length_RFC_5246_7_4_1_2 (HC.Server_Random));
      Set_Random (Ctx, To_RFLX (HC.Server_Random));
      --  RFC 8446 §4.1.3: echo the client's exact session_id length
      --  and bytes. BoGo Server-ShortSessionID-TLS13 sends a < 32-
      --  byte session_id; we used to always echo 32, which the
      --  runner rejects with "ClientHello and ServerHello session
      --  IDs did not match".
      declare
         Echo_Len : constant N32 :=
            (if HC.Legacy_Session_ID_Len in 0 .. 32
             then HC.Legacy_Session_ID_Len else 0);
      begin
         Set_Legacy_Session_ID_Length
           (Ctx,
            RFLX.TLS_Handshake.Legacy_Session_ID_Length (Echo_Len));
         if Echo_Len > 0 then
            declare
               SID : constant Byte_Seq (0 .. Echo_Len - 1) :=
                  HC.Legacy_Session_ID (0 .. Echo_Len - 1);
            begin
               Set_Legacy_Session_ID (Ctx, To_RFLX (SID));
            end;
         else
            --  RFLX requires the field to be set even when empty.
            declare
               Empty : constant Byte_Seq (1 .. 0) := (others => 0);
            begin
               Set_Legacy_Session_ID (Ctx, To_RFLX (Empty));
            end;
         end if;
      end;
      Set_Cipher_Suite_TLS_Suite (Ctx, To_Suite_Enum (S.Negotiated_Suite));
      --  RFC 8446 §4.1.3: legacy_compression_method MUST be 0.
      --  TLS 1.3 has no compression at all; the field is preserved
      --  for wire-format compatibility with TLS 1.2 parsers.
      pragma Assert (Compression_Method_None_RFC_5246_6_2_2 (0));
      Set_Legacy_Compression_Method (Ctx, 0);

      --  Set_Extensions_Length's Field_Condition is just
      --  Valid (Cursors (F_Legacy_Compression_Method)); make it
      --  explicit so the long Set_* chain doesn't lose precision.
      pragma Assert (Valid (Ctx, F_Legacy_Compression_Method));

      Set_Extensions_Length
        (Ctx, RFLX.TLS_Handshake.Server_Hello_Extensions_Length (Ext_Total));

      --  Switch_To_Extensions_TLS needs Valid_Next (F_Extensions_TLS),
      --  which Set_Extensions_Length's conditional Post gives us
      --  iff (Random /= HRR_Sentinel) and Legacy_Version is a TLS 1.x
      --  version. We set Legacy_Version = TLS_1_2 above, and the HRR
      --  sentinel was rejected at random-generation time, so both
      --  preconditions hold.
      pragma Assert (Valid_Next (Ctx, F_Extensions_TLS));

      --  Build extensions sequence
      declare
         Exts_Ctx : RFLX.TLS_Handshake.SH_Extensions_TLS.Context;
      begin
         Switch_To_Extensions_TLS (Ctx, Exts_Ctx);

         --  Switch_To Post: Seq_Ctx.First/Last = Field_First/Last of
         --  F_Extensions_TLS, Sequence_Last = Seq_Ctx.First - 1.
         --  Field_Size (Ctx, F_Extensions_TLS) = Get_Extensions_Length * 8
         --    = Ext_Total * 8 bits = 8*(4+KS_Raw_Len) + 8*(4+SV_Data_Len).
         --  So Available_Space starts at exactly 8*Ext_Total bits.
         pragma Assert
           (RFLX.TLS_Handshake.SH_Extensions_TLS.Available_Space
              (Exts_Ctx)
            >= RBT.Bit_Length (8) *
               (RBT.Bit_Length (4) + RBT.Bit_Length (KS_Raw_Len)));

         --  Extension 1: key_share (0x0033)
         Append_SH_Extension
           (Exts_Ctx,
            RFLX.Tls_Extensiontype_Values.Key_Share,
            KS_Raw (0 .. KS_Raw_Len - 1));

         --  After 1st append, 8*(4+SV_Data_Len) = 48 bits remain.
         pragma Assert
           (RFLX.TLS_Handshake.SH_Extensions_TLS.Available_Space
              (Exts_Ctx)
            >= RBT.Bit_Length (8) *
               (RBT.Bit_Length (4) + RBT.Bit_Length (SV_Data_Len)));

         --  Extension 2: supported_versions (0x002B)
         declare
            SV_Raw : constant Byte_Seq (0 .. SV_Data_Len - 1) :=
              (16#03#, 16#04#);  --  TLS 1.3
         begin
            --  RFC 8446 §4.2.1: server's selected_version is the
            --  exact 2-byte wire form 0x0304. Pinning the literal
            --  here means a future edit that miscodes the version
            --  (e.g. (3, 3) for TLS 1.2) fails SPARK proof.
            pragma Assert
              (Supported_Versions_Server_TLS13_RFC_8446_4_2_1 (SV_Raw));
            Append_SH_Extension
              (Exts_Ctx,
               RFLX.Tls_Extensiontype_Values.Supported_Versions,
               SV_Raw);
         end;

         --  Update_Extensions_TLS Pre wants Ctx.Buffer_First/Last to
         --  match Exts_Ctx.Buffer_First/Last; Switch_To established
         --  the equality and Append_SH_Extension preserved both sides.
         pragma Assert (Ctx.Buffer_First = Exts_Ctx.Buffer_First);
         pragma Assert (Ctx.Buffer_Last  = Exts_Ctx.Buffer_Last);

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

               --  Patch extensions length. Old_Ext_Len was read from a
               --  2-byte field so it is in 0 .. 65535; bound + PSK_Ext_Len
               --  to keep the high byte in range.
               declare
                  New_Ext_Len : constant N32 := Old_Ext_Len + PSK_Ext_Len;
               begin
                  if New_Ext_Len <= 16#FFFF# then
                     Result (Ext_Len_Offset) :=
                       Byte (New_Ext_Len / 256);
                     Result (Ext_Len_Offset + 1) :=
                       Byte (New_Ext_Len mod 256);
                  end if;
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
               declare
                  use type RFLX.RFLX_Builtin_Types.Bit_Length;
               begin
                  pragma Assert
                    (RFLX.TLS_Handshake.CR_Extension.Size (E_Ctx) > 0);
                  if RFLX.TLS_Handshake.CR_Extensions.Available_Space
                       (Ext_Seq_Ctx)
                     >= RFLX.TLS_Handshake.CR_Extension.Size (E_Ctx)
                  then
                     RFLX.TLS_Handshake.CR_Extensions.Append_Element
                       (Ext_Seq_Ctx, E_Ctx);
                  end if;
               end;
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
