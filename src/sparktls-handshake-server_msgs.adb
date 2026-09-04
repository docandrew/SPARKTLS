with Ada.Unchecked_Deallocation;
with Interfaces;           use Interfaces;
with SPARKTLS.RFLX_Bridge; use SPARKTLS.RFLX_Bridge;
with RFLX.TLS_Handshake.Client_Hello;
with RFLX.TLS_Handshake.CH_Extensions_TLS;
with RFLX.TLS_Handshake.CH_Extension_TLS;
with RFLX.TLS_Handshake.Cipher_Suites_TLS;
with RFLX.TLS_Handshake.Cipher_Suite_TLS;
with RFLX.Tls_Parameters;
with RFLX.Tls_Extensiontype_Values;
with RFLX.RFLX_Types;

package body SPARKTLS.Handshake.Server_Msgs
  with SPARK_Mode => On
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

   function Compression_Methods_OK (Data : Byte_Seq; Is_TLS13 : Boolean) return Boolean
   with Pre => Data'Length > 0 and then Data'Last <= N32 (Max_HS_Msg) - 1
   is
      BS, P                     : N32;
      Sid_Len, Cs_Len, Cm_Len   : N32;
      First_Method, Last_Method : N32;
      Has_Null                  : Boolean := False;
   begin
      --  Data includes the 4-byte handshake header.
      if Data'Length < 4 + 35 then
         return False;
      end if;

      BS := Data'First + 4;
      if BS + 34 > Data'Last then
         return False;
      end if;

      Sid_Len := N32 (Data (BS + 34));
      P := BS + 35;
      if P > Data'Last or else Sid_Len > Data'Last - P + 1 then
         return False;
      end if;
      pragma Assert (P <= Data'Last);
      pragma Assert (Sid_Len <= Data'Last - P + 1);
      pragma Assert (P + Sid_Len <= Data'Last + 1);
      P := P + Sid_Len;

      if P > Data'Last or else Data'Last - P < 1 then
         return False;
      end if;
      Cs_Len := N32 (Data (P)) * 256 + N32 (Data (P + 1));
      P := P + 2;
      if P > Data'Last or else Cs_Len > Data'Last - P + 1 then
         return False;
      end if;
      pragma Assert (P <= Data'Last);
      pragma Assert (Cs_Len <= Data'Last - P + 1);
      pragma Assert (P + Cs_Len <= Data'Last + 1);
      P := P + Cs_Len;

      if P > Data'Last then
         return False;
      end if;
      Cm_Len := N32 (Data (P));
      if Cm_Len = 0 then
         return False;
      end if;

      First_Method := P + 1;
      if First_Method > Data'Last or else Cm_Len > Data'Last - First_Method + 1 then
         return False;
      end if;
      pragma Assert (First_Method <= Data'Last);
      pragma Assert (Cm_Len <= Data'Last - First_Method + 1);
      pragma Assert (First_Method + Cm_Len - 1 <= Data'Last);
      Last_Method := First_Method + Cm_Len - 1;

      if Is_TLS13 then
         return Cm_Len = 1 and then Data (First_Method) = 0;
      end if;

      for I in N32 range First_Method .. Last_Method loop
         if Data (I) = 0 then
            Has_Null := True;
         end if;
      end loop;
      return Has_Null;
   end Compression_Methods_OK;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr)
   with Post => Buf = null;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr) with SPARK_Mode => Off is
      procedure Dealloc is new
        Ada.Unchecked_Deallocation (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
   begin
      Dealloc (Buf);
   end RFLX_Free;

   ----------------------------------------------------------------------------
   --  Per-extension helpers extracted from Parse_Client_Hello
   --  to keep each piece small enough for SPARK to discharge.
   --
   --  The caller (Parse_Client_Hello's extensions loop) owns the
   --  outer CH_Extension_TLS context (Ext_Ctx); each helper consumes
   --  its data via Get_Data / Get_Data_Length.
   ----------------------------------------------------------------------------

   procedure Parse_KS_Data (Data : in Byte_Seq; HC : in out Handshake_Context)
   with
     Pre => Data'First = 0 and then Data'Last in 0 .. 16_383,
     Post =>
       HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then Local_Config_Valid (HC.Cfg.Local'Old)
                 then Local_Config_Valid (HC.Cfg.Local));

   procedure Copy_X25519_KS
     (Data : in Byte_Seq; Pos : in N32; Peer_PK : out Bytes_32; Present : out Boolean)
   with
     Pre => Data'First = 0 and then Pos <= N32'Last - 35 and then Pos + 35 <= Data'Last,
     Post => Present;

   procedure Copy_X25519_KS
     (Data : in Byte_Seq; Pos : in N32; Peer_PK : out Bytes_32; Present : out Boolean) is
   begin
      for I in N32 range 0 .. 31 loop
         Peer_PK (I) := Data (Pos + 4 + I);
      end loop;
      Present := True;
   end Copy_X25519_KS;

   procedure Copy_P256_KS
     (Data : in Byte_Seq; Pos : in N32; Peer_PK : out P256_Peer_Key; Present : out Boolean)
   with
     Pre => Data'First = 0 and then Pos <= N32'Last - 68 and then Pos + 68 <= Data'Last,
     Post => Present;

   procedure Copy_P256_KS
     (Data : in Byte_Seq; Pos : in N32; Peer_PK : out P256_Peer_Key; Present : out Boolean) is
   begin
      for I in N32 range 0 .. 64 loop
         Peer_PK (I) := Data (Pos + 4 + I);
      end loop;
      Present := True;
   end Copy_P256_KS;

   procedure Copy_P384_KS
     (Data : in Byte_Seq; Pos : in N32; Peer_PK : out P384_Peer_Key; Present : out Boolean)
   with
     Pre => Data'First = 0 and then Pos <= N32'Last - 100 and then Pos + 100 <= Data'Last,
     Post => Present;

   procedure Copy_P384_KS
     (Data : in Byte_Seq; Pos : in N32; Peer_PK : out P384_Peer_Key; Present : out Boolean) is
   begin
      for I in N32 range 0 .. 96 loop
         Peer_PK (I) := Data (Pos + 4 + I);
      end loop;
      Present := True;
   end Copy_P384_KS;

   procedure Parse_KS_Data (Data : in Byte_Seq; HC : in out Handshake_Context) is
   begin
      if Data'Length < 2 then
         return;
      end if;

      declare
         DLen       : constant N32 := N32 (Data'Length);
         LL         : constant N32 := N32 (Data (0)) * 256 + N32 (Data (1));
         Pos        : N32 := 2;
         Bad        : Boolean := False;
         Iter_Count : N32 := 0;
         Cap        : constant N32 := HC.Cfg.DoS_Caps.Max_Key_Shares;
      begin
         if 2 + LL /= DLen then
            HC.Ext_Parse_Err := Decode_Error;
            return;
         end if;

         while not Bad and then Pos < DLen and then Iter_Count < Cap loop
            pragma Loop_Invariant (Pos >= 2 and then Pos <= DLen);
            pragma Loop_Invariant (Iter_Count <= Cap);
            pragma Loop_Invariant (HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Loop_Entry);
            pragma Loop_Invariant (if HC.Cfg.Local'Loop_Entry /= null then HC.Cfg.Local /= null);
            pragma
              Loop_Invariant
                (if HC.Cfg.Local'Loop_Entry /= null
                     and then Local_Config_Valid (HC.Cfg.Local'Loop_Entry)
                   then Local_Config_Valid (HC.Cfg.Local));

            pragma Loop_Variant (Increases => Pos);
            if Pos + 4 > DLen then
               Bad := True;
            else
               declare
                  Group : constant Unsigned_16 :=
                    Unsigned_16 (Data (Pos)) * 256 + Unsigned_16 (Data (Pos + 1));
                  KL    : constant N32 := N32 (Data (Pos + 2)) * 256 + N32 (Data (Pos + 3));
               begin
                  if Pos + 4 + KL > DLen then
                     Bad := True;
                  elsif Group = 16#001D# then
                     if HC.Client_Has_X25519 then
                        HC.Ext_Parse_Err := Illegal_Parameter;
                        return;
                     end if;
                     if KL /= 32 then
                        HC.Ext_Parse_Err := Illegal_Parameter;
                        return;
                     end if;
                     pragma Assert (Pos + 35 <= Data'Last);
                     Copy_X25519_KS (Data, Pos, HC.KE.Peer_PK, HC.Client_Has_X25519);
                     Pos := Pos + 4 + KL;
                  elsif Group = 16#0017# then
                     if HC.Client_Has_P256 then
                        HC.Ext_Parse_Err := Illegal_Parameter;
                        return;
                     end if;
                     if KL /= 65 then
                        HC.Ext_Parse_Err := Illegal_Parameter;
                        return;
                     end if;
                     pragma Assert (Pos + 68 <= Data'Last);
                     Copy_P256_KS (Data, Pos, HC.KE.P256_PK, HC.Client_Has_P256);
                     Pos := Pos + 4 + KL;
                  elsif Group = 16#0018# then
                     if HC.Client_Has_P384 then
                        HC.Ext_Parse_Err := Illegal_Parameter;
                        return;
                     end if;
                     if KL /= 97 then
                        HC.Ext_Parse_Err := Illegal_Parameter;
                        return;
                     end if;
                     pragma Assert (Pos + 100 <= Data'Last);
                     Copy_P384_KS (Data, Pos, HC.KE.P384_PK, HC.Client_Has_P384);
                     Pos := Pos + 4 + KL;
                  else
                     Pos := Pos + 4 + KL;
                  end if;
               end;
            end if;
            Iter_Count := Iter_Count + 1;
         end loop;

         if Bad or else Pos /= DLen then
            HC.Ext_Parse_Err := Decode_Error;
         end if;
      end;
   end Parse_KS_Data;

   --  Parse the key_share extension data (CH variant). The layout is
   --  KeyShareClientHello: client_shares<0..2^16-1>, where each entry is
   --  group(2) + key_exchange_len(2) + key_exchange.
   procedure Parse_KS_Extension
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in Wire_Key_Share_Len;
      HC      : in out Handshake_Context)
   with
     Pre =>
       RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx)
                = RFLX.TLS_Handshake.Data_Length (DLen),
     Post =>
       True
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null);

   procedure Parse_KS_Extension
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in Wire_Key_Share_Len;
      HC      : in out Handshake_Context)
   is
      KS_Buf  : RBT.Bytes (1 .. RBT.Index (DLen));
      KS_Data : Byte_Seq (0 .. DLen - 1);
   begin
      RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, KS_Buf);
      KS_Data := To_NaCl (KS_Buf);
      Parse_KS_Data (KS_Data, HC);
   end Parse_KS_Extension;

   --  Parse the signature_algorithms extension data: a 2-byte list_len
   --  followed by 2-byte algorithm codes. We only store algorithms we
   --  support (Peer_Sig_Algos array is fixed-size). On structural error
   --  (list_len mismatch, odd, or zero), OK is set to False and the
   --  outer parser aborts with Decode_Error.
   procedure Parse_Sig_Algs_Extension
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in Wire_Ext_Len;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   with
     Pre =>
       DLen
       >= 4
          --  RFLX Data_Length is 16-bit; Wire_Ext_Len allows larger
          --  reassembled values, but the Get_Data_Length read at the
          --  call site is always within Data_Length's range.
       and then DLen <= N32 (RFLX.TLS_Handshake.Data_Length'Last)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx)
                = RFLX.TLS_Handshake.Data_Length (DLen),
     Post =>
       True
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null);

   procedure Parse_Sig_Algs_Extension
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in Wire_Ext_Len;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   is
      SA_Buf   : RBT.Bytes_Ptr := new RBT.Bytes'(1 .. RBT.Index (DLen) => 0);
      Pos      : RBT.Index := 3;
      List_Len : N32;
   begin
      OK := True;
      RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, SA_Buf.all);
      List_Len := N32 (SA_Buf (1)) * 256 + N32 (SA_Buf (2));
      if List_Len /= DLen - 2 or else List_Len mod 2 /= 0 or else List_Len = 0 then
         RFLX_Free (SA_Buf);
         OK := False;
         return;
      end if;
      declare
         Iter_Count : N32 := 0;
         Cap        : constant N32 := HC.Cfg.DoS_Caps.Max_Sig_Algs_Wire;
      begin
         while Pos + 1 <= RBT.Index (DLen) and then Iter_Count < Cap loop
            declare
               Algo : constant Maybe_Sig_Scheme :=
                 Scheme_From_Wire
                   (Unsigned_16 (SA_Buf (Pos)) * 256 + Unsigned_16 (SA_Buf (Pos + 1)));
            begin
               --  Unknown or SHA-1 schemes map to Scheme_None and are
               --  dropped here; the stored list holds only schemes we
               --  can actually negotiate.
               if Algo /= Scheme_None and then HC.Peer_Sig_Algo_Count < Max_Sig_Algos then
                  HC.Peer_Sig_Algos (HC.Peer_Sig_Algo_Count) := Algo;
                  HC.Peer_Sig_Algo_Count := HC.Peer_Sig_Algo_Count + 1;
               end if;
            end;
            Pos := Pos + 2;
            Iter_Count := Iter_Count + 1;
         end loop;
      end;
      --  Iteration cap: any entries past DoS_Caps.Max_Sig_Algs_Wire
      --  are silently dropped (the cap is well above any legitimate
      --  client; default 64 vs typical 6-15).
      RFLX_Free (SA_Buf);
   end Parse_Sig_Algs_Extension;

   --  Parse the supported_groups extension data: 2-byte list_len
   --  followed by 2-byte group codes. Sets the matching
   --  HC.Client_Supports_* flag for x25519/P-256/P-384.
   procedure Parse_Supported_Groups_Extension
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in Wire_Small_Ext_Len;
      HC      : in out Handshake_Context)
   with
     Pre =>
       DLen >= 4
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx)
                = RFLX.TLS_Handshake.Data_Length (DLen),
     Post =>
       True
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null);

   procedure Parse_Supported_Groups_Extension
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in Wire_Small_Ext_Len;
      HC      : in out Handshake_Context)
   is
      SG_Buf   : RBT.Bytes_Ptr := new RBT.Bytes'(1 .. RBT.Index (DLen) => 0);
      List_Len : N32;
      Pos      : N32;
   begin
      RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, SG_Buf.all);
      List_Len := N32 (SG_Buf (1)) * 256 + N32 (SG_Buf (2));
      Pos := 3;
      declare
         Iter_Count : N32 := 0;
         Cap        : constant N32 := HC.Cfg.DoS_Caps.Max_Supported_Groups;
      begin
         while Pos + 1 <= N32 (DLen) and then Pos < 3 + List_Len and then Iter_Count < Cap loop
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
            Iter_Count := Iter_Count + 1;
         end loop;
      end;
      --  DoS_Caps.Max_Supported_Groups bounds the walk; entries past
      --  the cap are silently dropped.
      RFLX_Free (SG_Buf);
   end Parse_Supported_Groups_Extension;

   --  Parse the supported_versions extension data (CH variant):
   --  1-byte list_len followed by 2-byte version codes. Sets
   --  HC.Has_TLS_1_3 if 0x0304 appears.
   procedure Parse_Supported_Versions_Extension
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in Wire_Small_Ext_Len;
      HC      : in out Handshake_Context)
   with
     Pre =>
       DLen >= 3
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx)
                = RFLX.TLS_Handshake.Data_Length (DLen),
     Post => True and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old;

   procedure Parse_Supported_Versions_Data (Data : in Byte_Seq; HC : in out Handshake_Context)
   with
     Pre => Data'First = 0 and then Data'Last in 2 .. 511,
     Post =>
       HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                 then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity)
       and then (if Local_Config_Valid (HC.Cfg.Local'Old) then Local_Config_Valid (HC.Cfg.Local));

   procedure Parse_Supported_Versions_Data (Data : in Byte_Seq; HC : in out Handshake_Context) is
      List_Len : constant N32 := N32 (Data (0));

      procedure Check_At (Off : N32)
      with
        Pre =>
          Data'First = 0
          and then Data'Last >= 2
          and then Off <= Data'Last - 1
          and then Off < 1 + List_Len,
        Post =>
          HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
          and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
          and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
          and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                    then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity)
          and then (if Local_Config_Valid (HC.Cfg.Local'Old) then Local_Config_Valid (HC.Cfg.Local));

      procedure Check_At (Off : N32) is
      begin
         if N32 (Data (Off)) = 3 and then N32 (Data (Off + 1)) = 4 then
            HC.Has_TLS_1_3 := True;
            HC.SV_Has_Acceptable := True;
         elsif N32 (Data (Off)) = 3 and then N32 (Data (Off + 1)) = 3 then
            HC.SV_Has_Acceptable := True;
         end if;
      end Check_At;
   begin
      HC.Saw_Supported_Versions := True;

      if 2 <= Data'Last and then 1 < 1 + List_Len then
         Check_At (1);
      end if;
      if 4 <= Data'Last and then 3 < 1 + List_Len then
         Check_At (3);
      end if;
      if 6 <= Data'Last and then 5 < 1 + List_Len then
         Check_At (5);
      end if;
      if 8 <= Data'Last and then 7 < 1 + List_Len then
         Check_At (7);
      end if;
      if 10 <= Data'Last and then 9 < 1 + List_Len then
         Check_At (9);
      end if;
      if 12 <= Data'Last and then 11 < 1 + List_Len then
         Check_At (11);
      end if;
      if 14 <= Data'Last and then 13 < 1 + List_Len then
         Check_At (13);
      end if;
      if 16 <= Data'Last and then 15 < 1 + List_Len then
         Check_At (15);
      end if;
   end Parse_Supported_Versions_Data;

   procedure Parse_Supported_Versions_Extension
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in Wire_Small_Ext_Len;
      HC      : in out Handshake_Context)
   is
      SV_Buf  : RBT.Bytes (1 .. RBT.Index (DLen));
      SV_Data : Byte_Seq (0 .. DLen - 1);
   begin
      RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, SV_Buf);
      SV_Data := To_NaCl (SV_Buf);
      Parse_Supported_Versions_Data (SV_Data, HC);
   end Parse_Supported_Versions_Extension;

   --  Parse the ALPN extension data: 2-byte list_len followed by
   --  pascal-style protocol strings (1-byte length + bytes). Stores
   --  the FIRST protocol in HC.Client_ALPN. RFC 7301 3.1: each
   --  protocol_name MUST have length >= 1; an empty entry anywhere
   --  in the list is a fatal protocol violation. Sets OK=False and
   --  HC.Last_ALPN_Error so the caller can surface illegal_parameter.
   procedure Parse_ALPN_Extension
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in Wire_Small_Ext_Len;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   with
     Pre =>
       DLen >= 4
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx)
                = RFLX.TLS_Handshake.Data_Length (DLen),
     Post =>
       HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                 then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity)
       and then (if Local_Config_Valid (HC.Cfg.Local'Old) then Local_Config_Valid (HC.Cfg.Local));

   procedure Parse_ALPN_Data (Data : in Byte_Seq; HC : in out Handshake_Context; OK : out Boolean)
   with
     Pre => Data'First = 0 and then Data'Last in 3 .. 511,
     Post =>
       HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                 then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity)
       and then (if Local_Config_Valid (HC.Cfg.Local'Old) then Local_Config_Valid (HC.Cfg.Local));

   procedure Copy_ALPN_Name
     (Data : in Byte_Seq;
      P    : in N32;
      PL   : in N32;
      HC   : in out Handshake_Context;
      Slot : in ALPN_Index)
   with
     Pre =>
       Data'First = 0
       and then PL in 1 .. N32 (Max_Hostname_Len)
       and then P <= N32'Last - PL
       and then P + PL <= Data'Last
       and then Slot <= Max_Config_ALPN_Protocols,
     Post =>
       HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                 then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity)
       and then (if Local_Config_Valid (HC.Cfg.Local'Old) then Local_Config_Valid (HC.Cfg.Local));

   procedure Copy_ALPN_Name
     (Data : in Byte_Seq;
      P    : in N32;
      PL   : in N32;
      HC   : in out Handshake_Context;
      Slot : in ALPN_Index) is
   begin
      HC.Client_ALPN_List (Slot).Len := Natural (PL);
      for I in 1 .. Natural (PL) loop
         pragma Loop_Invariant (HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Loop_Entry);
         HC.Client_ALPN_List (Slot).Data (I) := Character'Val (Data (P + N32 (I)));
      end loop;
      if Slot = 1 then
         HC.Client_ALPN := HC.Client_ALPN_List (Slot);
      end if;
   end Copy_ALPN_Name;

   procedure Parse_ALPN_Data (Data : in Byte_Seq; HC : in out Handshake_Context; OK : out Boolean)
   is
      DLen       : constant N32 := N32 (Data'Length);
      List_Len   : constant N32 := N32 (Data (0)) * 256 + N32 (Data (1));
      P          : N32 := 2;
      Iter_Count : N32 := 0;
      Cap        : constant N32 := HC.Cfg.DoS_Caps.Max_ALPN_Protocols;
   begin
      OK := True;
      HC.Client_ALPN_Count := 0;
      HC.Client_ALPN.Len := 0;
      if List_Len = 0 or else DLen /= 2 + List_Len then
         OK := False;
         return;
      end if;

      while P <= 1 + List_Len and then Iter_Count < Cap loop
         pragma Loop_Invariant (P >= 2 and then P <= DLen);
         pragma Loop_Invariant (Iter_Count <= Cap);
         pragma Loop_Invariant (HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Loop_Entry);
         pragma Loop_Invariant (if HC.Cfg.Local'Loop_Entry /= null then HC.Cfg.Local /= null);
         pragma
           Loop_Invariant
             (if HC.Cfg.Local'Loop_Entry /= null and then HC.Cfg.Local'Loop_Entry.Has_Identity
                then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity);
         pragma
           Loop_Invariant
             (if Local_Config_Valid (HC.Cfg.Local'Loop_Entry)
                then Local_Config_Valid (HC.Cfg.Local));

         pragma Loop_Variant (Increases => P);
         declare
            PL : constant N32 := N32 (Data (P));
         begin
            if PL = 0 then
               OK := False;
               return;
            end if;
            if P + PL > 1 + List_Len then
               OK := False;
               return;
            end if;
            if PL <= N32 (Max_Hostname_Len)
              and then HC.Client_ALPN_Count < Max_Config_ALPN_Protocols
            then
               HC.Client_ALPN_Count := HC.Client_ALPN_Count + 1;
               pragma Assert (P + PL <= Data'Last);
               Copy_ALPN_Name (Data, P, PL, HC, ALPN_Index (HC.Client_ALPN_Count));
            end if;
            P := P + 1 + PL;
         end;
         Iter_Count := Iter_Count + 1;
      end loop;
   end Parse_ALPN_Data;

   procedure Parse_ALPN_Extension
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in Wire_Small_Ext_Len;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   is
      AB        : RBT.Bytes (1 .. RBT.Index (DLen));
      ALPN_Data : Byte_Seq (0 .. DLen - 1);
   begin
      RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, AB);
      ALPN_Data := To_NaCl (AB);
      Parse_ALPN_Data (ALPN_Data, HC, OK);
   end Parse_ALPN_Extension;

   --  Parse the pre_shared_key extension data:
   --    identities_len(2) || identity { len(2) || ticket || age(4) }+
   --    || binders_len(2) || binder { len(1) || binder_bytes }+
   --  Stores the FIRST identity's ticket ID (if length matches), the
   --  first binder, and the binders-list offset. Tolerates malformed
   --  data: any structural error just skips, leaving HC unchanged.
   subtype Wire_PSK_Ext_Len is N32 range 6 .. 1024;
   subtype PSK_Ext_Index is N32 range 0 .. 1024;
   subtype PSK_Entry_Count is N32 range 0 .. 17;
   type PSK_Binder_Status is (PSK_Binders_OK, PSK_Binders_Decode_Error, PSK_Binders_Verify_Error);
   type PSK_Identity_Status is (PSK_Identity_OK, PSK_Identity_Ignore, PSK_Identity_Decode_Error);

   procedure Count_PSK_Identities
     (Ext_Data    : in Byte_Seq;
      IDs_End     : in PSK_Ext_Index;
      Ident_Count : out PSK_Entry_Count;
      OK          : out Boolean)
   with
     Pre =>
       Ext_Data'First = 0
       and then Ext_Data'Last in 5 .. 1023
       and then IDs_End in 2 .. Ext_Data'Last + 1;

   procedure Count_PSK_Identities
     (Ext_Data    : in Byte_Seq;
      IDs_End     : in PSK_Ext_Index;
      Ident_Count : out PSK_Entry_Count;
      OK          : out Boolean)
   is
      Q : PSK_Ext_Index := 2;  --  past identities_len field
   begin
      Ident_Count := 0;
      OK := True;

      for Entry_No in PSK_Entry_Count range 1 .. 17 loop
         pragma Loop_Invariant (Q <= IDs_End);
         pragma Loop_Invariant (Ident_Count <= 17);
         declare
            IDs_Rem : constant PSK_Ext_Index := IDs_End - Q;
         begin
            exit when IDs_Rem < 2;
            pragma Assert (IDs_Rem >= 2);
            pragma Assert (Q + 1 < IDs_End);
            pragma Assert (Q + 1 <= Ext_Data'Last);
            declare
               TL : constant N32 := N32 (Ext_Data (Q)) * 256 + N32 (Ext_Data (Q + 1));
            begin
               if IDs_Rem < 6 or else TL > IDs_Rem - 6 then
                  OK := False;
                  return;
               end if;
               pragma Assert (TL + 6 <= IDs_Rem);
               pragma Assert (Q + TL + 6 <= IDs_End);
               Ident_Count := Entry_No;
               Q := Q + TL + 6;
            end;
         end;
      end loop;
   end Count_PSK_Identities;

   procedure Parse_First_PSK_Identity
     (Ext_Data : in Byte_Seq;
      IDs_End  : out PSK_Ext_Index;
      Ticket   : out Ticket_ID;
      Status   : out PSK_Identity_Status)
   with
     Pre => Ext_Data'First = 0 and then Ext_Data'Last in 5 .. 1023,
     Post => (if Status = PSK_Identity_OK then IDs_End in 2 .. Ext_Data'Last + 1);

   procedure Parse_First_PSK_Identity
     (Ext_Data : in Byte_Seq;
      IDs_End  : out PSK_Ext_Index;
      Ticket   : out Ticket_ID;
      Status   : out PSK_Identity_Status)
   is
      DLen    : constant PSK_Ext_Index := Ext_Data'Last + 1;
      IDs_Len : constant N32 := N32 (Ext_Data (0)) * 256 + N32 (Ext_Data (1));
      P       : constant PSK_Ext_Index := 2;
   begin
      IDs_End := 0;
      Ticket := (others => 0);
      Status := PSK_Identity_Ignore;

      if IDs_Len = 0 then
         return;
      end if;

      if IDs_Len > DLen - 2 then
         Status := PSK_Identity_Decode_Error;
         return;
      end if;

      IDs_End := 2 + IDs_Len;
      pragma Assert (IDs_End <= DLen);
      declare
         IDs_Rem  : constant PSK_Ext_Index := IDs_End - P;
         Tick_Len : constant N32 := N32 (Ext_Data (P)) * 256 + N32 (Ext_Data (P + 1));
      begin
         if IDs_Rem < 6
           or else Tick_Len = 0
           or else Tick_Len > N32 (Ticket_ID_Len)
           or else Tick_Len > IDs_Rem - 6
         then
            return;
         end if;

         pragma Assert (Tick_Len in 1 .. N32 (Ticket_ID_Len));
         pragma Assert (P + 2 + Tick_Len <= Ext_Data'Last);
         for I in N32 range 0 .. Tick_Len - 1 loop
            pragma Loop_Invariant (I < Tick_Len);
            pragma Loop_Invariant (P + 2 + I <= Ext_Data'Last);
            Ticket (I) := Ext_Data (P + 2 + I);
         end loop;
         Status := PSK_Identity_OK;
      end;
   end Parse_First_PSK_Identity;

   procedure Parse_PSK_Binders
     (Ext_Data      : in Byte_Seq;
      Binders_Start : in PSK_Ext_Index;
      HC            : in out Handshake_Context;
      Binder_Count  : out PSK_Entry_Count;
      OK            : out Boolean)
   with
     Pre =>
       Ext_Data'First = 0
       and then Ext_Data'Last in 5 .. 1023
       and then Binders_Start in 2 .. Ext_Data'Last + 1,
     Post =>
       (if OK then Binder_Count > 0 and then HC.PSK.Binder_Len in 32 | 48)
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null and then Local_Config_Valid (HC.Cfg.Local'Old)
                 then HC.Cfg.Local /= null and then Local_Config_Valid (HC.Cfg.Local));

   procedure Store_PSK_Binder
     (Ext_Data : in Byte_Seq; BP : in PSK_Ext_Index; BL : in N32; Binder : in out Bytes_48)
   with
     Pre =>
       Ext_Data'First = 0
       and then Ext_Data'Last in 5 .. 1023
       and then BP <= Ext_Data'Last
       and then BL in 32 | 48
       and then BP <= Ext_Data'Last - BL;

   procedure Store_PSK_Binder
     (Ext_Data : in Byte_Seq; BP : in PSK_Ext_Index; BL : in N32; Binder : in out Bytes_48) is
   begin
      for I in N32 range 0 .. BL - 1 loop
         pragma Loop_Invariant (I < BL);
         pragma Loop_Invariant (BP + 1 + I <= BP + BL);
         pragma Loop_Invariant (BP + 1 + I <= Ext_Data'Last);
         Binder (I) := Ext_Data (BP + 1 + I);
      end loop;
   end Store_PSK_Binder;

   procedure Scan_PSK_Binders
     (Ext_Data      : in Byte_Seq;
      Binders_Start : in PSK_Ext_Index;
      Binder_Count  : out PSK_Entry_Count;
      First_BP      : out PSK_Ext_Index;
      First_BL      : out N32;
      Status        : out PSK_Binder_Status)
   with
     Pre =>
       Ext_Data'First = 0
       and then Ext_Data'Last in 5 .. 1023
       and then Binders_Start in 2 .. Ext_Data'Last + 1,
     Post =>
       (if Status = PSK_Binders_OK
        then
          Binder_Count > 0
          and then First_BL in 32 | 48
          and then First_BP <= Ext_Data'Last - First_BL);

   procedure Scan_PSK_Binders
     (Ext_Data      : in Byte_Seq;
      Binders_Start : in PSK_Ext_Index;
      Binder_Count  : out PSK_Entry_Count;
      First_BP      : out PSK_Ext_Index;
      First_BL      : out N32;
      Status        : out PSK_Binder_Status)
   is
      DLen : constant PSK_Ext_Index := Ext_Data'Last + 1;
   begin
      Binder_Count := 0;
      First_BP := 0;
      First_BL := 0;
      Status := PSK_Binders_Decode_Error;

      if Binders_Start > DLen - 2 then
         return;
      end if;

      declare
         Binders_Data_Start : constant PSK_Ext_Index := Binders_Start + 2;
         Binders_Len        : constant N32 :=
           N32 (Ext_Data (Binders_Start)) * 256 + N32 (Ext_Data (Binders_Start + 1));
      begin
         if Binders_Len = 0 or else Binders_Len > DLen - Binders_Data_Start then
            return;
         end if;

         declare
            Binders_End : constant PSK_Ext_Index := Binders_Data_Start + Binders_Len;
            BP          : PSK_Ext_Index := Binders_Data_Start;
         begin
            pragma Assert (Binders_End <= DLen);
            for Entry_No in PSK_Entry_Count range 1 .. 17 loop
               pragma Loop_Invariant (BP <= Binders_End);
               pragma Loop_Invariant (Binder_Count <= 17);
               pragma
                 Loop_Invariant
                   (if Binder_Count > 0
                      then First_BL in 32 | 48 and then First_BP <= Ext_Data'Last - First_BL);
               declare
                  B_Rem : constant PSK_Ext_Index := Binders_End - BP;
               begin
                  exit when B_Rem = 0;
                  pragma Assert (BP < Binders_End);
                  pragma Assert (BP < DLen);
                  declare
                     BL : constant N32 := N32 (Ext_Data (BP));
                  begin
                     if BL not in 32 | 48 or else B_Rem < 1 or else BL > B_Rem - 1 then
                        Status := PSK_Binders_Verify_Error;
                        return;
                     end if;

                     pragma Assert (BL + 1 <= B_Rem);
                     pragma Assert (BP + BL + 1 <= Binders_End);
                     pragma Assert (BP + BL < Binders_End);
                     pragma Assert (BP + BL <= Ext_Data'Last);
                     if Binder_Count = 0 then
                        First_BP := BP;
                        First_BL := BL;
                     end if;

                     Binder_Count := Entry_No;
                     BP := BP + BL + 1;
                  end;
               end;
            end loop;

            if Binder_Count = 0 then
               Status := PSK_Binders_Decode_Error;
               return;
            end if;
            Status := PSK_Binders_OK;
         end;
      end;
   end Scan_PSK_Binders;

   procedure Parse_PSK_Binders
     (Ext_Data      : in Byte_Seq;
      Binders_Start : in PSK_Ext_Index;
      HC            : in out Handshake_Context;
      Binder_Count  : out PSK_Entry_Count;
      OK            : out Boolean)
   is
      First_BP : PSK_Ext_Index;
      First_BL : N32;
      Status   : PSK_Binder_Status;
   begin
      Scan_PSK_Binders (Ext_Data, Binders_Start, Binder_Count, First_BP, First_BL, Status);
      case Status is
         when PSK_Binders_OK =>
            Store_PSK_Binder (Ext_Data, First_BP, First_BL, HC.PSK.Binder);
            HC.PSK.Binder_Len := First_BL;
            OK := True;

         when PSK_Binders_Decode_Error =>
            HC.Ext_Parse_Err := Decode_Error;
            OK := False;

         when PSK_Binders_Verify_Error =>
            HC.Ext_Parse_Err := Certificate_Verify_Failed;
            OK := False;
      end case;
   end Parse_PSK_Binders;

   procedure Parse_PSK_Extension
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in Wire_PSK_Ext_Len;
      HC      : in out Handshake_Context)
   with
     Pre =>
       RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx)
                = RFLX.TLS_Handshake.Data_Length (DLen),
     Post => True and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old;

   procedure Parse_PSK_Data (Ext_Data : in Byte_Seq; HC : in out Handshake_Context)
   with
     Pre => Ext_Data'First = 0 and then Ext_Data'Last in 5 .. 1023,
     Post => True and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old;

   procedure Parse_PSK_Identity_Data
     (Ext_Data       : in Byte_Seq;
      HC             : in out Handshake_Context;
      IDs_End        : out PSK_Ext_Index;
      Continue_Parse : out Boolean)
   with
     Pre => Ext_Data'First = 0 and then Ext_Data'Last in 5 .. 1023,
     Post =>
       True
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null and then Local_Config_Valid (HC.Cfg.Local'Old)
                 then HC.Cfg.Local /= null and then Local_Config_Valid (HC.Cfg.Local))
       and then (if Continue_Parse then IDs_End in 2 .. Ext_Data'Last + 1);

   procedure Parse_PSK_Identity_Data
     (Ext_Data       : in Byte_Seq;
      HC             : in out Handshake_Context;
      IDs_End        : out PSK_Ext_Index;
      Continue_Parse : out Boolean)
   is
      Ticket : Ticket_ID;
      Status : PSK_Identity_Status;
   begin
      Parse_First_PSK_Identity (Ext_Data, IDs_End, Ticket, Status);
      case Status is
         when PSK_Identity_OK =>
            pragma Assert (IDs_End in 2 .. Ext_Data'Last + 1);
            HC.PSK.Offer_ID := Ticket;
            HC.PSK.Offered := True;
            Continue_Parse := True;

         when PSK_Identity_Decode_Error =>
            HC.Ext_Parse_Err := Decode_Error;
            Continue_Parse := False;

         when PSK_Identity_Ignore =>
            Continue_Parse := False;
      end case;
   end Parse_PSK_Identity_Data;

   procedure Parse_PSK_Binder_Data
     (Ext_Data : in Byte_Seq; IDs_End : in PSK_Ext_Index; HC : in out Handshake_Context)
   with
     Pre =>
       Ext_Data'First = 0
       and then Ext_Data'Last in 5 .. 1023
       and then IDs_End in 2 .. Ext_Data'Last + 1,
     Post => True and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old;

   procedure Parse_PSK_Binder_Data
     (Ext_Data : in Byte_Seq; IDs_End : in PSK_Ext_Index; HC : in out Handshake_Context)
   is
      Ident_Count  : PSK_Entry_Count;
      Binder_Count : PSK_Entry_Count;
      OK           : Boolean;
      Saved_Legacy : constant N32 := HC.Legacy_Session_ID_Len
      with Ghost;
   begin
      Count_PSK_Identities (Ext_Data, IDs_End, Ident_Count, OK);
      if not OK then
         HC.Ext_Parse_Err := Decode_Error;
         pragma Assert (HC.Legacy_Session_ID_Len = Saved_Legacy);
         return;
      end if;

      Parse_PSK_Binders (Ext_Data, IDs_End, HC, Binder_Count, OK);
      if not OK then
         pragma Assert (HC.Legacy_Session_ID_Len = Saved_Legacy);
         return;
      end if;

      if Ident_Count /= Binder_Count then
         HC.Ext_Parse_Err := Illegal_Parameter;
         HC.PSK.Binder_Len := 0;
         pragma Assert (HC.Legacy_Session_ID_Len = Saved_Legacy);
         return;
      end if;
      pragma Assert (HC.Legacy_Session_ID_Len = Saved_Legacy);
   end Parse_PSK_Binder_Data;

   procedure Parse_PSK_Data (Ext_Data : in Byte_Seq; HC : in out Handshake_Context) is
      IDs_End        : PSK_Ext_Index;
      Continue_Parse : Boolean;
   begin
      Parse_PSK_Identity_Data (Ext_Data, HC, IDs_End, Continue_Parse);
      if not Continue_Parse then
         return;
      end if;

      Parse_PSK_Binder_Data (Ext_Data, IDs_End, HC);
   end Parse_PSK_Data;

   procedure Parse_PSK_Extension
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      DLen    : in Wire_PSK_Ext_Len;
      HC      : in out Handshake_Context)
   is
      ED       : RBT.Bytes (1 .. RBT.Index (DLen));
      Ext_Data : Byte_Seq (0 .. DLen - 1);
   begin
      RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, ED);
      Ext_Data := To_NaCl (ED);
      Parse_PSK_Data (Ext_Data, HC);
   end Parse_PSK_Extension;

   --  Apply one parsed cipher suite to the session's negotiation state:
   --  pick the best TLS 1.3 suite (preferring ChaCha20) and the first
   --  TLS 1.2 ECDHE suite we recognize.
   function TLS12_Cipher_Group (Cfg : Config; Val : Unsigned_16) return Natural is
   begin
      if Cfg.TLS12_Cipher_Count = 0 then
         return 1;
      end if;

      for I in Cipher_Pref_Index loop
         exit when I > Cfg.TLS12_Cipher_Count;

         if Cfg.TLS12_Cipher_List (I) = Val then
            return Cfg.TLS12_Cipher_Groups (I);
         end if;
      end loop;

      return 0;
   end TLS12_Cipher_Group;

   function Prefer_TLS12_Candidate
     (Cfg : Config; Current : Unsigned_16; Candidate : Unsigned_16) return Boolean
   is
      Candidate_Group : constant Natural := TLS12_Cipher_Group (Cfg, Candidate);
   begin
      if Candidate_Group = 0 then
         return False;
      end if;

      if Current = 0 then
         return True;
      end if;

      if Cfg.TLS12_Cipher_Count = 0 then
         return False;
      end if;

      declare
         Current_Group : constant Natural := TLS12_Cipher_Group (Cfg, Current);
      begin
         return Current_Group = 0 or else Candidate_Group < Current_Group;
      end;
   end Prefer_TLS12_Candidate;

   procedure Apply_Raw_Cipher_Suite
     (Val           : in Unsigned_16;
      Negotiated    : in out Supported_Suite;
      Negotiated_12 : in out Supported_Suite;
      Last_Err      : in out Error_Code;
      HC            : in out Handshake_Context)
   with
     Post =>
       HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                 then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity)
       and then (if Local_Config_Valid (HC.Cfg.Local'Old) then Local_Config_Valid (HC.Cfg.Local));

   procedure Apply_Raw_Cipher_Suite
     (Val           : in Unsigned_16;
      Negotiated    : in out Supported_Suite;
      Negotiated_12 : in out Supported_Suite;
      Last_Err      : in out Error_Code;
      HC            : in out Handshake_Context)
   is
      Cert_Is_ECDSA : constant Boolean :=
        HC.Cfg.Local.Has_Identity
        and then HC.Cfg.Local.Sign_Algo in Sign_ECDSA_P256 | Sign_ECDSA_P384 | Sign_Ed25519;

      Cert_Is_RSA   : constant Boolean :=
        HC.Cfg.Local.Has_Identity
        and then HC.Cfg.Local.Sign_Algo = Sign_RSA_PSS;
   begin
      if Val = 16#00FF# then
         HC.Saw_Reneg_Info := True;
         return;
      end if;

      if Val in
           Wire_Suite_AES_256_GCM_SHA384
           | Wire_Suite_AES_128_GCM_SHA256
           | Wire_Suite_CHACHA20_POLY1305_SHA256
      then
         if Negotiated = Suite_None then
            Negotiated := To_Suite (Val);
         elsif Val = Wire_Suite_CHACHA20_POLY1305_SHA256 then
            Negotiated := To_Suite (Val);
         end if;
      end if;

      if Cert_Is_ECDSA
        and then Val in
                   Wire_Suite_ECDHE_ECDSA_AES128_GCM_SHA256
                   | Wire_Suite_ECDHE_ECDSA_AES256_GCM_SHA384
                   | Wire_Suite_ECDHE_ECDSA_CHACHA20_SHA256
        and then Prefer_TLS12_Candidate (HC.Cfg, Wire_Of (Negotiated_12), Val)
      then
         Negotiated_12 := To_Suite (Val);
      end if;

      if Cert_Is_RSA
        and then Val in
                   Wire_Suite_ECDHE_RSA_AES128_GCM_SHA256
                   | Wire_Suite_ECDHE_RSA_AES256_GCM_SHA384
                   | Wire_Suite_ECDHE_RSA_CHACHA20_SHA256
        and then Prefer_TLS12_Candidate (HC.Cfg, Wire_Of (Negotiated_12), Val)
      then
         Negotiated_12 := To_Suite (Val);
      end if;
   end Apply_Raw_Cipher_Suite;

   procedure Apply_Cipher_Suite
     (Suite_Ctx     : in RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
      Negotiated    : in out Supported_Suite;
      Negotiated_12 : in out Supported_Suite;
      Last_Err      : in out Error_Code;
      HC            : in out Handshake_Context)
   with
     Pre =>
       RFLX.TLS_Handshake.Cipher_Suite_TLS.Has_Buffer (Suite_Ctx)
       and then RFLX.TLS_Handshake.Cipher_Suite_TLS.Well_Formed_Message (Suite_Ctx),
     Post =>
       True
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                 then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity)
       and then (if Local_Config_Valid (HC.Cfg.Local'Old) then Local_Config_Valid (HC.Cfg.Local));

   procedure Apply_Cipher_Suite
     (Suite_Ctx     : in RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
      Negotiated    : in out Supported_Suite;
      Negotiated_12 : in out Supported_Suite;
      Last_Err      : in out Error_Code;
      HC            : in out Handshake_Context)
   is
      Suite      : constant RFLX.Tls_Parameters.TLS_Cipher_Suites :=
        RFLX.TLS_Handshake.Cipher_Suite_TLS.Get_Suite (Suite_Ctx);
      --  TLS_Cipher_Suites_Enum has Size=>16; Raw is 16-bit wire value.
      --  Both branches fit in Unsigned_16  guard with Valid predicate
      --  to make it explicit for the prover.
      Suite_Code : constant RFLX.RFLX_Types.Base_Integer :=
        RFLX.Tls_Parameters.To_Base_Integer (Suite);
      Val        : Unsigned_16;
   begin
      --  RFC 5746 3.6: TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF)
      --  is a *signaling* cipher suite value, not a real suite, so
      --  RFLX's TLS_Cipher_Suites enum (which only models negotiable
      --  suites) rejects it via Valid_TLS_Cipher_Suites  we detect
      --  it ourselves before falling through.
      --  Suite_Code is RFLX Base_Integer; guard the Unsigned_16
      --  conversion so SPARK can discharge the range check below.
      declare
         use type RFLX.RFLX_Types.Base_Integer;
         Hi : constant RFLX.RFLX_Types.Base_Integer := 16#FFFF#;
      begin
         if Suite_Code > Hi then
            return;
         end if;
      end;
      if Unsigned_16 (Suite_Code) = 16#00FF# then
         HC.Saw_Reneg_Info := True;
         return;
      end if;
      if not RFLX.Tls_Parameters.Valid_TLS_Cipher_Suites (Suite_Code) then
         return;
      end if;
      Val := Unsigned_16 (Suite_Code);
      Apply_Raw_Cipher_Suite (Val, Negotiated, Negotiated_12, Last_Err, HC);
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
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   with
     Pre =>
       RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then No_Duplicate_Extensions_RFC_8446_4_2 (HC),
     Post => True and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old;

   procedure Dispatch_CH_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   with
     Pre =>
       Tag.Known
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then DLen <= N32 (RFLX.TLS_Handshake.Data_Length'Last)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx)
                = RFLX.TLS_Handshake.Data_Length (DLen)
       and then No_Duplicate_Extensions_RFC_8446_4_2 (HC),
     Post => True and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old;

   procedure Dispatch_CH_Negotiation_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   with
     Pre =>
       Tag.Known
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then DLen <= N32 (RFLX.TLS_Handshake.Data_Length'Last)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx)
                = RFLX.TLS_Handshake.Data_Length (DLen)
       and then No_Duplicate_Extensions_RFC_8446_4_2 (HC),
     Post => True and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old;

   procedure Dispatch_CH_State_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   with
     Pre =>
       Tag.Known
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then DLen <= N32 (RFLX.TLS_Handshake.Data_Length'Last)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx)
                = RFLX.TLS_Handshake.Data_Length (DLen)
       and then No_Duplicate_Extensions_RFC_8446_4_2 (HC),
     Post => True and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old;

   procedure Dispatch_CH_State_Simple_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   with
     Pre =>
       Tag.Known
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then DLen <= N32 (RFLX.TLS_Handshake.Data_Length'Last)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx)
                = RFLX.TLS_Handshake.Data_Length (DLen)
       and then No_Duplicate_Extensions_RFC_8446_4_2 (HC),
     Post => True and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old;

   procedure Dispatch_CH_State_Validation_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   with
     Pre =>
       Tag.Known
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then DLen <= N32 (RFLX.TLS_Handshake.Data_Length'Last)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx)
                = RFLX.TLS_Handshake.Data_Length (DLen)
       and then No_Duplicate_Extensions_RFC_8446_4_2 (HC),
     Post =>
       True
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null and then Local_Config_Valid (HC.Cfg.Local'Old)
                 then HC.Cfg.Local /= null and then Local_Config_Valid (HC.Cfg.Local));

   procedure Dispatch_CH_State_Flag_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   with
     Pre =>
       Tag.Known
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then DLen <= N32 (RFLX.TLS_Handshake.Data_Length'Last)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx)
                = RFLX.TLS_Handshake.Data_Length (DLen)
       and then No_Duplicate_Extensions_RFC_8446_4_2 (HC),
     Post =>
       True
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null);

   procedure Dispatch_CH_State_Data_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   with
     Pre =>
       Tag.Known
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
       and then DLen <= N32 (RFLX.TLS_Handshake.Data_Length'Last)
       and then RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx)
                = RFLX.TLS_Handshake.Data_Length (DLen)
       and then No_Duplicate_Extensions_RFC_8446_4_2 (HC),
     Post =>
       True
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null and then Local_Config_Valid (HC.Cfg.Local'Old)
                 then HC.Cfg.Local /= null and then Local_Config_Valid (HC.Cfg.Local));

   procedure Register_CH_Extension
     (Code : in Unsigned_32; HC : in out Handshake_Context; OK : out Boolean)
   with
     Pre => No_Duplicate_Extensions_RFC_8446_4_2 (HC),
     Post =>
       True
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null and then Local_Config_Valid (HC.Cfg.Local'Old)
                 then HC.Cfg.Local /= null and then Local_Config_Valid (HC.Cfg.Local));

   procedure Register_CH_Extension
     (Code : in Unsigned_32; HC : in out Handshake_Context; OK : out Boolean) is
   begin
      OK := True;
      --  RFC 8446 4.2: duplicate extension types in CH MUST be
      --  rejected. BoGo's DuplicateExtension test exercises this.
      pragma Assert (No_Duplicate_Extensions_RFC_8446_4_2 (HC));
      for I in 1 .. HC.Seen_Ext_Count loop
         pragma Loop_Invariant (No_Duplicate_Extensions_RFC_8446_4_2 (HC));
         pragma Loop_Invariant (HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Loop_Entry);
         pragma
           Loop_Invariant
             (if HC.Cfg.Local'Loop_Entry /= null
                  and then Local_Config_Valid (HC.Cfg.Local'Loop_Entry)
                then HC.Cfg.Local /= null and then Local_Config_Valid (HC.Cfg.Local));
         if HC.Seen_Ext_Tags (I) = Code then
            OK := False;
            return;
         end if;
      end loop;
      if HC.Seen_Ext_Count < HC.Seen_Ext_Tags'Last then
         HC.Seen_Ext_Count := HC.Seen_Ext_Count + 1;
         HC.Seen_Ext_Tags (HC.Seen_Ext_Count) := Code;
      end if;
      pragma Assert (No_Duplicate_Extensions_RFC_8446_4_2 (HC));

      --  Record extension order fingerprint (rolling polynomial hash).
      --  Skip cookie (0x002C)  it's added after HRR.
      if Code /= 16#002C# then
         HC.CH_Ext_Hash := HC.CH_Ext_Hash * 31 xor Code;
         --  Saturating increment: the loop bound (max ~16K extensions
         --  in a 64K extensions field) is far below Natural'Last but
         --  the prover doesn't see that without an invariant.
         if HC.CH_Ext_Count < Natural'Last then
            HC.CH_Ext_Count := HC.CH_Ext_Count + 1;
         end if;
      end if;
   end Register_CH_Extension;

   procedure Parse_Server_Name_Data
     (Ext_Data : in Byte_Seq; HC : in out Handshake_Context; OK : out Boolean)
   with
     Pre => Ext_Data'First = 0 and then Ext_Data'Last in 1 .. 1023,
     Post =>
       True
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null and then Local_Config_Valid (HC.Cfg.Local'Old)
                 then HC.Cfg.Local /= null and then Local_Config_Valid (HC.Cfg.Local));

   procedure Copy_Server_Name
     (Ext_Data : in Byte_Seq; P : in N32; Name_Len : in N32; HC : in out Handshake_Context)
   with
     Pre =>
       Ext_Data'First = 0
       and then Ext_Data'Last in 1 .. 1023
       and then P <= Ext_Data'Last - 3
       and then Name_Len in 1 .. N32 (Max_Hostname_Len)
       and then Name_Len <= Ext_Data'Last - (P + 2),
     Post =>
       True
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then (if HC.Cfg.Local'Old /= null and then Local_Config_Valid (HC.Cfg.Local'Old)
                 then HC.Cfg.Local /= null and then Local_Config_Valid (HC.Cfg.Local));

   procedure Copy_Server_Name
     (Ext_Data : in Byte_Seq; P : in N32; Name_Len : in N32; HC : in out Handshake_Context) is
   begin
      HC.Peer_SNI.Len := Natural (Name_Len);
      for I in N32 range 0 .. Name_Len - 1 loop
         pragma Loop_Invariant (I < Name_Len);
         pragma Loop_Invariant (P + 3 + I <= Ext_Data'Last);
         pragma Loop_Invariant (HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Loop_Entry);
         HC.Peer_SNI.Data (HC.Peer_SNI.Data'First + Natural (I)) :=
           Character'Val (Natural (Ext_Data (P + 3 + I)));
      end loop;
   end Copy_Server_Name;

   procedure Parse_Server_Name_Data
     (Ext_Data : in Byte_Seq; HC : in out Handshake_Context; OK : out Boolean)
   is
      DLen     : constant N32 := Ext_Data'Last + 1;
      List_Len : constant N32 := N32 (Ext_Data (0)) * 256 + N32 (Ext_Data (1));
      P        : N32 := 2;
   begin
      OK := True;
      --  Outer list length must consume exactly the extension body past
      --  the 2-byte length field.
      if 2 + List_Len /= DLen then
         OK := False;
         return;
      end if;

      --  Walk entries: name_type(1) + host_name length(2) + host_name.
      while P + 3 <= DLen loop
         pragma Loop_Invariant (P >= 2 and then P <= DLen);
         pragma Loop_Invariant (HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Loop_Entry);
         pragma
           Loop_Invariant
             (if HC.Cfg.Local'Loop_Entry /= null
                  and then Local_Config_Valid (HC.Cfg.Local'Loop_Entry)
                then HC.Cfg.Local /= null and then Local_Config_Valid (HC.Cfg.Local));
         pragma Loop_Variant (Increases => P);
         declare
            Name_Type : constant Byte := Ext_Data (P);
            Name_Len  : constant N32 := N32 (Ext_Data (P + 1)) * 256 + N32 (Ext_Data (P + 2));
         begin
            if P + 3 + Name_Len > DLen then
               OK := False;
               return;
            end if;

            --  RFC 6066 3: HostName = 0. Record only the first one.
            if Name_Type = 0
              and then HC.Peer_SNI.Len = 0
              and then Name_Len > 0
              and then Name_Len <= N32 (Max_Hostname_Len)
            then
               pragma Assert (P + 3 <= Ext_Data'Last);
               Copy_Server_Name (Ext_Data, P, Name_Len, HC);
            end if;
            P := P + 3 + Name_Len;
         end;
      end loop;

      if P /= DLen then
         OK := False;
      end if;
   end Parse_Server_Name_Data;

   procedure Parse_Cert_Compression_Data (Ext_Data : in Byte_Seq; OK : out Boolean)
   with Pre => Ext_Data'First = 0 and then Ext_Data'Last in 0 .. 511;

   procedure Parse_EC_Point_Formats_Data (Ext_Data : in Byte_Seq; OK : out Boolean)
   with Pre => Ext_Data'First = 0 and then Ext_Data'Last in 1 .. 131071;

   procedure Parse_EC_Point_Formats_Data (Ext_Data : in Byte_Seq; OK : out Boolean) is
      DLen     : constant N32 := Ext_Data'Last + 1;
      List_Len : constant N32 := N32 (Ext_Data (0));
   begin
      OK := True;
      if List_Len > 0 and then List_Len <= DLen - 1 then
         if not EC_Point_Formats_Acceptable (Ext_Data (1 .. List_Len)) then
            OK := False;
         end if;
      end if;
   end Parse_EC_Point_Formats_Data;

   procedure Parse_Cert_Compression_Data (Ext_Data : in Byte_Seq; OK : out Boolean) is
      DLen     : constant N32 := Ext_Data'Last + 1;
      Algs_Len : constant N32 := N32 (Ext_Data (0));
   begin
      OK := True;
      if 1 + Algs_Len /= DLen or else Algs_Len = 0 or else Algs_Len mod 2 /= 0 then
         OK := False;
         return;
      end if;

      declare
         N_Algs   : constant N32 := Algs_Len / 2;
         subtype Seen_Range is N32 range 1 .. 64;
         Seen     : array (Seen_Range) of N32 := (others => 0);
         Seen_Cnt : N32 := 0;
      begin
         for I in N32 range 0 .. N_Algs - 1 loop
            pragma Loop_Invariant (Seen_Cnt <= 64);
            declare
               Off : constant N32 := 1 + I * 2;
               Alg : constant N32 := N32 (Ext_Data (Off)) * 256 + N32 (Ext_Data (Off + 1));
            begin
               for J in N32 range 1 .. Seen_Cnt loop
                  pragma Loop_Invariant (Seen_Cnt <= 64);
                  if Seen (J) = Alg then
                     OK := False;
                     return;
                  end if;
               end loop;
               if Seen_Cnt < 64 then
                  Seen_Cnt := Seen_Cnt + 1;
                  Seen (Seen_Cnt) := Alg;
               end if;
            end;
         end loop;
      end;
   end Parse_Cert_Compression_Data;

   procedure Parse_Certificate_Authorities_Data (Ext_Data : in Byte_Seq; OK : out Boolean)
   with Pre => Ext_Data'First = 0 and then Ext_Data'Last in 1 .. 131071;

   procedure Parse_Certificate_Authorities_Data (Ext_Data : in Byte_Seq; OK : out Boolean) is
      DLen     : constant N32 := Ext_Data'Last + 1;
      List_Len : constant N32 := N32 (Ext_Data (0)) * 256 + N32 (Ext_Data (1));
      P        : N32 := 2;
      Bad      : Boolean := False;
   begin
      OK := True;
      if 2 + List_Len /= DLen or List_Len = 0 then
         Bad := True;
      else
         while not Bad and then P < DLen loop
            pragma Loop_Invariant (P >= 2 and then P <= DLen);
            pragma Loop_Variant (Increases => P);
            if P + 2 > DLen then
               Bad := True;
            else
               declare
                  DN_Len : constant N32 := N32 (Ext_Data (P)) * 256 + N32 (Ext_Data (P + 1));
               begin
                  if P + 2 + DN_Len > DLen or DN_Len = 0 then
                     Bad := True;
                  else
                     P := P + 2 + DN_Len;
                  end if;
               end;
            end if;
         end loop;
      end if;

      if Bad then
         OK := False;
      end if;
   end Parse_Certificate_Authorities_Data;

   procedure Store_TLS12_Ticket_Data
     (Ext_Data   : in Byte_Seq;
      Ticket     : in out TLS12_Ticket_Buffer;
      Ticket_Len : out TLS12_Ticket_Length)
   with
     Pre => Ext_Data'First = 0 and then Ext_Data'Last in 0 .. Max_TLS12_Ticket_Len - 1,
     Post => Ticket_Len = Ext_Data'Last + 1;

   procedure Store_TLS12_Ticket_Data
     (Ext_Data   : in Byte_Seq;
      Ticket     : in out TLS12_Ticket_Buffer;
      Ticket_Len : out TLS12_Ticket_Length)
   is
      DLen : constant N32 := Ext_Data'Last + 1;
   begin
      for I in N32 range 0 .. DLen - 1 loop
         Ticket (I) := Ext_Data (I);
      end loop;
      Ticket_Len := DLen;
   end Store_TLS12_Ticket_Data;

   procedure Parse_PSK_Key_Exchange_Modes_Data
     (Ext_Data : in Byte_Seq; Has_PSK_DHE_KE : in out Boolean)
   with Pre => Ext_Data'First = 0 and then Ext_Data'Last in 1 .. 131071;

   procedure Parse_PSK_Key_Exchange_Modes_Data
     (Ext_Data : in Byte_Seq; Has_PSK_DHE_KE : in out Boolean)
   is
      DLen     : constant N32 := Ext_Data'Last + 1;
      List_Len : constant N32 := N32 (Ext_Data (0));
   begin
      if List_Len > 0 and then List_Len <= DLen - 1 then
         for I in N32 range 0 .. List_Len - 1 loop
            pragma Loop_Invariant (I < List_Len);
            pragma Loop_Invariant (1 + I <= Ext_Data'Last);
            if N32 (Ext_Data (1 + I)) = 16#01# then
               Has_PSK_DHE_KE := True;
            end if;
         end loop;
      end if;
   end Parse_PSK_Key_Exchange_Modes_Data;

   procedure Apply_CH_Extension
     (Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   is
      Tag  : constant RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values :=
        RFLX.TLS_Handshake.CH_Extension_TLS.Get_Tag (Ext_Ctx);
      DLen : constant N32 := N32 (RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data_Length (Ext_Ctx));
   begin
      declare
         Code : constant Unsigned_32 :=
           Unsigned_32 (RFLX.Tls_Extensiontype_Values.To_Base_Integer (Tag));
      begin
         Register_CH_Extension (Code, HC, OK);
         if not OK then
            return;
         end if;
      end;

      if not Tag.Known then
         return;
      end if;

      Dispatch_CH_Extension (Tag, DLen, Ext_Ctx, HC, OK);
   end Apply_CH_Extension;

   procedure Dispatch_CH_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean) is
   begin
      case Tag.Enum is
         when RFLX.Tls_Extensiontype_Values.Key_Share =>
            Dispatch_CH_Negotiation_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when RFLX.Tls_Extensiontype_Values.Signature_Algorithms =>
            Dispatch_CH_Negotiation_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when RFLX.Tls_Extensiontype_Values.Supported_Groups =>
            Dispatch_CH_Negotiation_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when RFLX.Tls_Extensiontype_Values.Pre_Shared_Key =>
            Dispatch_CH_Negotiation_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when RFLX.Tls_Extensiontype_Values.Supported_Versions =>
            Dispatch_CH_Negotiation_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when RFLX.Tls_Extensiontype_Values.Application_Layer_Protocol_Negotiation =>
            Dispatch_CH_Negotiation_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when others =>
            Dispatch_CH_State_Extension (Tag, DLen, Ext_Ctx, HC, OK);
      end case;
   end Dispatch_CH_Extension;

   procedure Dispatch_CH_Negotiation_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean) is
   begin
      OK := True;
      case Tag.Enum is
         when RFLX.Tls_Extensiontype_Values.Key_Share =>
            HC.Client_Saw_Key_Share := True;
            if DLen in Wire_Key_Share_Len then
               Parse_KS_Extension (Ext_Ctx, DLen, HC);
               --  Parse_KS_Extension â Apply_KS_Entry stashes
               --  Illegal_Parameter in HC.Ext_Parse_Err on duplicate-
               --  group violations (RFC 8446 4.2.8). Surface to the
               --  Parse_Client_Hello caller as a parse failure.
               if HC.Ext_Parse_Err /= No_Error then
                  OK := False;
                  return;
               end if;
            end if;

         when RFLX.Tls_Extensiontype_Values.Signature_Algorithms =>
            if DLen not in Wire_Ext_Len
              or else DLen < 4
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
            HC.Client_Saw_Supported_Groups := True;
            if DLen in Wire_Small_Ext_Len and then DLen >= 4 then
               Parse_Supported_Groups_Extension (Ext_Ctx, DLen, HC);
            end if;

         when RFLX.Tls_Extensiontype_Values.Pre_Shared_Key =>
            if DLen in Wire_PSK_Ext_Len then
               Parse_PSK_Extension (Ext_Ctx, DLen, HC);
               --  RFC 8446 4.2.11: PSK shape errors (missing
               --  binders, identity/binder count mismatch,
               --  wrong-length binder) are surfaced via
               --  HC.Ext_Parse_Err so the CH parser aborts with
               --  the right alert. BoGo Resume-Server-NoPSKBinder
               --  / -BinderWrongLength / -ExtraIdentityNoBinder.
               if HC.Ext_Parse_Err /= No_Error then
                  OK := False;
                  return;
               end if;
            end if;

         when RFLX.Tls_Extensiontype_Values.Supported_Versions =>
            if DLen in Wire_Small_Ext_Len and then DLen >= 3 then
               Parse_Supported_Versions_Extension (Ext_Ctx, DLen, HC);
            end if;

         when RFLX.Tls_Extensiontype_Values.Application_Layer_Protocol_Negotiation =>
            if DLen in Wire_Small_Ext_Len and then DLen >= 4 then
               declare
                  ALPN_OK : Boolean;
               begin
                  Parse_ALPN_Extension (Ext_Ctx, DLen, HC, ALPN_OK);
                  if not ALPN_OK then
                     --  RFC 7301 3.1: malformed protocol_name_list
                     --  (empty entry, truncated, list_len mismatch).
                     --  Stash for Parse_Client_Hello to surface.
                     HC.Ext_Parse_Err := Illegal_Parameter;
                     OK := False;
                     return;
                  end if;
               end;
            end if;

         when others =>
            null;
      end case;
   end Dispatch_CH_Negotiation_Extension;

   procedure Dispatch_CH_State_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean) is
   begin
      case Tag.Enum is
         when RFLX.Tls_Extensiontype_Values.Renegotiation_Info =>
            Dispatch_CH_State_Simple_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when RFLX.Tls_Extensiontype_Values.Session_Ticket =>
            Dispatch_CH_State_Simple_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when RFLX.Tls_Extensiontype_Values.Early_Data =>
            Dispatch_CH_State_Simple_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when RFLX.Tls_Extensiontype_Values.Psk_Key_Exchange_Modes =>
            Dispatch_CH_State_Simple_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when RFLX.Tls_Extensiontype_Values.Extended_Master_Secret =>
            Dispatch_CH_State_Simple_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when others =>
            Dispatch_CH_State_Validation_Extension (Tag, DLen, Ext_Ctx, HC, OK);
      end case;
   end Dispatch_CH_State_Extension;

   procedure Dispatch_CH_State_Simple_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean) is
   begin
      case Tag.Enum is
         when RFLX.Tls_Extensiontype_Values.Renegotiation_Info =>
            Dispatch_CH_State_Flag_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when RFLX.Tls_Extensiontype_Values.Early_Data =>
            Dispatch_CH_State_Flag_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when RFLX.Tls_Extensiontype_Values.Extended_Master_Secret =>
            Dispatch_CH_State_Flag_Extension (Tag, DLen, Ext_Ctx, HC, OK);

         when others =>
            Dispatch_CH_State_Data_Extension (Tag, DLen, Ext_Ctx, HC, OK);
      end case;
   end Dispatch_CH_State_Simple_Extension;

   procedure Dispatch_CH_State_Flag_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean)
   is
      pragma Unreferenced (Ext_Ctx);
   begin
      OK := True;
      case Tag.Enum is
         when RFLX.Tls_Extensiontype_Values.Renegotiation_Info =>
            --  RFC 5746: client offered the renegotiation_info
            --  extension. We echo it in ServerHello only when this
            --  flag (or the SCSV signal) is set.
            HC.Saw_Reneg_Info := True;

         when RFLX.Tls_Extensiontype_Values.Early_Data =>
            --  RFC 8446 4.2.10: presence (empty body) in CH means
            --  the client wants to send 0-RTT data. Server decides
            --  acceptance later (Build_Server_Flight) when the PSK
            --  resume + DHE_KE + ticket-most-recent conditions are
            --  evaluated; here we just record the offer.
            if DLen = 0 then
               HC.Early_Data_Offered := True;
            end if;

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

         when others =>
            null;
      end case;
   end Dispatch_CH_State_Flag_Extension;

   procedure Dispatch_CH_State_Data_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean) is
   begin
      OK := True;
      case Tag.Enum is
         when RFLX.Tls_Extensiontype_Values.Session_Ticket =>
            --  RFC 5077 3.2: session_ticket extension (TLS 1.2 only;
            --  obsoleted by TLS 1.3's PSK mechanism). Two shapes:
            --    * Empty (DLen=0): client supports tickets, wants the
            --      server to issue one in a later NewSessionTicket.
            --    * Non-empty: client is presenting a previously-issued
            --      ticket and offering resumption.
            --  Stash the bytes for the post-CH resume-decision logic
            --  in Build_Server_Flight_12 (server) to evaluate.
            HC.T12.Ticket_Offered := True;
            HC.T12.Peer_Ticket_Len := 0;
            if DLen > 0 and then DLen <= Max_TLS12_Ticket_Len then
               declare
                  ED       : RBT.Bytes (1 .. RBT.Index (DLen));
                  Ext_Data : Byte_Seq (0 .. DLen - 1);
               begin
                  RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, ED);
                  Ext_Data := To_NaCl (ED);
                  Store_TLS12_Ticket_Data (Ext_Data, HC.T12.Peer_Ticket, HC.T12.Peer_Ticket_Len);
               end;
            end if;

         when RFLX.Tls_Extensiontype_Values.Psk_Key_Exchange_Modes =>
            --  RFC 8446 4.2.9: body is list_len(1) + N modes(1 each).
            --  psk_dhe_ke = 0x01 is the only mode we support; presence
            --  is required before we may issue a NewSessionTicket on
            --  this connection (BoGo TLS13-ExpectNoSessionTicketOn
            --  BadKEMode-Server).
            if DLen >= 2 then
               declare
                  ED       : RBT.Bytes (1 .. RBT.Index (DLen));
                  Ext_Data : Byte_Seq (0 .. DLen - 1);
               begin
                  RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, ED);
                  Ext_Data := To_NaCl (ED);
                  Parse_PSK_Key_Exchange_Modes_Data (Ext_Data, HC.PSK.Has_DHE_KE);
               end;
            end if;

         when others =>
            null;
      end case;
   end Dispatch_CH_State_Data_Extension;

   procedure Dispatch_CH_State_Validation_Extension
     (Tag     : in RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values;
      DLen    : in N32;
      Ext_Ctx : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC      : in out Handshake_Context;
      OK      : out Boolean) is
   begin
      OK := True;
      case Tag.Enum is
         when RFLX.Tls_Extensiontype_Values.Server_Name =>
            --  RFC 6066 3: server_name body shape =
            --    server_name_list_length(2) +
            --    {name_type(1) + host_name<2..2^16-1>}*
            --  Validate the wire-level length sum so trailing bytes
            --  after the list (BoGo's
            --  ExtensionTrailingData-ServerName-Server) get rejected
            --  with decode_error. We don't actually use the host_name
            --  yet; this is purely a malformed-input gate.
            if DLen >= 2 and then DLen in Wire_Small_Ext_Len then
               declare
                  ED       : RBT.Bytes (1 .. RBT.Index (DLen));
                  Ext_Data : Byte_Seq (0 .. DLen - 1);
               begin
                  RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, ED);
                  Ext_Data := To_NaCl (ED);
                  Parse_Server_Name_Data (Ext_Data, HC, OK);
               end;
            elsif DLen /= 0 then
               --  Non-zero body shorter than minimum framing.
               OK := False;
               return;
            end if;

         when RFLX.Tls_Extensiontype_Values.Ec_Point_Formats =>
            --  RFC 8422 5.1.2: only point format 0 (uncompressed)
            --  may appear in this list  formats 1 and 2 are
            --  deprecated and MUST NOT be supported. We delegate to
            --  EC_Point_Formats_Acceptable, whose Post is formally
            --  proven by SPARK to match the RFC exactly.
            if DLen >= 2 and then DLen in Wire_Small_Ext_Len then
               declare
                  ED       : RBT.Bytes (1 .. RBT.Index (DLen));
                  Ext_Data : Byte_Seq (0 .. DLen - 1);
               begin
                  RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, ED);
                  Ext_Data := To_NaCl (ED);
                  Parse_EC_Point_Formats_Data (Ext_Data, OK);
               end;
            end if;

         when RFLX.Tls_Extensiontype_Values.Compress_Certificate =>
            --  RFC 8879 3 CertificateCompressionAlgorithms body:
            --    algorithms_len(1) + algorithms<algorithms_len>
            --    each algorithm = u16, so algorithms_len must be even
            --    and 2..254. Validate the length AND reject duplicate
            --    algorithm IDs (BoGo DuplicateCertCompressionExt).
            if DLen >= 1 and then DLen in Wire_Small_Ext_Len then
               declare
                  ED       : RBT.Bytes (1 .. RBT.Index (DLen));
                  Ext_Data : Byte_Seq (0 .. DLen - 1);
               begin
                  RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, ED);
                  Ext_Data := To_NaCl (ED);
                  Parse_Cert_Compression_Data (Ext_Data, OK);
                  if not OK then
                     OK := False;
                     return;
                  end if;
               end;
            end if;

         when RFLX.Tls_Extensiontype_Values.Certificate_Authorities =>
            --  RFC 8446 4.2.4 CertificateAuthoritiesExtension body:
            --    authorities_length(2) + DistinguishedName[]
            --    each DN = name_length(2) + DER bytes
            --  Validate that the outer length tiles the body exactly,
            --  each DN consumes its declared length, and the DN list
            --  is non-empty. BoGo ExtensionTrailingData-
            --  CertificateAuthorities-Server + RejectEmpty
            --  CertificateAuthorities-Server.
            if DLen >= 2 and then DLen in Wire_Ext_Len then
               declare
                  ED       : RBT.Bytes (1 .. RBT.Index (DLen));
                  Ext_Data : Byte_Seq (0 .. DLen - 1);
               begin
                  RFLX.TLS_Handshake.CH_Extension_TLS.Get_Data (Ext_Ctx, ED);
                  Ext_Data := To_NaCl (ED);
                  Parse_Certificate_Authorities_Data (Ext_Data, OK);
                  if not OK then
                     OK := False;
                     return;
                  end if;
               end;
            end if;

         when others =>
            null;
      end case;
   end Dispatch_CH_State_Validation_Extension;

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
      OK  : out Boolean)
   with
     Pre =>
       not Ctx'Constrained
       and then RFLX.TLS_Handshake.Client_Hello.Has_Buffer (Ctx)
       and then RFLX.TLS_Handshake.Client_Hello.Well_Formed
                  (Ctx, RFLX.TLS_Handshake.Client_Hello.F_Extensions_TLS)
       and then HC.Legacy_Session_ID_Len in 0 .. 32,
     Post =>
       RFLX.TLS_Handshake.Client_Hello.Has_Buffer (Ctx)
       and then Ctx.Buffer_First = Ctx.Buffer_First'Old
       and then Ctx.Buffer_Last = Ctx.Buffer_Last'Old
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old;

   procedure Process_CH_Extension_Element
     (Ext_Ctx  : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC       : in out Handshake_Context;
      Aborting : in out Boolean;
      Saw_PSK  : in out Boolean)
   with
     Pre =>
       RFLX.TLS_Handshake.CH_Extension_TLS.Has_Buffer (Ext_Ctx)
       and then No_Duplicate_Extensions_RFC_8446_4_2 (HC)
       and then HC.Legacy_Session_ID_Len in 0 .. 32,
     Post =>
       True
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then HC.Legacy_Session_ID_Len in 0 .. 32;

   procedure Process_CH_Extension_Element
     (Ext_Ctx  : in RFLX.TLS_Handshake.CH_Extension_TLS.Context;
      HC       : in out Handshake_Context;
      Aborting : in out Boolean;
      Saw_PSK  : in out Boolean) is
   begin
      if not Aborting and then RFLX.TLS_Handshake.CH_Extension_TLS.Well_Formed_Message (Ext_Ctx)
      then
         --  PSK-must-be-last enforcement BEFORE applying.
         if Saw_PSK then
            HC.Ext_Parse_Err := Illegal_Parameter;
            Aborting := True;
         end if;

         if not Aborting then
            declare
               Sub_OK  : Boolean;
               Tag_Hdr : constant RFLX.Tls_Extensiontype_Values.TLS_ExtensionType_Values :=
                 RFLX.TLS_Handshake.CH_Extension_TLS.Get_Tag (Ext_Ctx);
            begin
               Apply_CH_Extension (Ext_Ctx, HC, Sub_OK);
               if not Sub_OK then
                  Aborting := True;
               end if;
               if Tag_Hdr.Known and then Tag_Hdr.Enum = RFLX.Tls_Extensiontype_Values.Pre_Shared_Key
               then
                  Saw_PSK := True;
               end if;
            end;
         end if;
      end if;
   end Process_CH_Extension_Element;

   procedure Parse_CH_Extensions
     (Ctx : in out RFLX.TLS_Handshake.Client_Hello.Context;
      HC  : in out Handshake_Context;
      OK  : out Boolean)
   is
      use RFLX.TLS_Handshake.Client_Hello;
      Aborting : Boolean := False;
      --  RFC 8446 4.2.11: pre_shared_key MUST be the last
      --  extension in the ClientHello. Track whether we saw it on
      --  a previous iteration; any subsequent extension is an
      --  illegal_parameter.  BoGo Resume-Server-PSKBinderFirst-
      --  Extension exercises this.
      Saw_PSK  : Boolean := False;
   begin
      OK := True;
      if Field_Size (Ctx, F_Extensions_TLS) = 0 then
         return;
      end if;

      declare
         Exts_Ctx : RFLX.TLS_Handshake.CH_Extensions_TLS.Context;
      begin
         Switch_To_Extensions_TLS (Ctx, Exts_Ctx);

         while RFLX.TLS_Handshake.CH_Extensions_TLS.Has_Element (Exts_Ctx) loop
            pragma
              Loop_Invariant
                (RFLX.TLS_Handshake.CH_Extensions_TLS.Has_Buffer (Exts_Ctx)
                   and then RFLX.TLS_Handshake.CH_Extensions_TLS.Valid (Exts_Ctx)
                   and then Ctx.Buffer_First = Exts_Ctx.Buffer_First
                   and then Ctx.Buffer_Last = Exts_Ctx.Buffer_Last
                   and then Valid_Next (Ctx, F_Extensions_TLS)
                   and then Exts_Ctx.First = Field_First (Ctx, F_Extensions_TLS)
                   and then Exts_Ctx.Last = Field_Last (Ctx, F_Extensions_TLS)
                   and then No_Duplicate_Extensions_RFC_8446_4_2 (HC)
                   and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Loop_Entry);
            declare
               Ext_Ctx : RFLX.TLS_Handshake.CH_Extension_TLS.Context;
            begin
               RFLX.TLS_Handshake.CH_Extensions_TLS.Switch (Exts_Ctx, Ext_Ctx);
               RFLX.TLS_Handshake.CH_Extension_TLS.Verify_Message (Ext_Ctx);

               Process_CH_Extension_Element (Ext_Ctx, HC, Aborting, Saw_PSK);
               RFLX.TLS_Handshake.CH_Extensions_TLS.Update (Exts_Ctx, Ext_Ctx);
               pragma Unreferenced (Ext_Ctx);
            end;
         end loop;

         Update_Extensions_TLS (Ctx, Exts_Ctx);
         pragma Unreferenced (Exts_Ctx);
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
     (Ctx           : in out RFLX.TLS_Handshake.Client_Hello.Context;
      Negotiated    : in out Supported_Suite;
      Negotiated_12 : in out Supported_Suite;
      Last_Err      : in out Error_Code;
      HC            : in out Handshake_Context)
   with
     Pre =>
       not Ctx'Constrained
       and then RFLX.TLS_Handshake.Client_Hello.Has_Buffer (Ctx)
       and then RFLX.TLS_Handshake.Client_Hello.Well_Formed
                  (Ctx, RFLX.TLS_Handshake.Client_Hello.F_Cipher_Suites_TLS),
     Post =>
       RFLX.TLS_Handshake.Client_Hello.Has_Buffer (Ctx)
       and Ctx.Buffer_First = Ctx.Buffer_First'Old
       and Ctx.Buffer_Last = Ctx.Buffer_Last'Old
       and HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null);

   procedure Parse_CH_Cipher_Suites
     (Ctx           : in out RFLX.TLS_Handshake.Client_Hello.Context;
      Negotiated    : in out Supported_Suite;
      Negotiated_12 : in out Supported_Suite;
      Last_Err      : in out Error_Code;
      HC            : in out Handshake_Context)
   is
      use RFLX.TLS_Handshake.Client_Hello;
   begin
      if Field_Size (Ctx, F_Cipher_Suites_TLS) = 0 then
         return;
      end if;

      declare
         Suites_Ctx : RFLX.TLS_Handshake.Cipher_Suites_TLS.Context;
         Iter_Count : N32 := 0;
         Cap        : constant N32 := HC.Cfg.DoS_Caps.Max_Cipher_Suites;
      begin
         Switch_To_Cipher_Suites_TLS (Ctx, Suites_Ctx);

         while RFLX.TLS_Handshake.Cipher_Suites_TLS.Has_Element (Suites_Ctx)
           and then Iter_Count < Cap
         loop
            pragma
              Loop_Invariant
                (RFLX.TLS_Handshake.Cipher_Suites_TLS.Has_Buffer (Suites_Ctx)
                   and then RFLX.TLS_Handshake.Cipher_Suites_TLS.Valid (Suites_Ctx)
                   and then Ctx.Buffer_First = Suites_Ctx.Buffer_First
                   and then Ctx.Buffer_Last = Suites_Ctx.Buffer_Last
                   and then Valid_Next (Ctx, F_Cipher_Suites_TLS)
                   and then Suites_Ctx.First = Field_First (Ctx, F_Cipher_Suites_TLS)
                   and then Suites_Ctx.Last = Field_Last (Ctx, F_Cipher_Suites_TLS)
                   and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Loop_Entry
                   and then (if HC.Cfg.Local'Loop_Entry /= null then HC.Cfg.Local /= null));
            declare
               Suite_Ctx : RFLX.TLS_Handshake.Cipher_Suite_TLS.Context;
            begin
               RFLX.TLS_Handshake.Cipher_Suites_TLS.Switch (Suites_Ctx, Suite_Ctx);
               RFLX.TLS_Handshake.Cipher_Suite_TLS.Verify_Message (Suite_Ctx);
               if RFLX.TLS_Handshake.Cipher_Suite_TLS.Well_Formed_Message (Suite_Ctx) then
                  Apply_Cipher_Suite (Suite_Ctx, Negotiated, Negotiated_12, Last_Err, HC);
               end if;
               RFLX.TLS_Handshake.Cipher_Suites_TLS.Update (Suites_Ctx, Suite_Ctx);
            end;
            Iter_Count := Iter_Count + 1;
         end loop;

         --  RFC-defensive cap (DoS_Caps.Max_Cipher_Suites): drop
         --  further entries silently. Client sends suites in priority
         --  order; selecting from the first N still picks the best
         --  mutual suite for any legitimate client.

         Update_Cipher_Suites_TLS (Ctx, Suites_Ctx);
      end;
   end Parse_CH_Cipher_Suites;

   procedure Parse_Client_Hello
     (Negotiated    : in out Supported_Suite;
      Negotiated_12 : in out Supported_Suite;
      Last_Err      : in out Error_Code;
      HC            : in out Handshake_Context;
      Data          : in Byte_Seq;
      Version       : out TLS_Version;
      OK            : out Boolean)
   is
      use RFLX.TLS_Handshake.Client_Hello;

      Body_Len           : N32;
      Buf                : RBT.Bytes_Ptr;
      Ctx                : Context;
      Raw_Legacy_Version : N32 := 0;
   begin
      Version := TLS_Undetermined;
      OK := False;

      if Data'Length < 39 then
         Last_Err := Decode_Error;
         pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
         return;
      end if;

      if Data (Data'First) /= HS_Msg_Wire (HT_Client_Hello) then
         --  RFC 8446 6: a handshake message of an inappropriate
         --  type for the current state must be rejected with
         --  unexpected_message, not decode_error. The message is
         --  structurally well-formed (we read its 4-byte header to
         --  reach this point); the type byte just identifies a
         --  different message that doesn't belong here.
         Last_Err := Unexpected_Message;
         pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
         return;
      end if;

      --  Detect "CH + trailing bytes from a next handshake message in
      --  the same record". The HS header (bytes 1..3 of Data, after
      --  the type byte at 0) declares this message's body length. If
      --  the record fragment carries more than (4 + declared), the
      --  extra bytes are the start of another HS message  and since
      --  the caller invoked us expecting exactly one CH in this
      --  state, that's unexpected_message, not decode_error. BoGo
      --  PartialSecondClientHelloAfterFirst, PartialClientKey
      --  ExchangeWithClientHello.
      declare
         HS_Body_Len : constant N32 :=
           N32 (Data (Data'First + 1)) * 65536 + N32 (Data (Data'First + 2)) * 256
           + N32 (Data (Data'First + 3));
      begin
         if HS_Body_Len + 4 < N32 (Data'Length) then
            Last_Err := Unexpected_Message;
            pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
            return;
         end if;
      end;

      --  Skip 4-byte handshake header, pass body to Client_Hello context
      Body_Len := N32 (Data'Length) - 4;

      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      Buf.all := To_RFLX (Data (Data'First + 4 .. Data'Last));

      if Buf.all'Length >= 2 then
         Raw_Legacy_Version := N32 (Buf.all (1)) * 256 + N32 (Buf.all (2));
      end if;

      --  RFC 8446 4.1.2: legacy_version is now Legacy_Version_Any (any
      --  16-bit value) in the spec, so RecordFlux tolerates the values a
      --  TLS 1.3 client may put here; the real version is decided below
      --  from supported_versions (HC.Has_TLS_1_3) and Raw_Legacy_Version.
      --  Nothing rewrites the parse buffer, so Get_Legacy_Version and the
      --  transcript both see the wire bytes.

      Initialize (Ctx, Buf, Written_Last => RBT.Bit_Length (RBT.Length (Body_Len) * 8));
      Verify_Message (Ctx);

      --  Strict trailing-data check: the parsed CH structure must
      --  consume the entire body. RFC 8446 4.1.2 / RFC 5246 7.4.1.2
      --  do not permit trailing data after the extensions block.
      --  BoGo's `SendTrailingMessageData` test appends a stray byte
      --  inside the handshake length; if RFLX's structural fields
      --  all parse but the byte count exceeds Message_Last, reject
      --  with decode_error rather than silently accepting.
      if Well_Formed_Message (Ctx)
        and then Message_Last (Ctx) /= RBT.Bit_Length (RBT.Length (Body_Len) * 8)
      then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         Last_Err := Decode_Error;
         pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
         return;
      end if;

      if not Well_Formed_Message (Ctx) then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         --  Distinguish failure modes for the right alert:
         --    legacy_version != 0x0303      â protocol_version
         --    legacy_compression_methods    â illegal_parameter
         --       != single 0x00 byte
         --    other                         â decode_error
         --
         --  ClientHello body layout (RFC 8446 4.1.2):
         --    legacy_version(2) | random(32) | session_id_len(1) |
         --    session_id(0..32) | cipher_suites_len(2) |
         --    cipher_suites    | compression_methods_len(1) |
         --    compression_methods(1..255) | extensions...
         if Data'Length >= 6
           and then (Data (Data'First + 4) /= 16#03# or Data (Data'First + 5) /= 16#03#)
         then
            Last_Err := Protocol_Version;
         else
            --  Walk to legacy_compression_methods to check it's
            --  exactly the single byte 0x00. RFC 8446 4.1.2 +
            --  6.2.1: any other compression list is illegal_parameter.
            declare
               BS                      : constant N32 := Data'First + 4;  --  past HS hdr
               P                       : N32;
               OK                      : Boolean := False;
               Sid_Len, Cs_Len, Cm_Len : N32;
            begin
               --  Need at least: version(2)+random(32)+sid_len(1) = 35
               if N32 (Data'Length) >= 4 + 35 then
                  Sid_Len := N32 (Data (BS + 34));
                  P := BS + 35 + Sid_Len;
                  if P + 2 <= N32 (Data'Last) - N32 (Data'First) + 1 + N32 (Data'First) then
                     Cs_Len := N32 (Data (P)) * 256 + N32 (Data (P + 1));
                     P := P + 2 + Cs_Len;
                     if P + 1 <= Data'Last then
                        Cm_Len := N32 (Data (P));
                        if Cm_Len /= 1 or else (P + 1 <= Data'Last and then Data (P + 1) /= 0) then
                           OK := True;  --  found bad compression

                        end if;
                     end if;
                  end if;
               end if;
               if OK then
                  Last_Err := Illegal_Parameter;
               else
                  Last_Err := Decode_Error;
               end if;
            end;
         end if;

         pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
         return;
      end if;

      --  Extract client random (32 bytes)
      declare
         Random_Bytes : RBT.Bytes (1 .. 32);
      begin
         Get_Random (Ctx, Random_Bytes);
         HC.Client_Random := To_NaCl (Random_Bytes);
      end;

      --  Extract legacy session ID. RFC 8446 4.1.3: server MUST
      --  echo the exact bytes (and length) the client sent. Track
      --  both so Build_Server_Hello can echo accurately.
      declare
         SID_Len : constant N32 := N32 (Get_Legacy_Session_ID_Length (Ctx));
      begin
         HC.Legacy_Session_ID := (others => 0);
         if SID_Len > 32 then
            Take_Buffer (Ctx, Buf);
            RFLX_Free (Buf);
            Last_Err := Decode_Error;

            pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
            return;
         end if;

         HC.Legacy_Session_ID_Len := SID_Len;

         pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);

         if SID_Len > 0 then
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
      Negotiated := Suite_None;
      Negotiated_12 := Suite_None;

      if Well_Formed (Ctx, F_Cipher_Suites_TLS) then
         Parse_CH_Cipher_Suites (Ctx, Negotiated, Negotiated_12, Last_Err, HC);
      end if;

      --  Need at least one matching suite (either TLS 1.3 or 1.2)
      if Negotiated = Suite_None and Negotiated_12 = Suite_None then
         Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);

         pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
         return;
      end if;

      --  Iterate extensions to find key_share / sig_algs / etc.
      if Well_Formed (Ctx, F_Extensions_TLS) then
         declare
            Ext_OK : Boolean;
         begin
            Parse_CH_Extensions (Ctx, HC, Ext_OK);

            if not Ext_OK then
               --  Some extension's contents were malformed.
               --  Most paths default to decode_error; specific
               --  extensions can stash a more accurate alert in
               --  HC.Ext_Parse_Err
               Take_Buffer (Ctx, Buf);
               RFLX_Free (Buf);

               if HC.Ext_Parse_Err /= No_Error then
                  Last_Err := HC.Ext_Parse_Err;
               else
                  Last_Err := Decode_Error;
               end if;

               pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
               return;
            end if;
         end;
      end if;

      --  RFC 4492 5.1: a ClientHello with no extensions block (or an empty
      --  one) carries no supported_groups, but a TLS 1.2 ECDHE handshake is
      --  still permitted -- assume the widely-implemented X25519, exactly as
      --  the former no-extensions parser did. Without this a legacy client
      --  that omits extensions gets handshake_failure (BoGo
      --  Empty/OmitExtensions-ClientHello-TLS12).
      if not Present (Ctx, F_Extensions_TLS) then
         HC.Client_Supports_X25519 := True;
      end if;

      Take_Buffer (Ctx, Buf);
      RFLX_Free (Buf);

      --  If legacy_version was TLS 1.0/1.1 and no supported_versions
      --  override named a version we support, reject rather than
      --  silently treating the locally-normalized RFLX parse buffer as
      --  a TLS 1.2 ClientHello.
      --  RFC 8446 4.1.2 / RFC 5246 E.1: legacy_version MUST be a real TLS
      --  ProtocolVersion. Below TLS 1.0 (0x0301) it is SSL 3.0 or a bogus
      --  value we never speak, so reject with protocol_version regardless
      --  of supported_versions -- the old Protocol_Version enum rejected
      --  these at parse time, and tlsfuzzer's legacy-version cases expect
      --  it. Values above 0x0303 are tolerated and treated as TLS 1.2
      --  (RFC 8446 4.1.2: a TLS 1.3 client sets legacy_version 0x0303 but
      --  buggy or forward-version clients may send higher).
      if Raw_Legacy_Version < 16#0301# then
         Last_Err := Protocol_Version;
         OK := False;

         pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
         return;
      end if;

      --  TLS 1.0 / TLS 1.1 (0x0301 / 0x0302) as the sole offer -- no
      --  supported_versions naming a version we support -- is a client
      --  asking only for versions we do not implement.
      if not HC.Saw_Supported_Versions
        and then Raw_Legacy_Version in 16#0301# .. 16#0302#
      then
         Last_Err := Protocol_Version;
         OK := False;

         pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
         return;
      end if;

      --  RFC 8446 4.2.1: if the client sent supported_versions but
      --  did not list any version we can negotiate, reject with
      --  protocol_version (instead of silently falling back to the
      --  legacy_version path). BoGo NoSupportedVersions.
      if HC.Saw_Supported_Versions and then not HC.SV_Has_Acceptable then
         Last_Err := Protocol_Version;
         OK := False;

         pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
         return;
      end if;

      --  Set version based on supported_versions parsing.
      --  If the client offered TLS 1.3 (0x0304), use it.
      --  Otherwise fall back to TLS 1.2.
      if HC.Has_TLS_1_3 then
         Version := TLS_1_3;
      else
         Version := TLS_1_2;
      end if;

      if not Compression_Methods_OK (Data, Is_TLS13 => Version = TLS_1_3) then
         Last_Err := Illegal_Parameter;
         OK := False;

         pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
         return;
      end if;

      if Version = TLS_1_3
        and then Negotiated not in
                   Suite_AES_128_GCM_SHA256
                   | Suite_AES_256_GCM_SHA384
                   | Suite_CHACHA20_POLY1305_SHA256
      then
         Last_Err := Handshake_Failure;
         OK := False;

         pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
         return;
      end if;

      --  RFC 8446 4.2.9: a TLS 1.3 ClientHello with pre_shared_key
      --  MUST also include psk_key_exchange_modes with at least one
      --  mode the server recognises. We support only psk_dhe_ke
      --  (0x01), so require HC.PSK.Has_DHE_KE whenever a PSK binder
      --  is present. BoGo TLS13-SendNoKEMModesWithPSK-Server.
      if Version = TLS_1_3 and then HC.PSK.Binder_Len > 0 and then not HC.PSK.Has_DHE_KE then
         Last_Err := Missing_Extension;
         OK := False;

         pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
         return;
      end if;

      --  Shared secret computation deferred to Build_Server_Hello
      --  where we know which group to select.

      OK := True;

      pragma Assert (HC.Legacy_Session_ID_Len in 0 .. 32);
   end Parse_Client_Hello;

   ----------------------------------------------------------------------------
   --  Shared ALPN selection
   ----------------------------------------------------------------------------

   function Same_ALPN (A, B : Hostname_Buf) return Boolean is
   begin
      if A.Len = 0 or else A.Len /= B.Len then
         return False;
      end if;
      for I in 1 .. A.Len loop
         if A.Data (I) /= B.Data (I) then
            return False;
         end if;
      end loop;
      return True;
   end Same_ALPN;

   function Select_ALPN (HC : Handshake_Context) return Hostname_Buf is
      Empty : constant Hostname_Buf := (Len => 0, Data => (others => ' '));
   begin
      if HC.Client_ALPN_Count = 0 then
         return Empty;
      end if;

      if HC.Cfg.ALPN_Count > 0 then
         for C in ALPN_Index loop
            exit when C > HC.Cfg.ALPN_Count;
            for P in ALPN_Index loop
               exit when P > HC.Client_ALPN_Count;
               if Same_ALPN (HC.Cfg.ALPN_List (C), HC.Client_ALPN_List (P)) then
                  return HC.Cfg.ALPN_List (C);
               end if;
            end loop;
         end loop;
      elsif HC.Cfg.ALPN.Len > 0 then
         for P in ALPN_Index loop
            exit when P > HC.Client_ALPN_Count;
            if Same_ALPN (HC.Cfg.ALPN, HC.Client_ALPN_List (P)) then
               return HC.Cfg.ALPN;
            end if;
         end loop;
      end if;

      return Empty;
   end Select_ALPN;

   function Has_ALPN_Match (HC : Handshake_Context) return Boolean is
   begin
      return Select_ALPN (HC).Len > 0;
   end Has_ALPN_Match;

end SPARKTLS.Handshake.Server_Msgs;
