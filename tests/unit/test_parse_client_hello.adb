--  Unit tests for SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello.
--
--  Pinned BEFORE refactoring Parse_Client_Hello into smaller subprograms
--  for SPARK proving. These tests must continue to pass through the refactor.

with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;           use Interfaces;
with SPARKNaCl;            use SPARKNaCl;
with SPARKTLS;             use SPARKTLS;
with SPARKTLS.Handshake.Server_Msgs;
with Det_Random_Lib;
with SPARKTLS.Test_Support;

procedure Test_Parse_Client_Hello is

   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then
         Pass := Pass + 1;
         Put_Line ("  PASS: " & Name);
      else
         Fail := Fail + 1;
         Put_Line ("  FAIL: " & Name);
      end if;
   end Check;

   ----------------------------------------------------------------------------
   --  ClientHello byte builders
   ----------------------------------------------------------------------------

   --  Wrap raw body bytes in a handshake header (type 0x01, 24-bit len).
   function Wrap_Handshake (Body_Bytes : Byte_Seq) return Byte_Seq is
      Body_Len : constant N32 := Body_Bytes'Length;
      Result   : Byte_Seq (0 .. 3 + Body_Len);
   begin
      Result (0) := 16#01#;  --  HT_Client_Hello
      Result (1) := Byte (Body_Len / 65536);
      Result (2) := Byte ((Body_Len / 256) mod 256);
      Result (3) := Byte (Body_Len mod 256);
      Result (4 .. 4 + Body_Len - 1) :=
         Body_Bytes (Body_Bytes'First .. Body_Bytes'Last);
      return Result;
   end Wrap_Handshake;

   --  Encode a u16 as 2 big-endian bytes at given offset.
   procedure Put_U16 (Buf : in out Byte_Seq; Off : N32; Val : Unsigned_16) is
   begin
      Buf (Off)     := Byte (Val / 256);
      Buf (Off + 1) := Byte (Val mod 256);
   end Put_U16;

   --  Build a minimal valid ClientHello body with no extensions and a
   --  single TLS 1.3 cipher suite. Caller can append an extensions
   --  block by extending the returned Byte_Seq.
   --
   --  Body layout (TLS 1.3):
   --    legacy_version(2) || random(32) || sid_len(1) || sid(N)
   --    || suites_len(2) || suites(M*2) || comp_len(1) || comp(0x00)
   --    || ext_total_len(2) || extensions(K)
   function Build_Min_CH_Body
     (SID_Len : N32 := 0;
      Suites  : Byte_Seq := (1 .. 0 => 0);  --  empty default
      Compression : Byte_Seq := (0 => 0);
      Exts    : Byte_Seq := (1 .. 0 => 0))
      return Byte_Seq
   is
      Default_Suites : constant Byte_Seq (0 .. 1) :=
        (16#13#, 16#01#);  --  TLS_AES_128_GCM_SHA256
      --  Default extension: x25519 key_share with all-zero key.
      --  Empirically RFLX's CH parser requires a key_share-shaped
      --  extension to consider the message well-formed; supported_versions
      --  alone is not enough.
      Default_Exts : constant Byte_Seq (0 .. 41) :=
        (16#00#, 16#33#,   --  ext type = key_share (0x0033)
         16#00#, 16#26#,   --  ext data length = 38
         16#00#, 16#24#,   --  inner list_len = 36
         16#00#, 16#1D#,   --  group = x25519 (0x001D)
         16#00#, 16#20#,   --  key_len = 32
         others => 0);     --  32-byte all-zero pubkey
      Use_Suites : constant Byte_Seq :=
        (if Suites'Length = 0 then Default_Suites else Suites);
      Use_Compression : constant Byte_Seq := Compression;
      Use_Exts : constant Byte_Seq :=
        (if Exts'Length = 0 then Default_Exts else Exts);
      Suites_Len : constant N32 := Use_Suites'Length;
      Compression_Len : constant N32 := Use_Compression'Length;
      Exts_Len : constant N32 := Use_Exts'Length;
      Body_Len : constant N32 :=
         2 + 32 + 1 + SID_Len
         + 2 + Suites_Len
         + 1 + Compression_Len
         + 2 + Exts_Len;
      B   : Byte_Seq (0 .. Body_Len - 1) := (others => 0);
      Pos : N32 := 0;
   begin
      --  Legacy version 0x0303
      B (0) := 16#03#; B (1) := 16#03#;
      Pos := 2;
      --  Random (32 zero bytes; tests don't care about value)
      Pos := Pos + 32;
      --  Session ID
      B (Pos) := Byte (SID_Len);
      Pos := Pos + 1 + SID_Len;
      --  Cipher suites
      Put_U16 (B, Pos, Unsigned_16 (Suites_Len));
      Pos := Pos + 2;
      B (Pos .. Pos + Suites_Len - 1) := Use_Suites;
      Pos := Pos + Suites_Len;
      --  Compression methods.
      B (Pos) := Byte (Compression_Len);
      Pos := Pos + 1;
      B (Pos .. Pos + Compression_Len - 1) := Use_Compression;
      Pos := Pos + Compression_Len;
      --  Extensions: total length + extension list bytes
      Put_U16 (B, Pos, Unsigned_16 (Exts_Len));
      Pos := Pos + 2;
      B (Pos .. Pos + Exts_Len - 1) := Use_Exts;
      return B;
   end Build_Min_CH_Body;

   --  Build a single extension (type, data) -> wire bytes:
   --    type(2) || data_len(2) || data    (total 4 + L bytes)
   function Build_Extension
     (Ext_Type : Unsigned_16; Data : Byte_Seq) return Byte_Seq
   is
      L  : constant N32 := Data'Length;
      Bs : Byte_Seq (0 .. 3 + L);
   begin
      Put_U16 (Bs, 0, Ext_Type);
      Put_U16 (Bs, 2, Unsigned_16 (L));
      if L > 0 then
         Bs (4 .. 3 + L) := Data;
      end if;
      return Bs;
   end Build_Extension;

   --  key_share extension data: list_len(2) || entries
   --  Each entry: group(2) || key_len(2) || key  (4 + KL bytes)
   function Build_KS_Ext (Group : Unsigned_16; Key : Byte_Seq) return Byte_Seq
   is
      KL    : constant N32 := Key'Length;
      Entry_Len : constant N32 := 4 + KL;
      List_Bytes : Byte_Seq (0 .. 1 + Entry_Len);  --  2 + Entry_Len bytes
   begin
      Put_U16 (List_Bytes, 0, Unsigned_16 (Entry_Len));
      Put_U16 (List_Bytes, 2, Group);
      Put_U16 (List_Bytes, 4, Unsigned_16 (KL));
      List_Bytes (6 .. 5 + KL) := Key;
      return Build_Extension (16#0033#, List_Bytes);
   end Build_KS_Ext;

   --  signature_algorithms extension: list_len(2) || algo_codes (each 2B)
   function Build_Sig_Algs_Ext (Algos : Byte_Seq) return Byte_Seq is
      LL  : constant N32 := Algos'Length;
      Bs  : Byte_Seq (0 .. 1 + LL);  --  2 + LL bytes
   begin
      Put_U16 (Bs, 0, Unsigned_16 (LL));
      Bs (2 .. 1 + LL) := Algos;
      return Build_Extension (16#000D#, Bs);
   end Build_Sig_Algs_Ext;

   --  supported_groups extension: list_len(2) || group_codes (each 2B)
   function Build_Supported_Groups_Ext
     (Groups : Byte_Seq) return Byte_Seq
   is
      LL : constant N32 := Groups'Length;
      Bs : Byte_Seq (0 .. 1 + LL);
   begin
      Put_U16 (Bs, 0, Unsigned_16 (LL));
      Bs (2 .. 1 + LL) := Groups;
      return Build_Extension (16#000A#, Bs);
   end Build_Supported_Groups_Ext;

   --  supported_versions extension (ClientHello variant):
   --    list_len(1) || version_codes (each 2B)    (1 + LL bytes)
   function Build_Supported_Versions_Ext (Versions : Byte_Seq) return Byte_Seq
   is
      LL : constant N32 := Versions'Length;
      Bs : Byte_Seq (0 .. LL);
   begin
      Bs (0) := Byte (LL);
      Bs (1 .. LL) := Versions;
      return Build_Extension (16#002B#, Bs);
   end Build_Supported_Versions_Ext;

   --  ALPN extension: list_len(2) || (proto_len(1) || proto)+   (3 + PL bytes)
   function Build_ALPN_Ext (Proto : String) return Byte_Seq is
      PL : constant N32 := N32 (Proto'Length);
      Bs : Byte_Seq (0 .. 2 + PL);
   begin
      Put_U16 (Bs, 0, Unsigned_16 (1 + PL));  --  inner list_len
      Bs (2) := Byte (PL);
      for I in 1 .. Proto'Length loop
         Bs (2 + N32 (I)) :=
            Byte (Character'Pos (Proto (Proto'First + I - 1)));
      end loop;
      return Build_Extension (16#0010#, Bs);
   end Build_ALPN_Ext;

   --  Concatenate two extension blobs
   function Cat (A, B : Byte_Seq) return Byte_Seq is
      R : Byte_Seq (0 .. A'Length + B'Length - 1);
   begin
      R (0 .. A'Length - 1) := A;
      R (A'Length .. R'Last) := B;
      return R;
   end Cat;

   ----------------------------------------------------------------------------
   --  Context init
   ----------------------------------------------------------------------------

   procedure Init_Context (S : out Session; HC : out Handshake_Context) is
   begin
      SPARKTLS.Test_Support.Reset (S);
      HC := (others => <>);
      HC.Cfg.Random := Det_Random_Lib.Det_Random'Access;
   end Init_Context;

   ----------------------------------------------------------------------------
   --  Tests
   ----------------------------------------------------------------------------

   procedure Test_Reject_Short is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      Data : constant Byte_Seq (0 .. 9) := (others => 0);
      OK   : Boolean;
   begin
      Init_Context (S, HC);
      SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      Check ("Reject too-short input (len=10)", not OK);
   end Test_Reject_Short;

   procedure Test_Reject_Wrong_Type is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      Data : Byte_Seq (0 .. 100) := (others => 0);
      OK   : Boolean;
   begin
      Init_Context (S, HC);
      Data (0) := 16#02#;  --  ServerHello type, not ClientHello
      SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      Check ("Reject wrong handshake type byte (0x02)", not OK);
   end Test_Reject_Wrong_Type;

   procedure Test_Wellformed_Min is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      Body_Bs : constant Byte_Seq := Build_Min_CH_Body;
      Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      OK   : Boolean;
   begin
      Init_Context (S, HC);
      SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      Check ("Minimal well-formed CH parses (OK = True)", OK);
      Check ("Minimal CH selects TLS_AES_128_GCM_SHA256",
             Neg = Suite_AES_128_GCM_SHA256);
   end Test_Wellformed_Min;

   procedure Test_Random_Extracted is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      Body_Bs : Byte_Seq := Build_Min_CH_Body;
      OK   : Boolean;
   begin
      --  Patch random bytes (offset 2..33 in body)
      for I in N32 range 0 .. 31 loop
         Body_Bs (2 + I) := Byte (16#A0# + Natural (I) mod 16);
      end loop;
      Init_Context (S, HC);
      declare
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("Client_Random extracted from CH",
             OK and then
             (for all I in N32 range 0 .. 31 =>
                HC.Client_Random (I) = Byte (16#A0# + Natural (I) mod 16)));
   end Test_Random_Extracted;

   procedure Test_Session_ID_Extracted is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      Body_Bs : Byte_Seq := Build_Min_CH_Body (SID_Len => 16);
      OK   : Boolean;
   begin
      --  Session ID at offset 2 + 32 + 1 = 35 .. 35 + 16 - 1
      for I in N32 range 0 .. 15 loop
         Body_Bs (35 + I) := Byte (16#10# + Natural (I) mod 16);
      end loop;
      Init_Context (S, HC);
      declare
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("Legacy_Session_ID extracted from CH",
             OK and then
             (for all I in N32 range 0 .. 15 =>
                HC.Legacy_Session_ID (I) = Byte (16#10# + Natural (I) mod 16)));
   end Test_Session_ID_Extracted;

   procedure Test_Suite_TLS13_AES256 is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      Suites : constant Byte_Seq (0 .. 1) := (16#13#, 16#02#);  --  AES_256_GCM
      Body_Bs : constant Byte_Seq := Build_Min_CH_Body (Suites => Suites);
      OK : Boolean;
   begin
      Init_Context (S, HC);
      declare
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("TLS_AES_256_GCM_SHA384 selected",
             OK and then
             Neg = Suite_AES_256_GCM_SHA384);
   end Test_Suite_TLS13_AES256;

   procedure Test_Suite_Prefers_ChaCha is
      --  Offer AES-128 then ChaCha20: server should pick ChaCha20
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      Suites : constant Byte_Seq (0 .. 3) :=
        (16#13#, 16#01#,   --  AES_128
         16#13#, 16#03#);  --  CHACHA20
      Body_Bs : constant Byte_Seq := Build_Min_CH_Body (Suites => Suites);
      OK : Boolean;
   begin
      Init_Context (S, HC);
      declare
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("ChaCha20 preferred over AES-128",
             OK and then
             Neg = Suite_CHACHA20_POLY1305_SHA256);
   end Test_Suite_Prefers_ChaCha;

   procedure Test_Suite_TLS12 is
      --  Offer only TLS 1.2 ECDHE-RSA-AES128
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      Suites : constant Byte_Seq (0 .. 1) := (16#C0#, 16#2F#);
      Body_Bs : constant Byte_Seq := Build_Min_CH_Body (Suites => Suites);
      OK : Boolean;
   begin
      Init_Context (S, HC);
      declare
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("TLS 1.2 ECDHE-RSA-AES128 selected",
             OK and then
             (Neg = Suite_None
              and then Neg_12 = Suite_ECDHE_RSA_AES128_GCM_SHA256));
   end Test_Suite_TLS12;

   procedure Test_TLS12_Compression_List_With_Null is
      --  TLS 1.2 clients may offer multiple compression methods as long as
      --  the server selects null compression.
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      Suites : constant Byte_Seq (0 .. 1) := (16#C0#, 16#2F#);
      Compression : constant Byte_Seq (0 .. 6) :=
        (1, 2, 3, 0, 4, 5, 6);
      Body_Bs : constant Byte_Seq :=
        Build_Min_CH_Body (Suites => Suites, Compression => Compression);
      OK : Boolean;
   begin
      Init_Context (S, HC);
      declare
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("TLS 1.2 compression list containing null is accepted",
             OK and then Neg_12 = Suite_ECDHE_RSA_AES128_GCM_SHA256);
   end Test_TLS12_Compression_List_With_Null;

   procedure Test_TLS13_Compression_List_With_Extra_Rejected is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      Compression : constant Byte_Seq (0 .. 1) := (0, 1);
      Vers : constant Byte_Seq (0 .. 1) := (16#03#, 16#04#);
      Body_Bs : constant Byte_Seq :=
        Build_Min_CH_Body
          (Compression => Compression,
           Exts        => Build_Supported_Versions_Ext (Vers));
      OK : Boolean;
   begin
      Init_Context (S, HC);
      declare
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("TLS 1.3 compression list with extra method is rejected",
             not OK and then Err = Illegal_Parameter);
   end Test_TLS13_Compression_List_With_Extra_Rejected;

   procedure Test_KS_X25519 is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      KS   : Byte_Seq (0 .. 31) := (others => 0);
      Body_Bs : Byte_Seq := Build_Min_CH_Body
        (Exts => Build_KS_Ext (16#001D#, KS));
      OK : Boolean;
   begin
      for I in N32 range 0 .. 31 loop
         KS (I) := Byte (16#80# + Natural (I) mod 16);
      end loop;
      --  Rebuild now that KS has values
      Body_Bs := Build_Min_CH_Body
        (Exts => Build_KS_Ext (16#001D#, KS));
      Init_Context (S, HC);
      declare
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("X25519 key_share parsed → Client_Has_X25519",
             OK and HC.Client_Has_X25519);
      Check ("X25519 key_share marks extension present",
             HC.Client_Saw_Key_Share);
      Check ("X25519 Peer_PK matches",
             (for all I in N32 range 0 .. 31 =>
                HC.KE.Peer_PK (I) = Byte (16#80# + Natural (I) mod 16)));
   end Test_KS_X25519;

   procedure Test_KS_P256 is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      KS   : Byte_Seq (0 .. 64) := (others => 0);
      OK : Boolean;
   begin
      KS (0) := 16#04#;  --  uncompressed point indicator
      for I in N32 range 1 .. 64 loop
         KS (I) := Byte (16#20# + Natural (I) mod 16);
      end loop;
      Init_Context (S, HC);
      declare
         Body_Bs : constant Byte_Seq := Build_Min_CH_Body
           (Exts => Build_KS_Ext (16#0017#, KS));
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("P-256 key_share → Client_Has_P256",
             OK and HC.Client_Has_P256);
      Check ("P-256 key_share marks extension present",
             HC.Client_Saw_Key_Share);
      Check ("P-256 Peer_PK first byte = 0x04",
             HC.KE.P256_PK (0) = 16#04#);
   end Test_KS_P256;

   procedure Test_KS_P384 is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      KS   : Byte_Seq (0 .. 96) := (others => 0);
      OK : Boolean;
   begin
      KS (0) := 16#04#;
      for I in N32 range 1 .. 96 loop
         KS (I) := Byte (16#30# + Natural (I) mod 16);
      end loop;
      Init_Context (S, HC);
      declare
         Body_Bs : constant Byte_Seq := Build_Min_CH_Body
           (Exts => Build_KS_Ext (16#0018#, KS));
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("P-384 key_share → Client_Has_P384",
             OK and HC.Client_Has_P384);
      Check ("P-384 key_share marks extension present",
             HC.Client_Saw_Key_Share);
      Check ("P-384 Peer_PK first byte = 0x04",
             HC.KE.P384_PK (0) = 16#04#);
   end Test_KS_P384;

   procedure Test_Missing_Key_Share_State is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      Vers : constant Byte_Seq (0 .. 1) := (16#03#, 16#04#);
      Groups : constant Byte_Seq (0 .. 1) := (16#00#, 16#1D#);
      OK : Boolean;
   begin
      Init_Context (S, HC);
      declare
         Exts : constant Byte_Seq :=
           Cat (Build_Supported_Versions_Ext (Vers),
                Build_Supported_Groups_Ext (Groups));
         Body_Bs : constant Byte_Seq := Build_Min_CH_Body (Exts => Exts);
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("Missing key_share leaves extension-present flag clear",
             OK and then not HC.Client_Saw_Key_Share);
      Check ("Missing key_share still records supported group",
             HC.Client_Supports_X25519 and then not HC.Client_Has_X25519);
   end Test_Missing_Key_Share_State;

   procedure Test_Missing_Supported_Groups_State is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      KS   : Byte_Seq (0 .. 31) := (others => 16#33#);
      Vers : constant Byte_Seq (0 .. 1) := (16#03#, 16#04#);
      OK : Boolean;
   begin
      Init_Context (S, HC);
      declare
         Exts : constant Byte_Seq :=
           Cat (Build_KS_Ext (16#001D#, KS),
                Build_Supported_Versions_Ext (Vers));
         Body_Bs : constant Byte_Seq := Build_Min_CH_Body (Exts => Exts);
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("Missing supported_groups leaves extension-present flag clear",
             OK and then not HC.Client_Saw_Supported_Groups);
      Check ("Missing supported_groups still records key_share",
             HC.Client_Has_X25519 and then HC.Client_Saw_Key_Share);
   end Test_Missing_Supported_Groups_State;

   procedure Test_Sig_Algs is
      --  Offer Ed25519 (0x0807) + ECDSA-P256 (0x0403) + RSA-PSS-256 (0x0804)
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      Algos : constant Byte_Seq (0 .. 5) :=
        (16#08#, 16#07#, 16#04#, 16#03#, 16#08#, 16#04#);
      OK : Boolean;
   begin
      Init_Context (S, HC);
      declare
         Body_Bs : constant Byte_Seq := Build_Min_CH_Body
           (Exts => Build_Sig_Algs_Ext (Algos));
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("Sig_Algs parsed: count = 3",
             OK and HC.Peer_Sig_Algo_Count = 3);
      Check ("Sig_Algs[0] = 0x0807 (Ed25519)",
             HC.Peer_Sig_Algos (0) = 16#0807#);
      Check ("Sig_Algs[1] = 0x0403 (ECDSA-P256)",
             HC.Peer_Sig_Algos (1) = 16#0403#);
      Check ("Sig_Algs[2] = 0x0804 (RSA-PSS-256)",
             HC.Peer_Sig_Algos (2) = 16#0804#);
   end Test_Sig_Algs;

   procedure Test_Supported_Groups is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      --  Offer x25519, P-256, P-384
      Groups : constant Byte_Seq (0 .. 5) :=
        (16#00#, 16#1D#, 16#00#, 16#17#, 16#00#, 16#18#);
      OK : Boolean;
   begin
      Init_Context (S, HC);
      declare
         Body_Bs : constant Byte_Seq := Build_Min_CH_Body
           (Exts => Build_Supported_Groups_Ext (Groups));
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("Supported_Groups: x25519",
             OK and HC.Client_Supports_X25519);
      Check ("Supported_Groups marks extension present",
             HC.Client_Saw_Supported_Groups);
      Check ("Supported_Groups: P-256",
             HC.Client_Supports_P256);
      Check ("Supported_Groups: P-384",
             HC.Client_Supports_P384);
   end Test_Supported_Groups;

   procedure Test_Supported_Versions is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      --  Offer TLS 1.3 (0x0304) and TLS 1.2 (0x0303)
      Vers : constant Byte_Seq (0 .. 3) :=
        (16#03#, 16#04#, 16#03#, 16#03#);
      OK : Boolean;
   begin
      Init_Context (S, HC);
      declare
         Body_Bs : constant Byte_Seq := Build_Min_CH_Body
           (Exts => Build_Supported_Versions_Ext (Vers));
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("Supported_Versions: TLS 1.3 detected",
             OK and HC.Has_TLS_1_3);
   end Test_Supported_Versions;

   procedure Test_ALPN is
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      OK : Boolean;
   begin
      Init_Context (S, HC);
      declare
         Body_Bs : constant Byte_Seq := Build_Min_CH_Body
           (Exts => Build_ALPN_Ext ("h2"));
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("ALPN: 'h2' parsed",
             OK and then
             (HC.Client_ALPN.Len = 2
              and then HC.Client_ALPN.Data (1 .. 2) = "h2"));
   end Test_ALPN;

   procedure Test_Multiple_Extensions is
      --  CH with key_share + supported_versions + supported_groups
      S    : Session;
      Neg    : Supported_Suite := Suite_None;
      Neg_12 : Supported_Suite := Suite_None;
      Err    : Error_Code := No_Error;
      HC   : Handshake_Context;
      KS   : Byte_Seq (0 .. 31) := (others => 16#11#);
      Vers : constant Byte_Seq (0 .. 1) := (16#03#, 16#04#);
      Groups : constant Byte_Seq (0 .. 1) := (16#00#, 16#1D#);
      OK : Boolean;
   begin
      Init_Context (S, HC);
      declare
         Exts : constant Byte_Seq :=
           Cat (Cat (Build_KS_Ext (16#001D#, KS),
                     Build_Supported_Versions_Ext (Vers)),
                Build_Supported_Groups_Ext (Groups));
         Body_Bs : constant Byte_Seq := Build_Min_CH_Body (Exts => Exts);
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello (Neg, Neg_12, Err, HC, Data, OK);
      end;
      Check ("Multi-ext CH parses",
             OK and HC.Client_Has_X25519
             and HC.Has_TLS_1_3
             and HC.Client_Supports_X25519);
   end Test_Multiple_Extensions;

   procedure Test_Idempotent is
      S1, S2   : Session;
      Neg1, Neg2     : Supported_Suite := Suite_None;
      Neg1_12, Neg2_12 : Supported_Suite := Suite_None;
      Err1, Err2     : Error_Code := No_Error;
      HC1, HC2 : Handshake_Context;
      KS   : Byte_Seq (0 .. 31) := (others => 16#22#);
      OK1, OK2 : Boolean;
   begin
      Init_Context (S1, HC1);
      Init_Context (S2, HC2);
      declare
         Body_Bs : constant Byte_Seq := Build_Min_CH_Body
           (Exts => Build_KS_Ext (16#001D#, KS));
         Data : constant Byte_Seq := Wrap_Handshake (Body_Bs);
      begin
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello
           (Neg1, Neg1_12, Err1, HC1, Data, OK1);
         SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello
           (Neg2, Neg2_12, Err2, HC2, Data, OK2);
      end;
      Check ("Idempotent: both succeed", OK1 and OK2);
      Check ("Idempotent: same negotiated suite",
             Neg1 = Neg2);
      Check ("Idempotent: same Client_Has_X25519",
             HC1.Client_Has_X25519 = HC2.Client_Has_X25519);
      Check ("Idempotent: same Peer_PK",
             (for all I in N32 range 0 .. 31 =>
                HC1.KE.Peer_PK (I) = HC2.KE.Peer_PK (I)));
   end Test_Idempotent;

begin
   Put_Line ("--- SPARKTLS.Handshake.Server_Msgs.Parse_Client_Hello ---");
   Test_Reject_Short;
   Test_Reject_Wrong_Type;
   Test_Wellformed_Min;
   Test_Random_Extracted;
   Test_Session_ID_Extracted;
   Test_Suite_TLS13_AES256;
   Test_Suite_Prefers_ChaCha;
   Test_Suite_TLS12;
   Test_TLS12_Compression_List_With_Null;
   Test_TLS13_Compression_List_With_Extra_Rejected;
   Test_KS_X25519;
   Test_KS_P256;
   Test_KS_P384;
   Test_Missing_Key_Share_State;
   Test_Missing_Supported_Groups_State;
   Test_Sig_Algs;
   Test_Supported_Groups;
   Test_Supported_Versions;
   Test_ALPN;
   Test_Multiple_Extensions;
   Test_Idempotent;
   New_Line;
   Put_Line ("=== Results: " & Pass'Image & "/" & Total'Image
             & " passed, " & Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Parse_Client_Hello;
