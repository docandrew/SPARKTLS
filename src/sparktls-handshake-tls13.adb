with Ada.Unchecked_Deallocation;
with Interfaces; use Interfaces;
with X509;
with SPARKTLS.HS_Pool;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKTLSCrypto.Ed25519;
with SPARKTLSCrypto.P256.ECDSA;
with SPARKTLSCrypto.P384.ECDSA;
with SPARKTLSCrypto.RFC6979;
with SPARKTLSCrypto.RSA;
with SPARKTLSCrypto.X25519;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.Point;
use SPARKTLSCrypto;
with SPARKTLS.RFLX_Bridge; use SPARKTLS.RFLX_Bridge;
with SPARKTLS.Handshake.Server_Msgs; use SPARKTLS.Handshake.Server_Msgs;
with SPARKTLS.Handshake.Certs; use SPARKTLS.Handshake.Certs;
with RFLX.TLS_Handshake.Finished;
with RFLX.TLS_Handshake.Certificate;
with RFLX.TLS_Handshake.Certificate_Entries;
with RFLX.TLS_Handshake.Certificate_Entry;
with RFLX.TLS_Handshake.Certificate_Verify;
with RFLX.TLS_Handshake.Certificate_Request;
with RFLX.TLS_Handshake.CR_Extensions;
with RFLX.TLS_Handshake.CR_Extension;
with RFLX.Tls_Parameters;
with RFLX.Tls_Extensiontype_Values;
with RFLX.RFLX_Types;

with SPARKTLS_Transcript;
use type SPARKTLS_Transcript.Transcript_State;

package body SPARKTLS.Handshake.TLS13
  with SPARK_Mode => On
is
   use type RBT.Length;
   use type RBT.Index;
   use type RBT.Bit_Length;
   use type RBT.Bytes_Ptr;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr)
   with Post => Buf = null;

   --  RFC 8446 Section 4.1.3: a real ServerHello.Random must not equal
   --  the HelloRetryRequest sentinel.
   HRR_Sentinel : constant Bytes_32 :=
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

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr) with SPARK_Mode => Off is
      procedure Dealloc is new
        Ada.Unchecked_Deallocation (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
   begin
      Dealloc (Buf);
   end RFLX_Free;

   procedure Build_Finished
     (Verify_Data : in Bytes_32;
      Result      : out Byte_Seq;
      Len         : out N32)
   is
      use RFLX.TLS_Handshake.Finished;
      Body_Len : constant N32 := 32;
      Msg_Len  : constant N32 := 4 + Body_Len;
      Ctx      : Context;
   begin
      Result := (others => 0);

      declare
         Buf : RBT.Bytes_Ptr := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      begin
         Initialize (Ctx, Buf);
         Set_Verify_Data (Ctx, To_RFLX (Verify_Data));
         Take_Buffer (Ctx, Buf);

         Result (0) := HS_Msg_Wire (HT_Finished);
         Result (1) := 16#00#;
         Result (2) := 16#00#;
         Result (3) := Byte (Body_Len);
         Result (4 .. 4 + Body_Len - 1) := To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));
         RFLX_Free (Buf);
      end;

      Len := Msg_Len;
   end Build_Finished;

   ----------------------------------------------------------------------------
   --  Server-side build procedures
   ----------------------------------------------------------------------------

   ----------------------------------------------------------------------------
   --  Helpers extracted from Build_Server_Hello so each piece is
   --  small enough for SPARK's SMT solvers to discharge.
   --
   --  KS_Raw layout: 4-byte TLS NamedGroupEntry header (group(2) +
   --  key_len(2)) followed by the encoded public key bytes.
   ----------------------------------------------------------------------------

   subtype KS_Raw_Buffer is Byte_Seq (0 .. 103);  --  max P-384: 4 + 97
   --  Wire representation of a single TLS 1.3 KeyShareEntry.

   --  X25519 key share generation (RFC 8446 4.2.8.2).
   --  Always succeeds.
   procedure Generate_KS_X25519
     (HC         : in out Handshake_Context;
      KS_Raw     : out KS_Raw_Buffer;
      KS_Raw_Len : out N32;
      OK         : out Boolean)
   with
     Pre => HC.Cfg.Random /= null,
     Post =>
       (if OK then KS_Raw_Len = 36 else KS_Raw_Len = 0)
       and then HC.Cfg.Random /= null
       and then (if Local_Config_Valid (HC.Cfg.Local'Old) then Local_Config_Valid (HC.Cfg.Local))
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then Local_Config_Valid (HC.Cfg.Local'Old)
                 then Local_Config_Valid (HC.Cfg.Local))
       and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                 then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity)
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then HC.Server_Random = HC.Server_Random'Old
   is
      procedure Gen_Random (Output : out Byte_Seq) renames HC.Cfg.Random.all;
      PK_Bytes  : Bytes_32;
      Basepoint : constant Bytes_32 := (9, others => 0);
      Tmp_SK    : Bytes_32;
   begin
      KS_Raw := (others => 0);

      Gen_Random (Byte_Seq (Tmp_SK));
      HC.KE.Local_SK := Tmp_SK;
      SPARKTLSCrypto.X25519.Scalar_Mult (PK_Bytes, HC.KE.Local_SK, Basepoint);
      SPARKTLSCrypto.X25519.Scalar_Mult (HC.KE.Shared (0 .. 31), HC.KE.Local_SK, HC.KE.Peer_PK);

      --  RFC 7748 6.1 / RFC 8422 5.10: reject all-zero shared
      --  secret (small-subgroup attack defense). The X25519 spec
      --  permits this output for points of small order (orders 1,
      --  2, 4, 8  eight specific 32-byte strings). Without this
      --  check, an attacker who feeds such a point can predict
      --  the master secret. The helper's Post is formally proven.
      --  RFC 8446 6.2: invalid peer share is illegal_parameter.
      --  Bubble up via HC.Ext_Parse_Err so Build_Server_Flight
      --  picks the specific alert instead of handshake_failure.
      if not Shared_Secret_Is_Acceptable_X25519 (HC.KE.Shared (0 .. 31)) then
         HC.KE.Shared := (others => 0);
         HC.Ext_Parse_Err := Illegal_Parameter;
         KS_Raw_Len := 0;
         OK := False;
         return;
      end if;

      --  group(2) + key_len(2) + key(32) = 36
      KS_Raw (0) := 0;
      KS_Raw (1) := 16#1D#;  --  x25519
      KS_Raw (2) := 0;
      KS_Raw (3) := 32;
      for I in N32 range 0 .. 31 loop
         KS_Raw (4 + I) := PK_Bytes (I);
      end loop;
      KS_Raw_Len := 36;
      OK := True;
   end Generate_KS_X25519;

   --  P-256 key share generation (RFC 8446 4.2.8.2 + RFC 8422 5).
   --  OK = False if HC.KE.P256_PK is not a valid point.
   procedure Generate_KS_P256
     (HC         : in out Handshake_Context;
      KS_Raw     : out KS_Raw_Buffer;
      KS_Raw_Len : out N32;
      OK         : out Boolean)
   with
     Pre => HC.Cfg.Random /= null,
     Post =>
       (if OK then KS_Raw_Len = 69 else KS_Raw_Len = 0)
       and then HC.Cfg.Random /= null
       and then (if Local_Config_Valid (HC.Cfg.Local'Old) then Local_Config_Valid (HC.Cfg.Local))
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then Local_Config_Valid (HC.Cfg.Local'Old)
                 then Local_Config_Valid (HC.Cfg.Local))
       and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                 then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity)
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then HC.Server_Random = HC.Server_Random'Old
   is
      use SPARKTLSCrypto.P256.Point;
      procedure Gen_Random (Output : out Byte_Seq) renames HC.Cfg.Random.all;
      PK_Jac  : P256_Jacobian;
      PK_Enc  : Byte_Seq (0 .. 64);
      Peer_Pt : P256_Jacobian;
      Valid   : SPARKNaCl.U32;
      Tmp_SK  : Bytes_32;
   begin
      KS_Raw := (others => 0);
      KS_Raw_Len := 0;
      OK := False;

      Gen_Random (Byte_Seq (Tmp_SK));
      HC.KE.P256_SK := Tmp_SK;
      --  Our public key
      P256_Mulgen (PK_Jac, HC.KE.P256_SK, 32);
      P256_To_Affine (PK_Jac);
      P256_Encode (PK_Enc, PK_Jac);
      --  Shared secret: x-coord of [our_sk] * peer_pk
      P256_Decode (Peer_Pt, HC.KE.P256_PK, Valid);
      if Valid = 0 then
         HC.Ext_Parse_Err := Illegal_Parameter;
         return;  --  invalid peer pubkey

      end if;
      P256_Mul (Peer_Pt, HC.KE.P256_SK, 32);
      P256_To_Affine (Peer_Pt);
      declare
         Enc : Byte_Seq (0 .. 64);
      begin
         P256_Encode (Enc, Peer_Pt);
         HC.KE.Shared := (others => 0);
         HC.KE.Shared (0 .. 31) := Enc (1 .. 32);
      end;
      --  group(2) + key_len(2) + key(65) = 69
      KS_Raw (0) := 0;
      KS_Raw (1) := 16#17#;
      KS_Raw (2) := 0;
      KS_Raw (3) := 65;
      for I in N32 range 0 .. 64 loop
         KS_Raw (4 + I) := PK_Enc (I);
      end loop;
      KS_Raw_Len := 69;
      OK := True;
   end Generate_KS_P256;

   --  P-384 key share generation.
   --  OK = False if P384_ECDHE rejects HC.KE.P384_PK.
   procedure Generate_KS_P384
     (HC         : in out Handshake_Context;
      KS_Raw     : out KS_Raw_Buffer;
      KS_Raw_Len : out N32;
      OK         : out Boolean)
   with
     Pre => HC.Cfg.Random /= null,
     Post =>
       (if OK then KS_Raw_Len = 101 else KS_Raw_Len = 0)
       and then HC.Cfg.Random /= null
       and then (if Local_Config_Valid (HC.Cfg.Local'Old) then Local_Config_Valid (HC.Cfg.Local))
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                 then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity)
       and then HC.Legacy_Session_ID_Len = HC.Legacy_Session_ID_Len'Old
       and then HC.Server_Random = HC.Server_Random'Old
   is
      procedure Gen_Random (Output : out Byte_Seq) renames HC.Cfg.Random.all;
      PK_Enc : Byte_Seq (0 .. 96);
      SS     : Bytes_48;
      SS_OK  : Boolean;
      Tmp_SK : Bytes_48;
   begin
      KS_Raw := (others => 0);
      KS_Raw_Len := 0;
      OK := False;

      Gen_Random (Byte_Seq (Tmp_SK));
      HC.KE.P384_SK := Tmp_SK;
      SPARKTLSCrypto.P384.Point.P384_Mulgen (PK_Enc, HC.KE.P384_SK);
      SPARKTLSCrypto.P384.Point.P384_ECDHE
        (Secret => SS, OK => SS_OK, SK => HC.KE.P384_SK, Peer_PK => HC.KE.P384_PK);
      if not SS_OK then
         HC.Ext_Parse_Err := Illegal_Parameter;
         return;
      end if;
      HC.KE.Shared := SS;
      --  group(2) + key_len(2) + key(97) = 101
      KS_Raw (0) := 0;
      KS_Raw (1) := 16#18#;
      KS_Raw (2) := 0;
      KS_Raw (3) := 97;
      for I in N32 range 0 .. 96 loop
         KS_Raw (4 + I) := PK_Enc (I);
      end loop;
      KS_Raw_Len := 101;
      OK := True;
   end Generate_KS_P384;

   procedure SH_Put16 (Buf : in out Byte_Seq; Pos : in N32; V : in Unsigned_16)
   with Pre => Buf'First = 0 and then Pos < Buf'Last;

   procedure SH_Put16 (Buf : in out Byte_Seq; Pos : in N32; V : in Unsigned_16) is
   begin
      Buf (Pos) := Byte (V / 256);
      Buf (Pos + 1) := Byte (V mod 256);
   end SH_Put16;

   procedure Serialize_Server_Hello
     (Negotiated  : in TLS13_Suite;
      HC          : in Handshake_Context;
      KS_Raw      : in KS_Raw_Buffer;
      KS_Data_Len : in N32;
      Ext_Total   : in N32;
      SID_Echo    : in N32;
      SH_Body_Len : in N32;
      SH_Msg_Len  : in N32;
      Result      : in out Byte_Seq;
      Len         : out N32)
   with
     Pre =>
       Result'First = 0
       and then Result'Last in Max_Server_Hello - 1 .. N32'Last - 1
       and then KS_Data_Len in 36 | 69 | 101
       and then Ext_Total in 46 .. 117
       and then Ext_Total = 10 + KS_Data_Len + (if HC.Using_PSK then 6 else 0)
       and then SID_Echo <= 32
       and then SH_Body_Len <= 189
       and then SH_Msg_Len <= Max_Server_Hello
       and then SH_Msg_Len = 4 + SH_Body_Len
       and then SH_Body_Len = 40 + SID_Echo + Ext_Total
       and then Session_ID_Echo_RFC_8446_4_1_3 (HC)
       and then Random_Length_RFC_5246_7_4_1_2 (HC.Server_Random),
     Post => Len = SH_Msg_Len;

   procedure Serialize_Server_Hello_Prefix
     (Negotiated  : in TLS13_Suite;
      HC          : in Handshake_Context;
      Ext_Total   : in N32;
      SID_Echo    : in N32;
      SH_Body_Len : in N32;
      Result      : in out Byte_Seq;
      Pos         : out N32)
   with
     Pre =>
       Result'First = 0
       and then Result'Last in Max_Server_Hello - 1 .. N32'Last - 1
       and then Ext_Total in 46 .. 117
       and then SID_Echo <= 32
       and then SH_Body_Len <= 189
       and then SH_Body_Len = 40 + SID_Echo + Ext_Total
       and then Session_ID_Echo_RFC_8446_4_1_3 (HC)
       and then Random_Length_RFC_5246_7_4_1_2 (HC.Server_Random),
     Post => Pos = 44 + SID_Echo;

   procedure Serialize_Server_Hello_Fixed_Prefix
     (HC : in Handshake_Context; SH_Body_Len : in N32; Result : in out Byte_Seq; Pos : out N32)
   with
     Pre =>
       Result'First = 0
       and then Result'Last in Max_Server_Hello - 1 .. N32'Last - 1
       and then SH_Body_Len <= 189
       and then Random_Length_RFC_5246_7_4_1_2 (HC.Server_Random),
     Post => Pos = 38;

   procedure Serialize_Server_Hello_Fixed_Prefix
     (HC : in Handshake_Context; SH_Body_Len : in N32; Result : in out Byte_Seq; Pos : out N32) is
   begin
      --  Handshake header.
      Result (0) := HS_Msg_Wire (HT_Server_Hello);
      Result (1) := Byte (SH_Body_Len / 65536);
      Result (2) := Byte ((SH_Body_Len / 256) mod 256);
      Result (3) := Byte (SH_Body_Len mod 256);
      Pos := 4;

      --  RFC 8446 4.1.3: legacy_version = 0x0303 even for TLS 1.3.
      pragma Assert (ServerHello_Legacy_Version_RFC_8446_4_1_3 (TLS_1_2));
      pragma Assert (Pos + 1 <= Result'Last);
      Result (Pos) := 16#03#;
      Result (Pos + 1) := 16#03#;
      Pos := Pos + 2;

      pragma Assert (Random_Length_RFC_5246_7_4_1_2 (HC.Server_Random));
      pragma Assert (Pos + 31 <= Result'Last);
      Result (Pos .. Pos + 31) := Byte_Seq (HC.Server_Random);
      Pos := Pos + 32;
   end Serialize_Server_Hello_Fixed_Prefix;

   procedure Serialize_Server_Hello_Variable_Prefix
     (Negotiated : in TLS13_Suite;
      HC         : in Handshake_Context;
      Ext_Total  : in N32;
      SID_Echo   : in N32;
      Result     : in out Byte_Seq;
      Pos        : in out N32)
   with
     Pre =>
       Result'First = 0
       and then Result'Last in Max_Server_Hello - 1 .. N32'Last - 1
       and then Ext_Total in 46 .. 117
       and then SID_Echo <= 32
       and then Pos = 38
       and then Session_ID_Echo_RFC_8446_4_1_3 (HC),
     Post => Pos = 44 + SID_Echo;

   procedure Serialize_Server_Hello_Variable_Prefix
     (Negotiated : in TLS13_Suite;
      HC         : in Handshake_Context;
      Ext_Total  : in N32;
      SID_Echo   : in N32;
      Result     : in out Byte_Seq;
      Pos        : in out N32) is
   begin
      --  RFC 8446 4.1.3: echo the client's exact session_id.
      pragma Assert (Session_ID_Echo_RFC_8446_4_1_3 (HC));
      pragma Assert (Pos <= Result'Last);
      Result (Pos) := Byte (SID_Echo);
      Pos := Pos + 1;
      if SID_Echo > 0 then
         pragma Assert (Pos + SID_Echo - 1 <= Result'Last);
         Result (Pos .. Pos + SID_Echo - 1) := Byte_Seq (HC.Legacy_Session_ID (0 .. SID_Echo - 1));
      end if;
      Pos := Pos + SID_Echo;

      pragma Assert (Pos + 1 <= Result'Last);
      SH_Put16 (Result, Pos, Wire_Of (Negotiated));
      Pos := Pos + 2;

      pragma Assert (Compression_Method_None_RFC_5246_6_2_2 (0));
      pragma Assert (Pos <= Result'Last);
      Result (Pos) := 0;
      Pos := Pos + 1;

      pragma Assert (Pos + 1 <= Result'Last);
      SH_Put16 (Result, Pos, Unsigned_16 (Ext_Total));
      Pos := Pos + 2;
   end Serialize_Server_Hello_Variable_Prefix;

   procedure Serialize_Server_Hello_Prefix
     (Negotiated  : in TLS13_Suite;
      HC          : in Handshake_Context;
      Ext_Total   : in N32;
      SID_Echo    : in N32;
      SH_Body_Len : in N32;
      Result      : in out Byte_Seq;
      Pos         : out N32) is
   begin
      Serialize_Server_Hello_Fixed_Prefix
        (HC => HC, SH_Body_Len => SH_Body_Len, Result => Result, Pos => Pos);
      Serialize_Server_Hello_Variable_Prefix
        (Negotiated => Negotiated,
         HC         => HC,
         Ext_Total  => Ext_Total,
         SID_Echo   => SID_Echo,
         Result     => Result,
         Pos        => Pos);
   end Serialize_Server_Hello_Prefix;

   procedure Serialize_Server_Hello_Extensions
     (HC          : in Handshake_Context;
      KS_Raw      : in KS_Raw_Buffer;
      KS_Data_Len : in N32;
      Ext_Total   : in N32;
      Pos         : in out N32;
      Result      : in out Byte_Seq)
   with
     Pre =>
       Result'First = 0
       and then Result'Last in Max_Server_Hello - 1 .. N32'Last - 1
       and then KS_Data_Len in 36 | 69 | 101
       and then Ext_Total in 46 .. 117
       and then Ext_Total = 10 + KS_Data_Len + (if HC.Using_PSK then 6 else 0)
       and then Pos in 44 .. 76
       and then Pos + Ext_Total - 1 <= Result'Last,
     Post => Pos = Pos'Old + Ext_Total;

   procedure Serialize_Server_Hello_Extensions
     (HC          : in Handshake_Context;
      KS_Raw      : in KS_Raw_Buffer;
      KS_Data_Len : in N32;
      Ext_Total   : in N32;
      Pos         : in out N32;
      Result      : in out Byte_Seq)
   is
      SV_Data_Len : constant := 2;
      SV_Ext_Len : constant := 4 + SV_Data_Len;
      PSK_Ext_Len : constant := 6;
      Start_Pos : constant N32 := Pos;
   begin

      --  Extension 1: key_share (0x0033).
      pragma Assert (Pos + 4 + KS_Data_Len - 1 <= Result'Last);
      SH_Put16 (Result, Pos, 16#0033#);
      SH_Put16 (Result, Pos + 2, Unsigned_16 (KS_Data_Len));
      Result (Pos + 4 .. Pos + 4 + KS_Data_Len - 1) := KS_Raw (0 .. KS_Data_Len - 1);
      Pos := Pos + 4 + KS_Data_Len;

      --  Extension 2: supported_versions (0x002B), selected TLS 1.3.
      declare
         SV_Raw : constant Byte_Seq (0 .. SV_Data_Len - 1) := (16#03#, 16#04#);
      begin
         pragma Assert (Supported_Versions_Server_TLS13_RFC_8446_4_2_1 (SV_Raw));
         pragma Assert (Pos + SV_Ext_Len - 1 <= Result'Last);
         SH_Put16 (Result, Pos, 16#002B#);
         SH_Put16 (Result, Pos + 2, Unsigned_16 (SV_Data_Len));
         Result (Pos + 4 .. Pos + 5) := SV_Raw;
         Pos := Pos + SV_Ext_Len;
      end;

      --  Optional pre_shared_key extension. Format: tag(2) +
      --  data_len(2) + selected_identity(2).
      if HC.Using_PSK then
         pragma Assert (Pos + PSK_Ext_Len - 1 <= Result'Last);
         SH_Put16 (Result, Pos, 16#0029#);
         SH_Put16 (Result, Pos + 2, 2);
         SH_Put16 (Result, Pos + 4, 0);
         Pos := Pos + PSK_Ext_Len;
      end if;

      pragma Assert (Pos = Start_Pos + 10 + KS_Data_Len + (if HC.Using_PSK then 6 else 0));
      pragma Assert (Pos = Start_Pos + Ext_Total);
   end Serialize_Server_Hello_Extensions;

   procedure Serialize_Server_Hello
     (Negotiated  : in TLS13_Suite;
      HC          : in Handshake_Context;
      KS_Raw      : in KS_Raw_Buffer;
      KS_Data_Len : in N32;
      Ext_Total   : in N32;
      SID_Echo    : in N32;
      SH_Body_Len : in N32;
      SH_Msg_Len  : in N32;
      Result      : in out Byte_Seq;
      Len         : out N32)
   is
      Pos : N32;
   begin
      Serialize_Server_Hello_Prefix
        (Negotiated  => Negotiated,
         HC          => HC,
         Ext_Total   => Ext_Total,
         SID_Echo    => SID_Echo,
         SH_Body_Len => SH_Body_Len,
         Result      => Result,
         Pos         => Pos);

      pragma Assert (Pos + Ext_Total - 1 <= Result'Last);
      Serialize_Server_Hello_Extensions
        (HC          => HC,
         KS_Raw      => KS_Raw,
         KS_Data_Len => KS_Data_Len,
         Ext_Total   => Ext_Total,
         Pos         => Pos,
         Result      => Result);

      pragma Assert (Pos = 44 + SID_Echo + Ext_Total);
      pragma Assert (Pos = SH_Msg_Len);
      Len := SH_Msg_Len;
   end Serialize_Server_Hello;

   procedure Select_Server_Key_Share
     (HC         : in out Handshake_Context;
      KS_Raw     : out KS_Raw_Buffer;
      KS_Raw_Len : out N32;
      OK         : out Boolean)
   with
     Pre =>
       HC.Cfg.Random /= null
       and then Session_ID_Echo_RFC_8446_4_1_3 (HC)
       and then Random_Length_RFC_5246_7_4_1_2 (HC.Server_Random),
     Post =>
       (if OK then KS_Raw_Len in 36 | 69 | 101 else KS_Raw_Len = 0)
       and then HC.Cfg.Random /= null
       and then (if Local_Config_Valid (HC.Cfg.Local'Old) then Local_Config_Valid (HC.Cfg.Local))
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                 then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity)
       and then Session_ID_Echo_RFC_8446_4_1_3 (HC)
       and then Random_Length_RFC_5246_7_4_1_2 (HC.Server_Random);

   procedure Select_Server_Key_Share
     (HC         : in out Handshake_Context;
      KS_Raw     : out KS_Raw_Buffer;
      KS_Raw_Len : out N32;
      OK         : out Boolean) is
   begin
      KS_Raw := (others => 0);

      --  Select key exchange group (prefer x25519 > P-256 > P-384).
      --  RFC 8446 4.2.8: the selected_group MUST come from a group
      --  the client offered. Each branch below conditions on the
      --  matching Client_Has_* flag so the per-branch pragma Assert
      --  proves the cross-reference.
      HC.KE.Shared := (others => 0);
      if HC.HRR_Sent and then HC.HRR_Selected_Group = Group_X25519 then
         if not HC.Client_Has_X25519 then
            KS_Raw_Len := 0;
            OK := False;
            return;
         end if;
         HC.KE.Curve := Group_X25519;
         HC.KE.Negotiated := True;
         pragma Assert (Selected_Group_Was_Offered_RFC_8446_4_2_8 (HC));
         Generate_KS_X25519 (HC, KS_Raw, KS_Raw_Len, OK);
         if not OK then
            HC.Ext_Parse_Err := Illegal_Parameter;
            return;
         end if;
      elsif HC.HRR_Sent and then HC.HRR_Selected_Group = Group_Secp256r1 then
         if not HC.Client_Has_P256 then
            KS_Raw_Len := 0;
            OK := False;
            return;
         end if;
         HC.KE.Curve := Group_Secp256r1;
         HC.KE.Negotiated := True;
         pragma Assert (Selected_Group_Was_Offered_RFC_8446_4_2_8 (HC));
         Generate_KS_P256 (HC, KS_Raw, KS_Raw_Len, OK);
         if not OK then
            KS_Raw_Len := 0;
            return;
         end if;
      elsif HC.HRR_Sent and then HC.HRR_Selected_Group = Group_Secp384r1 then
         if not HC.Client_Has_P384 then
            KS_Raw_Len := 0;
            OK := False;
            return;
         end if;
         HC.KE.Curve := Group_Secp384r1;
         HC.KE.Negotiated := True;
         pragma Assert (Selected_Group_Was_Offered_RFC_8446_4_2_8 (HC));
         Generate_KS_P384 (HC, KS_Raw, KS_Raw_Len, OK);
         if not OK then
            KS_Raw_Len := 0;
            return;
         end if;
      elsif HC.HRR_Sent then
         KS_Raw_Len := 0;
         OK := False;
      elsif HC.Client_Has_X25519 then
         HC.KE.Curve := Group_X25519;
         HC.KE.Negotiated := True;
         pragma Assert (Selected_Group_Was_Offered_RFC_8446_4_2_8 (HC));
         Generate_KS_X25519 (HC, KS_Raw, KS_Raw_Len, OK);
         if not OK then
            --  RFC 7748 6.1: peer sent a small-order point.
            HC.Ext_Parse_Err := Illegal_Parameter;
            return;
         end if;
      elsif HC.Client_Has_P256 then
         HC.KE.Curve := Group_Secp256r1;
         HC.KE.Negotiated := True;
         pragma Assert (Selected_Group_Was_Offered_RFC_8446_4_2_8 (HC));
         Generate_KS_P256 (HC, KS_Raw, KS_Raw_Len, OK);
         if not OK then
            KS_Raw_Len := 0;
            return;
         end if;
      elsif HC.Client_Has_P384 then
         HC.KE.Curve := Group_Secp384r1;
         HC.KE.Negotiated := True;
         pragma Assert (Selected_Group_Was_Offered_RFC_8446_4_2_8 (HC));
         Generate_KS_P384 (HC, KS_Raw, KS_Raw_Len, OK);
         if not OK then
            KS_Raw_Len := 0;
            return;
         end if;
      else
         --  No common key exchange group.
         KS_Raw_Len := 0;
         OK := False;
      end if;
   end Select_Server_Key_Share;

   procedure Build_Server_Hello
     (Negotiated : in TLS13_Suite;
      HC         : in out Engaged_Context;
      Result     : out Byte_Seq;
      Len        : out N32)
   is
      procedure Gen_Random (Output : out Byte_Seq) renames HC.Cfg.Random.all;

      SV_Data_Len : constant := 2;
      SV_Ext_Len : constant := 4 + SV_Data_Len;
      PSK_Ext_Len : constant := 6;

      --  Key share data: varies by selected group
      KS_Raw     : KS_Raw_Buffer;
      KS_Raw_Len : N32;

      KS_Data_Len : N32;
      Ext_Total   : N32;
      SH_Body_Len : N32;
      SH_Msg_Len  : N32;
      SID_Echo    : N32;
   begin
      Result := (others => 0);
      Len := 0;

      --  Generate server random (use temp to avoid SPARK aliasing).
      --  RFC 8446 4.1.3: regenerate on the astronomical collision with
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

      declare
         KS_OK : Boolean;
      begin
         Select_Server_Key_Share (HC, KS_Raw, KS_Raw_Len, KS_OK);
         if not KS_OK then
            --  No common key exchange group or invalid peer share.
            --  Set Len = 0; caller will send handshake_failure unless a
            --  more specific HC.Ext_Parse_Err was set.
            Len := 0;
            return;
         end if;
      end;

      if KS_Raw_Len not in 36 | 69 | 101 then
         Len := 0;
         return;
      end if;

      KS_Data_Len := KS_Raw_Len;
      pragma Assert (KS_Data_Len in 36 | 69 | 101);
      Ext_Total := (4 + KS_Data_Len) + SV_Ext_Len;
      if HC.Using_PSK then
         Ext_Total := Ext_Total + PSK_Ext_Len;
      end if;
      pragma Assert (Ext_Total in 46 .. 117);
      --  Actual body bytes RFLX will encode depend on the echoed
      --  session_id length. ver(2)+random(32)+sid_len(1)+sid(N)+
      --  suite(2)+comp(1)+ext_len(2) = 40 + N. Was hardcoded to
      --  72 (assuming N=32); when the client sent a shorter SID
      --  (BoGo Resume-Server-TLS13 with SendBothTickets sends 16),
      --  the HS header overstated the body length, causing the
      --  peer to fail SH parse with trailing-garbage bytes.
      SID_Echo := HC.Legacy_Session_ID_Len;
      SH_Body_Len := 40 + SID_Echo + Ext_Total;
      SH_Msg_Len := 4 + SH_Body_Len;

      if SH_Msg_Len - 1 > Result'Last then
         return;
      end if;

      pragma Assert (SID_Echo <= 32);
      pragma Assert (Ext_Total <= 117);
      pragma Assert (SH_Body_Len <= 189);
      pragma Assert (SH_Msg_Len <= Max_Server_Hello);

      Serialize_Server_Hello
        (Negotiated  => Negotiated,
         HC          => HC,
         KS_Raw      => KS_Raw,
         KS_Data_Len => KS_Data_Len,
         Ext_Total   => Ext_Total,
         SID_Echo    => SID_Echo,
         SH_Body_Len => SH_Body_Len,
         SH_Msg_Len  => SH_Msg_Len,
         Result      => Result,
         Len         => Len);
   end Build_Server_Hello;

   procedure Build_Encrypted_Extensions (S : in out Session; Result : out Byte_Seq; Len : out N32)
   is
      Selected_ALPN : constant Hostname_Buf := Select_ALPN (S.HC);
      ALPN_Match    : constant Boolean := Selected_ALPN.Len > 0;
      subtype EE_ALPN_Protocol_Len is Natural range 0 .. Max_Hostname_Len;
      subtype EE_ALPN_Ext_Len is N32 range 0 .. 262;
      subtype EE_SNI_Ext_Len is N32 range 0 .. 4;
      subtype EE_Ext_List_Len is N32 range 0 .. 266;
      subtype EE_Body_Len is N32 range 2 .. 268;
      subtype EE_Msg_Len is N32 range 6 .. 272;

      ALPN_PL      : constant EE_ALPN_Protocol_Len := (if ALPN_Match then Selected_ALPN.Len else 0);
      --  ALPN ext: tag(2) + len(2) + list_len(2) + proto_len(1) + proto(N)
      ALPN_Ext_Len : constant EE_ALPN_Ext_Len := (if ALPN_Match then N32 (7 + ALPN_PL) else 0);
      --  RFC 6066 3 / RFC 8446 4.2: server_name acknowledgement
      --  has an empty extension_data body.  RFC 8446 4.6.1 omits it
      --  on resumption unless the server accepts early data, which this
      --  implementation does not.
      SNI_Ext_Len  : constant EE_SNI_Ext_Len :=
        (if S.HC.Cfg.Ack_Server_Name and then S.HC.Peer_SNI.Len > 0 and then not S.HC.Using_PSK
         then 4
         else 0);

      Ext_Len  : constant EE_Ext_List_Len := SNI_Ext_Len + ALPN_Ext_Len;
      Body_Len : constant EE_Body_Len := 2 + Ext_Len;  --  ext_list_len(2) + exts
      Msg_Len  : constant EE_Msg_Len := 4 + Body_Len;
      Pos      : N32;
   begin
      Result := (others => 0);

      --  Handshake header
      Result (0) := HS_Msg_Wire (HT_Encrypted_Extensions);
      Result (1) := Byte (Body_Len / 65536);
      Result (2) := Byte ((Body_Len / 256) mod 256);
      Result (3) := Byte (Body_Len mod 256);

      --  Extensions list length
      Result (4) := Byte (Ext_Len / 256);
      Result (5) := Byte (Ext_Len mod 256);

      Pos := 6;

      --  server_name acknowledgement (if client sent SNI and this is not
      --  a PSK resumption)
      if SNI_Ext_Len > 0 then
         Result (Pos) := 0;
         Result (Pos + 1) := 0;
         Result (Pos + 2) := 0;
         Result (Pos + 3) := 0;
         Pos := Pos + SNI_Ext_Len;
      end if;

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
            pragma Assert (Pos + N32 (6 + I) <= Result'Last);
            Result (Pos + N32 (6 + I)) := Byte (Character'Pos (Selected_ALPN.Data (I)));
         end loop;

         S.Negotiated_ALPN := Selected_ALPN;
         Pos := Pos + ALPN_Ext_Len;
      end if;

      pragma Unreferenced (Pos);
      Len := Msg_Len;
   end Build_Encrypted_Extensions;

   procedure Build_Certificate_Request (Result : out Byte_Seq; Len : out N32) is
      use RFLX.TLS_Handshake.Certificate_Request;
      use RFLX.Tls_Extensiontype_Values;
      use type RBT.Bytes;

      Sig_Ed25519           : constant Unsigned_16 := 16#0807#;
      Sig_ECDSA_P256_SHA256 : constant Unsigned_16 := 16#0403#;
      Sig_ECDSA_P384_SHA384 : constant Unsigned_16 := 16#0503#;
      Sig_RSA_PSS_SHA256    : constant Unsigned_16 := 16#0804#;
      Sig_RSA_PSS_SHA384    : constant Unsigned_16 := 16#0805#;
      Sig_RSA_PSS_SHA512    : constant Unsigned_16 := 16#0806#;

      function U16_Bytes (V : Unsigned_16) return RBT.Bytes
      is ((1 => RBT.Byte (V / 256), 2 => RBT.Byte (V mod 256)));

      --  TLS 1.3 CertificateRequest.signature_algorithms extension data:
      --  vector length followed by modern schemes accepted for client
      --  CertificateVerify. RSA in TLS 1.3 means RSA-PSS, not PKCS#1 v1.5.
      Sig_Algo_List : constant RBT.Bytes :=
        U16_Bytes (Sig_Ed25519)
        & U16_Bytes (Sig_ECDSA_P256_SHA256)
        & U16_Bytes (Sig_ECDSA_P384_SHA384)
        & U16_Bytes (Sig_RSA_PSS_SHA256)
        & U16_Bytes (Sig_RSA_PSS_SHA384)
        & U16_Bytes (Sig_RSA_PSS_SHA512);
      Sig_Algo_Data : constant RBT.Bytes :=
        (1 => 0, 2 => RBT.Byte (Sig_Algo_List'Length)) & Sig_Algo_List;

      --  Extension: type(2) + data_len(2) + data(14) = 18
      Ext_Len  : constant N32 := 4 + N32 (Sig_Algo_Data'Length);
      --  Body: context_len(1) + ext_list_len(2) + extension.
      Body_Len : constant N32 := 1 + 2 + Ext_Len;
      Msg_Len  : constant N32 := 4 + Body_Len;
      Ctx      : Context;
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
           (Ctx, RFLX.TLS_Handshake.Certificate_Request_Extensions_Length (Ext_Len));

         declare
            Ext_Seq_Ctx : RFLX.TLS_Handshake.CR_Extensions.Context;
         begin
            Switch_To_Extensions (Ctx, Ext_Seq_Ctx);

            --  Build signature_algorithms extension
            declare
               E_Buf : RBT.Bytes_Ptr := new RBT.Bytes'(1 .. RBT.Index (Ext_Len) => 0);
               E_Ctx : RFLX.TLS_Handshake.CR_Extension.Context;
            begin
               RFLX.TLS_Handshake.CR_Extension.Initialize (E_Ctx, E_Buf);
               RFLX.TLS_Handshake.CR_Extension.Set_Tag (E_Ctx, Signature_Algorithms);
               RFLX.TLS_Handshake.CR_Extension.Set_Data_Length
                 (E_Ctx, RFLX.TLS_Handshake.Data_Length (Sig_Algo_Data'Length));
               RFLX.TLS_Handshake.CR_Extension.Set_Data (E_Ctx, Sig_Algo_Data);
               declare
                  use type RFLX.RFLX_Builtin_Types.Bit_Length;
               begin
                  pragma Assert (RFLX.TLS_Handshake.CR_Extension.Size (E_Ctx) > 0);
                  if RFLX.TLS_Handshake.CR_Extensions.Available_Space (Ext_Seq_Ctx)
                    >= RFLX.TLS_Handshake.CR_Extension.Size (E_Ctx)
                  then
                     RFLX.TLS_Handshake.CR_Extensions.Append_Element (Ext_Seq_Ctx, E_Ctx);
                  end if;
               end;
               RFLX.TLS_Handshake.CR_Extension.Take_Buffer (E_Ctx, E_Buf);
               RFLX_Free (E_Buf);
            end;

            Update_Extensions (Ctx, Ext_Seq_Ctx);
         end;

         Take_Buffer (Ctx, Buf);

         --  Prepend handshake header
         Result (0) := HS_Msg_Wire (HT_Certificate_Request);
         Result (1) := Byte (Body_Len / 65536);
         Result (2) := Byte ((Body_Len / 256) mod 256);
         Result (3) := Byte (Body_Len mod 256);
         Result (4 .. 4 + Body_Len - 1) := To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));
         RFLX_Free (Buf);
      end;

      Len := Msg_Len;
   end Build_Certificate_Request;

   procedure Build_Certificate_Chain (Id : in Identity; Result : out Byte_Seq; Len : out N32) is
      --  Build the Certificate message manually (simpler than RFLX
      --  for variable-count entries).
      --
      --  Format:
      --    handshake_header(4)
      --    certificate_request_context_length(1) = 0
      --    certificate_list_length(3)
      --    for each cert:
      --      cert_data_length(3) + cert_data + extensions_length(2) = 0

      Pos : N32 := 0;

      procedure Put_U8 (V : Byte)
      with
        Pre => Result'First = 0 and then Result'Last < N32'Last and then Pos <= Result'Last + 1,
        Post =>
          Pos <= Result'Last + 1
          and then (if Pos'Old <= Result'Last then Pos = Pos'Old + 1 else Pos = Pos'Old)
      is
      begin
         if Pos <= Result'Last then
            Result (Pos) := V;
            Pos := Pos + 1;
         end if;
      end Put_U8;

      procedure Put_U24 (V : N32)
      with
        Pre =>
          Result'First = 0
          and then Result'Last < N32'Last
          and then Pos <= Result'Last + 1
          and then V <= 16#FFFFFF#,
        Post =>
          Pos <= Result'Last + 1
          and then (if Pos'Old <= Result'Last - 2 then Pos = Pos'Old + 3
                    else Pos <= Result'Last + 1)
      is
      begin
         Put_U8 (Byte (V / 65536));
         Put_U8 (Byte ((V / 256) mod 256));
         Put_U8 (Byte (V mod 256));
      end Put_U24;

      procedure Put_Cert_Entry (DER : Byte_Seq; DER_Len : N32)
      with
        Pre =>
          DER'First = 0
          and then DER_Len > 0
          and then DER_Len <= N32 (Max_Cert_DER)
          and then DER'Last in 0 .. N32 (Max_Cert_DER) - 1
          and then DER'Last >= DER_Len - 1
          and then Result'First = 0
          and then Result'Last < N32'Last
          and then Pos <= Result'Last + 1,
        Post => Pos <= Result'Last + 1
      is
      begin
         Put_U24 (DER_Len);              --  cert_data_length
         if Pos <= Result'Last and then Result'Last - Pos >= DER_Len - 1 then
            pragma Assert (Result'First = 0);
            pragma Assert (Pos >= Result'First);
            pragma Assert (Pos <= Result'Last - (DER_Len - 1));
            pragma Assert (Pos + DER_Len - 1 <= Result'Last);
            pragma Assert (DER_Len - 1 <= DER'Last);
            Result (Pos .. Pos + DER_Len - 1) := DER (0 .. DER_Len - 1);
            Pos := Pos + DER_Len;
         end if;
         Put_U8 (0);
         Put_U8 (0);         --  extensions_length = 0
      end Put_Cert_Entry;

      --  Compute total list length
      List_Len : N32;
   begin
      Result := (others => 0);
      Len := 0;

      if not Id.Has_Identity or Id.NaCl_Cert_Len = 0 then
         return;
      end if;

      --  Leaf entry: 3 + cert_len + 2
      List_Len := 3 + Id.NaCl_Cert_Len + 2;

      --  Intermediate entries. Each entry adds at most
      --  3 + Max_Cert_DER + 2 bytes; with at most Max_Pool_Size
      --  intermediates, total list â¤ leaf_entry + Max_Pool_Size *
      --  (Max_Cert_DER + 5), well below N32'Last.
      for I in 0 .. Id.Int_Count - 1 loop
         pragma
           Loop_Invariant
             (List_Len <= 3 + Id.NaCl_Cert_Len + 2 + N32 (I) * (3 + N32 (Max_Cert_DER) + 2));
         if Id.Ints (I).Present then
            List_Len := List_Len + 3 + N32 (Id.Ints (I).DER_Len) + 2;
         end if;
      end loop;

      declare
         Body_Len : constant N32 := 1 + 3 + List_Len;
         Msg_Len  : constant N32 := 4 + Body_Len;
      begin
         if Msg_Len > N32 (Result'Length) then
            return;
         end if;

         --  Handshake header
         Put_U8 (HS_Msg_Wire (HT_Certificate));
         Put_U24 (Body_Len);

         --  certificate_request_context (empty)
         Put_U8 (0);

         --  certificate_list_length
         Put_U24 (List_Len);

         --  Leaf certificate entry
         Put_Cert_Entry (Id.NaCl_Cert_DER, Id.NaCl_Cert_Len);

         --  Intermediate certificate entries
         for I in 0 .. Id.Int_Count - 1 loop
            pragma Loop_Invariant (Pos <= Result'Last + 1);
            if Id.Ints (I).Present and then Id.Ints (I).DER_Len > 0 then
               declare
                  Int_DER : Byte_Seq (0 .. N32 (Id.Ints (I).DER_Len) - 1);
               begin
                  pragma Assert (Id.Ints (I).DER_Len <= X509.N32 (Max_Cert_DER));
                  --  Convert X509.Byte_Seq to SPARKNaCl.Byte_Seq
                  for J in Int_DER'Range loop
                     pragma Assert (J <= N32 (Max_Cert_DER) - 1);
                     declare
                        J_Nat : constant Natural := Natural (J);
                        K     : constant X509.N32 := X509.N32 (J_Nat);
                     begin
                        pragma Assert (J_Nat <= Max_Cert_DER - 1);
                        pragma Assert (K >= Id.Ints (I).DER'First);
                        pragma Assert (K <= X509.N32 (Max_Cert_DER) - 1);
                        pragma Assert (K <= Id.Ints (I).DER'Last);
                        Int_DER (J) := Byte (Id.Ints (I).DER (K));
                     end;
                  end loop;
                  Put_Cert_Entry (Int_DER, N32 (Id.Ints (I).DER_Len));
               end;
            end if;
         end loop;

         Len := Pos;
      end;
   end Build_Certificate_Chain;

   --  RFC 8446 4.4.3 CertificateVerify signed-content layout:
   --    64 bytes 0x20 || context_str (32 or 33) || 0x00 || transcript_hash
   --  Total: 129 (32-byte hash) or 130 (32-byte hash, client) or 145/146
   --  (48-byte hash). Sized at 146 so all four shapes fit.
   Max_CV_Content : constant N32 := 146;

   procedure Build_CV_Content
     (Transcript_Hash : in Byte_Seq;
      Role            : in TLS_Role;
      Content         : out Byte_Seq;
      Content_Len     : out N32)
   with
     Pre =>
       Content'First = 0
       and Content'Last = Max_CV_Content - 1
       and Transcript_Hash'First = 0
       and Transcript_Hash'Last in 31 | 47,
     Post => Content_Len = 99 + N32 (Transcript_Hash'Last) and Content_Len in 130 .. Max_CV_Content;

   procedure Build_CV_Content
     (Transcript_Hash : in Byte_Seq;
      Role            : in TLS_Role;
      Content         : out Byte_Seq;
      Content_Len     : out N32)
   is
      --  Context_Str is statically 32 bytes regardless of role.
      Server_Ctx : constant String := "TLS 1.3, server CertificateVerify";
      Client_Ctx : constant String := "TLS 1.3, client CertificateVerify";
      pragma Assert (Server_Ctx'Length = 33);
      pragma Assert (Client_Ctx'Length = 33);
      H_Len      : constant N32 := N32 (Transcript_Hash'Last) + 1;
   begin
      Content := (others => 0);
      Content (0 .. 63) := (others => 16#20#);
      if Role = Role_Server then
         for I in Server_Ctx'Range loop
            pragma Loop_Invariant (I in Server_Ctx'Range);
            Content (64 + N32 (I - Server_Ctx'First)) := Byte (Character'Pos (Server_Ctx (I)));
         end loop;
      else
         for I in Client_Ctx'Range loop
            pragma Loop_Invariant (I in Client_Ctx'Range);
            Content (64 + N32 (I - Client_Ctx'First)) := Byte (Character'Pos (Client_Ctx (I)));
         end loop;
      end if;
      Content (97) := 16#00#;  --  64 + 33
      Content (98 .. 97 + H_Len) := Transcript_Hash;
      Content_Len := 98 + H_Len;
   end Build_CV_Content;

   procedure Build_Certificate_Verify
     (Transcript_Hash : in Byte_Seq;
      Id              : in Identity;
      Sig_Algo_Wire   : in Maybe_Sig_Scheme;
      Role            : in TLS_Role;
      Random          : in Random_Bytes_Fn;
      Result          : out Byte_Seq;
      Len             : out N32)
   is
      use RFLX.TLS_Handshake.Certificate_Verify;

      Content     : Byte_Seq (0 .. Max_CV_Content - 1);
      Content_Len : N32;

      Sig     : Byte_Seq (0 .. 511) := (others => 0);
      Sig_Len : N32 := 0;
      Sig_OK  : Boolean;

      Algo_Enum : RFLX.Tls_Parameters.TLS_SignatureScheme_Enum;
   begin
      Result := (others => 0);
      Len := 0;

      Build_CV_Content (Transcript_Hash, Role, Content, Content_Len);

      case Sig_Algo_Wire is
         when Sig_Ed25519 =>
            Algo_Enum := RFLX.Tls_Parameters.Ed25519_0807;
            Sig_Len := 64;
            declare
               SM_Len : constant N32 := 64 + Content_Len;
               SM     : Byte_Seq (0 .. SM_Len - 1);
               SK     : Bytes_64;
            begin
               SK := Id.Ed25519_Key;
               SPARKTLSCrypto.Ed25519.Sign (SM, Content (0 .. Content_Len - 1), SK);
               Sig (0 .. 63) := SM (0 .. 63);
               Sig_OK := True;
            end;

         when Sig_ECDSA_P256_SHA256 =>
            Algo_Enum := RFLX.Tls_Parameters.Ecdsa_Secp256r1_Sha256;
            declare
               use SPARKTLSCrypto.Hashing.SHA256;
               H              : constant Digest := Hash (Content (0 .. Content_Len - 1));
               K_Bytes        : Bytes_32;
               K_OK           : Boolean;
               R_Half, S_Half : SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half;
            begin
               --  RFC 6979 deterministic nonce. Abort signing if the
               --  fixed, constant-time candidate budget is exhausted.
               SPARKTLSCrypto.RFC6979.Derive_K_P256
                 (D => Bytes_32 (Id.ECDSA_P256_Key), H => Bytes_32 (H), K => K_Bytes, OK => K_OK);
               if not K_OK then
                  Sig_OK := False;
                  return;
               end if;
               SPARKTLSCrypto.P256.ECDSA.Sign
                 (Hash  => H,
                  D     => SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half (Id.ECDSA_P256_Key),
                  K     => SPARKTLSCrypto.P256.ECDSA.ECDSA_Sig_Half (K_Bytes),
                  R_Out => R_Half,
                  S_Out => S_Half,
                  OK    => Sig_OK);
               if Sig_OK then
                  ECDSA_To_DER (Byte_Seq (R_Half), Byte_Seq (S_Half), 32, Sig, Sig_Len);
               end if;
            end;

         when Sig_ECDSA_P384_SHA384 =>
            Algo_Enum := RFLX.Tls_Parameters.Ecdsa_Secp384r1_Sha384;
            declare
               use SPARKNaCl.Hashing.SHA384;
               H       : constant Digest := Hash (Content (0 .. Content_Len - 1));
               K_Bytes : Bytes_48;
               K_OK    : Boolean;
               R_Half  : Byte_Seq (0 .. 47);
               S_Half  : Byte_Seq (0 .. 47);
            begin
               --  RFC 6979 deterministic nonce (HMAC-SHA-384 DRBG).
               SPARKTLSCrypto.RFC6979.Derive_K_P384
                 (D => Bytes_48 (Id.ECDSA_P384_Key), H => Bytes_48 (H), K => K_Bytes, OK => K_OK);
               if not K_OK then
                  Sig_OK := False;
                  return;
               end if;
               SPARKTLSCrypto.P384.ECDSA.Sign
                 (Hash  => H,
                  D     => Byte_Seq (Id.ECDSA_P384_Key),
                  K     => Byte_Seq (K_Bytes),
                  R_Out => R_Half,
                  S_Out => S_Half,
                  OK    => Sig_OK);
               if Sig_OK then
                  ECDSA_To_DER (R_Half, S_Half, 48, Sig, Sig_Len);
               end if;
            end;

         when Sig_RSA_PSS_SHA256 =>
            Algo_Enum := RFLX.Tls_Parameters.Rsa_Pss_Rsae_Sha256;
            declare
               use SPARKTLSCrypto.Hashing.SHA256;
               H    : constant Digest := Hash (Content (0 .. Content_Len - 1));
               Salt : Bytes_32;
            begin
               Random.all (Byte_Seq (Salt));
               SPARKTLSCrypto.RSA.Sign_PSS
                 (M_Hash    => Byte_Seq (H),
                  Hash_Len  => 32,
                  Hash_Alg  => SPARKTLSCrypto.RSA.PSS_SHA256,
                  Modulus   => Id.RSA_Modulus,
                  Mod_Len   => Id.RSA_Mod_Len,
                  Priv_Exp  => Id.RSA_Priv_Exp,
                  Salt      => Byte_Seq (Salt),
                  Signature => Sig,
                  Sig_Len   => Sig_Len,
                  OK        => Sig_OK);
            end;

         when Sig_RSA_PSS_SHA384 =>
            Algo_Enum := RFLX.Tls_Parameters.Rsa_Pss_Rsae_Sha384;
            declare
               use SPARKNaCl.Hashing.SHA384;
               H    : constant Digest := Hash (Content (0 .. Content_Len - 1));
               Salt : Bytes_48;
            begin
               Random.all (Byte_Seq (Salt));
               SPARKTLSCrypto.RSA.Sign_PSS
                 (M_Hash    => Byte_Seq (H),
                  Hash_Len  => 48,
                  Hash_Alg  => SPARKTLSCrypto.RSA.PSS_SHA384,
                  Modulus   => Id.RSA_Modulus,
                  Mod_Len   => Id.RSA_Mod_Len,
                  Priv_Exp  => Id.RSA_Priv_Exp,
                  Salt      => Byte_Seq (Salt),
                  Signature => Sig,
                  Sig_Len   => Sig_Len,
                  OK        => Sig_OK);
            end;

         when Sig_RSA_PSS_SHA512 =>
            Algo_Enum := RFLX.Tls_Parameters.Rsa_Pss_Rsae_Sha512;
            declare
               use SPARKNaCl.Hashing.SHA512;
               H    : constant Digest := Hash (Content (0 .. Content_Len - 1));
               Salt : Bytes_64;
            begin
               Random.all (Byte_Seq (Salt));
               SPARKTLSCrypto.RSA.Sign_PSS
                 (M_Hash    => Byte_Seq (H),
                  Hash_Len  => 64,
                  Hash_Alg  => SPARKTLSCrypto.RSA.PSS_SHA512,
                  Modulus   => Id.RSA_Modulus,
                  Mod_Len   => Id.RSA_Mod_Len,
                  Priv_Exp  => Id.RSA_Priv_Exp,
                  Salt      => Byte_Seq (Salt),
                  Signature => Sig,
                  Sig_Len   => Sig_Len,
                  OK        => Sig_OK);
            end;

         when others =>
            return;
      end case;

      --  All sign-OK paths produce non-zero Sig_Len (Ed25519: 64,
      --  ECDSA: ECDSA_To_DER yields >= 8, RSA: Mod_Len). Reject the
      --  pathological path so the RFLX builder sees a non-empty
      --  signature.
      if not Sig_OK or else Sig_Len = 0 then
         return;
      end if;

      declare
         Body_Len : constant N32 := 4 + Sig_Len;
         Msg_Len  : constant N32 := 4 + Body_Len;
         Buf      : RBT.Bytes_Ptr;
         Ctx      : Context;
      begin
         if Msg_Len > N32 (Result'Length) then
            return;
         end if;

         Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
         Initialize (Ctx, Buf);
         Set_Algorithm (Ctx, Algo_Enum);
         Set_Signature_Length (Ctx, RFLX.TLS_Handshake.Signature_Length (Sig_Len));
         pragma Assert (Field_Size (Ctx, F_Signature) = RBT.Bit_Length (Sig_Len) * RBT.Byte'Size);
         declare
            Signature_Data : constant RBT.Bytes := To_RFLX (Sig (0 .. Sig_Len - 1));
         begin
            pragma Assert (Signature_Data'Length = RBT.Length (Sig_Len));
            pragma Assert (Valid_Length (Ctx, F_Signature, Signature_Data'Length));
            Set_Signature (Ctx, Signature_Data);
         end;
         Take_Buffer (Ctx, Buf);

         Result (0) := HS_Msg_Wire (HT_Certificate_Verify);
         Result (1) := 16#00#;
         Result (2) := Byte (Body_Len / 256);
         Result (3) := Byte (Body_Len mod 256);
         Result (4 .. 4 + Body_Len - 1) := To_NaCl (Buf.all (1 .. RBT.Index (Body_Len)));

         RFLX_Free (Buf);
         Len := Msg_Len;
      end;
   end Build_Certificate_Verify;

   ------------------------------------------------------------------
   --  RFC 8446 4.4.2 TLS 1.3 Certificate parser (via RFLX)
   ------------------------------------------------------------------

   procedure Parse_Certificate_Chain_13
     (HC                     : in out Engaged_Context;
      D                      : in out SPARKTLS.HS_Pool.HS_Data;
      HS_Msg                 : in Byte_Seq;
      Reject_Cert_Extensions : in Boolean;
      OK                     : out Boolean;
      Err                    : out Error_Code)
   is
      package C13 renames RFLX.TLS_Handshake.Certificate;
      package C13_Entries renames RFLX.TLS_Handshake.Certificate_Entries;
      package C13_Entry renames RFLX.TLS_Handshake.Certificate_Entry;
      Body_Len                : constant N32 := N32 (HS_Msg'Length) - 4;
      Buf                     : RBT.Bytes_Ptr;
      Ctx                     : C13.Context;
      Cert_Idx                : Natural := 0;
      Ext_Reject              : Boolean := False;
      Saved_Client_HS_Counter : constant Unsigned_64 := HC.Client_HS.Counter
      with Ghost;
   begin
      D.Peer_Leaf.Present := False;
      D.Peer_Leaf.DER_Len := 0;
      D.Peer_Int_Count := 0;
      OK := False;
      Err := Decode_Error;
      pragma Assert (HC.Client_HS.Counter = Saved_Client_HS_Counter);

      --  Minimum body: ctx_len(1) + cert_list_len(3) = 4 bytes.
      if Body_Len < 4 then
         pragma Assert (HC.Client_HS.Counter = Saved_Client_HS_Counter);
         return;
      end if;

      declare
         Ctx_Len : constant N32 := N32 (HS_Msg (HS_Msg'First + 4));
      begin
         if Ctx_Len > Body_Len - 4 then
            pragma Assert (HC.Client_HS.Counter = Saved_Client_HS_Counter);
            return;
         end if;

         declare
            List_Off : constant N32 := HS_Msg'First + 5 + Ctx_Len;
            List_Len : constant N32 :=
              N32 (HS_Msg (List_Off)) * 65536 + N32 (HS_Msg (List_Off + 1)) * 256
              + N32 (HS_Msg (List_Off + 2));
         begin
            if List_Len /= Body_Len - 4 - Ctx_Len then
               pragma Assert (HC.Client_HS.Counter = Saved_Client_HS_Counter);
               return;
            end if;
         end;
      end;

      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      Buf.all := To_RFLX (HS_Msg (HS_Msg'First + 4 .. HS_Msg'First + 4 + Body_Len - 1));
      C13.Initialize (Ctx, Buf, Written_Last => RBT.Bit_Length (Body_Len) * 8);
      C13.Verify_Message (Ctx);

      if not C13.Well_Formed_Message (Ctx) then
         C13.Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         pragma Assert (HC.Client_HS.Counter = Saved_Client_HS_Counter);
         return;
      end if;

      --  Walk certificate entries. Sequence iteration follows the
      --  RFLX message-sequence pattern: Switch â loop Has_Element â
      --  Switch / Verify_Message / Update.
      declare
         use type RBT.Bit_Length;
      begin
         if C13.Field_Size (Ctx, C13.F_Certificate_List) > 0 then
            declare
               Entries_Ctx : C13_Entries.Context;
            begin
               if not C13.Has_Buffer (Ctx) then
                  pragma Assert (HC.Client_HS.Counter = Saved_Client_HS_Counter);
                  return;
               end if;
               if not (C13.Valid_Next (Ctx, C13.F_Certificate_List)
                       and then C13.Field_First (Ctx, C13.F_Certificate_List) rem RBT.Byte'Size = 1
                       and then C13.Available_Space (Ctx, C13.F_Certificate_List)
                                >= C13.Field_Size (Ctx, C13.F_Certificate_List)
                       and then C13.Field_Condition (Ctx, C13.F_Certificate_List))
               then
                  C13.Take_Buffer (Ctx, Buf);
                  RFLX_Free (Buf);
                  pragma Assert (HC.Client_HS.Counter = Saved_Client_HS_Counter);
                  return;
               end if;
               C13.Switch_To_Certificate_List (Ctx, Entries_Ctx);

               while C13_Entries.Has_Element (Entries_Ctx) and then Cert_Idx <= Max_Pool_Size loop
                  pragma Loop_Invariant (C13_Entries.Has_Buffer (Entries_Ctx));
                  pragma Loop_Invariant (C13_Entries.Valid (Entries_Ctx));
                  pragma Loop_Invariant (HC.Client_HS.Counter = Saved_Client_HS_Counter);
                  pragma Loop_Invariant (Hash_Len (HC.Neg) = Hash_Len (HC.Neg)'Loop_Entry);
                  pragma
                    Loop_Invariant (if HC.Cfg.Local'Loop_Entry /= null then HC.Cfg.Local /= null);
                  pragma
                    Loop_Invariant
                      (if HC.Cfg.Local'Loop_Entry /= null
                           and then HC.Cfg.Local'Loop_Entry.Has_Identity
                         then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity);
                  pragma
                    Loop_Invariant
                      (if HC.Cfg.Local'Loop_Entry /= null
                           and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
                                      (HC.Cfg.Local'Loop_Entry)
                         then
                           HC.Cfg.Local /= null
                           and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
                                      (HC.Cfg.Local));
                  pragma
                    Loop_Invariant (if HC.Cfg.Random'Loop_Entry /= null then HC.Cfg.Random /= null);
                  declare
                     E_Ctx : C13_Entry.Context;
                  begin
                     C13_Entries.Switch (Entries_Ctx, E_Ctx);
                     C13_Entry.Verify_Message (E_Ctx);

                     if C13_Entry.Well_Formed_Message (E_Ctx) then
                        if C13_Entry.Valid (E_Ctx, C13_Entry.F_Cert_Data_Length)
                          and then C13_Entry.Valid (E_Ctx, C13_Entry.F_Extensions_Length)
                          and then C13_Entry.Well_Formed (E_Ctx, C13_Entry.F_Cert_Data)
                          and then C13_Entry.Valid_Next (E_Ctx, C13_Entry.F_Cert_Data)
                        then
                           declare
                              C_Len : constant N32 := N32 (C13_Entry.Get_Cert_Data_Length (E_Ctx));
                           begin
                              --  RFC 8446 4.4.2 per-cert extensions
                              --  policy check (client only).
                              if Reject_Cert_Extensions
                                and then N32 (C13_Entry.Get_Extensions_Length (E_Ctx)) > 0
                              then
                                 Ext_Reject := True;
                              end if;
                              if C_Len > 0
                                and then C_Len <= N32 (Max_Cert_DER)
                                and then C13_Entry.Field_Size (E_Ctx, C13_Entry.F_Cert_Data)
                                         = RBT.Bit_Length (C_Len) * RBT.Byte'Size
                                and then RFLX.RFLX_Types.To_Length
                                           (C13_Entry.Field_Size (E_Ctx, C13_Entry.F_Cert_Data))
                                         = RBT.Length (C_Len)
                              then
                                 declare
                                    Cert_RFLX : RBT.Bytes (1 .. RBT.Index (C_Len));
                                 begin
                                    pragma Assert (Cert_RFLX'First = 1);
                                    pragma Assert (Cert_RFLX'Length = RBT.Length (C_Len));
                                    C13_Entry.Get_Cert_Data (E_Ctx, Cert_RFLX);

                                    if Cert_Idx = 0 then
                                       --  Leaf cert
                                       Copy_Cert_To_Peer_DER (Cert_RFLX, D, C_Len);
                                       declare
                                          P_OK : Boolean;
                                       begin
                                          Parse_X509_From_RFLX
                                            (Cert_RFLX, C_Len, D.Peer_Leaf.Cert, P_OK);
                                          pragma Assert (D.Peer_Leaf.DER_Len = X509.N32 (C_Len));
                                          pragma Assert (D.Peer_Leaf.DER_Len > 0);
                                          pragma
                                            Assert
                                              (if P_OK
                                                 then
                                                   X509.Spans_Valid
                                                     (D.Peer_Leaf.Cert, X509.N32 (C_Len) - 1));
                                          pragma
                                            Assert
                                              (if P_OK
                                                 then
                                                   X509.Spans_Valid
                                                     (D.Peer_Leaf.Cert, D.Peer_Leaf.DER_Len - 1));
                                          D.Peer_Leaf.Present :=
                                            P_OK and then X509.Is_Valid (D.Peer_Leaf.Cert);
                                       end;
                                    elsif D.Peer_Int_Count < Max_Pool_Size then
                                       --  Intermediate cert
                                       declare
                                          Idx  : constant Natural := D.Peer_Int_Count;
                                          C    : X509.Certificate;
                                          P_OK : Boolean;
                                       begin
                                          Parse_X509_From_RFLX (Cert_RFLX, C_Len, C, P_OK);
                                          if P_OK and then X509.Is_Valid (C) then
                                             Store_Intermediate
                                               (Cert_RFLX, C, C_Len, D.Peer_Ints (Idx));
                                             D.Peer_Int_Count := D.Peer_Int_Count + 1;
                                          end if;
                                       end;
                                    end if;
                                 end;
                                 Cert_Idx := Cert_Idx + 1;
                              end if;
                           end;
                        end if;
                     end if;

                     C13_Entries.Update (Entries_Ctx, E_Ctx);
                     if not C13_Entries.Has_Buffer (Entries_Ctx) then
                        pragma Assert (HC.Client_HS.Counter = Saved_Client_HS_Counter);
                        return;
                     end if;
                     if not C13_Entries.Valid (Entries_Ctx) then
                        C13_Entries.Take_Buffer (Entries_Ctx, Buf);
                        RFLX_Free (Buf);
                        pragma Assert (HC.Client_HS.Counter = Saved_Client_HS_Counter);
                        return;
                     end if;
                  end;
               end loop;

               C13_Entries.Take_Buffer (Entries_Ctx, Buf);
               RFLX_Free (Buf);
               if Ext_Reject then
                  OK := False;
                  Err := Unsupported_Extension;
               else
                  OK := True;
                  Err := No_Error;
               end if;
               pragma Assert (HC.Client_HS.Counter = Saved_Client_HS_Counter);
               return;
            end;
         end if;
      end;

      C13.Take_Buffer (Ctx, Buf);
      RFLX_Free (Buf);

      if Ext_Reject then
         OK := False;
         Err := Unsupported_Extension;
      else
         OK := True;
         Err := No_Error;
      end if;
      pragma Assert (HC.Client_HS.Counter = Saved_Client_HS_Counter);
   end Parse_Certificate_Chain_13;

end SPARKTLS.Handshake.TLS13;
