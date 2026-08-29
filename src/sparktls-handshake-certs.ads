with SPARKNaCl;  use SPARKNaCl;
with X509;
with SPARKTLS.HS_Pool;
with SPARKTLS.Handshake.Server_Msgs;

--  Certificate parsing and X.509 storage shared across protocol versions.
--  Version-specific builders and parsers live in Handshake.TLS12 and
--  Handshake.TLS13.
with RFLX.RFLX_Builtin_Types;
use type RFLX.RFLX_Builtin_Types.Index;
use type RFLX.RFLX_Builtin_Types.Length;

package SPARKTLS.Handshake.Certs
  with SPARK_Mode => On
is

   pragma Unevaluated_Use_Of_Old (Allow);
   --  Maximum accepted Certificate handshake message size.
   --  Header(4) + ListLen(3) + N * (CertLen(3) + Cert + Exts(2))
   --  with N up to Max_Pool_Size + 1 leaf, each cert <= Max_Cert_DER.
   Max_Cert_Msg : constant := 16#100000#;  --  1 MB safety cap

   --  RFC 5246 7.4.2 TLS 1.2 Certificate parser. Takes the complete
   --  handshake message bytes (4-byte header + cert_list_len(3) +
   --  entries). On wire-format errors, OK := False and Err := Decode_Error.
   --  X.509 parse failures leave OK = True but D.Peer_Leaf.Present = False,
   --  matching the TLS 1.3 parser's split between wire syntax and cert
   --  semantic validity.
   procedure Parse_Certificate_Chain_12
     (HC     : in out Engaged_Context;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      HS_Msg : in Byte_Seq;
      OK     : out Boolean;
      Err    : out Error_Code)
   with
     Pre => HS_Msg'First = 0 and then HS_Msg'Length >= 7 and then HS_Msg'Length <= Max_Cert_Msg,
     Post =>
       Hash_Len (HC.Neg) = Hash_Len (HC.Neg'Old)
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                 then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity)
       and then (if HC.Cfg.Local'Old /= null
                   and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (HC.Cfg.Local'Old)
                 then
                   HC.Cfg.Local /= null
                   and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (HC.Cfg.Local))
       and then (if HC.Cfg.Random'Old /= null then HC.Cfg.Random /= null);


   --  Shared RFLX-to-X509 copy helpers (were duplicated verbatim in
   --  Client.TLS12; deduplicated 2026-08-27, see task #116).
   procedure Copy_Cert_To_X509
     (Cert_RFLX : in RFLX.RFLX_Builtin_Types.Bytes; Cert_X : out X509.Byte_Seq)
   with
     Pre =>
       Cert_RFLX'First = 1
       and then Cert_X'First = 0
       and then Cert_X'Length > 0
       and then Cert_X'Length <= Max_Cert_DER
       and then Natural (Cert_RFLX'Length) = Cert_X'Length;

   procedure Parse_X509_From_RFLX
     (Cert_RFLX : in RFLX.RFLX_Builtin_Types.Bytes;
      C_Len     : in N32;
      Cert      : out X509.Certificate;
      OK        : out Boolean)
   with
     Pre =>
       C_Len > 0
       and then C_Len <= N32 (Max_Cert_DER)
       and then Cert_RFLX'First = 1
       and then Cert_RFLX'Length = RFLX.RFLX_Builtin_Types.Length (C_Len),
     Post => (if OK then X509.Is_Valid (Cert) and X509.Spans_Valid (Cert, X509.N32 (C_Len) - 1));

   procedure Copy_Cert_To_Peer_DER
     (Cert_RFLX : in RFLX.RFLX_Builtin_Types.Bytes;
      D         : in out SPARKTLS.HS_Pool.HS_Data;
      C_Len     : in N32)
   with
     Pre =>
       Cert_RFLX'First = 1
       and then Cert_RFLX'Length = RFLX.RFLX_Builtin_Types.Length (C_Len)
       and then C_Len > 0
       and then C_Len <= N32 (Max_Cert_DER),
     --  Control-plane framing is AUTOMATIC now: this subprogram
     --  only receives the data-plane record (#106).
     Post => D.Peer_Leaf.DER_Len = X509.N32 (C_Len) and then not D.Peer_Leaf.Present;

   procedure Store_Intermediate
     (Cert_RFLX : in RFLX.RFLX_Builtin_Types.Bytes;
      Cert      : in X509.Certificate;
      C_Len     : in N32;
      Target    : out Pool_Entry)
   with
     Pre =>
       Cert_RFLX'First = 1
       and Cert_RFLX'Length = RFLX.RFLX_Builtin_Types.Length (C_Len)
       and C_Len > 0
       and C_Len <= N32 (Max_Cert_DER)
       and X509.Is_Valid (Cert)
       and X509.Spans_Valid (Cert, X509.N32 (C_Len) - 1);

end SPARKTLS.Handshake.Certs;
