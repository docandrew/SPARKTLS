with SPARKNaCl;  use SPARKNaCl;
with Interfaces; use Interfaces;
with X509;
with SPARKTLS.HS_Pool;
with SPARKTLS.Records;
with SPARKTLS.Handshake.Server_Msgs;
with SPARKTLSCrypto.P384.Field;
with SPARKTLSCrypto.P384.ECDSA;

with SPARKTLS_Transcript;
use type SPARKTLS_Transcript.Transcript_State;
--  TLS 1.3 Certificate Handshake Messages
--
--  Build Certificate, CertificateChain, and CertificateVerify messages.
--  Shared between client (mTLS) and server.
with RFLX.RFLX_Builtin_Types;
use type RFLX.RFLX_Builtin_Types.Index;
use type RFLX.RFLX_Builtin_Types.Length;

package SPARKTLS.Handshake.Certs
  with SPARK_Mode => On
is

   pragma Unevaluated_Use_Of_Old (Allow);
   --  Max wire size of any Certificate handshake message we build.
   --  Header(4) + ListLen(3) + N * (CertLen(3) + Cert + Exts(2))
   --  with N up to Max_Pool_Size + 1 leaf, each cert <= Max_Cert_DER.
   Max_Cert_Msg : constant := 16#100000#;  --  1 MB safety cap

   --  Build a Certificate handshake message wrapping a single DER cert.
   procedure Build_Certificate
     (Cert_DER : in Byte_Seq; Cert_Len : in N32; Result : out Byte_Seq; Len : out N32)
   with
     Pre =>
       Result'First = 0
       and then Result'Last in 15 .. Max_Cert_Msg - 1
       and then Cert_DER'First = 0
       and then Cert_DER'Last in 0 .. N32 (Max_Cert_DER) - 1
       and then Cert_Len in 1 .. Cert_DER'Last + 1
       and then N32 (Result'Length) >= Cert_Len + 16,
     Post => Len <= N32 (Result'Length) and then Len <= SPARKTLS.Records.Max_Fragment;

   --  Build a Certificate message with leaf + intermediates from an Identity.
   procedure Build_Certificate_Chain (Id : in Identity; Result : out Byte_Seq; Len : out N32)
   with
     Pre =>
       Result'First = 0
       and Result'Last in 15 .. Max_Cert_Msg - 1
       and Id.NaCl_Cert_Len <= N32 (Max_Cert_DER)
       and Id.Int_Count <= Max_Pool_Size
       and (for all I in 0 .. Max_Pool_Size - 1 => Id.Ints (I).DER_Len <= X509.N32 (Max_Cert_DER)),
     Post => Len <= N32 (Result'Length);

   --  Build a CertificateVerify handshake message.
   --  Signs the transcript hash with the identity's private key.
   procedure Build_Certificate_Verify
     (Transcript_Hash : in Byte_Seq;
      Id              : in Identity;
      Sig_Algo_Wire   : in Unsigned_16;
      Role            : in TLS_Role;
      Random          : in Random_Bytes_Fn;
      Result          : out Byte_Seq;
      Len             : out N32)
   with
     Pre =>
       Result'First = 0
       and then Result'Last in 523 .. Max_Cert_Msg - 1
       and then Transcript_Hash'First = 0
       and then Transcript_Hash'Last in 31 | 47
       and then (if Sig_Algo_Wire in 16#0804# | 16#0805# | 16#0806#
                 then Random /= null and then Id.RSA_Mod_Len in 64 .. 512),
     Post => Len <= N32 (Result'Length);

   --  RFC 8446 Â§4.4.2 TLS 1.3 Certificate parser. Replaces the
   --  hand-rolled cert chain walker that previously lived (in
   --  near-identical form) at the TLS 1.3 server's Wait_Client_Certificate
   --  arm and at the TLS 1.3 client's HT_Certificate dispatch.
   --
   --  Takes the COMPLETE handshake message bytes (4-byte HS header +
   --  body). Validates the wire structure via
   --  RFLX.TLS_Handshake.Certificate (cert_request_context length-prefixed
   --  + cert_list_length + sequence of CertificateEntry, each
   --  cert_data_length + cert_data + per-cert extensions). Each cert's
   --  DER bytes are then passed to X509.Parse â the wire-parsing and
   --  cert-content-parsing layers stay distinct.
   --
   --  On success: D.Peer_Leaf.Cert holds the leaf cert (if parseable),
   --  D.Peer_Leaf.DER + D.Peer_Leaf.DER_Len hold its DER bytes,
   --  HC.Peer_Ints (0 .. HC.Peer_Int_Count - 1) hold parseable
   --  intermediates, D.Peer_Leaf.Present reflects whether the leaf
   --  parsed AND `X509.Is_Valid` is true. OK := True.
   --
   --  On any wire-format error (malformed RFLX message, length-field
   --  mismatch): OK := False. D.Peer_Leaf.Present := False.
   --
   --  Per-cert X509.Parse failures and intermediate-pool-overflow
   --  do NOT set OK := False â that matches the prior hand-rolled
   --  behavior (let the caller decide what to do with an unparseable
   --  leaf based on D.Peer_Leaf.Present + chain-validation policy).
   --  Reject_Cert_Extensions: TLS 1.3 Â§4.4.2 / BoGo
   --  SendUnknownExtensionOnCertificate-TLS13. Set True on the client
   --  side: the server MAY echo only per-cert extensions the client
   --  requested via the matching CH extension (status_request,
   --  signed_certificate_timestamp, etc.); we request none, so any
   --  non-empty entry is a fatal `unsupported_extension`. Set False
   --  on the server side: we tolerate extensions the client may have
   --  bundled (the server doesn't currently policy them).
   --
   --  Err is meaningful only when OK = False:
   --    Decode_Error           â wire format malformed
   --    Unsupported_Extension  â Reject_Cert_Extensions was --                             a cert entry carried non-empty
   --                             extensions.
   procedure Parse_Certificate_Chain_13
     (HC                     : in out Engaged_Context;
      D                      : in out SPARKTLS.HS_Pool.HS_Data;
      HS_Msg                 : in Byte_Seq;
      Reject_Cert_Extensions : in Boolean;
      OK                     : out Boolean;
      Err                    : out Error_Code)
   with
     Pre => HS_Msg'First = 0 and then HS_Msg'Length >= 4 and then HS_Msg'Length <= Max_Cert_Msg,
     Post =>
       HC.Client_HS.Counter = HC.Client_HS.Counter'Old
       and then Hash_Len (HC.Neg) = Hash_Len (HC.Neg'Old)
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                 then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity)
       and then (if HC.Cfg.Local'Old /= null
                   and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (HC.Cfg.Local'Old)
                 then
                   HC.Cfg.Local /= null
                   and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (HC.Cfg.Local))
       and then (if HC.Cfg.Random'Old /= null then HC.Cfg.Random /= null);

   --  RFC 5246 Â§7.4.2 TLS 1.2 Certificate parser. Takes the complete
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
