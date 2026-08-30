with SPARKNaCl; use SPARKNaCl;
with Interfaces; use Interfaces;
with X509;
with SPARKTLS.HS_Pool;
with SPARKTLS.Records;
with SPARKTLS.Handshake.Server_Msgs;
with SPARKTLS.Handshake.Certs;

--  TLS 1.3-specific handshake messages (RFC 8446 Section 4).
package SPARKTLS.Handshake.TLS13
  with SPARK_Mode => On
is
   pragma Unevaluated_Use_Of_Old (Allow);

   Max_Server_Hello : constant := 256;
   Max_Cert_Msg     : constant := SPARKTLS.Handshake.Certs.Max_Cert_Msg;

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
      Sig_Algo_Wire   : in Maybe_Sig_Scheme;
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
       and then (if Sig_Algo_Wire in
                      Sig_RSA_PSS_SHA256 | Sig_RSA_PSS_SHA384 | Sig_RSA_PSS_SHA512
                 then Random /= null and then Id.RSA_Mod_Len in 64 .. 512),
     Post => Len <= N32 (Result'Length);

   --  RFC 8446 4.4.2 TLS 1.3 Certificate parser. Replaces the
   --  hand-rolled cert chain walker that previously lived (in
   --  near-identical form) at the TLS 1.3 server's Wait_Client_Certificate
   --  arm and at the TLS 1.3 client's HT_Certificate dispatch.
   --
   --  Takes the COMPLETE handshake message bytes (4-byte HS header +
   --  body). Validates the wire structure via
   --  RFLX.TLS_Handshake.Certificate (cert_request_context length-prefixed
   --  + cert_list_length + sequence of CertificateEntry, each
   --  cert_data_length + cert_data + per-cert extensions). Each cert's
   --  DER bytes are then passed to X509.Parse  the wire-parsing and
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
   --  do NOT set OK := False  that matches the prior hand-rolled
   --  behavior (let the caller decide what to do with an unparseable
   --  leaf based on D.Peer_Leaf.Present + chain-validation policy).
   --  Reject_Cert_Extensions: TLS 1.3 4.4.2 / BoGo
   --  SendUnknownExtensionOnCertificate-TLS13. Set True on the client
   --  side: the server MAY echo only per-cert extensions the client
   --  requested via the matching CH extension (status_request,
   --  signed_certificate_timestamp, etc.); we request none, so any
   --  non-empty entry is a fatal `unsupported_extension`. Set False
   --  on the server side: we tolerate extensions the client may have
   --  bundled (the server doesn't currently policy them).
   --
   --  Err is meaningful only when OK = False:
   --    Decode_Error            wire format malformed
   --    Unsupported_Extension   Reject_Cert_Extensions was --                             a cert entry carried non-empty
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
                   and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (HC.Cfg.Local));
   --  RFC 8446 Section 4.1.3: ServerHello with key_share and
   --  supported_versions extensions. The suite type makes the TLS 1.3
   --  ownership explicit without a separate membership precondition.
   procedure Build_Server_Hello
     (Negotiated : in TLS13_Suite;
      HC         : in out Engaged_Context;
      Result     : out Byte_Seq;
      Len        : out N32)
   with
     Pre =>
       Result'First = 0
       and then Result'Last in Max_Server_Hello - 1 .. N32'Last - 1
       and then HC.Cfg.Random /= null,
     Post =>
       Len <= N32 (Result'Length)
       and then (if Len > 0 then Len >= 4)
       and then HC.Cfg.Random /= null
       and then
         (if SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (HC.Cfg.Local'Old)
          then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (HC.Cfg.Local))
       and then (if HC.Cfg.Local'Old /= null then HC.Cfg.Local /= null)
       and then (if HC.Cfg.Local'Old /= null and then HC.Cfg.Local'Old.Has_Identity
                 then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity);

   --  RFC 8446 Section 4.3.1: EncryptedExtensions, including the
   --  negotiated ALPN and optional server_name acknowledgement.
   procedure Build_Encrypted_Extensions
     (S : in out Session; Result : out Byte_Seq; Len : out N32)
   with
     Pre => Result'First = 0 and then Result'Last in 271 .. N32'Last - 1,
     Post =>
       State (S) = State (S)'Old
       and then Role (S) = Role (S)'Old
       and then Negotiated_Suite (S) = Negotiated_Suite (S)'Old
       and then Len in 6 .. N32 (Result'Length);

   --  RFC 8446 Section 4.3.2: CertificateRequest with an empty context
   --  and the supported TLS 1.3 signature schemes.
   procedure Build_Certificate_Request (Result : out Byte_Seq; Len : out N32)
   with
     Pre => Result'First = 0 and Result'Last in 31 .. 16#FFFF#,
     Post => Len <= N32 (Result'Length);

   --  RFC 8446 Section 4.4.4: Finished contains 32 bytes of
   --  verify_data when the negotiated transcript hash is SHA-256.
   procedure Build_Finished
     (Verify_Data : in Bytes_32;
      Result      : out Byte_Seq;
      Len         : out N32)
   with
     Pre => Result'First = 0 and Result'Last < N32'Last and Result'Last >= 35,
     Post => Len = 36;
end SPARKTLS.Handshake.TLS13;
