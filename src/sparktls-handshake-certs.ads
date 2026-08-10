with SPARKNaCl; use SPARKNaCl;
with Interfaces; use Interfaces;
with X509;
with SPARKTLS.Records;
with SPARKTLS.Handshake.Server_Msgs;
with SPARKTLSCrypto.P384.Field;
with SPARKTLSCrypto.P384.ECDSA;

--  TLS 1.3 Certificate Handshake Messages
--
--  Build Certificate, CertificateChain, and CertificateVerify messages.
--  Shared between client (mTLS) and server.
package SPARKTLS.Handshake.Certs with
   SPARK_Mode => On
is
   --  Max wire size of any Certificate handshake message we build.
   --  Header(4) + ListLen(3) + N * (CertLen(3) + Cert + Exts(2))
   --  with N up to Max_Pool_Size + 1 leaf, each cert <= Max_Cert_DER.
   Max_Cert_Msg : constant := 16#100000#;  --  1 MB safety cap

   --  Build a Certificate handshake message wrapping a single DER cert.
   procedure Build_Certificate
     (Cert_DER : in     Byte_Seq;
      Cert_Len : in     N32;
      Result   :    out Byte_Seq;
      Len      :    out N32)
   with Pre => Result'First = 0
               and then Result'Last in 15 .. Max_Cert_Msg - 1
               and then Cert_DER'First = 0
               and then Cert_DER'Last in 0 .. N32 (Max_Cert_DER) - 1
               and then Cert_Len in 1 .. Cert_DER'Last + 1
               and then N32 (Result'Length) >= Cert_Len + 16,
        Post => Len <= N32 (Result'Length)
                and then Len <= SPARKTLS.Records.Max_Fragment;

   --  Build a Certificate message with leaf + intermediates from an Identity.
   procedure Build_Certificate_Chain
     (Id     : in     Identity;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre => Result'First = 0
               and Result'Last in 15 .. Max_Cert_Msg - 1
               and Id.NaCl_Cert_Len <= N32 (Max_Cert_DER)
               and Id.Int_Count <= Max_Pool_Size
               and (for all I in 0 .. Max_Pool_Size - 1 =>
                       Id.Ints (I).DER_Len <= X509.N32 (Max_Cert_DER)),
        Post => Len <= N32 (Result'Length);

   --  Build a CertificateVerify handshake message.
   --  Signs the transcript hash with the identity's private key.
   procedure Build_Certificate_Verify
     (Transcript_Hash : in     Byte_Seq;
      Id              : in     Identity;
      Sig_Algo_Wire   : in     Unsigned_16;
      Role            : in     TLS_Role;
      Random          : in     Random_Bytes_Fn;
      Result          :    out Byte_Seq;
      Len             :    out N32)
   with Pre => Result'First = 0
               and then Result'Last in 523 .. Max_Cert_Msg - 1
               and then Transcript_Hash'First = 0
               and then Transcript_Hash'Last in 31 | 47
               and then
                 (if Sig_Algo_Wire in 16#0804# | 16#0805# | 16#0806#
                  then Random /= null
                       and then Id.RSA_Mod_Len in 64 .. 512)
               and then SPARKTLSCrypto.P384.Field.Initialized
               and then SPARKTLSCrypto.P384.ECDSA.Initialized,
        Post => Len <= N32 (Result'Length);

   --  RFC 8446 §4.4.2 TLS 1.3 Certificate parser. Replaces the
   --  hand-rolled cert chain walker that previously lived (in
   --  near-identical form) at the TLS 1.3 server's Wait_Client_Certificate
   --  arm and at the TLS 1.3 client's HT_Certificate dispatch.
   --
   --  Takes the COMPLETE handshake message bytes (4-byte HS header +
   --  body). Validates the wire structure via
   --  RFLX.TLS_Handshake.Certificate (cert_request_context length-prefixed
   --  + cert_list_length + sequence of CertificateEntry, each
   --  cert_data_length + cert_data + per-cert extensions). Each cert's
   --  DER bytes are then passed to X509.Parse — the wire-parsing and
   --  cert-content-parsing layers stay distinct.
   --
   --  On success: HC.Peer_Cert holds the leaf cert (if parseable),
   --  HC.Peer_Cert_DER + HC.Peer_Cert_DER_Len hold its DER bytes,
   --  HC.Peer_Ints (0 .. HC.Peer_Int_Count - 1) hold parseable
   --  intermediates, HC.Peer_Cert_Valid reflects whether the leaf
   --  parsed AND `X509.Is_Valid` is true. OK := True.
   --
   --  On any wire-format error (malformed RFLX message, length-field
   --  mismatch): OK := False. HC.Peer_Cert_Valid := False.
   --
   --  Per-cert X509.Parse failures and intermediate-pool-overflow
   --  do NOT set OK := False — that matches the prior hand-rolled
   --  behavior (let the caller decide what to do with an unparseable
   --  leaf based on HC.Peer_Cert_Valid + chain-validation policy).
   --  Reject_Cert_Extensions: TLS 1.3 §4.4.2 / BoGo
   --  SendUnknownExtensionOnCertificate-TLS13. Set True on the client
   --  side: the server MAY echo only per-cert extensions the client
   --  requested via the matching CH extension (status_request,
   --  signed_certificate_timestamp, etc.); we request none, so any
   --  non-empty entry is a fatal `unsupported_extension`. Set False
   --  on the server side: we tolerate extensions the client may have
   --  bundled (the server doesn't currently policy them).
   --
   --  Err is meaningful only when OK = False:
   --    Decode_Error           — wire format malformed
   --    Unsupported_Extension  — Reject_Cert_Extensions was True and
   --                             a cert entry carried non-empty
   --                             extensions.
   procedure Parse_Certificate_Chain_13
     (HC                     : in out Handshake_Context;
      HS_Msg                 : in     Byte_Seq;
      Reject_Cert_Extensions : in     Boolean;
      OK                     :    out Boolean;
      Err                    :    out Error_Code)
   with Pre => HS_Msg'First = 0
	               and then HS_Msg'Length >= 4
				               and then HS_Msg'Length <= Max_Cert_Msg
				               and then Reasm_Coherent (HC),
			        Post => HC.Client_HS.Counter =
			                  HC.Client_HS.Counter'Old
			                and then HC.Transcript_Len = HC.Transcript_Len'Old
	                and then HC.Hash_Len = HC.Hash_Len'Old
	                and then (if HC.Cfg.Local'Old /= null
	                          then HC.Cfg.Local /= null)
	                and then (if HC.Cfg.Local'Old /= null
	                              and then HC.Cfg.Local'Old.Has_Identity
	                          then HC.Cfg.Local /= null
	                               and then HC.Cfg.Local.Has_Identity)
                   and then
                     (if HC.Cfg.Local'Old /= null
                         and then SPARKTLS.Handshake.Server_Msgs
                           .Local_Config_Valid (HC.Cfg.Local'Old)
                      then HC.Cfg.Local /= null
                           and then SPARKTLS.Handshake.Server_Msgs
                             .Local_Config_Valid (HC.Cfg.Local))
	                and then (if HC.Cfg.Random'Old /= null
	                          then HC.Cfg.Random /= null)
						                and then Reasm_Coherent (HC)
				                  and then HC.Reasm_Len = HC.Reasm_Len'Old
	                  and then HC.Reasm_Need = HC.Reasm_Need'Old
	                  and then
	                    (if HC.Reasm_Len'Old <= HC.Reasm_Need'Old
	                     then HC.Reasm_Len <= HC.Reasm_Need)
	                and then HC.Reasm_Hdr_Pending =
	                  HC.Reasm_Hdr_Pending'Old
		                and then
		                  (if HC.Peer_Cert_Valid
	                   then HC.Peer_Cert_DER_Len in 1 .. Max_Cert_DER_Len
	                        and then X509.Spans_Valid
	                          (HC.Peer_Cert,
	                           X509.N32 (HC.Peer_Cert_DER_Len) - 1));

   --  RFC 5246 §7.4.2 TLS 1.2 Certificate parser. Takes the complete
   --  handshake message bytes (4-byte header + cert_list_len(3) +
   --  entries). On wire-format errors, OK := False and Err := Decode_Error.
   --  X.509 parse failures leave OK = True but HC.Peer_Cert_Valid = False,
   --  matching the TLS 1.3 parser's split between wire syntax and cert
   --  semantic validity.
   procedure Parse_Certificate_Chain_12
     (HC     : in out Handshake_Context;
      HS_Msg : in     Byte_Seq;
      OK     :    out Boolean;
      Err    :    out Error_Code)
   with Pre => HS_Msg'First = 0
		               and then HS_Msg'Length >= 7
		               and then HS_Msg'Length <= Max_Cert_Msg
		               and then Reasm_Coherent (HC),
        Post => HC.Transcript_Len = HC.Transcript_Len'Old
                and then HC.Hash_Len = HC.Hash_Len'Old
                and then (if HC.Cfg.Local'Old /= null
                          then HC.Cfg.Local /= null)
	                and then (if HC.Cfg.Local'Old /= null
	                              and then HC.Cfg.Local'Old.Has_Identity
	                          then HC.Cfg.Local /= null
	                               and then HC.Cfg.Local.Has_Identity)
                   and then
                     (if HC.Cfg.Local'Old /= null
                         and then SPARKTLS.Handshake.Server_Msgs
                           .Local_Config_Valid (HC.Cfg.Local'Old)
                      then HC.Cfg.Local /= null
                           and then SPARKTLS.Handshake.Server_Msgs
                             .Local_Config_Valid (HC.Cfg.Local))
	                and then (if HC.Cfg.Random'Old /= null
	                          then HC.Cfg.Random /= null)
			                and then Reasm_Coherent (HC)
			                and then HC.Reasm_Len = HC.Reasm_Len'Old
                and then HC.Reasm_Need = HC.Reasm_Need'Old
                and then
                  (if HC.Reasm_Len'Old <= HC.Reasm_Need'Old
                   then HC.Reasm_Len <= HC.Reasm_Need)
                and then HC.Reasm_Hdr_Pending =
                  HC.Reasm_Hdr_Pending'Old
                and then
                  (if HC.Peer_Cert_Valid
                   then HC.Peer_Cert_DER_Len in 1 .. Max_Cert_DER_Len
                        and then X509.Spans_Valid
                          (HC.Peer_Cert,
                           X509.N32 (HC.Peer_Cert_DER_Len) - 1));

end SPARKTLS.Handshake.Certs;
