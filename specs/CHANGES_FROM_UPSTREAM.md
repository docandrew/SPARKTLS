# Changes from upstream RecordFlux specs

The RFLX message specifications in this directory are taken from
AdaCore's [RecordFlux project](https://github.com/AdaCore/RecordFlux)
(`examples/specs/`), which is licensed under Apache-2.0. See `../NOTICE`
for the full attribution.

All specs are **byte-identical** to upstream except for the changes below.

## tls_handshake.rflx — TLS 1.2 compatibility messages (added)

**Upstream** models TLS 1.3 / DTLS 1.3 only. A complete TLS implementation
also has to handle TLS 1.2 on the wire (RFC 8446 §D allows negotiation
down from 1.3 to 1.2, and real-world peers still default to 1.2).

**Our change**: a new "TLS 1.2 Compatibility Messages" section appended
after the `Key_Update` refinements (before "Server Name Indication
Extension"), declaring three standalone messages:

- `TLS_1_2_New_Session_Ticket` — RFC 5077 §3.3 wire format. Distinct
  from the existing TLS 1.3 `New_Session_Ticket` because the 1.2 form
  has no `ticket_age_add`, no `ticket_nonce`, and no `extensions`
  field. Shares Handshake tag 4 with the 1.3 form, so cannot use a
  `for TLS_Handshake use (Payload => ...)` refinement (RFLX forbids
  duplicate tag refinements); the caller dispatches on protocol
  version.

- `TLS_1_2_Server_Key_Exchange_ECDHE` — RFC 8422 §5.4 wire format for
  the named-curve form. Models the `curve_type = named_curve` branch
  only (a `then ... if Curve_Type = Named_Curve` clause excludes the
  explicit-prime / explicit-char2 variants, which are MUST-NOT for
  modern TLS 1.2). Uses `Tls_Parameters::TLS_SignatureScheme` for the
  digitally-signed-struct algorithm field since the 1.2 {hash,sig}
  pair and the 1.3 SignatureScheme uint16 share the same wire
  encoding.

- `TLS_1_2_Client_Key_Exchange_ECDHE` — RFC 5246 §7.4.7 + RFC 8422
  §5.7 wire format. Only the ECDHE form is modelled; RSA-KX CKE
  (`EncryptedPreMasterSecret`) is intentionally omitted because we
  do not advertise rsa_static cipher suites.

**Why**: extending the spec is preferable to hand-rolling these
messages in SPARK Ada (which we previously did in
`sparktls-handshake-tls12.adb`). RFLX gives us free length-bound
proofs, dispatch-on-curve-type validation, and a single source of
truth for the wire format.

All three messages are declared standalone (no `for TLS_Handshake
use (Payload => ...) if Tag = ...` clause) to keep this deviation
contained to one file — adding the missing TLS 1.2 handshake-type
literals (`Server_Key_Exchange => 12`, `Client_Key_Exchange => 16`)
to `tls_parameters.rflx`'s `TLS_HandshakeType` would be required for
refinements but is not strictly necessary; the caller handles
dispatch already based on the parsed handshake header.

## tls_handshake.rflx — ClientHello compression list length

**Upstream** models the TLS 1.3 `legacy_compression_methods` invariant
directly by constraining `Legacy_Compression_Methods_Length` to `1 .. 1`.

**Our change**: widened `Legacy_Compression_Methods_Length` to `1 .. 255`.

**Why**: TLS 1.2 ClientHello carries `compression_methods<1..2^8-1>`.
SPARKTLS still only negotiates null compression, but TLS 1.2 peers may offer a
larger list as long as null compression is present. TLS 1.3's stricter
single-null requirement is enforced in `Parse_Client_Hello` after
`supported_versions` is parsed.

When regenerating, make sure the generated
`Valid_Legacy_Compression_Methods_Length` predicate also accepts `1 .. 255`.

## tls_handshake.rflx — `Tls_Extension_TLS` Tag constraint

**Upstream** (RecordFlux `main`, around line 94 of the `Tls_Extension_TLS`
message): emits an automatically-generated whitelist condition that
forbids any TLS-1.2-only extension Tag from appearing in a TLS 1.3
ClientHello (about 20 `Tag /= ...Renegotiation_Info`-style clauses).

**Our change**: removed that whitelist; the `Tag` field is now
unconstrained on the `Tls_Extension_TLS` message.

**Why**: real-world TLS 1.3 clients (Chrome, curl, Firefox, OpenSSL
s_client) routinely include TLS-1.2-era extensions in their TLS 1.3
ClientHellos for backward-compatibility reasons. Specifically:

- RFC 8446 Appendix D.1 ("Negotiating with an Older Server") explicitly
  contemplates this — a TLS 1.3-capable client expecting to connect to a
  potentially-older server includes the TLS-1.2 extensions it would have
  needed if the server downgrades.
- RFC 8446 §4.2 ("Extensions") sets the rule for the *server*: it MUST
  ignore any extension it does not recognize. Rejecting them outright at
  the parser layer would prevent a 1.3-only server from accepting any
  real-world client.

Common offenders we observed before removing the whitelist:
`ec_point_formats` (0x000B), `extended_master_secret` (0x0017),
`session_ticket` (0x0023), and `renegotiation_info` (0xFF01).

The change is annotated inline in `tls_handshake.rflx` with the same
RFC reasoning. After regenerating with `rflx generate`, this patch
must be re-applied.
