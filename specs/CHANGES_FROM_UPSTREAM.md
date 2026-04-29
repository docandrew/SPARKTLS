# Changes from upstream RecordFlux specs

The RFLX message specifications in this directory are taken from
AdaCore's [RecordFlux project](https://github.com/AdaCore/RecordFlux)
(`examples/specs/`), which is licensed under Apache-2.0. See `../NOTICE`
for the full attribution.

All specs are **byte-identical** to upstream except for the change below.

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
