# Attack-class coverage

What this document is for: a single place that answers, for every class of
attack that has been mounted against TLS implementations, whether SparkTLS is
exposed to it, what in the code closes it, and which test or proof is the
evidence. The claim it supports is deliberately bounded:

> Modulo features SparkTLS does not implement and behaviour differences it
> documents as intentional, no known TLS implementation attack class applies to
> it, and no memory-safety or logic bug of the kind behind published TLS CVEs is
> present in the proven code. Attacks on the underlying algorithms themselves
> (factoring an RSA modulus, breaking AES) are outside the claim.

Everything below is verifiable from the repository: file and unit names are
the ones in `src/`, evidence names are lanes of `tests/run_all.sh`, baseline
files under `tests/`, or the proof gate `ci/prove.sh`. Dates mark when a gap was
closed so the history in git can be followed.

## 1. Foundations the whole stack rests on

| Property | How | Evidence |
|---|---|---|
| No memory-safety bugs in the library | Every library unit is SPARK with `SPARK_Mode => On`; `gnatprove --level=1` discharges every run-time check (bounds, overflow, initialisation, aliasing) and every contract. No heap in the library; all buffers are fixed-size and index-checked by proof. | `ci/prove.sh` at 0 owned findings (the 5 unowned ones are in upstream SPARKNaCl and RecordFlux-generated code and are listed there). `PROOF_BURNDOWN.md`. |
| Wire parsing is not hand-written | Every TLS message and extension is parsed and built through RecordFlux-generated SPARK code from `specs/*.rflx`; a message is only readable once `Well_Formed_Message` holds. Lists are walked as RFLX sequences and the walker refuses a list that does not tile its declared length (2026-09-15, both roles). | `generated/`, `Parse_CH_Extensions` post-loop check, client-side twins in `sparktls-client-tls13.adb` and `sparktls-client-tls12.adb`; TLS-Anvil length-field families all pass. |
| Adversarial input does not reach undefined behaviour | Checked build (`--checked`) runs the unit, protocol and x509 lanes with all run-time checks and contracts enabled; AFL++ campaign over the handshake parsers with seed replay under checks. | `tests/run_all.sh --checked` in CI; `tests/fuzz/run.sh regress` 0 findings; `SECURITY_BURNDOWN_2026_09.md` fuzz section. |
| Conformance against independent test suites | BoringSSL's BoGo runner (1534 cases), tlsfuzzer (90 scripts, ~2600 conversations), TLS-Anvil (218 enabled tests), x509-limbo (9778), NIST PKITS (249), Wycheproof (5218 vectors), NIST CAVP. Every failure is named in a baseline file with its disposition; an unlisted failure fails CI. | `tests/bogo/EXPECTED_FAILURES.txt`, `tests/protocol/run.sh`, `tests/tlsanvil/EXPECTED_FAILURES.txt`, `tests/x509/*EXPECTED_FAILURES.txt`. |

## 2. Attack classes, by layer

Status legend: **closed** = code prevents it and a test or proof shows so;
**n/a** = the feature the attack needs is not implemented (see section 4);
**policy** = a documented behaviour difference.

### 2.1 Record layer

| Attack class | Status | Mechanism | Evidence |
|---|---|---|---|
| Buffer overflow / over-read on record parsing | closed | Record header parsed by RFLX; fragment bounded by 2^14 (+256 for ciphertext); every index proven in range. | Proof of `sparktls-records.adb`; BoGo `LargeRecord`, `Overflow` cases. |
| AEAD nonce reuse / counter wrap | closed | Per-direction 64-bit counters advance only when a record is emitted or accepted (post-conditions state it); TLS 1.3 rotates keys at 2^23 records (KeyUpdate) and refuses to write at the arithmetic cap; TLS 1.2 fails closed at the cap. | Post of `Build_Encrypted_Record*`; SR-34, SR-47 in `SECURITY_BURNDOWN_2026_09.md`; BoGo `KeyUpdate-*`. |
| Undefined record type / plaintext record after keys | closed | Content types other than 20..23 are refused with unexpected_message in every state; plaintext handshake or alert records after the handshake are refused; a record whose version is outside policy gets protocol_version instead of stalling (2026-09-15: three TLS 1.3 server handlers and six client handlers previously waited for more input). | TLS-Anvil `sendNotDefinedRecordTypes*`, BoGo `CheckRecordVersion-*`; SR-28. |
| Empty-record flood | closed | Empty encrypted application records are counted and capped (`Max_Empty_Records`); zero-length Alert or Handshake content is unexpected_message per RFC 8446 5.4 (2026-09-15). A zero-length record (no content at all) is bad_record_mac when it arrives as application_data under keys (too short for the AEAD tag, RFC 5246 6.2.3.3 / RFC 8446 5.2) and unexpected_message otherwise (RFC 8446 5.1), never record_overflow; `Records.Overflow_Error` is the single decision point. | `Empty_Records_Bounded_RFC_8446_5_2` predicate; tlsfuzzer `empty-alert`. |
| Warning-alert flood | closed | At most 4 non-close_notify warning alerts per connection, then decode_error. | `Warning_Alerts_Bounded_RFC_8446_6_1`; BoGo `SendWarningAlerts-TooMany`. |
| Padding oracle in TLS 1.3 inner plaintext | closed | Padding strip and content-type recovery use mask selection, no data-dependent branch or index. | SR-45; ctgrind `ct_aead_decrypt`. |
| Truncation attack (dropping close_notify) | closed | Orderly close is recorded (`Peer_Closed_Cleanly`) and exposed so applications distinguish a finished stream from a cut one; exactly one close_notify per side (2026-09-15). | `tests/integration/run.sh`; TLS-Anvil `AlertProtocol.closeNotify` (P-256 half). |
| CBC attacks: BEAST, Lucky13, POODLE, SWEET32, RC4 biases | n/a | No CBC, 3DES or RC4 suite exists in the stack; AEAD only. | Suite list in `README.md`. |
| Compression oracles (CRIME) | n/a | No TLS compression; `compression_methods` must be exactly null. | BoGo `NoNullCompression-*`. |

### 2.2 Handshake state machine

| Attack class | Status | Mechanism | Evidence |
|---|---|---|---|
| State-machine confusion (SMACK, skip/duplicate/reorder messages) | closed | Every state transition is a proven `Valid_Transition`; each handler admits exactly the message type its state expects and answers anything else with unexpected_message, including a non-ClientHello first message and a handshake record between ClientKeyExchange and ChangeCipherSpec (2026-09-15: both used to draw decode_error); TLS 1.2 client and server pin per-message seen flags (Certificate, SKE, CertificateRequest, NST once and in RFC 5246 7.3 order). | Proof of `Set_State` contracts; BoGo `SendUnexpected*`, `Duplicate*`; TLS-Anvil `StateMachine.*`; tlsfuzzer `message-skipping`, `message-duplication`; SR-27, SR-32. |
| ChangeCipherSpec injection (CVE-2014-0224) and early CCS | closed | One CCS per direction, accepted only when the state admits it: TLS 1.2 after ClientKeyExchange and CertificateVerify or after the abbreviated server Finished (2026-09-15); TLS 1.3 only at the middlebox-compatibility positions, never before ClientHello or after Finished. | `Single_CCS_RFC_5246_7_1` predicate; BoGo `EarlyChangeCipherSpec-*`; TLS-Anvil `secondChangeCipherSpec*`; tlsfuzzer `multiple-ccs-messages`. |
| Finished forgery / transcript splice | closed | Finished is an HMAC over the running transcript hash under the handshake traffic key; wrong length or wrong value is decrypt_error (RFC 8446 4.4.4); trailing data after Finished is unexpected_message. | BoGo `BadFinished-*`, `TrailingMessageData-*`. |
| Triple Handshake / session identity confusion | closed | TLS 1.2 uses extended_master_secret when the client offers it; a resumption ticket records the EMS state and a session is only resumed when it matches; renegotiation is refused. | BoGo `ExtendedMasterSecret-*`; `sparktls-tickets.adb` flag byte. |
| Renegotiation attacks (CVE-2009-3555) | closed | Client-initiated renegotiation is answered with a no_renegotiation warning and never performed; `renegotiation_info` in an initial ClientHello must be exactly one zero byte (2026-09-15), SCSV honoured. | BoGo `Renegotiate-Server-Forbidden`; TLS-Anvil `RenegotiationExtension.*`. |
| Version downgrade (POODLE-style fallback, TLS 1.3 to 1.2) | closed | The version is decided before the cipher suites are judged, so TLS 1.0/1.1 clients and clients whose supported_versions lists nothing we speak get protocol_version whatever suites they offer (2026-09-15; before that a legacy client with only legacy suites drew handshake_failure); a TLS 1.3-capable server negotiating 1.2 sets the RFC 8446 4.1.3 sentinel in ServerHello.random and the client checks it; supported_versions must tile and is the only source of the version when present. | `Downgrade_Sentinel_Present`; BoGo `Downgrade-*`, `VersionNegotiation*`; tlsfuzzer `downgrade-protection`. |
| Cross-protocol (ALPACA) | closed at the TLS layer | ALPN is enforced strictly (RFC 7301, no_application_protocol when nothing matches) and SNI selects the certificate; the application must require ALPN to close the class end to end. | BoGo `ALPN*`; `tests/integration/run.sh` SNI cases. |
| Selfie / PSK identity misbinding | closed | A PSK is bound to its cipher suite hash; binders are verified over the transcript including HelloRetryRequest; psk_dhe_ke only (no psk_ke). | BoGo `Resume-Server-PSK*`, binder cases; bug #1 in `progress_2026_04_29`. |
| 0-RTT replay | n/a | Early data is not implemented on either side; offered 0-RTT records are skipped (bounded) without disturbing the read counter. | `README.md` Not Supported; SR-33. |
| HelloRetryRequest cookie / second-hello tampering | closed | The second ClientHello must match the first except where RFC 8446 4.1.2 allows; key_share group must equal the selected group; PSK state is reset across HRR. | BoGo `HelloRetryRequest-*`; SR-26, SR-32. |
| Certificate-message and extension length lies | closed | Every list length must tile its container: cipher suites, extensions (ClientHello, EncryptedExtensions, CertificateRequest, NewSessionTicket), supported_versions, supported_groups, psk_key_exchange_modes, ec_point_formats, PSK identities and binders, certificate entries and their extensions, on both roles (2026-09-15 completes the set; the TLS 1.2 client's certificate list previously validated a truncated chain as complete). | TLS-Anvil `*Length*` tests; BoGo `ExtensionTrailingData-*`. |

### 2.3 Key exchange and signatures

| Attack class | Status | Mechanism | Evidence |
|---|---|---|---|
| Invalid-curve attack (CVE-2015-7511 class) | closed | P-256 peer points must carry the 0x04 prefix and satisfy the curve equation; P-384 additionally checks x < p and y < p; the shared secret is computed only after validation, in constant time. | `P256_Decode`, `P384_Public_Key_Valid_Mask`; Wycheproof ECDH vectors. |
| Small-subgroup / low-order X25519 points | closed | The shared secret is checked for all-zero at every call site; low-order inputs mask to zero in `SPARKTLSCrypto.X25519`. | `Shared_Secret_Is_Acceptable_X25519`; SR-25; Wycheproof X25519. |
| Bleichenbacher / ROBOT (RSA key exchange oracle) | n/a | No RSA key exchange; RSA is signature-only. | Suite list. |
| FREAK, Logjam, DROWN (export / DHE / SSLv2) | n/a | No DHE, no export suites, no SSL 2/3. | Suite list; `version-negotiation` classification. |
| PKCS#1 v1.5 signature forgery (Bleichenbacher 2006, BERserk) | closed | The verifier reconstructs the full encoded message and compares it position by position (00, 01, 0xFF padding of at least 8, 00, fixed DigestInfo, hash); it never parses the padding. | `Verify_PKCS1_v1_5` in `sparktlscrypto-rsa.adb`; Wycheproof RSA vectors. |
| RSA-PSS malleability | closed | RFC 8017 9.1.2 verification with salt length equal to the hash length, trailer 0xBC, and a constant-time verdict. | `Verify_PSS`; Wycheproof. |
| ECDSA nonce leakage / reuse | closed | Server signatures use deterministic RFC 6979 nonces; nonce validation is constant time; ECDSA verification runs in constant time over attacker-controlled inputs. | `SPARKTLSCrypto.RFC6979`; ctgrind `ct_rfc6979`, `ct_p256_ecdsa`, `ct_p384_ecdsa`; dudect. |
| Ed25519 malleability | policy | S < L and a canonical R are enforced; a non-canonical A is accepted, the TweetNaCl / RFC 8032 5.1.7 policy, documented in the spec. | SR-49. |
| Signature-algorithm confusion in CertificateVerify / ServerKeyExchange | closed | The scheme must be one the peer offered; an unrepresentable code point (unassigned, SHA-1, rsa_pss_pss) is illegal_parameter on every path: TLS 1.3 server and client CertificateVerify, TLS 1.2 server CertificateVerify and TLS 1.2 client ServerKeyExchange (2026-09-15); rsa_pkcs1 is refused in TLS 1.3; Ed25519 in TLS 1.2 is refused because the raw transcript is not kept. | BoGo `SigningHash-*`, `Verify-*`; tlsfuzzer `tls13-certificate-verify` "is refused" cases. |
| Private-key / certificate mismatch | closed | `Set_Identity` derives the public key from the private key and compares it to the certificate's SPKI; EC scalars are range-checked. | SR-31. |
| Weak or all-zero randomness | partly outside scope | Randomness comes from the application through `Random_Bytes_Fn`; the server rejects an all-zero draw for ECDHE scalars and ticket keys; `sparkentropy` is the reference source. RNG quality itself is the application's responsibility. | SR-46. |

### 2.4 Certificates and identities

| Attack class | Status | Mechanism | Evidence |
|---|---|---|---|
| Chain forgery / missing basicConstraints or keyUsage | closed | Path building is bounded (8 intermediates), every issuer must be a CA with keyCertSign, signatures verified up to a trust anchor, criticality rules enforced. | x509-limbo 9752/9778, PKITS 189/249 with every deviation listed. |
| Name-constraint bypass | closed | dNSName, IP and DN constraints applied to leaf and intermediates; leading-dot and empty-subtree forms handled (2026-09-15: empty permitted/excluded subtrees rejected). | x509-limbo `rfc5280--nc--*`; sparkx509 `tests/nc`. |
| Hostname mismatch / wildcard abuse | closed | Only subjectAltName is matched, wildcards only as a whole left-most label, no CN fallback, IP addresses matched as addresses. | x509-limbo `webpki--san--*`; the public-suffix cases are policy (no PSL shipped). |
| Expired or not-yet-valid certificate | closed | Both bounds checked against the application clock; an unparsable time fails closed (SR-42). | x509-limbo validity cases. |
| Revoked certificate | policy | Stapled OCSP is verified when present, CRLs are checked when the application attaches them, must-staple is enforced, and the policy knob (Ignore / Soft_Fail / Hard_Fail) is documented. The library never fetches revocation data itself. | `README.md` Certificate Validation Policy; SR-43. |
| Client-certificate EKU / purpose confusion | closed | mTLS leaves must carry clientAuth when EKU is present; server leaves serverAuth. | `PRODUCTION_READINESS.md` P0. |
| Signature encoding malleability | closed | BIT STRING unused bits must be zero (SR-41); DER is parsed strictly. | sparkx509 smoke tests. |

### 2.5 Resource exhaustion

| Attack class | Status | Mechanism | Evidence |
|---|---|---|---|
| Handshake-message reassembly bombs | closed | Handshake reassembly is capped at 32 KB; larger ClientHellos are decode_error; per-list DoS caps (`DoS_Caps`) bound cipher suites, groups, key shares and signature algorithms. | tlsfuzzer `large-hello`, `large-number-of-extensions`; TLS-Anvil `manyGroupsOffered`. |
| Handshake-slot starvation | closed | 16 in-flight handshake contexts (`Max_Inflight`); `Drop` releases an abandoned session; the examples enforce handshake and idle deadlines. | `tests/integration/abandoned_handshakes.py`, `silent_connections.py`. |
| Certificate-chain bombs | closed | 8 intermediates (`Max_Pool_Size`), 8 KB per certificate (`Max_Cert_DER`); more is refused. | x509-limbo bettertls path-building cases (fail closed). |
| Extension count / duplicate extensions | closed | Duplicates are illegal_parameter; a 65th extension is decode_error. | SR-38, SR-40; BoGo `DuplicateExtension*`. |

### 2.6 Side channels

| Attack class | Status | Mechanism | Evidence |
|---|---|---|---|
| Timing leaks in symmetric crypto, key schedule, HMAC | closed | Branch-free kernels; every kernel runs under valgrind with secrets poisoned (ctgrind) and under the optimised build with rdtsc statistics (dudect); both lanes carry a canary with a planted leak that must be flagged. | `ci/timing.sh all` in CI; `tests/ctgrind/`. |
| Timing leaks in ECDH / ECDSA | closed | Constant-time field and point arithmetic; ctgrind and dudect over P-256, P-384, X25519, Ed25519 and RFC 6979. | as above; `ct_findings.md` history. |
| RSA CRT timing | policy | The CRT signer has three classified data-dependent sites (the fault-check compare); dudect measures no key-dependent timing between two RSA-2048 keys, and verify-after-sign guards against fault attacks. | `ct_rsa_sign_crt` (3 expected sites); `dudect_rsa_sign`. |
| Bleichenbacher-style padding timing | n/a | No RSA decryption path exists. | |
| Lucky13-style MAC timing | n/a | No MAC-then-encrypt suites. | |

## 3. Behaviour differences that are intentional

Each is documented next to its baseline entry; none is an open bug.

- Record-layer version must be 0x0301..0x0304 after the initial ClientHello
  (BoringSSL policy, BoGo `CheckRecordVersion`; RFC 8446 5.1 says receivers
  ignore the field). tlsfuzzer's post-ClientHello records at 0x0300 draw
  protocol_version.
- KeyUpdate replies are sent before the next application-data record, not on
  their own (RFC 8446 4.6.3 allows it; BoGo `KeyUpdate-Requested*` requires
  it). TLS-Anvil `KeyUpdate.respondsWithValidKeyUpdate` and two tlsfuzzer
  conversations expect an immediate reply.
- TLS 1.2 without a signature_algorithms extension signs with SHA-256, not the
  RFC 5246 SHA-1 default (RFC 9155).
- With a P-256 certificate, a TLS 1.2 client listing only X25519 in
  supported_groups gets handshake_failure (RFC 8422 5.3).
- The Public Suffix List is not shipped, so wildcard certificates for public
  suffixes are accepted (x509-limbo `webpki--san--public-suffix-*`).
- CN is never used for hostname matching (x509-limbo `webpki--cn--*`).
- A Finished message of the wrong length is decrypt_error, following RFC 8446
  4.4.4 and BoGo, where tlsfuzzer expects decode_error.

## 4. Not implemented (attacks needing these do not apply)

TLS 1.0/1.1, SSL 2/3, DTLS, QUIC; RSA key exchange, DHE, CBC, 3DES, RC4, NULL,
CCM and export suites; compression; heartbeat (the extension is ignored and a
heartbeat record is an undefined content type); renegotiation; 0-RTT early
data; TLS 1.2 session-ID resumption (tickets only); external PSKs and psk_ke;
certificate compression (the extension is validated, never used); SHA-1
signatures; ML-DSA certificates (planned with the post-quantum work).

## 5. Outside the library's control

The application's random source, its clock, its trust store and revocation
data, its use of `Peer_Closed_Cleanly` and ALPN, the transport, and the host
(memory disclosure by other processes, speculative-execution channels). The
examples under `examples/` show the intended use of each and are covered by the
CLI and integration lanes.
