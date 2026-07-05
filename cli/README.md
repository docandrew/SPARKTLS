# sparktls_cli

`sparktls_cli` is the user-facing command line utility for SPARKTLS
certificate tasks. It can generate private keys, create development
certificates, build self-signed CA or leaf certificates, create and sign CSRs,
inspect certificates, and verify certificate chains.

The CLI is intended for local development, testing, and inspection workflows.
It is not a replacement for a public CA, ACME client, or full certificate
management system.

## Build

From this directory:

```sh
alr -n --no-tty build
```

The executable is written to the parent repository's `bin` directory:

```sh
../bin/sparktls_cli --help
```

## Test

From this directory:

```sh
tests/run.sh
```

The test script builds `sparktls_cli`, runs the main key/certificate/CSR
workflows in a temporary directory, and checks selected help and error paths.

## File Formats

Generation and signing commands write PEM:

- Private keys are written as `-----BEGIN PRIVATE KEY-----`.
- Certificates are written as `-----BEGIN CERTIFICATE-----`.
- CSRs are written as `-----BEGIN CERTIFICATE REQUEST-----`.

The `show` and `verify` commands accept certificates as either PEM or raw DER.

## Algorithms

Key generation supports:

- `ed25519`
- `p256`
- `p384`

Certificate parsing and verification may recognize additional public key and
signature algorithms through the underlying SPARKx509/SPARKTLS code, but the
CLI's key generation path is limited to the algorithms above.

## Commands

### Generate a Private Key

```sh
sparktls_cli generate <algo> key to <file>
```

Example:

```sh
sparktls_cli generate p256 key to server.key
```

### Generate a Development Certificate

```sh
sparktls_cli devcert <name> to <key-file> <cert-file> [options]
```

Options:

- `algo <ed25519|p256|p384>`: key algorithm, default `p256`
- `valid-for <days>`: validity period, default `365`
- `with-san <n1,n2,...>`: extra DNS names or IPv4 addresses

`devcert` automatically includes `<name>`, `localhost`, and `127.0.0.1` as
subject alternative names. The certificate is self-signed and intended as a
development trust anchor.

Example:

```sh
sparktls_cli devcert localhost to server.key server.crt
```

### Create a Self-Signed Certificate

```sh
sparktls_cli create cert for <name> using <key> to <file> [options]
sparktls_cli create ca for <name> using <key> to <file> [options]
```

Options:

- `valid-for <days>`: validity period, default `365`
- `with-san <n1,n2,...>`: DNS names or IPv4 addresses
- `with-org <org>`: organization name

Examples:

```sh
sparktls_cli create ca for "Local Test CA" using ca.key to ca.crt valid-for 3650
sparktls_cli create cert for localhost using server.key to server.crt with-san localhost,127.0.0.1
```

### Sign a Leaf Certificate With a CA

```sh
sparktls_cli sign <leaf-key> with-ca <ca-key> <ca-cert> for <name> to <file> [options]
```

Options:

- `valid-for <days>`: validity period, default `365`
- `with-san <n1,n2,...>`: DNS names or IPv4 addresses
- `with-org <org>`: organization name

Example:

```sh
sparktls_cli sign server.key with-ca ca.key ca.crt for localhost to server.crt with-san localhost,127.0.0.1
```

### Create a CSR

```sh
sparktls_cli create csr for <name> using <key> to <file> [with-san <n1,n2,...>]
```

Example:

```sh
sparktls_cli create csr for localhost using server.key to server.csr with-san localhost,127.0.0.1
```

### Sign a CSR

```sh
sparktls_cli sign-csr <csr.pem> with-ca <ca-key> <ca-cert> to <cert.pem> [valid-for <days>]
```

The current CSR signing path extracts the subject and public key from the CSR.
SAN extraction from CSR extensions is not yet implemented, so add SANs through
the direct `sign` command when SANs are required.

Example:

```sh
sparktls_cli sign-csr server.csr with-ca ca.key ca.crt to server.crt valid-for 90
```

### Show a Certificate

```sh
sparktls_cli show <cert.pem|cert.der> [--brief]
```

`show` prints certificate fields, validity, public key information, extensions,
and structural validation results. Use `--brief` or `-b` for a compact summary.

Example:

```sh
sparktls_cli show server.crt --brief
```

### Verify a Certificate Chain

```sh
sparktls_cli verify <cert.pem|cert.der> --ca <ca.pem|ca.der> [--ca <int.pem|int.der>] [--host <name>]
```

Provide the end-entity certificate first, followed by one or more issuer
certificates with `--ca`. The order of `--ca` certificates should follow the
chain from the leaf issuer toward the trust anchor. Use `--host` to check the
leaf certificate's subject alternative names.

Example:

```sh
sparktls_cli verify server.crt --ca ca.crt --host localhost
```

## Example Local CA Workflow

```sh
sparktls_cli generate p256 key to ca.key
sparktls_cli create ca for "Local Test CA" using ca.key to ca.crt valid-for 3650

sparktls_cli generate p256 key to server.key
sparktls_cli sign server.key with-ca ca.key ca.crt for localhost to server.crt with-san localhost,127.0.0.1

sparktls_cli verify server.crt --ca ca.crt --host localhost
```

## Exit Status

- `0`: command succeeded
- `1`: command ran but the requested operation failed, such as invalid input or
  failed verification
- `2`: command line usage error
