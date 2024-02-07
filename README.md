# SparkTLS

SparkTLS is a proof-of-concept project in Ada that utilizes pure SPARK/Ada to perform TLS 1.3 handshakes and communication.

**Note: This project is still in its early stages of development and is not suitable for production use at this time.**

## Overview

SparkTLS aims to demonstrate the capabilities of SPARK/Ada in the context of secure communication 
using the TLS 1.3 protocol. By leveraging the strong static analysis and formal verification features of SPARK/Ada, 
SparkTLS eventually aims to provide a high level of assurance and security in TLS implementations.

## (Someday) Features

- TLS 1.3 handshake implementation
- Crypto provided by SPARKNaCl
- Secure communication using the TLS protocol
- Pure SPARK/Ada implementation for enhanced security and reliability

## Building/Running

Clone the SPARKTLS and SPARKx509 repos:

```sh
git clone https://github.com/docandrew/sparkx509.git    # for the x509 certificate parsing
git clone https://github.com/docandrew/sparktls.git
```

Build the test program with

```sh
cd sparktls
alr build
```

The executable will be `obj/tls`

Today SPARKNaCl can support the ChaCha20-Poly1305-SHA256 cipher suite and has support for ed25519 to
perform signature validation. The code in this repo can start the handshake but only with that
supported cipher suite. You can generate the appropriate certificate (ed25519 signature algo) 
and run a test server with only the supported cipher suite with the following commands:

```sh
cd tests
make tlscert       # generate the self-signed ed25519 certificate for testing
make debugserver   # run's openssl s_server on port 8443 with the generated certificate
```

You can then run `obj/tls` and it will connect to the server and start to perform the handshake.

## Disclaimer

SparkTLS is a proof-of-concept project and is provided "as is" without any warranty. 
Use at your own risk. The code here is still very much a science experiment!
