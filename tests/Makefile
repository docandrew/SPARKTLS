
@PHONY: tlscert
tlscert: openssl-25519.cnf
	@echo
	@echo -----------------------------------------
	@echo Generating Private ED25519 key
	@echo -----------------------------------------
	openssl genpkey -algorithm ED25519 > tlscipher.lan.key

	@echo
	@echo -----------------------------------------
	@echo Creating certificate signing request
	@echo -----------------------------------------
	openssl req -new -out tlscipher.lan.csr -key tlscipher.lan.key -config openssl-25519.cnf
	openssl req -in tlscipher.lan.csr -text -noout

	@echo
	@echo -----------------------------------------
	@echo Self-signing certificate
	@echo -----------------------------------------
	openssl x509 -req -days 700 -in tlscipher.lan.csr -signkey tlscipher.lan.key -out tlscipher.lan.crt
	openssl x509 -in tlscipher.lan.crt -text -noout

	@echo -----------------------------------------
	@echo Run server with:
	@echo openssl s_server -accept 8443 -tls1_3 -key tlscipher.lan.key -cert tlscipher.lan.crt -sigalgs "ed25519" -ciphersuites "TLS_CHACHA20_POLY1305_SHA256" -debug
	@echo OR
	@echo make debugserver

@PHONY: debugserver
debugserver:
	openssl s_server -accept 8443 -tls1_3 -key tlscipher.lan.key -cert tlscipher.lan.crt -sigalgs "ed25519" -ciphersuites "TLS_CHACHA20_POLY1305_SHA256" -debug
