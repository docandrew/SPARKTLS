with SPARKNaCl; use SPARKNaCl;
with SPARKTLSCrypto.P384.Field;

--  TLS 1.3 Client Handshake Messages
--
--  Build ClientHello and parse ServerHello.
package SPARKTLS.Handshake.Client_Msgs with
   SPARK_Mode => On
is
   --  Maximum ClientHello size
   Max_Client_Hello : constant := 1024;

   --  Build a TLS 1.3 ClientHello handshake message.
   --  Returns the complete handshake message (type + length + body)
   --  ready to be wrapped in a TLS record.
   --
   --  Retry_Mode=False (default): build the initial CH (CH1) —
   --  fresh random, session_id, ephemeral X25519/P-256/P-384
   --  keypairs, all three key_share entries, no cookie extension.
   --
   --  Retry_Mode=True (RFC 8446 §4.1.4 HRR retry, CH2):
   --   * reuse HC.Client_Random, HC.Legacy_Session_ID, and the
   --     ephemeral SKs from CH1 (key_share PKs are re-derived).
   --   * if HC.HRR_Selected_Group is set (X25519/P-256/P-384),
   --     emit only that group's key_share.
   --   * if HC.HRR_Cookie_Len > 0, append the cookie extension
   --     (RFC 8446 §4.2.2).
   procedure Build_Client_Hello
     (S          : in     Session;
      HC         : in out Handshake_Context;
      Result     :    out Byte_Seq;
      Len        :    out N32;
      Retry_Mode : in     Boolean := False)
		   with Pre  => Result'First = 0
		                and then Result'Last in Max_Client_Hello - 1 .. N32'Last - 1
		                and then HC.Cfg.Random /= null
		                and then SPARKTLSCrypto.P384.Field.Initialized
		                and then HC.HRR_Cookie_Len <=
		                  N32 (HC.HRR_Cookie'Length)
	                and then
	                  (if Retry_Mode
	                   then HC.HRR_Cookie_Len <= N32 (HC.HRR_Cookie'Length))
		                and then
		                  (if HC.Cfg.TLS12_Resume_Ticket.Valid
		                   then HC.Cfg.TLS12_Resume_Ticket.Ticket_Len
		                        <= Max_TLS12_Ticket_Len)
		                and then Reasm_Coherent (HC),
					        Post => (if HC.Cfg.Random'Old /= null
					                          then HC.Cfg.Random /= null)
						                and then HC.HRR_Cookie_Len = HC.HRR_Cookie_Len'Old
		                and then HC.Sent_HRR_CCS = HC.Sent_HRR_CCS'Old
		                and then Reasm_Coherent (HC)
		                and then HC.Reasm_Len = HC.Reasm_Len'Old
		                and then HC.Reasm_Need = HC.Reasm_Need'Old
		                and then HC.Reasm_Hdr_Pending =
		                  HC.Reasm_Hdr_Pending'Old;

   --  Parse a ServerHello from raw handshake message bytes.
   --  Extracts: server random, cipher suite, key share (server public key).
	   procedure Parse_Server_Hello
	     (S    : in out Session;
	      HC   : in out Handshake_Context;
	      Data : in     Byte_Seq;
	      OK   :    out Boolean)
			   with Pre => Data'Length > 0
			               and then SPARKTLSCrypto.P384.Field.Initialized
			               and then HC.HRR_Cookie_Len <=
			                 N32 (HC.HRR_Cookie'Length)
			               and then Reasm_Coherent (HC),
										        Post =>
										                  (if OK
										                     or else
										                       S.Last_Error = No_Error
										                   then
										                     (if HC.Cfg.Random'Old /= null
										                      then HC.Cfg.Random /= null)
										                     and then HC.Transcript_Len =
										                       HC.Transcript_Len'Old
										                     and then HC.HRR_Cookie_Len <=
										                       N32 (HC.HRR_Cookie'Length)
										                     and then Reasm_Coherent (HC))
											                and then
											                  (if OK
											                   and then HC.Version = TLS_1_3
										                   then S.Negotiated_Suite in
										                     Suite_AES_128_GCM_SHA256
									                   | Suite_AES_256_GCM_SHA384
									                   | Suite_CHACHA20_POLY1305_SHA256)
												                ;

end SPARKTLS.Handshake.Client_Msgs;
