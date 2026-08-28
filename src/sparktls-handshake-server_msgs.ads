with SPARKNaCl; use SPARKNaCl;
with Interfaces; use Interfaces;
with SPARKTLS.Records.TLS12;
with SPARKTLSCrypto.P384.Field;
with X509;

--  TLS 1.3 Server Handshake Messages
--
--  Parse ClientHello, build ServerHello, EncryptedExtensions,
--  and CertificateRequest.
package SPARKTLS.Handshake.Server_Msgs with
   SPARK_Mode => On
is
   --  Needed because Session is now a private type: contracts that used to
   --  say S.State'Old now say State (S)'Old, and Ada only permits 'Old on a
   --  function call in a potentially-unevaluated context (inside an "if" in
   --  a postcondition) when this pragma is present. The accessors are
   --  precondition-free expression functions over one component each, so
   --  evaluating them unconditionally is harmless. Same pragma RecordFlux
   --  emits in its own generated specs.
   pragma Unevaluated_Use_Of_Old (Allow);
   --  Maximum ServerHello size
   Max_Server_Hello : constant := 256;

   --  Defined as membership in the predicated subtype rather than by
   --  restating its conjuncts. Config.Local now has subtype
   --  Valid_Identity_Access, so Local_Config_Valid (HC.Cfg.Local) unfolds to
   --  a membership test that holds by construction. Written as a second
   --  literal conjunction it did not: the prover had to match two
   --  independent copies of the same predicate and could not.
   function Local_Config_Valid (Local : Identity_Access) return Boolean is
     (Local in Valid_Identity_Access)
   with Ghost;

   --  Parse a ClientHello from raw handshake message bytes.
   --  Extracts: client_random, legacy_session_id, cipher suites offered,
   --  key share (client public key).
   --  Selects the best cipher suite we support.
   --
   --  Pre bounds Data'Length by Max_HS_Msg (the wire-message limit
   --  enforced by the record-layer reassembler). Without this bound
   --  the body-length conversion and bit-length multiplications inside
   --  could overflow N32.
   procedure Parse_Client_Hello
     (S    : in out Session;
      HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
              OK   :    out Boolean)
                                                              with Pre => Data'Length > 0
                                                                                 and then Data'Last <= N32 (Max_HS_Msg) - 1,
                    Post => (if HC.Cfg.Local'Old /= null
                              then HC.Cfg.Local /= null
                                   and then
                                     (if HC.Cfg.Local'Old.Has_Identity
                                      then HC.Cfg.Local.Has_Identity))
                            and then
                              (if HC.Cfg.Random'Old /= null
                               then HC.Cfg.Random /= null)
                                    and then State (S) = State (S)'Old
                                    and then Role (S) = Role (S)'Old
                                    and then Input (S).Read_Pos =
                                      Input (S).Read_Pos'Old
                                    and then Input (S).Write_Pos =
                                      Input (S).Write_Pos'Old
                                                            and then
                                      (if OK and then HC.Version = TLS_1_3
                                       then Negotiated_Suite (S) in
                                         Suite_AES_128_GCM_SHA256
                                       | Suite_AES_256_GCM_SHA384
                                       | Suite_CHACHA20_POLY1305_SHA256);

   --  Build a ServerHello handshake message.
   --  Includes key_share and supported_versions extensions.
   --  Returns the complete handshake message ready for record wrapping.
   procedure Build_Server_Hello
     (S      : in     Session;
      HC     : in out Engaged_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre  => Result'First = 0
                and then Result'Last in Max_Server_Hello - 1 .. N32'Last - 1
                and then HC.Cfg.Random /= null
                                and then Negotiated_Suite (S) in Suite_AES_128_GCM_SHA256
                                                       | Suite_AES_256_GCM_SHA384
                                                       | Suite_CHACHA20_POLY1305_SHA256,
           Post => Len <= N32 (Result'Length)
                   and then (if Len > 0 then Len >= 4)
                   and then HC.Cfg.Random /= null
                   and then
                     (if Local_Config_Valid (HC.Cfg.Local'Old)
                      then Local_Config_Valid (HC.Cfg.Local))
                           and then (if HC.Cfg.Local'Old /= null
                                     then HC.Cfg.Local /= null)
                                   and then (if HC.Cfg.Local'Old /= null
                                                 and then HC.Cfg.Local'Old.Has_Identity
                                             then HC.Cfg.Local /= null
                                                  and then HC.Cfg.Local.Has_Identity);

   function Has_ALPN_Match (HC : Handshake_Context) return Boolean;

   --  Exported for the TLS 1.2 ServerHello builder (was a byte-identical
   --  _12 clone in Handshake.TLS12; deleted 2026-08-27).
   function Select_ALPN (HC : Handshake_Context) return Hostname_Buf;

   --  RFC 8446 Section 4.3.1: Build EncryptedExtensions.
   --  Sent immediately after ServerHello (encrypted with HS keys).
   --  May include ALPN extension if client offered and server matches.
   --
   --  Body writes S.Negotiated_ALPN on a successful match but never
   --  touches State (S); the frame post lets callers preserve their
   --  State (S) knowledge through the call so the surrounding flight
   --  builder can keep proving its Set_State / Send_Alert_And_Error
   --  preconditions.
   procedure Build_Encrypted_Extensions
     (HC     : in     Engaged_Context;
      S      : in out Session;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre  => Result'First = 0
                and then Result'Last in 271 .. N32'Last - 1,
   --  Header(4) + ext_list_len(2) + SNI ack(4)
   --  + ALPN ext(7 + Max_Hostname_Len=255) = 272
        Post => State (S) = State (S)'Old
                and then Role (S) = Role (S)'Old
                and then Negotiated_Suite (S) = Negotiated_Suite (S)'Old
                and then (if Role (S)'Old = Role_Server
                          and then State (S)'Old not in
                            Idle | Closing | Closed | Error_State
                          then Role (S) = Role_Server
                               and then State (S) not in
                                 Idle | Closing | Closed | Error_State)
                and then Len in 6 .. N32 (Result'Length);

   --  Build a CertificateRequest handshake message (server -> client).
   --  Minimal: empty certificate_request_context, signature_algorithms
   --  extension listing Ed25519, ECDSA-P256-SHA256, ECDSA-P384-SHA384.
   procedure Build_Certificate_Request
     (Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre => Result'First = 0
               and Result'Last in 31 .. 16#FFFF#,
        Post => Len <= N32 (Result'Length);

end SPARKTLS.Handshake.Server_Msgs;
