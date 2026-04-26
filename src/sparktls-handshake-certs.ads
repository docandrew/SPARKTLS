with SPARKNaCl; use SPARKNaCl;
with Interfaces; use Interfaces;
with X509;
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
               and then N32 (Result'Length) >= Cert_Len + 16;

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
                       Id.Ints (I).DER_Len <= X509.N32 (Max_Cert_DER));

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
               and then (Transcript_Hash'Length = 32
                         or Transcript_Hash'Length = 48)
               and then Random /= null
               and then Id.RSA_Mod_Len in 64 .. 512
               and then SPARKTLSCrypto.P384.Field.Initialized
               and then SPARKTLSCrypto.P384.ECDSA.Initialized;

end SPARKTLS.Handshake.Certs;
