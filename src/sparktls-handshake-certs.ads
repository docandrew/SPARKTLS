with SPARKNaCl; use SPARKNaCl;
with Interfaces; use Interfaces;

--  TLS 1.3 Certificate Handshake Messages
--
--  Build Certificate, CertificateChain, and CertificateVerify messages.
--  Shared between client (mTLS) and server.
package SPARKTLS.Handshake.Certs with
   SPARK_Mode => On
is
   --  Build a Certificate handshake message wrapping a single DER cert.
   procedure Build_Certificate
     (Cert_DER : in     Byte_Seq;
      Cert_Len : in     N32;
      Result   :    out Byte_Seq;
      Len      :    out N32)
   with Pre => Result'First = 0
               and N32 (Result'Length) >= Cert_Len + 16
               and Cert_DER'First = 0
               and Cert_Len > 0;

   --  Build a Certificate message with leaf + intermediates from an Identity.
   procedure Build_Certificate_Chain
     (Id     : in     Identity;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre => Result'First = 0 and N32 (Result'Length) >= 16;

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
               and N32 (Result'Length) >= 524
               and Transcript_Hash'First = 0
               and (Transcript_Hash'Length = 32
                    or Transcript_Hash'Length = 48);

end SPARKTLS.Handshake.Certs;
