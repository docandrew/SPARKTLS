--  SPARKTLS.Revocation -- certificate revocation evidence verifier
--
--  Consumes revocation evidence the TLS layer already holds and returns
--  a verdict; never fetches anything. Two sources:
--
--    * a stapled OCSP response for the leaf (RFC 6960 4.2, delivered by
--      RFC 8446 4.4.2.1 / RFC 6066 8) -- Check_Stapled_OCSP;
--    * application-supplied CRLs (RFC 5280 5)          -- Check_CRLs.
--
--  Both need the leaf's DIRECT issuer certificate: its key signs the
--  CRL and authorizes the OCSP responder (RFC 6960 4.2.2.2). The chain
--  validator reports only the trust anchor, so Find_Issuer locates the
--  issuer among the peer's intermediates and the trust store by name
--  match plus a signature check, without touching the proven chain code.
--
--  OCSP verification follows RFC 6960 3.2 the way Chromium's verifier
--  does: the SingleResponse must match the leaf by serial AND by
--  CertID issuer hashes (SHA-1 when the policy allows it, or SHA-256 /
--  384 / 512), the signer must be the issuer itself or an embedded
--  responder certificate directly issued by the issuer carrying
--  id-kp-OCSPSigning, and the signature must verify over
--  tbsResponseData. Freshness is thisUpdate .. nextUpdate widened by
--  the configured clock skew.
--
--  Verdicts:
--    Rev_Ok           positive "good" evidence.
--    Rev_Revoked      positive "revoked" evidence -- always fatal.
--    Rev_Insufficient no usable evidence (nothing stapled, responder
--                     error, stale, unknown status, CRL for another
--                     issuer, IDP scope excludes the leaf ...). The
--                     Soft_Fail / Hard_Fail policy decides.
--    Rev_Malformed    evidence was present but unparseable or fails
--                     verification (bad signature, unauthorized signer,
--                     unrecognized critical extension). Under Hard_Fail
--                     this is a bad_certificate_status_response; under
--                     Soft_Fail it is treated like Rev_Insufficient.

with Interfaces;
with X509;
with X509.CRL;
with X509.OCSP;

package SPARKTLS.Revocation with
   SPARK_Mode => On
is
   type Revocation_Result is (Rev_Ok, Rev_Revoked, Rev_Insufficient, Rev_Malformed);

   --  Longest CRL / OCSP DER the verifier will process.
   Max_Evidence_Bytes : constant := 64 * 1024 * 1024;

   ----------------------------------------------------------------------------
   --  CRL store
   ----------------------------------------------------------------------------

   --  Parse and register a CRL. OK is False (and the store unchanged)
   --  when the CRL is malformed or the store is full. The application
   --  keeps DER.all alive for as long as the store is in use.
   procedure Add_CRL
     (Store : in out CRL_Store;
      DER   : in     CRL_Bytes_Access;
      OK    :    out Boolean)
   with Pre  => DER /= null
                and then DER.all'First = 0
                and then DER.all'Last < X509.N32 (Max_Evidence_Bytes),
        Post => (if OK then Store.Count = Store.Count'Old + 1
                 else Store.Count = Store.Count'Old);

   ----------------------------------------------------------------------------
   --  Issuer discovery
   ----------------------------------------------------------------------------

   --  Locate the leaf's direct issuer: a certificate in Ints (first) or
   --  Roots whose subject matches the leaf's issuer (RFC 5280 7.1
   --  comparison) and whose key verifies the leaf's signature. Found =
   --  False when none does (a chain the validator accepted always has
   --  one, so this is defensive).
   procedure Find_Issuer
     (Leaf_DER   : in     X509.Byte_Seq;
      Leaf       : in     X509.Certificate;
      Ints       : in     Cert_Pool;
      Int_Count  : in     Natural;
      Roots      : in     Root_Pool;
      Root_Count : in     Natural;
      Found      :    out Boolean;
      In_Roots   :    out Boolean;
      Index      :    out Natural)
   with Pre  => Leaf_DER'First = 0
                and Leaf_DER'Last < X509.N32 (Max_Cert_DER)
                and X509.Spans_Valid (Leaf, Leaf_DER'Last)
                and Int_Count <= Max_Pool_Size
                and Root_Count <= Max_Root_Pool_Size,
        Post => (if Found then
                   (if In_Roots
                    then Index < Root_Count and then Roots (Index).Present
                    else Index < Int_Count and then Ints (Index).Present));

   ----------------------------------------------------------------------------
   --  Stapled OCSP
   ----------------------------------------------------------------------------

   procedure Check_Stapled_OCSP
     (Leaf_DER     : in     X509.Byte_Seq;
      Leaf         : in     X509.Certificate;
      Issuer_DER   : in     X509.Byte_Seq;
      Issuer       : in     X509.Certificate;
      Response     : in     X509.Byte_Seq;
      Now          : in     X509.Date_Time;
      Allow_SHA1   : in     Boolean;
      Skew_Seconds : in     Natural;
      Result       :    out Revocation_Result)
   with Pre => Leaf_DER'First = 0
               and Leaf_DER'Last < X509.N32 (Max_Cert_DER)
               and X509.Spans_Valid (Leaf, Leaf_DER'Last)
               and Issuer_DER'First = 0
               and Issuer_DER'Last < X509.N32 (Max_Cert_DER)
               and X509.Spans_Valid (Issuer, Issuer_DER'Last)
               and Response'First = 0
               and Response'Length > 0
               and Response'Last < Max_OCSP_Response
               and Skew_Seconds <= 86_400;

   ----------------------------------------------------------------------------
   --  CRLs
   ----------------------------------------------------------------------------

   --  Check one parsed CRL. Rev_Insufficient when the CRL is not the
   --  issuer's (name / AKID mismatch), stale, a delta or indirect CRL,
   --  reason-partitioned, or scoped by issuingDistributionPoint to
   --  certificates of the other kind (CA vs end-entity).
   procedure Check_CRL
     (Leaf_DER     : in     X509.Byte_Seq;
      Leaf         : in     X509.Certificate;
      Issuer_DER   : in     X509.Byte_Seq;
      Issuer       : in     X509.Certificate;
      CRL_DER      : in     X509.Byte_Seq;
      CRL          : in     X509.CRL.CRL_View;
      Now          : in     X509.Date_Time;
      Skew_Seconds : in     Natural;
      Result       :    out Revocation_Result)
   with Pre => Leaf_DER'First = 0
               and Leaf_DER'Last < X509.N32 (Max_Cert_DER)
               and X509.Spans_Valid (Leaf, Leaf_DER'Last)
               and Issuer_DER'First = 0
               and Issuer_DER'Last < X509.N32 (Max_Cert_DER)
               and X509.Spans_Valid (Issuer, Issuer_DER'Last)
               and CRL_DER'First = 0
               and CRL_DER'Last < X509.N32 (Max_Evidence_Bytes)
               and X509.CRL.Is_Valid (CRL)
               and X509.CRL.Spans_Valid (CRL, CRL_DER'Last)
               and Skew_Seconds <= 86_400;

   --  Run Check_CRL over a store: the first CRL that belongs to the
   --  issuer decides. Rev_Insufficient when none does.
   --
   --  RFC 5280 6.3.3 (f): a CRL need not be signed by the key that signed
   --  the certificate -- a CA may sign CRLs with a rollover key or a
   --  dedicated CRL-signing key carried in a self-issued certificate.
   --  When the leaf's issuer certificate does not verify a CRL, every
   --  pool certificate is tried as the CRL signer; one is accepted only
   --  if Check_CRL reaches a verdict with it AND that certificate
   --  validates to the same trust anchors as an RFC 5280 path in its own
   --  right (PKITS 4.4.19, 4.5.1/4/6, 4.6.15/17).
   procedure Check_CRLs
     (Leaf_DER     : in     X509.Byte_Seq;
      Leaf         : in     X509.Certificate;
      Issuer_DER   : in     X509.Byte_Seq;
      Issuer       : in     X509.Certificate;
      Store        : in     CRL_Store;
      Ints         : in     Cert_Pool;
      Int_Count    : in     Natural;
      Roots        : in     Root_Pool;
      Root_Count   : in     Natural;
      Now          : in     X509.Date_Time;
      Skew_Seconds : in     Natural;
      Result       :    out Revocation_Result)
   with Pre => Leaf_DER'First = 0
               and Leaf_DER'Last < X509.N32 (Max_Cert_DER)
               and X509.Spans_Valid (Leaf, Leaf_DER'Last)
               and Issuer_DER'First = 0
               and Issuer_DER'Last < X509.N32 (Max_Cert_DER)
               and X509.Spans_Valid (Issuer, Issuer_DER'Last)
               and Int_Count <= Max_Pool_Size
               and Root_Count <= Max_Root_Pool_Size
               and Skew_Seconds <= 86_400;

   ----------------------------------------------------------------------------
   --  Policy decision
   ----------------------------------------------------------------------------

   --  Proceed          continue the handshake.
   --  Fail_Revoked     alert certificate_revoked (44).
   --  Fail_Bad_Status  alert bad_certificate_status_response (113): the
   --                   stapled response is unusable, or must-staple and
   --                   nothing good was stapled.
   --  Fail_No_Evidence alert bad_certificate (42): Hard_Fail with no
   --                   usable evidence.
   type Decision is (Proceed, Fail_Revoked, Fail_Bad_Status, Fail_No_Evidence);

   --  Apply Config's revocation policy to the evidence at hand once the
   --  chain has been validated. Stapled (0 .. Stapled_Len - 1) is the
   --  stapled OCSPResponse DER (Stapled_Len = 0: none); Stapled_Too_Big
   --  says the server stapled something over the size cap. Evidence
   --  precedence: stapled OCSP, then CRLs.
   procedure Evaluate
     (Policy        : in     Revocation_Policy;
      Staple_Asked  : in     Boolean;
      Allow_SHA1    : in     Boolean;
      Skew_Seconds  : in     Natural;
      CRLs          : in     CRL_Store_Access;
      Now           : in     X509.Date_Time;
      Leaf_DER      : in     X509.Byte_Seq;
      Leaf          : in     X509.Certificate;
      Ints          : in     Cert_Pool;
      Int_Count     : in     Natural;
      Roots         : in     Root_Pool;
      Root_Count    : in     Natural;
      Stapled       : in     X509.Byte_Seq;
      Stapled_Len   : in     X509.N32;
      Stapled_Too_Big : in   Boolean;
      Verdict       :    out Decision)
   with Pre => Leaf_DER'First = 0
               and Leaf_DER'Last < X509.N32 (Max_Cert_DER)
               and X509.Spans_Valid (Leaf, Leaf_DER'Last)
               and Int_Count <= Max_Pool_Size
               and Root_Count <= Max_Root_Pool_Size
               and Stapled'First = 0
               and Stapled'Last = Max_OCSP_Response - 1
               and Stapled_Len <= Max_OCSP_Response
               and Skew_Seconds <= 86_400;

   ----------------------------------------------------------------------------
   --  Time helpers (public for tests)
   ----------------------------------------------------------------------------

   --  Seconds since 1970-01-01T00:00:00Z; 0 for dates before that or
   --  with out-of-range fields.
   function To_Seconds (T : X509.Date_Time) return Interfaces.Unsigned_64;

   --  True when Now lies in [From - Skew, Upper + Skew] (Upper ignored
   --  when Has_Until is False).
   function In_Window
     (Now       : X509.Date_Time;
      From      : X509.Date_Time;
      Has_Until : Boolean;
      Upper     : X509.Date_Time;
      Skew      : Natural) return Boolean;

end SPARKTLS.Revocation;
