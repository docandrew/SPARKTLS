with SPARKNaCl; use SPARKNaCl;
with X509;

--  Certificate Signature & Chain Verification
--
--  Verifies certificate signatures and validates certificate chains.
--  Uses SPARKTLS crypto (RSA-PSS, ECDSA P-256/P-384, Ed25519).
package SPARKTLS.Cert_Verify with
   SPARK_Mode => On
is
   --  Verify a certificate's signature against its issuer's public key.
   function Verify_Cert_Signature
     (Cert_DER : Byte_Seq;
      Cert     : X509.Certificate;
      Issuer   : X509.Certificate) return Boolean
   with Pre => Cert_DER'First = 0 and Cert_DER'Last < N32'Last;

   --  Validation result
   type Validation_Result is
     (Valid,
      Err_Parse_Failed,
      Err_Structural,
      Err_Expired,
      Err_Unknown_Critical,
      Err_Unknown_Algorithm,
      Err_Signature_Invalid,
      Err_Not_CA,
      Err_Missing_AKI,
      Err_Forbidden_EKU,
      Err_Wrong_EKU,
      Err_Missing_SAN,
      Err_Weak_Key,
      Err_Issuer_Mismatch,
      Err_Name_Constraint,
      Err_Path_Length_Exceeded,
      Err_Hostname_Mismatch,
      Err_No_Trust_Anchor);

   --  Validate a trust anchor (root CA).
   --  Checks: structural validity, CA flag, known algorithms, date validity.
   --  Does NOT verify the root's self-signature (trust anchors are trusted
   --  by definition, and self-signature verification is not required by
   --  RFC 5280 §6.1).
   function Validate_Root
     (Root : X509.Certificate;
      Now  : X509.Date_Time;
      Mode : Validation_Mode := Mode_WebPKI) return Validation_Result
   with Post =>
     (if Validate_Root'Result = Valid then
        --  RFC 5280 §6.1.1(d): trust anchor must parse
        X509.Is_Valid (Root)
        --  RFC 5280 §4.2: no unrecognized critical extensions
        and not X509.Has_Unknown_Critical_Extension (Root)
        --  RFC 5280 §4.1.2.5: must be within validity period
        and X509.Is_Date_Valid (Root, Now)
        --  RFC 5280 §4.2.1.9: trust anchor must be CA
        and X509.Is_CA (Root)
        --  RFC 5280 §4.2.1.9: BC must be critical on CA certs
        and X509.Is_Basic_Constraints_Critical (Root)
        --  Full structural validity (encoding, extensions, etc.)
        and X509.Is_Structurally_Valid (Root, Now));

   --================================================================
   --  Chain validation building blocks
   --
   --  The caller walks the chain and calls these for each level:
   --    1. Validate_Root       — trust anchor
   --    2. Validate_Link       — each issuer->subject pair
   --    3. Validate_Leaf_Policy — leaf-specific policy checks
   --
   --  All SPARK_Mode On.  DER buffers use X509.Byte_Seq so that
   --  X509 functions (Issuer_Matches, Satisfies_Name_Constraints,
   --  Matches_Hostname) can be called directly.
   --================================================================

   --  Verify a certificate's signature using X509.Byte_Seq DER.
   --  Copies TBS bytes to SPARKNaCl.Byte_Seq internally for crypto.
   function Verify_Cert_Signature
     (Cert_DER : X509.Byte_Seq;
      Cert     : X509.Certificate;
      Issuer   : X509.Certificate) return Boolean
   with Pre => Cert_DER'First = 0 and Cert_DER'Last < X509.N32'Last;

   --  Validate one link in the chain: Issuer signs Cert.
   --
   --  Always checks (RFC 5280):
   --    - Cert structural validity (parse, dates, extensions, encoding)
   --    - Cert AKI present
   --    - Issuer DN matches Cert's Issuer field
   --    - Issuer Key Usage allows cert signing
   --    - Issuer EKU allows signing (if present)
   --    - Issuer name constraints satisfied
   --    - Issuer path length constraint not exceeded
   --    - Cryptographic signature verification
   --
   --  Mode_WebPKI additionally checks:
   --    - RSA keys >= 2048 bits and divisible by 8
   --
   --  Must_Be_CA: True for intermediates, False for leaf.
   --  CAs_Below_Issuer: number of CA certs between the issuer and
   --    the leaf (for path length constraint checking).
   function Validate_Link
     (Cert_DER         : X509.Byte_Seq;
      Cert             : X509.Certificate;
      Issuer_DER       : X509.Byte_Seq;
      Issuer           : X509.Certificate;
      Now              : X509.Date_Time;
      Must_Be_CA       : Boolean;
      CAs_Below_Issuer : Natural;
      Mode             : Validation_Mode := Mode_WebPKI) return Validation_Result
   with Pre => Cert_DER'First = 0 and Cert_DER'Last < X509.N32'Last
               and Issuer_DER'First = 0 and Issuer_DER'Last < X509.N32'Last;

   --  Validate leaf-specific policy.
   --  Called after Validate_Link succeeds on the leaf.
   --
   --  Always checks (RFC 5280):
   --    - EKU matches Purpose (if EKU present)
   --    - Hostname matches SAN/CN
   --
   --  Mode_WebPKI additionally checks:
   --    - Leaf must have EKU with serverAuth (Purpose_Server)
   --    - anyExtendedKeyUsage forbidden on leaf
   --    - EKU must not be critical
   --    - SAN extension must be present (DNS or IP)
   --    - Leaf must not be a CA
   --    - CN must be byte-for-byte copy of a SAN entry
   --    - RSA keys >= 2048 bits and divisible by 8
   function Validate_Leaf_Policy
     (Leaf     : X509.Certificate;
      Leaf_DER : X509.Byte_Seq;
      Hostname : String;
      Purpose  : Validation_Purpose := Purpose_Server;
      Mode     : Validation_Mode := Mode_WebPKI) return Validation_Result
   with Pre => Leaf_DER'First = 0 and Leaf_DER'Last < X509.N32'Last;

   --================================================================
   --  Credential loading helpers
   --
   --  Types (Trust_Store, Identity, Cert_Pool, etc.) are in the
   --  parent package SPARKTLS.  These procedures load data into them.
   --================================================================

   --  Parse a DER certificate and add it to the trust store.
   --  Fails if the store is full or the cert doesn't parse.
   procedure Add_Root
     (Store : in out Trust_Store;
      DER   : X509.Byte_Seq;
      OK    : out Boolean)
   with Pre => DER'First = 0 and DER'Last < X509.N32'Last
               and X509.N32 (DER'Length) <= X509.N32 (Max_Cert_DER);

   --  Load all DER certificates from a concatenated blob.
   --  Each cert is a complete DER SEQUENCE (tag 0x30 + length + value).
   --  Stops when the blob is exhausted or the store is full.
   procedure Load_Roots
     (Store  : out Trust_Store;
      DER    : X509.Byte_Seq;
      Loaded : out Natural;
      OK     : out Boolean)
   with Pre => DER'First = 0 and DER'Last < X509.N32'Last;

   function Root_Count (Store : Trust_Store) return Natural is
     (Store.Root_Count);

   --  Load a leaf certificate and private key into an Identity.
   --  The signing algorithm is inferred from the certificate:
   --    Algo_EC_Ed25519 → Ed25519 (Key: 64 bytes, secret || public)
   --    Algo_EC_P256    → ECDSA P-256 (Key: 32 bytes, scalar)
   --    Algo_EC_P384    → ECDSA P-384 (Key: 48 bytes, scalar)
   procedure Set_Identity
     (Id       : out Identity;
      Cert_DER : X509.Byte_Seq;
      Key      : Byte_Seq;
      OK       : out Boolean)
   with Pre => Cert_DER'First = 0 and Cert_DER'Last < X509.N32'Last
               and X509.N32 (Cert_DER'Length) <= X509.N32 (Max_Cert_DER)
               and Key'First = 0;

   --  Add an intermediate certificate to the identity's chain.
   procedure Add_Intermediate
     (Id  : in out Identity;
      DER : X509.Byte_Seq;
      OK  : out Boolean)
   with Pre => DER'First = 0 and DER'Last < X509.N32'Last
               and X509.N32 (DER'Length) <= X509.N32 (Max_Cert_DER);

   --================================================================
   --  Chain building and validation
   --================================================================

   Max_Chain_Depth : constant := 8;   --  EE + 6 sub-CAs + root
   Max_Build_Calls : constant := 1000;  --  budget to prevent DoS

   --  Build and validate a complete certificate chain.
   --
   --  Leaf_DER / Leaf: the end-entity certificate to validate.
   --  Ints / Int_Count: pool of candidate intermediates.
   --  Roots / Root_Count: pool of trust anchors.
   --  Hostname: expected peer name (empty string to skip).
   --
   --  Algorithm: recursive DFS starting from the leaf.  At each level
   --  tries roots first, then unused intermediates.  Backtracks on
   --  failure.  Validates each link via Validate_Link (proven).
   --  Budget counter prevents DoS from pathological chains.
   function Validate_Chain
     (Leaf_DER   : X509.Byte_Seq;
      Leaf       : X509.Certificate;
      Ints       : Cert_Pool;
      Int_Count  : Natural;
      Roots      : Root_Pool;
      Root_Count : Natural;
      Now        : X509.Date_Time;
      Hostname   : String;
      Purpose    : Validation_Purpose := Purpose_Server;
      Mode       : Validation_Mode := Mode_WebPKI) return Validation_Result
   with Pre => Leaf_DER'First = 0 and Leaf_DER'Last < X509.N32'Last
               and Int_Count <= Max_Pool_Size
               and Root_Count <= Max_Root_Pool_Size;

end SPARKTLS.Cert_Verify;
