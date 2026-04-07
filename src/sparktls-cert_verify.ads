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

   --  Validation mode controls which rules are enforced.
   --
   --  Mode_RFC5280: RFC 5280 rules only.  Structural validity, signature
   --    verification, issuer DN match, name constraints, path length,
   --    AKI, hostname matching.  No key size or EKU requirements beyond
   --    what RFC 5280 specifies (EKU checked only if present).
   --
   --  Mode_WebPKI: RFC 5280 + CA/Browser Forum Baseline Requirements.
   --    All RFC 5280 checks plus:
   --    - Leaf must have EKU with serverAuth (for server validation)
   --    - Leaf EKU must not be critical
   --    - Leaf must have SAN extension (DNS or IP)
   --    - Leaf must not be a CA
   --    - Leaf CN must be a byte-for-byte copy of a SAN entry (BR 7.1.4.3)
   --    - anyExtendedKeyUsage forbidden on leaf (BR 7.1.2.7.10)
   --    - Root must not have EKU extension
   --    - RSA keys must be >= 2048 bits and divisible by 8 (BR 6.1.5)
   type Validation_Mode is (Mode_RFC5280, Mode_WebPKI);

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

   --  Validation purpose (controls EKU requirements on the leaf)
   type Validation_Purpose is (Purpose_Server, Purpose_Client, Purpose_Any);

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
   --  Chain building and validation
   --
   --  Builds a chain from the leaf to a trust anchor by searching
   --  a pool of candidate intermediates.  Uses recursive DFS with
   --  backtracking, bounded by a call budget and max chain depth.
   --
   --  The caller packs all intermediate and root DER into flat
   --  buffers and provides offset/length for each entry.
   --  No heap allocation; all state is stack or parameter-based.
   --================================================================

   Max_Chain_Depth : constant := 8;   --  EE + 6 sub-CAs + root
   Max_Pool_Size   : constant := 40;
   Max_Build_Calls : constant := 1000;  --  budget to prevent DoS
   Max_Cert_DER    : constant := 8192;  --  max DER bytes per cert

   --  Each pool entry holds a parsed cert and its own DER buffer
   --  starting at index 0 (required by X509 span offsets).
   subtype Cert_DER_Buf is X509.Byte_Seq (0 .. X509.N32 (Max_Cert_DER) - 1);

   type Pool_Entry is record
      Cert    : X509.Certificate;
      DER     : Cert_DER_Buf;
      DER_Len : X509.N32;
      Present : Boolean;
   end record;

   type Cert_Pool is array (0 .. Max_Pool_Size - 1) of Pool_Entry;
   type Used_Set  is array (0 .. Max_Pool_Size - 1) of Boolean;

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
      Roots      : Cert_Pool;
      Root_Count : Natural;
      Now        : X509.Date_Time;
      Hostname   : String;
      Purpose    : Validation_Purpose := Purpose_Server;
      Mode       : Validation_Mode := Mode_WebPKI) return Validation_Result
   with Pre => Leaf_DER'First = 0 and Leaf_DER'Last < X509.N32'Last
               and Int_Count <= Max_Pool_Size
               and Root_Count <= Max_Pool_Size;

end SPARKTLS.Cert_Verify;
