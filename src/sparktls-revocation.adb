with SPARKNaCl; use SPARKNaCl;
with SPARKNaCl.Hashing.SHA384;
with SPARKNaCl.Hashing.SHA512;
with SPARKTLSCrypto.Hashing.SHA1;
with SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLS.Cert_Verify;
with X509.DER_Ext;

package body SPARKTLS.Revocation with
   SPARK_Mode => On
is
   use type Interfaces.Unsigned_64;
   use type X509.Algorithm_ID;
   use type X509.OCSP.Response_Status;
   use type X509.OCSP.Cert_Status;
   use type X509.OCSP.Hash_Algorithm;
   use type X509.OCSP.Responder_ID_Kind;

   subtype U64 is Interfaces.Unsigned_64;

   --  Maximum bytes hashed in one go (a Name TLV, an SPKI, an OCSP
   --  tbsResponseData or a CRL TBSCertList).
   Max_Hash_Input : constant := Max_Evidence_Bytes;

   ----------------------------------------------------------------------------
   --  Time helpers
   ----------------------------------------------------------------------------

   function To_Seconds (T : X509.Date_Time) return U64 is
      --  Days-from-civil (Howard Hinnant), all in Natural: era <= 25
      --  for years <= 9999, so every intermediate is far below 2**31.
      Y   : Natural;
      Era, YoE, MP, DoY, DoE, Total : Natural;
   begin
      if T.Year < 1970 or else T.Year > 9999
        or else T.Month < 1 or else T.Month > 12
        or else T.Day < 1 or else T.Day > 31
        or else T.Hour > 23 or else T.Minute > 59 or else T.Second > 60
      then
         return 0;
      end if;
      Y := (if T.Month <= 2 then T.Year - 1 else T.Year);
      Era := Y / 400;
      YoE := Y - Era * 400;                        --  0 .. 399
      MP  := (T.Month + 9) mod 12;                 --  March = 0
      DoY := (153 * MP + 2) / 5 + T.Day - 1;       --  0 .. 365
      DoE := YoE * 365 + YoE / 4 - YoE / 100 + DoY; --  0 .. 146096
      Total := Era * 146097 + DoE;
      if Total < 719468 then
         return 0;
      end if;
      return U64 (Total - 719468) * 86_400
             + U64 (T.Hour) * 3_600 + U64 (T.Minute) * 60 + U64 (T.Second);
   end To_Seconds;

   function In_Window
     (Now       : X509.Date_Time;
      From      : X509.Date_Time;
      Has_Until : Boolean;
      Upper     : X509.Date_Time;
      Skew      : Natural) return Boolean
   is
      N : constant U64 := To_Seconds (Now);
      F : constant U64 := To_Seconds (From);
      S : constant U64 := U64 (Skew);
   begin
      if N + S < F then
         return False;
      end if;
      if Has_Until and then N > To_Seconds (Upper) + S then
         return False;
      end if;
      return True;
   end In_Window;

   ----------------------------------------------------------------------------
   --  Byte helpers
   ----------------------------------------------------------------------------

   --  Copy the bytes of span S (present, in range) into a SPARKNaCl
   --  sequence starting at 0.
   function To_NaCl (DER : X509.Byte_Seq; S : X509.Span) return Byte_Seq
   with Pre  => DER'First = 0
                and DER'Last < X509.N32 (Max_Hash_Input)
                and S.Present
                and X509.Span_In_Range (S, DER'Last)
                and X509.Span_Length (S) > 0,
        Post => To_NaCl'Result'First = 0
                and To_NaCl'Result'Length = X509.Span_Length (S)
                and To_NaCl'Result'Last < N32 (Max_Hash_Input)
   is
      Len : constant X509.N32 := X509.Span_Length (S);
      R   : Byte_Seq (0 .. N32 (Len) - 1) := (others => 0);
   begin
      for I in R'Range loop
         pragma Loop_Invariant (S.First + X509.N32 (I) <= S.Last);
         R (I) := Byte (DER (S.First + X509.N32 (I)));
      end loop;
      return R;
   end To_NaCl;

   --  Byte-for-byte equality of two spans in two buffers.
   function Span_Bytes_Equal
     (A_DER : X509.Byte_Seq; A : X509.Span;
      B_DER : X509.Byte_Seq; B : X509.Span) return Boolean
   with Pre => A_DER'First = 0 and A_DER'Last < X509.N32'Last
               and B_DER'First = 0 and B_DER'Last < X509.N32'Last
               and X509.Span_In_Range (A, A_DER'Last)
               and X509.Span_In_Range (B, B_DER'Last)
   is
      Len : constant X509.N32 := X509.Span_Length (A);
   begin
      if not A.Present or else not B.Present then
         return False;
      end if;
      if Len = 0 or else Len /= X509.Span_Length (B) then
         return False;
      end if;
      for I in X509.N32 range 0 .. Len - 1 loop
         pragma Loop_Invariant (I < Len);
         if A_DER (A.First + I) /= B_DER (B.First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Span_Bytes_Equal;

   --  Digest of the bytes of S in DER under Algo; Len = 0 when the
   --  algorithm is unknown.
   procedure Digest_Of
     (DER  : in     X509.Byte_Seq;
      S    : in     X509.Span;
      Algo : in     X509.OCSP.Hash_Algorithm;
      D    :    out Byte_Seq;
      Len  :    out N32)
   with Pre  => DER'First = 0
                and DER'Last < X509.N32 (Max_Hash_Input)
                and S.Present
                and X509.Span_In_Range (S, DER'Last)
                and X509.Span_Length (S) > 0
                and D'First = 0 and D'Last = 63,
        Post => Len <= 64
   is
      M : constant Byte_Seq := To_NaCl (DER, S);
   begin
      D := (others => 0);
      Len := 0;
      case Algo is
         when X509.OCSP.Hash_SHA1 =>
            declare
               H : SPARKTLSCrypto.Hashing.SHA1.Digest;
            begin
               SPARKTLSCrypto.Hashing.SHA1.Hash (H, M);
               D (0 .. 19) := H;
               Len := 20;
            end;
         when X509.OCSP.Hash_SHA256 =>
            declare
               H : SPARKTLSCrypto.Hashing.SHA256.Digest;
            begin
               SPARKTLSCrypto.Hashing.SHA256.Hash (H, M);
               D (0 .. 31) := Byte_Seq (H);
               Len := 32;
            end;
         when X509.OCSP.Hash_SHA384 =>
            declare
               H : SPARKNaCl.Hashing.SHA384.Digest;
            begin
               SPARKNaCl.Hashing.SHA384.Hash (H, M);
               D (0 .. 47) := Byte_Seq (H);
               Len := 48;
            end;
         when X509.OCSP.Hash_SHA512 =>
            declare
               H : SPARKNaCl.Hashing.SHA512.Digest;
            begin
               SPARKNaCl.Hashing.SHA512.Hash (H, M);
               D (0 .. 63) := Byte_Seq (H);
               Len := 64;
            end;
         when X509.OCSP.Hash_Unknown =>
            null;
      end case;
   end Digest_Of;

   --  hash(S in DER) = bytes of H in H_DER
   function Hash_Matches
     (DER   : X509.Byte_Seq; S : X509.Span;
      Algo  : X509.OCSP.Hash_Algorithm;
      H_DER : X509.Byte_Seq; H : X509.Span) return Boolean
   with Pre => DER'First = 0
               and DER'Last < X509.N32 (Max_Hash_Input)
               and X509.Span_In_Range (S, DER'Last)
               and H_DER'First = 0 and H_DER'Last < X509.N32'Last
               and X509.Span_In_Range (H, H_DER'Last)
   is
      D   : Byte_Seq (0 .. 63);
      Len : N32;
   begin
      if not S.Present or else X509.Span_Length (S) = 0
        or else not H.Present
      then
         return False;
      end if;
      Digest_Of (DER, S, Algo, D, Len);
      if Len = 0 or else X509.Span_Length (H) /= X509.N32 (Len) then
         return False;
      end if;
      for I in N32 range 0 .. Len - 1 loop
         pragma Loop_Invariant (I < Len);
         if H_DER (H.First + X509.N32 (I)) /= X509.Byte (D (I)) then
            return False;
         end if;
      end loop;
      return True;
   end Hash_Matches;

   --  Reconstruct the full SEQUENCE TLV around a Name content span
   --  (RFC 6960 4.1.1 hashes the DER of the Name, tag and length
   --  included). DER length encoding is canonical, so the header is
   --  determined by the content length; verify the bytes really are
   --  that header.
   procedure Name_TLV
     (DER     : in     X509.Byte_Seq;
      Content : in     X509.Span;
      TLV     :    out X509.Span;
      OK      :    out Boolean)
   with Pre  => DER'First = 0 and DER'Last < X509.N32'Last
                and X509.Span_In_Range (Content, DER'Last),
        Post => (if OK then TLV.Present
                 and then X509.Span_In_Range (TLV, DER'Last)
                 and then X509.Span_Length (TLV) > 0)
   is
      L   : constant X509.N32 := X509.Span_Length (Content);
      Hdr : X509.N32;
      St  : X509.N32;
   begin
      TLV := (0, 0, False);
      OK := False;
      if not Content.Present or else L = 0 then
         return;
      end if;
      Hdr := (if L < 128 then 2 elsif L < 256 then 3
              elsif L < 65_536 then 4 else 5);
      if Content.First < Hdr then
         return;
      end if;
      St := Content.First - Hdr;
      if DER (St) /= 16#30# then
         return;
      end if;
      case Hdr is
         when 2 =>
            if DER (St + 1) /= X509.Byte (L mod 256) then return; end if;
         when 3 =>
            if DER (St + 1) /= 16#81# or else DER (St + 2) /= X509.Byte (L mod 256) then
               return;
            end if;
         when 4 =>
            if DER (St + 1) /= 16#82#
              or else DER (St + 2) /= X509.Byte ((L / 256) mod 256)
              or else DER (St + 3) /= X509.Byte (L mod 256)
            then
               return;
            end if;
         when others =>
            if DER (St + 1) /= 16#83#
              or else DER (St + 2) /= X509.Byte ((L / 65_536) mod 256)
              or else DER (St + 3) /= X509.Byte ((L / 256) mod 256)
              or else DER (St + 4) /= X509.Byte (L mod 256)
            then
               return;
            end if;
      end case;
      TLV := (First => St, Last => Content.Last, Present => True);
      OK := True;
   end Name_TLV;

   ----------------------------------------------------------------------------
   --  CRL store
   ----------------------------------------------------------------------------

   procedure Add_CRL
     (Store : in out CRL_Store;
      DER   : in     CRL_Bytes_Access;
      OK    :    out Boolean)
   is
      V : X509.CRL.CRL_View;
      P : Boolean;
   begin
      OK := False;
      if Store.Count >= Max_CRLs then
         return;
      end if;
      X509.CRL.Parse (DER.all, V, P);
      if not P then
         return;
      end if;
      Store.Count := Store.Count + 1;
      Store.Entries (Store.Count) := (DER => DER, View => V, Present => True);
      OK := True;
   end Add_CRL;

   ----------------------------------------------------------------------------
   --  Issuer discovery
   ----------------------------------------------------------------------------

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
   is
   begin
      Found := False; In_Roots := False; Index := 0;

      for I in 0 .. Int_Count - 1 loop
         pragma Loop_Invariant (not Found);
         if Ints (I).Present
           and then X509.Issuer_Matches
                      (Leaf, Leaf_DER,
                       Ints (I).Cert, Ints (I).DER (0 .. Ints (I).DER_Len - 1))
           and then Cert_Verify.Verify_Cert_Signature (Leaf_DER, Leaf, Ints (I).Cert)
         then
            Found := True; In_Roots := False; Index := I;
            return;
         end if;
      end loop;

      for I in 0 .. Root_Count - 1 loop
         pragma Loop_Invariant (not Found);
         if Roots (I).Present
           and then X509.Issuer_Matches
                      (Leaf, Leaf_DER,
                       Roots (I).Cert, Roots (I).DER (0 .. Roots (I).DER_Len - 1))
           and then Cert_Verify.Verify_Cert_Signature (Leaf_DER, Leaf, Roots (I).Cert)
         then
            Found := True; In_Roots := True; Index := I;
            return;
         end if;
      end loop;
   end Find_Issuer;

   ----------------------------------------------------------------------------
   --  OCSP
   ----------------------------------------------------------------------------

   --  ResponderID (RFC 6960 4.2.2.1) names Cand: byName = Cand's subject
   --  bytes, byKey = SHA-1 of Cand's subjectPublicKey bits. KeyHash is
   --  SHA-1 by definition, so it is computed regardless of the CertID
   --  policy; it only SELECTS the signer, the signature check binds it.
   function Responder_Names
     (Resp_DER : X509.Byte_Seq; V : X509.OCSP.OCSP_View;
      Cand_DER : X509.Byte_Seq; Cand : X509.Certificate) return Boolean
   with Pre => Resp_DER'First = 0 and Resp_DER'Last < Max_OCSP_Response
               and X509.OCSP.Spans_Valid (V, Resp_DER'Last)
               and Cand_DER'First = 0 and Cand_DER'Last < X509.N32 (Max_Cert_DER)
               and X509.Spans_Valid (Cand, Cand_DER'Last)
   is
   begin
      --  Spans_Valid is opaque outside X509 / X509.OCSP: re-establish the
      --  getter ranges at runtime (the existing sparktls convention).
      if not X509.Span_In_Range (X509.OCSP.Responder_ID (V), Resp_DER'Last)
        or else not X509.Span_In_Range (X509.Subject_Raw (Cand), Cand_DER'Last)
        or else not X509.Span_In_Range (X509.Subject_Public_Key_Bits (Cand), Cand_DER'Last)
      then
         return False;
      end if;
      case X509.OCSP.Responder_Kind (V) is
         when X509.OCSP.Responder_By_Name =>
            return Span_Bytes_Equal
                     (Resp_DER, X509.OCSP.Responder_ID (V),
                      Cand_DER, X509.Subject_Raw (Cand));
         when X509.OCSP.Responder_By_Key =>
            return Hash_Matches
                     (Cand_DER, X509.Subject_Public_Key_Bits (Cand),
                      X509.OCSP.Hash_SHA1,
                      Resp_DER, X509.OCSP.Responder_ID (V));
         when X509.OCSP.Responder_None =>
            return False;
      end case;
   end Responder_Names;

   --  Signature over tbsResponseData verifies with Cand's key.
   function Signed_By
     (Resp_DER : X509.Byte_Seq; V : X509.OCSP.OCSP_View;
      Cand     : X509.Certificate) return Boolean
   with Pre => Resp_DER'First = 0 and Resp_DER'Last < Max_OCSP_Response
               and X509.OCSP.Spans_Valid (V, Resp_DER'Last)
   is
      TBS : constant X509.Span := X509.OCSP.TBS (V);
   begin
      if not TBS.Present or else X509.Span_Length (TBS) = 0
        or else not X509.Span_In_Range (TBS, Resp_DER'Last)
        or else X509.OCSP.Sig_Length (V) = 0
        or else X509.OCSP.Sig_Length (V) > X509.Max_Sig_Bytes
        or else X509.OCSP.Sig_Algorithm (V) = X509.Algo_Unknown
      then
         return False;
      end if;
      return Cert_Verify.Verify_Raw_Signature
               (To_NaCl (Resp_DER, TBS),
                X509.OCSP.Sig_Algorithm (V),
                X509.OCSP.Sig_Data (V),
                Cand);
   end Signed_By;

   --  CertID (RFC 6960 4.1.1) identifies Leaf under Issuer.
   function CertID_Matches
     (Resp_DER   : X509.Byte_Seq; R : X509.OCSP.Single_Response;
      Leaf_DER   : X509.Byte_Seq; Leaf   : X509.Certificate;
      Issuer_DER : X509.Byte_Seq; Issuer : X509.Certificate;
      Allow_SHA1 : Boolean) return Boolean
   with Pre => Resp_DER'First = 0 and Resp_DER'Last < Max_OCSP_Response
               and X509.OCSP.Single_Spans_Valid (R, Resp_DER'Last)
               and Leaf_DER'First = 0 and Leaf_DER'Last < X509.N32 (Max_Cert_DER)
               and X509.Spans_Valid (Leaf, Leaf_DER'Last)
               and Issuer_DER'First = 0 and Issuer_DER'Last < X509.N32 (Max_Cert_DER)
               and X509.Spans_Valid (Issuer, Issuer_DER'Last)
   is
      Name : X509.Span;
      N_OK : Boolean;
   begin
      if not X509.Span_In_Range (X509.Serial (Leaf), Leaf_DER'Last)
        or else not X509.Span_In_Range (X509.Subject_Raw (Issuer), Issuer_DER'Last)
        or else not X509.Span_In_Range (X509.Subject_Public_Key_Bits (Issuer), Issuer_DER'Last)
      then
         return False;
      end if;
      if R.Hash_Algo = X509.OCSP.Hash_Unknown then
         return False;
      end if;
      if R.Hash_Algo = X509.OCSP.Hash_SHA1 and then not Allow_SHA1 then
         return False;
      end if;
      if not Span_Bytes_Equal (Resp_DER, R.S_Serial, Leaf_DER, X509.Serial (Leaf)) then
         return False;
      end if;
      Name_TLV (Issuer_DER, X509.Subject_Raw (Issuer), Name, N_OK);
      if not N_OK then
         return False;
      end if;
      if not Hash_Matches (Issuer_DER, Name, R.Hash_Algo,
                           Resp_DER, R.S_Issuer_Name_Hash)
      then
         return False;
      end if;
      return Hash_Matches (Issuer_DER, X509.Subject_Public_Key_Bits (Issuer),
                           R.Hash_Algo, Resp_DER, R.S_Issuer_Key_Hash);
   end CertID_Matches;

   --  RFC 6960 4.2.2.2: an embedded certificate is an authorized
   --  responder for Issuer when Issuer directly issued it, it carries
   --  id-kp-OCSPSigning, it is within its validity period, and its
   --  ResponderID / signature match the response.
   procedure Delegate_Signs
     (Resp_DER   : in     X509.Byte_Seq; V : in X509.OCSP.OCSP_View;
      Issuer_DER : in     X509.Byte_Seq; Issuer : in X509.Certificate;
      Now        : in     X509.Date_Time;
      Signs      :    out Boolean)
   with Pre => Resp_DER'First = 0 and Resp_DER'Last < Max_OCSP_Response
               and X509.OCSP.Is_Valid (V)
               and X509.OCSP.Spans_Valid (V, Resp_DER'Last)
               and Issuer_DER'First = 0 and Issuer_DER'Last < X509.N32 (Max_Cert_DER)
               and X509.Spans_Valid (Issuer, Issuer_DER'Last)
   is
      Count : constant Natural := X509.OCSP.Embedded_Cert_Count (V);
   begin
      Signs := False;
      if Count > X509.OCSP.Max_Embedded_Certs then
         return;
      end if;
      for I in 1 .. Count loop
         pragma Loop_Invariant (not Signs);
         declare
            Sp  : constant X509.Span := X509.OCSP.Embedded_Cert (V, I);
            Len : constant X509.N32 := X509.Span_Length (Sp);
         begin
            if Sp.Present and then Len > 0 and then Len <= X509.N32 (Max_Cert_DER)
              and then X509.Span_In_Range (Sp, Resp_DER'Last)
            then
               declare
                  Cand_DER : X509.Byte_Seq (0 .. Len - 1) := (others => 0);
                  Cand     : X509.Certificate;
                  P_OK     : Boolean;
               begin
                  for J in X509.N32 range 0 .. Len - 1 loop
                     pragma Loop_Invariant (Sp.First + J <= Sp.Last);
                     Cand_DER (J) := Resp_DER (Sp.First + J);
                  end loop;
                  X509.Parse (Cand_DER, Cand, P_OK);
                  if P_OK
                    and then X509.Is_Valid (Cand)
                    and then X509.Is_Date_Valid (Cand, Now)
                    and then X509.Has_EKU_OCSP_Signing (Cand)
                    and then (not X509.Has_Key_Usage (Cand)
                              or else X509.KU_Digital_Signature (Cand))
                    and then not X509.Has_Unknown_Critical_Extension (Cand)
                    and then X509.Issuer_Matches (Cand, Cand_DER, Issuer, Issuer_DER)
                    and then Cert_Verify.Verify_Cert_Signature (Cand_DER, Cand, Issuer)
                    and then Responder_Names (Resp_DER, V, Cand_DER, Cand)
                    and then Signed_By (Resp_DER, V, Cand)
                  then
                     Signs := True;
                     return;
                  end if;
               end;
            end if;
         end;
      end loop;
   end Delegate_Signs;

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
   is
      V  : X509.OCSP.OCSP_View;
      OK : Boolean;
   begin
      Result := Rev_Malformed;

      X509.OCSP.Parse (Response, V, OK);
      if not OK then
         return;
      end if;

      --  RFC 6960 4.2.1: a non-successful status carries no evidence.
      if X509.OCSP.Status (V) /= X509.OCSP.Successful
        or else not X509.OCSP.Has_Basic_Response (V)
      then
         Result := Rev_Insufficient;
         return;
      end if;

      if X509.OCSP.Has_Unknown_Critical_Extension (V) then
         return;
      end if;

      --  RFC 6960 4.2.2.2: signer = the issuer itself, or a delegate.
      declare
         Signer_OK : Boolean :=
           Responder_Names (Response, V, Issuer_DER, Issuer)
           and then Signed_By (Response, V, Issuer);
      begin
         if not Signer_OK then
            Delegate_Signs (Response, V, Issuer_DER, Issuer, Now, Signer_OK);
         end if;
         if not Signer_OK then
            return;
         end if;
      end;

      --  Find the SingleResponse for this certificate.
      declare
         Count : constant Natural := X509.OCSP.Response_Count (V);
      begin
         if Count > X509.OCSP.Max_Single_Responses then
            return;
         end if;
         for I in 1 .. Count loop
            declare
               R : constant X509.OCSP.Single_Response := X509.OCSP.Get_Response (V, I);
            begin
               if CertID_Matches (Response, R, Leaf_DER, Leaf,
                                  Issuer_DER, Issuer, Allow_SHA1)
               then
                  if R.Unknown_Critical then
                     Result := Rev_Malformed;
                     return;
                  end if;
                  --  Freshness (RFC 6960 3.2 / RFC 5019 4). Without
                  --  nextUpdate the responder promises nothing about
                  --  validity; accept a thisUpdate at most 7 days old.
                  if not In_Window (Now, R.This_Update, R.Has_Next_Update,
                                    R.Next_Update, Skew_Seconds)
                    or else (not R.Has_Next_Update
                             and then To_Seconds (Now)
                                      > To_Seconds (R.This_Update) + 7 * 86_400)
                  then
                     Result := Rev_Insufficient;
                     return;
                  end if;
                  case R.Status is
                     when X509.OCSP.Status_Good    => Result := Rev_Ok;
                     when X509.OCSP.Status_Revoked => Result := Rev_Revoked;
                     when X509.OCSP.Status_Unknown => Result := Rev_Insufficient;
                  end case;
                  return;
               end if;
            end;
         end loop;
      end;
      --  Verified response, but not about this certificate.
      Result := Rev_Insufficient;
   end Check_Stapled_OCSP;

   ----------------------------------------------------------------------------
   --  CRL
   ----------------------------------------------------------------------------

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
   is
      TBS : constant X509.Span := X509.CRL.TBS (CRL);
   begin
      Result := Rev_Insufficient;

      --  Spans_Valid is opaque outside X509 / X509.CRL: re-establish the
      --  getter ranges at runtime.
      if not X509.Span_In_Range (X509.CRL.Issuer_Raw (CRL), CRL_DER'Last)
        or else not X509.Span_In_Range (X509.CRL.Authority_Key_ID (CRL), CRL_DER'Last)
        or else not X509.Span_In_Range (TBS, CRL_DER'Last)
        or else not X509.Span_In_Range (X509.Subject_Raw (Issuer), Issuer_DER'Last)
        or else not X509.Span_In_Range (X509.Subject_Key_ID (Issuer), Issuer_DER'Last)
        or else not X509.Span_In_Range (X509.Serial (Leaf), Leaf_DER'Last)
      then
         return;
      end if;

      --  This CRL must be the issuer's own: same name, and when both
      --  sides carry key identifiers, the same key (RFC 5280 6.3.3).
      --  The CRL's issuer name must be the certificate's issuer name
      --  (RFC 5280 6.3.3 (b)). A CA may re-encode its name over time
      --  (PrintableString -> UTF8String rollover, PKITS 4.3.10): the
      --  leaf's issuer field and the CRL's issuer field are written by
      --  the same CA in the same era, so a byte match against either the
      --  issuer certificate's subject or the leaf's issuer is accepted.
      if not Span_Bytes_Equal (CRL_DER, X509.CRL.Issuer_Raw (CRL),
                               Issuer_DER, X509.Subject_Raw (Issuer))
        and then not (X509.Span_In_Range (X509.Issuer_Raw (Leaf), Leaf_DER'Last)
                      and then Span_Bytes_Equal (CRL_DER, X509.CRL.Issuer_Raw (CRL),
                                                 Leaf_DER, X509.Issuer_Raw (Leaf)))
      then
         return;
      end if;
      if X509.CRL.Authority_Key_ID (CRL).Present
        and then X509.Subject_Key_ID (Issuer).Present
        and then not Span_Bytes_Equal (CRL_DER, X509.CRL.Authority_Key_ID (CRL),
                                       Issuer_DER, X509.Subject_Key_ID (Issuer))
      then
         return;
      end if;

      --  From here on the CRL claims to be this issuer's. A CRL that is
      --  not RFC 5280 conforming, or whose issuer may not sign CRLs, is
      --  invalid evidence (Rev_Malformed), not merely inapplicable.
      if X509.CRL.Has_Unknown_Critical_Extension (CRL)
        or else X509.CRL.Has_Bad_Extension (CRL)
        or else (X509.Has_Key_Usage (Issuer) and then not X509.KU_CRL_Sign (Issuer))
      then
         Result := Rev_Malformed;
         return;
      end if;

      --  Scope we do not implement (RFC 5280 5.2.4 / 5.2.5 / 5.3.3):
      --  valid CRLs that this verifier cannot apply.
      if X509.CRL.Is_Delta_CRL (CRL)
        or else X509.CRL.Has_Critical_Entry_Extension (CRL)
        or else X509.CRL.IDP_Indirect_CRL (CRL)
        or else X509.CRL.IDP_Only_Some_Reasons (CRL)
        or else X509.CRL.IDP_Only_Attribute_Certs (CRL)
      then
         return;
      end if;
      if (X509.CRL.IDP_Only_CA_Certs (CRL) and then not X509.Is_CA (Leaf))
        or else (X509.CRL.IDP_Only_User_Certs (CRL) and then X509.Is_CA (Leaf))
      then
         return;
      end if;

      --  RFC 5280 6.3.3 (b)(2): a CRL scoped to a distribution point
      --  covers only certificates whose cRLDistributionPoints name it
      --  (sharded CRLs). Otherwise this CRL says nothing about Leaf.
      if X509.CRL.IDP_Has_Distribution_Point (CRL) then
         declare
            Cert_DP : constant X509.Span := X509.CRL_Distribution_Points (Leaf);
            IDP_DP  : constant X509.Span := X509.CRL.IDP_Distribution_Point (CRL);
         begin
            if not X509.Span_In_Range (Cert_DP, Leaf_DER'Last)
              or else not X509.Span_In_Range (X509.Issuer_Raw (Leaf), Leaf_DER'Last)
              or else not X509.Span_In_Range (IDP_DP, CRL_DER'Last)
              or else not X509.DER_Ext.DP_Name_Matches
                            (Leaf_DER, Cert_DP, X509.Issuer_Raw (Leaf),
                             CRL_DER, IDP_DP, X509.CRL.Issuer_Raw (CRL))
            then
               return;
            end if;
         end;
      end if;

      --  Signature (RFC 5280 5.1.1.2 / 5.1.1.3).
      Result := Rev_Malformed;
      if X509.CRL.Sig_Algorithm (CRL) = X509.Algo_Unknown
        or else X509.CRL.Sig_Algorithm (CRL) /= X509.CRL.Sig_Algorithm_2 (CRL)
        or else X509.CRL.Sig_Length (CRL) = 0
        or else X509.CRL.Sig_Length (CRL) > X509.Max_Sig_Bytes
        or else not TBS.Present
        or else X509.Span_Length (TBS) = 0
      then
         return;
      end if;
      if not Cert_Verify.Verify_Raw_Signature
               (To_NaCl (CRL_DER, TBS),
                X509.CRL.Sig_Algorithm (CRL),
                X509.CRL.Sig_Data (CRL),
                Issuer)
      then
         return;
      end if;

      --  Freshness.
      if not In_Window (Now, X509.CRL.This_Update (CRL),
                        X509.CRL.Has_Next_Update (CRL),
                        X509.CRL.Next_Update (CRL), Skew_Seconds)
      then
         Result := Rev_Insufficient;
         return;
      end if;

      declare
         Serial : constant X509.Span := X509.Serial (Leaf);
         Len    : constant X509.N32 := X509.Span_Length (Serial);
         Found  : Boolean;
         When_R : X509.Date_Time;
         Has_R  : Boolean;
         Reason : Natural;
      begin
         if not Serial.Present or else Len = 0
           or else Len > X509.CRL.Max_Serial_Bytes
         then
            Result := Rev_Insufficient;
            return;
         end if;
         X509.CRL.Lookup (CRL_DER, CRL,
                          Leaf_DER (Serial.First .. Serial.Last),
                          Found, When_R, Has_R, Reason);
         Result := (if Found then Rev_Revoked else Rev_Ok);
      end;
   end Check_CRL;

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
   is
      Best : Revocation_Result := Rev_Insufficient;

      --  RFC 5280 6.3.3 (f) fallback: another certificate of the SAME CA
      --  (same subject name as the leaf's issuer) may have signed the CRL
      --  -- a rollover key or a dedicated CRL-signing key. A candidate is
      --  accepted only if (1) Check_CRL reaches a verdict with it, (2) it
      --  validates to the same anchors as an RFC 5280 path in its own
      --  right (Purpose_Any: a CA certificate, no hostname), and (3) no
      --  CRL in the store lists the candidate itself as revoked -- checked
      --  against its own issuer's CRLs and against CRLs it signs itself,
      --  since a CRL-signing key may be the one revoking its own
      --  certificate (PKITS 4.4.21). Same-name rule keeps a CRL from an
      --  unrelated CA out even when that CA is in the pool (4.14.27).

      --  The nested helpers are proved as subprograms of their own, so the
      --  enclosing Check_CRLs precondition is restated where they rely on it.
      function Same_CA_Name (J : Natural) return Boolean
      with Pre => J < Int_Count and then J < Max_Pool_Size and then Ints (J).Present
                  and then Leaf_DER'First = 0
                  and then Leaf_DER'Last < X509.N32 (Max_Cert_DER)
                  and then Issuer_DER'First = 0
                  and then Issuer_DER'Last < X509.N32 (Max_Cert_DER);

      function Same_CA_Name (J : Natural) return Boolean is
         C_Last : constant X509.N32 := Ints (J).DER_Len - 1;
         Subj   : constant X509.Span := X509.Subject_Raw (Ints (J).Cert);
      begin
         if not X509.Span_In_Range (Subj, C_Last) then
            return False;
         end if;
         return (X509.Span_In_Range (X509.Issuer_Raw (Leaf), Leaf_DER'Last)
                 and then Span_Bytes_Equal (Ints (J).DER (0 .. C_Last), Subj,
                                            Leaf_DER, X509.Issuer_Raw (Leaf)))
           or else (X509.Span_In_Range (X509.Subject_Raw (Issuer), Issuer_DER'Last)
                    and then Span_Bytes_Equal (Ints (J).DER (0 .. C_Last), Subj,
                                               Issuer_DER, X509.Subject_Raw (Issuer)));
      end Same_CA_Name;

      --  Is pool certificate J listed as revoked by any CRL in the store,
      --  taken from its direct issuer or from J itself as CRL signer?
      function Signer_Revoked (J : Natural) return Boolean
      with Pre => J < Int_Count and then J < Max_Pool_Size and then Ints (J).Present
                  and then Int_Count <= Max_Pool_Size
                  and then Root_Count <= Max_Root_Pool_Size
                  and then Skew_Seconds <= 86_400;

      function Signer_Revoked (J : Natural) return Boolean is
         C_Last : constant X509.N32 := Ints (J).DER_Len - 1;
         Found, In_Roots : Boolean;
         Index  : Natural;
      begin
         Find_Issuer (Ints (J).DER (0 .. C_Last), Ints (J).Cert,
                      Ints, Int_Count, Roots, Root_Count, Found, In_Roots, Index);
         for I in 1 .. Store.Count loop
            declare
               E : CRL_Entry renames Store.Entries (I);
               R : Revocation_Result;
            begin
               if E.Present
                 and then E.DER /= null
                 and then E.DER.all'First = 0
                 and then E.DER.all'Last < X509.N32 (Max_Evidence_Bytes)
                 and then X509.CRL.Is_Valid (E.View)
                 and then X509.CRL.Spans_Valid (E.View, E.DER.all'Last)
               then
                  --  self-signed revocation claim
                  Check_CRL (Ints (J).DER (0 .. C_Last), Ints (J).Cert,
                             Ints (J).DER (0 .. C_Last), Ints (J).Cert,
                             E.DER.all, E.View, Now, Skew_Seconds, R);
                  if R = Rev_Revoked then
                     return True;
                  end if;
                  if Found then
                     if In_Roots then
                        if Index < Root_Count and then Index < Max_Root_Pool_Size
                          and then Roots (Index).Present
                        then
                           Check_CRL (Ints (J).DER (0 .. C_Last), Ints (J).Cert,
                                      Roots (Index).DER (0 .. Roots (Index).DER_Len - 1),
                                      Roots (Index).Cert,
                                      E.DER.all, E.View, Now, Skew_Seconds, R);
                           if R = Rev_Revoked then
                              return True;
                           end if;
                        end if;
                     elsif Index < Int_Count and then Index < Max_Pool_Size
                       and then Ints (Index).Present
                     then
                        Check_CRL (Ints (J).DER (0 .. C_Last), Ints (J).Cert,
                                   Ints (Index).DER (0 .. Ints (Index).DER_Len - 1),
                                   Ints (Index).Cert,
                                   E.DER.all, E.View, Now, Skew_Seconds, R);
                        if R = Rev_Revoked then
                           return True;
                        end if;
                     end if;
                  end if;
               end if;
            end;
         end loop;
         return False;
      end Signer_Revoked;

      procedure Check_Other_Signers
        (CRL_DER : in     X509.Byte_Seq;
         CRL     : in     X509.CRL.CRL_View;
         R       :    out Revocation_Result)
      with Pre => CRL_DER'First = 0
                  and CRL_DER'Last < X509.N32 (Max_Evidence_Bytes)
                  and X509.CRL.Is_Valid (CRL)
                  and X509.CRL.Spans_Valid (CRL, CRL_DER'Last)
                  and Leaf_DER'First = 0
                  and Leaf_DER'Last < X509.N32 (Max_Cert_DER)
                  and X509.Spans_Valid (Leaf, Leaf_DER'Last)
                  and Issuer_DER'First = 0
                  and Issuer_DER'Last < X509.N32 (Max_Cert_DER)
                  and Int_Count <= Max_Pool_Size
                  and Root_Count <= Max_Root_Pool_Size
                  and Skew_Seconds <= 86_400;

      procedure Check_Other_Signers
        (CRL_DER : in     X509.Byte_Seq;
         CRL     : in     X509.CRL.CRL_View;
         R       :    out Revocation_Result)
      is
      begin
         R := Rev_Insufficient;
         for J in 0 .. Int_Count - 1 loop
            pragma Loop_Invariant (R = Rev_Insufficient);
            --  A candidate signer must look like a CRL issuer: a CA, or a
            --  certificate whose keyUsage grants cRLSign. Check_CRL rejects
            --  a keyUsage WITHOUT cRLSign; this closes the remaining case of
            --  a same-named end-entity certificate with no keyUsage at all.
            if Ints (J).Present
              and then Same_CA_Name (J)
              and then (X509.Is_CA (Ints (J).Cert)
                        or else (X509.Has_Key_Usage (Ints (J).Cert)
                                 and then X509.KU_CRL_Sign (Ints (J).Cert)))
            then
               declare
                  R2 : Revocation_Result;
               begin
                  Check_CRL (Leaf_DER, Leaf,
                             Ints (J).DER (0 .. Ints (J).DER_Len - 1), Ints (J).Cert,
                             CRL_DER, CRL, Now, Skew_Seconds, R2);
                  --  The signer's own chain is validated in RFC 5280 mode on
                  --  purpose: a CRL signer is not a TLS end entity, and the
                  --  WebPKI profile would reject it for lacking a SAN. What
                  --  matters is that it reaches one of the session's anchors
                  --  and is not itself revoked.
                  if R2 in Rev_Ok | Rev_Revoked
                    and then Cert_Verify.Validate_Chain
                               (Ints (J).DER (0 .. Ints (J).DER_Len - 1), Ints (J).Cert,
                                Ints, Int_Count, Roots, Root_Count, Now,
                                Hostname => "",
                                Purpose  => Purpose_Any,
                                Mode     => Mode_RFC5280) in Cert_Verify.Valid
                    and then not Signer_Revoked (J)
                  then
                     R := R2;
                     return;
                  end if;
               end;
            end if;
         end loop;
      end Check_Other_Signers;
   begin
      for I in 1 .. Store.Count loop
         pragma Loop_Invariant (Best in Rev_Insufficient | Rev_Malformed);
         declare
            E : CRL_Entry renames Store.Entries (I);
         begin
            if E.Present
              and then E.DER /= null
              and then E.DER.all'First = 0
              and then E.DER.all'Last < X509.N32 (Max_Evidence_Bytes)
              and then X509.CRL.Is_Valid (E.View)
              and then X509.CRL.Spans_Valid (E.View, E.DER.all'Last)
            then
               declare
                  R : Revocation_Result;
               begin
                  Check_CRL (Leaf_DER, Leaf, Issuer_DER, Issuer,
                             E.DER.all, E.View, Now, Skew_Seconds, R);
                  case R is
                     when Rev_Ok | Rev_Revoked =>
                        Result := R;
                        return;
                     when Rev_Malformed =>
                        Best := Rev_Malformed;
                     when Rev_Insufficient =>
                        --  Not signed by the leaf's issuer certificate:
                        --  maybe by another certificate of the same CA.
                        declare
                           R2 : Revocation_Result;
                        begin
                           Check_Other_Signers (E.DER.all, E.View, R2);
                           if R2 in Rev_Ok | Rev_Revoked then
                              Result := R2;
                              return;
                           end if;
                        end;
                  end case;
               end;
            end if;
         end;
      end loop;
      Result := Best;
   end Check_CRLs;

   ----------------------------------------------------------------------------
   --  Policy decision
   ----------------------------------------------------------------------------

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
   is
      Found    : Boolean;
      In_Roots : Boolean;
      Index    : Natural;
      --  RFC 7633 4.2.1: the leaf demands a staple. Only meaningful when
      --  we asked for one (a server cannot staple unsolicited).
      Must_Staple : constant Boolean := Staple_Asked and then X509.Must_Staple (Leaf);
      OCSP_R   : Revocation_Result := Rev_Insufficient;
      CRL_R    : Revocation_Result := Rev_Insufficient;
   begin
      Verdict := Proceed;
      if Policy = Ignore then
         return;
      end if;

      --  Nothing to evaluate: no staple, no CRLs and no must-staple
      --  demand. This is the common Soft_Fail case; skip Find_Issuer's
      --  extra signature verification entirely.
      if Stapled_Len = 0 and then not Stapled_Too_Big
        and then CRLs = null and then not Must_Staple
      then
         if Policy = Hard_Fail then
            Verdict := Fail_No_Evidence;
         end if;
         return;
      end if;

      Find_Issuer (Leaf_DER, Leaf, Ints, Int_Count, Roots, Root_Count,
                   Found, In_Roots, Index);
      if not Found then
         --  Cannot verify any evidence without the issuer's key.
         if Must_Staple then
            Verdict := Fail_Bad_Status;
         elsif Policy = Hard_Fail then
            Verdict := Fail_No_Evidence;
         end if;
         return;
      end if;

      declare
         Issuer_DER_Len : constant X509.N32 :=
           (if In_Roots then Roots (Index).DER_Len else Ints (Index).DER_Len);
         Issuer_DER : constant X509.Byte_Seq :=
           (if In_Roots then Roots (Index).DER (0 .. Issuer_DER_Len - 1)
            else Ints (Index).DER (0 .. Issuer_DER_Len - 1));
         Issuer : constant X509.Certificate :=
           (if In_Roots then Roots (Index).Cert else Ints (Index).Cert);
      begin
         --  1. Stapled OCSP
         if Stapled_Too_Big then
            OCSP_R := Rev_Malformed;
         elsif Stapled_Len > 0 then
            Check_Stapled_OCSP (Leaf_DER, Leaf, Issuer_DER, Issuer,
                                Stapled (0 .. Stapled_Len - 1),
                                Now, Allow_SHA1, Skew_Seconds, OCSP_R);
         end if;

         case OCSP_R is
            when Rev_Revoked =>
               Verdict := Fail_Revoked;
               return;
            when Rev_Ok =>
               return;
            when Rev_Malformed =>
               if Must_Staple or else Policy = Hard_Fail then
                  Verdict := Fail_Bad_Status;
                  return;
               end if;
            when Rev_Insufficient =>
               if Must_Staple then
                  Verdict := Fail_Bad_Status;
                  return;
               end if;
         end case;

         --  2. CRLs
         if CRLs /= null then
            Check_CRLs (Leaf_DER, Leaf, Issuer_DER, Issuer, CRLs.all,
                        Ints, Int_Count, Roots, Root_Count,
                        Now, Skew_Seconds, CRL_R);
         end if;
         case CRL_R is
            when Rev_Revoked =>
               Verdict := Fail_Revoked;
            when Rev_Ok =>
               null;
            when Rev_Malformed | Rev_Insufficient =>
               if Policy = Hard_Fail then
                  Verdict := Fail_No_Evidence;
               end if;
         end case;
      end;
   end Evaluate;

end SPARKTLS.Revocation;
