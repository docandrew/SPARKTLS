--  RFC 8446 §4.6.3 post-handshake KeyUpdate. See the spec for why this
--  exists and why receive-only support is insufficient.

with SPARKTLS.Key_Schedule;
with SPARKTLSCrypto.Hashing.SHA256;  use SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.HKDF;            use SPARKTLSCrypto.HKDF;
with SPARKNaCl.Hashing.SHA384;
with SPARKTLSCrypto.HKDF384;

package body SPARKTLS.Key_Update with
   SPARK_Mode => On
is

   --  RFC 8446 §7.1 label for the traffic-secret ratchet. The full wire
   --  label is "tls13 traffic upd"; Expand_Label prepends the "tls13 "
   --  prefix, so only the suffix is given here.
   Traffic_Update_Label : constant String := "traffic upd";

   --  Re-derive key and IV from a (new) traffic secret. This mirrors the
   --  Set_Traffic_Keys helpers in Client and Server -- which are duplicated
   --  there already -- rather than adding a third copy to each.
   procedure Install_Keys
     (TK     :    out Traffic_Keys;
      Secret : in     Bytes_48;
      Suite  : in     Supported_Suite)
   with         Post => TK.Counter = 0
                and then TK.Suite = Suite;

   procedure Install_Keys
     (TK     :    out Traffic_Keys;
      Secret : in     Bytes_48;
      Suite  : in     Supported_Suite)
   is
   begin
      case Suite is
         when Suite_AES_256_GCM_SHA384 =>
            declare
               K384  : SPARKTLSCrypto.HKDF384.OKM384_Seq (0 .. 31);
               IV384 : SPARKTLSCrypto.HKDF384.OKM384_Seq (0 .. 11);
            begin
               Key_Schedule.Derive_Traffic_Key_IV_256 (K384, IV384, Secret);
               TK.Key := Bytes_32 (Byte_Seq (K384));
               TK.IV  := Bytes_12 (Byte_Seq (IV384));
            end;

         when Suite_AES_128_GCM_SHA256 =>
            declare
               K128 : OKM_Seq (0 .. 15);
               IV12 : OKM_Seq (0 .. 11);
            begin
               Key_Schedule.Derive_Traffic_Key_IV
                 (K128, IV12, Secret (0 .. 31));
               TK.Key := (others => 0);
               TK.Key (0 .. 15) := Bytes_16 (Byte_Seq (K128));
               TK.IV  := Bytes_12 (Byte_Seq (IV12));
            end;

         when others =>
            --  ChaCha20-Poly1305: 32-byte key.
            declare
               K32  : OKM_Seq (0 .. 31);
               IV12 : OKM_Seq (0 .. 11);
            begin
               Key_Schedule.Derive_Traffic_Key_IV
                 (K32, IV12, Secret (0 .. 31));
               TK.Key := Bytes_32 (Byte_Seq (K32));
               TK.IV  := Bytes_12 (Byte_Seq (IV12));
            end;
      end case;

      --  RFC 8446 §5.3: the sequence number resets to zero whenever the
      --  key changes. This is the whole point of the rekey -- it is what
      --  restores nonce space.
      TK.Counter := 0;
      TK.Suite   := Suite;
   end Install_Keys;

   ----------------------------------------------------------------------
   --  Update_Secret
   ----------------------------------------------------------------------

   procedure Update_Secret
     (Secret : in out Bytes_48;
      Len    : in     N32;
      TK     : in out Traffic_Keys;
      Suite  : in     Supported_Suite)
   is
      New_Secret : Bytes_48 := (others => 0);
      Empty      : constant Byte_Seq (0 .. -1) := (others => 0);
   begin
      if Len = 48 then
         declare
            OKM : SPARKTLSCrypto.HKDF384.OKM384_Seq (0 .. 47);
         begin
            Key_Schedule.Expand_Label_384
              (OKM     => OKM,
               PRK     => SPARKNaCl.Hashing.SHA384.Digest (Secret (0 .. 47)),
               Label   => Traffic_Update_Label,
               Context => Empty);
            New_Secret (0 .. 47) := Bytes_48 (Byte_Seq (OKM));
         end;
      else
         declare
            OKM : OKM_Seq (0 .. 31);
         begin
            Key_Schedule.Expand_Label
              (OKM     => OKM,
               PRK     => Digest (Secret (0 .. 31)),
               Label   => Traffic_Update_Label,
               Context => Empty);
            New_Secret (0 .. 31) := Bytes_32 (Byte_Seq (OKM));
         end;
      end if;

      --  Overwrite the old secret. The KDF is one-way, so the previous
      --  generation cannot be recovered from this one -- that is the
      --  forward secrecy KeyUpdate provides. (It does NOT provide
      --  post-compromise security: an attacker holding secret_N can
      --  derive every later generation. That is inherent to the scheme,
      --  not a defect here.)
      Secret := New_Secret;
      New_Secret := (others => 0);

      Install_Keys (TK, Secret, Suite);
   end Update_Secret;

   ----------------------------------------------------------------------
   --  Build_Key_Update
   ----------------------------------------------------------------------

   procedure Build_Key_Update
     (Out_Buf : out Byte_Seq;
      Len     : out N32;
      Request : in  Boolean)
   is
   begin
      Out_Buf := (others => 0);

      --  Handshake header: type (1) + 24-bit length (3), body is 1 byte.
      Out_Buf (0) := HS_Key_Update;
      Out_Buf (1) := 0;
      Out_Buf (2) := 0;
      Out_Buf (3) := 1;
      Out_Buf (4) := (if Request then Update_Requested
                      else Update_Not_Requested);

      Len := Key_Update_Msg_Len;
   end Build_Key_Update;

   ----------------------------------------------------------------------
   --  Parse_Key_Update
   ----------------------------------------------------------------------

   procedure Parse_Key_Update
     (Msg     : in  Byte_Seq;
      Request : out Boolean;
      Status  : out Parse_Status)
   is
   begin
      Request := False;
      Status  := Parse_Malformed;

      --  Must be exactly type + 3-byte length + 1-byte body, and the
      --  declared length must be 1. RFC 8446 §4.6.3 gives the body a fixed
      --  size, so anything else is malformed rather than an extension
      --  point.
      if Msg'Length /= Key_Update_Msg_Len then
         return;
      end if;

      if Msg (0) /= HS_Key_Update then
         return;
      end if;

      if Msg (1) /= 0 or else Msg (2) /= 0 or else Msg (3) /= 1 then
         return;
      end if;

      --  RFC 8446 §4.6.3: "Implementations which receive any other value
      --  MUST terminate the connection with an illegal_parameter alert."
      --  So an unknown request_update is rejected, not ignored.
      case Msg (4) is
         when Update_Not_Requested =>
            Request := False;
            Status  := Parse_OK;
         when Update_Requested =>
            Request := True;
            Status  := Parse_OK;
         when others =>
            --  Structurally fine, value out of range: illegal_parameter,
            --  NOT decode_error.
            Status := Parse_Bad_Value;
      end case;
   end Parse_Key_Update;

end SPARKTLS.Key_Update;
