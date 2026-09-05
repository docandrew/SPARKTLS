with SPARKTLS.Records;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Key_Schedule;
with SPARKTLS.Key_Schedule_12;
with SPARKTLSCrypto.HKDF;
with SPARKTLSCrypto.HKDF384;

with SPARKTLS.Key_Update;

package body SPARKTLS
  with SPARK_Mode => On
is
   --  RFC 7748 6.1 / RFC 8422 5.10: see the contract in the spec.
   --  The body accumulates a byte-wise OR; the loop invariant ties
   --  the accumulator to the existence of a non-zero byte seen so
   --  far, allowing gnatprove to discharge the function-level Post.
   function Shared_Secret_Is_Acceptable_X25519 (Shared_Secret : Byte_Seq) return Boolean is
      Acc : Byte := 0;
   begin
      for I in Shared_Secret'Range loop
         pragma
           Loop_Invariant
             ((Acc /= 0) = (for some J in Shared_Secret'First .. I - 1 => Shared_Secret (J) /= 0));
         Acc := Acc or Shared_Secret (I);
      end loop;
      return Acc /= 0;
   end Shared_Secret_Is_Acceptable_X25519;

   --  RFC 8422 5.1.2: see contract in spec.
   --  Returns True iff the list is non-empty AND contains at least
   --  one occurrence of 0 (uncompressed). Deprecated formats {1, 2}
   --  are silently tolerated alongside 0.
   function EC_Point_Formats_Acceptable (List : Byte_Seq) return Boolean is
   begin
      if List'Length = 0 then
         return False;
      end if;
      for I in List'Range loop
         pragma Loop_Invariant (not (for some J in List'First .. I - 1 => List (J) = 0));
         if List (I) = 0 then
            return True;
         end if;
      end loop;
      return False;
   end EC_Point_Formats_Acceptable;

   ----------------------------------------------------------------------------
   --  Set_State
   ----------------------------------------------------------------------------
   procedure Set_State (S : in out Session; To : Connection_State) is
   begin
      S.State := To;
   end Set_State;

   procedure Copy_In (Dst : out RBT_A.Bytes; Src : in Byte_Seq) is
      subtype Target is RBT_A.Bytes (Dst'Range);
   begin
      Dst := Target (Src);
   end Copy_In;

   procedure Begin_Flight (S : in out Session) is
   begin
      S.Flight_Start := S.Output.Write_Pos;
      S.In_Flight := True;
   end Begin_Flight;

   procedure Abort_Flight (S : in out Session) is
   begin
      if S.In_Flight then
         --  Drop the partial flight. The mark was taken at Begin_Flight and
         --  Read_Pos only moves in Drain_Ciphertext, which cannot run
         --  mid-flight, so the mark is still inside the live window.
         if S.Flight_Start in S.Output.Read_Pos .. S.Output.Write_Pos then
            S.Output.Write_Pos := S.Flight_Start;
         end if;
         S.In_Flight := False;
      end if;
   end Abort_Flight;

   procedure End_Flight (S : in out Session; Failed : Boolean) is
   begin
      if Failed then
         Abort_Flight (S);
      else
         S.In_Flight := False;
      end if;
   end End_Flight;

   ----------------------------------------------------------------------------
   --  Compact
   --  Shift unread data to the front of the buffer to reclaim space
   ----------------------------------------------------------------------------
   procedure Compact (Buf : in out IO_Buffer)
   with Post => Buf.Read_Pos = 0 and Available (Buf) = Available (Buf)'Old
   is
      Len : constant N32 := Available (Buf);
   begin
      if Buf.Read_Pos > 0 and Len > 0 then
         Buf.Storage (Ix (0) .. Ix (Len - 1)) := Buf.Storage (Ix (Buf.Read_Pos) .. Ix (Buf.Read_Pos + Len - 1));
         Buf.Read_Pos := 0;
         Buf.Write_Pos := Len;
      elsif Len = 0 then
         Buf.Read_Pos := 0;
         Buf.Write_Pos := 0;
      end if;
   end Compact;

   ----------------------------------------------------------------------------
   --  Group_From_Wire
   ----------------------------------------------------------------------------
   function Group_From_Wire (W : Unsigned_16) return Maybe_ECDHE_Group is
   begin
      case W is
         when Group_Secp256r1_Wire => return Group_Secp256r1;
         when Group_Secp384r1_Wire => return Group_Secp384r1;
         when Group_X25519_Wire    => return Group_X25519;
         when others               => return Group_None;
      end case;
   end;

   ----------------------------------------------------------------------------
   --  Scheme_From_Wire
   --  Wire SignatureScheme -> enum; unknown (incl. SHA-1) -> Scheme_None.
   ----------------------------------------------------------------------------
   function Scheme_From_Wire (W : Unsigned_16) return Maybe_Sig_Scheme is
   begin
      case W is
         when 16#0401# => return Sig_RSA_PKCS1_SHA256;
         when 16#0501# => return Sig_RSA_PKCS1_SHA384;
         when 16#0601# => return Sig_RSA_PKCS1_SHA512;
         when 16#0403# => return Sig_ECDSA_P256_SHA256;
         when 16#0503# => return Sig_ECDSA_P384_SHA384;
         when 16#0804# => return Sig_RSA_PSS_SHA256;
         when 16#0805# => return Sig_RSA_PSS_SHA384;
         when 16#0806# => return Sig_RSA_PSS_SHA512;
         when 16#0807# => return Sig_Ed25519;
         when others   => return Scheme_None;
      end case;
   end Scheme_From_Wire;

   ----------------------------------------------------------------------------
   --  HS_Msg_From_Wire
   --  Wire HandshakeType byte -> enum; unknown -> HT_Unknown.
   ----------------------------------------------------------------------------
   function HS_Msg_From_Wire (W : Byte) return Maybe_HS_Msg is
   begin
      case W is
         when 16#01# => return HT_Client_Hello;
         when 16#02# => return HT_Server_Hello;
         when 16#04# => return HT_New_Session_Ticket;
         when 16#08# => return HT_Encrypted_Extensions;
         when 16#0B# => return HT_Certificate;
         when 16#0C# => return HT_Server_Key_Exchange;
         when 16#0D# => return HT_Certificate_Request;
         when 16#0E# => return HT_Server_Hello_Done;
         when 16#0F# => return HT_Certificate_Verify;
         when 16#10# => return HT_Client_Key_Exchange;
         when 16#14# => return HT_Finished;
         when others => return HT_Unknown;
      end case;
   end HS_Msg_From_Wire;

   ----------------------------------------------------------------------------
   --  Feed_Ciphertext
   ----------------------------------------------------------------------------
   procedure Feed_Ciphertext (S : in out Session; Data : in Byte_Seq; Bytes_Fed : out N32) is
      Space : N32;
      Count : N32;
   begin
      --  Compact if we're running low on write space
      if Free_Space (S.Input) < N32 (Data'Length) then
         Compact (S.Input);
      end if;

      Space := Free_Space (S.Input);

      if Space = 0 or Data'Length = 0 then
         Bytes_Fed := 0;
         return;
      end if;

      Count := N32'Min (Space, N32 (Data'Length));
      pragma Assert (Count >= 1);
      pragma Assert (Count <= Space);
      pragma Assert (S.Input.Write_Pos + Count <= IO_Buffer_Capacity);

      Copy_In (S.Input.Storage (Ix (S.Input.Write_Pos) .. Ix (S.Input.Write_Pos + Count - 1)), Data (0 .. Count - 1));
      S.Input.Write_Pos := S.Input.Write_Pos + Count;

      Bytes_Fed := Count;
   end Feed_Ciphertext;

   ----------------------------------------------------------------------------
   --  Drain_Ciphertext
   ----------------------------------------------------------------------------
   procedure Drain_Ciphertext (S : in out Session; Dest : out Byte_Seq; Bytes_Drained : out N32) is
      Avail : constant N32 := Available (S.Output);
      Count : N32;
   begin
      if Avail = 0 or Dest'Length = 0 then
         Dest := (others => 0);
         Bytes_Drained := 0;
         return;
      end if;

      Count := N32'Min (Avail, N32 (Dest'Length));
      pragma Assert (Count >= 1);
      pragma Assert (Count <= Avail);
      pragma Assert (S.Output.Read_Pos + Count <= S.Output.Write_Pos);

      --  Copy data, then zero only the unused tail
      Dest (0 .. Count - 1) := Byte_Seq (S.Output.Storage (Ix (S.Output.Read_Pos) .. Ix (S.Output.Read_Pos + Count - 1)));
      if Count < N32 (Dest'Length) then
         Dest (Count .. Dest'Last) := (others => 0);
      end if;

      S.Output.Read_Pos := S.Output.Read_Pos + Count;

      --  Compact after draining
      if Available (S.Output) = 0 then
         S.Output.Read_Pos := 0;
         S.Output.Write_Pos := 0;
      end if;

      Bytes_Drained := Count;
   end Drain_Ciphertext;

   ----------------------------------------------------------------------------
   --  Read_Plaintext
   ----------------------------------------------------------------------------
   procedure Read_Plaintext (S : in out Session; Dest : out Byte_Seq; Bytes_Read : out N32) is
      Count : N32;
   begin
      if S.App_Data_Len = 0 or Dest'Length = 0 then
         Dest := (others => 0);
         Bytes_Read := 0;
         return;
      end if;

      pragma Assert (S.App_Data_Len <= Max_Record_Plaintext);
      Count := N32'Min (S.App_Data_Len, N32 (Dest'Length));
      pragma Assert (Count >= 1);
      pragma Assert (Count <= S.App_Data_Len);
      pragma Assert (Count <= Max_Record_Plaintext);

      Dest (0 .. Count - 1) := S.App_Data (0 .. Count - 1);
      if Count < N32 (Dest'Length) then
         Dest (Count .. Dest'Last) := (others => 0);
      end if;

      --  Shift remaining data forward
      if Count < S.App_Data_Len then
         pragma Assert (S.App_Data_Len - Count >= 1);
         S.App_Data (0 .. S.App_Data_Len - Count - 1) := S.App_Data (Count .. S.App_Data_Len - 1);
      end if;

      S.App_Data_Len := S.App_Data_Len - Count;
      Bytes_Read := Count;
   end Read_Plaintext;

   ----------------------------------------------------------------------------
   --  Write_Plaintext
   ----------------------------------------------------------------------------
   --  RFC 8446 4.6.3: emit the deferred KeyUpdate reply and rotate our
   --  write key. Direction depends on role -- a client writes under
   --  Client_App, a server under Server_App.
   --
   --  Ordering matters: the message is sealed under the CURRENT write key
   --  and only then is the key rotated. Rotating first would encrypt the
   --  notification under a key the peer has not adopted yet, and it would
   --  never be readable.
   --
   --  Never sets request_update -- replying with a request would be an
   --  unbounded ping-pong (RFC 8446 4.6.3).
   --  True when our own write direction is approaching the RFC 8446 5.5
   --  AEAD usage limit and should be rotated before sending more.
   function Write_Key_Exhausted (S : Session) return Boolean
   is (if S.Role = Role_Client then S.Client_App.Counter >= Rekey_After_Records - Rekey_Margin
       else S.Server_App.Counter >= Rekey_After_Records - Rekey_Margin);

   procedure Flush_Pending_Key_Update (S : in out Session)
   with Pre => S.App_Secret_Len in 32 | 48 and then S.Version = TLS_1_3;

   procedure Flush_Pending_Key_Update (S : in out Session) is
      KU_Buf : Byte_Seq (0 .. Key_Update.Key_Update_Msg_Len - 1);
      KU_Len : N32;
      Sent   : N32;
   begin
      if S.Negotiated_Suite not in
           Suite_AES_128_GCM_SHA256
           | Suite_AES_256_GCM_SHA384
           | Suite_CHACHA20_POLY1305_SHA256
      then
         return;
      end if;

      Key_Update.Build_Key_Update (KU_Buf, KU_Len, Request => False);

      if S.Role = Role_Client then
         Records.Build_Encrypted_Record
           (Plaintext  => KU_Buf (0 .. KU_Len - 1),
            Inner_Type => 16#16#,
            Keys       => S.Client_App,
            Output     => S.Output,
            Bytes_Out  => Sent,
            Hdr_Buf    => S.Rec_Hdr);
         if Sent = 0 then
            return;   --  no room; retry on the next write

         end if;
         Key_Update.Update_Secret
           (S.Client_App_Secret, S.App_Secret_Len, S.Client_App, S.Negotiated_Suite);
      else
         Records.Build_Encrypted_Record
           (Plaintext  => KU_Buf (0 .. KU_Len - 1),
            Inner_Type => 16#16#,
            Keys       => S.Server_App,
            Output     => S.Output,
            Bytes_Out  => Sent,
            Hdr_Buf    => S.Rec_Hdr);
         if Sent = 0 then
            return;
         end if;
         Key_Update.Update_Secret
           (S.Server_App_Secret, S.App_Secret_Len, S.Server_App, S.Negotiated_Suite);
      end if;

      S.Key_Update_Pending := False;
   end Flush_Pending_Key_Update;

   procedure Request_Key_Update (S : in out Session) is
   begin
      --  TLS 1.2 has no rekey mechanism, and without retained traffic
      --  secrets there is nothing to ratchet from.
      if S.Version /= TLS_1_3 or else S.App_Secret_Len not in 32 | 48 then
         return;
      end if;

      --  Flush immediately rather than deferring to the next write. The
      --  deferred path exists to collapse a BURST of peer requests into one
      --  reply; an explicit application request should take effect when it
      --  is made, so the caller can drain and know it is done.
      S.Key_Update_Pending := True;
      Flush_Pending_Key_Update (S);
   end Request_Key_Update;

   procedure Write_Plaintext (S : in out Session; Plaintext : in Byte_Seq; Bytes_Written : out N32)
   is
      --  RFC 8446 5.1 caps a single TLS record at 2^14 bytes of
      --  plaintext. Larger writes are queued as multiple records.
      --
      --  Check output capacity before encryption. The record builders
      --  own nonce/sequence advancement, so this procedure only calls
      --  them when the whole record can fit in S.Output.
      Total          : constant N32 := N32 (Plaintext'Length);
      Pos            : N32 := 0;
      Chunk          : N32;
      Enc_Out        : N32;
      TLS13_Overhead : constant N32 := 22; -- header + inner type + tag
      TLS12_Overhead : constant N32 := 29; -- header + explicit nonce + tag
      Overhead       : constant N32 :=
        (if S.Version = TLS_1_2 then TLS12_Overhead else TLS13_Overhead);
   begin
      if S.Version = TLS_Undetermined then
         Bytes_Written := 0;
         return;
      end if;

      --  RFC 8446 4.6.3: if the peer asked us to rekey, we MUST send our
      --  KeyUpdate before the next Application Data record. Flushing it
      --  here -- rather than inline when the request arrived -- is what
      --  collapses a burst of requests into a single reply, and is also
      --  what makes the reply correct when it is discovered mid-write.
      --
      --  TLS 1.3 only: TLS 1.2 has no rekey mechanism.
      --  Two reasons to rotate our write key before sending, both
      --  discharged by the same mechanism:
      --
      --   1. The peer asked (RFC 8446 4.6.3 request_update). We owe them a
      --      KeyUpdate before the next Application Data record.
      --   2. We are approaching the RFC 8446 5.5 AEAD usage limit on our
      --      OWN write direction. Nobody will ask us to do this -- a
      --      KeyUpdate rotates only the sender's key, so protecting our
      --      write direction is ours alone to do. Without it a long-lived
      --      high-volume connection runs past the AEAD security margin and,
      --      eventually, toward the modular wrap that would reuse nonces.
      if S.Version = TLS_1_3
        and then S.App_Secret_Len in 32 | 48
        and then (S.Key_Update_Pending or else Write_Key_Exhausted (S))
      then
         Flush_Pending_Key_Update (S);
      end if;

      while Pos < Total loop
         pragma
           Loop_Invariant
             (Pos in 0 .. Total
                and S.Role = S.Role'Loop_Entry
                and S.Version = S.Version'Loop_Entry);
         pragma Loop_Variant (Increases => Pos);

         Chunk := N32'Min (Max_Record_Plaintext, Total - Pos);

         if Free_Space (S.Output) < Chunk + Overhead then
            exit;
         end if;

         if S.Role = Role_Client then
            --  TLS 1.2 cannot rekey, so the write budget is a hard stop
            --  rather than a rotation trigger; stopping at the BUDGET
            --  (cap minus margin) leaves headroom for close_notify.
            if S.Version = TLS_1_2 and then Write_Budget_Reached (S.Client_App) then
               exit;
            end if;
         else
            --  Mirror of the client side: budget stop with close_notify
            --  headroom.
            if S.Version = TLS_1_2 and then Write_Budget_Reached (S.Server_App) then
               exit;
            end if;
         end if;

         declare
            Frag_Len : constant N32 := Chunk;
            Frag     : Byte_Seq (0 .. Frag_Len - 1);
         begin
            Frag := Plaintext (Plaintext'First + Pos .. Plaintext'First + Pos + Frag_Len - 1);

            if S.Role = Role_Client then
               if S.Version = TLS_1_2 then
                  Records.TLS12.Build_Encrypted_Record_12
                    (Plaintext    => Frag,
                     Content_Type => 16#17#,
                     Keys         => S.Client_App,
                     Implicit_IV  => S.Client_IV_12,
                     Output       => S.Output,
                     Bytes_Out    => Enc_Out,
                     Hdr_Buf      => S.Rec_Hdr);
               else
                  Records.Build_Encrypted_Record
                    (Plaintext  => Frag,
                     Inner_Type => 16#17#,
                     Keys       => S.Client_App,
                     Output     => S.Output,
                     Bytes_Out  => Enc_Out,
                     Hdr_Buf    => S.Rec_Hdr);
               end if;
            else
               if S.Version = TLS_1_2 then
                  Records.TLS12.Build_Encrypted_Record_12
                    (Plaintext    => Frag,
                     Content_Type => 16#17#,
                     Keys         => S.Server_App,
                     Implicit_IV  => S.Server_IV_12,
                     Output       => S.Output,
                     Bytes_Out    => Enc_Out,
                     Hdr_Buf      => S.Rec_Hdr);
               else
                  Records.Build_Encrypted_Record
                    (Plaintext  => Frag,
                     Inner_Type => 16#17#,
                     Keys       => S.Server_App,
                     Output     => S.Output,
                     Bytes_Out  => Enc_Out,
                     Hdr_Buf    => S.Rec_Hdr);
               end if;
            end if;
         end;

         exit when Enc_Out = 0;
         Pos := Pos + Chunk;
      end loop;

      Bytes_Written := Pos;
   end Write_Plaintext;

   procedure Sanitize_Keys (S : in out Session) is
   begin
      --  Zero traffic keys (both directions)
      S.Client_App.Key := (others => 0);
      S.Client_App.IV := (others => 0);
      S.Client_App.Counter := 0;
      S.Server_App.Key := (others => 0);
      S.Server_App.IV := (others => 0);
      S.Server_App.Counter := 0;

      --  Zero resumption master secret
      S.Res_Master := (others => 0);
      S.Res_Master_Len := 0;

      --  Zero exporter material
      S.Exporter_Secret := (others => 0);
      S.Exporter_Secret_Len := 0;
      S.Exporter_Client_Random := (others => 0);
      S.Exporter_Server_Random := (others => 0);

      --  Zero TLS 1.2 implicit IVs
      S.Client_IV_12 := (others => 0);
      S.Server_IV_12 := (others => 0);
      --  The channel counters are zeroed with the channels themselves
      --  (Client_App / Server_App are sanitized above, Counter included).
   end Sanitize_Keys;

   ----------------------------------------------------------------------------
   --  RFC 8446 4.2 extension policy table
   --
   --  One row per known IANA extension type. Where_Allowed is the
   --  set of message types the extension MAY appear in (server-side;
   --  CH coverage is via Tag_Is_Offered_Static). Requires_Offer is
   --  True for everything that's a server "echo / reply"  i.e. the
   --  server may only include it if the client offered it. Empty_Echo
   --  is True for extensions whose echoed body must be zero bytes
   --  (RFC 6066 3 SNI ack, RFC 7627 EMS, etc.).
   ----------------------------------------------------------------------------
   function Ext_Policy_For (Tag : Interfaces.Unsigned_16) return Ext_Policy is
   begin
      case Tag is
         when 16#0000# =>
            --  server_name (RFC 6066)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_SH12 | E_EE => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => True,
               Always_In_CH   => False);

         when 16#000A# =>
            --  supported_groups (RFC 7919, RFC 8446)
            --  Strictly RFC 8446 4.2 only lists CH/EE, but in
            --  practice some TLS 1.2 servers echo supported_groups
            --  in SH for client-preference signaling  clients must
            --  tolerate. BoGo SupportedCurves-ServerHello-TLS12.
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_EE | E_SH12 => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => True);

         when 16#000B# =>
            --  ec_point_formats (RFC 4492 / 8422)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_SH12 => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => True);

         when 16#000D# =>
            --  signature_algorithms (RFC 8446 4.2.3)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_CR => True, others => False),
               Requires_Offer => False,
               Empty_Echo     => False,
               Always_In_CH   => True);

         when 16#000F# =>
            --  heartbeat (RFC 6520)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_EE => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0010# =>
            --  ALPN (RFC 7301)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_SH12 | E_EE => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0012# =>
            --  signed_certificate_timestamp (RFC 6962)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_SH12 | E_CR | E_CT => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0017# =>
            --  extended_master_secret (RFC 7627)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_SH12 => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => True,
               Always_In_CH   => False);

         when 16#001B# =>
            --  compress_certificate (RFC 8879)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_CR => True, others => False),
               Requires_Offer => False,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#001C# =>
            --  record_size_limit (RFC 8449)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_SH12 | E_EE => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0023# =>
            --  session_ticket (RFC 5077)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_SH12 => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0029# =>
            --  pre_shared_key (RFC 8446 4.2.11)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_SH13 => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#002A# =>
            --  early_data (RFC 8446 4.2.10)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_EE | E_NST => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#002B# =>
            --  supported_versions (RFC 8446 4.2.1)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_SH13 | E_HRR => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => True);

         when 16#002C# =>
            --  cookie (RFC 8446 4.2.2)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_HRR => True, others => False),
               Requires_Offer => False,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#002D# =>
            --  psk_key_exchange_modes (RFC 8446 4.2.9)
            return
              (Known          => True,
               Where_Allowed  => (E_CH => True, others => False),
               Requires_Offer => False,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#002F# =>
            --  certificate_authorities (RFC 8446 4.2.4)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_CR => True, others => False),
               Requires_Offer => False,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0032# =>
            --  signature_algorithms_cert (RFC 8446 4.2.3)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_CR => True, others => False),
               Requires_Offer => False,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0033# =>
            --  key_share (RFC 8446 4.2.8)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_SH13 | E_HRR => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => True);

         when 16#FF01# =>
            --  renegotiation_info (RFC 5746)
            return
              (Known          => True,
               Where_Allowed  => (E_CH | E_SH12 => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => True);

         when others =>
            --  Unknown / unsupported extension. Where_Allowed empty,
            --  so any appearance in a server-generated message will
            --  reject as unsupported_extension. Requires_Offer is
            --  irrelevant (default).
            return
              (Known          => False,
               Where_Allowed  => (others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);
      end case;
   end Ext_Policy_For;

   procedure Validate_Server_Ext
     (Where    : in Ext_Where;
      Tag      : in Interfaces.Unsigned_16;
      Body_Len : in N32;
      HC       : in Handshake_Context;
      OK       : out Boolean;
      Err      : out Error_Code)
   is
      Policy : constant Ext_Policy := Ext_Policy_For (Tag);
   begin
      OK := True;
      Err := No_Error;

      --  Unknown extension tag. RFC 8446 4.3.2 / 4.4: clients MUST
      --  ignore unrecognised extensions in CR / CT / NST (extension
      --  points designed for forward extensibility). Elsewhere  SH,
      --  EE, HRR  unknown tags are forbidden because the server can
      --  only echo extensions the client offered, and we don't offer
      --  unknown tags. BoGo
      --  UnknownExtensionInCertificateRequest-TLS13 confirms the CR
      --  ignore behaviour.
      if not Policy.Known then
         if Where = E_CR or Where = E_CT or Where = E_NST then
            return;
         end if;
         OK := False;
         Err := Unsupported_Extension;
         return;
      end if;

      if not Policy.Where_Allowed (Where) then
         OK := False;
         Err := Unsupported_Extension;
         return;
      end if;

      if Policy.Requires_Offer and then not Tag_Is_Offered (Tag, HC) then
         OK := False;
         Err := Unsupported_Extension;
         return;
      end if;

      if Policy.Empty_Echo and then Body_Len /= 0 then
         OK := False;
         Err := Decode_Error;
         return;
      end if;
   end Validate_Server_Ext;

   procedure Validate_ALPN_Echo_Body
     (Data       : in Byte_Seq;
      Body_Start : in N32;
      E_Len      : in N32;
      HC         : in Handshake_Context;
      ALPN       : in out Hostname_Buf;
      OK         : out Boolean;
      Err        : out Error_Code) is
   begin
      OK := True;
      Err := No_Error;

      --  Smallest valid body is 4: list_len(2)+proto_len(1)+1 byte.
      if E_Len < 4 then
         OK := False;
         Err := Decode_Error;
         return;
      end if;

      declare
         List_Len  : constant N32 := N32 (Data (Body_Start)) * 256 + N32 (Data (Body_Start + 1));
         Proto_Len : constant N32 := N32 (Data (Body_Start + 2));
      begin
         if Proto_Len = 0 or List_Len /= 1 + Proto_Len or 2 + List_Len /= E_Len then
            OK := False;
            Err := Decode_Error;
            return;
         end if;

         --  RFC 7301 3.2: chosen proto MUST be one we offered.
         if Proto_Len > N32 (Max_Hostname_Len) then
            OK := False;
            Err := Illegal_Parameter;
            return;
         end if;

         declare
            Match : Boolean := False;
         begin
            if HC.Cfg.ALPN_Count > 0 then
               for P in ALPN_Index loop
                  exit when P > HC.Cfg.ALPN_Count;
                  if Proto_Len = N32 (HC.Cfg.ALPN_List (P).Len) then
                     Match := True;
                     for I in 1 .. Natural (Proto_Len) loop
                        if Character'Val (Data (Body_Start + 2 + N32 (I)))
                          /= HC.Cfg.ALPN_List (P).Data (I)
                        then
                           Match := False;
                           exit;
                        end if;
                     end loop;
                     exit when Match;
                  end if;
               end loop;
            elsif Proto_Len = N32 (HC.Cfg.ALPN.Len) then
               Match := True;
               for I in 1 .. Natural (Proto_Len) loop
                  if Character'Val (Data (Body_Start + 2 + N32 (I))) /= HC.Cfg.ALPN.Data (I) then
                     Match := False;
                     exit;
                  end if;
               end loop;
            end if;

            if not Match then
               OK := False;
               Err := Illegal_Parameter;
               return;
            end if;
         end;

         --  Match  copy into Negotiated_ALPN.
         ALPN.Len := Natural (Proto_Len);
         for I in 1 .. Natural (Proto_Len) loop
            pragma
              Loop_Invariant
                (ALPN.Len = Natural (Proto_Len) and Proto_Len <= N32 (Max_Hostname_Len));
            ALPN.Data (I) := Character'Val (Data (Body_Start + 2 + N32 (I)));
         end loop;
      end;
   end Validate_ALPN_Echo_Body;

   procedure Export_Keying_Material
     (S           : in Session;
      Label       : in String;
      Context     : in Byte_Seq;
      Use_Context : in Boolean;
      Output      : out Byte_Seq;
      OK          : out Boolean) is
   begin
      Output := (others => 0);
      OK := False;

      if S.State /= Connected or else S.Exporter_Secret_Len = 0 then
         return;
      end if;

      if S.Version = TLS_Undetermined then
         return;
      elsif S.Version = TLS_1_2 then
         if S.Exporter_Secret_Len /= 48 then
            return;
         end if;

         SPARKTLS.Key_Schedule_12.Export_Keying_Material_12
           (Output        => Output,
            Master        => S.Exporter_Secret,
            Client_Random => S.Exporter_Client_Random,
            Server_Random => S.Exporter_Server_Random,
            Label         => Label,
            Context       => Context,
            Use_Context   => Use_Context,
            Use_SHA384    =>
              S.Negotiated_Suite in
                Suite_ECDHE_RSA_AES256_GCM_SHA384
                | Suite_ECDHE_ECDSA_AES256_GCM_SHA384
              );
         OK := True;
      elsif Label'Length = 0 then
         return;
      elsif S.Exporter_Secret_Len = 48 then
         declare
            Tmp : SPARKTLSCrypto.HKDF384.OKM384_Seq (0 .. Output'Length - 1);
         begin
            SPARKTLS.Key_Schedule.Export_Keying_Material_384
              (Output          => Tmp,
               Exporter_Master => S.Exporter_Secret,
               Label           => Label,
               Context         => Context);
            Output := Byte_Seq (Tmp);
            OK := True;
         end;
      elsif S.Exporter_Secret_Len = 32 then
         declare
            Tmp : SPARKTLSCrypto.HKDF.OKM_Seq (0 .. Output'Length - 1);
         begin
            SPARKTLS.Key_Schedule.Export_Keying_Material
              (Output          => Tmp,
               Exporter_Master => S.Exporter_Secret (0 .. 31),
               Label           => Label,
               Context         => Context);
            Output := Byte_Seq (Tmp);
            OK := True;
         end;
      end if;
   end Export_Keying_Material;

   --------------
   -- Describe --
   --------------

   function Describe (E : Error_Code) return String is
   begin
      --  A complete case expression: adding an Error_Code value without a
      --  description here is a compile error, not a silently wrong string.
      case E is
         when No_Error =>
            return "no error";

         when Unexpected_Message =>
            return
              "unexpected handshake message for the current state " & "(RFC 8446 6.2, alert 10)";

         when Bad_Record_MAC =>
            return "record failed AEAD authentication (RFC 8446 5.2, " & "alert 20)";

         when Record_Overflow =>
            return "record exceeded the maximum permitted length " & "(RFC 8446 5.1, alert 22)";

         when Handshake_Failure =>
            return
              "could not negotiate an acceptable set of security "
              & "parameters (RFC 8446 6.2, alert 40)";

         when Bad_Certificate =>
            return "peer certificate was malformed or could not be parsed " & "(alert 42)";

         when Certificate_Unknown =>
            return
              "peer certificate was rejected by the application verification "
              & "hook, Config.Verify_Peer (alert 46)";

         when Certificate_Expired =>
            return "peer certificate is expired or not yet valid (alert 45)";

         when Certificate_Verify_Failed =>
            return
              "peer certificate chain did not validate against the "
              & "trust store, or the hostname did not match (alert 51)";

         when Certificate_Required =>
            return
              "a client certificate was required but none was sent " & "(RFC 8446 6, alert 116)";

         when Decode_Error =>
            return
              "a message could not be decoded: a length or field was "
              & "inconsistent with the wire format (alert 50)";

         when Illegal_Parameter =>
            return "a field was syntactically correct but not permitted " & "here (alert 47)";

         when Protocol_Version =>
            return "peer offered no protocol version this configuration " & "accepts (alert 70)";

         when Unsupported_Extension =>
            return "peer sent an extension not offered in ClientHello " & "(RFC 8446 6, alert 110)";

         when Missing_Extension =>
            return "a required extension was absent (RFC 8446 6, alert 109)";

         when No_Application_Protocol =>
            return "no mutually supported ALPN protocol " & "(RFC 7301 3.2, alert 120)";

         when Internal_Error =>
            return "internal error: an invariant was violated (alert 80)";

         when Insufficient_Buffer =>
            return "the caller-supplied buffer was too small for the data";

         when Bad_Configuration =>
            return "the Config cannot start a handshake (missing RNG, missing server identity or " &
              "incoherent mTLS settings)";

         when No_Free_Sessions =>
            return "all handshake pool slots are in use; retry after a session completes or raise" &
              " the HS_Pool capacity";

         when Unsupported_Cipher_Suite =>
            return "peer selected a cipher suite this build does not " & "implement";
      end case;
   end Describe;

   ----------------------
   -- Error_From_Alert --
   ----------------------

   function Error_From_Alert (Description : Byte) return Error_Code is
   begin
      case Description is
         when 40 =>
            return Handshake_Failure;           --  handshake_failure

         when 42 | 43 =>
            return Bad_Certificate;             --  bad/unsupported cert

         when 44 =>
            return Certificate_Verify_Failed;   --  certificate_revoked

         when 45 =>
            return Certificate_Expired;         --  certificate_expired

         when 46 =>
            return Certificate_Unknown;         --  certificate_unknown

         when 47 =>
            return Illegal_Parameter;           --  illegal_parameter

         when 48 =>
            return Certificate_Verify_Failed;   --  unknown_ca

         when 49 =>
            return Certificate_Verify_Failed;   --  access_denied

         when 50 =>
            return Decode_Error;                --  decode_error

         when 51 =>
            return Certificate_Verify_Failed;   --  decrypt_error

         when 70 =>
            return Protocol_Version;            --  protocol_version

         when 71 =>
            return Handshake_Failure;           --  insufficient_security

         when 80 =>
            return Internal_Error;              --  internal_error

         when 109 =>
            return Missing_Extension;           --  missing_extension

         when 110 =>
            return Unsupported_Extension;       --  unsupported_extension

         when 112 =>
            return Illegal_Parameter;           --  unrecognized_name

         when 116 =>
            return Certificate_Required;        --  certificate_required

         when 120 =>
            return No_Application_Protocol;     --  no_application_protocol

         when others =>
            return Handshake_Failure;
      end case;
   end Error_From_Alert;

   ----------------------------------------------------------------------------
   --  To_Name
   ----------------------------------------------------------------------------
   function To_Name (ALPN_Str : String) return Hostname_Buf
   is
   begin
      return HB : Hostname_Buf do
         HB.Data (1 .. ALPN_Str'Length) := ALPN_Str;
         HB.Len := ALPN_Str'Length;
      end return;
   end To_Name;

   ----------------------------------------------------------------------------
   --  Not_Random
   ----------------------------------------------------------------------------
   procedure Not_Random (Output : out Byte_Seq)
   is
   begin
      Output := (others => 0);
   end Not_Random;

   ----------------------------------------------------------------------------
   --  Is_Sentinel_Random
   ----------------------------------------------------------------------------
   function Is_Sentinel_Random (F : Live_Random_Fn) return Boolean
      with SPARK_Mode => Off
   is
   begin
      return F = Not_Random'Access;
   end Is_Sentinel_Random;

end SPARKTLS;
