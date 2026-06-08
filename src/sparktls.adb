with Ada.Unchecked_Deallocation;

package body SPARKTLS with
   SPARK_Mode => On
is
   procedure Free_Byte_Seq (Ptr : in out Byte_Seq_Access) is
      procedure Dealloc is new Ada.Unchecked_Deallocation
        (Object => Byte_Seq, Name => Byte_Seq_Access);
   begin
      Dealloc (Ptr);
   end Free_Byte_Seq;

   --  RFC 7748 §6.1 / RFC 8422 §5.10: see the contract in the spec.
   --  The body accumulates a byte-wise OR; the loop invariant ties
   --  the accumulator to the existence of a non-zero byte seen so
   --  far, allowing gnatprove to discharge the function-level Post.
   function Shared_Secret_Is_Acceptable_X25519
     (Shared_Secret : Byte_Seq) return Boolean
   is
      Acc : Byte := 0;
   begin
      for I in Shared_Secret'Range loop
         pragma Loop_Invariant
           ((Acc /= 0) =
              (for some J in Shared_Secret'First .. I - 1
                 => Shared_Secret (J) /= 0));
         Acc := Acc or Shared_Secret (I);
      end loop;
      return Acc /= 0;
   end Shared_Secret_Is_Acceptable_X25519;

   --  RFC 8422 §5.1.2: see contract in spec.
   --  Returns True iff the list is non-empty AND contains at least
   --  one occurrence of 0 (uncompressed). Deprecated formats {1, 2}
   --  are silently tolerated alongside 0.
   function EC_Point_Formats_Acceptable
     (List : Byte_Seq) return Boolean
   is
   begin
      if List'Length = 0 then
         return False;
      end if;
      for I in List'Range loop
         pragma Loop_Invariant
           (not (for some J in List'First .. I - 1 => List (J) = 0));
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

   ----------------------------------------------------------------------------
   --  Compact
   --  Shift unread data to the front of the buffer to reclaim space
   ----------------------------------------------------------------------------
   procedure Compact (Buf : in out IO_Buffer)
   with Post => Buf.Read_Pos = 0
                and Available (Buf) = Available (Buf'Old)
   is
      Len : constant N32 := Available (Buf);
   begin
      if Buf.Read_Pos > 0 and Len > 0 then
         Buf.Data (0 .. Len - 1) :=
            Buf.Data (Buf.Read_Pos .. Buf.Read_Pos + Len - 1);
         Buf.Read_Pos  := 0;
         Buf.Write_Pos := Len;
      elsif Len = 0 then
         Buf.Read_Pos  := 0;
         Buf.Write_Pos := 0;
      end if;
   end Compact;

   ----------------------------------------------------------------------------
   --  Feed_Ciphertext
   ----------------------------------------------------------------------------
   procedure Feed_Ciphertext
     (S         : in out Session;
      Data      : in     Byte_Seq;
      Bytes_Fed :    out N32)
   is
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

      S.Input.Data (S.Input.Write_Pos .. S.Input.Write_Pos + Count - 1) :=
         Data (0 .. Count - 1);
      S.Input.Write_Pos := S.Input.Write_Pos + Count;

      Bytes_Fed := Count;
   end Feed_Ciphertext;

   ----------------------------------------------------------------------------
   --  Drain_Ciphertext
   ----------------------------------------------------------------------------
   procedure Drain_Ciphertext
     (S              : in out Session;
      Dest           :    out Byte_Seq;
      Bytes_Drained  :    out N32)
   is
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
      Dest (0 .. Count - 1) :=
         S.Output.Data (S.Output.Read_Pos ..
                        S.Output.Read_Pos + Count - 1);
      if Count < N32 (Dest'Length) then
         Dest (Count .. Dest'Last) := (others => 0);
      end if;

      S.Output.Read_Pos := S.Output.Read_Pos + Count;

      --  Compact after draining
      if Available (S.Output) = 0 then
         S.Output.Read_Pos  := 0;
         S.Output.Write_Pos := 0;
      end if;

      Bytes_Drained := Count;
   end Drain_Ciphertext;

   ----------------------------------------------------------------------------
   --  Read_Plaintext
   ----------------------------------------------------------------------------
   procedure Read_Plaintext
     (S          : in out Session;
      Dest       :    out Byte_Seq;
      Bytes_Read :    out N32)
   is
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
         S.App_Data (0 .. S.App_Data_Len - Count - 1) :=
            S.App_Data (Count .. S.App_Data_Len - 1);
      end if;

      S.App_Data_Len := S.App_Data_Len - Count;
      Bytes_Read := Count;
   end Read_Plaintext;

   procedure Sanitize_Keys (S : in out Session) is
   begin
      --  Zero traffic keys (both directions)
      S.Client_App.Key := (others => 0);
      S.Client_App.IV  := (others => 0);
      S.Client_App.Counter := 0;
      S.Server_App.Key := (others => 0);
      S.Server_App.IV  := (others => 0);
      S.Server_App.Counter := 0;

      --  Zero resumption master secret
      S.Res_Master     := (others => 0);
      S.Res_Master_Len := 0;

      --  Zero TLS 1.2 implicit IVs
      S.Client_IV_12 := (others => 0);
      S.Server_IV_12 := (others => 0);
      S.Client_Seq_12 := 0;
      S.Server_Seq_12 := 0;
   end Sanitize_Keys;

   ----------------------------------------------------------------------------
   --  RFC 8446 §4.2 extension policy table
   --
   --  One row per known IANA extension type. Where_Allowed is the
   --  set of message types the extension MAY appear in (server-side;
   --  CH coverage is via Tag_Is_Offered_Static). Requires_Offer is
   --  True for everything that's a server "echo / reply" — i.e. the
   --  server may only include it if the client offered it. Empty_Echo
   --  is True for extensions whose echoed body must be zero bytes
   --  (RFC 6066 §3 SNI ack, RFC 7627 EMS, etc.).
   ----------------------------------------------------------------------------
   function Ext_Policy_For (Tag : Interfaces.Unsigned_16)
      return Ext_Policy is
   begin
      case Tag is
         when 16#0000# =>  --  server_name (RFC 6066)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_SH12 | E_EE => True,
                                  others => False),
               Requires_Offer => True,
               Empty_Echo     => True,
               Always_In_CH   => False);

         when 16#000A# =>  --  supported_groups (RFC 7919, RFC 8446)
            --  Strictly RFC 8446 §4.2 only lists CH/EE, but in
            --  practice some TLS 1.2 servers echo supported_groups
            --  in SH for client-preference signaling — clients must
            --  tolerate. BoGo SupportedCurves-ServerHello-TLS12.
            return
              (Known => True,
               Where_Allowed  =>
                 (E_CH | E_EE | E_SH12 => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => True);

         when 16#000B# =>  --  ec_point_formats (RFC 4492 / 8422)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_SH12 => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => True);

         when 16#000D# =>  --  signature_algorithms (RFC 8446 §4.2.3)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_CR => True, others => False),
               Requires_Offer => False,
               Empty_Echo     => False,
               Always_In_CH   => True);

         when 16#000F# =>  --  heartbeat (RFC 6520)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_EE => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0010# =>  --  ALPN (RFC 7301)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_SH12 | E_EE => True,
                                  others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0012# =>  --  signed_certificate_timestamp (RFC 6962)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_SH12 | E_CR | E_CT => True,
                                  others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0017# =>  --  extended_master_secret (RFC 7627)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_SH12 => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => True,
               Always_In_CH   => False);

         when 16#001B# =>  --  compress_certificate (RFC 8879)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_CR => True, others => False),
               Requires_Offer => False,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#001C# =>  --  record_size_limit (RFC 8449)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_SH12 | E_EE => True,
                                  others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0023# =>  --  session_ticket (RFC 5077)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_SH12 => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0029# =>  --  pre_shared_key (RFC 8446 §4.2.11)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_SH13 => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#002A# =>  --  early_data (RFC 8446 §4.2.10)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_EE | E_NST => True,
                                  others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#002B# =>  --  supported_versions (RFC 8446 §4.2.1)
            return
              (Known => True,
               Where_Allowed  =>
                 (E_CH | E_SH13 | E_HRR => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => True);

         when 16#002C# =>  --  cookie (RFC 8446 §4.2.2)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_HRR => True, others => False),
               Requires_Offer => False,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#002D# =>  --  psk_key_exchange_modes (RFC 8446 §4.2.9)
            return
              (Known => True,
               Where_Allowed  => (E_CH => True, others => False),
               Requires_Offer => False,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#002F# =>  --  certificate_authorities (RFC 8446 §4.2.4)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_CR => True, others => False),
               Requires_Offer => False,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0032# =>  --  signature_algorithms_cert (RFC 8446 §4.2.3)
            return
              (Known => True,
               Where_Allowed  => (E_CH | E_CR => True, others => False),
               Requires_Offer => False,
               Empty_Echo     => False,
               Always_In_CH   => False);

         when 16#0033# =>  --  key_share (RFC 8446 §4.2.8)
            return
              (Known => True,
               Where_Allowed  =>
                 (E_CH | E_SH13 | E_HRR => True, others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => True);

         when 16#FF01# =>  --  renegotiation_info (RFC 5746)
            return
              (Known => True,
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
              (Known => False,
               Where_Allowed  => (others => False),
               Requires_Offer => True,
               Empty_Echo     => False,
               Always_In_CH   => False);
      end case;
   end Ext_Policy_For;

   procedure Validate_Server_Ext
     (Where    : in     Ext_Where;
      Tag      : in     Interfaces.Unsigned_16;
      Body_Len : in     N32;
      HC       : in     Handshake_Context;
      OK       :    out Boolean;
      Err      :    out Error_Code)
   is
      Policy : constant Ext_Policy := Ext_Policy_For (Tag);
   begin
      OK  := True;
      Err := No_Error;

      --  Unknown extension tag. RFC 8446 §4.3.2 / §4.4: clients MUST
      --  ignore unrecognised extensions in CR / CT / NST (extension
      --  points designed for forward extensibility). Elsewhere — SH,
      --  EE, HRR — unknown tags are forbidden because the server can
      --  only echo extensions the client offered, and we don't offer
      --  unknown tags. BoGo
      --  UnknownExtensionInCertificateRequest-TLS13 confirms the CR
      --  ignore behaviour.
      if not Policy.Known then
         if Where = E_CR or Where = E_CT or Where = E_NST then
            return;
         end if;
         OK  := False;
         Err := Unsupported_Extension;
         return;
      end if;

      if not Policy.Where_Allowed (Where) then
         OK  := False;
         Err := Unsupported_Extension;
         return;
      end if;

      if Policy.Requires_Offer and then not Tag_Is_Offered (Tag, HC) then
         OK  := False;
         Err := Unsupported_Extension;
         return;
      end if;

      if Policy.Empty_Echo and then Body_Len /= 0 then
         OK  := False;
         Err := Decode_Error;
         return;
      end if;
   end Validate_Server_Ext;

   procedure Validate_ALPN_Echo_Body
     (Data       : in     Byte_Seq;
      Body_Start : in     N32;
      E_Len      : in     N32;
      HC         : in     Handshake_Context;
      S          : in out Session;
      OK         :    out Boolean;
      Err        :    out Error_Code)
   is
   begin
      OK  := True;
      Err := No_Error;

      --  Smallest valid body is 4: list_len(2)+proto_len(1)+1 byte.
      if E_Len < 4 then
         OK  := False;
         Err := Decode_Error;
         return;
      end if;

      declare
         List_Len  : constant N32 :=
            N32 (Data (Body_Start)) * 256
            + N32 (Data (Body_Start + 1));
         Proto_Len : constant N32 := N32 (Data (Body_Start + 2));
      begin
         if Proto_Len = 0
           or List_Len /= 1 + Proto_Len
           or 2 + List_Len /= E_Len
         then
            OK  := False;
            Err := Decode_Error;
            return;
         end if;

         --  RFC 7301 §3.2: chosen proto MUST be one we offered.
         --  Single-proto offer today (Cfg.ALPN).
         if Proto_Len /= N32 (HC.Cfg.ALPN.Len)
           or Proto_Len > N32 (Max_Hostname_Len)
         then
            OK  := False;
            Err := Illegal_Parameter;
            return;
         end if;

         for I in 1 .. Natural (Proto_Len) loop
            pragma Loop_Invariant
              (Proto_Len <= N32 (Max_Hostname_Len)
               and Natural (Proto_Len) = HC.Cfg.ALPN.Len);
            if Character'Val (Data (Body_Start + 2 + N32 (I)))
              /= HC.Cfg.ALPN.Data (I)
            then
               OK  := False;
               Err := Illegal_Parameter;
               return;
            end if;
         end loop;

         --  Match — copy into Negotiated_ALPN.
         S.Negotiated_ALPN.Len := Natural (Proto_Len);
         for I in 1 .. Natural (Proto_Len) loop
            pragma Loop_Invariant
              (S.Negotiated_ALPN.Len = Natural (Proto_Len)
               and Proto_Len <= N32 (Max_Hostname_Len));
            S.Negotiated_ALPN.Data (I) :=
               Character'Val (Data (Body_Start + 2 + N32 (I)));
         end loop;
      end;
   end Validate_ALPN_Echo_Body;

end SPARKTLS;
