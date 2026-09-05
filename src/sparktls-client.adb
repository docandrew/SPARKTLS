with Interfaces;          use Interfaces;
with SPARKTLS_Reassembly; use SPARKTLS_Reassembly;
with SPARKTLS.HS_Pool;
with SPARKTLS.Records;    use SPARKTLS.Records;
with SPARKTLS.Handshake;
with SPARKTLS.Handshake.Client_Msgs;
with SPARKTLS.Handshake.TLS12;
with SPARKTLS.Tickets_12;
with SPARKTLS.Records.TLS12;
with SPARKTLS.Client.TLS12;
with SPARKTLS.Client.TLS13;

package body SPARKTLS.Client
  with SPARK_Mode => On
is
   --  Frame conditions here guard a ghost accessor with 'Old inside an
   --  implication, e.g. "if not Handled then Has_Context (S) =
   --  Has_Context (S)'Old". A potentially unevaluated 'Old must otherwise
   --  statically name an entity, which a function call does not -- and the
   --  alternatives are worse: 'Old on the pointer itself is illegal (a move
   --  on an owning access type), and there is no entity to name for
   --  "is the context still borrowed out". Same allowance already used in
   --  sparktls.ads, handshake-server_msgs.ads, handshake-tls12.ads and
   --  handshake-client_msgs.adb.
   pragma Unevaluated_Use_Of_Old (Allow);

   function Lower_ASCII (C : Character) return Character
   is (if C in 'A' .. 'Z' then Character'Val (Character'Pos (C) + 32) else C);

   function Same_Hostname (Left, Right : Hostname_Buf) return Boolean is
   begin
      if Left.Len /= Right.Len then
         return False;
      end if;

      for I in 1 .. Left.Len loop
         if Lower_ASCII (Left.Data (I)) /= Lower_ASCII (Right.Data (I)) then
            return False;
         end if;
      end loop;

      return True;
   end Same_Hostname;

   procedure Check_Resume_Ticket_Usable
     (T : Session_Ticket; Clock : Get_Time_Fn; Server_Name : Hostname_Buf; Usable : out Boolean)
   with Always_Terminates => False
   is
   begin
      if not T.Valid or else T.PSK_Len = 0 or else T.Ticket_Len = 0 or else T.Lifetime = 0 then
         Usable := False;
         return;
      end if;

      if not T.Resumption_Across_Names and then not Same_Hostname (T.Server_Name, Server_Name) then
         Usable := False;
         return;
      end if;

      if Clock = null or else T.Received_At = 0 then
         Usable := True;
         return;
      end if;

      declare
         Now : constant Unsigned_64 := SPARKTLS.Tickets_12.To_Unix_Seconds (Clock.all);
      begin
         Usable := Now < T.Received_At or else Now - T.Received_At < Unsigned_64 (T.Lifetime);
      end;
   end Check_Resume_Ticket_Usable;

   ----------------------------------------------------------------------------
   --  Client_Config_Can_Start
   --
   --  A RNG callback must be supplied.
   --
   --  Certificate checking ON (not Skip_Verify) requires a CLOCK, with no
   --  exception for resumption.
   --
   --  A missing TRUST STORE is deliberately NOT fatal here: a client that
   --  only ever resumes legitimately has no roots, and the second
   --  conjunct still lets it start. If such a client is forced into a
   --  full handshake it fails closed at the same runtime guard.
   ----------------------------------------------------------------------------
   function Client_Config_Can_Start (Cfg : Config; Resume_Usable : Boolean) return Boolean
   is (not Is_Sentinel_Random (Cfg.Random)
       --  mTLS identity, if offered, must carry a certificate: the run-time
       --  enforcement of the Valid_Identity_Access predicate (mirrors the
       --  server's Configure check; predicates do not execute in shipped builds).
       and then Identity_Valid (Cfg.Local.all)
       and then (Cfg.Skip_Verify or else Cfg.Get_Time /= null)
       and then
         (Cfg.Skip_Verify
          or else (Cfg.Trust /= null and then Cfg.Get_Time /= null)
          or else Resume_Usable));

   --  Advance the version-neutral ClientHello/ServerHello prefix.
   procedure Advance_Handshake
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action);

   procedure Handle_WSH_Frame
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   with
     Pre =>
       S.State = Wait_Server_Hello
       and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length);

   procedure Handle_WSH_HS_Frame
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Rec    : in Records.Parse_Result;
      Result : out Action)
   with
     Pre =>
       S.State = Wait_Server_Hello
       and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length)

       and then Rec.OK
       and then Rec.Content = Records.Content_Handshake
       and then Rec.Fragment_Pos = Records.Record_Header_Size
       and then Rec.Fragment_Len >= 1
       and then Rec.Fragment_Len <= Records.Max_Fragment + Max_Record_Overhead
       and then Rec.Record_Len = Rec.Fragment_Pos + Rec.Fragment_Len
       and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
       and then S.Input.Read_Pos + Rec.Record_Len <= S.Input.Write_Pos
       and then S.Input.Read_Pos + Rec.Record_Len <= IO_Buffer_Capacity;

   procedure Parse_SH_From_Reasm
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   with
     Pre  =>
       S.State = Wait_Server_Hello
       and then Has_Message (D.Reasm)
       and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length),
     Post =>
       (if Result = OK and then S.State = Wait_Server_Hello
        then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length));

   procedure Finalize_SH_Processing
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   with
     Pre =>
       S.State = Wait_Server_Hello
       and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length);

   procedure Reassemble_For_SH
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Rec    : in Records.Parse_Result;
      Result : out Action)
   with
     Pre  =>
       S.State = Wait_Server_Hello
       and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length)
       and then Rec.OK
       and then Rec.Content = Records.Content_Handshake
       and then Rec.Fragment_Pos = Records.Record_Header_Size
       and then Rec.Fragment_Len >= 1
       and then Rec.Fragment_Len <= Records.Max_Fragment + Max_Record_Overhead
       and then Rec.Record_Len = Rec.Fragment_Pos + Rec.Fragment_Len
       and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
       and then S.Input.Read_Pos + Rec.Record_Len <= S.Input.Write_Pos
       and then S.Input.Read_Pos + Rec.Record_Len <= IO_Buffer_Capacity,
     Post =>
       (if Result = OK
        then
          S.State = Wait_Server_Hello
          and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length));

   procedure Reasm_Fresh_Fragment
     (S          : in out Session;
      D          : in out SPARKTLS.HS_Pool.HS_Data;
      Rec        : in Records.Parse_Result;
      Frag_Len   : in Records.Fragment_Length;
      Frag_Start : in N32;
      Result     : out Action)
   with
     Pre  =>
       S.State = Wait_Server_Hello
       and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length)
       and then Rec.OK
       and then Rec.Content = Records.Content_Handshake
       and then Rec.Fragment_Pos = Records.Record_Header_Size
       and then Rec.Fragment_Len = Frag_Len
       and then Frag_Len >= 1
       and then Frag_Len <= Records.Max_Fragment + Max_Record_Overhead
       and then Rec.Record_Len = Rec.Fragment_Pos + Rec.Fragment_Len
       and then S.Input.Read_Pos <= N32'Last - Rec.Record_Len
       and then S.Input.Read_Pos + Rec.Record_Len <= S.Input.Write_Pos
       and then S.Input.Read_Pos + Rec.Record_Len <= IO_Buffer_Capacity
       and then Frag_Start = S.Input.Read_Pos + Rec.Fragment_Pos
       and then Frag_Start <= N32'Last - Frag_Len
       and then Frag_Start + Frag_Len <= IO_Buffer_Capacity
       and then (if Frag_Len >= 4 then Frag_Start <= IO_Buffer_Capacity - 4),
     Post =>
       (if Result = OK
        then
          S.State = Wait_Server_Hello
          and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length));

   procedure Initialize_Client_Handshake (S : in out Client_Session; OK : out Boolean)
   is
      CH_Buf  : Byte_Seq (0 .. Handshake.Client_Msgs.Max_Client_Hello - 1);
      CH_Len  : N32;
      Rec_Out : N32;
   begin
      OK := False;
      Handshake.Client_Msgs.Build_Client_Hello (S.Ticket, S.Get_Time, S.HC, CH_Buf, CH_Len);

      if CH_Len = 0 then
         Set_State (S, Error_State);
         S.Last_Error := Internal_Error;
         return;
      end if;

      --  ENGAGE (phase carve): the client's own ClientHello starts the
      --  transcript; the context leaves Setup here and never returns.
      declare
         L : SPARKTLS_Transcript.Transcript_State;
      begin
         SPARKTLS_Transcript.Start (L);
         SPARKTLS_Transcript.Append (L, CH_Buf (0 .. CH_Len - 1));
         S.HC :=
           (TS                          => L,
            Cfg                         => S.HC.Cfg,
            Peer_SNI                    => S.HC.Peer_SNI,
            Client_Random               => S.HC.Client_Random,
            Server_Random               => S.HC.Server_Random,
            Client_Has_X25519           => S.HC.Client_Has_X25519,
            Client_Has_P256             => S.HC.Client_Has_P256,
            Client_Has_P384             => S.HC.Client_Has_P384,
            Client_Saw_Key_Share        => S.HC.Client_Saw_Key_Share,
            Client_Saw_Supported_Groups => S.HC.Client_Saw_Supported_Groups,
            Client_Supports_X25519      => S.HC.Client_Supports_X25519,
            Client_Supports_P256        => S.HC.Client_Supports_P256,
            Client_Supports_P384        => S.HC.Client_Supports_P384,
            KE                          => S.HC.KE,
            HRR_Sent                    => S.HC.HRR_Sent,
            Got_HRR                     => S.HC.Got_HRR,
            HRR_Cipher_Suite            => S.HC.HRR_Cipher_Suite,
            HRR_Selected_Group          => S.HC.HRR_Selected_Group,
            HRR_Cookie_Len              => S.HC.HRR_Cookie_Len,
            HRR_Cookie                  => S.HC.HRR_Cookie,
            Sent_HRR_CCS                => S.HC.Sent_HRR_CCS,
            CH_Ext_Hash                 => S.HC.CH_Ext_Hash,
            CH_Ext_Count                => S.HC.CH_Ext_Count,
            Seen_Ext_Tags               => S.HC.Seen_Ext_Tags,
            Seen_Ext_Count              => S.HC.Seen_Ext_Count,
            Client_HS                   => S.HC.Client_HS,
            Server_HS                   => S.HC.Server_HS,
            Client_HS_Secret            => S.HC.Client_HS_Secret,
            Server_HS_Secret            => S.HC.Server_HS_Secret,
            Handshake_Secret            => S.HC.Handshake_Secret,
            Master_Secret               => S.HC.Master_Secret,
            Neg                         => S.HC.Neg,
            Legacy_Session_ID           => S.HC.Legacy_Session_ID,
            Legacy_Session_ID_Len       => S.HC.Legacy_Session_ID_Len,
            Peer_Sig_Algos              => S.HC.Peer_Sig_Algos,
            Peer_Sig_Algo_Count         => S.HC.Peer_Sig_Algo_Count,
            Negotiated_Sig_Algo         => S.HC.Negotiated_Sig_Algo,
            CCS_Received                => S.HC.CCS_Received,
            T12                         => S.HC.T12,
            PSK                         => S.HC.PSK,
            Cert_Request_Received       => S.HC.Cert_Request_Received,
            Has_TLS_1_3                 => S.HC.Has_TLS_1_3,
            Saw_Supported_Versions      => S.HC.Saw_Supported_Versions,
            SV_Has_Acceptable           => S.HC.SV_Has_Acceptable,
            CKE_Received_12             => S.HC.CKE_Received_12,
            Use_EMS                     => S.HC.Use_EMS,
            EMS_Session_Hash            => S.HC.EMS_Session_Hash,
            EMS_Hash_Taken              => S.HC.EMS_Hash_Taken,
            Saw_Reneg_Info              => S.HC.Saw_Reneg_Info,
            Ext_Parse_Err               => S.HC.Ext_Parse_Err,
            Client_ALPN                 => S.HC.Client_ALPN,
            Client_ALPN_List            => S.HC.Client_ALPN_List,
            Client_ALPN_Count           => S.HC.Client_ALPN_Count,
            Master_Secret_12            => S.HC.Master_Secret_12,
            Client_Write_IV_12          => S.HC.Client_Write_IV_12,
            Server_Write_IV_12          => S.HC.Server_Write_IV_12,
            MS_Derivation               => S.HC.MS_Derivation,
            Using_PSK                   => S.HC.Using_PSK,
            Early_Data_Offered          => S.HC.Early_Data_Offered,
            Skipped_Early_Data_Records  => S.HC.Skipped_Early_Data_Records);
      end;

      --  RFC 8446 5.1: initial ClientHello uses record version 0x0301
      --  (TLS 1.0) for middlebox compatibility, even though the actual
      --  protocol is negotiated via supported_versions.
      Records.Build_Initial_ClientHello_Record
        (Fragment => CH_Buf (0 .. CH_Len - 1), Output => S.Output, Bytes_Out => Rec_Out,
        Hdr_Buf   => S.Rec_Hdr);

      if Rec_Out = 0 then
         Set_State (S, Error_State);
         S.Last_Error := Insufficient_Buffer;
      else
         OK := True;
      end if;
   end Initialize_Client_Handshake;

   function Configure (Cfg : in Config) return Session is
      OK            : Boolean;
      Resume_Usable : Boolean := False;
   begin
      Check_Resume_Ticket_Usable (Cfg.Resume_Ticket, Cfg.Get_Time, Cfg.Server_Name, Resume_Usable);

      return S : Client_Session :=
        (Role  => Role_Client,
         State => Client_Hello_Sent,
         Get_Time => Cfg.Get_Time,
         Server_Name => Cfg.Server_Name,
         HC => (Cfg => Cfg, others => <>),
         others => <>)
      do
         if not Client_Config_Can_Start (Cfg, Resume_Usable) then
            Set_State (S, Error_State);
            S.Last_Error := Bad_Configuration;
         else
            SPARKTLS.HS_Pool.Acquire (S.Slot);

            if S.Slot = No_Slot then
               S.State := Error_State;
               S.Last_Error := No_Free_Sessions;
            else
               --  RFC 8446 4.6.1: a usable saved ticket rides in the CH as pre_shared_key;
               --  the binder derives from its PSK.
               if Resume_Usable then
                  S.Ticket := Cfg.Resume_Ticket;
               end if;

               declare
                  Acquired_Slot : constant Slot_Index := S.Slot;
               begin
                  Initialize_Client_Handshake (S, OK);

                  if not OK then
                     SPARKTLS.HS_Pool.Release (Acquired_Slot);
                     S.Slot := No_Slot;
                  end if;
               end;
            end if;
         end if;
      end return;
   end Configure;

   --  Process a decrypted handshake message during the handshake
   --  RFC 8446 4.3.1 client-side EncryptedExtensions handler.
   --  Body shape check (â¥ 2-byte ext-len prefix), ALPN extraction
   --  per RFC 7301, transition to Wait_Server_Finished (PSK path)
   --  or Wait_Certificate (full handshake).
   procedure Copy_Input_Fragment
     (S : in Session; D : in out SPARKTLS.HS_Pool.HS_Data; From : in N32; Len : in N32)
   with
     Pre =>
       Len in 1 .. Max_HS_Msg
       and then From <= N32'Last - Len
       and then From + Len <= IO_Buffer_Capacity;

   procedure Copy_Input_Fragment
     (S : in Session; D : in out SPARKTLS.HS_Pool.HS_Data; From : in N32; Len : in N32) is
   begin
      --  Start a fresh reassembly from this fragment. Callers used to set the
      --  Phase/Len/Need triple themselves and then call this to move the
      --  bytes -- two half-updates that had to agree. Now the bytes ARE the
      --  state.
      Reset (D.Reasm);
      Append (D.Reasm, Byte_Seq (S.Input.Storage (Ix (From) .. Ix (From + Len - 1))));
   end Copy_Input_Fragment;

   procedure Start_Pending_SH_Reassembly
     (S          : in out Session;
      D          : in out SPARKTLS.HS_Pool.HS_Data;
      Frag_Len   : in Records.Fragment_Length;
      Frag_Start : in N32;
      Next_Read  : in Buffer_Size;
      Result     : out Action)
   with
     Pre  =>
       S.State = Wait_Server_Hello
       and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length)
       and then Frag_Len in 1 .. 3
       and then Frag_Start <= N32'Last - Frag_Len
       and then Frag_Start + Frag_Len <= IO_Buffer_Capacity
       and then Next_Read <= S.Input.Write_Pos,
     Post =>
       Result = OK
       and then S.State = Wait_Server_Hello
       and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length);

   procedure Start_Pending_SH_Reassembly
     (S          : in out Session;
      D          : in out SPARKTLS.HS_Pool.HS_Data;
      Frag_Len   : in Records.Fragment_Length;
      Frag_Start : in N32;
      Next_Read  : in Buffer_Size;
      Result     : out Action) is
   begin
      Copy_Input_Fragment (S, D, Frag_Start, Frag_Len);
      S.Input.Read_Pos := Next_Read;
      Result := OK;
   end Start_Pending_SH_Reassembly;

   procedure Start_Spanning_SH_Reassembly
     (S          : in out Session;
      D          : in out SPARKTLS.HS_Pool.HS_Data;
      Frag_Len   : in Records.Fragment_Length;
      Frag_Start : in N32;
      HS_Total   : in N32;
      Next_Read  : in Buffer_Size;
      Result     : out Action)
   with
     Pre  =>
       S.State = Wait_Server_Hello
       and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length)
       and then Frag_Len >= 4
       and then HS_Total > Frag_Len
       and then HS_Total <= Max_HS_Msg
       and then HS_Total <= Transcript_Capacity
       and then Frag_Start <= N32'Last - Frag_Len
       and then Frag_Start + Frag_Len <= IO_Buffer_Capacity
       and then Next_Read <= S.Input.Write_Pos,
     Post =>
       Result = OK
       and then S.State = Wait_Server_Hello
       and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length);

   procedure Start_Spanning_SH_Reassembly
     (S          : in out Session;
      D          : in out SPARKTLS.HS_Pool.HS_Data;
      Frag_Len   : in Records.Fragment_Length;
      Frag_Start : in N32;
      HS_Total   : in N32;
      Next_Read  : in Buffer_Size;
      Result     : out Action) is
   begin
      Copy_Input_Fragment (S, D, Frag_Start, Frag_Len);
      S.Input.Read_Pos := Next_Read;
      Result := OK;
   end Start_Spanning_SH_Reassembly;

   procedure Start_Complete_SH_Reassembly
     (S          : in out Session;
      D          : in out SPARKTLS.HS_Pool.HS_Data;
      Frag_Len   : in Records.Fragment_Length;
      Frag_Start : in N32;
      HS_Total   : in N32;
      Next_Read  : in Buffer_Size)
   with
     Pre  =>
       S.State = Wait_Server_Hello
       and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length)
       and then Frag_Len >= 4
       and then HS_Total >= 4
       and then HS_Total <= Frag_Len
       and then HS_Total <= Transcript_Capacity
       and then Frag_Start <= N32'Last - Frag_Len
       and then Frag_Start + Frag_Len <= IO_Buffer_Capacity
       and then Next_Read <= S.Input.Write_Pos,
     Post =>
       S.State = Wait_Server_Hello
       and then S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length);

   procedure Start_Complete_SH_Reassembly
     (S          : in out Session;
      D          : in out SPARKTLS.HS_Pool.HS_Data;
      Frag_Len   : in Records.Fragment_Length;
      Frag_Start : in N32;
      HS_Total   : in N32;
      Next_Read  : in Buffer_Size) is
   begin
      Copy_Input_Fragment (S, D, Frag_Start, Frag_Len);
      S.Input.Read_Pos := Next_Read;
   end Start_Complete_SH_Reassembly;

   procedure Reasm_Fresh_Fragment
     (S          : in out Session;
      D          : in out SPARKTLS.HS_Pool.HS_Data;
      Rec        : in Records.Parse_Result;
      Frag_Len   : in Records.Fragment_Length;
      Frag_Start : in N32;
      Result     : out Action)
   is
      Next_Read : constant Buffer_Size := S.Input.Read_Pos + Rec.Record_Len;
   begin
      Result := OK;
      --  Fresh record. Frag_Len < 4 â start
      --  reassembly with Hdr_Pending sentinel.
      if Frag_Len < 4 then
         Start_Pending_SH_Reassembly (S, D, Frag_Len, Frag_Start, Next_Read, Result);
         return;
      end if;

      --  Header is in this fragment. Decode
      --  HS_Total; if msg spans, start reassembly.
      declare
         pragma Assert (Frag_Start + 3 < IO_Buffer_Capacity);
         HS_Len   : constant N32 :=
           N32 (S.Input.Storage (Ix (Frag_Start + 1))) * 65536
           + N32 (S.Input.Storage (Ix (Frag_Start + 2))) * 256
           + N32 (S.Input.Storage (Ix (Frag_Start + 3)));
         HS_Total : constant N32 := HS_Len + 4;
      begin
         if HS_Total > Max_HS_Msg or else HS_Total > Transcript_Capacity then
            S.Input.Read_Pos := Next_Read;
            S.Last_Error := Decode_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;
         if HS_Total > Frag_Len then
            Start_Spanning_SH_Reassembly (S, D, Frag_Len, Frag_Start, HS_Total, Next_Read, Result);
            return;
         end if;
         --  Single-record happy path: buffer the
         --  WHOLE record fragment (which may include
         --  trailing packed messages per BoGo's
         --  PackHandshakeFlight). The buffer reports
         --  one message at a time, so the TLS 1.2
         --  Process_Server_Flight drains the rest.
         Start_Complete_SH_Reassembly (S, D, Frag_Len, Frag_Start, HS_Total, Next_Read);
      end;
   end Reasm_Fresh_Fragment;

   procedure Reassemble_For_SH
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Rec    : in Records.Parse_Result;
      Result : out Action)
   is
      Frag_Len   : constant N32 := Rec.Fragment_Len;
      Frag_Start : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
   begin
      Result := OK;
      if Used (D.Reasm) > 0 then
         if Has_Message (D.Reasm) then
            Result := OK;
            pragma Assert (S.State = Wait_Server_Hello);
            return;
         end if;

         declare
            Take : constant HS_Msg_Len :=
              N32'Min (N32'Min (Wanted (D.Reasm), Frag_Len), Free_Space (D.Reasm));
         begin
            if Take > 0 then
               Append (D.Reasm, Byte_Seq (S.Input.Storage (Ix (Frag_Start) .. Ix (Frag_Start + Take - 1))));
            end if;
         end;
         S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;

         --  Header just arrived: validate the peer's
         --  declared size. Nothing is stored -- the size is
         --  read from the bytes themselves.
         if Header_Ready (D.Reasm) then
            if Message_Too_Large (D.Reasm) or else Declared_Size (D.Reasm) > Transcript_Capacity
            then
               Reset (D.Reasm);
               S.Last_Error := Decode_Error;
               Set_State (S, Error_State);
               Result := Error_Alert;
               return;
            end if;
         end if;

         if not Has_Message (D.Reasm) then
            Result := OK;
            pragma Assert (S.State = Wait_Server_Hello);
            return;  --  need more fragments

         end if;
      else
         Reasm_Fresh_Fragment (S, D, Rec, Frag_Len, Frag_Start, Result);
         pragma Assert (if Result = OK then S.State = Wait_Server_Hello);
      end if;
   end Reassemble_For_SH;

   procedure Finalize_SH_Processing
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action) is
   begin
      --  PackHandshake (TLS 1.2 PackHandshakeFlight):
      --  the record may pack SH + Cert + SKE + ... +
      --  SHD. Preserve trailing bytes so the next
      --  Process_Server_Flight call drains them via
      --  its in-progress reassembly path; otherwise
      --  free the buffer.
      if S.Version = TLS_1_2 and then Has_Message (D.Reasm) then
         --  Drop the ServerHello and keep whatever the peer
         --  packed behind it, so the next
         --  Process_Server_Flight call drains it. That is
         --  exactly Consume: the shift, the tail clear, the
         --  next header decode and the re-derivation of the
         --  following message's size were all this one
         --  operation open-coded, with nine bounds asserts
         --  to justify the arithmetic.
         Consume (D.Reasm);

         --  The NEXT message's declared size is peer data,
         --  so it is validated here rather than trusted.
         if Header_Ready (D.Reasm)
           and then
             (Message_Too_Large (D.Reasm) or else Declared_Size (D.Reasm) > Transcript_Capacity)
         then
            Reset (D.Reasm);
            S.Last_Error := Decode_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;
      else
         Reset (D.Reasm);
      end if;

      if S.Version = TLS_1_3 then
         SPARKTLS.Client.TLS13.Complete_Server_Hello_13 (S, D);
      else
         --  RFC 5077 3.4 client-side resume detection.
         --  If we sent a session_ticket ext AND the
         --  server echoed it AND we have a cached
         --  ticket AND the suites match  we're in
         --  the abbreviated handshake. Install the
         --  cached master_secret + flag for the
         --  TLS 1.2 flight machinery to skip Cert/
         --  SKE/Done waiting and route NST â server
         --  CCS+Finished â our CCS+Finished.
         if S.HC.T12.Sent_Ticket_Ext
           and then S.HC.T12.Server_Will_Issue
           and then S.HC.T12.Server_Echoed_SID
           and then S.HC.Cfg.TLS12_Resume_Ticket.Valid
           and then S.HC.Cfg.TLS12_Resume_Ticket.Suite = Wire_Of (S.Negotiated_Suite)
         then
            S.HC.T12.Resuming := True;
            S.HC.Master_Secret_12 := S.HC.Cfg.TLS12_Resume_Ticket.Master_Secret;
         end if;
         S.State := Wait_Server_Finished;
      end if;
      Result := OK;
   end Finalize_SH_Processing;

   procedure Parse_SH_From_Reasm
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action) is
   begin
      Result := OK;
      --  Full ServerHello reassembled.
      declare
         Frag      : constant Message_Bytes := Message (D.Reasm);
         pragma Assert (Has_Message (D.Reasm));  --  PROBE-T8
         Parse_OK  : Boolean;
         Candidate : TLS_Version;
      begin
         --  RFC 8446 4 / RFC 5246 7.4: the first
         --  message in this state MUST be ServerHello
         --  (type 2). Any other handshake type is an
         --  unexpected_message  BoGo
         --  WrongMessageType-ServerHello tests this.
         if Frag (Frag'First) /= HS_Msg_Wire (HT_Server_Hello) then
            S.Last_Error := Unexpected_Message;
         end if;
         Handshake.Client_Msgs.Parse_Server_Hello
           (S.Negotiated_Suite,
            S.Last_Error,
            S.Negotiated_ALPN,
            S.HC,
            Byte_Seq (Frag),
            Candidate,
            Parse_OK);

         if not Parse_OK then
            if S.Last_Error = No_Error then
               S.Last_Error := Handshake_Failure;
            end if;
            --  Queue a plaintext alert on the wire so
            --  the peer sees a real :DECODE_ERROR: /
            --  :ILLEGAL_PARAMETER: rather than TCP RST.
            --  Pre-key state  alert is unencrypted.
            declare
               Ignored_A : N32;
            begin
               Abort_Flight (S);
               Records.Build_Plaintext_Alert
                 (Level     => 2,
                  Desc      => Alert_Desc (S.Last_Error),
                  Output    => S.Output,
                  Bytes_Out => Ignored_A,
                  Hdr_Buf   => S.Rec_Hdr);
            end;
            S.State := Error_State;
            Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
            Reset (D.Reasm);
            return;
         end if;

         if S.Version = TLS_Undetermined then
            S.Version := Candidate;
         elsif S.Version /= Candidate then
            S.Last_Error := Illegal_Parameter;
            S.State := Error_State;
            Result := Error_Alert;
            Reset (D.Reasm);
            return;
         end if;

         --  RFC 8446 4.1.4 HelloRetryRequest: if
         --  the SH was actually an HRR (sentinel
         --  random recognised by Parse_Server_Hello),
         --  replace the CH1 transcript with a
         --  synthetic `message_hash` (4.4.1):
         --
         --    Transcript-Hash(CH1) â 32 bytes
         --    Transcript becomes 0xFE 00 00 20 || hash
         --
         --  Then append the HRR bytes and build &
         --  send CH2. Stay in Wait_Server_Hello to
         --  receive the real SH.
         if S.HC.Got_HRR and then not S.HC.Sent_HRR_CCS then
            if Used (D.Reasm) > Message_Length (D.Reasm) then
               pragma Assert (Has_Message (D.Reasm));  --  PROBE-T8
               declare
                  Ignored_A : N32;
               begin
                  Abort_Flight (S);
                  Records.Build_Plaintext_Alert
                    (Level     => 2,
                     Desc      => Alert_Desc (Unexpected_Message),
                     Output    => S.Output,
                     Bytes_Out => Ignored_A,
                     Hdr_Buf   => S.Rec_Hdr);
               end;
               S.Last_Error := Unexpected_Message;
               S.State := Error_State;
               Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
               Reset (D.Reasm);
               return;
            end if;

            --  RFC 8446 4.4.1 via the streaming ADT.
            --  The HRR names the suite, so select the
            --  digest first; the OLD code hard-coded
            --  SHA-256 here, wrong for 384 suites.
            SPARKTLS_Transcript.Select_Hash
              (S.HC.TS,
               (if S.Negotiated_Suite = Suite_AES_256_GCM_SHA384
                then SPARKTLS_Transcript.Only_384
                else SPARKTLS_Transcript.Only_256));
            SPARKTLS_Transcript.Reset_For_HRR (S.HC.TS);
            SPARKTLS_Transcript.Append (S.HC.TS, Byte_Seq (Frag));

            if S.HC.HRR_Cookie_Len > N32 (S.HC.HRR_Cookie'Length)
              or else
                (S.HC.Cfg.TLS12_Resume_Ticket.Valid
                 and then S.HC.Cfg.TLS12_Resume_Ticket.Ticket_Len > Max_TLS12_Ticket_Len)
            then
               S.Last_Error := Internal_Error;
               S.State := Error_State;
               Result := Error_Alert;
               Reset (D.Reasm);
               return;
            end if;
            pragma Assert (S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length));
            --  Build and send CH2.
            declare
               CH2_Buf         : Byte_Seq (0 .. Handshake.Client_Msgs.Max_Client_Hello - 1);
               CH2_Len         : N32;
               Ignored_Rec_Out : N32;
            begin
               Handshake.Client_Msgs.Build_Client_Hello
                 (S.Ticket, S.Get_Time, S.HC, CH2_Buf, CH2_Len, Retry_Mode => True);
               if CH2_Len = 0 or else CH2_Len > N32 (CH2_Buf'Length) then
                  S.Last_Error := Internal_Error;
                  S.State := Error_State;
                  Result := Error_Alert;
                  Reset (D.Reasm);
                  return;
               end if;
               SPARKTLS_Transcript.Append (S.HC.TS, CH2_Buf (0 .. CH2_Len - 1));
               --  RFC 8446 D.4 middlebox-compat:
               --  emit dummy CCS between HRR and
               --  CH2 so the server's
               --  expectChangeCipherSpec is
               --  satisfied. This is the only CCS
               --  the client sends in the HRR
               --  flow; the post-SH flight skips
               --  the CCS emission it would
               --  normally do (handled below).
               declare
                  Ignored_CCS_Bytes : N32;
               begin
                  Records.Build_CCS_Record (S.Output, Ignored_CCS_Bytes);
               end;
               S.HC.Sent_HRR_CCS := True;
               Records.Build_Handshake_Record
                 (CH2_Buf (0 .. CH2_Len - 1), S.Output, Ignored_Rec_Out, S.Rec_Hdr);
            end;
            --  Reset Has_TLS_1_3 so the next SH
            --  parse re-derives it; without this,
            --  the second SH's matrix lookup uses
            --  a stale Where.
            Reset (D.Reasm);
            S.HC.Has_TLS_1_3 := False;
            Result := Has_Output;
            return;
         end if;

         SPARKTLS_Transcript.Append (S.HC.TS, Byte_Seq (Frag));
         pragma Assert (S.HC.HRR_Cookie_Len <= N32 (S.HC.HRR_Cookie'Length));
      end;
   end Parse_SH_From_Reasm;

   procedure Handle_WSH_HS_Frame
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Rec    : in Records.Parse_Result;
      Result : out Action) is
   begin
      --  Reassemble across records (BoGo SplitHandshakeRecords with
      --  MaxHandshakeRecordLength=1 fragments ServerHello into ~80
      --  single-byte records). Reassemble_For_SH does the heavy
      --  reassembly bookkeeping; Parse_SH_From_Reasm decodes the
      --  completed SH (and handles HRR); Finalize_SH_Processing
      --  installs handshake keys and transitions state.
      Reassemble_For_SH (S, D, Rec, Result);
      if Result /= OK then
         return;
      end if;
      if not Has_Message (D.Reasm) then
         return;
      end if;

      Parse_SH_From_Reasm (S, D, Result);
      if Result /= OK then
         return;
      end if;
      if S.State /= Wait_Server_Hello then
         return;
      end if;

      Finalize_SH_Processing (S, D, Result);
   end Handle_WSH_HS_Frame;

   procedure Handle_WSH_Frame
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action) is
   begin
      if Input_Available (S) = 0 then
         Result := Need_Input;
         return;
      end if;

      --  Parse record from input
      declare
         Rec : Records.Parse_Result;
      begin
         Records.Parse_Record_Header
           (Data   => Byte_Seq (S.Input.Storage (Ix (S.Input.Read_Pos) .. Ix (S.Input.Write_Pos - 1))),
            Avail  => Available (S.Input),
            Result => Rec,
            Hdr    => S.Rec_Hdr);

         if Rec.Bad_Version then
            S.Last_Error := Protocol_Version;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;

         --  RFC 8446 5.1 / 5.2: a record whose declared
         --  fragment length exceeds the per-type cap must be
         --  rejected with `record_overflow`. Without this
         --  check the parser would loop on Need_Input
         --  forever. BoGo LargePlaintext sends maxPlaintext+1.
         if Rec.Overflow then
            S.Last_Error := Record_Overflow;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;

         if not Rec.OK then
            Result := Need_Input;
            return;
         end if;

         case Rec.Content is
            when Records.Content_Handshake          =>
               Handle_WSH_HS_Frame (S, D, Rec, Result);

            when Records.Content_Change_Cipher_Spec =>
               --  RFC 8446 5: a TLS 1.3 client may receive at
               --  most ONE CCS for middlebox-compat between
               --  ServerHello and the encrypted handshake.
               --  Subsequent CCS records are unexpected. BoGo
               --  TooManyChangeCipherSpec-Client-TLS13 forces 33
               --  CCS records and expects rejection
               --  (:TOO_MANY_EMPTY_FRAGMENTS:). Payload MUST be
               --  the single byte 0x01 (BoGo BadChangeCipherSpec).
               declare
                  CCS_Pos : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
                  CCS_OK  : constant Boolean :=
                    Rec.Fragment_Len = 1 and then S.Input.Storage (Ix (CCS_Pos)) = 16#01#;
               begin
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  if CCS_OK and then not S.HC.CCS_Received then
                     S.HC.CCS_Received := True;
                     Result := OK;
                  else
                     --  Pre-key state: plaintext alert.
                     declare
                        A : N32;
                     begin
                        Abort_Flight (S);
                        Records.Build_Plaintext_Alert
                          (Level     => 2,
                           Desc      => Alert_Desc (Unexpected_Message),
                           Output    => S.Output,
                           Bytes_Out => A,
                           Hdr_Buf   => S.Rec_Hdr);
                        pragma Assert (A <= N32 (S.Output.Storage'Length));
                     end;
                     S.Last_Error := Unexpected_Message;
                     Set_State (S, Error_State);
                     Result := (if Output_Pending (S) > 0 then Has_Output else Error_Alert);
                  end if;
               end;

            when Records.Content_Alert              =>
               --  Plaintext alert before keys are established
               --  (e.g. server's close_notify, warning alert,
               --  or fatal alert). TLS 1.2 peers may send
               --  warning-level unrecognized_name before
               --  ServerHello; tolerate bounded warning alerts
               --  like the later TLS 1.2 alert-handling paths.
               declare
                  Alert_Pos : constant N32 := S.Input.Read_Pos + Rec.Fragment_Pos;
               begin
                  S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
                  if Rec.Fragment_Len /= 2 then
                     S.Last_Error := Decode_Error;
                     Set_State (S, Error_State);
                     Result := Error_Alert;
                  elsif S.Input.Storage (Ix (Alert_Pos)) = 1 and then S.Input.Storage (Ix (Alert_Pos + 1)) /= 0
                  then
                     if S.Warning_Alerts_Recvd >= Max_Warning_Alerts then
                        S.Last_Error := Decode_Error;
                        Set_State (S, Error_State);
                        Result := Error_Alert;
                     else
                        S.Warning_Alerts_Recvd := S.Warning_Alerts_Recvd + 1;
                        Result := OK;
                     end if;
                  elsif S.Input.Storage (Ix (Alert_Pos + 1)) = 0 then
                     --  close_notify before ServerHello: the peer
                     --  hung up mid-handshake. Unchanged behaviour.
                     S.Last_Error := Unexpected_Message;
                     Set_State (S, Error_State);
                     Result := Error_Alert;
                  else
                     --  Fatal alert. Reflect the peer's description
                     --  instead of discarding it: the server has
                     --  just told us why it rejected the handshake
                     --  (e.g. handshake_failure when no signature
                     --  algorithm is shared), and reporting
                     --  "unexpected message" hides that. No alert
                     --  is queued in reply -- we are reacting to
                     --  the peer's alert, not raising our own.
                     S.Last_Error := Error_From_Alert (S.Input.Storage (Ix (Alert_Pos + 1)));
                     Set_State (S, Error_State);
                     Result := Error_Alert;
                  end if;
               end;

            when others                             =>
               --  RFC 8446 6.2: any other record type  most
               --  commonly Content_Application_Data  before
               --  ServerHello is a record-layer state-machine
               --  violation. Reject with unexpected_message
               --  (BoGo AppDataBeforeHandshake, expected
               --  ":UNEXPECTED_RECORD:").
               S.Input.Read_Pos := S.Input.Read_Pos + Rec.Record_Len;
               S.Last_Error := Unexpected_Message;
               Set_State (S, Error_State);
               Result := Error_Alert;
         end case;
      end;
   end Handle_WSH_Frame;

   procedure Advance_Handshake
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action) is
   begin
      --  This parent state machine owns only the version-neutral prefix.
      --  ServerHello commits S.Version before post-negotiation dispatch.
      case S.State is
         when Client_Hello_Sent =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            else
               Set_State (S, Wait_Server_Hello);
               Result := Need_Input;
            end if;

         when Wait_Server_Hello =>
            Handle_WSH_Frame (S, D, Result);

         when others            =>
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
      end case;
   end Advance_Handshake;
   procedure Scrub_Handshake_Context (HC : in out Handshake_Context) is
   begin
      HC.KE.Shared := (others => 0);
      HC.Client_HS_Secret := (others => 0);
      HC.Server_HS_Secret := (others => 0);
      HC.Handshake_Secret := (others => 0);
      HC.Master_Secret := (others => 0);
      HC.Master_Secret_12 := (others => 0);
      HC.KE.Local_SK := (others => 0);
      HC.KE.P256_SK := (others => 0);
      HC.KE.P384_SK := (others => 0);
      SPARKTLS_Transcript.Wipe (HC.TS);
      HC.T12.Resumed_Master_Secret := (others => 0);
      HC.EMS_Session_Hash := (others => 0);
      HC.PSK.Value := (others => 0);
      HC.PSK.Binder := (others => 0);
      HC.PSK.Offer_ID := (others => 0);
      HC.Client_Random := (others => 0);
      HC.Server_Random := (others => 0);
   end Scrub_Handshake_Context;

   procedure Advance_Client_Non_Handshake
     (S : in out Session; Result : out Action; Handled : out Boolean)
   with
     Pre  =>
       S.Role = Role_Client
       and then S.App_Data_Len <= Max_Record_Plaintext
       and then Warning_Alerts_Bounded_RFC_8446_6_1 (S)
       and then Empty_Records_Bounded_RFC_8446_5_2 (S),
     --  Frame, scoped deliberately to the not-Handled path.
     --
     --  That is the only path Advance continues on, and it is the
     --  "others" branch here, which assigns nothing but Result and
     --  Handled. So this is provable locally, WITHOUT pushing frame
     --  conditions down into Process_Connected / Process_Connected_12
     --  and the rest of the TLS 1.3 handler chain -- threading frames
     --  through that chain previously turned one finding into six and
     --  had to be reverted, so it is avoided here on purpose.
     Post =>
       (if not Handled
        then
          S.State = S.State'Old
          and then S.Role = S.Role'Old
          and then Has_Context (S) = Has_Context (S)'Old)
   is
   begin
      Handled := True;
      case S.State is
         when Connected =>
            if Output_Pending (S) > 0 then
               --  Drain queued output (e.g. abbreviated TLS 1.2
               --  resumption's CCS+Finished) before handing control
               --  back to the caller.
               Result := Has_Output;
            elsif S.Handshake_Just_Done then
               --  Deliver Handshake_Done exactly once after the
               --  handshake finished AND all queued output is on the
               --  wire. The caller relies on this signal to mark the
               --  connection ready for app data.
               S.Handshake_Just_Done := False;
               Result := Handshake_Done;
            else
               case S.Version is
                  when TLS_1_2          =>
                     SPARKTLS.Client.TLS12.Process_Connected_12 (S, Result);

                  when TLS_1_3          =>
                     SPARKTLS.Client.TLS13.Process_Connected_13 (S, Result);

                  when TLS_Undetermined =>
                     S.Last_Error := Internal_Error;
                     Set_State (S, Error_State);
                     Result := Error_Alert;
               end case;
            end if;

         when Closing   =>
            if Output_Pending (S) > 0 then
               Result := Has_Output;
            elsif Input_Available (S) > 0 then
               case S.Version is
                  when TLS_1_2          =>
                     SPARKTLS.Client.TLS12.Process_Connected_12 (S, Result);

                  when TLS_1_3          =>
                     SPARKTLS.Client.TLS13.Process_Connected_13 (S, Result);

                  when TLS_Undetermined =>
                     S.Last_Error := Internal_Error;
                     Set_State (S, Error_State);
                     Result := Error_Alert;
               end case;
            elsif S.Peer_Closed_Cleanly then
               --  Both directions are closed: our close_notify is sent
               --  and the peer's has arrived. THIS -- not our own send
               --  buffer draining -- is what completes a TLS close.
               --  Zero the traffic keys here, where the connection is
               --  genuinely finished.
               S.Server_App.Key := (others => 0);
               S.Server_App.IV := (others => 0);
               S.Client_App.Key := (others => 0);
               S.Client_App.IV := (others => 0);
               Set_State (S, Closed);
               Result := Shutdown;
            else
               --  Half-duplex close in progress (RFC 8446 6.1). We have
               --  closed our WRITE direction; the peer has not closed
               --  theirs, so the READ direction is still open and this
               --  connection is NOT finished. Stay in Closing.
               --
               --  Critically, keep the read key: it is what authenticates
               --  a late close_notify. Zeroing it here -- which is what
               --  this branch used to do -- destroyed the only means of
               --  telling an orderly close from a truncation attack, and
               --  left Peer_Closed_Cleanly permanently False.
               --
               --  Report Shutdown, not Need_Input: an application that
               --  stops here behaves exactly as it always has and can
               --  never hang waiting for a close_notify that an attacker
               --  simply will not send. One that keeps reading until the
               --  transport ends reaches Closed via the peer's
               --  close_notify, and can then distinguish the two cases.
               --
               --  This mirrors OpenSSL's SSL_shutdown returning 0 (sent,
               --  not yet received) versus 1 (both).
               Result := Shutdown;
            end if;

         when Closed    =>
            --  The connection is finished. A peer may still have records
            --  in flight -- BoGo's Shutdown-Shim-* tests drain after
            --  close_notify with -check-close-notify, and a real
            --  application may call Advance again for the same reason.
            --  Report Shutdown idempotently and discard anything that
            --  arrives: the traffic keys have already been zeroed, so
            --  there is nothing left to decrypt with, and nothing useful
            --  a late record could tell us.
            --
            --  Before 2026-08-17 this fell through to "others", which set
            --  Handled := False and let Advance reach its "HC_Ptr = null"
            --  branch -- reporting Internal_Error for the entirely normal
            --  act of calling Advance on a closed session.
            S.Input.Read_Pos := 0;
            S.Input.Write_Pos := 0;
            Result := Shutdown;

         when others    =>
            Handled := False;
            Result := Need_Input;
      end case;
   end Advance_Client_Non_Handshake;

   procedure Advance (S : in out Session; Result : out Action) is
      Handled : Boolean;
   begin
      Advance_Client_Non_Handshake (S, Result, Handled);
      if not Handled then
         if S.Slot = No_Slot then
            S.Last_Error := Internal_Error;
            Set_State (S, Error_State);
            Result := Error_Alert;
            return;
         end if;

         declare
            Sl : constant Slot_Index := S.Slot;
         begin
            --  ClientHello and ServerHello negotiation are version-agnostic.
            --  Once ServerHello selects a version, dispatch only to that
            --  version's state machine.
            --
            --  BORROW: the handshake handlers take both S and the context.
            --  Passing S and S.HC_Ptr.C together is aliasing (SPARK RM
            --  6.4.2, reported as "high" by flow analysis -- note that
            --  --mode=check_all does NOT catch this, since aliasing is a flow
            --  check rather than a legality one). Move the pointer out of S
            --  for the duration of the call so S no longer reaches the
            --  context, then hand ownership back.
            --  #106: state-phase coupling is now single-object (S.State vs
            --  S.HC.Phase) -- the Session predicate carries it.
            if S.State in Client_Hello_Sent | Wait_Server_Hello then
               Advance_Handshake (S, SPARKTLS.HS_Pool.Slots (Sl), Result);
            else
               case S.Version is
                  when TLS_1_2          =>
                     SPARKTLS.Client.TLS12.Advance_Handshake_12
                       (S, SPARKTLS.HS_Pool.Slots (Sl), Result);

                  when TLS_1_3          =>
                     SPARKTLS.Client.TLS13.Advance_Handshake_13
                       (S, SPARKTLS.HS_Pool.Slots (Sl), Result);

                  when TLS_Undetermined =>
                     S.Last_Error := Internal_Error;
                     Set_State (S, Error_State);
                     Result := Error_Alert;
               end case;
            end if;

            if S.State = Connected or S.State = Error_State then
               S.Peer_Cert_Valid := SPARKTLS.HS_Pool.Slots (Sl).Peer_Leaf.Present;
               S.Use_EMS := S.HC.Use_EMS;
               --  Persist resumption flags out of HC before free.
               S.Resumed_From_PSK := S.HC.Using_PSK;
               --  Zero traffic keys on error (Connected path keeps them)
               if S.State = Error_State then
                  S.Server_App.Key := (others => 0);
                  S.Server_App.IV := (others => 0);
                  S.Client_App.Key := (others => 0);
                  S.Client_App.IV := (others => 0);
               end if;
               --  Zero ALL key material before freeing S.HC.
               --  This includes ephemeral keys (forward secrecy),
               --  transcript (contains plaintext handshake), and
               --  PSK material (resumption secrets).
               Scrub_Handshake_Context (S.HC);
               SPARKTLS.HS_Pool.Release (Sl);
               S.Slot := No_Slot;
            end if;
         end;
      end if;
   end Advance;

   --  Helper: derive key/IV and set Traffic_Keys based on suite.
   --  Suite must be one of the three RFC 8446 TLS-1.3 / RFC 5288/7905
   --  TLS-1.2 negotiable AEAD suites  matches the Traffic_Keys
   --  Predicate at sparktls.ads:770.
   procedure Close_Notify (S : in out Session) is
      Ignored_Alert_Out : N32;
   begin
      --  See the server-side twin. Advance zeroes the traffic keys and
      --  sets Closed once both directions have closed, but reports it with
      --  the same Shutdown result used for a half-duplex close, so an
      --  application cannot tell them apart. Encrypting here would build
      --  an alert under the all-zero scrubbed key and burn a sequence
      --  number on a dead session.
      if S.State not in Connected | Closing then
         return;
      end if;

      case S.Version is
         when TLS_1_2          =>
            Abort_Flight (S);
            Records.TLS12.Build_Alert_Record_12
              (Level       => 1,
               Desc        => 0,
               Keys        => S.Client_App,
               Implicit_IV => S.Client_IV_12,
               Output      => S.Output,
               Bytes_Out   => Ignored_Alert_Out,
               Hdr_Buf     => S.Rec_Hdr);

         when TLS_1_3          =>
            Abort_Flight (S);
            Records.Build_Alert_Record
              (Level     => 1,
               Desc      => 0,
               Keys      => S.Client_App,
               Output    => S.Output,
               Bytes_Out => Ignored_Alert_Out,
               Hdr_Buf   => S.Rec_Hdr);

         when TLS_Undetermined =>
            null;
      end case;

      if S.State = Connected then
         Set_State (S, Closing);
      end if;
   end Close_Notify;

end SPARKTLS.Client;
