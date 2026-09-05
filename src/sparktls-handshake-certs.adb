with SPARKTLS.HS_Pool;
with Ada.Unchecked_Deallocation;
with SPARKTLS.RFLX_Bridge; use SPARKTLS.RFLX_Bridge;
with RFLX.TLS_Handshake.TLS_1_2_Certificate;
with RFLX.TLS_Handshake.TLS_1_2_Certificate_Entries;
with RFLX.TLS_Handshake.TLS_1_2_Certificate_Entry;

package body SPARKTLS.Handshake.Certs
  with SPARK_Mode => On
is

   pragma Unevaluated_Use_Of_Old (Allow);
   use type RBT.Length;
   use type RBT.Index;
   use type RBT.Bytes_Ptr;
   use type RBT.Bit_Length;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr)
   with Post => Buf = null;

   procedure RFLX_Free (Buf : in out RBT.Bytes_Ptr) with SPARK_Mode => Off is
      procedure Dealloc is new
        Ada.Unchecked_Deallocation (Object => RBT.Bytes, Name => RBT.Bytes_Ptr);
   begin
      Dealloc (Buf);
   end RFLX_Free;

   ------------------------------------------------------------------
   --  RFLX-to-X.509 copy helpers shared by TLS 1.2 and TLS 1.3
   ------------------------------------------------------------------

   --  Copy a single RFLX-shape cert blob (1-based RBT.Bytes index) into
   --  the X509 Byte_Seq (0-based X509 index). Isolates the index
   --  conversion + loop-invariant arithmetic from the parent
   --  Parse_Certificate_Chain_13 body so the prover sees a tight
   --  obligation rather than a deeply-nested cascade.

   procedure Copy_Cert_To_X509 (Cert_RFLX : in RBT.Bytes; Cert_X : out X509.Byte_Seq) is
   begin
      Cert_X := (others => 0);
      for J in Natural range 0 .. Cert_X'Length - 1 loop
         pragma
           Loop_Invariant
             (J in 0 .. Cert_X'Length - 1
                and J <= Max_Cert_DER - 1
                and X509.N32 (J) in Cert_X'Range
                and RBT.Index (J + 1) in Cert_RFLX'Range);
         Cert_X (X509.N32 (J)) := X509.Byte (Cert_RFLX (RBT.Index (J + 1)));
      end loop;
   end Copy_Cert_To_X509;

   procedure Parse_X509_From_RFLX
     (Cert_RFLX : in RBT.Bytes; C_Len : in N32; Cert : out X509.Certificate; OK : out Boolean)
   is
      Cert_X : X509.Byte_Seq (0 .. X509.N32 (C_Len) - 1);
   begin
      pragma Assert (X509.N32 (C_Len) <= X509.N32 (Max_Cert_DER));
      pragma Assert (Cert_X'Last < X509.N32'Last);
      Copy_Cert_To_X509 (Cert_RFLX, Cert_X);
      X509.Parse (Cert_X, Cert, OK);
   end Parse_X509_From_RFLX;

   --  Same as Copy_Cert_To_X509 but into the D.Peer_Leaf.DER buffer
   --  region (0-based, capacity Max_Cert_DER_Len).

   procedure Copy_Cert_To_Peer_DER
     (Cert_RFLX : in RBT.Bytes; D : in out SPARKTLS.HS_Pool.HS_Data; C_Len : in N32) is
   begin
      --  Ordering discipline: clear Present before touching any other
      --  component. While Present is False the Pool_Entry predicate is
      --  trivially true, so the writes below carry no proof burden; the
      --  entry only becomes "valid" again at the caller's Present write.
      D.Peer_Leaf.Present := False;
      D.Peer_Leaf.DER_Len := X509.N32 (C_Len);
      for I in N32 range 0 .. C_Len - 1 loop
         pragma Loop_Invariant (I in 0 .. C_Len - 1 and RBT.Index (I + 1) in Cert_RFLX'Range);
         D.Peer_Leaf.DER (X509.N32 (I)) := Byte (Cert_RFLX (RBT.Index (I + 1)));
      end loop;
   end Copy_Cert_To_Peer_DER;

   procedure Store_Intermediate
     (Cert_RFLX : in RBT.Bytes; Cert : in X509.Certificate; C_Len : in N32; Target : out Pool_Entry)
   is
      DER_Copy : Cert_DER_Buf := (others => 0);
   begin
      for I in N32 range 0 .. C_Len - 1 loop
         pragma
           Loop_Invariant
             (I in 0 .. C_Len - 1
                and I <= N32 (Max_Cert_DER) - 1
                and RBT.Index (I + 1) in Cert_RFLX'Range);
         DER_Copy (X509.N32 (I)) := X509.Byte (Cert_RFLX (RBT.Index (I + 1)));
      end loop;
      Target := (Cert => Cert, DER => DER_Copy, DER_Len => X509.N32 (C_Len), Present => True);
   end Store_Intermediate;

   procedure Parse_Certificate_Chain_12
     (HC     : in out Engaged_Context;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      HS_Msg : in Byte_Seq;
      OK     : out Boolean;
      Err    : out Error_Code)
   is
      package C12 renames RFLX.TLS_Handshake.TLS_1_2_Certificate;
      package C12_Entries renames RFLX.TLS_Handshake.TLS_1_2_Certificate_Entries;
      package C12_Entry renames RFLX.TLS_Handshake.TLS_1_2_Certificate_Entry;
      Body_Len : constant N32 := N32 (HS_Msg'Length) - 4;
      Buf      : RBT.Bytes_Ptr;
      Ctx      : C12.Context;
      Cert_Idx : Natural := 0;
   begin
      D.Peer_Leaf.Present := False;
      D.Peer_Leaf.DER_Len := 0;
      D.Peer_Int_Count := 0;
      OK := False;
      Err := Decode_Error;

      if Body_Len < 3 then
         return;
      end if;

      declare
         List_Len : constant N32 :=
           N32 (HS_Msg (HS_Msg'First + 4)) * 65536 + N32 (HS_Msg (HS_Msg'First + 5)) * 256
           + N32 (HS_Msg (HS_Msg'First + 6));
      begin
         if List_Len /= Body_Len - 3 then
            return;
         end if;
      end;

      Buf := new RBT.Bytes'(1 .. RBT.Index (Body_Len) => 0);
      Buf.all := To_RFLX (HS_Msg (HS_Msg'First + 4 .. HS_Msg'First + 4 + Body_Len - 1));
      C12.Initialize (Ctx, Buf, Written_Last => RBT.Bit_Length (Body_Len) * 8);
      C12.Verify_Message (Ctx);

      if not C12.Well_Formed_Message (Ctx) then
         C12.Take_Buffer (Ctx, Buf);
         RFLX_Free (Buf);
         return;
      end if;

      if C12.Field_Size (Ctx, C12.F_Certificate_List) > 0 then
         declare
            Entries_Ctx : C12_Entries.Context;
         begin
            if not C12.Has_Buffer (Ctx) then
               return;
            end if;
            if not (C12.Valid_Next (Ctx, C12.F_Certificate_List)
                    and then C12.Field_First (Ctx, C12.F_Certificate_List) rem RBT.Byte'Size = 1
                    and then C12.Available_Space (Ctx, C12.F_Certificate_List)
                             >= C12.Field_Size (Ctx, C12.F_Certificate_List)
                    and then C12.Field_Condition (Ctx, C12.F_Certificate_List))
            then
               C12.Take_Buffer (Ctx, Buf);
               RFLX_Free (Buf);
               return;
            end if;

            C12.Switch_To_Certificate_List (Ctx, Entries_Ctx);
            while C12_Entries.Has_Element (Entries_Ctx) and then Cert_Idx <= Max_Pool_Size loop
               pragma Loop_Invariant (C12_Entries.Has_Buffer (Entries_Ctx));
               pragma Loop_Invariant (C12_Entries.Valid (Entries_Ctx));
               pragma Loop_Invariant (Hash_Len (HC.Neg) = Hash_Len (HC.Neg)'Loop_Entry);
               pragma Loop_Invariant (if HC.Cfg.Local'Loop_Entry /= null then HC.Cfg.Local /= null);
               pragma
                 Loop_Invariant
                   (if HC.Cfg.Local'Loop_Entry /= null and then HC.Cfg.Local'Loop_Entry.Has_Identity
                      then HC.Cfg.Local /= null and then HC.Cfg.Local.Has_Identity);
               pragma
                 Loop_Invariant
                   (if HC.Cfg.Local'Loop_Entry /= null
                        and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid
                                   (HC.Cfg.Local'Loop_Entry)
                      then
                        HC.Cfg.Local /= null
                        and then SPARKTLS.Handshake.Server_Msgs.Local_Config_Valid (HC.Cfg.Local));

               declare
                  E_Ctx : C12_Entry.Context;
               begin
                  C12_Entries.Switch (Entries_Ctx, E_Ctx);
                  C12_Entry.Verify_Message (E_Ctx);

                  if C12_Entry.Well_Formed_Message (E_Ctx) then
                     declare
                        C_Len : constant N32 := N32 (C12_Entry.Get_Cert_Data_Length (E_Ctx));
                     begin
                        if C_Len > 0 and then C_Len <= N32 (Max_Cert_DER) then
                           declare
                              Cert_RFLX : RBT.Bytes (1 .. RBT.Index (C_Len));
                           begin
                              pragma Assert (Cert_RFLX'First = 1);
                              pragma Assert (Cert_RFLX'Length = RBT.Length (C_Len));
                              C12_Entry.Get_Cert_Data (E_Ctx, Cert_RFLX);
                              if Cert_Idx = 0 then
                                 Copy_Cert_To_Peer_DER (Cert_RFLX, D, C_Len);
                                 declare
                                    P_OK : Boolean;
                                 begin
                                    Parse_X509_From_RFLX (Cert_RFLX, C_Len, D.Peer_Leaf.Cert, P_OK);
                                    D.Peer_Leaf.Present :=
                                      P_OK and then X509.Is_Valid (D.Peer_Leaf.Cert);
                                    pragma
                                      Assert
                                        (if D.Peer_Leaf.Present
                                           then
                                             X509.Spans_Valid
                                                        (D.Peer_Leaf.Cert,
                                                         X509.N32 (D.Peer_Leaf.DER_Len) - 1));
                                 end;
                              elsif D.Peer_Int_Count < Max_Pool_Size then
                                 declare
                                    Idx  : constant Natural := D.Peer_Int_Count;
                                    C    : X509.Certificate;
                                    P_OK : Boolean;
                                 begin
                                    Parse_X509_From_RFLX (Cert_RFLX, C_Len, C, P_OK);
                                    if P_OK and then X509.Is_Valid (C) then
                                       Store_Intermediate (Cert_RFLX, C, C_Len, D.Peer_Ints (Idx));
                                       D.Peer_Int_Count := D.Peer_Int_Count + 1;
                                    end if;
                                 end;
                              end if;
                           end;
                           Cert_Idx := Cert_Idx + 1;
                        end if;
                     end;
                  end if;

                  if C12_Entries.Has_Buffer (Entries_Ctx)
                    or else not C12_Entries.Has_Element (Entries_Ctx)
                    or else not C12_Entries.Valid (Entries_Ctx)
                    or else not C12_Entry.Has_Buffer (E_Ctx)
                  then
                     return;
                  end if;
                  pragma Assert (not C12_Entries.Has_Buffer (Entries_Ctx));
                  pragma Assert (C12_Entries.Has_Element (Entries_Ctx));
                  pragma Assert (C12_Entries.Valid (Entries_Ctx));
                  pragma Assert (C12_Entry.Has_Buffer (E_Ctx));
                  C12_Entries.Update (Entries_Ctx, E_Ctx);
                  if not C12_Entries.Has_Buffer (Entries_Ctx) then
                     return;
                  end if;
                  if not C12_Entries.Valid (Entries_Ctx) then
                     C12_Entries.Take_Buffer (Entries_Ctx, Buf);
                     RFLX_Free (Buf);
                     return;
                  end if;
                  pragma Assert (C12_Entries.Has_Buffer (Entries_Ctx));
                  pragma Assert (C12_Entries.Valid (Entries_Ctx));
               end;
            end loop;

            C12_Entries.Take_Buffer (Entries_Ctx, Buf);
            RFLX_Free (Buf);
            OK := True;
            Err := No_Error;
            return;
         end;
      end if;

      C12.Take_Buffer (Ctx, Buf);
      RFLX_Free (Buf);
      OK := True;
      Err := No_Error;
   end Parse_Certificate_Chain_12;

end SPARKTLS.Handshake.Certs;
