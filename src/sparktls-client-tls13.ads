with SPARKTLS.HS_Pool;

--  TLS 1.3 client state machine (RFC 8446).
--
--  ClientHello construction and ServerHello negotiation remain in the
--  version-neutral parent.  Once the selected version is committed, the
--  parent dispatches the rest of the handshake and connected record
--  processing here.
private package SPARKTLS.Client.TLS13
  with SPARK_Mode => On
is
   --  Finish the TLS 1.3 side of ServerHello processing: derive the
   --  handshake traffic keys and enter the encrypted handshake.
   procedure Complete_Server_Hello_13
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data)
   with
     Pre =>
       S.Version = TLS_1_3
       and then S.State = Wait_Server_Hello;

   --  Step the TLS 1.3 handshake after ServerHello.
   procedure Advance_Handshake_13
     (S : in out Session; D : in out SPARKTLS.HS_Pool.HS_Data; Result : out Action)
   with
     Pre => S.Version = TLS_1_3;

   --  Process records in Connected/Closing state using TLS 1.3 framing.
   procedure Process_Connected_13 (S : in out Session; Result : out Action)
   with
     Pre =>
       S.Version = TLS_1_3
       and then S.State in Connected | Closing
       and then S.App_Data_Len <= Max_Record_Plaintext
       and then Warning_Alerts_Bounded_RFC_8446_6_1 (S)
       and then Empty_Records_Bounded_RFC_8446_5_2 (S);

end SPARKTLS.Client.TLS13;
