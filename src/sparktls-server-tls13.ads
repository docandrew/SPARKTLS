with SPARKTLS.HS_Pool;

--  TLS 1.3 server state machine (RFC 8446).
--
--  Initial ClientHello parsing and version negotiation remain in the
--  version-neutral parent. Once S.Version is committed, the parent
--  dispatches TLS 1.3 flight construction and record processing here.
private package SPARKTLS.Server.TLS13
  with SPARK_Mode => On
is
   procedure Build_Server_Flight_13
     (S      : in out Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Cfg    : in Ready_Config;
      Result : out Action)
   with
     Pre =>
       S.Version = TLS_1_3
       and then S.Role = Role_Server
       and then S.State in Wait_Client_Hello | Wait_Client_Hello_Retry;

   procedure Advance_Handshake_13
     (S      : in out Server_Session;
      D      : in out SPARKTLS.HS_Pool.HS_Data;
      Result : out Action)
   with Pre => S.Version = TLS_1_3;

   procedure Process_Connected_13 (S : in out Session; Result : out Action)
   with
     Pre =>
       S.Version = TLS_1_3
       and then S.Role = Role_Server
       and then S.State in Connected | Closing
       and then S.App_Data_Len <= Max_Record_Plaintext
       and then Warning_Alerts_Bounded_RFC_8446_6_1 (S)
       and then Empty_Records_Bounded_RFC_8446_5_2 (S);

end SPARKTLS.Server.TLS13;
