--  Bodies for the test-only accessors. Every one is a direct component
--  read or write: a child unit's body has visibility of the parent's
--  private part, which is what makes this legal without SPARKTLS exposing
--  anything to real consumers.

package body SPARKTLS.Test_Support with
   SPARK_Mode => Off
is

   procedure Reset (S : out Session) is
   begin
      S := (others => <>);
   end Reset;

   procedure Set_Negotiated_Version (S : in out Session; V : TLS_Version) is
   begin
      S.Negotiated_Version := V;
   end Set_Negotiated_Version;

   procedure Set_State (S : in out Session; V : Connection_State) is
   begin
      S.State := V;
   end Set_State;

   procedure Set_Negotiated_Suite (S : in out Session; V : Unsigned_16) is
   begin
      S.Negotiated_Suite := V;
   end Set_Negotiated_Suite;

   procedure Set_Negotiated_Suite_12 (S : in out Session; V : Unsigned_16) is
   begin
      S.Negotiated_Suite_12 := V;
   end Set_Negotiated_Suite_12;

   procedure Set_Exporter_State
     (S             : in out Session;
      Secret        : Bytes_48;
      Len           : N32;
      Client_Random : Bytes_32;
      Server_Random : Bytes_32) is
   begin
      S.Exporter_Secret         := Secret;
      S.Exporter_Secret_Len     := Len;
      S.Exporter_Client_Random  := Client_Random;
      S.Exporter_Server_Random  := Server_Random;
   end Set_Exporter_State;

   function Exporter_Secret (S : Session) return Bytes_48 is
     (S.Exporter_Secret);

   function Exporter_Secret_Len (S : Session) return N32 is
     (S.Exporter_Secret_Len);

   function Exporter_Client_Random (S : Session) return Bytes_32 is
     (S.Exporter_Client_Random);

   function Exporter_Server_Random (S : Session) return Bytes_32 is
     (S.Exporter_Server_Random);

   function PSK_Offered (S : Session) return Boolean is
     (S.HC_Ptr /= null and then S.HC_Ptr.PSK_Offered);

   function Has_Handshake_Context (S : Session) return Boolean is
     (S.HC_Ptr /= null);

   function Client_Seq_12 (S : Session) return Unsigned_64 is
     (S.Client_Seq_12);

   function Server_Seq_12 (S : Session) return Unsigned_64 is
     (S.Server_Seq_12);

   function Client_App_Counter (S : Session) return Unsigned_64 is
     (S.Client_App.Counter);

   function Server_App_Counter (S : Session) return Unsigned_64 is
     (S.Server_App.Counter);

   function Key_Update_Pending (S : Session) return Boolean is
     (S.Key_Update_Pending);

   function Key_Updates_Recvd (S : Session) return Natural is
     (S.Key_Updates_Recvd);

   procedure Set_Client_App_Counter (S : in out Session; V : Unsigned_64) is
   begin
      S.Client_App.Counter := V;
   end Set_Client_App_Counter;

   procedure Set_Server_App_Counter (S : in out Session; V : Unsigned_64) is
   begin
      S.Server_App.Counter := V;
   end Set_Server_App_Counter;

   function Extended_Master_Secret_Used (S : Session) return Boolean is
   begin
      --  TLS 1.3 binds the transcript inherently -- see the spec note.
      if S.Negotiated_Version = TLS_1_3 then
         return True;
      end if;
      return S.Use_EMS;
   end Extended_Master_Secret_Used;

end SPARKTLS.Test_Support;
