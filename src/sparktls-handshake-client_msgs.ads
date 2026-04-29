with SPARKNaCl; use SPARKNaCl;

--  TLS 1.3 Client Handshake Messages
--
--  Build ClientHello and parse ServerHello.
package SPARKTLS.Handshake.Client_Msgs with
   SPARK_Mode => On
is
   --  Maximum ClientHello size
   Max_Client_Hello : constant := 816;

   --  Build a TLS 1.3 ClientHello handshake message.
   --  Returns the complete handshake message (type + length + body)
   --  ready to be wrapped in a TLS record.
   procedure Build_Client_Hello
     (S      : in     Session;
      HC     : in out Handshake_Context;
      Result :    out Byte_Seq;
      Len    :    out N32)
   with Pre  => Result'First = 0
                and N32 (Result'Length) >= Max_Client_Hello
                and HC.Cfg.Random /= null;

   --  Parse a ServerHello from raw handshake message bytes.
   --  Extracts: server random, cipher suite, key share (server public key).
   procedure Parse_Server_Hello
     (S    : in out Session;
      HC   : in out Handshake_Context;
      Data : in     Byte_Seq;
      OK   :    out Boolean)
   with Pre => Data'Length > 0;

end SPARKTLS.Handshake.Client_Msgs;
