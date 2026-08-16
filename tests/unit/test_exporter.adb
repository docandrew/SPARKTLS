with Ada.Command_Line;
with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with SPARKNaCl;
with SPARKTLS; use SPARKTLS;
with SPARKTLS.Key_Schedule;
with SPARKTLS.Key_Schedule_12;
with SPARKTLSCrypto.HKDF;
with SPARKTLS.Test_Support;

procedure Test_Exporter is
   use type SPARKNaCl.Byte_Seq;

   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then
         Pass := Pass + 1;
         Put_Line ("  PASS: " & Name);
      else
         Fail := Fail + 1;
         Put_Line ("  FAIL: " & Name);
      end if;
   end Check;

   function Seq (Offset : SPARKNaCl.Byte) return SPARKTLS.Bytes_48 is
      R : SPARKTLS.Bytes_48 := (others => 0);
   begin
      for I in R'Range loop
         R (I) :=
           SPARKNaCl.Byte
             ((Unsigned_16 (Offset) + Unsigned_16 (I)) mod 256);
      end loop;
      return R;
   end Seq;

   function Seq32 (Offset : SPARKNaCl.Byte) return SPARKNaCl.Bytes_32 is
      R48 : constant SPARKTLS.Bytes_48 := Seq (Offset);
      R32 : SPARKNaCl.Bytes_32 := (others => 0);
   begin
      for I in R32'Range loop
         R32 (I) := R48 (I);
      end loop;
      return R32;
   end Seq32;

   procedure Test_Unavailable is
      S : Session;
      Outp : SPARKNaCl.Byte_Seq (0 .. 31);
      OK : Boolean;
   begin
      Export_Keying_Material
        (S, "EXPORTER-test", (1 .. 0 => 0), False, Outp, OK);
      Check ("exporter unavailable before handshake", not OK);
      Check ("unavailable exporter zeros output", Outp = (0 .. 31 => 0));
   end Test_Unavailable;

   procedure Test_TLS12 is
      S : Session;
      Outp : SPARKNaCl.Byte_Seq (0 .. 31);
      Expected : SPARKNaCl.Byte_Seq (0 .. 31);
      Ctx : constant SPARKNaCl.Byte_Seq (0 .. 2) := (16#A0#, 16#A1#, 16#A2#);
      OK : Boolean;
   begin
      SPARKTLS.Test_Support.Set_State (S, Connected);
      SPARKTLS.Test_Support.Set_Negotiated_Version (S, TLS_1_2);
      SPARKTLS.Test_Support.Set_Negotiated_Suite_12 (S, Suite_ECDHE_RSA_AES128_GCM_SHA256);
      SPARKTLS.Test_Support.Set_Exporter_State
        (S, Seq (16#10#), 48, Seq32 (16#40#), Seq32 (16#80#));

      Export_Keying_Material
        (S, "EXPORTER-test", Ctx, True, Outp, OK);
      SPARKTLS.Key_Schedule_12.Export_Keying_Material_12
        (Expected, SPARKTLS.Test_Support.Exporter_Secret (S), SPARKTLS.Test_Support.Exporter_Client_Random (S),
         SPARKTLS.Test_Support.Exporter_Server_Random (S), "EXPORTER-test", Ctx, True, False);

      Check ("TLS 1.2 exporter succeeds", OK);
      Check ("TLS 1.2 exporter matches RFC5705 helper", Outp = Expected);

      declare
         No_Ctx : SPARKNaCl.Byte_Seq (0 .. 31);
      begin
         Export_Keying_Material
           (S, "EXPORTER-test", Ctx, False, No_Ctx, OK);
         Check ("TLS 1.2 exporter no-context succeeds", OK);
         Check ("TLS 1.2 context flag changes output", No_Ctx /= Outp);
      end;

      declare
         Wide     : SPARKNaCl.Byte_Seq (0 .. 1023);
         Expected_Wide : SPARKNaCl.Byte_Seq (0 .. 1023);
         Empty_Label   : SPARKNaCl.Byte_Seq (0 .. 31);
         Expected_Empty : SPARKNaCl.Byte_Seq (0 .. 31);
      begin
         Export_Keying_Material
           (S, "EXPORTER-test", Ctx, True, Wide, OK);
         SPARKTLS.Key_Schedule_12.Export_Keying_Material_12
           (Expected_Wide, SPARKTLS.Test_Support.Exporter_Secret (S), SPARKTLS.Test_Support.Exporter_Client_Random (S),
            SPARKTLS.Test_Support.Exporter_Server_Random (S), "EXPORTER-test", Ctx, True, False);
         Check ("TLS 1.2 1024-byte exporter succeeds", OK);
         Check ("TLS 1.2 1024-byte exporter matches RFC5705 helper",
                Wide = Expected_Wide);

         Export_Keying_Material
           (S, "", Ctx, False, Empty_Label, OK);
         SPARKTLS.Key_Schedule_12.Export_Keying_Material_12
           (Expected_Empty, SPARKTLS.Test_Support.Exporter_Secret (S), SPARKTLS.Test_Support.Exporter_Client_Random (S),
            SPARKTLS.Test_Support.Exporter_Server_Random (S), "", Ctx, False, False);
         Check ("TLS 1.2 empty-label exporter succeeds", OK);
         Check ("TLS 1.2 empty-label exporter matches RFC5705 helper",
                Empty_Label = Expected_Empty);
      end;
   end Test_TLS12;

   procedure Test_TLS13 is
      S : Session;
      Outp : SPARKNaCl.Byte_Seq (0 .. 31);
      Expected : SPARKTLSCrypto.HKDF.OKM_Seq (0 .. 31);
      Ctx : constant SPARKNaCl.Byte_Seq (0 .. 3) := (1, 2, 3, 4);
      OK : Boolean;
   begin
      SPARKTLS.Test_Support.Set_State (S, Connected);
      SPARKTLS.Test_Support.Set_Negotiated_Version (S, TLS_1_3);
      SPARKTLS.Test_Support.Set_Negotiated_Suite (S, Suite_AES_128_GCM_SHA256);
      declare
         Sec : Bytes_48 := (others => 0);
      begin
         Sec (0 .. 31) := Seq32 (16#22#);
         SPARKTLS.Test_Support.Set_Exporter_State
           (S, Sec, 32, (others => 0), (others => 0));
      end;

      Export_Keying_Material
        (S, "EXPORTER-test", Ctx, True, Outp, OK);
      SPARKTLS.Key_Schedule.Export_Keying_Material
        (Expected, SPARKTLS.Test_Support.Exporter_Secret (S) (0 .. 31), "EXPORTER-test", Ctx);

      Check ("TLS 1.3 exporter succeeds", OK);
      Check ("TLS 1.3 exporter matches RFC8446 helper",
             Outp = SPARKNaCl.Byte_Seq (Expected));
   end Test_TLS13;

   procedure Test_Sanitize is
      S : Session;
   begin
      SPARKTLS.Test_Support.Set_Exporter_State
        (S, Seq (16#33#), 48, Seq32 (16#44#), Seq32 (16#55#));
      Sanitize_Keys (S);
      Check ("Sanitize zeros exporter secret",
             SPARKTLS.Test_Support.Exporter_Secret (S) = (0 .. 47 => 0));
      Check ("Sanitize clears exporter length", SPARKTLS.Test_Support.Exporter_Secret_Len (S) = 0);
      Check ("Sanitize zeros exporter randoms",
             SPARKTLS.Test_Support.Exporter_Client_Random (S) = (0 .. 31 => 0)
             and then SPARKTLS.Test_Support.Exporter_Server_Random (S) = (0 .. 31 => 0));
   end Test_Sanitize;

begin
   Put_Line ("=== SPARKTLS Exporter Unit Tests ===");
   Test_Unavailable;
   Test_TLS12;
   Test_TLS13;
   Test_Sanitize;

   Put_Line ("");
   Put_Line ("Total checks:" & Total'Image
             & " passed" & Pass'Image
             & " failed" & Fail'Image);
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
   end if;
end Test_Exporter;
