with SPARKTLS.Initialize;
with Ada.Text_IO;
with SPARKTLS.RBG;

--  Log lines go to standard error: programs like the BoGo shim speak a
--  protocol on standard output.
package body Entropy_Random is
   use type SPARKTLS.RBG.RBG_Status;

   --  The generator latched off: the entropy source failed persistently.
   procedure On_Failure is
   begin
      Ada.Text_IO.Put_Line
        (Ada.Text_IO.Standard_Error,
         "entropy: jitter source failed persistently (OSR"
         & SPARKTLS.RBG.Entropy_OSR'Image & ", intermittent recoveries"
         & SPARKTLS.RBG.Entropy_Resets'Image
         & "); generator latched off, handshakes will fail with Entropy_Failure");
   end On_Failure;

   procedure Init (Verbose : Boolean := False; Mode : SPARKTLS.FIPS_Mode := SPARKTLS.FIPS) is
      OK : Boolean;
   begin
      SPARKTLS.Initialize (OK, Mode => Mode, On_Failure => On_Failure'Access);
      if not OK then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "Entropy: SPARKTLS.RBG start-up failed (FIPS self-tests or integrity test, jitter source start-up test, or first seed)");
      elsif Verbose then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "Entropy: SPARKEntropy jitter source (OSR" & SPARKTLS.RBG.Entropy_OSR'Image
            & ") seeding SPARKTLS.RBG (core HMAC_DRBG; serving HMAC_DRBG reseeded from it every"
            & Integer'Image (SPARKTLS.RBG.Default_Reseed_Requests) & " requests)");
      end if;
   end Init;

   procedure Random (Output : out SPARKNaCl.Byte_Seq) is
   begin
      if SPARKTLS.RBG.Status /= SPARKTLS.RBG.Ready then
         Init;
      end if;
      SPARKTLS.RBG.Random (Output);
   end Random;

end Entropy_Random;
