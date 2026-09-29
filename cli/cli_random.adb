with Ada.Text_IO;
with SPARKNaCl;
with SPARKTLS;
with SPARKTLS.Initialize;
with SPARKTLS.RBG;

package body CLI_Random is
   use type SPARKTLS.RBG.RBG_Status;
   use type SPARKNaCl.N32;
   use type X509.N32;
   use type X509.Byte;

   procedure Start (OK : out Boolean) is
   begin
      if SPARKTLS.RBG.Status = SPARKTLS.RBG.Ready then
         OK := True;
         return;
      end if;
      SPARKTLS.Initialize (OK, Mode => SPARKTLS.FIPS);
      if not OK then
         Ada.Text_IO.Put_Line
           (Ada.Text_IO.Standard_Error,
            "Error: SPARKTLS module failed to start (self-tests, integrity test or "
            & "entropy source); was the binary processed by tools/fips_inject?");
      end if;
   end Start;

   procedure Get (Output : out X509.Byte_Seq; OK : out Boolean) is
      Buf : SPARKNaCl.Byte_Seq (0 .. SPARKNaCl.N32 (Output'Length) - SPARKNaCl.N32 (1)) :=
        (others => 0);
   begin
      Output := (others => 0);
      Start (OK);
      if not OK or else Output'Length = 0 then
         return;
      end if;
      SPARKTLS.RBG.Random (Buf);
      OK := (for some B of Buf => Integer (B) /= 0);   --  all zero: the generator failed
      if not OK then
         return;
      end if;
      for I in Buf'Range loop
         Output (Output'First + X509.N32 (I)) := X509.Byte (Buf (I));
      end loop;
   end Get;
end CLI_Random;
