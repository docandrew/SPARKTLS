--  X.509 microbenchmark: parse cost and chain-validation cost separately
--  (the x509_validate --repeat loop includes file I/O by design).
--  Usage: bench_x509 <leaf.der> <ca.pem> [iters]

with Ada.Text_IO;   use Ada.Text_IO;
with Ada.Command_Line;
with Ada.Real_Time; use Ada.Real_Time;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with SPARKNaCl;     use SPARKNaCl;
with Interfaces;
use type Interfaces.Unsigned_32;
with X509;
with SPARKTLS;      use SPARKTLS;
with SPARKTLS.Credentials;
with SPARKTLS.Cert_Verify;

procedure Bench_X509 is
   function Load (Path : String) return X509.Byte_Seq is
      package SIO renames Ada.Streams.Stream_IO;
      File : SIO.File_Type;
   begin
      SIO.Open (File, SIO.In_File, Path);
      declare
         Size : constant Natural := Natural (SIO.Size (File));
         Raw  : Ada.Streams.Stream_Element_Array (1 .. Ada.Streams.Stream_Element_Offset (Size));
         Last : Ada.Streams.Stream_Element_Offset;
         DER  : X509.Byte_Seq (0 .. X509.N32 (Size - 1));
      begin
         SIO.Read (File, Raw, Last);
         SIO.Close (File);
         for I in DER'Range loop
            DER (I) := X509.Byte (Raw (Ada.Streams.Stream_Element_Offset (I + 1)));
         end loop;
         return DER;
      end;
   end Load;

   procedure Report (What : String; Iters : Positive; Elapsed : Duration) is
      Us : constant Long_Float := Long_Float (Elapsed) * 1.0e6 / Long_Float (Iters);
   begin
      Put_Line (What & ":" & Integer'Image (Integer (Us)) & " us/op,"
                & Integer'Image (Integer (1.0e6 / Us)) & " ops/s");
   end Report;

   Iters : Positive := 5000;
begin
   if Ada.Command_Line.Argument_Count < 2 then
      Put_Line ("usage: bench_x509 <leaf.der> <ca.pem> [iters]");
      return;
   end if;
   if Ada.Command_Line.Argument_Count >= 3 then
      Iters := Positive'Value (Ada.Command_Line.Argument (3));
   end if;
   declare
      Leaf_DER : constant X509.Byte_Seq := Load (Ada.Command_Line.Argument (1));
      Leaf     : X509.Certificate;
      OK       : Boolean;
      Roots    : Trust_Store;
      Ints     : Cert_Pool;
      Now      : constant X509.Date_Time := (2026, 9, 10, 12, 0, 0);
      T0, T1   : Time;
      Res      : Cert_Verify.Validation_Result := Cert_Verify.Valid;
      use type Cert_Verify.Validation_Result;
   begin
      Credentials.Load_Trust_Store (Roots, Ada.Command_Line.Argument (2), OK);
      if not OK then Put_Line ("trust store load failed"); return; end if;
      X509.Parse (Leaf_DER, Leaf, OK);
      if not OK then Put_Line ("leaf parse failed"); return; end if;
      Put_Line ("leaf" & Integer'Image (Integer (Leaf_DER'Length)) & " bytes, sig algo "
                & X509.Sig_Algorithm (Leaf)'Image);

      T0 := Clock;
      for I in 1 .. Iters loop
         X509.Parse (Leaf_DER, Leaf, OK);
      end loop;
      T1 := Clock;
      Report ("X509.Parse (leaf)   ", Iters, To_Duration (T1 - T0));

      T0 := Clock;
      for I in 1 .. Iters loop
         Res := Cert_Verify.Validate_Chain
           (Leaf_DER => Leaf_DER, Leaf => Leaf, Ints => Ints, Int_Count => 0,
            Roots => Roots.Roots, Root_Count => Roots.Root_Count,
            Now => Now, Hostname => "localhost", Mode => Mode_RFC5280);
      end loop;
      T1 := Clock;
      Report ("Validate_Chain      ", Iters, To_Duration (T1 - T0));
      Put_Line ("result: " & Res'Image);
   end;
end Bench_X509;
