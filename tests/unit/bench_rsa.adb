--  RSA sign / verify microbenchmark (not a test; not run by run_all).
--  Usage: bench_rsa <cert.pem> <key.pem> [sign_iters] [verify_iters]

with Ada.Text_IO;   use Ada.Text_IO;
with Ada.Command_Line;
with Ada.Real_Time; use Ada.Real_Time;
with Interfaces;    use Interfaces;
with SPARKNaCl;     use SPARKNaCl;
with SPARKTLS;      use SPARKTLS;
with SPARKTLS.Credentials;
with SPARKTLSCrypto.RSA;

procedure Bench_RSA is
   Id     : SPARKTLS.Identity;
   OK     : Boolean;
   S_It   : Positive := 20;
   V_It   : Positive := 500;

   function Arg (I : Positive; Default : Positive) return Positive is
   begin
      if Ada.Command_Line.Argument_Count >= I then
         return Positive'Value (Ada.Command_Line.Argument (I));
      end if;
      return Default;
   end Arg;

   procedure Report (What : String; Iters : Positive; Elapsed : Duration) is
      Us : constant Long_Float := Long_Float (Elapsed) * 1.0e6 / Long_Float (Iters);
   begin
      Put_Line (What & ":" & Integer'Image (Integer (Us)) & " us/op,"
                & Integer'Image (Integer (1.0e6 / Us)) & " ops/s");
   end Report;
begin
   if Ada.Command_Line.Argument_Count < 2 then
      Put_Line ("usage: bench_rsa <cert.pem> <key.pem> [sign_iters] [verify_iters]");
      return;
   end if;
   S_It := Arg (3, 20);
   V_It := Arg (4, 500);
   SPARKTLS.Credentials.Load_Identity
     (Id, Ada.Command_Line.Argument (1), Ada.Command_Line.Argument (2), OK);
   if not OK or else Id.Sign_Algo /= Sign_RSA_PSS then
      Put_Line ("not an RSA identity");
      return;
   end if;
   Put_Line ("RSA" & Integer'Image (Integer (Id.RSA_Mod_Len) * 8) & "-bit key, e ="
             & Unsigned_32'Image (Id.RSA_Pub_Exp));

   declare
      Hash : constant Bytes_32 := (others => 16#5A#);
      Salt : constant Bytes_32 := (others => 16#A5#);
      Sig  : Byte_Seq (0 .. N32 (Id.RSA_Mod_Len) - 1) := (others => 0);
      Sig_Len : N32;
      Sign_OK : Boolean;
      T0, T1  : Time;
      Good    : Boolean := True;
   begin
      T0 := Clock;
      for I in 1 .. S_It loop
         SPARKTLSCrypto.RSA.Sign_PSS
           (M_Hash    => Byte_Seq (Hash),
            Hash_Len  => 32,
            Hash_Alg  => SPARKTLSCrypto.RSA.PSS_SHA256,
            Modulus   => Id.RSA_Modulus,
            Mod_Len   => Id.RSA_Mod_Len,
            Priv_Exp  => Id.RSA_Priv_Exp,
            Salt      => Byte_Seq (Salt),
            Signature => Sig,
            Sig_Len   => Sig_Len,
            OK        => Sign_OK);
         Good := Good and Sign_OK;
      end loop;
      T1 := Clock;
      Report ("Sign_PSS   ", S_It, To_Duration (T1 - T0));
      if not Good then Put_Line ("  (signing reported failure)"); end if;

      Put_Line ("CRT parameters loaded: " & Id.RSA_CRT.Valid'Image);
      declare
         Sig2 : Byte_Seq (0 .. N32 (Id.RSA_Mod_Len) - 1) := (others => 0);
         L2   : N32;
      begin
         T0 := Clock;
         for I in 1 .. S_It loop
            SPARKTLSCrypto.RSA.Sign_PSS
              (M_Hash    => Byte_Seq (Hash),
               Hash_Len  => 32,
               Hash_Alg  => SPARKTLSCrypto.RSA.PSS_SHA256,
               Modulus   => Id.RSA_Modulus,
               Mod_Len   => Id.RSA_Mod_Len,
               Priv_Exp  => Id.RSA_Priv_Exp,
               Salt      => Byte_Seq (Salt),
               Signature => Sig2,
               Sig_Len   => L2,
               OK        => Sign_OK,
               Pub_Exp   => Id.RSA_Pub_Exp,
               CRT       => Id.RSA_CRT);
            Good := Good and Sign_OK;
         end loop;
         T1 := Clock;
         Report ("Sign_PSS/CRT", S_It, To_Duration (T1 - T0));
         Put_Line ("CRT signature identical to plain: "
                   & Boolean'Image (L2 = Sig_Len and then Sig2 = Sig));
      end;

      T0 := Clock;
      for I in 1 .. V_It loop
         Good := Good and SPARKTLSCrypto.RSA.Verify_PSS_SHA256
           (Hash      => Hash,
            Modulus   => Id.RSA_Modulus,
            Mod_Len   => Id.RSA_Mod_Len,
            Exponent  => Id.RSA_Pub_Exp,
            Signature => Sig,
            Sig_Len   => Sig_Len);
      end loop;
      T1 := Clock;
      Report ("Verify_PSS ", V_It, To_Duration (T1 - T0));
      Put_Line ("signature verifies: " & Good'Image);
   end;
end Bench_RSA;
