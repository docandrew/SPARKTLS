--  Unit tests for SPARKTLS cryptographic primitives.
--  Tests sign/verify round-trips for all supported ECDSA algorithms.

with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;
with SPARKNaCl;            use SPARKNaCl;
with Interfaces;           use Interfaces;
with SPARKTLS.P384.ECDSA;
with SPARKTLS.BigNat;      use SPARKTLS.BigNat;

procedure Test_Crypto is
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

   --================================================================
   --  P-384 ECDSA Sign/Verify round-trip
   --================================================================
   procedure Test_P384_Round_Trip is
      use SPARKTLS.P384.ECDSA;
      Hash : constant Bytes_48 := (others => 16#BB#);
      D    : Byte_Seq (0 .. 47) := (0 => 0, others => 16#01#);
      K    : Byte_Seq (0 .. 47) := (0 => 0, 1 => 0, others => 16#42#);
      R_Out, S_Out : Byte_Seq (0 .. 47);
      Qx, Qy : Byte_Seq (0 .. 47);
      Sign_OK : Boolean;
   begin
      --  Compute public key
      Public_Key (D, Qx, Qy);

      --  Sign
      Sign (Hash, D, K, R_Out, S_Out, Sign_OK);
      Check ("P-384 Sign", Sign_OK);
      if not Sign_OK then return; end if;
      Put ("    s(0..5): ");
      for I in 0 .. 5 loop Put (S_Out (N32 (I))'Image); end loop;
      New_Line;

      --  Check r and s are in valid range
      declare
         R_BN, S_BN, N_BN : Big_Nat;
         N_Bytes : constant Byte_Seq (0 .. 47) :=
           (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
            16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
            16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
            16#C7#, 16#63#, 16#4D#, 16#81#, 16#F4#, 16#37#, 16#2D#, 16#DF#,
            16#58#, 16#1A#, 16#0D#, 16#B2#, 16#48#, 16#B0#, 16#A7#, 16#7A#,
            16#EC#, 16#EC#, 16#19#, 16#6A#, 16#CC#, 16#C5#, 16#29#, 16#73#);
         Trial_R, Trial_S : Arith_Result;
      begin
         Decode (R_BN, Byte_Seq (R_Out));
         Decode (S_BN, Byte_Seq (S_Out));
         Decode (N_BN, N_Bytes);
         R_BN.Len := N_BN.Len;
         S_BN.Len := N_BN.Len;
         Trial_R := CT_Sub (R_BN, N_BN, 0);
         Trial_S := CT_Sub (S_BN, N_BN, 0);
         Check ("r < n (borrow=" & Trial_R.Carry'Image & ")",
                Trial_R.Carry = 1);
         Check ("s < n (borrow=" & Trial_S.Carry'Image & ")",
                Trial_S.Carry = 1);
      end;

      --  Verify
      declare
         V : constant Boolean := Verify (Hash, Qx, Qy, R_Out, S_Out);
      begin
         Check ("P-384 Verify (round-trip)", V);
         if not V then
            --  Debug: recompute r from k*G using Public_Key trick
            --  (Public_Key computes d*G; if we pass K as d, we get k*G)
            declare
               KGx, KGy : Byte_Seq (0 .. 47);
            begin
               Public_Key (K, KGx, KGy);
               Put_Line ("    Sign R(0..5):    " &
                  R_Out(0)'Image & R_Out(1)'Image & R_Out(2)'Image &
                  R_Out(3)'Image & R_Out(4)'Image & R_Out(5)'Image);
               Put_Line ("    k*G x(0..5):     " &
                  KGx(0)'Image & KGx(1)'Image & KGx(2)'Image &
                  KGx(3)'Image & KGx(4)'Image & KGx(5)'Image);
               Check ("  R matches k*G.x", R_Out = KGx);
            end;
         end if;
      end;
   end Test_P384_Round_Trip;

begin
   Put_Line ("=== SPARKTLS Crypto Unit Tests ===");
   Put_Line ("");

   Put_Line ("--- P-384 BigNat ---");
   --  Test: modular inverse round-trip
   --  k * k^(-1) mod n should = 1
   declare
      P384_N : constant Byte_Seq (0 .. 47) :=
        (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#C7#, 16#63#, 16#4D#, 16#81#, 16#F4#, 16#37#, 16#2D#, 16#DF#,
         16#58#, 16#1A#, 16#0D#, 16#B2#, 16#48#, 16#B0#, 16#A7#, 16#7A#,
         16#EC#, 16#EC#, 16#19#, 16#6A#, 16#CC#, 16#C5#, 16#29#, 16#73#);
      K_Bytes : constant Byte_Seq (0 .. 47) :=
        (0 => 0, 1 => 0, others => 16#42#);
      N_BN, K_BN, K_Inv, Product, T1, T2, One_BN : Big_Nat;
      M0I : Word;
   begin
      Decode (N_BN, P384_N);
      M0I := Ninv32 (N_BN.W (0));
      Decode (K_BN, K_Bytes);
      K_BN.Len := N_BN.Len;

      --  k^(-1) mod n
      Modpow (K_Inv, K_BN,
              (0 .. 47 => 0),  --  placeholder, need n-2
              N_BN, M0I);
      --  Actually we need n-2 as exponent. Let me just compute it:
      declare
         NM2 : Byte_Seq (0 .. 47) := P384_N;
      begin
         NM2 (47) := Byte (Unsigned_8 (NM2 (47)) - 2);
         Modpow (K_Inv, K_BN, NM2, N_BN, M0I);
      end;

      --  Now compute k * k_inv mod n using Montgomery
      T1 := K_BN;
      To_Monty (T1, N_BN, M0I);
      T2 := K_Inv;
      To_Monty (T2, N_BN, M0I);
      Monty_Mul (Product, T1, T2, N_BN, M0I);
      --  Convert from Montgomery
      Zero (One_BN, N_BN.Len);
      One_BN.W (0) := 1;
      Monty_Mul (T1, Product, One_BN, N_BN, M0I);

      --  T1 should be 1
      declare
         Is_One : Boolean := T1.W (0) = 1;
      begin
         for I in 1 .. N_BN.Len - 1 loop
            if T1.W (I) /= 0 then
               Is_One := False;
            end if;
         end loop;
         Check ("k * k^(-1) mod n = 1", Is_One);
         if not Is_One then
            Put_Line ("    T1.W(0) =" & T1.W(0)'Image);
            Put_Line ("    T1.W(1) =" & T1.W(1)'Image);
         end if;
      end;
   end;

   Put_Line ("");
   Put_Line ("--- P-384 ECDSA ---");
   Test_P384_Round_Trip;

   Put_Line ("");
   Put_Line ("=== Results:" & Pass'Image & "/" & Total'Image &
             " passed," & Fail'Image & " failed ===");

   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Crypto;
