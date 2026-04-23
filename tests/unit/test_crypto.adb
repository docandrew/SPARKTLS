--  Unit tests for SPARKTLS cryptographic primitives.
--  Tests sign/verify round-trips for all supported ECDSA algorithms.

with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;
with SPARKNaCl;            use SPARKNaCl;
with Interfaces;           use Interfaces;
with SPARKTLS.P384.ECDSA;
with SPARKTLS.X25519;
with SPARKNaCl.Scalar;
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
   Put_Line ("--- X25519 ---");
   --  Test field multiply: 9 * 9 = 81
   declare
      Nine : constant Bytes_32 := (9, others => 0);
      EightyOne : constant Bytes_32 := (81, others => 0);
      Result : Bytes_32;
   begin
      SPARKTLS.X25519.Test_FE_Mul (Nine, Nine, Result);
      Check ("FE_Mul(9, 9) = 81",
             Byte_Seq (Result) = Byte_Seq (EightyOne));
      if Byte_Seq (Result) /= Byte_Seq (EightyOne) then
         Put ("    Got(0..5): ");
         for I in N32 range 0 .. 5 loop Put (Result (I)'Image); end loop; New_Line;
      end if;
   end;

   --  Test encode/decode round-trip
   declare
      Test_In : constant Bytes_32 := (1, 2, 3, 4, 5, 6, 7, 8,
                                       9, 10, 11, 12, 13, 14, 15, 16,
                                       17, 18, 19, 20, 21, 22, 23, 24,
                                       25, 26, 27, 28, 29, 30, 31, 0);
      Test_Out : Bytes_32;
   begin
      SPARKTLS.X25519.Test_Encode_Decode (Test_In, Test_Out);
      Check ("X25519 encode/decode round-trip",
             Byte_Seq (Test_In) = Byte_Seq (Test_Out));
      if Byte_Seq (Test_In) /= Byte_Seq (Test_Out) then
         Put ("    In (0..7):  ");
         for I in N32 range 0 .. 7 loop Put (Test_In (I)'Image); end loop; New_Line;
         Put ("    Out(0..7):  ");
         for I in N32 range 0 .. 7 loop Put (Test_Out (I)'Image); end loop; New_Line;
      end if;
   end;

   declare
      --  Scalar = 1 (after clamping: 64, because bit 254 is set)
      --  Use RFC 7748 test vector instead:
      --  scalar: a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4
      --  u:      e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c
      --  output: c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552
      N_Key : constant Bytes_32 :=
        (16#a5#, 16#46#, 16#e3#, 16#6b#, 16#f0#, 16#52#, 16#7c#, 16#9d#,
         16#3b#, 16#16#, 16#15#, 16#4b#, 16#82#, 16#46#, 16#5e#, 16#dd#,
         16#62#, 16#14#, 16#4c#, 16#0a#, 16#c1#, 16#fc#, 16#5a#, 16#18#,
         16#50#, 16#6a#, 16#22#, 16#44#, 16#ba#, 16#44#, 16#9a#, 16#c4#);
      P_Key : constant Bytes_32 :=
        (16#e6#, 16#db#, 16#68#, 16#67#, 16#58#, 16#30#, 16#30#, 16#db#,
         16#35#, 16#94#, 16#c1#, 16#a4#, 16#24#, 16#b1#, 16#5f#, 16#7c#,
         16#72#, 16#66#, 16#24#, 16#ec#, 16#26#, 16#b3#, 16#35#, 16#3b#,
         16#10#, 16#a9#, 16#03#, 16#a6#, 16#d0#, 16#ab#, 16#1c#, 16#4c#);
      Expected : constant Bytes_32 :=
        (16#c3#, 16#da#, 16#55#, 16#37#, 16#9d#, 16#e9#, 16#c6#, 16#90#,
         16#8e#, 16#94#, 16#ea#, 16#4d#, 16#f2#, 16#8d#, 16#08#, 16#4f#,
         16#32#, 16#ec#, 16#cf#, 16#03#, 16#49#, 16#1c#, 16#71#, 16#f7#,
         16#54#, 16#b4#, 16#07#, 16#55#, 16#77#, 16#a2#, 16#85#, 16#52#);
      P_Key_Simple : constant Bytes_32 := (9, others => 0);
      Q_Ours : Bytes_32;
      Q_Ref  : Bytes_32;
   begin
      --  Test against RFC 7748 §6.1 vector
      SPARKTLS.X25519.Scalar_Mult (Q_Ours, N_Key, P_Key);
      Check ("X25519 vs RFC 7748 vector",
             Byte_Seq (Q_Ours) = Byte_Seq (Expected));
      if Byte_Seq (Q_Ours) /= Byte_Seq (Expected) then
         Put ("    Ours(0..5):     ");
         for I in N32 range 0 .. 5 loop Put (Q_Ours (I)'Image); end loop; New_Line;
         Put ("    Expected(0..5): ");
         for I in N32 range 0 .. 5 loop Put (Expected (I)'Image); end loop; New_Line;
      end if;

      --  Test against SPARKNaCl with simple basepoint
      SPARKTLS.X25519.Scalar_Mult (Q_Ours, N_Key, P_Key_Simple);
      Q_Ref := SPARKNaCl.Scalar.Mult (N_Key, P_Key_Simple);
      Check ("X25519 vs SPARKNaCl (basepoint)",
             Byte_Seq (Q_Ours) = Byte_Seq (Q_Ref));
      if Byte_Seq (Q_Ours) /= Byte_Seq (Q_Ref) then
         Put ("    Ours(0..5): ");
         for I in N32 range 0 .. 5 loop Put (Q_Ours (I)'Image); end loop; New_Line;
         Put ("    Ref (0..5): ");
         for I in N32 range 0 .. 5 loop Put (Q_Ref (I)'Image); end loop; New_Line;
      end if;
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
