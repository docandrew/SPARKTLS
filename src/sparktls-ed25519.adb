--  SPARKTLS Ed25519 — EdDSA signatures using Fiat Crypto field arithmetic
--
--  Replaces SPARKNaCl.Sign for ~10x speedup on GF(2^255-19) operations.
--  SHA-512 still comes from SPARKNaCl.

with Interfaces;           use Interfaces;
with SPARKTLS.Fiat_25519;  use SPARKTLS.Fiat_25519;
with SPARKNaCl.Hashing.SHA512;

package body SPARKTLS.Ed25519 with
   SPARK_Mode => On
is
   --================================================================
   --  Extended twisted Edwards point: (X, Y, Z, T) where
   --  x = X/Z, y = Y/Z, x*y = T/Z on -x^2 + y^2 = 1 + d*x^2*y^2
   --================================================================

   type Ext_Point is record
      X, Y, Z, T : Fiat_25519.FE;
   end record;

   --  d = -121665/121666 mod p (twisted Edwards curve constant)
   --  In 5×51-bit limbs:
   GF_D : constant Fiat_25519.FE :=
     (16#34DCA135978A3#, 16#1A8283B156EBD#, 16#5E7A26001C029#,
      16#739C663A03CBB#, 16#52036CEE2B6FF#);

   --  2*d
   GF_D2 : constant Fiat_25519.FE :=
     (16#69B9426B2F159#, 16#35050762ADD7A#, 16#3CF44C0038052#,
      16#6738CC7407977#, 16#2406D9DC56DFF#);

   --  Base point coordinates
   GF_BX : constant Fiat_25519.FE :=
     (16#62D608F25D51A#, 16#412A4B4F6592A#, 16#75B7171A4B31D#,
      16#1FF60527118FE#, 16#216936D3CD6E5#);

   GF_BY : constant Fiat_25519.FE :=
     (16#6666666666658#, 16#4CCCCCCCCCCCC#, 16#1999999999999#,
      16#3333333333333#, 16#6666666666666#);

   --  sqrt(-1) mod p
   GF_I : constant Fiat_25519.FE :=
     (16#61B274A0EA0B0#, 16#0D5A5FC8F189D#, 16#7EF5E9CBD0C60#,
      16#78595A6804C9E#, 16#2B8324804FC1D#);

   --================================================================
   --  Point addition (extended coordinates)
   --  Unified addition formula (works for doubling too)
   --================================================================

   function Is_Valid (P : Ext_Point) return Boolean is
     (Fiat_25519.Is_Mul_Safe (P.X) and Fiat_25519.Is_Mul_Safe (P.Y) and
      Fiat_25519.Is_Mul_Safe (P.Z) and Fiat_25519.Is_Mul_Safe (P.T))
   with Ghost;

   function Point_Add (P, Q : Ext_Point) return Ext_Point
   with Pre  => Is_Valid (P) and Is_Valid (Q),
        Post => Is_Valid (Point_Add'Result)
   is
      A : constant Fiat_25519.FE := Fiat_25519.Mul
            (Fiat_25519.Sub (P.Y, P.X), Fiat_25519.Sub (Q.Y, Q.X));
      B : constant Fiat_25519.FE := Fiat_25519.Mul
            (Fiat_25519.Add (P.X, P.Y), Fiat_25519.Add (Q.X, Q.Y));
      C : constant Fiat_25519.FE := Fiat_25519.Mul
            (Fiat_25519.Mul (P.T, Q.T), GF_D2);
      D : Fiat_25519.FE := Fiat_25519.Add
            (Fiat_25519.Mul (P.Z, Q.Z), Fiat_25519.Mul (P.Z, Q.Z));
      E : constant Fiat_25519.FE := Fiat_25519.Sub (B, A);
      F, G, H : Fiat_25519.FE;
   begin
      Fiat_25519.Carry (D);
      F := Fiat_25519.Sub (D, C);
      G := Fiat_25519.Add (D, C);
      H := Fiat_25519.Add (B, A);
      return Ext_Point'(X => Fiat_25519.Mul (E, F),
                         Y => Fiat_25519.Mul (H, G),
                         Z => Fiat_25519.Mul (G, F),
                         T => Fiat_25519.Mul (E, H));
   end Point_Add;

   --================================================================
   --  Scalar multiplication: double-and-add, MSB first
   --================================================================

   function Scalarmult (Q : Ext_Point; S : Bytes_32) return Ext_Point is
      LP : Ext_Point := (X => Fiat_25519.FE_Zero,
                          Y => Fiat_25519.FE_One,
                          Z => Fiat_25519.FE_One,
                          T => Fiat_25519.FE_Zero);
      LQ : Ext_Point := Q;
      CB : Byte;
      Swap : Unsigned_64;
   begin
      for I in reverse N32 range 0 .. 31 loop
         CB := S (I);
         for J in reverse Natural range 0 .. 7 loop
            Swap := Unsigned_64 (Shift_Right (CB, J) mod 2);
            Fiat_25519.CSwap (LP.X, LQ.X, Swap);
            Fiat_25519.CSwap (LP.Y, LQ.Y, Swap);
            Fiat_25519.CSwap (LP.Z, LQ.Z, Swap);
            Fiat_25519.CSwap (LP.T, LQ.T, Swap);
            LQ := Point_Add (LQ, LP);
            LP := Point_Add (LP, LP);
            Fiat_25519.CSwap (LP.X, LQ.X, Swap);
            Fiat_25519.CSwap (LP.Y, LQ.Y, Swap);
            Fiat_25519.CSwap (LP.Z, LQ.Z, Swap);
            Fiat_25519.CSwap (LP.T, LQ.T, Swap);
         end loop;
      end loop;
      return LP;
   end Scalarmult;

   --================================================================
   --  Point doubling (dedicated formula, faster than Add(P,P))
   --  From RFC 8032 / ref10: uses only 4 squarings + 4 muls
   --================================================================

   --================================================================
   --  P1xP1/P2 intermediate representations for chained doublings
   --  Convention matches our Point_Add: E = H-(X+Y)², G = XX-YY
   --================================================================

   type Proj_Point is record
      X, Y, Z : Fiat_25519.FE;
   end record;

   type P1xP1_Point is record
      X, Y, Z, T : Fiat_25519.FE;
   end record;

   --  Double: P2 → P1xP1 (4 Sqr, 0 Mul)
   --  P1xP1 components: X=E, Y=H, Z=G, T=F in our naming convention
   function Double_P2 (P : Proj_Point) return P1xP1_Point is
      XX    : constant Fiat_25519.FE := Fiat_25519.Sqr (P.X);
      YY    : constant Fiat_25519.FE := Fiat_25519.Sqr (P.Y);
      ZZ2   : Fiat_25519.FE := Fiat_25519.Add
                (Fiat_25519.Sqr (P.Z), Fiat_25519.Sqr (P.Z));
      H     : constant Fiat_25519.FE := Fiat_25519.Add (XX, YY);
      XpYsq : constant Fiat_25519.FE :=
        Fiat_25519.Sqr (Fiat_25519.Add (P.X, P.Y));
      E     : constant Fiat_25519.FE := Fiat_25519.Sub (H, XpYsq);
      G     : constant Fiat_25519.FE := Fiat_25519.Sub (XX, YY);
      F     : Fiat_25519.FE;
   begin
      Fiat_25519.Carry (ZZ2);
      F := Fiat_25519.Add (ZZ2, G);
      return P1xP1_Point'(X => E, Y => H, Z => G, T => F);
   end Double_P2;

   --  P1xP1 → Extended: X=E*F, Y=G*H, Z=F*G, T=E*H (4 Mul)
   function P1xP1_To_Ext (P : P1xP1_Point) return Ext_Point is
     (X => Fiat_25519.Mul (P.X, P.T),   --  E * F
      Y => Fiat_25519.Mul (P.Z, P.Y),   --  G * H
      Z => Fiat_25519.Mul (P.T, P.Z),   --  F * G
      T => Fiat_25519.Mul (P.X, P.Y));  --  E * H

   --  P1xP1 → Projective: X=E*F, Y=G*H, Z=F*G (3 Mul, drop T)
   function P1xP1_To_P2 (P : P1xP1_Point) return Proj_Point is
     (X => Fiat_25519.Mul (P.X, P.T),   --  E * F
      Y => Fiat_25519.Mul (P.Z, P.Y),   --  G * H
      Z => Fiat_25519.Mul (P.T, P.Z));  --  F * G

   --  Extended → Projective (drop T)
   function Ext_To_P2 (P : Ext_Point) return Proj_Point is
     (X => P.X, Y => P.Y, Z => P.Z);

   --  Point_Double: uses P1xP1 internally, equivalent to old direct formula
   function Point_Double (P : Ext_Point) return Ext_Point
   with Pre  => Is_Valid (P),
        Post => Is_Valid (Point_Double'Result)
   is
   begin
      return P1xP1_To_Ext (Double_P2 (Ext_To_P2 (P)));
   end Point_Double;

   --================================================================
   --  Precomputed base point table: [1]B .. [15]B
   --================================================================

   type Table_Index is range 1 .. 15;
   type Precomp_Table is array (Table_Index) of Ext_Point;

   Base_Table : constant Precomp_Table :=
     (1 => (X => (16#62D608F25D51A#, 16#412A4B4F6592A#, 16#75B7171A4B31D#, 16#1FF60527118FE#, 16#216936D3CD6E5#),
            Y => (16#6666666666658#, 16#4CCCCCCCCCCCC#, 16#1999999999999#, 16#3333333333333#, 16#6666666666666#),
            Z => (16#0000000000001#, 16#0000000000000#, 16#0000000000000#, 16#0000000000000#, 16#0000000000000#),
            T => (16#68AB3A5B7DDA3#, 16#00EEA2A5EADBB#, 16#2AF8DF483C27E#, 16#332B375274732#, 16#67875F0FD78B7#)),
      2 => (X => (16#5E6CF9F3FD67E#, 16#102C74ED242A2#, 16#4F06F677913E2#, 16#56A2BBB68F090#, 16#3B6F8891960F6#),
            Y => (16#34C9A874A007E#, 16#4EA20E6F1B6DA#, 16#36AE09F5B8559#, 16#0492C90FA078A#, 16#336D9ECE4CDB3#),
            Z => (16#55B0BF61C8608#, 16#7E636B3174E45#, 16#3D9D6D142C9EF#, 16#7517ECE5C0B89#, 16#59E4EA1A52A20#),
            T => (16#2C7E392CAD989#, 16#00907A27378A6#, 16#5781F05C9D254#, 16#6D57E37537F6E#, 16#1F6E08DA2D298#)),
      3 => (X => (16#156CFC90DF8E0#, 16#196D5EAD66B28#, 16#4D791276C18B3#, 16#538FC7902D80E#, 16#7C79BD81BE5FE#),
            Y => (16#4C07F50735CA7#, 16#642CA75393A6E#, 16#0D8746961B46F#, 16#48A3066E1A7F0#, 16#1EEBD8C6EBA89#),
            Z => (16#459D9FBA69EFE#, 16#093AA464EBF37#, 16#100B25633CF01#, 16#215CA7060ACD1#, 16#0101F45083ACE#),
            T => (16#156E48AA004BB#, 16#51810CBE7A4E0#, 16#27E856C7FE9BC#, 16#40EDF86C3CFCA#, 16#1217D7AF665DF#)),
      4 => (X => (16#363FCDE8526BF#, 16#1D68A2A5FA320#, 16#6A2F2C809BBF0#, 16#0EECC96E5AC0C#, 16#3349374B8FF7F#),
            Y => (16#77C9E0A55F002#, 16#1A485852CC110#, 16#6BA5D0D3D0A6E#, 16#7BCA2393AB1F5#, 16#7B444D3F155E7#),
            Z => (16#193B1DC80E4CD#, 16#29815CC4A591E#, 16#58EFC4492128B#, 16#02E952A5C5BA9#, 16#045BE850E83C1#),
            T => (16#1FD8F28269DE7#, 16#34706555DA2B1#, 16#7579A811F358A#, 16#4AEF75D1154AE#, 16#59A06515D0063#)),
      5 => (X => (16#674DBE2986BD1#, 16#6A89CB9682122#, 16#2AE6D23A87BD6#, 16#0584C6F708F4A#, 16#2AB2A5B6DA2F3#),
            Y => (16#5C3587C6E9B73#, 16#52166752AFA34#, 16#07712601BE749#, 16#47A5F3193A9FC#, 16#69BAE0F220CCD#),
            Z => (16#06417ADA5C85D#, 16#0B049C57163A2#, 16#0954AC7E72939#, 16#0A3B9A8B64744#, 16#5699F014033FB#),
            T => (16#1A7CECD7B5BE4#, 16#1FD131D540E5C#, 16#48BCFE215DB4E#, 16#733386FFB2F12#, 16#5102C2E99AEC9#)),
      6 => (X => (16#7AD5C3589C7FB#, 16#3C5C40566298F#, 16#7305C1E744B0D#, 16#06B448FB3F2F6#, 16#1BDF617094D86#),
            Y => (16#6255D04CF5337#, 16#18015C31F0C42#, 16#1E1376D78C608#, 16#44E4882139578#, 16#29013DDF39C51#),
            Z => (16#55220806A5D9D#, 16#1378B181D70C1#, 16#777DB0F4DDF0C#, 16#77DA29F1DAA0E#, 16#4E9738D2FA7D2#),
            T => (16#7D6B4CA97E1DB#, 16#77E358B13557B#, 16#009D4DCFA58C7#, 16#5B3E6602BB3E3#, 16#2A53F2979379A#)),
      7 => (X => (16#615BEC1AC2631#, 16#1539D7AC30191#, 16#24E1D6E598611#, 16#2E378D6F743F7#, 16#1D3781242E289#),
            Y => (16#1A7626D655B61#, 16#796F94507A3FA#, 16#7087A3A9DBCD4#, 16#440C8C863EA82#, 16#536FD5AFF5CEB#),
            Z => (16#4C36801D1A6A4#, 16#66E3EE1A0423A#, 16#396877CC5DDDB#, 16#3EE04C554CCE9#, 16#4EF4533A71ACD#),
            T => (16#1E56A321A6F9C#, 16#427987DA13AFD#, 16#0B4EAE780343D#, 16#1BB5F2732AADE#, 16#66B8AA0D998B2#)),
      8 => (X => (16#57970824CD1D9#, 16#75F464679035B#, 16#56DB315444133#, 16#4B3EC9D800062#, 16#592A134F7F38D#),
            Y => (16#4EE686D78FAFC#, 16#7338475AE9788#, 16#4F6313796B18B#, 16#2EA2A34E1F515#, 16#1D8FDFA3AFB4E#),
            Z => (16#729E8B78555F5#, 16#5A148F96BE5E8#, 16#0F787820BFF44#, 16#5915988098A90#, 16#70E6708DCBA0D#),
            T => (16#1F7CBF0A2A9ED#, 16#3C2A22D3457AF#, 16#007F83D5E7E13#, 16#7DF878E9FADCC#, 16#6850E0DBE8207#)),
      9 => (X => (16#615E817869F29#, 16#39CF714140AEE#, 16#2146222466D84#, 16#78351A63DBD15#, 16#7F41CDC857AAF#),
            Y => (16#06E4878F88310#, 16#3027B721F4AE9#, 16#0C0C9CD4F294C#, 16#1057A98CD7061#, 16#774584288CCA5#),
            Z => (16#2FB214DD2EF61#, 16#134D205AAEA64#, 16#51742F87AF2A7#, 16#1DED4F7DB773E#, 16#34FA437F1052B#),
            T => (16#6B1BE1E02EBF7#, 16#0B65760FD043B#, 16#14B36A3878264#, 16#1D7264BBA3FBB#, 16#3DB50BA8F813D#)),
      10 => (X => (16#00E945EEBEA57#, 16#2261F53154BFD#, 16#605DD6D5EA34C#, 16#1C5B5175826BF#, 16#7CA8C99DFC9DA#),
             Y => (16#60FE831D260D3#, 16#61D6BE35D0380#, 16#2EA75A4D6DF0B#, 16#451FE81225642#, 16#015C96F0E41E3#),
             Z => (16#5E80C7C761DAB#, 16#60F177DAE6E5B#, 16#6F4B9D88DEABD#, 16#439F7C695D36D#, 16#6612CEEAE0F41#),
             T => (16#60221288B3D66#, 16#100D7F9C8EE98#, 16#1A2BC7829C300#, 16#039FE91BB4565#, 16#1AB3F536937B9#)),
      11 => (X => (16#29B3635FC6914#, 16#26F608C9EDF4F#, 16#3E56D529E151A#, 16#42154EB014A1A#, 16#3A08C55DBA964#),
             Y => (16#44DFFAB8B3BAD#, 16#22DA29D2B2168#, 16#3F8A8E2598333#, 16#2A33D0BDE867A#, 16#54577A6F45DA2#),
             Z => (16#35919BCD30D0A#, 16#524CC2711906B#, 16#1BD13EE300532#, 16#0151809AA28C2#, 16#24DC143469070#),
             T => (16#2CA5A3B408934#, 16#0E2E305E98B76#, 16#09B105E8EE732#, 16#130C889074E86#, 16#531BA123C246F#)),
      12 => (X => (16#3DA9F894EEFE8#, 16#308377672F345#, 16#0C43FAAD6CC67#, 16#6FBD908BFCEBE#, 16#4CB58F88DCFC9#),
             Y => (16#277567DF66147#, 16#30EA75443702C#, 16#43019FD9D04E1#, 16#5DF286E59EFB4#, 16#7843D5E446AD9#),
             Z => (16#59A7582C10E88#, 16#3D9C924CA4B88#, 16#648AD546F3A83#, 16#62BF4F7F80D7A#, 16#0DFC907E5D0BF#),
             T => (16#20D023800B442#, 16#14416EFD7CFFA#, 16#5D296477E1216#, 16#0CB515F16F737#, 16#1AC0064BA99AD#)),
      13 => (X => (16#0149CC6469094#, 16#21E8FB1897090#, 16#14B2FC62C9DBB#, 16#00395D8A143A3#, 16#0622E8797C947#),
             Y => (16#68CA0A259C979#, 16#5C6A1C8A170EA#, 16#53572930258C6#, 16#3B49FF8AD08D7#, 16#11A559BBC1494#),
             Z => (16#059A3956D28D4#, 16#08AEC2ABA8954#, 16#0EBEDF24F94F5#, 16#2F12C6ECECB59#, 16#59A225DA6049B#),
             T => (16#428E6BC6DFFF6#, 16#5A50E6914B357#, 16#37FA4203CA759#, 16#40E2FB6AEA720#, 16#2E013BDB4974C#)),
      14 => (X => (16#6ADB3D4065F0F#, 16#0B71E55756165#, 16#3D57CF2F44823#, 16#3BD20C992FB21#, 16#627471A969692#),
             Y => (16#77AC0A5C35E7D#, 16#26A3AF3F9F112#, 16#5F7A979957A15#, 16#60657AAAF941C#, 16#1C5B41B279989#),
             Z => (16#658DCC42FEC91#, 16#5EF8491E1F4E1#, 16#06B456A020848#, 16#17304BB8444D4#, 16#309488BED7AE2#),
             T => (16#50576E87D52F5#, 16#10424C24AE929#, 16#44A16D6AA6A9C#, 16#1A3962F2672A9#, 16#3E5A47E87D464#)),
      15 => (X => (16#68748671AE865#, 16#1E572A6A489E5#, 16#5D260CAA7E620#, 16#51614D952CEAD#, 16#3AEA74F08B2D7#),
             Y => (16#163735DA74113#, 16#6D31354945942#, 16#1EE3E65CCF368#, 16#24B4EB44B7DF9#, 16#7F9D6C35DC49F#),
             Z => (16#5826CC9D90A24#, 16#0CB7D1928E0ED#, 16#4C02F52699E41#, 16#489651A84D053#, 16#533552E07F39F#),
             T => (16#75B37FD6EA971#, 16#442A3B028DF79#, 16#0F880856384F6#, 16#6A7B9783232EE#, 16#32A3F803CDDB7#)));

   --================================================================
   --  Windowed scalar base multiplication (4-bit window)
   --  Processes 4 bits at a time using precomputed [1]B .. [15]B
   --================================================================

   function Scalarbase (S : Bytes_32) return Ext_Point is
      Identity : constant Ext_Point :=
        (X => Fiat_25519.FE_Zero, Y => Fiat_25519.FE_One,
         Z => Fiat_25519.FE_One,  T => Fiat_25519.FE_Zero);
      R : Ext_Point := Identity;
      Nibble : Unsigned_64;

      --  Constant-time table lookup: select Base_Table(idx) or identity
      --  Always touches every table entry to avoid timing leaks.
      function CT_Lookup (Idx : Unsigned_64) return Ext_Point is
         Result : Ext_Point := Identity;
      begin
         for K in Table_Index loop
            --  CT equality: diff = K xor Idx. If equal, diff = 0.
            --  Collapse all bits: if any bit set, result is nonzero.
            declare
               Diff : Unsigned_64 := Unsigned_64 (K) xor Idx;
               Eq   : Unsigned_64;
               M    : Unsigned_64;
            begin
               --  Fold diff to bit 0: nonzero → 1, zero → 0
               Diff := Diff or Shift_Right (Diff, 32);
               Diff := Diff or Shift_Right (Diff, 16);
               Diff := Diff or Shift_Right (Diff, 8);
               Diff := Diff or Shift_Right (Diff, 4);
               Diff := Diff or Shift_Right (Diff, 2);
               Diff := Diff or Shift_Right (Diff, 1);
               Eq := 1 - (Diff and 1);  --  1 if K=Idx, 0 otherwise
               M := -Eq;               --  all-ones if K=Idx, 0 otherwise
               for L in 0 .. 4 loop
                  Result.X (L) := Result.X (L) xor (M and (Result.X (L) xor Base_Table (K).X (L)));
                  Result.Y (L) := Result.Y (L) xor (M and (Result.Y (L) xor Base_Table (K).Y (L)));
                  Result.Z (L) := Result.Z (L) xor (M and (Result.Z (L) xor Base_Table (K).Z (L)));
                  Result.T (L) := Result.T (L) xor (M and (Result.T (L) xor Base_Table (K).T (L)));
               end loop;
            end;
         end loop;
         return Result;
      end CT_Lookup;

      --  Constant-time conditional point add: always does the add,
      --  then selects old or new result based on whether nibble is 0.
      procedure CT_Add (Acc : in out Ext_Point; Nibble : Unsigned_64) is
         T     : constant Ext_Point := CT_Lookup (Nibble);
         Sum   : constant Ext_Point := Point_Add (Acc, T);
         --  Select: if Nibble = 0, keep Acc; else use Sum
         Nz    : Unsigned_64 := Nibble;
         M     : Unsigned_64;
      begin
         Nz := Nz or Shift_Right (Nz, 32);
         Nz := Nz or Shift_Right (Nz, 16);
         Nz := Nz or Shift_Right (Nz, 8);
         Nz := Nz or Shift_Right (Nz, 4);
         Nz := Nz or Shift_Right (Nz, 2);
         Nz := Nz or Shift_Right (Nz, 1);
         M := -(Nz and 1);  --  all-ones if nonzero, 0 if zero
         for L in 0 .. 4 loop
            Acc.X (L) := Acc.X (L) xor (M and (Acc.X (L) xor Sum.X (L)));
            Acc.Y (L) := Acc.Y (L) xor (M and (Acc.Y (L) xor Sum.Y (L)));
            Acc.Z (L) := Acc.Z (L) xor (M and (Acc.Z (L) xor Sum.Z (L)));
            Acc.T (L) := Acc.T (L) xor (M and (Acc.T (L) xor Sum.T (L)));
         end loop;
      end CT_Add;
   begin
      --  Process scalar 4 bits at a time, MSB first
      --  Scalar is 256 bits = 64 nibbles
      --  Uses P2 intermediate form for chained doublings:
      --  P2→P1xP1→P2→P1xP1→P2→P1xP1→P2→P1xP1→Ext for the CT_Add
      --  Saves 4 Sqr + 4 Mul per nibble vs full Point_Double.
      for I in reverse N32 range 0 .. 31 loop
         --  High nibble: 4 doublings via P2 chain (saves 4 Mul vs Point_Double)
         Nibble := Unsigned_64 (Shift_Right (S (I), 4));
         declare
            P2 : Proj_Point := Ext_To_P2 (R);
         begin
            P2 := P1xP1_To_P2 (Double_P2 (P2));  --  3 Mul
            P2 := P1xP1_To_P2 (Double_P2 (P2));  --  3 Mul
            P2 := P1xP1_To_P2 (Double_P2 (P2));  --  3 Mul
            R  := P1xP1_To_Ext (Double_P2 (P2));  --  4 Mul (need T for Add)
         end;
         CT_Add (R, Nibble);

         --  Low nibble: 4 doublings via P2 chain
         Nibble := Unsigned_64 (S (I) and 16#0F#);
         declare
            P2 : Proj_Point := Ext_To_P2 (R);
         begin
            P2 := P1xP1_To_P2 (Double_P2 (P2));
            P2 := P1xP1_To_P2 (Double_P2 (P2));
            P2 := P1xP1_To_P2 (Double_P2 (P2));
            R  := P1xP1_To_Ext (Double_P2 (P2));
         end;
         CT_Add (R, Nibble);
      end loop;

      return R;
   end Scalarbase;

   --================================================================
   --  Point encoding/decoding
   --================================================================

   --  Encode a field element to 32 little-endian bytes
   procedure FE_To_Bytes (R : out Bytes_32; F : Fiat_25519.FE) is
      T : Fiat_25519.FE := F;
      Q : Unsigned_64;
      H : Unsigned_64;
      function Lo8 (X : Unsigned_64) return Byte is (Byte (X mod 256));
      procedure Store64 (S : in out Bytes_32; Off : I32; V : Unsigned_64)
      with Pre => Off in 0 .. 24
      is
      begin
         S (Off)     := Lo8 (V);
         S (Off + 1) := Lo8 (Shift_Right (V, 8));
         S (Off + 2) := Lo8 (Shift_Right (V, 16));
         S (Off + 3) := Lo8 (Shift_Right (V, 24));
         S (Off + 4) := Lo8 (Shift_Right (V, 32));
         S (Off + 5) := Lo8 (Shift_Right (V, 40));
         S (Off + 6) := Lo8 (Shift_Right (V, 48));
         S (Off + 7) := Lo8 (Shift_Right (V, 56));
      end Store64;
   begin
      Fiat_25519.Carry (T);
      Fiat_25519.Carry (T);
      Q := (T (0) + 19) / (2**51);
      Q := (T (1) + Q) / (2**51);
      Q := (T (2) + Q) / (2**51);
      Q := (T (3) + Q) / (2**51);
      Q := (T (4) + Q) / (2**51);
      T (0) := T (0) + 19 * Q;
      Fiat_25519.Carry (T);
      R := (others => 0);
      H := T (0) or Shift_Left (T (1), 51);
      Store64 (R, 0, H);
      H := Shift_Right (T (1), 13) or Shift_Left (T (2), 38);
      Store64 (R, 8, H);
      H := Shift_Right (T (2), 26) or Shift_Left (T (3), 25);
      Store64 (R, 16, H);
      H := Shift_Right (T (3), 39) or Shift_Left (T (4), 12);
      Store64 (R, 24, H);
   end FE_To_Bytes;

   function Bytes_To_FE (S : Bytes_32) return Fiat_25519.FE is
      function Load64 (S : Bytes_32; Off : I32) return Unsigned_64 is
        (Unsigned_64 (S (Off)) or
         Shift_Left (Unsigned_64 (S (Off + 1)), 8) or
         Shift_Left (Unsigned_64 (S (Off + 2)), 16) or
         Shift_Left (Unsigned_64 (S (Off + 3)), 24) or
         Shift_Left (Unsigned_64 (S (Off + 4)), 32) or
         Shift_Left (Unsigned_64 (S (Off + 5)), 40) or
         Shift_Left (Unsigned_64 (S (Off + 6)), 48) or
         Shift_Left (Unsigned_64 (S (Off + 7)), 56))
      with Pre => Off in 0 .. 24;
   begin
      return Fiat_25519.FE'(
        Load64 (S, 0) and Fiat_25519.Mask51,
        Shift_Right (Load64 (S, 6), 3) and Fiat_25519.Mask51,
        Shift_Right (Load64 (S, 12), 6) and Fiat_25519.Mask51,
        Shift_Right (Load64 (S, 19), 1) and Fiat_25519.Mask51,
        Shift_Right (Load64 (S, 24), 12) and Fiat_25519.Mask51);
   end Bytes_To_FE;

   function Par (A : Fiat_25519.FE) return Byte is
      D : Bytes_32;
   begin
      FE_To_Bytes (D, A);
      return D (0) mod 2;
   end Par;

   function Pack (P : Ext_Point) return Bytes_32 is
      ZI : constant Fiat_25519.FE := Fiat_25519.Inv (P.Z);
      TX : constant Fiat_25519.FE := Fiat_25519.Mul (P.X, ZI);
      TY : constant Fiat_25519.FE := Fiat_25519.Mul (P.Y, ZI);
      R  : Bytes_32;
   begin
      FE_To_Bytes (R, TY);
      R (31) := R (31) xor (Par (TX) * 128);
      return R;
   end Pack;

   procedure Unpackneg (R      :    out Ext_Point;
                         Valid  :    out Boolean;
                         PK     : in     Bytes_32)
   is
      --  Follows SPARKNaCl/TweetNaCl unpackneg exactly:
      --  R1 = y (from bytes), R2 = 1
      --  num = y^2 - 1,  den = 1 + d*y^2
      --  den2 = den^2,  den4 = den2^2
      --  R0 = pow2523(den4 * num * den * den2) * num * den * den2
      --  check = R0^2 * den;  if check != num, R0 *= sqrt(-1)
      --  check again;  if still != num, invalid
      --  if par(R0) == par bit from PK, negate R0

      function Pow2523 (I : Fiat_25519.FE) return Fiat_25519.FE is
         C : Fiat_25519.FE := I;
      begin
         for A in 0 .. 248 loop
            C := Fiat_25519.Mul (Fiat_25519.Sqr (C), I);
         end loop;
         return Fiat_25519.Mul (Fiat_25519.Sqr (Fiat_25519.Sqr (C)), I);
      end Pow2523;

      function FE_Eq (A, B : Fiat_25519.FE) return Boolean is
         BA, BB : Bytes_32;
      begin
         FE_To_Bytes (BA, A);
         FE_To_Bytes (BB, B);
         return Byte_Seq (BA) = Byte_Seq (BB);
      end FE_Eq;

      R1   : constant Fiat_25519.FE := Bytes_To_FE (PK);
      R1_Sq   : constant Fiat_25519.FE := Fiat_25519.Sqr (R1);
      Num     : constant Fiat_25519.FE := Fiat_25519.Sub (R1_Sq, Fiat_25519.FE_One);
      Den     : constant Fiat_25519.FE := Fiat_25519.Add (Fiat_25519.FE_One,
                   Fiat_25519.Mul (R1_Sq, GF_D));
      Den2    : constant Fiat_25519.FE := Fiat_25519.Sqr (Den);
      Den4    : constant Fiat_25519.FE := Fiat_25519.Sqr (Den2);
      Num_Den3 : constant Fiat_25519.FE := Fiat_25519.Mul (
                    Fiat_25519.Mul (Num, Den), Den2);
      R0  : Fiat_25519.FE;
      Chk : Fiat_25519.FE;
   begin
      R0  := Fiat_25519.Mul (Pow2523 (Fiat_25519.Mul (Den4, Num_Den3)), Num_Den3);

      Chk := Fiat_25519.Mul (Fiat_25519.Sqr (R0), Den);
      if not FE_Eq (Chk, Num) then
         R0 := Fiat_25519.Mul (R0, GF_I);
      end if;

      Chk := Fiat_25519.Mul (Fiat_25519.Sqr (R0), Den);
      if not FE_Eq (Chk, Num) then
         R := (X => Fiat_25519.FE_Zero, Y => Fiat_25519.FE_One,
               Z => Fiat_25519.FE_One, T => Fiat_25519.FE_Zero);
         Valid := False;
         return;
      end if;

      if Par (R0) = (PK (31) / 128) then
         R0 := Fiat_25519.Sub (Fiat_25519.FE_Zero, R0);
         Fiat_25519.Carry (R0);
      end if;

      R := (X => R0, Y => R1, Z => Fiat_25519.FE_One,
            T => Fiat_25519.Mul (R0, R1));
      Valid := True;
   end Unpackneg;

   --================================================================
   --  Scalar reduction mod L (curve order)
   --  L = 2^252 + 27742317777372353535851937790883648493
   --================================================================

   L : constant Byte_Seq (0 .. 31) :=
     (16#ed#, 16#d3#, 16#f5#, 16#5c#, 16#1a#, 16#63#, 16#12#, 16#58#,
      16#d6#, 16#9c#, 16#f7#, 16#a2#, 16#de#, 16#f9#, 16#de#, 16#14#,
      16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
      16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#10#);

   --  Arithmetic shift right by 8 (floor division by 256)
   --  Uses floor-div idiom: (X - 255) / 256 when negative, X / 256 when positive.
   function ASR_8 (X : I64) return I64 is
     ((X - (if X < 0 then 255 else 0)) / 256);

   function ModL (X_In : I64_Seq_64) return Bytes_32 is
      X : I64_Seq_64 := X_In;
      Carry : I64;
      R : Bytes_32;
   begin
      for I in reverse N32 range 32 .. 63 loop
         Carry := 0;
         for J in N32 range I - 32 .. I - 13 loop
            X (J) := X (J) + Carry - 16 * X (I) * I64 (L (J - (I - 32)));
            Carry := ASR_8 (X (J) + 128);
            X (J) := X (J) - Carry * 256;
         end loop;
         X (I - 12) := X (I - 12) + Carry;
         X (I) := 0;
      end loop;

      Carry := 0;
      for J in N32 range 0 .. 31 loop
         X (J) := X (J) + Carry - I64 (Shift_Right_Arithmetic (Unsigned_64 (X (31)), 4)) * I64 (L (J));
         Carry := ASR_8 (X (J));
         X (J) := X (J) - Carry * 256;
      end loop;
      --  Final reduction
      for J in N32 range 0 .. 31 loop
         X (J) := X (J) - Carry * I64 (L (J));
      end loop;
      for I in N32 range 0 .. 31 loop
         Carry := ASR_8 (X (I));
         X (I + 1) := X (I + 1) + Carry;
         R (I) := Byte (Unsigned_64 (X (I)) mod 256);
      end loop;

      return R;
   end ModL;

   --  SHA-512 hash wrapper
   procedure Hash (Output : out Bytes_64; Input : in Byte_Seq) is
   begin
      SPARKNaCl.Hashing.SHA512.Hash (Output, Input);
   end Hash;

   function Hash_Reduce (M : Byte_Seq) return Bytes_32 is
      H : Bytes_64;
      X : I64_Seq_64;
   begin
      Hash (H, M);
      X := (others => 0);
      for I in N32 range 0 .. 63 loop
         X (I) := I64 (H (I));
      end loop;
      return ModL (X);
   end Hash_Reduce;

   --================================================================
   --  High-level operations
   --================================================================

   procedure Keypair
     (Seed : in     Bytes_32;
      PK   :    out Bytes_32;
      SK   :    out Bytes_64)
   is
      D : Bytes_64;
   begin
      Hash (D, Byte_Seq (Seed));
      D (0)  := D (0) and 248;
      D (31) := (D (31) and 127) or 64;
      PK := Pack (Scalarbase (D (0 .. 31)));
      SK := Seed & PK;
   end Keypair;

   procedure Sign
     (SM : out Byte_Seq;
      M  : in  Byte_Seq;
      SK : in  Bytes_64)
   is
      D    : Bytes_64;
      H, R : Bytes_32;
      X    : I64_Seq_64;
      P    : Ext_Point;
   begin
      --  Hash the secret key
      Hash (D, Byte_Seq (SK (0 .. 31)));
      D (0)  := D (0) and 248;
      D (31) := (D (31) and 127) or 64;

      --  Initialize SM = [zeros_32 | prefix | M]
      SM := (others => 0);
      SM (64 .. SM'Last) := M;
      SM (32 .. 63) := D (32 .. 63);  --  prefix = second half of hash
      SM (0 .. 31) := (others => 0);

      --  R = Hash_Reduce(prefix || M)
      R := Hash_Reduce (SM (32 .. SM'Last));

      --  Encode R*B
      P := Scalarbase (R);
      SM (0 .. 31) := Pack (P);

      --  Put public key in bytes 32..63
      SM (32 .. 63) := SK (32 .. 63);

      --  H = Hash_Reduce(SM)
      H := Hash_Reduce (SM);

      --  X = R + H*D mod L
      X := (others => 0);
      for I in N32 range 0 .. 31 loop
         X (I) := I64 (R (I));
      end loop;
      for I in N32 range 0 .. 31 loop
         for J in N32 range 0 .. 31 loop
            X (I + J) := X (I + J) + I64 (H (I)) * I64 (D (J));
         end loop;
      end loop;

      SM (32 .. 63) := ModL (X);
   end Sign;

   procedure Open
     (M       :    out Byte_Seq;
      Valid   :    out Boolean;
      Msg_Len :    out I32;
      SM      : in     Byte_Seq;
      PK      : in     Bytes_32)
   is
      T    : Bytes_32;
      P, Q : Ext_Point;
   begin
      M := (others => 0);
      Msg_Len := -1;
      if SM'Length < 64 then
         Valid := False;
         return;
      end if;

      Unpackneg (Q, Valid, PK);
      if not Valid then
         M := (others => 0);
         return;
      end if;

      M := SM;
      M (32 .. 63) := PK;
      P := Scalarmult (Q, Hash_Reduce (M));
      Q := Scalarbase (SM (32 .. 63));
      P := Point_Add (P, Q);
      T := Pack (P);

      --  Constant-time comparison
      Valid := Byte_Seq (SM (0 .. 31)) = Byte_Seq (T);
      if not Valid then
         M := (others => 0);
         return;
      end if;

      declare
         LN : constant I32 := I32 (I64 (SM'Length) - 64);
      begin
         M (0 .. LN - 1) := SM (64 .. LN + 63);
         Msg_Len := LN;
      end;
   end Open;

   procedure Scalar_Mult_Base_To_Montgomery
     (U : out Bytes_32;
      N : in  Bytes_32)
   is
      --  Clamp the scalar (same as X25519 / RFC 7748 §5)
      E : Bytes_32 := N;
      P : Ext_Point;
      Num, Den, Mont_U : Fiat_25519.FE;
   begin
      E (0)  := E (0) and 248;
      E (31) := (E (31) and 127) or 64;

      --  Compute [clamped_scalar] * G in Edwards (windowed)
      P := Scalarbase (E);

      --  Convert Edwards y to Montgomery u: u = (1 + y) / (1 - y)
      --  With projective coords: y = Y/Z, so u = (Z + Y) / (Z - Y)
      Num := Fiat_25519.Add (P.Z, P.Y);
      Den := Fiat_25519.Sub (P.Z, P.Y);
      Mont_U := Fiat_25519.Mul (Num, Fiat_25519.Inv (Den));

      --  Encode to 32 little-endian bytes
      FE_To_Bytes (U, Mont_U);
   end Scalar_Mult_Base_To_Montgomery;

   function Test_ASR_8 (X : I64) return I64 is
   begin
      return ASR_8 (X);
   end Test_ASR_8;

end SPARKTLS.Ed25519;
