--  SPARKTLS SHA-256 — SHA-NI hardware acceleration with software fallback
--
--  SHA-NI implementation based on Jeffrey Walton's public domain
--  sha256-x86.c (Intel SHA extensions using C intrinsics).

with Interfaces;              use Interfaces;
with System.Machine_Code;     use System.Machine_Code;
with SPARKNaCl.Hashing.SHA256;

package body SPARKTLS.Hashing.SHA256 with
   SPARK_Mode => Off  --  Machine_Code requires SPARK_Mode Off
is
   --================================================================
   --  CPUID detection (cached at elaboration)
   --================================================================

   function Detect_SHA_NI return Boolean is
      EAX, EBX, ECX, EDX : Unsigned_32;
   begin
      Asm ("cpuid",
           Outputs  => (Unsigned_32'Asm_Output ("=a", EAX),
                        Unsigned_32'Asm_Output ("=b", EBX),
                        Unsigned_32'Asm_Output ("=c", ECX),
                        Unsigned_32'Asm_Output ("=d", EDX)),
           Inputs   => Unsigned_32'Asm_Input ("a", 0),
           Volatile => True);
      if EAX < 7 then
         return False;
      end if;
      Asm ("cpuid",
           Outputs  => (Unsigned_32'Asm_Output ("=a", EAX),
                        Unsigned_32'Asm_Output ("=b", EBX),
                        Unsigned_32'Asm_Output ("=c", ECX),
                        Unsigned_32'Asm_Output ("=d", EDX)),
           Inputs   => (Unsigned_32'Asm_Input ("a", 7),
                        Unsigned_32'Asm_Input ("c", 0)),
           Volatile => True);
      return (EBX and 16#2000_0000#) /= 0;
   end Detect_SHA_NI;

   SHA_NI_Available : constant Boolean := Detect_SHA_NI;
   function Has_HW_Accel return Boolean is (SHA_NI_Available);

   --================================================================
   --  SHA-NI block processing
   --  Translates Jeffrey Walton's sha256-x86.c (public domain)
   --  State is uint32[8] in standard H0..H7 order.
   --================================================================

   --  State_Array defined in private part of spec

   --  Byte-swap mask for PSHUFB: big-endian → little-endian 32-bit words
   Bswap : constant array (0 .. 15) of Unsigned_8 :=
     (3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12)
   with Alignment => 16;

   --  Round constants K[0..63] packed as 16 x 128-bit (pairs of U64)
   --  Each 128-bit value holds K[4i], K[4i+1], K[4i+2], K[4i+3]
   --  in the order SHA256RNDS2 expects (low 64 bits used first)
   type K128 is array (0 .. 1) of Unsigned_64 with Alignment => 16;
   type K_Table is array (0 .. 15) of K128 with Alignment => 16;
   K : constant K_Table :=
     (0  => (16#71374491428A2F98#, 16#E9B5DBA5B5C0FBCF#),
      1  => (16#59F111F13956C25B#, 16#AB1C5ED5923F82A4#),
      2  => (16#12835B01D807AA98#, 16#550C7DC3243185BE#),
      3  => (16#80DEB1FE72BE5D74#, 16#C19BF1749BDC06A7#),
      4  => (16#EFBE4786E49B69C1#, 16#240CA1CC0FC19DC6#),
      5  => (16#4A7484AA2DE92C6F#, 16#76F988DA5CB0A9DC#),
      6  => (16#A831C66D983E5152#, 16#BF597FC7B00327C8#),
      7  => (16#D5A79147C6E00BF3#, 16#1429296706CA6351#),
      8  => (16#2E1B213827B70A85#, 16#53380D134D2C6DFC#),
      9  => (16#766A0ABB650A7354#, 16#92722C8581C2C92E#),
      10 => (16#A81A664BA2BFE8A1#, 16#C76C51A3C24B8B70#),
      11 => (16#D6990624D192E819#, 16#106AA070F40E3585#),
      12 => (16#1E376C0819A4C116#, 16#34B0BCB52748774C#),
      13 => (16#4ED8AA4A391C0CB3#, 16#682E6FF35B9CCA4F#),
      14 => (16#78A5636F748F82EE#, 16#8CC7020884C87814#),
      15 => (16#A4506CEB90BEFFFA#, 16#C67178F2BEF9A3F7#));

   procedure Process_Block (S : in out State_Array; Data : System.Address) is
   begin
      --  Faithful translation of sha256-x86.c using inline asm.
      --  Register usage:
      --    xmm0 = MSG (implicit operand for sha256rnds2)
      --    xmm1 = STATE0 (ABEF)
      --    xmm2 = STATE1 (CDGH)
      --    xmm3 = MSG0, xmm4 = MSG1, xmm5 = MSG2, xmm6 = MSG3
      --    xmm7 = TMP / MASK
      --    xmm8 = ABEF_SAVE, xmm9 = CDGH_SAVE
      Asm (
        --  Load initial state and rearrange for SHA256RNDS2
        "movdqu   (%0), %%xmm7"        & ASCII.LF &  -- TMP = state[0..3] (ABCD)
        "movdqu   16(%0), %%xmm2"      & ASCII.LF &  -- STATE1 = state[4..7] (EFGH)
        "pshufd   $0xb1, %%xmm7, %%xmm7" & ASCII.LF & -- TMP = CDAB
        "pshufd   $0x1b, %%xmm2, %%xmm2" & ASCII.LF & -- STATE1 = HGFE
        "movdqa   %%xmm7, %%xmm1"      & ASCII.LF &  -- xmm1 = TMP (CDAB)
        "palignr  $8, %%xmm2, %%xmm1"  & ASCII.LF &  -- STATE0 = ABEF
        "pblendw  $0xf0, %%xmm7, %%xmm2" & ASCII.LF & -- STATE1 = CDGH

        --  Save state
        "movdqa   %%xmm1, %%xmm8"      & ASCII.LF &  -- ABEF_SAVE
        "movdqa   %%xmm2, %%xmm9"      & ASCII.LF &  -- CDGH_SAVE

        --  Load byte-swap mask
        "movdqa   (%2), %%xmm7"        & ASCII.LF &

        --  Load and byte-swap message words
        "movdqu   (%1), %%xmm3"        & ASCII.LF &  -- MSG0
        "pshufb   %%xmm7, %%xmm3"      & ASCII.LF &
        "movdqu   16(%1), %%xmm4"      & ASCII.LF &  -- MSG1
        "pshufb   %%xmm7, %%xmm4"      & ASCII.LF &
        "movdqu   32(%1), %%xmm5"      & ASCII.LF &  -- MSG2
        "pshufb   %%xmm7, %%xmm5"      & ASCII.LF &
        "movdqu   48(%1), %%xmm6"      & ASCII.LF &  -- MSG3
        "pshufb   %%xmm7, %%xmm6"      & ASCII.LF &

        --  Rounds 0-3
        "movdqa   %%xmm3, %%xmm0"      & ASCII.LF &
        "paddd    (%3), %%xmm0"        & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2"   & ASCII.LF &
        "pshufd   $0x0e, %%xmm0, %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm2, %%xmm1"   & ASCII.LF &

        --  Rounds 4-7
        "movdqa   %%xmm4, %%xmm0"      & ASCII.LF &
        "paddd    16(%3), %%xmm0"      & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2"   & ASCII.LF &
        "pshufd   $0x0e, %%xmm0, %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm2, %%xmm1"   & ASCII.LF &
        "sha256msg1 %%xmm4, %%xmm3"    & ASCII.LF &

        --  Rounds 8-11
        "movdqa   %%xmm5, %%xmm0"      & ASCII.LF &
        "paddd    32(%3), %%xmm0"      & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2"   & ASCII.LF &
        "pshufd   $0x0e, %%xmm0, %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm2, %%xmm1"   & ASCII.LF &
        "sha256msg1 %%xmm5, %%xmm4"    & ASCII.LF &

        --  Rounds 12-15
        "movdqa   %%xmm6, %%xmm0"      & ASCII.LF &
        "paddd    48(%3), %%xmm0"      & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2"   & ASCII.LF &
        "movdqa   %%xmm6, %%xmm7"      & ASCII.LF &
        "palignr  $4, %%xmm5, %%xmm7"  & ASCII.LF &
        "paddd    %%xmm7, %%xmm3"      & ASCII.LF &
        "sha256msg2 %%xmm6, %%xmm3"    & ASCII.LF &
        "pshufd   $0x0e, %%xmm0, %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm2, %%xmm1"   & ASCII.LF &
        "sha256msg1 %%xmm6, %%xmm5"    & ASCII.LF &

        --  Rounds 16-19 through 60-63: repeating pattern
        --  Each group: add K, rnds2 x2, msg schedule (alignr+add+msg2+msg1)

        --  Rounds 16-19
        "movdqa   %%xmm3, %%xmm0" & ASCII.LF & "paddd 64(%3), %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2" & ASCII.LF &
        "movdqa %%xmm3, %%xmm7" & ASCII.LF & "palignr $4, %%xmm6, %%xmm7" & ASCII.LF &
        "paddd %%xmm7, %%xmm4" & ASCII.LF & "sha256msg2 %%xmm3, %%xmm4" & ASCII.LF &
        "pshufd $0x0e, %%xmm0, %%xmm0" & ASCII.LF & "sha256rnds2 %%xmm2, %%xmm1" & ASCII.LF &
        "sha256msg1 %%xmm3, %%xmm6" & ASCII.LF &

        --  Rounds 20-23
        "movdqa %%xmm4, %%xmm0" & ASCII.LF & "paddd 80(%3), %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2" & ASCII.LF &
        "movdqa %%xmm4, %%xmm7" & ASCII.LF & "palignr $4, %%xmm3, %%xmm7" & ASCII.LF &
        "paddd %%xmm7, %%xmm5" & ASCII.LF & "sha256msg2 %%xmm4, %%xmm5" & ASCII.LF &
        "pshufd $0x0e, %%xmm0, %%xmm0" & ASCII.LF & "sha256rnds2 %%xmm2, %%xmm1" & ASCII.LF &
        "sha256msg1 %%xmm4, %%xmm3" & ASCII.LF &

        --  Rounds 24-27
        "movdqa %%xmm5, %%xmm0" & ASCII.LF & "paddd 96(%3), %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2" & ASCII.LF &
        "movdqa %%xmm5, %%xmm7" & ASCII.LF & "palignr $4, %%xmm4, %%xmm7" & ASCII.LF &
        "paddd %%xmm7, %%xmm6" & ASCII.LF & "sha256msg2 %%xmm5, %%xmm6" & ASCII.LF &
        "pshufd $0x0e, %%xmm0, %%xmm0" & ASCII.LF & "sha256rnds2 %%xmm2, %%xmm1" & ASCII.LF &
        "sha256msg1 %%xmm5, %%xmm4" & ASCII.LF &

        --  Rounds 28-31
        "movdqa %%xmm6, %%xmm0" & ASCII.LF & "paddd 112(%3), %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2" & ASCII.LF &
        "movdqa %%xmm6, %%xmm7" & ASCII.LF & "palignr $4, %%xmm5, %%xmm7" & ASCII.LF &
        "paddd %%xmm7, %%xmm3" & ASCII.LF & "sha256msg2 %%xmm6, %%xmm3" & ASCII.LF &
        "pshufd $0x0e, %%xmm0, %%xmm0" & ASCII.LF & "sha256rnds2 %%xmm2, %%xmm1" & ASCII.LF &
        "sha256msg1 %%xmm6, %%xmm5" & ASCII.LF &

        --  Rounds 32-35
        "movdqa %%xmm3, %%xmm0" & ASCII.LF & "paddd 128(%3), %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2" & ASCII.LF &
        "movdqa %%xmm3, %%xmm7" & ASCII.LF & "palignr $4, %%xmm6, %%xmm7" & ASCII.LF &
        "paddd %%xmm7, %%xmm4" & ASCII.LF & "sha256msg2 %%xmm3, %%xmm4" & ASCII.LF &
        "pshufd $0x0e, %%xmm0, %%xmm0" & ASCII.LF & "sha256rnds2 %%xmm2, %%xmm1" & ASCII.LF &
        "sha256msg1 %%xmm3, %%xmm6" & ASCII.LF &

        --  Rounds 36-39
        "movdqa %%xmm4, %%xmm0" & ASCII.LF & "paddd 144(%3), %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2" & ASCII.LF &
        "movdqa %%xmm4, %%xmm7" & ASCII.LF & "palignr $4, %%xmm3, %%xmm7" & ASCII.LF &
        "paddd %%xmm7, %%xmm5" & ASCII.LF & "sha256msg2 %%xmm4, %%xmm5" & ASCII.LF &
        "pshufd $0x0e, %%xmm0, %%xmm0" & ASCII.LF & "sha256rnds2 %%xmm2, %%xmm1" & ASCII.LF &
        "sha256msg1 %%xmm4, %%xmm3" & ASCII.LF &

        --  Rounds 40-43
        "movdqa %%xmm5, %%xmm0" & ASCII.LF & "paddd 160(%3), %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2" & ASCII.LF &
        "movdqa %%xmm5, %%xmm7" & ASCII.LF & "palignr $4, %%xmm4, %%xmm7" & ASCII.LF &
        "paddd %%xmm7, %%xmm6" & ASCII.LF & "sha256msg2 %%xmm5, %%xmm6" & ASCII.LF &
        "pshufd $0x0e, %%xmm0, %%xmm0" & ASCII.LF & "sha256rnds2 %%xmm2, %%xmm1" & ASCII.LF &
        "sha256msg1 %%xmm5, %%xmm4" & ASCII.LF &

        --  Rounds 44-47
        "movdqa %%xmm6, %%xmm0" & ASCII.LF & "paddd 176(%3), %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2" & ASCII.LF &
        "movdqa %%xmm6, %%xmm7" & ASCII.LF & "palignr $4, %%xmm5, %%xmm7" & ASCII.LF &
        "paddd %%xmm7, %%xmm3" & ASCII.LF & "sha256msg2 %%xmm6, %%xmm3" & ASCII.LF &
        "pshufd $0x0e, %%xmm0, %%xmm0" & ASCII.LF & "sha256rnds2 %%xmm2, %%xmm1" & ASCII.LF &
        "sha256msg1 %%xmm6, %%xmm5" & ASCII.LF &

        --  Rounds 48-51
        "movdqa %%xmm3, %%xmm0" & ASCII.LF & "paddd 192(%3), %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2" & ASCII.LF &
        "movdqa %%xmm3, %%xmm7" & ASCII.LF & "palignr $4, %%xmm6, %%xmm7" & ASCII.LF &
        "paddd %%xmm7, %%xmm4" & ASCII.LF & "sha256msg2 %%xmm3, %%xmm4" & ASCII.LF &
        "pshufd $0x0e, %%xmm0, %%xmm0" & ASCII.LF & "sha256rnds2 %%xmm2, %%xmm1" & ASCII.LF &
        "sha256msg1 %%xmm3, %%xmm6" & ASCII.LF &

        --  Rounds 52-55
        "movdqa %%xmm4, %%xmm0" & ASCII.LF & "paddd 208(%3), %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2" & ASCII.LF &
        "movdqa %%xmm4, %%xmm7" & ASCII.LF & "palignr $4, %%xmm3, %%xmm7" & ASCII.LF &
        "paddd %%xmm7, %%xmm5" & ASCII.LF & "sha256msg2 %%xmm4, %%xmm5" & ASCII.LF &
        "pshufd $0x0e, %%xmm0, %%xmm0" & ASCII.LF & "sha256rnds2 %%xmm2, %%xmm1" & ASCII.LF &

        --  Rounds 56-59
        "movdqa %%xmm5, %%xmm0" & ASCII.LF & "paddd 224(%3), %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2" & ASCII.LF &
        "movdqa %%xmm5, %%xmm7" & ASCII.LF & "palignr $4, %%xmm4, %%xmm7" & ASCII.LF &
        "paddd %%xmm7, %%xmm6" & ASCII.LF & "sha256msg2 %%xmm5, %%xmm6" & ASCII.LF &
        "pshufd $0x0e, %%xmm0, %%xmm0" & ASCII.LF & "sha256rnds2 %%xmm2, %%xmm1" & ASCII.LF &

        --  Rounds 60-63
        "movdqa %%xmm6, %%xmm0" & ASCII.LF & "paddd 240(%3), %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm1, %%xmm2" & ASCII.LF &
        "pshufd $0x0e, %%xmm0, %%xmm0" & ASCII.LF &
        "sha256rnds2 %%xmm2, %%xmm1" & ASCII.LF &

        --  Add saved state
        "paddd    %%xmm8, %%xmm1"      & ASCII.LF &  -- STATE0 += ABEF_SAVE
        "paddd    %%xmm9, %%xmm2"      & ASCII.LF &  -- STATE1 += CDGH_SAVE

        --  Rearrange back to standard H0..H7 order
        "pshufd   $0x1b, %%xmm1, %%xmm7" & ASCII.LF & -- TMP = FEBA
        "pshufd   $0xb1, %%xmm2, %%xmm2" & ASCII.LF & -- STATE1 = DCHG
        "movdqa   %%xmm7, %%xmm1"      & ASCII.LF &
        "pblendw  $0xf0, %%xmm2, %%xmm1" & ASCII.LF & -- STATE0 = DCBA = state[0..3]
        "palignr  $8, %%xmm7, %%xmm2"  & ASCII.LF &   -- STATE1 = HGFE = state[4..7]

        --  Store state
        "movdqu   %%xmm1, (%0)"        & ASCII.LF &
        "movdqu   %%xmm2, 16(%0)",

        Inputs   => (System.Address'Asm_Input ("r", S (S'First)'Address),     -- %0
                     System.Address'Asm_Input ("r", Data),                    -- %1
                     System.Address'Asm_Input ("r", Bswap (Bswap'First)'Address), -- %2
                     System.Address'Asm_Input ("r", K (K'First)'Address)),    -- %3
        Clobber  => "xmm0,xmm1,xmm2,xmm3,xmm4,xmm5,xmm6,xmm7,xmm8,xmm9,memory",
        Volatile => True);
   end Process_Block;

   --================================================================
   --  Helpers
   --================================================================

   Init_State : constant State_Array :=
     (16#6a09e667#, 16#bb67ae85#, 16#3c6ef372#, 16#a54ff53a#,
      16#510e527f#, 16#9b05688c#, 16#1f83d9ab#, 16#5be0cd19#);

   procedure State_To_Digest (Output : out Digest; S : State_Array) is
   begin
      for I in 0 .. 7 loop
         Output (I32 (I * 4))     := Byte (Shift_Right (S (I), 24));
         Output (I32 (I * 4 + 1)) := Byte (Shift_Right (S (I), 16) and 16#FF#);
         Output (I32 (I * 4 + 2)) := Byte (Shift_Right (S (I), 8) and 16#FF#);
         Output (I32 (I * 4 + 3)) := Byte (S (I) and 16#FF#);
      end loop;
   end State_To_Digest;

   --================================================================
   --  Streaming (incremental) interface
   --================================================================

   procedure Init (Ctx : out Context) is
   begin
      Ctx.State   := Init_State;
      Ctx.Buffer  := (others => 0);
      Ctx.Buf_Len := 0;
      Ctx.Total   := 0;
   end Init;

   procedure Update (Ctx : in out Context; Data : Byte_Seq) is
      Pos       : N32 := Data'First;
      Remaining : N32;
      Space     : N32;
   begin
      if Data'Length = 0 then
         return;
      end if;
      Remaining := N32 (Data'Length);

      --  Fill partial buffer
      if Ctx.Buf_Len > 0 then
         Space := 64 - Ctx.Buf_Len;
         if Remaining < Space then
            Ctx.Buffer (Ctx.Buf_Len .. Ctx.Buf_Len + Remaining - 1) :=
              Data (Pos .. Pos + Remaining - 1);
            Ctx.Buf_Len := Ctx.Buf_Len + Remaining;
            Ctx.Total := Ctx.Total + Unsigned_64 (Remaining);
            return;
         end if;
         Ctx.Buffer (Ctx.Buf_Len .. 63) :=
           Data (Pos .. Pos + Space - 1);
         Process_Block (Ctx.State, Ctx.Buffer (0)'Address);
         Pos := Pos + Space;
         Remaining := Remaining - Space;
         Ctx.Buf_Len := 0;
      end if;

      --  Process full blocks directly
      while Remaining >= 64 loop
         Process_Block (Ctx.State, Data (Pos)'Address);
         Pos := Pos + 64;
         Remaining := Remaining - 64;
      end loop;

      --  Buffer remainder
      if Remaining > 0 then
         Ctx.Buffer (0 .. Remaining - 1) := Data (Pos .. Pos + Remaining - 1);
         Ctx.Buf_Len := Remaining;
      end if;

      Ctx.Total := Ctx.Total + Unsigned_64 (Data'Length);
   end Update;

   procedure Final (Ctx : in out Context; Output : out Digest) is
      Bit_Len : constant Unsigned_64 := Ctx.Total * 8;
   begin
      --  Append 0x80
      Ctx.Buffer (Ctx.Buf_Len) := 16#80#;
      Ctx.Buf_Len := Ctx.Buf_Len + 1;

      --  Need room for 8-byte length; if not, pad+process extra block
      if Ctx.Buf_Len > 56 then
         for I in Ctx.Buf_Len .. 63 loop
            Ctx.Buffer (I) := 0;
         end loop;
         Process_Block (Ctx.State, Ctx.Buffer (0)'Address);
         Ctx.Buf_Len := 0;
      end if;

      --  Pad zeros up to length field
      for I in Ctx.Buf_Len .. 55 loop
         Ctx.Buffer (I) := 0;
      end loop;

      --  Big-endian 64-bit length
      for I in 0 .. 7 loop
         Ctx.Buffer (56 + I32 (I)) :=
           Byte (Shift_Right (Bit_Len, (7 - I) * 8) and 16#FF#);
      end loop;

      Process_Block (Ctx.State, Ctx.Buffer (0)'Address);
      State_To_Digest (Output, Ctx.State);
   end Final;

   --================================================================
   --  One-shot interface (built on streaming)
   --================================================================

   procedure Hash (Output : out Digest; M : in Byte_Seq) is
      Ctx : Context;
   begin
      Init (Ctx);
      Update (Ctx, M);
      Final (Ctx, Output);
   end Hash;

   function Hash (M : in Byte_Seq) return Digest is
      D : Digest;
   begin
      Hash (D, M);
      return D;
   end Hash;

end SPARKTLS.Hashing.SHA256;
