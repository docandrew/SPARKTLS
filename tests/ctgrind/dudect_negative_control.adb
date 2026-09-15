--  dudect canary: a PLANTED secret-dependent delay on top of the real
--  AEAD encrypt. The lane requires this harness to report
--  "TIMING DEPENDS ON SECRET INPUT"; if it ever reads "ok", the
--  statistics or the measurement loop have lost their teeth and every
--  other dudect verdict is meaningless. Mirrors ct_negative_control on
--  the ctgrind side.
--
--  Same shape as dudect_aead (Prepare/Subject form, masked select,
--  shared buffers) so the canary exercises exactly the code path the
--  real harness relies on. The subject does the genuine 4 KiB
--  ChaCha20-Poly1305 encrypt and then spends Leak extra dependent
--  iterations (~2-3 cycles each) only when the secret's low bit is set.
--  Leak defaults to 16 (~40 cycles, under 1% of the subject's cost;
--  measured min t over 10 runs: Leak=1 -> 8.6, Leak=8 -> 13.9, so 16
--  keeps the canary itself far from flaking) and can be overridden on
--  the command line to probe the detection floor:
--
--     dudect_negative_control 1      -- ~2-3 cycles planted
--     dudect_negative_control 0      -- no leak: must read "ok"

with Interfaces;      use Interfaces; use type Interfaces.Unsigned_8;
with Ada.Command_Line;
with SPARKNaCl;       use SPARKNaCl;
with SPARKNaCl.Core;
with SPARKTLSCrypto.ChaCha20_Poly1305;
with Dudect_Helpers;

procedure Dudect_Negative_Control is
   M     : aliased Byte_Seq (0 .. 4095) := (others => 16#AA#);
   AAD   : aliased Byte_Seq (0 .. 15)   := (others => 16#BB#);
   N_Bytes : constant Bytes_12 :=
     (16#01#, 16#02#, 16#03#, 16#04#, 16#05#, 16#06#,
      16#07#, 16#08#, 16#09#, 16#0A#, 16#0B#, 16#0C#);
   Nonce : SPARKNaCl.Core.ChaCha20_IETF_Nonce := N_Bytes;

   K0_Bytes : constant Bytes_32 := (others => 16#00#);
   K1_Bytes : constant Bytes_32 := (others => 16#FF#);

   C   : aliased Byte_Seq (0 .. 4095);
   Tag : Bytes_16;

   Leak : Natural := 16;

   --  Shared buffers written by Prepare, read by Subject.
   Cur    : SPARKNaCl.Core.ChaCha20_Key;
   Secret : Byte := 0;

   --  Sink for the planted work so it cannot be optimised away.
   Acc : Unsigned_64 := 0 with Volatile;

   procedure Prep (Second : Boolean) is
      Mask : constant Byte := Byte (Boolean'Pos (Second)) * Byte'Last;
      KB   : Bytes_32;
   begin
      for I in KB'Range loop
         KB (I) := (K0_Bytes (I) and not Mask) or (K1_Bytes (I) and Mask);
      end loop;
      SPARKNaCl.Core.Construct (Cur, KB);
      Secret := KB (0);
   end Prep;

   procedure Encrypt_Then_Leak is
      Extra : constant Natural := Natural (Secret and 1) * Leak;
      A     : Unsigned_64 := Acc;
   begin
      SPARKTLSCrypto.ChaCha20_Poly1305.Encrypt
        (C => C, Tag => Tag, M => M, N => Nonce, K => Cur, AAD => AAD);
      --  THE PLANTED LEAK: work proportional to a secret bit.
      for I in 1 .. Extra loop
         A := A * 3 + Unsigned_64 (I);
      end loop;
      Acc := A;
   end Encrypt_Then_Leak;
begin
   if Ada.Command_Line.Argument_Count >= 1 then
      Leak := Natural'Value (Ada.Command_Line.Argument (1));
   end if;
   Dudect_Helpers.Time_Test
     (Name      =>
        "CANARY: AEAD 4KiB + planted" & Leak'Image
        & "-iteration secret-dependent delay (must be flagged)",
      Prepare   => Prep'Access,
      Subject   => Encrypt_Then_Leak'Access,
      N         => 20_000);
end Dudect_Negative_Control;
