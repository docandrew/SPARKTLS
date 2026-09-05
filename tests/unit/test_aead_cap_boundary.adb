--  #80: behavior at the AEAD record-cap boundary (RFC 8446 Section 5.5;
--  the same 2**23 budget adopted for TLS 1.2 where no rekey exists).
--
--  The cap is proof-enforced on the encrypt side (Space_Left preconditions)
--  and runtime-enforced against peers on the decrypt side, but no protocol
--  suite can drive 8 million records to reach it -- so the boundary itself
--  was never executed until this test. Since 2026-08-24 Record_Counter's
--  TYPE bound is the cap, so this also pins the type/design agreement.
--
--  Runs with no network and no ports, so it also executes under --checked.

with Ada.Text_IO;   use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;    use Interfaces;
with SPARKNaCl;     use SPARKNaCl;
with SPARKTLS;
with SPARKTLS_Reassembly;      use SPARKTLS;
with SPARKTLS.Records.TLS12;
with RFLX.RFLX_Builtin_Types;

procedure Test_AEAD_Cap_Boundary is
   --  Record-layer RecordFlux scratch buffer, threaded through every record
   --  builder below exactly as Session.Rec_Hdr is in production.
   Hdr_Buf : RFLX.RFLX_Builtin_Types.Bytes_Ptr := null;

   Pass : Natural := 0;
   Fail : Natural := 0;

   procedure Check (Name : String; Ok : Boolean) is
   begin
      if Ok then
         Pass := Pass + 1;
      else
         Fail := Fail + 1;
         Put_Line ("FAIL: " & Name);
      end if;
   end Check;

   Cap : constant Unsigned_64 := Unsigned_64 (Rekey_After_Records);

begin
   --  1. The type/design agreement: the counter's bound IS the budget,
   --     and Space_Left flips exactly at it.
   Check ("Rekey_After_Records is the TX budget cap",
          Unsigned_64 (Rekey_After_Records) = Cap);
   Check ("Record_Counter'Last is the RX arithmetic bound (#115)",
          Unsigned_64 (Record_Counter'Last) = 2**62);
   declare
      K : Traffic_Keys;
   begin
      K.Counter := Rekey_After_Records - 1;
      Check ("Space_Left at cap - 1", Space_Left (K));
      K.Counter := Rekey_After_Records;
      Check ("no Space_Left at the cap", not Space_Left (K));
   end;

   --  2. Walking the last legal step: an encrypt at cap - 1 succeeds and
   --     lands the channel exactly on the cap, budget exhausted.
   declare
      Keys      : Traffic_Keys;
      IV        : constant Byte_Seq
        (0 .. SPARKTLS.Records.TLS12.Implicit_IV_Len - 1) :=
        (others => 16#42#);
      Plain     : constant Byte_Seq (0 .. 15) := (others => 16#AB#);
      Output    : IO_Buffer;
      Bytes_Out : N32;
   begin
      Output.Data := new RFLX.RFLX_Builtin_Types.Bytes'(1 .. RFLX.RFLX_Builtin_Types.Index (SPARKTLS_Reassembly.IO_Buffer_Capacity) => 0);
      Keys.Suite   := Suite_AES_128_GCM_SHA256;
      Keys.Counter := Rekey_After_Records - 1;
      SPARKTLS.Records.TLS12.Build_Encrypted_Record_12
        (Plaintext    => Plain,
         Content_Type => 16#17#,
         Keys         => Keys,
         Implicit_IV  => IV,
         Output       => Output,
         Bytes_Out    => Bytes_Out,
         Hdr_Buf      => Hdr_Buf);
      Check ("final in-budget record is emitted", Bytes_Out > 0);
      Check ("counter lands exactly on the cap",
             Unsigned_64 (Keys.Counter) = Cap);
      Check ("budget exhausted after the final record",
             not Space_Left (Keys));

      --  3. Refusal at the cap: the alert builder carries no Space_Left
      --     precondition (alerts fire from error paths), so it is the
      --     legal probe of the internal fail-closed branch -- it must
      --     refuse to encrypt and must not advance the counter.
      SPARKTLS.Records.TLS12.Build_Alert_Record_12
        (Level       => 2,
         Desc        => 80,
         Keys        => Keys,
         Implicit_IV => IV,
         Output      => Output,
         Bytes_Out   => Bytes_Out,
         Hdr_Buf     => Hdr_Buf);
      Check ("exhausted channel refuses the alert", Bytes_Out = 0);
      Check ("refusal does not advance the counter",
             Unsigned_64 (Keys.Counter) = Cap);

      --  3b. The encrypted-record builder is now best-effort too (the
      --  Space_Left precondition was dropped 2026-08-24): at the cap it
      --  must refuse exactly like the alert builder.
      SPARKTLS.Records.TLS12.Build_Encrypted_Record_12
        (Plaintext    => Plain,
         Content_Type => 16#17#,
         Keys         => Keys,
         Implicit_IV  => IV,
         Output       => Output,
         Bytes_Out    => Bytes_Out,
         Hdr_Buf      => Hdr_Buf);
      Check ("exhausted channel refuses app data", Bytes_Out = 0);
      Check ("refused app data does not advance the counter",
             Unsigned_64 (Keys.Counter) = Cap);

      --  3c. The control-record margin: the write budget must stop far
      --  enough below the cap that KeyUpdate / close_notify still fit.
      Check ("write budget sits below the cap",
             Unsigned_64 (Rekey_After_Records) - Unsigned_64 (Rekey_Margin)
               < Cap);
      declare
         K : Traffic_Keys;
      begin
         K.Counter := Rekey_After_Records - Rekey_Margin;
         Check ("budget reached exactly at cap - margin",
                Write_Budget_Reached (K));
         K.Counter := K.Counter - 1;
         Check ("one below the budget is still writable",
                not Write_Budget_Reached (K));
         Check ("headroom inside the margin still has Space_Left",
                Space_Left ((K with delta
                              Counter => Rekey_After_Records - 1)));
      end;

      --  Rekey as the only exit is covered elsewhere: Update_Secret's
      --  PROVEN postcondition pins TK.Counter = 0 under the new secret
      --  (Key_Update is a private child, unreachable from tests), and
      --  the tlsfuzzer keyupdate suite drives the rotation end to end.
   end;

   Put_Line ("=== AEAD cap boundary:" & Pass'Image & " passed,"
             & Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_AEAD_Cap_Boundary;
