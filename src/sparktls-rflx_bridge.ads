with SPARKNaCl; use SPARKNaCl;
with RFLX.RFLX_Builtin_Types;

--  Bridge between SPARKNaCl types (0-indexed, Byte = mod 256)
--  and RecordFlux types (1-indexed, Byte = mod 2**8).
--  Both Byte types are mod 2**8, so conversion is representation-safe.

package SPARKTLS.RFLX_Bridge
  with SPARK_Mode => On
is
   package RBT renames RFLX.RFLX_Builtin_Types;

   use type RBT.Length;
   use type RBT.Index;
   use type RBT.Bytes_Ptr;
   use type RBT.Byte;

   --  Convert SPARKNaCl Byte_Seq to RFLX Bytes (changes index base)
   function To_RFLX (Data : Byte_Seq) return RBT.Bytes
   with
     Pre => Data'Length > 0 and Data'Last < N32 (Natural'Last),
     Post =>
       To_RFLX'Result'First = 1
       and To_RFLX'Result'Length
           = Data'Length
             --  Byte preservation: caller proofs about Equal (Ctx, F, X)
             --  vs Equal (Ctx, F, To_RFLX (Y)) need a way to relate
             --  the two byte sequences.
       and (for all I in Data'Range
            => To_RFLX'Result (RBT.Index (I - Data'First + 1)) = RBT.Byte (Data (I)));

   --  Convert RFLX Bytes to SPARKNaCl Byte_Seq (changes index base)
   function To_NaCl (Data : RBT.Bytes) return Byte_Seq
   with
     Pre => Data'Length > 0,
     Post => To_NaCl'Result'First = 0 and To_NaCl'Result'Length = Data'Length;

   --  There are deliberately no View_As_* helpers here. Now that RFLX's Byte
   --  is SPARKNaCl's Byte, a conversion written inline as an actual parameter
   --  (Byte_Seq (X) / RBT.Bytes (X)) is a zero-copy view; a FUNCTION returning
   --  the same conversion copies its whole result through the secondary stack
   --  (measured with -gnatG, 2026-09-05). To_RFLX and To_NaCl are the sliding
   --  copies, named as such. See generated/README.md for the bounds rule.

end SPARKTLS.RFLX_Bridge;
