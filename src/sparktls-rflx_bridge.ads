with SPARKNaCl;          use SPARKNaCl;
with RFLX.RFLX_Builtin_Types;

--  Bridge between SPARKNaCl types (0-indexed, Byte = mod 256)
--  and RecordFlux types (1-indexed, Byte = mod 2**8).
--  Both Byte types are mod 2**8, so conversion is representation-safe.
package SPARKTLS.RFLX_Bridge with
   SPARK_Mode => On
is
   package RBT renames RFLX.RFLX_Builtin_Types;

   use type RBT.Length;
   use type RBT.Index;
   use type RBT.Bytes_Ptr;

   --  Convert SPARKNaCl Byte_Seq to RFLX Bytes (changes index base)
   function To_RFLX (Data : Byte_Seq) return RBT.Bytes
   with Pre  => Data'Length > 0,
        Post => To_RFLX'Result'First = 1
                and To_RFLX'Result'Length = Data'Length;

   --  Convert RFLX Bytes to SPARKNaCl Byte_Seq (changes index base)
   function To_NaCl (Data : RBT.Bytes) return Byte_Seq
   with Pre  => Data'Length > 0,
        Post => To_NaCl'Result'First = 0
                and To_NaCl'Result'Length = Data'Length;

end SPARKTLS.RFLX_Bridge;
