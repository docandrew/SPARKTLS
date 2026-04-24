--  SPARKTLS SHA-256 — Hardware-accelerated when available
--
--  Uses SHA-NI instructions (x86) when detected at elaboration,
--  falls back to SPARKNaCl's software implementation otherwise.
--  Provides one-shot and streaming (incremental) interfaces.
--
--  API mirrors SPARKNaCl.Hashing.SHA256 for drop-in replacement.

with Interfaces;
with SPARKNaCl; use SPARKNaCl;

package SPARKTLS.Hashing.SHA256 with
   SPARK_Mode => On,
   Elaborate_Body
is
   subtype Digest is Bytes_32;

   --------------------------------------------------------
   --  One-shot interface
   --------------------------------------------------------

   procedure Hash (Output : out Digest;
                   M      : in  Byte_Seq)
   with Global => null;

   function Hash (M : in Byte_Seq) return Digest
   with Global => null;

   --------------------------------------------------------
   --  Streaming (incremental) interface
   --------------------------------------------------------

   type Context is private;

   procedure Init (Ctx : out Context)
   with Global => null;

   procedure Update (Ctx : in out Context; Data : Byte_Seq)
   with Global => null;

   procedure Final (Ctx : in out Context; Output : out Digest)
   with Global => null;

   --------------------------------------------------------
   --  Hardware detection
   --------------------------------------------------------

   function Has_HW_Accel return Boolean
   with Global => null;

private
   type State_Array is array (0 .. 7) of Interfaces.Unsigned_32
   with Alignment => 16;

   type Context is record
      State    : State_Array;
      Buffer   : Byte_Seq (0 .. 63);
      Buf_Len  : N32;
      Total    : Interfaces.Unsigned_64;
   end record;

end SPARKTLS.Hashing.SHA256;
