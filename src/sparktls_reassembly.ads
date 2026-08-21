--  Handshake message reassembly: the buffer AND its accounting, owned
--  together by one module.
--
--  TOP-LEVEL, not a child of SPARKTLS, on purpose. Handshake_Context is
--  declared in sparktls.ads, and a parent spec cannot name a child package's
--  type -- so the buffer has to be the MORE PRIMITIVE module and SPARKTLS
--  depends on it, not the other way round. That is the honest direction
--  anyway: reassembly knows nothing about sessions, versions or roles.
--
--  Why this package exists at all: the previous design kept the byte buffer
--  and its accounting (Len/Need) as separate, unrelated state that six
--  different subprograms wrote independently. Nothing owned the relation
--  between them, so every call site had to re-establish it -- which produced
--  a ghost function asserted at 398 sites and 13 separate "Need - Len"
--  subtractions, each needing its own justification. Here the relation is not
--  asserted, it is STRUCTURAL: callers cannot reach the fields, so they
--  cannot desynchronise them.
--
--  Two kinds of check are kept deliberately distinct:
--    * PEER-CONTROLLED length is validated at RUNTIME (Free_Space,
--      Message_Too_Large). Untrusted input must always be checked.
--    * OUR OWN flow control is a PRECONDITION, proved. There are no runtime
--      guards here against our own logic errors.
with Interfaces; use Interfaces;
with SPARKNaCl;  use SPARKNaCl;
package SPARKTLS_Reassembly with SPARK_Mode => On is

   --  RFC 8446 4: largest handshake message we will reassemble. Anything
   --  larger is a decode error. Defined HERE rather than in SPARKTLS because
   --  it is a property of the buffer, and SPARKTLS re-exports it unchanged.
   Max_HS_Msg : constant := 131_072;
   subtype HS_Msg_Len is N32 range 0 .. Max_HS_Msg;

   --  Record sizing. Owned here rather than in SPARKTLS because Wire_Chunk's
   --  bound depends on it, and a single source of truth beats two constants
   --  that agree today. SPARKTLS re-exports all three unchanged.
   Max_Record_Plaintext : constant := 16_384;   --  RFC 8446 limit
   Max_Record_Overhead  : constant := 256;      --  tag + content type
   Max_Record_Size      : constant :=
      Max_Record_Plaintext + Max_Record_Overhead;

   --  Capacity of the IO buffers wire data is sliced from. Large enough for
   --  two max-size records so the caller need not drain after every record.
   IO_Buffer_Capacity : constant N32 := 2 * Max_Record_Size;

   --  Data that came off the wire: a slice of a bounded IO buffer.
   --
   --  Byte_Seq is indexed by N32 = 0 .. I32'Last, so an arbitrary slice's
   --  'Length is I32'Last + 1 in the worst case -- it OVERFLOWS, and the
   --  prover is right to refuse to evaluate it. Every real caller slices a
   --  bounded IO buffer or a record plaintext, but nothing in the types said
   --  so. A subtype rather than a precondition conjunct, so the bound holds
   --  everywhere the type is used instead of being restated by every
   --  subprogram that accepts wire data.
   subtype Wire_Chunk is Byte_Seq
     with Dynamic_Predicate => Wire_Chunk'Last < IO_Buffer_Capacity;

   type Buffer is limited private;

   --  Bytes currently buffered, from offset 0.
   function Used (B : Buffer) return HS_Msg_Len;

   --  Room remaining. Callers check this against peer-supplied lengths.
   function Free_Space (B : Buffer) return HS_Msg_Len;

   --  At least four bytes: the handshake header is readable.
   function Header_Ready (B : Buffer) return Boolean;

   --  Total size of the message at offset 0, header included. Derived from
   --  the buffer's own bytes 1 .. 3 -- there is no second copy to fall out of
   --  step. Peer-controlled, so it may exceed what we can ever hold; see
   --  Message_Too_Large.
   function Declared_Size (B : Buffer) return N32
     with Pre => Header_Ready (B);

   --  The peer declared a message we can never buffer. A protocol error: the
   --  caller must alert rather than proceed.
   function Message_Too_Large (B : Buffer) return Boolean;

   --  A whole message is present at offset 0. May STILL be true after
   --  Consume: that is the packed-flight case, and it needs no separate
   --  concept, no second phase and no second set of fields.
   function Has_Message (B : Buffer) return Boolean;

   function Message_Length (B : Buffer) return HS_Msg_Len
     with Pre  => Has_Message (B) and then not Message_Too_Large (B),
          Post => Message_Length'Result >= 4;

   --  The complete message at offset 0, header included.
   function Message (B : Buffer) return Byte_Seq
     with Pre  => Has_Message (B) and then not Message_Too_Large (B),
          Post => Message'Result'First = 0
                  and then Message'Result'Length = Message_Length (B);

   procedure Reset (B : out Buffer)
     with Post => Used (B) = 0
                  and then Free_Space (B) = Max_HS_Msg
                  and then not Has_Message (B);

   --  ALL-OR-NOTHING. Running out of room is not a condition to handle, it is
   --  a state the caller proves unreachable -- having first checked the
   --  peer's length against Free_Space. A partial copy would silently turn
   --  our own flow-control error into "data".
   procedure Append (B : in out Buffer; Data : Wire_Chunk)
     with Pre  => Data'Length <= Free_Space (B),
          --  Stated via Free_Space, not Used: both are true, but this form
          --  keeps every term inside HS_Msg_Len's bounds.
          Post => Free_Space (B) = Free_Space (B)'Old - Data'Length;

   --  Drop the message at offset 0; shift any trailing bytes down.
   procedure Consume (B : in out Buffer)
     with Pre  => Has_Message (B) and then not Message_Too_Large (B),
          Post => Used (B) = Used (B)'Old - Message_Length (B)'Old;

private

   subtype Buf_Index is N32 range 0 .. Max_HS_Msg - 1;

   type Buffer is record
      Data   : Byte_Seq (Buf_Index) := (others => 0);
      Filled : HS_Msg_Len           := 0;
   end record;

end SPARKTLS_Reassembly;
