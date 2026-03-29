with Interfaces; use Interfaces;
with SPARKNaCl;  use SPARKNaCl;

--  SPARK-verified arbitrary-precision natural number arithmetic.
--
--  Designed for RSA (up to 4096 bits) and P-384 field arithmetic.
--  All operations are constant-time where noted.
--
--  Key design choices for SPARK provability:
--    - Fixed-size word array (no runtime header word)
--    - Word count tracked in a separate record field
--    - Functions return results (no aliasing)
--    - Procedures use non-overlapping out/in parameters
--    - All loops have explicit bounds from Len field
package SPARKTLS.BigNat with
   SPARK_Mode => On
is
   Max_Words : constant := 256;  --  Up to 8192-bit values
   Max_Bits  : constant := Max_Words * 32;

   subtype Word is Unsigned_32;
   subtype DWord is Unsigned_64;

   subtype Word_Count is Natural range 0 .. Max_Words;
   type Word_Array is array (Natural range 0 .. Max_Words - 1) of Word;

   --  A big natural number: Len active words in little-endian order.
   --  Words beyond Len are always zero.
   type Big_Nat is record
      Len : Word_Count := 0;
      W   : Word_Array := (others => 0);
   end record;

   --  Result of addition/subtraction with carry/borrow
   type Arith_Result is record
      Value : Big_Nat;
      Carry : Word;  --  0 or 1
   end record;

   --  Predicate: all words beyond Len are zero
   function Well_Formed (A : Big_Nat) return Boolean is
      (for all I in A.Len .. Max_Words - 1 => A.W (I) = 0);

   --  Create a Big_Nat from a byte sequence (big-endian)
   procedure Decode
     (Result : out Big_Nat;
      Src    : in  Byte_Seq)
   with Pre  => Src'First = 0 and Src'Length <= Max_Words * 4
               and Src'Last < N32'Last,
        Always_Terminates;

   --  Encode a Big_Nat to a byte sequence (big-endian)
   procedure Encode
     (Dst    : out Byte_Seq;
      A      : in  Big_Nat)
   with Pre => Dst'First = 0 and Dst'Length <= Max_Words * 4,
        Always_Terminates;

   --  Set to zero with a given word count
   procedure Zero
     (Result : out Big_Nat;
      Len    : in  Word_Count)
   with Post => Result.Len = Len and Well_Formed (Result);

   --  Constant-time conditional subtraction: if Ctl=1, Result = A - B;
   --  if Ctl=0, Result = A (unchanged). Returns borrow bit.
   function CT_Sub
     (A, B : Big_Nat;
      Ctl  : Word) return Arith_Result
   with Pre  => A.Len = B.Len and A.Len > 0,
        Post => CT_Sub'Result.Value.Len = A.Len;

   --  Constant-time conditional addition: if Ctl=1, Result = A + B;
   --  if Ctl=0, Result = A (unchanged). Returns carry bit.
   function CT_Add
     (A, B : Big_Nat;
      Ctl  : Word) return Arith_Result
   with Pre  => A.Len = B.Len and A.Len > 0,
        Post => CT_Add'Result.Value.Len = A.Len;

   --  Constant-time comparison helpers
   function CT_Eq  (X, Y : Word) return Word;
   function CT_Neq (X, Y : Word) return Word;
   function CT_Not (X : Word) return Word;
   function CT_Mux (Ctl, X, Y : Word) return Word;

   --  Montgomery multiplication: Result = (A * B * R^-1) mod M
   --  M0I is -M^(-1) mod 2^32.
   procedure Monty_Mul
     (Result : out Big_Nat;
      A, B   : in  Big_Nat;
      M      : in  Big_Nat;
      M0I    : in  Word)
   with Pre => A.Len = M.Len and B.Len = M.Len
               and M.Len > 0,
        Post => Result.Len = M.Len;

   --  Convert to Montgomery domain: A * R mod M
   procedure To_Monty
     (A   : in out Big_Nat;
      M   : in     Big_Nat;
      M0I : in     Word)
   with Pre  => A.Len = M.Len and M.Len > 0,
        Post => A.Len = M.Len;

   --  Modular exponentiation: Result = Base^Exp mod M (via Montgomery)
   procedure Modpow
     (Result : out Big_Nat;
      Base   : in  Big_Nat;
      Exp    : in  Byte_Seq;
      M      : in  Big_Nat;
      M0I    : in  Word)
   with Pre  => Base.Len = M.Len and M.Len > 0
               and Exp'First = 0 and Exp'Length > 0
               and Exp'Last < N32'Last / 8,
        Post => Result.Len = M.Len;

   --  Compute -M^(-1) mod 2^32 from M.W(0)
   function Ninv32 (M0 : Word) return Word;

end SPARKTLS.BigNat;
