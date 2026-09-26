--  Send one contiguous span without a staging copy. The callback may accept
--  any prefix, including zero bytes for backpressure. It must not retain the
--  span or access/mutate S through another alias while the call is active.
--  The span uses the session's native byte type and may start above index 1.
--  A callback reporting more bytes than offered moves S to Error_State
--  (Internal_Error) and consumes nothing.
--  Use Drain_Ciphertext when ownership of a copied buffer is needed instead.
generic
   with procedure Send (Data : in RBT_A.Bytes; Sent : out N32)
     with Pre => Data'Length > 0 and Data'Length <= Buffer_Size'Last,
          Post => Sent <= N32 (Data'Length);
procedure SPARKTLS.Send_Ciphertext (S : in out Session; Bytes_Sent : out N32)
with
  SPARK_Mode => On,
  Post => Bytes_Sent <= Output_Pending (S)'Old
    and Output_Pending (S) = Output_Pending (S)'Old - Bytes_Sent
    and State (S) = State (S)'Old;
