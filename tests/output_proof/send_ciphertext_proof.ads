with Interfaces; use Interfaces;
with SPARKTLS; use SPARKTLS;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLS.Send_Ciphertext;
package Send_Ciphertext_Proof with SPARK_Mode => On is
   --  Unconstrained environment choice: prove every accepted prefix.
   Limit : N32 := 0;
   procedure Send (Data : RBT_A.Bytes; Sent : out N32)
   with Global => (Input => Limit),
        Pre => Data'Length > 0 and Data'Length <= Buffer_Size'Last,
        Post => Sent <= N32 (Data'Length);
   procedure Flush is new SPARKTLS.Send_Ciphertext (Send);
end Send_Ciphertext_Proof;
