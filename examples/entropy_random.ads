--  The examples' start-up for SPARKTLS.RBG, the library's generator
--  (SPARKEntropy behind an HMAC_DRBG, both inside the library). No
--  operating-system randomness is used anywhere.
--
--  Failure policy, the application's part: when the entropy source fails
--  persistently the generator latches off; On_Failure logs it, and the
--  servers watch SPARKTLS.RBG.Status and stop accepting connections.
--  Every handshake in between fails closed with Entropy_Failure.
with SPARKNaCl;

package Entropy_Random is

   --  Start SPARKTLS.RBG. Call once, before the first handshake. Failures
   --  are always reported on standard error; Verbose adds a start-up line
   --  on success (quiet by default: the BoGo shim must keep its output
   --  streams clean).
   procedure Init (Verbose : Boolean := False);

   --  Draw from SPARKTLS.RBG, starting it quietly if Init was not called
   --  (for helpers such as the example software signer).
   procedure Random (Output : out SPARKNaCl.Byte_Seq);

end Entropy_Random;
