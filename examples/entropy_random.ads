--  Bridge between SPARKEntropy (CSPRNG) and SPARKTLS Random_Bytes_Fn.
--
--  Call Init once at startup. Then pass Random'Access as the
--  Random_Bytes_Fn to SPARKTLS.Client.Configure or Server.Configure.

with SPARKNaCl;

package Entropy_Random is

   --  Initialize the jitter entropy collector.
   --  Must be called before Random. Aborts if the platform timer
   --  is unsuitable (no jitter).
   procedure Init;

   --  Random_Bytes_Fn-compatible callback.
   procedure Random (Output : out SPARKNaCl.Byte_Seq);

end Entropy_Random;
