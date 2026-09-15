--  Dudect-style statistical timing analysis helper. See body for
--  details.

package Dudect_Helpers is

   --  Run Subject_0 and Subject_1 N times each (interleaved, random
   --  order within each pair), capture rdtsc cycle counts, and report
   --  Welch's t-statistic on the timing distributions. If |t| exceeds
   --  Threshold the timing depends on which subject was called →
   --  side-channel.
   --
   --  Suited to slow subjects (tens of thousands of cycles and up).
   --  Two closures are two code addresses and usually two data
   --  addresses, and at n in the tens of thousands a ~1-cycle
   --  placement asymmetry between them is already a significant
   --  offset for a subject that costs only a few thousand cycles. Use
   --  the form below for those.
   procedure Time_Test
     (Name      : String;
      Subject_0 : not null access procedure;
      Subject_1 : not null access procedure;
      N         : Positive := 50_000;
      Threshold : Float := 4.5);

   --  Same test, dudect's own shape. Prepare (Second) writes the
   --  class's secret into a buffer the harness owns, untimed; Subject
   --  is then timed reading that buffer. The class reaches Prepare as
   --  a Boolean it must consume as DATA (mask-select between the two
   --  secrets, no branch on it), so both classes execute one
   --  instruction stream on one set of addresses, before and inside
   --  the timed region. The only thing that differs is the secret
   --  bytes, which is the property under test. Calibrated with a
   --  same-secret control on the AEAD harness: the two-closure form
   --  read |t| up to ~12 with identical keys, this form does not.
   procedure Time_Test
     (Name      : String;
      Prepare   : not null access procedure (Second : Boolean);
      Subject   : not null access procedure;
      N         : Positive := 50_000;
      Threshold : Float := 4.5);

end Dudect_Helpers;
