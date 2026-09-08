--  Dudect-style statistical timing analysis helper. See body for
--  details.

package Dudect_Helpers is

   --  Run Subject_0 and Subject_1 N times each (interleaved),
   --  capture rdtsc cycle counts, and report Welch's t-statistic
   --  on the timing distributions. If |t| exceeds Threshold the
   --  timing depends on which subject was called → side-channel.
   procedure Time_Test
     (Name      : String;
      Subject_0 : not null access procedure;
      Subject_1 : not null access procedure;
      N         : Positive := 50_000;
      Threshold : Float := 4.5);

end Dudect_Helpers;
