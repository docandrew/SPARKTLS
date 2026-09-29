procedure SPARKTLS.Initialize
  (OK              : out Boolean;
   Mode            : FIPS_Mode := FIPS;
   On_Failure      : SPARKTLS.RBG.Entropy_Failure_Fn := null;
   OSR             : SPARKEntropy.OSR_Range := SPARKEntropy.Min_OSR;
   Reseed_Requests : Positive := SPARKTLS.RBG.Default_Reseed_Requests)
  with SPARK_Mode => On
is
begin
   SPARKTLS.RBG.Init (OK, On_Failure, OSR, Reseed_Requests, Mode);
end SPARKTLS.Initialize;
