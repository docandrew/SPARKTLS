package body SPARKTLS.RBG.Testing is

   procedure Init_From
     (Source          : Test_Source;
      OK              : out Boolean;
      On_Failure      : Entropy_Failure_Fn := null;
      Reseed_Requests : Positive := Default_Reseed_Requests;
      Core_Requests   : Natural := 0;
      Start_Fails     : Boolean := False)
   is
   begin
      Init_With
        (Source          => Entropy_Source_Fn (Source),
         Start_OK        => not Start_Fails,
         OK              => OK,
         On_Failure      => On_Failure,
         Reseed_Requests => Reseed_Requests,
         Core_Requests   => Core_Requests);
   end Init_From;

end SPARKTLS.RBG.Testing;
