--  Quick ECDSA P-256 benchmark
with Ada.Text_IO;       use Ada.Text_IO;
with Ada.Real_Time;     use Ada.Real_Time;
with SPARKNaCl;         use SPARKNaCl;
with SPARKTLS.P256.ECDSA; use SPARKTLS.P256.ECDSA;

procedure ECDSA_Bench is
   Iterations : constant := 10;
   Start, Stop : Time;
   Elapsed : Duration;
   Result : Boolean;

   Hash : constant Bytes_32 :=
     (16#d1#, 16#b8#, 16#ef#, 16#21#, 16#eb#, 16#41#, 16#82#, 16#ee#,
      16#27#, 16#06#, 16#38#, 16#06#, 16#10#, 16#63#, 16#a3#, 16#f3#,
      16#c1#, 16#6c#, 16#11#, 16#4e#, 16#33#, 16#93#, 16#7f#, 16#69#,
      16#fb#, 16#23#, 16#2c#, 16#c8#, 16#33#, 16#96#, 16#5a#, 16#94#);
   Qx : constant ECDSA_Sig_Half :=
     (16#e4#, 16#24#, 16#dc#, 16#61#, 16#d4#, 16#bb#, 16#3c#, 16#b7#,
      16#ef#, 16#43#, 16#44#, 16#a7#, 16#f8#, 16#95#, 16#7a#, 16#0c#,
      16#51#, 16#34#, 16#e1#, 16#6f#, 16#7a#, 16#67#, 16#c0#, 16#74#,
      16#f8#, 16#2e#, 16#6e#, 16#12#, 16#f4#, 16#9a#, 16#bf#, 16#3c#);
   Qy : constant ECDSA_Sig_Half :=
     (16#97#, 16#0e#, 16#ed#, 16#7a#, 16#a2#, 16#bc#, 16#48#, 16#65#,
      16#15#, 16#45#, 16#94#, 16#9d#, 16#e1#, 16#dd#, 16#da#, 16#f0#,
      16#12#, 16#7e#, 16#59#, 16#65#, 16#ac#, 16#85#, 16#d1#, 16#24#,
      16#3d#, 16#6f#, 16#60#, 16#e7#, 16#df#, 16#ae#, 16#e9#, 16#27#);
   R : constant ECDSA_Sig_Half :=
     (16#bf#, 16#96#, 16#b9#, 16#9a#, 16#a4#, 16#9c#, 16#70#, 16#5c#,
      16#91#, 16#0b#, 16#e3#, 16#31#, 16#42#, 16#01#, 16#7c#, 16#64#,
      16#2f#, 16#f5#, 16#40#, 16#c7#, 16#63#, 16#49#, 16#b9#, 16#da#,
      16#b7#, 16#2f#, 16#98#, 16#1f#, 16#d9#, 16#34#, 16#7f#, 16#4f#);
   S : constant ECDSA_Sig_Half :=
     (16#17#, 16#c5#, 16#50#, 16#95#, 16#81#, 16#90#, 16#89#, 16#c2#,
      16#e0#, 16#3b#, 16#9c#, 16#d4#, 16#15#, 16#ab#, 16#df#, 16#12#,
      16#44#, 16#4e#, 16#32#, 16#30#, 16#75#, 16#d9#, 16#8f#, 16#31#,
      16#92#, 16#0b#, 16#9e#, 16#0f#, 16#57#, 16#ec#, 16#87#, 16#1c#);
begin
   Put_Line ("Benchmarking ECDSA P-256 Verify (" &
             Integer'Image (Iterations) & " iterations)...");

   Start := Clock;
   for I in 1 .. Iterations loop
      Result := Verify (Hash, Qx, Qy, R, S);
      if not Result then
         Put_Line ("ERROR: verification failed!");
         return;
      end if;
   end loop;
   Stop := Clock;

   Elapsed := To_Duration (Stop - Start);
   Put_Line ("Total: " & Duration'Image (Elapsed) & " s");
   Put_Line ("Per verify: " &
             Duration'Image (Elapsed / Iterations) & " s");
end ECDSA_Bench;
