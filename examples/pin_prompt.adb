with Ada.Text_IO;
with Interfaces.C; use Interfaces.C;

package body PIN_Prompt is

   --  struct termios on Linux x86_64: 4 x tcflag_t (unsigned int),
   --  c_line (unsigned char), c_cc[32], then two speed_t (unsigned int).
   type CC_Array is array (0 .. 31) of unsigned_char with Convention => C;
   type Termios is record
      C_Iflag, C_Oflag, C_Cflag, C_Lflag : unsigned;
      C_Line  : unsigned_char;
      C_CC    : CC_Array;
      C_Ispeed, C_Ospeed : unsigned;
   end record with Convention => C;

   ECHO   : constant unsigned := 8;      --  termios.h ECHO
   TCSANOW : constant int := 0;
   STDIN  : constant int := 0;

   function Tcgetattr (FD : int; T : access Termios) return int
   with Import, Convention => C, External_Name => "tcgetattr";
   function Tcsetattr (FD : int; Actions : int; T : access constant Termios) return int
   with Import, Convention => C, External_Name => "tcsetattr";

   function Read_Stdin return String is
   begin
      return Ada.Text_IO.Get_Line;
   exception
      when others => return "";
   end Read_Stdin;

   function Read_Hidden (Prompt : String) return String is
      Saved, Quiet : aliased Termios;
      Have_TTY : Boolean;
      Dummy    : int;
      pragma Unreferenced (Dummy);
   begin
      Ada.Text_IO.Put (Prompt);
      Have_TTY := Tcgetattr (STDIN, Saved'Access) = 0;
      if Have_TTY then
         Quiet := Saved;
         Quiet.C_Lflag := Quiet.C_Lflag and not ECHO;
         Dummy := Tcsetattr (STDIN, TCSANOW, Quiet'Access);
      end if;
      declare
         PIN : constant String := Read_Stdin;
      begin
         if Have_TTY then
            Dummy := Tcsetattr (STDIN, TCSANOW, Saved'Access);
            Ada.Text_IO.New_Line;   --  the user's Enter was not echoed
         end if;
         return PIN;
      end;
   end Read_Hidden;

end PIN_Prompt;
