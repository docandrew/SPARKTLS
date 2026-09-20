--  Read a PIN without echo (termios via libc), or from stdin when the
--  caller passes --pin-stdin (pipes, tests). Example code.
package PIN_Prompt is
   --  Prompt on the terminal with echo off. Returns the PIN without the
   --  trailing newline; empty on EOF or error.
   function Read_Hidden (Prompt : String) return String;
   --  Read one line from standard input, no prompt, no echo control.
   function Read_Stdin return String;
end PIN_Prompt;
