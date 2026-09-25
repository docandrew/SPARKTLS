with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with SPARKNaCl; use SPARKNaCl;
with SPARKTLS_Reassembly; use SPARKTLS_Reassembly;
with SPARKTLS; use SPARKTLS;
with SPARKTLS.Records;
with SPARKTLS.Test_Support;
procedure Test_Prepared_Write is
   package TS renames SPARKTLS.Test_Support;
   Total : Natural := 0;
   procedure Check (OK : Boolean; What : String) is
   begin
      if not OK then raise Program_Error with What; end if;
      Total := Total + 1;
   end Check;
   procedure Exercise (Role : TLS_Role; Suite : Supported_Suite) is
      S : Session (Role);
      Scratch : Byte_Seq (0 .. IO_Buffer_Capacity - 1);
      N : N32;
      procedure Write_And_Check (Len : N32) is
         Plain : Byte_Seq (0 .. Len - 1);
         Expected : IO_Buffer;
         Keys : Traffic_Keys := TS.Write_Keys (S);
         Pos : N32 := 0;
         Chunk, Written, Encoded : N32;
      begin
         for I in Plain'Range loop Plain (I) := Byte (I mod 251); end loop;
         while Pos < Len loop
            Chunk := N32'Min (16384, Len - Pos);
            exit when Free_Space (Expected) < Chunk + 22;
            Records.Build_Encrypted_Record
              (Plain (Pos .. Pos + Chunk - 1), 16#17#, Keys, Expected, Encoded);
            Check (Encoded = Chunk + 22, "reference record size");
            Pos := Pos + Chunk;
         end loop;
         Write_Plaintext (S, Plain, Written);
         Check (Written = Pos and Written > 0, "incorrect partial-write boundary");
         Check ((for all I in Plain'Range => Plain (I) = Byte (I mod 251)),
                "write changed caller plaintext");
         Drain_Ciphertext (S, Scratch, N);
         Check (N = Expected.Write_Pos, "wire length mismatch");
         Check (Scratch (0 .. N - 1) = Byte_Seq (Expected.Storage (1 .. RBT_A.Index (N))),
                "cached write differs from one-shot record");
         Check (TS.Write_Keys (S).Counter = Keys.Counter, "counter advanced incorrectly");
         Check (TS.Write_Cache_Erased (S) = (Suite = Suite_ChaCha20_Poly1305_SHA256),
                "unexpected cache state for suite");
      end Write_And_Check;
      procedure Rotate_And_Check is
         Expected : IO_Buffer;
         Keys : Traffic_Keys := TS.Write_Keys (S);
         Encoded : N32;
      begin
         Records.Build_Encrypted_Record
           (Byte_Seq'(24, 0, 0, 1, 0), 16#16#, Keys, Expected, Encoded);
         Request_Key_Update (S);
         Check (TS.Write_Cache_Erased (S), "key update retained stale cache");
         Check (TS.Write_Keys (S).Counter = 0, "rekey counter not reset");
         Check (TS.Write_Keys (S).Key /= Keys.Key, "key update left old key");
         Drain_Ciphertext (S, Scratch, N);
         Check (N = Encoded and then
                Scratch (0 .. N - 1) = Byte_Seq (Expected.Storage (1 .. RBT_A.Index (N))),
                "key update must be encrypted under old key");
         Write_And_Check (16384 + 37);
      end Rotate_And_Check;
   begin
      TS.Install_Test_Traffic (S, Suite);
      Check (TS.Write_Cache_Erased (S), "initial cache not empty");
      Write_And_Check (1);
      Write_And_Check (64);
      Write_And_Check (16384 + 37);
      Write_And_Check (3 * 16384 + 5);
      Rotate_And_Check;
      Rotate_And_Check;
      --  A full output buffer delays rotation, retaining the old key/cache.
      TS.Fill_Output (S);
      declare
         Keys : constant Traffic_Keys := TS.Write_Keys (S);
      begin
         Request_Key_Update (S);
         Check (TS.Write_Keys (S) = Keys, "failed rekey changed traffic keys");
         Check (TS.Write_Cache_Erased (S) = (Suite = Suite_ChaCha20_Poly1305_SHA256),
                "failed rekey changed cache state");
         Write_Plaintext (S, Byte_Seq'(1, 2, 3), N);
         Check (N = 0 and TS.Write_Keys (S) = Keys, "full output consumed input");
      end;
      Drain_Ciphertext (S, Scratch, N);
      Rotate_And_Check;
      --  Automatic usage-limit rotation must also invalidate the cache.
      if Role = Role_Client then
         TS.Set_Client_App_Counter (S, Unsigned_64 (Rekey_After_Records - Rekey_Margin));
      else
         TS.Set_Server_App_Counter (S, Unsigned_64 (Rekey_After_Records - Rekey_Margin));
      end if;
      Write_Plaintext (S, Byte_Seq'(1, 2, 3), N);
      Check (N = 3 and TS.Write_Keys (S).Counter = 1, "automatic rekey failed");
      Drain_Ciphertext (S, Scratch, N);
      Write_And_Check (65);
      Sanitize_Keys (S);
      Check (TS.Write_Cache_Erased (S), "sanitize retained derived key material");
      TS.Install_Test_Traffic (S, Suite);
      Write_And_Check (257);
      Drop (S);
      Check (TS.Write_Cache_Erased (S), "drop retained derived key material");
      TS.Reset (S);
      TS.Install_Test_Traffic (S, Suite);
      Write_And_Check (16384);
      Drop (S);
   end Exercise;
begin
   for Role in TLS_Role loop
      Exercise (Role, Suite_AES_128_GCM_SHA256);
      Exercise (Role, Suite_AES_256_GCM_SHA384);
      Exercise (Role, Suite_ChaCha20_Poly1305_SHA256);
   end loop;
   Put_Line ("PASS: prepared application writes and lifecycle checks:" & Total'Image);
end Test_Prepared_Write;
