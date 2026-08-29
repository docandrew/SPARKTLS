with Interfaces;                    use Interfaces;
with SPARKTLSCrypto.Hashing.SHA256; use SPARKTLSCrypto.Hashing.SHA256;
with SPARKTLSCrypto.MAC;            use SPARKTLSCrypto.MAC;
with SPARKTLSCrypto.HMAC384;
use SPARKTLSCrypto;

package body SPARKTLS.Key_Schedule_12
  with SPARK_Mode => On
is
   --  RFC 5246 Â§5: P_hash iteration.
   --
   --  P_hash(secret, seed) = HMAC(secret, A(1) || seed) ||
   --                         HMAC(secret, A(2) || seed) || ...
   --  where A(0) = seed, A(i) = HMAC(secret, A(i-1))
   --
   --  The label is prepended to the seed: actual_seed = label_bytes || seed.
   --  We concatenate label + seed into a single buffer before iterating.

   procedure Prove_Client_Finished_Label is
   begin
      pragma Assert (Label_Client_Finished = Label_Client_Finished);
   end Prove_Client_Finished_Label;

   procedure Prove_Server_Finished_Label is
   begin
      pragma Assert (Label_Server_Finished = Label_Server_Finished);
   end Prove_Server_Finished_Label;

   procedure PRF_SHA256
     (Output : out Byte_Seq; Secret : in Byte_Seq; Label : in String; Seed : in Byte_Seq)
   is
      --  SHA-256 digest = 32 bytes
      Hash_Size : constant := 32;

      --  Combine label + seed into one buffer.
      --  Max: label(64) + seed(128) = 192 bytes.
      Combined_Len : constant N32 := N32 (Label'Length) + N32 (Seed'Length);
      Combined     : Byte_Seq (0 .. Combined_Len - 1) := (others => 0);

      --  A(i): iterative HMAC chain, always 32 bytes
      A_Val : Digest;

      --  P(i) = HMAC(secret, A(i) || combined), 32 bytes each
      P_Input : Byte_Seq (0 .. Hash_Size - 1 + Combined_Len) := (others => 0);
      P_Val   : Digest;

      Pos    : N32;
      Remain : N32;
   begin
      Output := (others => 0);

      --  Build combined = label_bytes || seed
      for I in Label'Range loop
         Combined (N32 (I - Label'First)) := Byte (Character'Pos (Label (I)));
      end loop;
      Combined (N32 (Label'Length) .. Combined_Len - 1) := Seed;

      --  A(0) = combined (i.e., label || seed)
      --  A(1) = HMAC(secret, A(0))
      HMAC_SHA_256 (A_Val, Combined, Secret);

      --  Iterate: generate 32 bytes per round
      Pos := 0;
      while Pos < N32 (Output'Length) loop
         pragma Loop_Invariant (Pos <= N32 (Output'Length));

         --  P(i) = HMAC(secret, A(i) || combined)
         P_Input (0 .. Hash_Size - 1) := Byte_Seq (A_Val);
         P_Input (Hash_Size .. Hash_Size + Combined_Len - 1) := Combined;
         HMAC_SHA_256 (P_Val, P_Input (0 .. Hash_Size - 1 + Combined_Len), Secret);

         --  Copy to output (may be partial on last round)
         Remain := N32 (Output'Length) - Pos;
         if Remain >= Hash_Size then
            Output (Pos .. Pos + Hash_Size - 1) := Byte_Seq (P_Val);
            Pos := Pos + Hash_Size;
         else
            Output (Pos .. Pos + Remain - 1) := Byte_Seq (P_Val) (0 .. Remain - 1);
            Pos := Pos + Remain;
         end if;

         --  A(i+1) = HMAC(secret, A(i)) â temp avoids out/in aliasing
         declare
            A_In : constant SPARKTLSCrypto.Hashing.SHA256.Digest := A_Val;
         begin
            HMAC_SHA_256 (A_Val, Byte_Seq (A_In), Secret);
         end;
      end loop;
   end PRF_SHA256;

   procedure PRF_SHA384
     (Output : out Byte_Seq; Secret : in Byte_Seq; Label : in String; Seed : in Byte_Seq)
   is
      Hash_Size : constant := 48;

      Combined_Len : constant N32 := N32 (Label'Length) + N32 (Seed'Length);
      Combined     : Byte_Seq (0 .. Combined_Len - 1) := (others => 0);

      A_Val : HMAC384.Digest_384;

      P_Input : Byte_Seq (0 .. Hash_Size - 1 + Combined_Len) := (others => 0);
      P_Val   : HMAC384.Digest_384;

      Pos    : N32;
      Remain : N32;
   begin
      Output := (others => 0);

      for I in Label'Range loop
         Combined (N32 (I - Label'First)) := Byte (Character'Pos (Label (I)));
      end loop;
      Combined (N32 (Label'Length) .. Combined_Len - 1) := Seed;

      HMAC384.HMAC_SHA_384 (A_Val, Combined, Secret);

      Pos := 0;
      while Pos < N32 (Output'Length) loop
         pragma Loop_Invariant (Pos <= N32 (Output'Length));

         P_Input (0 .. Hash_Size - 1) := Byte_Seq (A_Val);
         P_Input (Hash_Size .. Hash_Size + Combined_Len - 1) := Combined;
         HMAC384.HMAC_SHA_384 (P_Val, P_Input (0 .. Hash_Size - 1 + Combined_Len), Secret);

         Remain := N32 (Output'Length) - Pos;
         if Remain >= Hash_Size then
            Output (Pos .. Pos + Hash_Size - 1) := Byte_Seq (P_Val);
            Pos := Pos + Hash_Size;
         else
            Output (Pos .. Pos + Remain - 1) := Byte_Seq (P_Val) (0 .. Remain - 1);
            Pos := Pos + Remain;
         end if;

         declare
            A_In : constant HMAC384.Digest_384 := A_Val;
         begin
            HMAC384.HMAC_SHA_384 (A_Val, Byte_Seq (A_In), Secret);
         end;
      end loop;
   end PRF_SHA384;

   procedure Derive_Master_Secret_12
     (Master        : out Bytes_48;
      Pre_Master    : in Byte_Seq;
      Client_Random : in Bytes_32;
      Server_Random : in Bytes_32;
      Use_SHA384    : in Boolean)
   is
      --  RFC 5246 Â§8.1: seed = client_random || server_random
      Seed : Seed_64 := (others => 0);
   begin
      Seed (0 .. 31) := Client_Random;
      Seed (32 .. 63) := Server_Random;

      if Use_SHA384 then
         PRF_SHA384 (Byte_Seq (Master), Pre_Master, Label_Master_Secret, Byte_Seq (Seed));
      else
         PRF_SHA256 (Byte_Seq (Master), Pre_Master, Label_Master_Secret, Byte_Seq (Seed));
      end if;
   end Derive_Master_Secret_12;

   procedure Expand_Keys_12
     (Client_Key    : out Byte_Seq;
      Server_Key    : out Byte_Seq;
      Client_IV     : out Byte_Seq;
      Server_IV     : out Byte_Seq;
      Master        : in Bytes_48;
      Server_Random : in Bytes_32;
      Client_Random : in Bytes_32;
      Key_Len       : in N32;
      IV_Len        : in N32;
      Use_SHA384    : in Boolean)
   is
      --  RFC 5246 Â§6.3: seed = server_random || client_random
      --  (OPPOSITE order from master secret derivation!)
      Seed      : Seed_64 := (others => 0);
      Block_Len : constant N32 := 2 * Key_Len + 2 * IV_Len;
      Key_Block : Byte_Seq (0 .. Block_Len - 1);
      Pos       : N32 := 0;
   begin
      Seed (0 .. 31) := Server_Random;
      Seed (32 .. 63) := Client_Random;

      Client_IV := (others => 0);
      Server_IV := (others => 0);

      if Use_SHA384 then
         PRF_SHA384 (Key_Block, Byte_Seq (Master), Label_Key_Expansion, Byte_Seq (Seed));
      else
         PRF_SHA256 (Key_Block, Byte_Seq (Master), Label_Key_Expansion, Byte_Seq (Seed));
      end if;

      --  Partition key_block (RFC 5246 Â§6.3 + RFC 5288 Â§3 / RFC 7905 Â§2):
      --    client_write_key [Key_Len]
      --    server_write_key [Key_Len]
      --    client_write_IV  [IV_Len]   â 4 (AES-GCM) or 12 (ChaCha20)
      --    server_write_IV  [IV_Len]
      --  The out IVs are always 12 bytes; bytes [IV_Len..11] stay zero.
      Client_Key := Key_Block (Pos .. Pos + Key_Len - 1);
      Pos := Pos + Key_Len;
      Server_Key := Key_Block (Pos .. Pos + Key_Len - 1);
      Pos := Pos + Key_Len;
      Client_IV (0 .. IV_Len - 1) := Key_Block (Pos .. Pos + IV_Len - 1);
      Pos := Pos + IV_Len;
      Server_IV (0 .. IV_Len - 1) := Key_Block (Pos .. Pos + IV_Len - 1);
   end Expand_Keys_12;

   procedure Compute_Finished_12
     (Verify     : out Verify_Data_12;
      Master     : in Bytes_48;
      Label      : in String;
      TH         : in Byte_Seq;
      Use_SHA384 : in Boolean) is
   begin
      --  RFC 5246 Â§7.4.9:
      --  verify_data = PRF(master_secret, finished_label,
      --                    Hash(handshake_messages))[0..11]
      if Use_SHA384 then
         PRF_SHA384 (Byte_Seq (Verify), Byte_Seq (Master), Label, TH);
      else
         PRF_SHA256 (Byte_Seq (Verify), Byte_Seq (Master), Label, TH);
      end if;
   end Compute_Finished_12;

   procedure Export_Keying_Material_12
     (Output        : out Byte_Seq;
      Master        : in Bytes_48;
      Client_Random : in Bytes_32;
      Server_Random : in Bytes_32;
      Label         : in String;
      Context       : in Byte_Seq;
      Use_Context   : in Boolean;
      Use_SHA384    : in Boolean)
   is
      Seed_No_Context : Byte_Seq (0 .. 63) := (others => 0);
   begin
      Seed_No_Context (0 .. 31) := Byte_Seq (Client_Random);
      Seed_No_Context (32 .. 63) := Byte_Seq (Server_Random);

      if Use_Context then
         declare
            Seed : Byte_Seq (0 .. 65 + N32 (Context'Length)) := (others => 0);
         begin
            Seed (0 .. 63) := Seed_No_Context;
            Seed (64) := Byte (Context'Length / 256);
            Seed (65) := Byte (Context'Length mod 256);
            if Context'Length > 0 then
               Seed (66 .. Seed'Last) := Context;
            end if;

            if Use_SHA384 then
               PRF_SHA384 (Output, Byte_Seq (Master), Label, Seed);
            else
               PRF_SHA256 (Output, Byte_Seq (Master), Label, Seed);
            end if;
         end;
      else
         if Use_SHA384 then
            PRF_SHA384 (Output, Byte_Seq (Master), Label, Seed_No_Context);
         else
            PRF_SHA256 (Output, Byte_Seq (Master), Label, Seed_No_Context);
         end if;
      end if;
   end Export_Keying_Material_12;

end SPARKTLS.Key_Schedule_12;
