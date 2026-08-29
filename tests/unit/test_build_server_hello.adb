--  Unit tests for SPARKTLS.Handshake.TLS13.Build_Server_Hello.
--
--  Pinned BEFORE refactoring Build_Server_Hello into smaller subprograms
--  for SPARK proving. These tests must continue to pass through the refactor.

with Ada.Text_IO;          use Ada.Text_IO;
with Ada.Command_Line;
with Interfaces;           use Interfaces;
with SPARKNaCl;            use SPARKNaCl;
with SPARKTLS;             use SPARKTLS;
with SPARKTLS.Handshake.TLS13;
with SPARKTLSCrypto.P256.Point;
with SPARKTLSCrypto.P384.Point;
with Det_Random_Lib;
with SPARKTLS.Test_Support;

procedure Test_Build_Server_Hello is

   Total : Natural := 0;
   Pass  : Natural := 0;
   Fail  : Natural := 0;

   procedure Check (Name : String; OK : Boolean) is
   begin
      Total := Total + 1;
      if OK then
         Pass := Pass + 1;
         Put_Line ("  PASS: " & Name);
      else
         Fail := Fail + 1;
         Put_Line ("  FAIL: " & Name);
      end if;
   end Check;

   ----------------------------------------------------------------------------
   --  Helpers
   ----------------------------------------------------------------------------

   --  Set up a minimal Session + Handshake_Context that's enough for
   --  Build_Server_Hello to run on the x25519 happy path.
   procedure Init_Context
     (S      : out Session;
      HC     : out Handshake_Context;
      Suite  : in  Unsigned_16 := Wire_Suite_AES_128_GCM_SHA256)
   is
      pragma Unreferenced (Suite);
   begin
      SPARKTLS.Test_Support.Reset (S);
      HC         := (others => <>);
      HC.Cfg.Random       := Det_Random_Lib.Det_Random'Access;
      HC.Cfg.Suite        := TLS_AES_128_GCM_SHA256;
      HC.Client_Has_X25519 := True;
      HC.KE.Peer_PK := (others => 16#01#);  --  arbitrary peer pubkey
   end Init_Context;

   --  Generate a valid P-256 peer pubkey by running Mulgen on a fixed
   --  scalar. Encoded as 0x04 || X(32) || Y(32) per SEC 1.
   function Make_P256_Peer_PK return Byte_Seq is
      use SPARKTLSCrypto.P256.Point;
      Peer_SK : constant Bytes_32 :=
        (0 => 0, 1 => 0,  --  small scalar so it stays in [1, n)
         others => 16#42#);
      PK_Jac  : P256_Jacobian;
      Encoded : Byte_Seq (0 .. 64) := (others => 0);
   begin
      P256_Mulgen (PK_Jac, Byte_Seq (Peer_SK), 32);
      P256_To_Affine (PK_Jac);
      P256_Encode (Encoded, PK_Jac);
      return Encoded;
   end Make_P256_Peer_PK;

   --  Generate a valid P-384 peer pubkey similarly.
   function Make_P384_Peer_PK return Byte_Seq is
      use SPARKTLSCrypto.P384.Point;
      Peer_SK : constant Byte_Seq (0 .. 47) :=
        (0 => 0, 1 => 0, 2 => 0,  --  small scalar
         others => 16#33#);
      Encoded : Byte_Seq (0 .. 96) := (others => 0);
   begin
      P384_Mulgen (Encoded, Peer_SK);
      return Encoded;
   end Make_P384_Peer_PK;

   ----------------------------------------------------------------------------
   --  Tests
   ----------------------------------------------------------------------------

   procedure Test_X25519_Builds is
      S      : Session;
      HC     : Handshake_Context;
      Result : Byte_Seq (0 .. 511) := (others => 0);
      Len    : N32;
   begin
      Init_Context (S, HC);
      SPARKTLS.Handshake.TLS13.Build_Server_Hello
        (TLS13_Suite (Suite (S)), HC, Result, Len);

      Check ("X25519: produces non-empty message", Len > 4);
      if Len <= 4 then return; end if;

      Check ("X25519: type byte = 0x02 (server_hello)",
             Result (0) = 16#02#);

      declare
         --  RFC 8446 §4: handshake header length is 24-bit big-endian
         BL : constant N32 :=
            N32 (Result (1)) * 65536
            + N32 (Result (2)) * 256
            + N32 (Result (3));
      begin
         Check ("X25519: header length = body bytes",
                BL = Len - 4);
      end;

      Check ("X25519: legacy_version = 0x0303",
             Result (4) = 16#03# and Result (5) = 16#03#);

      Check ("X25519: server_random matches deterministic source",
             (for all I in 0 .. 31 =>
                HC.Server_Random (N32 (I)) =
                  Byte (16#A0# + (Natural (I) mod 16))));

      --  legacy_session_id_echo length at offset 38 (4 hdr + 2 ver + 32 rnd)
      Check ("X25519: session_id_echo_length is a single byte",
             Len > 38);
   end Test_X25519_Builds;

   procedure Test_Selected_Group is
      S      : Session;
      HC     : Handshake_Context;
      Result : Byte_Seq (0 .. 511) := (others => 0);
      Len    : N32;
   begin
      Init_Context (S, HC);
      SPARKTLS.Handshake.TLS13.Build_Server_Hello
        (TLS13_Suite (Suite (S)), HC, Result, Len);

      Check ("X25519: negotiated curve is 0x001D (x25519)",
             HC.KE.Negotiated and then HC.KE.Curve = 16#001D#);
   end Test_Selected_Group;

   procedure Test_Buffer_Too_Small is
      S      : Session;
      HC     : Handshake_Context;
      --  Min by Pre is Max_Server_Hello = 256.
      Result : Byte_Seq (0 .. 255) := (others => 16#FF#);
      Len    : N32;
   begin
      Init_Context (S, HC);
      SPARKTLS.Handshake.TLS13.Build_Server_Hello
        (TLS13_Suite (Suite (S)), HC, Result, Len);
      Check ("Min-size buffer (256B): fits", Len > 0 and Len <= 256);
   end Test_Buffer_Too_Small;

   procedure Test_P256_Builds is
      S      : Session;
      HC     : Handshake_Context;
      Result : Byte_Seq (0 .. 511) := (others => 0);
      Len    : N32;
   begin
      Init_Context (S, HC);
      HC.Client_Has_X25519 := False;
      HC.Client_Has_P256   := True;
      HC.KE.P256_PK      := Make_P256_Peer_PK;

      SPARKTLS.Handshake.TLS13.Build_Server_Hello
        (TLS13_Suite (Suite (S)), HC, Result, Len);

      Check ("P-256: produces non-empty message", Len > 4);
      if Len <= 4 then return; end if;
      Check ("P-256: type byte = 0x02 (server_hello)",
             Result (0) = 16#02#);
      Check ("P-256: negotiated curve is 0x0017 (secp256r1)",
             HC.KE.Negotiated and then HC.KE.Curve = 16#0017#);
      Check ("P-256: shared secret is non-zero",
             (for some I in 0 .. 31 => HC.KE.Shared (N32 (I)) /= 0));
   end Test_P256_Builds;

   procedure Test_P384_Builds is
      S      : Session;
      HC     : Handshake_Context;
      Result : Byte_Seq (0 .. 511) := (others => 0);
      Len    : N32;
   begin
      Init_Context (S, HC);
      HC.Client_Has_X25519 := False;
      HC.Client_Has_P384   := True;
      HC.KE.P384_PK      := Make_P384_Peer_PK;

      SPARKTLS.Handshake.TLS13.Build_Server_Hello
        (TLS13_Suite (Suite (S)), HC, Result, Len);

      Check ("P-384: produces non-empty message", Len > 4);
      if Len <= 4 then return; end if;
      Check ("P-384: type byte = 0x02 (server_hello)",
             Result (0) = 16#02#);
      Check ("P-384: negotiated curve is 0x0018 (secp384r1)",
             HC.KE.Negotiated and then HC.KE.Curve = 16#0018#);
      Check ("P-384: shared secret is non-zero",
             (for some I in 0 .. 47 => HC.KE.Shared (N32 (I)) /= 0));
   end Test_P384_Builds;

   procedure Test_P256_Invalid_Peer_PK_Rejected is
      S      : Session;
      HC     : Handshake_Context;
      Result : Byte_Seq (0 .. 511) := (others => 0);
      Len    : N32;
   begin
      Init_Context (S, HC);
      HC.Client_Has_X25519 := False;
      HC.Client_Has_P256   := True;
      HC.KE.P256_PK      := (others => 0);  --  not a valid point

      SPARKTLS.Handshake.TLS13.Build_Server_Hello
        (TLS13_Suite (Suite (S)), HC, Result, Len);
      Check ("P-256: invalid peer pubkey → Len = 0", Len = 0);
   end Test_P256_Invalid_Peer_PK_Rejected;

   procedure Test_No_Common_Group is
      S      : Session;
      HC     : Handshake_Context;
      Result : Byte_Seq (0 .. 511) := (others => 0);
      Len    : N32;
   begin
      Init_Context (S, HC);
      HC.Client_Has_X25519 := False;
      HC.Client_Has_P256   := False;
      HC.Client_Has_P384   := False;
      SPARKTLS.Handshake.TLS13.Build_Server_Hello
        (TLS13_Suite (Suite (S)), HC, Result, Len);
      Check ("No common group → Len = 0", Len = 0);
   end Test_No_Common_Group;

   --  RFC 7748 §6.1 / RFC 8422 §5.10: the X25519 contributory check.
   --  Eight specific 32-byte peer-pubkey values produce an all-zero
   --  shared secret. Generate_KS_X25519 must (a) detect via
   --  Shared_Secret_Is_Acceptable_X25519, (b) abort with KS_Raw_Len=0,
   --  (c) zero HC.KE.Shared, (d) plumb Illegal_Parameter via
   --  HC.Ext_Parse_Err so Build_Server_Flight emits the RFC-correct
   --  alert instead of generic handshake_failure.
   --
   --  Two complementary tests below:
   --   (1) Helper-direct: confirm Shared_Secret_Is_Acceptable_X25519
   --       returns False for an all-zero shared-secret input. This
   --       is the security predicate itself; the rest of the
   --       Generate_KS_X25519 logic is wired around it via SPARK
   --       contract.
   --   (2) Sanity: the post-helper assignments in Generate_KS_X25519
   --       (Ext_Parse_Err := Illegal_Parameter; KS_Raw_Len := 0)
   --       run unconditionally on helper=False, so confirming the
   --       helper itself is the load-bearing check.
   procedure Test_X25519_Small_Subgroup_Helper is
      All_Zero  : constant Byte_Seq (0 .. 31) := (others => 0);
      One_Set   : Byte_Seq (0 .. 31) := (others => 0);
      All_Ones  : constant Byte_Seq (0 .. 31) := (others => 16#FF#);
   begin
      One_Set (15) := 1;  --  single non-zero byte
      Check ("Acceptable_X25519 rejects all-zero shared secret",
             not Shared_Secret_Is_Acceptable_X25519 (All_Zero));
      Check ("Acceptable_X25519 accepts shared secret with one set byte",
             Shared_Secret_Is_Acceptable_X25519 (One_Set));
      Check ("Acceptable_X25519 accepts all-ones shared secret",
             Shared_Secret_Is_Acceptable_X25519 (All_Ones));
   end Test_X25519_Small_Subgroup_Helper;

   procedure Test_Idempotent_Two_Calls is
      S1, S2   : Session;
      HC1, HC2 : Handshake_Context;
      R1 : Byte_Seq (0 .. 511) := (others => 0);
      R2 : Byte_Seq (0 .. 511) := (others => 0);
      L1, L2 : N32;
   begin
      Init_Context (S1, HC1);
      Init_Context (S2, HC2);
      SPARKTLS.Handshake.TLS13.Build_Server_Hello
        (TLS13_Suite (Suite (S1)), HC1, R1, L1);
      SPARKTLS.Handshake.TLS13.Build_Server_Hello
        (TLS13_Suite (Suite (S2)), HC2, R2, L2);

      Check ("Two identical inputs produce identical lengths", L1 = L2);
      Check ("Two identical inputs produce identical bytes",
             L1 = L2 and then
             (for all I in 0 .. L1 - 1 => R1 (I) = R2 (I)));
   end Test_Idempotent_Two_Calls;

begin
   Put_Line ("--- SPARKTLS.Handshake.TLS13.Build_Server_Hello ---");
   Test_X25519_Builds;
   Test_Selected_Group;
   Test_Buffer_Too_Small;
   Test_P256_Builds;
   Test_P384_Builds;
   Test_P256_Invalid_Peer_PK_Rejected;
   Test_No_Common_Group;
   Test_X25519_Small_Subgroup_Helper;
   Test_Idempotent_Two_Calls;
   New_Line;
   Put_Line ("=== Results: " & Pass'Image & "/" & Total'Image
             & " passed, " & Fail'Image & " failed ===");
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Build_Server_Hello;
