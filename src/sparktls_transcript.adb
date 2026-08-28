package body SPARKTLS_Transcript with
   SPARK_Mode => On
is
   package H256 renames SPARKTLSCrypto.Hashing.SHA256;
   package H384 renames SPARKTLSCrypto.Hashing.SHA384;
   package H512 renames SPARKTLSCrypto.Hashing.SHA512;

   procedure Start (TS : out Transcript_State) is
      C2 : H256.Context;
      C3 : H384.Context;
      C5 : H512.Context;
   begin
      H256.Init (C2);
      H384.Init (C3);
      H512.Init (C5);
      TS := (C256 => C2, C384 => C3, C512 => C5,
             Choice => Both, Has_Data => False);
   end Start;

   procedure Append (TS : in out Transcript_State; Data : Byte_Seq) is
   begin
      if Data'Length = 0 then
         return;
      end if;
      if TS.Choice in Both | Only_256 then
         H256.Update (TS.C256, Data);
      end if;
      if TS.Choice in Both | Only_384 then
         H384.Update (TS.C384, Data);
      end if;
      H512.Update (TS.C512, Data);
      TS.Has_Data := True;
   end Append;

   procedure Select_Hash (TS : in out Transcript_State; C : Hash_Choice) is
   begin
      TS.Choice := C;
   end Select_Hash;

   procedure Current_256
     (TS : in Transcript_State;
      H  : out H256.Digest)
   is
      Clone : H256.Context := TS.C256;
   begin
      H256.Final (Clone, H);
   end Current_256;

   procedure Current_384
     (TS : in Transcript_State;
      H  : out H384.Digest)
   is
      Clone : H384.Context := TS.C384;
   begin
      H384.Final (Clone, H);
   end Current_384;

   procedure Suffix_256
     (TS     : in Transcript_State;
      Suffix : in Byte_Seq;
      H      : out H256.Digest)
   is
      Clone : H256.Context := TS.C256;
   begin
      H256.Update (Clone, Suffix);
      H256.Final (Clone, H);
   end Suffix_256;

   procedure Suffix_384
     (TS     : in Transcript_State;
      Suffix : in Byte_Seq;
      H      : out H384.Digest)
   is
      Clone : H384.Context := TS.C384;
   begin
      H384.Update (Clone, Suffix);
      H384.Final (Clone, H);
   end Suffix_384;

   procedure Current_512
     (TS : in Transcript_State;
      H  : out H512.Digest)
   is
      Clone : H512.Context := TS.C512;
   begin
      H512.Final (Clone, H);
   end Current_512;

   procedure Reset_For_HRR (TS : in out Transcript_State) is
      --  RFC 8446 Section 4.4.1 message_hash header: a synthetic
      --  handshake message of type message_hash (254) whose body is
      --  the hash of ClientHello1 under the negotiated digest.
      Hdr : Byte_Seq (0 .. 3) := (254, 0, 0, 0);
   begin
      case TS.Choice is
         when Only_256 =>
            declare
               D : H256.Digest;
            begin
               Current_256 (TS, D);
               H256.Init (TS.C256);
               Hdr (3) := 32;
               H256.Update (TS.C256, Hdr);
               H256.Update (TS.C256, Byte_Seq (D));
            end;
         when Only_384 =>
            declare
               D : H384.Digest;
            begin
               Current_384 (TS, D);
               H384.Init (TS.C384);
               Hdr (3) := 48;
               H384.Update (TS.C384, Hdr);
               H384.Update (TS.C384, Byte_Seq (D));
            end;
         when Both =>
            --  HRR always names the suite; reaching here without a
            --  selection is a state-machine defect. Replace BOTH so the
            --  transcript is at least self-consistent rather than
            --  silently stale (fail-safe, not fail-open: the peer's
            --  Finished cannot match either way).
            declare
               D2 : H256.Digest;
               D3 : H384.Digest;
            begin
               Current_256 (TS, D2);
               Current_384 (TS, D3);
               H256.Init (TS.C256);
               H384.Init (TS.C384);
               Hdr (3) := 32;
               H256.Update (TS.C256, Hdr);
               H256.Update (TS.C256, Byte_Seq (D2));
               Hdr (3) := 48;
               H384.Update (TS.C384, Hdr);
               H384.Update (TS.C384, Byte_Seq (D3));
            end;
      end case;
   end Reset_For_HRR;

   function Fresh return Transcript_State is
      TS : Transcript_State;
   begin
      Start (TS);
      return TS;
   end Fresh;

   procedure Wipe (TS : in out Transcript_State) is
   begin
      H256.Init (TS.C256);
      H384.Init (TS.C384);
      H512.Init (TS.C512);
      TS.Choice := Both;
   end Wipe;

end SPARKTLS_Transcript;
