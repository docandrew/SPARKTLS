with Ada.Text_IO; use Ada.Text_IO;
with Ada.Assertions; use Ada.Assertions;

with SPARKNaCl; use SPARKNaCl;
with SPARKTLS; use SPARKTLS;
with SPARKTLS.Extensions; use SPARKTLS.Extensions;

package body Test_SPARKTLS_Extensions is

   procedure Test_To_TLVE is
      E : Extension_Type := Server_Name;
      Msg : Byte_Seq := (1, 2, 3);
      Result : Byte_Seq := SPARKTLS.Extensions.TLVE(E, Msg);
   begin
      Result := SPARKTLS.Extensions.TLVE(E, Msg);
      Put_Line("Test_To_TLVE: " & Result(0)'Image & ", " & Result(1)'Image & ", " & Result(2)'Image & ", " & Result(3)'Image & ", " & Result(4)'Image & ", " & Result(5)'Image);
      pragma Assert(Result = (0, 0, 0, 1, 0, 3, 1, 2, 3));
   end Test_To_TLVE;

   procedure Test_Server_Name_Extension is
      Host : String := "abc.com";
      Result : Byte_Seq := SPARKTLS.Extensions.Server_Name_Extension(Host);
   begin
      Result := SPARKTLS.Extensions.Server_Name_Extension(Host);
      Put_Line("Test_Server_Name_Extension: " & Result(0)'Image & ", " & Result(1)'Image & ", " & Result(2)'Image & ", " & Result(3)'Image & ", " & Result(4)'Image & ", " & Result(5)'Image & ", " & Result(6)'Image & ", " & Result(7)'Image & ", " & Result(8)'Image & ", " & Result(9)'Image & ", " & Result(10)'Image & ", " & Result(11)'Image & ", " & Result(12)'Image & ", " & Result(13)'Image);
      pragma Assert(Result = (0, 0, 0, 14, 0, 9, 0, 7, 97, 98, 99, 3, 99, 111, 109, 0));
   end Test_Server_Name_Extension;

   procedure Test_Supported_Groups_Extension is
      Groups : Supported_Group_List := (X25519, secp256r1, ffdhe_2048);
      Result : Byte_Seq := SPARKTLS.Extensions.Supported_Groups_Extension(Groups);
   begin
      Put_Line("Test_Supported_Groups_Extension: " & Result(0)'Image & ", " & Result(1)'Image & ", " 
               & Result(2)'Image & ", " & Result(3)'Image & ", " & Result(4)'Image & ", " 
               & Result(5)'Image & ", " & Result(6)'Image & ", " & Result(7)'Image & ", " 
               & Result(8)'Image & ", " & Result(9)'Image & ", " & Result(10)'Image & ", " 
               & Result(11)'Image & ", " & Result(12)'Image & ", " & Result(13)'Image);
      pragma Assert(Result = (0, 0, 0, 10, 0, 8, 0, 6, 0, 3, 0, 23, 0, 28));
   end Test_Supported_Groups_Extension;

   procedure Test_Signature_Algorithms_Extension is
      Sigs : Supported_Signature_List := (rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512);
      Result : Byte_Seq := SPARKTLS.Extensions.Signature_Algorithms_Extension(Sigs);
   begin
      Put_Line("Test_Signature_Algorithms_Extension: " & Result(0)'Image & ", " & Result(1)'Image & ", " 
               & Result(2)'Image & ", " & Result(3)'Image & ", " & Result(4)'Image & ", " 
               & Result(5)'Image & ", " & Result(6)'Image & ", " & Result(7)'Image & ", " 
               & Result(8)'Image & ", " & Result(9)'Image & ", " & Result(10)'Image & ", " 
               & Result(11)'Image & ", " & Result(12)'Image & ", " & Result(13)'Image);
      pragma Assert(Result = (0, 0, 0, 13, 0, 9, 0, 6, 0, 8, 0, 7, 0, 8, 0, 6, 0, 3, 0, 4, 0, 3, 0, 2, 0, 1));
   end Test_Signature_Algorithms_Extension;

   procedure Run_Tests is
   begin
      Test_To_TLVE;
      Test_Server_Name_Extension;
      Test_Supported_Groups_Extension;
      Test_Signature_Algorithms_Extension;
   end Run_Tests;

end Test_SPARKTLS_Extensions;
