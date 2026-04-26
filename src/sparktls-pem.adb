with SPARKTLSCrypto.Base64;
use SPARKTLSCrypto;

package body SPARKTLS.PEM with
   SPARK_Mode => On
is
   Begin_Marker : constant String := "-----BEGIN ";
   End_Marker   : constant String := "-----END ";
   Dashes       : constant String := "-----";

   --  Classify a label string into a known PEM_Label
   function Classify_Label (S : String) return PEM_Label is
   begin
      if S = "CERTIFICATE" then
         return Label_Certificate;
      elsif S = "PRIVATE KEY" then
         return Label_Private_Key;
      elsif S = "PUBLIC KEY" then
         return Label_Public_Key;
      else
         return Label_Unknown;
      end if;
   end Classify_Label;

   procedure Decode (Input : String; Result : out Decode_Result) is
      --  Maximum SPARKTLSCrypto.Base64 content: (Max_Cert_DER * 4) / 3 + 4
      Max_B64 : constant := (Max_Cert_DER * 4) / 3 + 4;

      B64_Buf : String (1 .. Max_B64) := (others => 'A');
      B64_Len : Natural := 0;

      Pos         : Positive;
      Label_Start : Positive;
      Label_End   : Natural;
      Body_Start  : Positive;
   begin
      Result := (others => <>);

      if Input'Length < Begin_Marker'Length + Dashes'Length then
         return;
      end if;

      Pos := Input'First;

      --  Scan for "-----BEGIN "
      Find_Begin : loop
         exit Find_Begin when Pos + Begin_Marker'Length - 1 > Input'Last;

         if Input (Pos .. Pos + Begin_Marker'Length - 1) = Begin_Marker then
            Label_Start := Pos + Begin_Marker'Length;
            Label_End := Label_Start;

            --  Find closing dashes of the header line
            Find_Label_End : loop
               exit Find_Label_End when
                  Label_End + Dashes'Length - 1 > Input'Last;

               if Input (Label_End .. Label_End + Dashes'Length - 1) =
                  Dashes
               then
                  --  Extract label
                  declare
                     Len : constant Natural := Label_End - Label_Start;
                  begin
                     if Len > 0 and Len <= Max_Label_Length then
                        Result.Label_Raw (1 .. Len) :=
                           Input (Label_Start .. Label_End - 1);
                        Result.Label_Len := Len;
                        Result.Label := Classify_Label
                           (Input (Label_Start .. Label_End - 1));
                     end if;
                  end;

                  --  Body starts after closing dashes + newline
                  Body_Start := Label_End + Dashes'Length;
                  while Body_Start <= Input'Last and then
                        (Input (Body_Start) = ASCII.LF or
                         Input (Body_Start) = ASCII.CR)
                  loop
                     Body_Start := Body_Start + 1;
                  end loop;

                  --  Collect SPARKTLSCrypto.Base64 characters until "-----END"
                  Pos := Body_Start;
                  Collect : loop
                     exit Collect when Pos > Input'Last;
                     if Pos + End_Marker'Length - 1 <= Input'Last
                        and then Input (Pos .. Pos + End_Marker'Length - 1) =
                                 End_Marker
                     then
                        exit Collect;
                     end if;

                     if Input (Pos) = ASCII.LF or
                        Input (Pos) = ASCII.CR or
                        Input (Pos) = ' ' or
                        Input (Pos) = ASCII.HT
                     then
                        Pos := Pos + 1;
                     else
                        if B64_Len < Max_B64 then
                           B64_Len := B64_Len + 1;
                           B64_Buf (B64_Len) := Input (Pos);
                        else
                           --  SPARKTLSCrypto.Base64 content exceeds buffer — cert is oversize
                           Result.Oversize := True;
                        end if;
                        Pos := Pos + 1;
                     end if;
                  end loop Collect;

                  if Result.Oversize then
                     return;
                  end if;

                  --  SPARKTLSCrypto.Base64 decode → DER as X509.Byte_Seq
                  if B64_Len > 0 and then
                     B64_Len mod 4 = 0 and then
                     SPARKTLSCrypto.Base64.Validate (B64_Buf (1 .. B64_Len))
                  then
                     declare
                        B64 : constant SPARKTLSCrypto.Base64.Base64_String :=
                           SPARKTLSCrypto.Base64.Construct (B64_Buf (1 .. B64_Len));
                        DER_Str : constant String := SPARKTLSCrypto.Base64.Decode (B64);
                     begin
                        if DER_Str'Length > Max_Cert_DER then
                           Result.Oversize := True;
                        elsif DER_Str'Length > 0 then
                           for I in 0 .. DER_Str'Length - 1 loop
                              Result.DER (X509.N32 (I)) :=
                                 X509.Byte (Character'Pos
                                    (DER_Str (DER_Str'First + I)));
                           end loop;
                           Result.DER_Len := X509.N32 (DER_Str'Length);
                           Result.OK := True;
                        end if;
                     end;
                  end if;

                  return;
               end if;

               Label_End := Label_End + 1;
            end loop Find_Label_End;
         end if;

         Pos := Pos + 1;
      end loop Find_Begin;
   end Decode;

end SPARKTLS.PEM;
