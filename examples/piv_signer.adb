with Interfaces;
with PIV.Linux_USB;

package body PIV_Signer is
   use type PIV.Index;
   use type PIV.Byte;
   use type Interfaces.Integer_32;

   Transmit : constant PIV.Transmit_Fn := PIV.Linux_USB.Transmit'Access;
   The_Slot : PIV.Slot := PIV.Slot_9C_Signature;
   PIN_Buf  : PIV.Bytes (0 .. 7) := (others => 0);
   PIN_Len  : PIV.Index := 0;
   Ready    : Boolean := False;

   procedure Init
     (S        : PIV.Slot;
      PIN      : String;
      Cert     : out Byte_Seq;
      Cert_Len : out N32;
      OK       : out Boolean;
      Why      : out PIV.Status)
   is
      use type PIV.Status;
      use type PIV.Slot;
      C   : PIV.Bytes (0 .. PIV.Max_Object - 1);
      C_L : PIV.Index;
      Retries : Natural;
   begin
      Cert := (others => 0);
      Cert_Len := 0;
      OK := False;
      The_Slot := S;
      PIN_Len := PIV.Index (PIN'Length);
      for I in PIN'Range loop
         PIN_Buf (PIV.Index (I - PIN'First)) := PIV.Byte (Character'Pos (PIN (I)));
      end loop;
      PIV.Select_Applet (Transmit, Why);
      if Why /= PIV.Success then
         return;
      end if;
      --  Slot 9E (card authentication) signs without a PIN by PIV policy;
      --  the other slots need VERIFY first.
      if S /= PIV.Slot_9E_Card_Authentication then
         PIV.Verify_PIN (Transmit, PIN_Buf (0 .. PIN_Len - 1), Why, Retries);
         if Why /= PIV.Success then
            return;
         end if;
      end if;
      PIV.Read_Certificate (Transmit, S, C, C_L, Why);
      if Why /= PIV.Success then
         return;
      end if;
      if N32 (C_L) > Cert'Length then
         Why := PIV.Buffer_Too_Small;
         return;
      end if;
      for I in 0 .. C_L - 1 loop
         Cert (Cert'First + N32 (I)) := Byte (C (I));
      end loop;
      Cert_Len := N32 (C_L);
      Ready := True;
      OK := True;
   end Init;

   procedure Sign
     (Scheme  : in     Maybe_Sig_Scheme;
      Message : in     Byte_Seq;
      Digest  : in     Byte_Seq;
      Sig     :    out Byte_Seq;
      Sig_Len :    out N32;
      Status  :    out Sign_Status)
   is
      use type PIV.Status;
      use type PIV.Slot;
      Alg     : PIV.Algorithm;
      --  ECDSA signs the digest; Ed25519 signs the message (the card hashes).
      Use_Msg : constant Boolean := Scheme = Sig_Ed25519;
      In_Len  : constant N32 := (if Use_Msg then Message'Length else Digest'Length);
      D       : PIV.Bytes (0 .. PIV.Index (In_Len) - 1);
      Out_S   : PIV.Bytes (0 .. 1023);
      Out_L   : PIV.Index;
      Result  : PIV.Status;
      Retries : Natural;
   begin
      Sig := (others => 0);
      Sig_Len := 0;
      Status := Failed;
      if not Ready then
         return;
      end if;
      case Scheme is
         when Sig_ECDSA_P256_SHA256 => Alg := PIV.ECC_P256;
         when Sig_ECDSA_P384_SHA384 => Alg := PIV.ECC_P384;
         when Sig_Ed25519           => Alg := PIV.Ed25519;   --  firmware 5.7+
         when others => return;   --  RSA needs PKCS#1 encoding here first
      end case;
      if In_Len = 0 or else In_Len > 512 then
         return;
      end if;
      for I in D'Range loop
         D (I) := PIV.Byte (if Use_Msg then Message (Message'First + N32 (I))
                            else Digest (Digest'First + N32 (I)));
      end loop;
      --  A "PIN always" slot policy needs VERIFY before each signature;
      --  for "once" it is a cheap no-op. Do it every time, except for 9E
      --  which never takes a PIN.
      if The_Slot /= PIV.Slot_9E_Card_Authentication then
         PIV.Verify_PIN (Transmit, PIN_Buf (0 .. PIN_Len - 1), Result, Retries);
         if Result /= PIV.Success then
            return;
         end if;
      end if;
      PIV.Sign (Transmit, The_Slot, Alg, D, Out_S, Out_L, Result);
      if Result /= PIV.Success or else N32 (Out_L) > Sig'Length
        or else (Use_Msg and then Out_L /= 64)
      then
         return;
      end if;
      for I in 0 .. Out_L - 1 loop
         Sig (Sig'First + N32 (I)) := Byte (Out_S (I));
      end loop;
      Sig_Len := N32 (Out_L);
      Status := Signed;
   end Sign;

end PIV_Signer;
