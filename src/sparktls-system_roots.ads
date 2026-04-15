--  Load the OS certificate store into a Trust_Store.
--
--  SPARK_Mode Off: performs file I/O.
--
--  Usage:
--    Roots  : aliased SPARKTLS.Trust_Store;
--    Loaded : Natural;
--    OK     : Boolean;
--    SPARKTLS.System_Roots.Load (Roots, Loaded, OK);

package SPARKTLS.System_Roots with
   SPARK_Mode => Off
is
   --  Load the platform's trusted root certificates.
   --
   --  Linux: tries these paths in order:
   --    /etc/ssl/certs/ca-certificates.crt  (Debian/Ubuntu)
   --    /etc/pki/tls/certs/ca-bundle.crt    (RHEL/Fedora)
   --    /etc/ssl/ca-bundle.pem              (SUSE)
   --
   --  Loaded: number of roots successfully parsed and added.
   --  OK: True if at least one root was loaded.
   procedure Load
     (Store  : out Trust_Store;
      Loaded : out Natural;
      OK     : out Boolean);

   --  Load from a specific PEM bundle file.
   procedure Load_Bundle
     (Store  : in out Trust_Store;
      Path   : String;
      Loaded : out Natural;
      OK     : out Boolean);

end SPARKTLS.System_Roots;
