/* FIPS 140-3 module boundary for the software integrity test.

   sparktls.gpr passes this to every link that uses the library
   (Linker'Linker_Options). INSERT keeps GNU ld's default script; these
   rules only gather the module's code into .fips_text and its read-only
   data into .fips_rodata. SPARKTLS.Integrity HMACs both at start-up and
   compares them with .fips_hmac, which tools/fips_inject fills in after
   the final link.

   The module is every crate this library links: sparktls, sparktlscrypto,
   sparkx509, sparkmlkem, SPARKNaCl, libkeccak and sparkentropy (whose
   objects are linked loose, not from an archive). The GNAT runtime and
   libc are outside it. Constant data holding addresses lands in
   .data.rel.ro, not .rodata; it is rewritten by the loader and so cannot
   be hashed, and stays outside. */

SECTIONS
{
  .fips_text : ALIGN(64)
  {
    __fips_text_start = .;
    *libSparktls.a:*(.text .text.*)
    *libsparktlscrypto.a:*(.text .text.*)
    *libsparkx509.a:*(.text .text.*)
    *libsparkmlkem.a:*(.text .text.*)
    *libSparknacl.a:*(.text .text.*)
    *libkeccak.a:*(.text .text.*)
    *sparkentropy*.o(.text .text.*)
    __fips_text_end = .;
  }
}
INSERT AFTER .text;

SECTIONS
{
  .fips_rodata : ALIGN(64)
  {
    __fips_rodata_start = .;
    *libSparktls.a:*(.rodata .rodata.*)
    *libsparktlscrypto.a:*(.rodata .rodata.*)
    *libsparkx509.a:*(.rodata .rodata.*)
    *libsparkmlkem.a:*(.rodata .rodata.*)
    *libSparknacl.a:*(.rodata .rodata.*)
    *libkeccak.a:*(.rodata .rodata.*)
    *sparkentropy*.o(.rodata .rodata.*)
    __fips_rodata_end = .;
  }
}
INSERT AFTER .rodata;
