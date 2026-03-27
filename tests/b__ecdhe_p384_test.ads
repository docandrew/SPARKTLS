pragma Warnings (Off);
pragma Ada_95;
with System;
with System.Parameters;
with System.Secondary_Stack;
package ada_main is

   gnat_argc : Integer;
   gnat_argv : System.Address;
   gnat_envp : System.Address;

   pragma Import (C, gnat_argc);
   pragma Import (C, gnat_argv);
   pragma Import (C, gnat_envp);

   gnat_exit_status : Integer;
   pragma Import (C, gnat_exit_status);

   GNAT_Version : constant String :=
                    "GNAT Version: 14.2.0" & ASCII.NUL;
   pragma Export (C, GNAT_Version, "__gnat_version");

   GNAT_Version_Address : constant System.Address := GNAT_Version'Address;
   pragma Export (C, GNAT_Version_Address, "__gnat_version_address");

   Ada_Main_Program_Name : constant String := "_ada_ecdhe_p384_test" & ASCII.NUL;
   pragma Export (C, Ada_Main_Program_Name, "__gnat_ada_main_program_name");

   procedure adainit;
   pragma Export (C, adainit, "adainit");

   procedure adafinal;
   pragma Export (C, adafinal, "adafinal");

   function main
     (argc : Integer;
      argv : System.Address;
      envp : System.Address)
      return Integer;
   pragma Export (C, main, "main");

   type Version_32 is mod 2 ** 32;
   u00001 : constant Version_32 := 16#6380c12f#;
   pragma Export (C, u00001, "ecdhe_p384_testB");
   u00002 : constant Version_32 := 16#30305195#;
   pragma Export (C, u00002, "system__standard_libraryB");
   u00003 : constant Version_32 := 16#0626cc96#;
   pragma Export (C, u00003, "system__standard_libraryS");
   u00004 : constant Version_32 := 16#76789da1#;
   pragma Export (C, u00004, "adaS");
   u00005 : constant Version_32 := 16#e6d4fa36#;
   pragma Export (C, u00005, "ada__stringsS");
   u00006 : constant Version_32 := 16#14286b0f#;
   pragma Export (C, u00006, "systemS");
   u00007 : constant Version_32 := 16#c71e6c8a#;
   pragma Export (C, u00007, "system__exception_tableB");
   u00008 : constant Version_32 := 16#99031d16#;
   pragma Export (C, u00008, "system__exception_tableS");
   u00009 : constant Version_32 := 16#fd5f5f4c#;
   pragma Export (C, u00009, "system__soft_linksB");
   u00010 : constant Version_32 := 16#455c24f2#;
   pragma Export (C, u00010, "system__soft_linksS");
   u00011 : constant Version_32 := 16#524f7d04#;
   pragma Export (C, u00011, "system__secondary_stackB");
   u00012 : constant Version_32 := 16#bae33a03#;
   pragma Export (C, u00012, "system__secondary_stackS");
   u00013 : constant Version_32 := 16#9a5d1b93#;
   pragma Export (C, u00013, "ada__exceptionsB");
   u00014 : constant Version_32 := 16#64d9391c#;
   pragma Export (C, u00014, "ada__exceptionsS");
   u00015 : constant Version_32 := 16#0740df23#;
   pragma Export (C, u00015, "ada__exceptions__last_chance_handlerB");
   u00016 : constant Version_32 := 16#a028f72d#;
   pragma Export (C, u00016, "ada__exceptions__last_chance_handlerS");
   u00017 : constant Version_32 := 16#268dd43d#;
   pragma Export (C, u00017, "system__exceptionsS");
   u00018 : constant Version_32 := 16#69416224#;
   pragma Export (C, u00018, "system__exceptions__machineB");
   u00019 : constant Version_32 := 16#46355a4a#;
   pragma Export (C, u00019, "system__exceptions__machineS");
   u00020 : constant Version_32 := 16#7706238d#;
   pragma Export (C, u00020, "system__exceptions_debugB");
   u00021 : constant Version_32 := 16#2426335c#;
   pragma Export (C, u00021, "system__exceptions_debugS");
   u00022 : constant Version_32 := 16#36b7284e#;
   pragma Export (C, u00022, "system__img_intS");
   u00023 : constant Version_32 := 16#f2c63a02#;
   pragma Export (C, u00023, "ada__numericsS");
   u00024 : constant Version_32 := 16#174f5472#;
   pragma Export (C, u00024, "ada__numerics__big_numbersS");
   u00025 : constant Version_32 := 16#ee021456#;
   pragma Export (C, u00025, "system__unsigned_typesS");
   u00026 : constant Version_32 := 16#d8f6bfe7#;
   pragma Export (C, u00026, "system__storage_elementsS");
   u00027 : constant Version_32 := 16#5c7d9c20#;
   pragma Export (C, u00027, "system__tracebackB");
   u00028 : constant Version_32 := 16#92b29fb2#;
   pragma Export (C, u00028, "system__tracebackS");
   u00029 : constant Version_32 := 16#5f6b6486#;
   pragma Export (C, u00029, "system__traceback_entriesB");
   u00030 : constant Version_32 := 16#dc34d483#;
   pragma Export (C, u00030, "system__traceback_entriesS");
   u00031 : constant Version_32 := 16#b27c8a69#;
   pragma Export (C, u00031, "system__traceback__symbolicB");
   u00032 : constant Version_32 := 16#140ceb78#;
   pragma Export (C, u00032, "system__traceback__symbolicS");
   u00033 : constant Version_32 := 16#179d7d28#;
   pragma Export (C, u00033, "ada__containersS");
   u00034 : constant Version_32 := 16#701f9d88#;
   pragma Export (C, u00034, "ada__exceptions__tracebackB");
   u00035 : constant Version_32 := 16#26ed0985#;
   pragma Export (C, u00035, "ada__exceptions__tracebackS");
   u00036 : constant Version_32 := 16#9111f9c1#;
   pragma Export (C, u00036, "interfacesS");
   u00037 : constant Version_32 := 16#0390ef72#;
   pragma Export (C, u00037, "interfaces__cB");
   u00038 : constant Version_32 := 16#1a6d7811#;
   pragma Export (C, u00038, "interfaces__cS");
   u00039 : constant Version_32 := 16#a43efea2#;
   pragma Export (C, u00039, "system__parametersB");
   u00040 : constant Version_32 := 16#21bf971e#;
   pragma Export (C, u00040, "system__parametersS");
   u00041 : constant Version_32 := 16#0978786d#;
   pragma Export (C, u00041, "system__bounded_stringsB");
   u00042 : constant Version_32 := 16#63d54a16#;
   pragma Export (C, u00042, "system__bounded_stringsS");
   u00043 : constant Version_32 := 16#9f0c0c80#;
   pragma Export (C, u00043, "system__crtlS");
   u00044 : constant Version_32 := 16#a604bd9c#;
   pragma Export (C, u00044, "system__dwarf_linesB");
   u00045 : constant Version_32 := 16#f38e5e19#;
   pragma Export (C, u00045, "system__dwarf_linesS");
   u00046 : constant Version_32 := 16#5b4659fa#;
   pragma Export (C, u00046, "ada__charactersS");
   u00047 : constant Version_32 := 16#9de61c25#;
   pragma Export (C, u00047, "ada__characters__handlingB");
   u00048 : constant Version_32 := 16#729cc5db#;
   pragma Export (C, u00048, "ada__characters__handlingS");
   u00049 : constant Version_32 := 16#cde9ea2d#;
   pragma Export (C, u00049, "ada__characters__latin_1S");
   u00050 : constant Version_32 := 16#c5e1e773#;
   pragma Export (C, u00050, "ada__strings__mapsB");
   u00051 : constant Version_32 := 16#6feaa257#;
   pragma Export (C, u00051, "ada__strings__mapsS");
   u00052 : constant Version_32 := 16#b451a498#;
   pragma Export (C, u00052, "system__bit_opsB");
   u00053 : constant Version_32 := 16#d9dbc733#;
   pragma Export (C, u00053, "system__bit_opsS");
   u00054 : constant Version_32 := 16#b459efcb#;
   pragma Export (C, u00054, "ada__strings__maps__constantsS");
   u00055 : constant Version_32 := 16#a0d3d22b#;
   pragma Export (C, u00055, "system__address_imageB");
   u00056 : constant Version_32 := 16#b5c4f635#;
   pragma Export (C, u00056, "system__address_imageS");
   u00057 : constant Version_32 := 16#7da15eb1#;
   pragma Export (C, u00057, "system__img_unsS");
   u00058 : constant Version_32 := 16#20ec7aa3#;
   pragma Export (C, u00058, "system__ioB");
   u00059 : constant Version_32 := 16#8a6a9c40#;
   pragma Export (C, u00059, "system__ioS");
   u00060 : constant Version_32 := 16#e15ca368#;
   pragma Export (C, u00060, "system__mmapB");
   u00061 : constant Version_32 := 16#da9a152c#;
   pragma Export (C, u00061, "system__mmapS");
   u00062 : constant Version_32 := 16#367911c4#;
   pragma Export (C, u00062, "ada__io_exceptionsS");
   u00063 : constant Version_32 := 16#dd82c35a#;
   pragma Export (C, u00063, "system__mmap__os_interfaceB");
   u00064 : constant Version_32 := 16#37fd3b64#;
   pragma Export (C, u00064, "system__mmap__os_interfaceS");
   u00065 : constant Version_32 := 16#c8a05a18#;
   pragma Export (C, u00065, "system__mmap__unixS");
   u00066 : constant Version_32 := 16#29c68ba2#;
   pragma Export (C, u00066, "system__os_libB");
   u00067 : constant Version_32 := 16#ee44bb50#;
   pragma Export (C, u00067, "system__os_libS");
   u00068 : constant Version_32 := 16#94d23d25#;
   pragma Export (C, u00068, "system__atomic_operations__test_and_setB");
   u00069 : constant Version_32 := 16#57acee8e#;
   pragma Export (C, u00069, "system__atomic_operations__test_and_setS");
   u00070 : constant Version_32 := 16#d34b112a#;
   pragma Export (C, u00070, "system__atomic_operationsS");
   u00071 : constant Version_32 := 16#553a519e#;
   pragma Export (C, u00071, "system__atomic_primitivesB");
   u00072 : constant Version_32 := 16#5f776048#;
   pragma Export (C, u00072, "system__atomic_primitivesS");
   u00073 : constant Version_32 := 16#b98923bf#;
   pragma Export (C, u00073, "system__case_utilB");
   u00074 : constant Version_32 := 16#db3bbc5a#;
   pragma Export (C, u00074, "system__case_utilS");
   u00075 : constant Version_32 := 16#256dbbe5#;
   pragma Export (C, u00075, "system__stringsB");
   u00076 : constant Version_32 := 16#8faa6b17#;
   pragma Export (C, u00076, "system__stringsS");
   u00077 : constant Version_32 := 16#edf7b7b1#;
   pragma Export (C, u00077, "system__object_readerB");
   u00078 : constant Version_32 := 16#87571f07#;
   pragma Export (C, u00078, "system__object_readerS");
   u00079 : constant Version_32 := 16#75406883#;
   pragma Export (C, u00079, "system__val_lliS");
   u00080 : constant Version_32 := 16#838eea00#;
   pragma Export (C, u00080, "system__val_lluS");
   u00081 : constant Version_32 := 16#47d9a892#;
   pragma Export (C, u00081, "system__sparkS");
   u00082 : constant Version_32 := 16#a571a4dc#;
   pragma Export (C, u00082, "system__spark__cut_operationsB");
   u00083 : constant Version_32 := 16#629c0fb7#;
   pragma Export (C, u00083, "system__spark__cut_operationsS");
   u00084 : constant Version_32 := 16#1bac5121#;
   pragma Export (C, u00084, "system__val_utilB");
   u00085 : constant Version_32 := 16#b851cf14#;
   pragma Export (C, u00085, "system__val_utilS");
   u00086 : constant Version_32 := 16#bad10b33#;
   pragma Export (C, u00086, "system__exception_tracesB");
   u00087 : constant Version_32 := 16#f8b00269#;
   pragma Export (C, u00087, "system__exception_tracesS");
   u00088 : constant Version_32 := 16#fd158a37#;
   pragma Export (C, u00088, "system__wch_conB");
   u00089 : constant Version_32 := 16#cd2b486c#;
   pragma Export (C, u00089, "system__wch_conS");
   u00090 : constant Version_32 := 16#5c289972#;
   pragma Export (C, u00090, "system__wch_stwB");
   u00091 : constant Version_32 := 16#e03a646d#;
   pragma Export (C, u00091, "system__wch_stwS");
   u00092 : constant Version_32 := 16#7cd63de5#;
   pragma Export (C, u00092, "system__wch_cnvB");
   u00093 : constant Version_32 := 16#cbeb821c#;
   pragma Export (C, u00093, "system__wch_cnvS");
   u00094 : constant Version_32 := 16#e538de43#;
   pragma Export (C, u00094, "system__wch_jisB");
   u00095 : constant Version_32 := 16#7e5ce036#;
   pragma Export (C, u00095, "system__wch_jisS");
   u00096 : constant Version_32 := 16#0286ce9f#;
   pragma Export (C, u00096, "system__soft_links__initializeB");
   u00097 : constant Version_32 := 16#2ed17187#;
   pragma Export (C, u00097, "system__soft_links__initializeS");
   u00098 : constant Version_32 := 16#8599b27b#;
   pragma Export (C, u00098, "system__stack_checkingB");
   u00099 : constant Version_32 := 16#d3777e19#;
   pragma Export (C, u00099, "system__stack_checkingS");
   u00100 : constant Version_32 := 16#603adc29#;
   pragma Export (C, u00100, "ada__strings__fixedB");
   u00101 : constant Version_32 := 16#b4492da2#;
   pragma Export (C, u00101, "ada__strings__fixedS");
   u00102 : constant Version_32 := 16#fb589256#;
   pragma Export (C, u00102, "ada__strings__searchB");
   u00103 : constant Version_32 := 16#a44727a7#;
   pragma Export (C, u00103, "ada__strings__searchS");
   u00104 : constant Version_32 := 16#a201b8c5#;
   pragma Export (C, u00104, "ada__strings__text_buffersB");
   u00105 : constant Version_32 := 16#a7cfd09b#;
   pragma Export (C, u00105, "ada__strings__text_buffersS");
   u00106 : constant Version_32 := 16#8b7604c4#;
   pragma Export (C, u00106, "ada__strings__utf_encodingB");
   u00107 : constant Version_32 := 16#c9e86997#;
   pragma Export (C, u00107, "ada__strings__utf_encodingS");
   u00108 : constant Version_32 := 16#bb780f45#;
   pragma Export (C, u00108, "ada__strings__utf_encoding__stringsB");
   u00109 : constant Version_32 := 16#b85ff4b6#;
   pragma Export (C, u00109, "ada__strings__utf_encoding__stringsS");
   u00110 : constant Version_32 := 16#d1d1ed0b#;
   pragma Export (C, u00110, "ada__strings__utf_encoding__wide_stringsB");
   u00111 : constant Version_32 := 16#5678478f#;
   pragma Export (C, u00111, "ada__strings__utf_encoding__wide_stringsS");
   u00112 : constant Version_32 := 16#c2b98963#;
   pragma Export (C, u00112, "ada__strings__utf_encoding__wide_wide_stringsB");
   u00113 : constant Version_32 := 16#d7af3358#;
   pragma Export (C, u00113, "ada__strings__utf_encoding__wide_wide_stringsS");
   u00114 : constant Version_32 := 16#0d5e09a4#;
   pragma Export (C, u00114, "ada__tagsB");
   u00115 : constant Version_32 := 16#2a9756e0#;
   pragma Export (C, u00115, "ada__tagsS");
   u00116 : constant Version_32 := 16#3548d972#;
   pragma Export (C, u00116, "system__htableB");
   u00117 : constant Version_32 := 16#95f133e4#;
   pragma Export (C, u00117, "system__htableS");
   u00118 : constant Version_32 := 16#1f1abe38#;
   pragma Export (C, u00118, "system__string_hashB");
   u00119 : constant Version_32 := 16#32b4b39b#;
   pragma Export (C, u00119, "system__string_hashS");
   u00120 : constant Version_32 := 16#2170d2a2#;
   pragma Export (C, u00120, "ada__text_ioB");
   u00121 : constant Version_32 := 16#0277f011#;
   pragma Export (C, u00121, "ada__text_ioS");
   u00122 : constant Version_32 := 16#b4f41810#;
   pragma Export (C, u00122, "ada__streamsB");
   u00123 : constant Version_32 := 16#67e31212#;
   pragma Export (C, u00123, "ada__streamsS");
   u00124 : constant Version_32 := 16#05222263#;
   pragma Export (C, u00124, "system__put_imagesB");
   u00125 : constant Version_32 := 16#08866c10#;
   pragma Export (C, u00125, "system__put_imagesS");
   u00126 : constant Version_32 := 16#22b9eb9f#;
   pragma Export (C, u00126, "ada__strings__text_buffers__utilsB");
   u00127 : constant Version_32 := 16#89062ac3#;
   pragma Export (C, u00127, "ada__strings__text_buffers__utilsS");
   u00128 : constant Version_32 := 16#1cacf006#;
   pragma Export (C, u00128, "interfaces__c_streamsB");
   u00129 : constant Version_32 := 16#d07279c2#;
   pragma Export (C, u00129, "interfaces__c_streamsS");
   u00130 : constant Version_32 := 16#f74fab1c#;
   pragma Export (C, u00130, "system__file_ioB");
   u00131 : constant Version_32 := 16#72673e49#;
   pragma Export (C, u00131, "system__file_ioS");
   u00132 : constant Version_32 := 16#86c56e5a#;
   pragma Export (C, u00132, "ada__finalizationS");
   u00133 : constant Version_32 := 16#95817ed8#;
   pragma Export (C, u00133, "system__finalization_rootB");
   u00134 : constant Version_32 := 16#5bda189f#;
   pragma Export (C, u00134, "system__finalization_rootS");
   u00135 : constant Version_32 := 16#9881056b#;
   pragma Export (C, u00135, "system__file_control_blockS");
   u00136 : constant Version_32 := 16#1f2359a4#;
   pragma Export (C, u00136, "sparknaclB");
   u00137 : constant Version_32 := 16#10bbf952#;
   pragma Export (C, u00137, "sparknaclS");
   u00138 : constant Version_32 := 16#e6928b8b#;
   pragma Export (C, u00138, "sparknacl__carB");
   u00139 : constant Version_32 := 16#8e96cfc2#;
   pragma Export (C, u00139, "sparknacl__carS");
   u00140 : constant Version_32 := 16#08311ff9#;
   pragma Export (C, u00140, "sparktlsB");
   u00141 : constant Version_32 := 16#dd537a4b#;
   pragma Export (C, u00141, "sparktlsS");
   u00142 : constant Version_32 := 16#f90f9c90#;
   pragma Export (C, u00142, "rflxS");
   u00143 : constant Version_32 := 16#df50c1da#;
   pragma Export (C, u00143, "rflx__rflx_builtin_typesS");
   u00144 : constant Version_32 := 16#e63b808f#;
   pragma Export (C, u00144, "x509S");
   u00145 : constant Version_32 := 16#21b023a2#;
   pragma Export (C, u00145, "ada__calendarB");
   u00146 : constant Version_32 := 16#63f2c9c2#;
   pragma Export (C, u00146, "ada__calendarS");
   u00147 : constant Version_32 := 16#d172d809#;
   pragma Export (C, u00147, "system__os_primitivesB");
   u00148 : constant Version_32 := 16#13d50ef9#;
   pragma Export (C, u00148, "system__os_primitivesS");
   u00149 : constant Version_32 := 16#3a11d4dc#;
   pragma Export (C, u00149, "ada__strings__boundedB");
   u00150 : constant Version_32 := 16#05047448#;
   pragma Export (C, u00150, "ada__strings__boundedS");
   u00151 : constant Version_32 := 16#c8a8099a#;
   pragma Export (C, u00151, "ada__strings__superboundedB");
   u00152 : constant Version_32 := 16#84cd51a4#;
   pragma Export (C, u00152, "ada__strings__superboundedS");
   u00153 : constant Version_32 := 16#ec48c658#;
   pragma Export (C, u00153, "system__compare_array_unsigned_8B");
   u00154 : constant Version_32 := 16#84cef56c#;
   pragma Export (C, u00154, "system__compare_array_unsigned_8S");
   u00155 : constant Version_32 := 16#74e358eb#;
   pragma Export (C, u00155, "system__address_operationsB");
   u00156 : constant Version_32 := 16#6a1c47af#;
   pragma Export (C, u00156, "system__address_operationsS");
   u00157 : constant Version_32 := 16#b417f8bc#;
   pragma Export (C, u00157, "oidB");
   u00158 : constant Version_32 := 16#ae6ccfed#;
   pragma Export (C, u00158, "oidS");
   u00159 : constant Version_32 := 16#2925b690#;
   pragma Export (C, u00159, "sparkx509S");
   u00160 : constant Version_32 := 16#8517b946#;
   pragma Export (C, u00160, "sparktls__p384S");
   u00161 : constant Version_32 := 16#f177fee6#;
   pragma Export (C, u00161, "sparktls__p384__pointB");
   u00162 : constant Version_32 := 16#a6da3b0c#;
   pragma Export (C, u00162, "sparktls__p384__pointS");
   u00163 : constant Version_32 := 16#696c9ce5#;
   pragma Export (C, u00163, "sparktls__p384__fieldB");
   u00164 : constant Version_32 := 16#f37f0ae3#;
   pragma Export (C, u00164, "sparktls__p384__fieldS");
   u00165 : constant Version_32 := 16#10e0e29f#;
   pragma Export (C, u00165, "sparktls__rsaB");
   u00166 : constant Version_32 := 16#5aa2f244#;
   pragma Export (C, u00166, "sparktls__rsaS");
   u00167 : constant Version_32 := 16#d7f57dbe#;
   pragma Export (C, u00167, "sparknacl__hashingS");
   u00168 : constant Version_32 := 16#9c5a8e24#;
   pragma Export (C, u00168, "sparknacl__hashing__sha256B");
   u00169 : constant Version_32 := 16#15b257d0#;
   pragma Export (C, u00169, "sparknacl__hashing__sha256S");
   u00170 : constant Version_32 := 16#5dc71609#;
   pragma Export (C, u00170, "sparknacl__hashing__sha2_commonB");
   u00171 : constant Version_32 := 16#b6faa632#;
   pragma Export (C, u00171, "sparknacl__hashing__sha2_commonS");
   u00172 : constant Version_32 := 16#3b89f5e4#;
   pragma Export (C, u00172, "sparknacl__hashing__sha384B");
   u00173 : constant Version_32 := 16#35af6668#;
   pragma Export (C, u00173, "sparknacl__hashing__sha384S");
   u00174 : constant Version_32 := 16#5a088811#;
   pragma Export (C, u00174, "sparknacl__hashing__sha512B");
   u00175 : constant Version_32 := 16#613ef537#;
   pragma Export (C, u00175, "sparknacl__hashing__sha512S");
   u00176 : constant Version_32 := 16#ca878138#;
   pragma Export (C, u00176, "system__concat_2B");
   u00177 : constant Version_32 := 16#a1d318f8#;
   pragma Export (C, u00177, "system__concat_2S");
   u00178 : constant Version_32 := 16#752a67ed#;
   pragma Export (C, u00178, "system__concat_3B");
   u00179 : constant Version_32 := 16#9e5272ad#;
   pragma Export (C, u00179, "system__concat_3S");
   u00180 : constant Version_32 := 16#ebb39bbb#;
   pragma Export (C, u00180, "system__concat_5B");
   u00181 : constant Version_32 := 16#54b1bad4#;
   pragma Export (C, u00181, "system__concat_5S");
   u00182 : constant Version_32 := 16#8f2423cb#;
   pragma Export (C, u00182, "system__memoryB");
   u00183 : constant Version_32 := 16#0cbcf715#;
   pragma Export (C, u00183, "system__memoryS");

   --  BEGIN ELABORATION ORDER
   --  ada%s
   --  ada.characters%s
   --  ada.characters.latin_1%s
   --  interfaces%s
   --  system%s
   --  system.address_operations%s
   --  system.address_operations%b
   --  system.atomic_operations%s
   --  system.io%s
   --  system.io%b
   --  system.parameters%s
   --  system.parameters%b
   --  system.crtl%s
   --  interfaces.c_streams%s
   --  interfaces.c_streams%b
   --  system.os_primitives%s
   --  system.os_primitives%b
   --  system.spark%s
   --  system.spark.cut_operations%s
   --  system.spark.cut_operations%b
   --  system.storage_elements%s
   --  system.stack_checking%s
   --  system.stack_checking%b
   --  system.string_hash%s
   --  system.string_hash%b
   --  system.htable%s
   --  system.htable%b
   --  system.strings%s
   --  system.strings%b
   --  system.traceback_entries%s
   --  system.traceback_entries%b
   --  system.unsigned_types%s
   --  system.wch_con%s
   --  system.wch_con%b
   --  system.wch_jis%s
   --  system.wch_jis%b
   --  system.wch_cnv%s
   --  system.wch_cnv%b
   --  system.compare_array_unsigned_8%s
   --  system.compare_array_unsigned_8%b
   --  system.concat_2%s
   --  system.concat_2%b
   --  system.concat_3%s
   --  system.concat_3%b
   --  system.concat_5%s
   --  system.concat_5%b
   --  system.traceback%s
   --  system.traceback%b
   --  ada.characters.handling%s
   --  system.atomic_operations.test_and_set%s
   --  system.case_util%s
   --  system.os_lib%s
   --  system.secondary_stack%s
   --  system.standard_library%s
   --  ada.exceptions%s
   --  system.exceptions_debug%s
   --  system.exceptions_debug%b
   --  system.soft_links%s
   --  system.val_util%s
   --  system.val_util%b
   --  system.val_llu%s
   --  system.val_lli%s
   --  system.wch_stw%s
   --  system.wch_stw%b
   --  ada.exceptions.last_chance_handler%s
   --  ada.exceptions.last_chance_handler%b
   --  ada.exceptions.traceback%s
   --  ada.exceptions.traceback%b
   --  system.address_image%s
   --  system.address_image%b
   --  system.bit_ops%s
   --  system.bit_ops%b
   --  system.bounded_strings%s
   --  system.bounded_strings%b
   --  system.case_util%b
   --  system.exception_table%s
   --  system.exception_table%b
   --  ada.containers%s
   --  ada.io_exceptions%s
   --  ada.numerics%s
   --  ada.numerics.big_numbers%s
   --  ada.strings%s
   --  ada.strings.maps%s
   --  ada.strings.maps%b
   --  ada.strings.maps.constants%s
   --  interfaces.c%s
   --  interfaces.c%b
   --  system.atomic_primitives%s
   --  system.atomic_primitives%b
   --  system.exceptions%s
   --  system.exceptions.machine%s
   --  system.exceptions.machine%b
   --  ada.characters.handling%b
   --  system.atomic_operations.test_and_set%b
   --  system.exception_traces%s
   --  system.exception_traces%b
   --  system.img_int%s
   --  system.img_uns%s
   --  system.memory%s
   --  system.memory%b
   --  system.mmap%s
   --  system.mmap.os_interface%s
   --  system.mmap%b
   --  system.mmap.unix%s
   --  system.mmap.os_interface%b
   --  system.object_reader%s
   --  system.object_reader%b
   --  system.dwarf_lines%s
   --  system.dwarf_lines%b
   --  system.os_lib%b
   --  system.secondary_stack%b
   --  system.soft_links.initialize%s
   --  system.soft_links.initialize%b
   --  system.soft_links%b
   --  system.standard_library%b
   --  system.traceback.symbolic%s
   --  system.traceback.symbolic%b
   --  ada.exceptions%b
   --  ada.strings.search%s
   --  ada.strings.search%b
   --  ada.strings.fixed%s
   --  ada.strings.fixed%b
   --  ada.strings.utf_encoding%s
   --  ada.strings.utf_encoding%b
   --  ada.strings.utf_encoding.strings%s
   --  ada.strings.utf_encoding.strings%b
   --  ada.strings.utf_encoding.wide_strings%s
   --  ada.strings.utf_encoding.wide_strings%b
   --  ada.strings.utf_encoding.wide_wide_strings%s
   --  ada.strings.utf_encoding.wide_wide_strings%b
   --  ada.tags%s
   --  ada.tags%b
   --  ada.strings.text_buffers%s
   --  ada.strings.text_buffers%b
   --  ada.strings.text_buffers.utils%s
   --  ada.strings.text_buffers.utils%b
   --  system.put_images%s
   --  system.put_images%b
   --  ada.streams%s
   --  ada.streams%b
   --  ada.strings.superbounded%s
   --  ada.strings.superbounded%b
   --  ada.strings.bounded%s
   --  ada.strings.bounded%b
   --  system.file_control_block%s
   --  system.finalization_root%s
   --  system.finalization_root%b
   --  ada.finalization%s
   --  system.file_io%s
   --  system.file_io%b
   --  ada.calendar%s
   --  ada.calendar%b
   --  ada.text_io%s
   --  ada.text_io%b
   --  sparknacl%s
   --  sparknacl.car%s
   --  sparknacl.car%b
   --  sparknacl%b
   --  sparknacl.hashing%s
   --  sparknacl.hashing.sha2_common%s
   --  sparknacl.hashing.sha2_common%b
   --  sparknacl.hashing.sha256%s
   --  sparknacl.hashing.sha256%b
   --  sparknacl.hashing.sha384%s
   --  sparknacl.hashing.sha384%b
   --  sparknacl.hashing.sha512%s
   --  sparknacl.hashing.sha512%b
   --  rflx%s
   --  rflx.rflx_builtin_types%s
   --  sparkx509%s
   --  oid%s
   --  oid%b
   --  x509%s
   --  sparktls%s
   --  sparktls%b
   --  sparktls.p384%s
   --  sparktls.rsa%s
   --  sparktls.rsa%b
   --  sparktls.p384.field%s
   --  sparktls.p384.field%b
   --  sparktls.p384.point%s
   --  sparktls.p384.point%b
   --  ecdhe_p384_test%b
   --  END ELABORATION ORDER

end ada_main;
