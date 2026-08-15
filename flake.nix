{
  description = "Reproducible SPARKTLS build and test environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          alirePackages =
            if system == "x86_64-linux" then
              [ pkgs.alire ]
            else
              [ ];
        in
        {
          default = pkgs.mkShell {
            packages = alirePackages ++ (with pkgs; [
              bash
              coreutils
              curl
              findutils
              gawk
              gcc
              git
              gnugrep
              gnused
              gnumake
              iproute2
              openssl
              patchelf
              procps
              python3
              tcpdump
              valgrind
              which
            ]);

            #  valgrind must also be a buildInput, not just a package.
            #  `packages` in mkShell is an alias for nativeBuildInputs, and
            #  Nix only adds -I include paths (NIX_CFLAGS_COMPILE) for
            #  buildInputs. With it only in `packages` the valgrind binary is
            #  on PATH -- so the tool runs -- but tests/ctgrind/ctgrind_helpers.c
            #  fails on `#include <valgrind/memcheck.h>`. This does not show up
            #  on a dev box that has system valgrind headers in /usr/include.
            buildInputs = with pkgs; [ valgrind ];

            shellHook = ''
              #  tests/ctgrind/ctgrind_helpers.c does #include <valgrind/memcheck.h>,
              #  but gprbuild compiles it with ALIRE's toolchain gcc
              #  (~/.local/share/alire/toolchains/gnat_native_*/bin/gcc), not the
              #  nix-wrapped one. That plain gcc ignores NIX_CFLAGS_COMPILE, so
              #  buildInputs above is not sufficient on its own. C_INCLUDE_PATH is
              #  honoured by any gcc, wrapped or not.
              #
              #  This is invisible on a dev box that has system valgrind headers
              #  in /usr/include -- the build silently uses those instead.
              export C_INCLUDE_PATH="${pkgs.valgrind.dev}/include''${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"

              echo "SPARKTLS dev shell: use ci/check.sh for the reproducible CI lane."
            '';
          };
        }
      );
    };
}
