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
              echo "SPARKTLS dev shell: use ci/check.sh for the reproducible CI lane."
            '';
          };
        }
      );
    };
}
