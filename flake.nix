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
          #  Colibri2 (CEA LIST, LGPL-2.1): the constraint-programming SMT
          #  solver RecordFlux routes its 2**N `Fits_Into` arithmetic to. FSF
          #  gnatprove 16.1.0 already ships the why3 driver and the
          #  gnatprove.conf entry for `colibri2`; only the binary is missing,
          #  so putting this on PATH is the whole integration
          #  (`gnatprove --prover=z3,cvc5,altergo,colibri2`).
          #
          #  Source: Frama-C GitLab, tag 0.6 (2026-06-22), CI job
          #  `generate-static` of pipeline 111937. The release .tbz assets
          #  are SOURCE tarballs; the static-PIE binary only exists as this
          #  job artifact, fetched as a fixed-output derivation so the bytes
          #  are pinned. Their own flake.nix does not build on current
          #  nixpkgs (stale dune pin), hence the binary rather than a source
          #  build for now. Job artifacts can expire upstream: if this fetch
          #  ever fails, mirror the zip and update the URL (hash stays).
          #  Nine popop_lib/colibrics files carry a CEA proprietary header
          #  alongside the LGPL package license -- review before
          #  redistributing the binary itself.
          colibri2 =
            if system == "x86_64-linux" then
              [
                (pkgs.stdenvNoCC.mkDerivation {
                  pname = "colibri2";
                  version = "0.6";
                  src = pkgs.fetchurl {
                    name = "colibri2-0.6-generate-static-artifacts.zip";
                    url = "https://git.frama-c.com/api/v4/projects/879/jobs/1970747/artifacts";
                    hash = "sha256-VycazpUOjL4LkUU+s+GmzIHz/AE43FuO/1dOeWLMpa4=";
                  };
                  nativeBuildInputs = [ pkgs.unzip ];
                  unpackPhase = "unzip -q $src";
                  dontBuild = true;
                  #  static-pie: no patchelf, no strip -- keep the bytes as shipped.
                  dontFixup = true;
                  installPhase = "install -Dm755 bin/colibri2 $out/bin/colibri2";
                  meta = {
                    description = "Colibri2 CP-based SMT solver (static binary)";
                    homepage = "https://colibri.frama-c.com";
                    license = pkgs.lib.licenses.lgpl21Only;
                    platforms = [ "x86_64-linux" ];
                  };
                })
              ]
            else
              [ ];
        in
        {
          default = pkgs.mkShell {
            packages = alirePackages ++ colibri2 ++ (with pkgs; [
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
              #  BoGo's runner is Go. Without it here, tests/bogo/run.sh
              #  curls its own Go tarball from go.dev at run time (~75 MB)
              #  -- so the toolchain becomes whatever upstream serves that
              #  day, and the suite silently skips entirely if the network
              #  is unavailable. Pinning it through nixpkgs is the whole
              #  point of this shell.
              go
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
