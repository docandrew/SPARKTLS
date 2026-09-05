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
          #  COLIBRI for gnatprove: the colibri2 ENGINE behind the COLIBRI v1
          #  DRIVER. gnatprove ships two why3 drivers: colibri.drv (v1; maps
          #  integer power to the solver's native colibri_pow_int_int) and
          #  colibri2.drv (no power mapping, so `2**N` is left axiomatized and
          #  no solver inducts through it). Measured 2026-09-03 on the RFLX
          #  generated `Fits_Into (Val, Field_Size ...)` preconditions: the
          #  real COLIBRI v1 gives up with spurious `sat` on 160/630 goals of
          #  a unit, while colibri2 fed the v1-dialect goals proves them in
          #  under a second, and clears the unit through gnatprove (1 -> 0).
          #  So bin/colibri is a wrapper that translates the v1 arguments
          #  gnatprove passes (--memlimit MB, --steplimit N) and execs the
          #  static colibri2 next to it; gnatprove's stock `colibri` entry
          #  and driver do the rest (`--prover=z3,cvc5,altergo,colibri`).
          #
          #  Engine: Colibri2 0.6 (CEA LIST, LGPL-2.1), Frama-C GitLab tag 0.6,
          #  CI job `generate-static` (pipeline 111937), fetched as a fixed-
          #  output derivation (release .tbz assets are source tarballs; the
          #  static-PIE binary only exists as this job artifact - if it ever
          #  expires, mirror the zip; the hash stays). Nine popop_lib/colibrics
          #  files carry a CEA proprietary header alongside the LGPL package
          #  license: review before redistributing the binary. #!/bin/sh on
          #  purpose: the wrapper also runs inside the ubuntu:24.04 proof
          #  container, where the Nix bash path does not exist.
          colibri =
            if system == "x86_64-linux" then
              [
                (pkgs.stdenvNoCC.mkDerivation {
                  pname = "colibri";
                  version = "colibri2-0.6";
                  src = pkgs.fetchurl {
                    name = "colibri2-0.6-generate-static-artifacts.zip";
                    url = "https://git.frama-c.com/api/v4/projects/879/jobs/1970747/artifacts";
                    hash = "sha256-VycazpUOjL4LkUU+s+GmzIHz/AE43FuO/1dOeWLMpa4=";
                  };
                  nativeBuildInputs = [ pkgs.unzip ];
                  unpackPhase = "unzip -q $src";
                  dontBuild = true;
                  dontFixup = true;
                  dontPatchShebangs = true;
                  installPhase = ''
                    install -Dm755 bin/colibri2 $out/bin/colibri2
                    cat > $out/bin/colibri <<'EOF'
                    #!/bin/sh
                    # gnatprove's `colibri` prover entry (why3 colibri.drv) driving the colibri2 engine.
                    # COLIBRI v1 arguments -> colibri2: --memlimit MB => --size <MB>M, --steplimit N => --max-steps N.
                    args=""
                    while [ $# -gt 0 ]; do
                      case "$1" in
                        --memlimit) shift; args="$args --size ''${1}M" ;;
                        --steplimit) shift; args="$args --max-steps $1" ;;
                        --get-steps) args="$args --show-steps" ;;
                        *) args="$args $1" ;;
                      esac
                      shift
                    done
                    exec "$(dirname "$0")/colibri2" $args
                    EOF
                    chmod +x $out/bin/colibri
                  '';
                  meta = {
                    description = "colibri2 CP-based SMT solver, wrapped as gnatprove's `colibri` prover";
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
            packages = alirePackages ++ colibri ++ (with pkgs; [
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
