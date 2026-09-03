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
          #  COLIBRI (CEA LIST, LGPL-2.1): the constraint-programming SMT solver
          #  RecordFlux routes its 2**N `Fits_Into` arithmetic to, and the one
          #  SPARK Pro bundles. FSF gnatprove 16.1.0 already ships the why3
          #  driver (colibri.drv, with the native integer-power mapping) and
          #  the gnatprove.conf entry for `colibri`; only the binary is missing,
          #  so putting this on PATH is the whole integration
          #  (`gnatprove --prover=z3,cvc5,altergo,colibri`).
          #
          #  Source: Frama-C GitLab project pub/colibri, monthly release bundle
          #  (ECLiPSe-7 build). Fetched as a fixed-output derivation so the
          #  bytes are pinned. The bundle is an ELF binary depending only on
          #  the system glibc plus its COLIBRI/ and ECLIPSE/ runtime trees,
          #  which it locates relative to itself, so the WHOLE tree is
          #  installed and bin/colibri is a wrapper. dontFixup keeps the bytes
          #  as shipped (host glibc; on NixOS add autoPatchelfHook).
          #  Chosen over the static colibri2 (2026-09-03): gnatprove's stock
          #  colibri2.drv lacks the integer-power mapping, so colibri2 cannot
          #  prove the 2**Bits goals without a patched driver; v1 does with
          #  the stock driver and RecordFlux's own configuration.
          colibri =
            if system == "x86_64-linux" then
              [
                (pkgs.stdenvNoCC.mkDerivation {
                  pname = "colibri";
                  version = "2026.06";
                  src = pkgs.fetchurl {
                    name = "colibri.2026.06-e7.tbz";
                    url = "https://git.frama-c.com/api/v4/projects/804/packages/generic/colibri/2026.06/colibri.2026.06-e7.tbz";
                    hash = "sha256-UROzLleQoNMyGf0lvbZnozpF/l2/MlUVFwmnvIBabck=";
                  };
                  dontBuild = true;
                  dontFixup = true;
                  dontPatchShebangs = true;
                  installPhase = ''
                    mkdir -p $out/opt/colibri $out/bin
                    cp -r . $out/opt/colibri/
                    cat > $out/bin/colibri <<EOF
                    #!${pkgs.runtimeShell}
                    exec $out/opt/colibri/colibri "\$@"
                    EOF
                    chmod +x $out/bin/colibri
                  '';
                  meta = {
                    description = "COLIBRI constraint-programming SMT solver (CEA LIST), release bundle";
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
