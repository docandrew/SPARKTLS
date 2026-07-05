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

            shellHook = ''
              echo "SPARKTLS dev shell: use ci/check.sh for the reproducible CI lane."
            '';
          };
        }
      );
    };
}
