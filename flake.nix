{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let pkgs = import nixpkgs { inherit system; }; in
        rec {
          packages.bandaid = pkgs.stdenv.mkDerivation {
            name = "bandaid";
            src = self;
            nativeBuildInputs = with pkgs;[
              stdenv.cc
              meson
              ninja
              pkg-config
            ];
            buildInputs = with pkgs;[
              systemd
              libseccomp
            ];
          };
          devShell = pkgs.mkShell {
            inputsFrom = [ packages.bandaid ];
          };
        });
}
