{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let pkgs = import nixpkgs { inherit system; }; in
        {
          devShell = pkgs.mkShell {
            nativeBuildInputs = with pkgs;[
              stdenv.cc
            ];
            buildInputs = with pkgs;[
              systemd
              libseccomp
            ];
          };
        });
}
