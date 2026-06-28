{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    pkg-config
    fuse
    fuse3
    cargo
    rustc
    rustfmt
    ansible
    (python3.withPackages (ps: [ ps.pytest ]))
  ];
}
