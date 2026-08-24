{
  description = "hhm-desktop-app.rs reproducible Rust, FFI, UI, and SOPS development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    ores-sops.url = "github:ORESoftware/ores-sops";
  };

  outputs = { self, nixpkgs, flake-utils, ores-sops }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ ores-sops.overlays.default ];
        };
        linuxUiPackages = pkgs.lib.optionals pkgs.stdenv.isLinux (with pkgs; [
          fontconfig
          freetype
          libxkbcommon
          wayland
          xorg.libX11
          xorg.libXcursor
          xorg.libXi
          xorg.libXrandr
        ]);
      in {
        devShells.default = pkgs.mkShell {
          name = "hhm-desktop-app";
          packages = (with pkgs; [
            age
            cargo
            cargo-audit
            cbindgen
            clang
            clippy
            git
            just
            pkg-config
            pkgs.ores-sops
            rustc
            rustfmt
            sops
          ]) ++ linuxUiPackages;

          shellHook = ores-sops.lib.shellHook + ''
            export SLINT_BACKEND="''${SLINT_BACKEND:-winit-software}"
          '';
        };
      });
}
