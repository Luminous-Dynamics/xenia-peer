{
  description = "xenia-peer — peer-to-peer, consciousness-first remote-session stack. Wayland + H.264 dev shell.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # ffmpeg_7 is pinned deliberately. ffmpeg-next 7.x ships bindings
        # up through ffmpeg_7_1; nixpkgs' default `ffmpeg` is 8.x which
        # compiles but drifts at the API call sites (matches Symthaea's
        # experience in Phase I.B — see the symthaea flake for the
        # regression log).
        ffmpeg = pkgs.ffmpeg_7;

      in {
        devShells.default = pkgs.mkShell {
          name = "xenia-peer-dev";

          # Native build-tool deps (runtime: see buildInputs for libs).
          nativeBuildInputs = with pkgs; [
            pkg-config
            # bindgen (used by ffmpeg-sys-next via the `h264` feature) needs
            # libclang to parse libav headers. Without it the build fails
            # with "Unable to find libclang" mid-build-script.
            llvmPackages.libclang
          ];

          buildInputs = with pkgs; [
            # Rust toolchain — stable matches the xenia-peer-core MSRV (1.85).
            rustc
            cargo
            rust-analyzer
            rustfmt
            clippy

            # ffmpeg for the `h264` feature. Both the full package (for
            # the `ffmpeg` binary, useful for manual debugging) and the
            # dev output (for pkg-config discovery).
            ffmpeg
            ffmpeg.dev

            # Wayland + DBus deps for the upcoming M1.2c capture backends
            # (wlr-screencopy + xdg-desktop-portal ScreenCast). Installed
            # now so the `wayland-wlroots` and `wayland-portal` features
            # build inside this shell once their impls land.
            wayland
            wayland-protocols
            wayland-scanner
            libxkbcommon
            dbus
            dbus.dev
            pipewire
            pipewire.dev

            # Misc
            git
          ];

          shellHook = ''
            # pkg-config needs to see libav's .pc files + dbus + pipewire.
            export PKG_CONFIG_PATH="${ffmpeg.dev}/lib/pkgconfig:${pkgs.dbus.dev}/lib/pkgconfig:${pkgs.pipewire.dev}/lib/pkgconfig:$PKG_CONFIG_PATH"

            # bindgen needs libclang on PATH-equivalent + glibc cflags so
            # its internal clang can find errno.h and friends.
            export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
            export BINDGEN_EXTRA_CLANG_ARGS="$(< ${pkgs.stdenv.cc}/nix-support/libc-cflags) $(< ${pkgs.stdenv.cc}/nix-support/cc-cflags)"

            # Preserve parent CARGO_TARGET_DIR for build isolation across
            # concurrent sessions (matches Symthaea's shellHook pattern).
            if [[ -z "''${CARGO_TARGET_DIR:-}" ]] && [[ -r "/proc/$PPID/environ" ]]; then
              _parent_target=$(tr '\0' '\n' < /proc/$PPID/environ 2>/dev/null | grep '^CARGO_TARGET_DIR=' | head -1 | cut -d= -f2-)
              if [[ -n "$_parent_target" ]] && [[ -d "$_parent_target" ]]; then
                export CARGO_TARGET_DIR="$_parent_target"
              fi
            fi

            export RUST_BACKTRACE=1

            cat <<'BANNER'
            xenia-peer dev shell — H.264 + Wayland deps ready.
              cargo test --workspace --features "xenia-peer/h264 xenia-viewer/h264"
              cargo build --release --workspace
            BANNER
          '';
        };

        # Convenience: expose a minimal CI shell that's the same as
        # `default` minus the rust-analyzer / clippy dev tools. CI
        # workflows can use `nix develop .#ci` for smaller closures.
        devShells.ci = self.devShells.${system}.default.overrideAttrs (old: {
          buildInputs = old.buildInputs ++ [ ];
        });
      });
}
