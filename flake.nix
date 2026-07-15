{
  description = "xenia-peer — peer-to-peer, consciousness-first remote-session stack. Wayland + H.264 dev shell.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = pkgs.lib;

        # ffmpeg_7 is pinned deliberately. ffmpeg-next 7.x ships bindings
        # up through ffmpeg_7_1; nixpkgs' default `ffmpeg` may drift at the
        # API call sites. Keep this explicit until xenia-video's H.264 backend
        # is validated against newer libav releases.
        ffmpeg = pkgs.ffmpeg_7;

        pkgConfigPath = lib.makeSearchPathOutput "dev" "lib/pkgconfig" [
          ffmpeg
          pkgs.alsa-lib
          pkgs.dbus
          pkgs.libopus
          pkgs.pipewire
        ];

        runtimeLibraryPath = lib.makeLibraryPath [
          pkgs.wayland
          pkgs.libxkbcommon
          pkgs.libGL
        ];

        commonNativeBuildInputs = with pkgs; [
          pkg-config
          cmake
          llvmPackages.libclang
          git
        ];

        rustCoreTools = with pkgs; [
          rustc
          cargo
          rustfmt
          clippy
        ];

        rustDevTools = with pkgs; [
          rust-analyzer
        ];

        auditTools = with pkgs; [
          cargo-audit
          cargo-deny
          cargo-nextest
          cargo-llvm-cov
          ripgrep
          jq
        ];

        webTools = with pkgs; [
          trunk
          wasm-bindgen-cli
          binaryen
        ];

        # Item 6 (docs/security/POST_DELEGATION_HARDENING_PLAN.md): the
        # browser-driven vertical-slice test. Python (not Node) drives
        # Playwright, matching this project's existing bias toward Python
        # for verification scripts; `playwright-driver.browsers` supplies
        # pre-fetched, `autoPatchelfHook`-patched browser binaries, which is
        # the idiomatic NixOS-recommended path and avoids needing a
        # `buildFHSEnv` wrapper (Playwright's own bundled browsers need real
        # FHS dynamic-linker paths, which pure Nix binaries don't have).
        # `pexpect` drives `xenia-operator-agent`'s interactive host-trust
        # confirmation prompt over a real pseudo-terminal -- a plain piped
        # subprocess stdin does not satisfy `is_terminal()` and would
        # silently take the noninteractive-refusal path instead of the real
        # approval path this test exists to exercise.
        e2eTools = with pkgs; [
          (python3.withPackages (ps: [ ps.playwright ps.pexpect ]))
          playwright-driver.browsers
        ];

        # Heap-profiling tools for chasing real memory growth (e.g. the
        # scap/dbus-rs Linux capture leak documented in ROADMAP.md).
        # heaptrack is the default choice -- much lower overhead than
        # valgrind/massif, which matters here since the repro involves
        # real-time D-Bus/PipeWire interaction that heavy instrumentation
        # can visibly slow down or change the timing of. valgrind is kept
        # too for cases heaptrack's sampling approach doesn't suit.
        profilingTools = with pkgs; [
          heaptrack
          valgrind
        ];

        mediaAndPlatformInputs = with pkgs; [
          # ffmpeg for the `h264` feature. Both the full package (for the
          # `ffmpeg` binary, useful for manual debugging) and the dev output
          # (for pkg-config discovery).
          ffmpeg
          ffmpeg.dev

          # Native audio deps for CPAL capture/playback and Opus codec checks.
          alsa-lib
          alsa-lib.dev
          libopus
          libopus.dev

          # Wayland + DBus deps for capture/viewer backends.
          wayland
          wayland-protocols
          wayland-scanner
          libxkbcommon
          libGL
          dbus
          dbus.dev
          pipewire
          pipewire.dev
        ];

        xeniaEnv = ''
          export PKG_CONFIG_PATH="${pkgConfigPath}:''${PKG_CONFIG_PATH:-}"
          export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
          BINDGEN_EXTRA_CLANG_ARGS="$(< ${pkgs.stdenv.cc}/nix-support/libc-cflags) $(< ${pkgs.stdenv.cc}/nix-support/cc-cflags)"
          export BINDGEN_EXTRA_CLANG_ARGS
          export LD_LIBRARY_PATH="${runtimeLibraryPath}:''${LD_LIBRARY_PATH:-}"
          export RUST_SRC_PATH="${pkgs.rustPlatform.rustLibSrc}"
        '';

        mkValidationApp =
          name: description: commands:
          let
            script = pkgs.writeShellApplication {
              inherit name;
              runtimeInputs =
                commonNativeBuildInputs
                ++ rustCoreTools
                ++ mediaAndPlatformInputs
                ++ auditTools
                ++ [ pkgs.coreutils pkgs.nix pkgs.nixpkgs-fmt pkgs.python3 ];
              text = ''
                set -euo pipefail
                ${xeniaEnv}
                ${commands}
              '';
            };
          in
          {
            type = "app";
            program = "${script}/bin/${name}";
            meta.description = description;
          };

        mkXeniaShell =
          { name
          , includeDevTools ? true
          , includeAuditTools ? true
          , includeWebTools ? true
          , includeProfilingTools ? false
          }:
          pkgs.mkShell {
            inherit name;

            nativeBuildInputs = commonNativeBuildInputs;

            buildInputs =
              rustCoreTools
              ++ mediaAndPlatformInputs
              ++ lib.optionals includeDevTools rustDevTools
              ++ lib.optionals includeAuditTools auditTools
              ++ lib.optionals includeWebTools webTools
              ++ lib.optionals includeProfilingTools profilingTools;

            shellHook = ''
              ${xeniaEnv}

              # Preserve parent CARGO_TARGET_DIR for build isolation across
              # concurrent agent sessions.
              if [[ -z "''${CARGO_TARGET_DIR:-}" ]] && [[ -r "/proc/$PPID/environ" ]]; then
                _parent_target=$(tr '\0' '\n' < /proc/$PPID/environ 2>/dev/null | grep '^CARGO_TARGET_DIR=' | head -1 | cut -d= -f2-)
                if [[ -n "$_parent_target" ]] && [[ -d "$_parent_target" ]]; then
                  export CARGO_TARGET_DIR="$_parent_target"
                fi
              fi

              export RUST_BACKTRACE=1

              cat <<'BANNER'
              xenia-peer dev shell — H.264 + Wayland/PipeWire + audio deps ready.
                scripts/xenia-validate.sh .
                cargo test --workspace --features "xenia-peer/h264 xenia-viewer/h264"
                cargo build --release --workspace
              BANNER
            '';
          };
      in
      rec {
        devShells.default = mkXeniaShell {
          name = "xenia-peer-dev";
          includeDevTools = true;
          includeAuditTools = true;
          includeWebTools = true;
          includeProfilingTools = true;
        };

        # CI shell: same system libraries, but no rust-analyzer or browser build
        # tools. This makes the closure smaller and keeps the old comment true.
        devShells.ci = mkXeniaShell {
          name = "xenia-peer-ci";
          includeDevTools = false;
          includeAuditTools = true;
          includeWebTools = false;
        };

        # Web/admin shell: include Trunk/wasm tooling explicitly for browser UI
        # work without bloating CI jobs that only need Rust + system deps.
        devShells.web = mkXeniaShell {
          name = "xenia-peer-web";
          includeDevTools = true;
          includeAuditTools = true;
          includeWebTools = true;
        };

        # e2e shell: everything `web` has (Trunk builds the real
        # sovereign-admin console) plus Python/Playwright/pexpect for the
        # item-6 browser-driven vertical-slice test. Kept separate from
        # `web`/`ci` so ordinary Rust/web work never pays for the browser
        # binary closure.
        devShells.e2e = pkgs.mkShell {
          name = "xenia-peer-e2e";

          nativeBuildInputs = commonNativeBuildInputs;

          buildInputs =
            rustCoreTools
            ++ mediaAndPlatformInputs
            ++ rustDevTools
            ++ auditTools
            ++ webTools
            ++ e2eTools;

          shellHook = ''
            ${xeniaEnv}

            export RUST_BACKTRACE=1
            export PLAYWRIGHT_BROWSERS_PATH="${pkgs.playwright-driver.browsers}"
            export PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=true

            cat <<'BANNER'
            xenia-peer e2e shell — Playwright + pexpect ready for the item-6
            browser-driven vertical-slice test.
              scripts/xenia-e2e-vertical-slice.sh .
            BANNER
          '';
        };

        formatter = pkgs.nixpkgs-fmt;

        apps.fast = mkValidationApp "xenia-fast-check" "Fast Xenia Rust/protocol validation gate" ''
          scripts/xenia-fast-check.sh .
        '';

        apps.audio = mkValidationApp "xenia-audio-check" "Xenia audio feature validation gate" ''
          scripts/xenia-audio-check.sh .
        '';

        apps.full = mkValidationApp "xenia-full-check" "Full Xenia workspace validation gate" ''
          scripts/xenia-full-check.sh .
        '';

        apps.ci = mkValidationApp "xenia-ci-check" "Default Xenia CI validation gate" ''
          scripts/xenia-ci-check.sh .
        '';

        apps.e2e =
          let
            script = pkgs.writeShellApplication {
              name = "xenia-e2e-check";
              runtimeInputs =
                commonNativeBuildInputs
                ++ rustCoreTools
                ++ mediaAndPlatformInputs
                ++ auditTools
                ++ webTools
                ++ e2eTools
                ++ [ pkgs.coreutils pkgs.nix pkgs.nixpkgs-fmt ];
              text = ''
                set -euo pipefail
                ${xeniaEnv}
                export PLAYWRIGHT_BROWSERS_PATH="${pkgs.playwright-driver.browsers}"
                export PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=true
                scripts/xenia-e2e-vertical-slice.sh .
              '';
            };
          in
          {
            type = "app";
            program = "${script}/bin/xenia-e2e-check";
            meta.description = "Item 6: real browser-driven vertical-slice test (daemon + agent + console + Playwright)";
          };

        apps.default = apps.ci;

        checks.hygiene = pkgs.runCommand "xenia-hygiene-audit"
          {
            src = self;
            nativeBuildInputs = with pkgs; [ bash cargo coreutils findutils gnugrep gnused ripgrep ];
          } ''
          cp -R "$src" source
          chmod -R +w source
          cd source
          if [[ -f scripts/xenia-hygiene-audit.sh ]]; then
            bash scripts/xenia-hygiene-audit.sh .
          else
            echo "scripts/xenia-hygiene-audit.sh not present; skipping static hygiene check"
          fi
          touch "$out"
        '';
      });
}
