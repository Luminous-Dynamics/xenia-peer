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
          cargo-vet
          cargo-nextest
          cargo-llvm-cov
          ripgrep
          jq
        ];

        webTools = with pkgs; [
          trunk
          wasm-bindgen-cli
          binaryen
          # nixpkgs' rustc/cargo derivation sets
          # CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER=lld via its own
          # setup hook (not something this flake or the repo configures),
          # so any wasm32 build under this flake's shells needs a real
          # `lld` binary on PATH regardless of whether the host machine
          # happens to have one system-wide. Found live: this worked on
          # a NixOS dev machine with system-wide lld/mold, then failed in
          # GitHub Actions (a bare ubuntu-latest runner) with
          # "error: linker `lld` not found" the first time `trunk build`
          # actually ran there.
          lld
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

        # Nix-hermetic builds of the two host binaries, default features
        # only (no h264/audio-capture/scap/xdg-portal/uinput -- matches
        # what the existing GitHub Actions `network-chaos`/e2e jobs already
        # exercise via plain `cargo build`). Exist primarily so nixosTest
        # VMs (see checks.network-vm-nat below) have something real to
        # install as a systemPackage -- Nix VMs are hermetic and can't see
        # a host `target/release` the way a bare CI runner can. `doCheck`
        # is off: correctness is already covered by the extensive
        # cargo-test-based CI jobs; this derivation's only job is producing
        # a working binary.
        #
        # Filtered to just the Cargo-relevant paths -- not `self` wholesale
        # -- so editing flake.nix's own non-Rust bits (e.g. a nixosTest
        # testScript below) doesn't change this derivation's source hash
        # and force a from-scratch Cargo rebuild on every iteration.
        rustWorkspaceSrc = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./apps ./crates ];
        };

        packages.xenia-peer = pkgs.rustPlatform.buildRustPackage {
          pname = "xenia-peer";
          version = "0.0.0-dev";
          src = rustWorkspaceSrc;
          cargoLock = {
            lockFile = ./Cargo.lock;
            # xenia-capture's optional `scap` backend is a git dependency;
            # Cargo.lock alone doesn't give Nix a fixed-output-derivation
            # hash for it, even though scap-backend isn't enabled here.
            outputHashes = {
              "scap-0.1.0-beta.1" = "sha256-r6QlXBJMVaBrVFi2ATBC8jinPNug6LFRvPmbLT3rJX0=";
            };
          };
          nativeBuildInputs = commonNativeBuildInputs ++ [ pkgs.makeWrapper ];
          buildInputs = mediaAndPlatformInputs;
          # preprod-fixtures gates `--m1-preprod-auto-consent`, needed so a
          # scripted VM test can complete a session without a human
          # clicking through the real consent UI.
          cargoBuildFlags = [ "--package" "xenia-peer" "--features" "preprod-fixtures" ];
          doCheck = false;
          postFixup = ''
            wrapProgram $out/bin/xenia-peer --prefix LD_LIBRARY_PATH : "${runtimeLibraryPath}"
          '';
          meta.description = "Xenia daemon binary, Nix-packaged (default features + preprod-fixtures). Built for nixosTest Tier 1 VM scenarios.";
        };

        packages.xenia-viewer = pkgs.rustPlatform.buildRustPackage {
          pname = "xenia-viewer";
          version = "0.0.0-dev";
          src = rustWorkspaceSrc;
          cargoLock = {
            lockFile = ./Cargo.lock;
            # xenia-capture's optional `scap` backend is a git dependency;
            # Cargo.lock alone doesn't give Nix a fixed-output-derivation
            # hash for it, even though scap-backend isn't enabled here.
            outputHashes = {
              "scap-0.1.0-beta.1" = "sha256-r6QlXBJMVaBrVFi2ATBC8jinPNug6LFRvPmbLT3rJX0=";
            };
          };
          nativeBuildInputs = commonNativeBuildInputs ++ [ pkgs.makeWrapper ];
          buildInputs = mediaAndPlatformInputs;
          cargoBuildFlags = [ "--package" "xenia-viewer" ];
          doCheck = false;
          postFixup = ''
            wrapProgram $out/bin/xenia-viewer --prefix LD_LIBRARY_PATH : "${runtimeLibraryPath}"
          '';
          meta.description = "Xenia viewer binary (CLI path used for scripted tests; GUI deps compiled in but unused headlessly), Nix-packaged. Built for nixosTest Tier 1 VM scenarios.";
        };

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

        # Tier 1 of the network-reliability testing plan (Tier 0 is
        # scripts/xenia-network-chaos-smoke.sh, wired into xenia-validate.yml).
        # Two genuinely separate NixOS VMs -- distinct kernels and network
        # stacks, unlike Tier 0's shared-kernel network-namespace approach --
        # proving a real cross-machine session, and that daemon state (the
        # consent ledger + operator/identity keys) survives a hard VM
        # reboot, not just a process restart. Deliberately does not attempt
        # NAT traversal / iroh relay testing here: that needs real relay
        # infrastructure this sandboxed test can't reach, so it's left out
        # rather than half-built.
        checks.network-vm = pkgs.testers.runNixOSTest {
          name = "xenia-network-vm";

          nodes = {
            daemonNode = { ... }: {
              virtualisation.vlans = [ 1 ];
              networking.interfaces.eth1.ipv4.addresses = [
                { address = "192.168.1.1"; prefixLength = 24; }
              ];
              networking.firewall.allowedTCPPorts = [ 17890 ];
              environment.systemPackages = [ self.packages.${system}.xenia-peer ];
            };
            viewerNode = { ... }: {
              virtualisation.vlans = [ 1 ];
              networking.interfaces.eth1.ipv4.addresses = [
                { address = "192.168.1.2"; prefixLength = 24; }
              ];
              environment.systemPackages = [ self.packages.${system}.xenia-viewer ];
            };
          };

          testScript = ''
            # NixOS test driver's wait_for_open_port() does a real TCP
            # connect()+close() to probe. xenia-peer's daemon (pre-alpha,
            # single-session-only) treats any accepted connection as a real
            # client and exits when it disconnects -- so a "just checking"
            # probe kills the daemon before the real viewer ever connects.
            # Same bug class as Tier 0's chaos script; fixed the same way:
            # poll /proc/net/tcp for LISTEN state instead of connecting.
            # 17890 decimal == 45E2 hex.
            def wait_for_daemon_listening(machine):
                machine.wait_until_succeeds(
                    "awk 'NR>1 {print $2, $4}' /proc/net/tcp | grep -qi ':45E2 0A'"
                )

            state_dir = "/var/lib/xenia-test-state"
            daemon_cmd = (
                "xenia-peer --transport tcp --listen 0.0.0.0:17890 "
                "--admin-port 0 --consent-port 0 --frames 12 --fps 30 "
                "--telemetry-level off --m1-preprod-auto-consent "
                f"--operator-key-path {state_dir}/operator.key "
                f"--consent-ledger-path {state_dir}/consent.ledger "
                f"--m1-consent-key-path {state_dir}/consent-ledger.key "
                f"--host-identity-key-path {state_dir}/host-identity.key "
                f"--http-auth-ml-dsa-key-path {state_dir}/operator-http-ml-dsa.key"
            )
            viewer_cmd = (
                "timeout 60 xenia-viewer --transport tcp --connect 192.168.1.1:17890 "
                "--frames 8 --codec passthrough --verify"
            )

            start_all()
            daemonNode.wait_for_unit("multi-user.target")
            viewerNode.wait_for_unit("multi-user.target")
            daemonNode.succeed(f"mkdir -p {state_dir}")

            with subtest("cross-VM session completes with byte-exact frames"):
                daemonNode.succeed(f"{daemon_cmd} > /tmp/daemon-1.log 2>&1 &")
                wait_for_daemon_listening(daemonNode)
                out = viewerNode.succeed(f"{viewer_cmd} 2>&1 | tee /tmp/viewer-1.log")
                assert "fail" not in out.lower() and "mismatch" not in out.lower() and "panic" not in out.lower(), (
                    f"viewer session 1 showed a failure signature:\n{out}"
                )
                # Stop the daemon cleanly (SIGTERM, wait for exit) before
                # the VM reboots below -- a hard VM shutdown SIGKILLs
                # whatever's still running, which is a real risk for any
                # buffered-but-not-yet-flushed state.
                daemonNode.succeed("pkill -TERM xenia-peer || true")
                daemonNode.wait_until_fails("pgrep xenia-peer")

            # --m1-preprod-auto-consent only bypasses an in-memory M1
            # consent gate (M1RuntimeSession::grant_consent()) -- it does
            # NOT write consent.ledger, which is only ever populated by the
            # HTTP consent-server flow (an operator agent / browser POSTing
            # a real decision), not exercised by this pure-CLI session.
            # What genuinely is created and reused on every daemon startup,
            # unconditionally, is the host identity keypair
            # (load_or_create_host_identity(), called before any consent
            # gating). That's the real persistence claim worth testing:
            # does the daemon keep the same identity across a reboot,
            # rather than silently regenerating a new one (which would
            # break every viewer's pinned host fingerprint).
            identity_path = f"{state_dir}/host-identity.key"

            with subtest("daemon identity key survives a hard VM reboot unchanged"):
                identity_before = daemonNode.succeed(f"sha256sum {identity_path}").split()[0]
                daemonNode.shutdown()
                daemonNode.start()
                daemonNode.wait_for_unit("multi-user.target")
                daemonNode.succeed(f"test -s {identity_path}")
                identity_after = daemonNode.succeed(f"sha256sum {identity_path}").split()[0]
                assert identity_before == identity_after, (
                    f"host identity key changed across reboot: {identity_before} -> {identity_after}"
                )

            with subtest("a fresh session succeeds post-reboot using the persisted keys"):
                daemonNode.succeed(f"{daemon_cmd} > /tmp/daemon-2.log 2>&1 &")
                wait_for_daemon_listening(daemonNode)
                out = viewerNode.succeed(f"{viewer_cmd} 2>&1 | tee /tmp/viewer-2.log")
                assert "fail" not in out.lower() and "mismatch" not in out.lower() and "panic" not in out.lower(), (
                    f"viewer session 2 (post-reboot) showed a failure signature:\n{out}"
                )
          '';
        };
      });
}
