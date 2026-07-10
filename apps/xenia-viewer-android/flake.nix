# Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Android build environment for the Xenia mobile viewer app. Adapted
# from symthaea-soma's proven Gradle/Kotlin/JNI/NDK flake
# (symthaea/crates/domains/symthaea-soma/android/flake.nix) -- same
# SDK/NDK provisioning approach, without Soma's LiteRT-specific build
# steps (Xenia's Rust core has no on-device inference dependency).
{
  description = "Xenia Android viewer — mobile build environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
          config.android_sdk.accept_license = true;
          overlays = [ rust-overlay.overlays.default ];
        };

        androidComposition = pkgs.androidenv.composeAndroidPackages {
          platformVersions = [ "34" ];
          buildToolsVersions = [ "34.0.0" ];
          cmakeVersions = [ "3.22.1" ];
          includeNDK = true;
          ndkVersions = [ "27.0.12077973" ];
          includeEmulator = false;
          includeSources = false;
          includeSystemImages = false;
        };
        androidSdk = androidComposition.androidsdk;
        ndkRoot = "${androidSdk}/libexec/android-sdk/ndk/27.0.12077973";
        ndkToolchain = "${ndkRoot}/toolchains/llvm/prebuilt/linux-x86_64";

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "clippy" "rustfmt" ];
          targets = [ "aarch64-linux-android" ];
        };

        jdk = pkgs.jdk17;

      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            rustToolchain
            androidSdk
            jdk
            pkgs.gradle
            pkgs.pkg-config
            pkgs.cacert
            pkgs.jq
          ];

          ANDROID_NDK_HOME = ndkRoot;
          ANDROID_HOME = "${androidSdk}/libexec/android-sdk";
          ANDROID_SDK_ROOT = "${androidSdk}/libexec/android-sdk";
          JAVA_HOME = "${jdk}";
          GRADLE_OPTS = "-Dorg.gradle.daemon=false";

          CC_aarch64_linux_android = "${ndkToolchain}/bin/aarch64-linux-android24-clang";
          AR_aarch64_linux_android = "${ndkToolchain}/bin/llvm-ar";
          CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "${ndkToolchain}/bin/aarch64-linux-android24-clang";

          shellHook = ''
            echo ""
            echo "╔═══════════════════════════════════════════════════════════════╗"
            echo "║     XENIA ANDROID VIEWER                                      ║"
            echo "║     Mobile build environment                                   ║"
            echo "╚═══════════════════════════════════════════════════════════════╝"
            echo ""
            echo "  Rust:    $(rustc --version)"
            echo "  NDK:     ${ndkRoot}"
            echo "  SDK:     ${androidSdk}/libexec/android-sdk"
            echo ""
            echo "  Phase 0 proof (no Gradle/JNI):"
            echo "    cargo build --target aarch64-linux-android --release -p xenia-mobile-ffi --bin xenia_mobile_smoke"
            echo "    adb push \$(cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')/aarch64-linux-android/release/xenia_mobile_smoke /data/local/tmp/"
            echo "    adb shell /data/local/tmp/xenia_mobile_smoke <host:port> passthrough"
            echo ""
            echo "  Phase 1 — build + install the real app:"
            echo "    ./build-jni.sh"
            echo "    gradle assembleDebug"
            echo "    adb install -r build/outputs/apk/debug/xenia-viewer-android-debug.apk"
            echo ""
          '';
        };
      }
    );
}
