{
  description = "UserSU flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    android-nixpkgs.url = "github:tadfisher/android-nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, android-nixpkgs }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Android SDK with NDK
        android-sdk = android-nixpkgs.sdk.${system} (sdkPkgs: with sdkPkgs; [
          cmdline-tools-latest
          build-tools-34-0-0
          platform-tools
          platforms-android-34
          ndk-26-1-10909125
        ]);

        # The cross compilers you want to expose
        crossCompilers = with pkgs.pkgsCross; [
          aarch64-multiplatform.buildPackages.gcc
          armv7l-hf-multiplatform.buildPackages.gcc
          riscv64.buildPackages.gcc
        ];
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            gcc
            clang
            llvm
            rustup
            gnumake
            just
            gdb
            python314
            uv
            gradle
            openjdk17
            android-sdk
            kotlin
            jdk17
          ] ++ crossCompilers;

          shellHook = ''
            echo "⚙️  Welcome to UserSU DevShell"
            echo "Available cross-compilers:"
            echo "  - aarch64-linux-gnu-gcc"
            echo "  - armv7l-linux-gnu-gcc"
#            echo "  - riscv64-linux-gnu-gcc"
            echo ""
            echo "Android NDK available at: $ANDROID_HOME/ndk/*"
            echo ""

            export CC=gcc
            export CXX=g++
            export JAVA_HOME=${pkgs.openjdk17}
            export PATH=$JAVA_HOME/bin:$PATH
            export GRADLE_OPTS="-Dorg.gradle.daemon=false"

            # Android environment
            export ANDROID_HOME="${android-sdk}/share/android-sdk"
            export ANDROID_SDK_ROOT="$ANDROID_HOME"

            # Find NDK directory
            export ANDROID_NDK_ROOT="$ANDROID_HOME/ndk/26.1.10909125"

            # Add NDK toolchain to PATH
            if [ -d "$ANDROID_NDK_ROOT" ]; then
              export PATH="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
              echo "✓ Android NDK added to PATH"
            else
              echo "⚠ Android NDK not found at $ANDROID_NDK_ROOT"
            fi

            # Cargo configuration for Android
            mkdir -p .cargo
            cat > .cargo/config.toml << 'EOF'
[target.armv7-linux-androideabi]
linker = "armv7a-linux-androideabi21-clang"
ar = "llvm-ar"

[target.aarch64-linux-android]
linker = "aarch64-linux-android21-clang"
ar = "llvm-ar"

[target.i686-linux-android]
linker = "i686-linux-android21-clang"
ar = "llvm-ar"

[target.x86_64-linux-android]
linker = "x86_64-linux-android21-clang"
ar = "llvm-ar"
EOF
            echo "✓ Created .cargo/config.toml for Android cross-compilation"

            gradle2nix() {
              nix run github:tadfisher/gradle2nix -- "$@"
            }

            # Install cargo-ndk if not present
            if ! command -v cargo-ndk &> /dev/null; then
              echo "Installing cargo-ndk..."
              cargo install cargo-ndk
            fi
          '';
        };
      });
}
