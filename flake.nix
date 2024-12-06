{
  description = "High-level tracing language for Linux";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    nix-appimage = {
      # We're maintaining a fork b/c upstream is missing support for 24.11
      # and has also dropped the following feature we depend on:
      #   https://github.com/ralismark/nix-appimage/pull/9
      #
      # Also b/c appimage-runtime (which nix-appimage depends on) has a bug
      # that's being fixed in:
      #   https://github.com/AppImageCrafters/appimage-runtime/pull/14
      url = "github:danobi/nix-appimage/74e44691812b4f220e84fd89895931ff4f904a03";
      # Avoid multiple copies of the same dependency
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = { self, nixpkgs, flake-utils, nix-appimage, ... }:
    # This flake only supports 64-bit linux systems.
    # Note bpftrace support aarch32 but for simplicity we'll omit it for now.
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ]
      (system:
        let
          # The default LLVM version is the latest supported release
          defaultLlvmVersion = 18;

          # Overlay to specify build should use the specific libbpf we want
          libbpfVersion = "1.4.2";
          libbpfOverlay =
            (self: super: {
              libbpf = super.libbpf.overrideAttrs (old: {
                version = libbpfVersion;
                src = super.fetchFromGitHub {
                  owner = "libbpf";
                  repo = "libbpf";
                  # We need libbpf support for "module:function" syntax for
                  # fentry/fexit probes. This is not released, yet, hence we pin
                  # to a specific commit for now. Once the next release is out,
                  # we should move to the corresponding version (likely 1.5.0).
                  rev = "dd589c3b31c13164bdc61ed174fbae6fe76c8308";
                  # If you don't know the hash the first time, set:
                  # hash = "";
                  # then nix will fail the build with such an error message:
                  # hash mismatch in fixed-output derivation '/nix/store/m1ga09c0z1a6n7rj8ky3s31dpgalsn0n-source':
                  # specified: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
                  # got:    sha256-173gxk0ymiw94glyjzjizp8bv8g72gwkjhacigd1an09jshdrjb4
                  sha256 = "sha256-zreQ18XLzk65w1TxCbL7RUdmzABYSSlfsGBKq2CvvXE=";
                };
              });
            });

          # Overlay to specify build should use the specific bcc we want
          bccVersion = "0.30.0";
          bccOverlay =
            (self: super: {
              bcc = super.bcc.overridePythonAttrs (old: {
                version = bccVersion;
                src = super.fetchFromGitHub {
                  owner = "iovisor";
                  repo = "bcc";
                  rev = "v${bccVersion}";
                  sha256 = "sha256-ngGLGfLv2prnjhgaRPf8ea3oyy4129zGodR0Yz1QtCw=";
                };
                # Seems like these extra tools are needed to build bcc
                nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.python310Packages.setuptools pkgs.zip ];
              });
            });

          # We need to use two overlays so that bcc inherits the our pinned libbpf
          overlayedPkgs = import nixpkgs { inherit system; overlays = [ libbpfOverlay bccOverlay ]; };

          pkgs = import nixpkgs { inherit system; };

          # Define lambda that returns a derivation for bpftrace given llvm version as input
          mkBpftrace =
            llvmVersion:
              with pkgs;
              pkgs.stdenv.mkDerivation rec {
                name = "bpftrace";

                src = self;

                nativeBuildInputs = [ cmake ninja bison flex gcc clang ];

                buildInputs = [
                  asciidoctor
                  cereal
                  elfutils
                  gtest
                  libbfd
                  libelf
                  libffi
                  libopcodes
                  libpcap
                  libsystemtap
                  pkgs."llvmPackages_${toString llvmVersion}".libclang
                  pkgs."llvmPackages_${toString llvmVersion}".lldb
                  pkgs."llvmPackages_${toString llvmVersion}".llvm
                  overlayedPkgs.bcc
                  overlayedPkgs.libbpf
                  pahole
                  xxd
                  zlib
                ];

                # Release flags
                cmakeFlags = [
                  "-DCMAKE_BUILD_TYPE=Release"
                ];

                # Technically not needed cuz package name matches mainProgram, but
                # explicit is fine too.
                meta.mainProgram = "bpftrace";
              };

          # Define lambda that returns a devShell derivation with extra test-required packages
          # given the bpftrace package derivation as input
          mkBpftraceDevShell =
            pkg:
              with pkgs;
              pkgs.mkShell {
                buildInputs = [
                  binutils
                  coreutils
                  # Needed for the nix-aware "wrapped" clang-tidy
                  clang-tools
                  findutils
                  gawk
                  git
                  gnugrep
                  kmod
                  # For git-clang-format
                  libclang.python
                  nftables
                  procps
                  python3
                  python3Packages.looseversion
                  strace
                  unixtools.ping
                  util-linux
                ] ++ pkg.nativeBuildInputs ++ pkg.buildInputs;

                # Some hardening features (like _FORTIFY_SOURCE) requires building with
                # optimizations on. That's fine for actual flake build, but for most of the
                # dev builds we do in nix shell, it just causes warning spew.
                hardeningDisable = [ "all" ];
              };
        in
        {
          # Set formatter for `nix fmt` command
          formatter = pkgs.nixpkgs-fmt;

          # Define package set
          packages = rec {
            default = self.packages.${system}."bpftrace-llvm${toString defaultLlvmVersion}";

            # Support matrix of llvm versions
            bpftrace-llvm18 = mkBpftrace 18;
            bpftrace-llvm17 = mkBpftrace 17;
            bpftrace-llvm16 = mkBpftrace 16;
            bpftrace-llvm15 = mkBpftrace 15;
            bpftrace-llvm14 = mkBpftrace 14;
            bpftrace-llvm13 = mkBpftrace 13;

            # Self-contained static binary with all dependencies
            appimage = nix-appimage.mkappimage.${system} {
              drv = default;
              entrypoint = pkgs.lib.getExe default;
              name = default.name;

              # Exclude the following groups to reduce appimage size:
              #
              # *.a: Static archives are not necessary at runtime
              # *.h: Header files are not necessary at runtime (some ARM headers for clang are large)
              # *.pyc, *.whl: bpftrace does not use python at runtime (with exception
              #               of stdlib for unfortunate lldb python bindings)
              # libLLVM-11.so: Appimage uses the latest llvm we support, so not llvm11
              #
              # The basic process to identify large and useless files is to:
              #
              # ```
              # $ nix build .#appimage
              # $ ./result --appimage-mount
              # $ cd /tmp/.mount_resultXXXX    # in new terminal
              # $ fd -S +1m -l
              # ```
              exclude = [
                "... *.a"
                "... *.h"
                "... *.pyc"
                "... *.whl"
                "... libLLVM-11.so"
              ];
            };
          };

          # Define apps that can be run with `nix run`
          apps.default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/bpftrace";
          };

          devShells = rec {
            default = self.devShells.${system}."bpftrace-llvm${toString defaultLlvmVersion}";

            bpftrace-llvm18 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm18;
            bpftrace-llvm17 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm17;
            bpftrace-llvm16 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm16;
            bpftrace-llvm15 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm15;
            bpftrace-llvm14 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm14;
            bpftrace-llvm13 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm13;
          };
        });
}
