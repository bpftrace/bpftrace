{
  description = "High-level tracing language for Linux eBPF";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-24.05";
    flake-utils.url = "github:numtide/flake-utils";
    nix-appimage = {
      # Use fork until following PRs are in:
      #   https://github.com/ralismark/nix-appimage/pull/8
      #   https://github.com/ralismark/nix-appimage/pull/9
      url = "github:danobi/nix-appimage/83c61d93ee96d4d530f5382edca51ee30ce2769f";
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
          pkgs = import nixpkgs { inherit system; overlays = [ libbpfOverlay bccOverlay ]; };

          # Define lambda that returns a derivation for bpftrace given llvm package as input
          mkBpftrace =
            llvmPackages:
              with pkgs;
              pkgs.stdenv.mkDerivation rec {
                name = "bpftrace";

                src = self;

                nativeBuildInputs = [ cmake ninja bison flex gcc clang ];

                buildInputs = with llvmPackages;
                  [
                    asciidoctor
                    bcc
                    cereal
                    elfutils
                    gtest
                    libbpf
                    libbfd
                    libclang
                    libelf
                    libffi
                    libopcodes
                    libpcap
                    libsystemtap
                    lldb
                    llvm
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
                buildInputs = pkg.nativeBuildInputs ++ pkg.buildInputs ++ [
                  binutils
                  coreutils
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
                  strace
                  util-linux
                ];
              };
        in
        {
          # Set formatter for `nix fmt` command
          formatter = pkgs.nixpkgs-fmt;

          # Define package set
          packages = rec {
            # Default package is latest supported LLVM release
            default = bpftrace-llvm18;

            # Support matrix of llvm versions
            bpftrace-llvm18 = mkBpftrace pkgs.llvmPackages_18;
            bpftrace-llvm17 = mkBpftrace pkgs.llvmPackages_17;
            bpftrace-llvm16 = mkBpftrace pkgs.llvmPackages_16;
            bpftrace-llvm15 = mkBpftrace pkgs.llvmPackages_15;
            bpftrace-llvm14 = mkBpftrace pkgs.llvmPackages_14;
            bpftrace-llvm13 = mkBpftrace pkgs.llvmPackages_13;

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
            default = bpftrace-llvm18;

            bpftrace-llvm18 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm18;
            bpftrace-llvm17 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm17;
            bpftrace-llvm16 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm16;
            bpftrace-llvm15 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm15;
            bpftrace-llvm14 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm14;
            bpftrace-llvm13 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm13;
          };
        });
}
