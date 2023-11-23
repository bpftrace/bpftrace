{
  description = "High-level tracing language for Linux eBPF";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-22.11";
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
          libbpfOverlay =
            (self: super: {
              libbpf_1 = super.libbpf_1.overrideAttrs (old: {
                # 1.3 is the next release as of (11/11/23)
                version = "1.3.0";
                src = super.fetchFromGitHub {
                  owner = "libbpf";
                  repo = "libbpf";
                  rev = "3189f70538b50fe3d2fd63f77351991a224e435b";
                  # If you don't know the hash the first time, set:
                  # hash = "";
                  # then nix will fail the build with such an error message:
                  # hash mismatch in fixed-output derivation '/nix/store/m1ga09c0z1a6n7rj8ky3s31dpgalsn0n-source':
                  # specified: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
                  # got:    sha256-173gxk0ymiw94glyjzjizp8bv8g72gwkjhacigd1an09jshdrjb4
                  sha256 = "sha256-nh1xs4jT/YCBq6uT4WbSJc6/BfMg1Ussd11aY1Nmlq4=";
                };
              });
            });

          # Overlay to specify build should use the specific bcc we want
          bccVersion = "0.27.0";
          bccOverlay =
            (self: super: {
              bcc = super.bcc.overridePythonAttrs (old: {
                version = bccVersion;
                src = super.fetchFromGitHub {
                  owner = "iovisor";
                  repo = "bcc";
                  rev = "v${bccVersion}";
                  sha256 = "sha256-+RK5RZcoNHlgMOFPgygRf2h+OZGxR9gJ+fTbYjDB6Ww=";
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

                nativeBuildInputs = [ cmake ninja bison flex gcc12 clang ];

                buildInputs = with llvmPackages;
                  [
                    asciidoctor
                    bcc
                    cereal
                    elfutils
                    gtest
                    libbpf_1
                    libbfd
                    libclang
                    libelf
                    libffi
                    libopcodes
                    libpcap
                    libsystemtap
                    llvm
                    pahole
                    xxd
                    zlib
                  ];

                # Release flags
                cmakeFlags = [
                  "-DCMAKE_BUILD_TYPE=Release"
                ];
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
                  gnugrep
                  kmod
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
            default = bpftrace-llvm16;

            # Support matrix of llvm versions
            bpftrace-llvm16 = mkBpftrace pkgs.llvmPackages_16;
            bpftrace-llvm15 = mkBpftrace pkgs.llvmPackages_15;
            bpftrace-llvm14 = mkBpftrace pkgs.llvmPackages_14;
            bpftrace-llvm13 = mkBpftrace pkgs.llvmPackages_13;
            bpftrace-llvm12 = mkBpftrace pkgs.llvmPackages_12;
            bpftrace-llvm11 = mkBpftrace pkgs.llvmPackages_11;
            bpftrace-llvm10 = mkBpftrace pkgs.llvmPackages_10;

            # Self-contained static binary with all dependencies
            appimage = nix-appimage.mkappimage.${system} {
              drv = default;
              entrypoint = pkgs.lib.getExe default;
              name = default.name;

              # Exclude the following groups to reduce appimage size:
              #
              # *.a: Static archives are not necessary at runtime
              # *.pyc, *.py, *.whl: bpftrace does not use python at runtime
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
                "... *.pyc"
                "... *.py"
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
            default = bpftrace-llvm16;

            bpftrace-llvm16 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm16;
            bpftrace-llvm15 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm15;
            bpftrace-llvm14 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm14;
            bpftrace-llvm13 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm13;
            bpftrace-llvm12 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm12;
            bpftrace-llvm11 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm11;
            bpftrace-llvm10 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm10;
          };
        });
}
