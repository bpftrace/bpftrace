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
          pkgs = import nixpkgs { inherit system; };

          # The default LLVM version is the latest supported release
          defaultLlvmVersion = 19;

          # Override to specify the libbpf build we want
          libbpfVersion = "1.5.0";
          libbpf = pkgs.libbpf.overrideAttrs {
            version = libbpfVersion;
            src = pkgs.fetchFromGitHub {
              owner = "libbpf";
              repo = "libbpf";
              rev = "v${libbpfVersion}";
              # If you don't know the hash the first time, set:
              # hash = "";
              # then nix will fail the build with such an error message:
              # hash mismatch in fixed-output derivation '/nix/store/m1ga09c0z1a6n7rj8ky3s31dpgalsn0n-source':
              # specified: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
              # got:    sha256-173gxk0ymiw94glyjzjizp8bv8g72gwkjhacigd1an09jshdrjb4
              sha256 = "sha256-+L/rbp0a3p4PHq1yTJmuMcNj0gT5sqAPeaNRo3Sh6U8=";
            };
          };

          # Override to specify the bcc build we want.
          # First overrides with the above libbpf and then overrides the rev.
          bccVersion = "0.33.0";
          bcc = (pkgs.bcc.override { libbpf = libbpf; }).overridePythonAttrs {
            version = bccVersion;
            src = pkgs.fetchFromGitHub {
              owner = "iovisor";
              repo = "bcc";
              rev = "v${bccVersion}";
              sha256 = "sha256-6dT3seLuEVQNKWiYGLK1ajXzW7pb62S/GQ0Lp4JdGjc=";
            };
          };

          # Download statically linked vmtest binary
          arch = pkgs.lib.strings.removeSuffix "-linux" system;
          vmtestVersion = "0.18.0";
          vmtest = pkgs.stdenv.mkDerivation {
            name = "vmtest";
            version = vmtestVersion;
            src = builtins.fetchurl {
              url = "https://github.com/danobi/vmtest/releases/download/v${vmtestVersion}/vmtest-${arch}";
              sha256 = "sha256:1wv49fq7n820jj7zyvbvrrzg2vwvyy8kb3gfw1lg55rzfqzhl9v3";
            };
            # Remove all other phases b/c we already have a prebuilt binary
            phases = [ "installPhase" ];
            installPhase = ''
              install -m755 -D $src $out/bin/vmtest
            '';
          };

          # Define lambda that returns a derivation for a kernel given kernel version and SHA as input
          mkKernel = kernelVersion: sha256:
            with pkgs;
            stdenv.mkDerivation rec {
              name = "kernel";
              version = kernelVersion;
              src = builtins.fetchurl {
                url = "https://github.com/bpftrace/kernels/releases/download/assets/linux-v${kernelVersion}.tar.zst";
                sha256 = sha256;
              };
              # Remove all other phases b/c we already have a prebuilt binary
              phases = [ "installPhase" ];
              installPhase = ''
                mkdir -p $out
                tar xvf $src --strip-components=1 -C $out
              '';
              nativeBuildInputs = [ gnutar zstd ];
            };

          # Define lambda that returns a derivation for bpftrace given llvm version as input
          mkBpftrace =
            llvmVersion:
              pkgs.stdenv.mkDerivation rec {
                name = "bpftrace";

                src = self;

                nativeBuildInputs = [
                  pkgs.bison
                  pkgs.clang
                  pkgs.cmake
                  pkgs.flex
                  pkgs.gcc
                  pkgs.ninja
                ];

                buildInputs = [
                  bcc
                  libbpf
                  pkgs.asciidoctor
                  pkgs.cereal
                  pkgs.elfutils
                  pkgs.gtest
                  pkgs.libbfd
                  pkgs.libelf
                  pkgs.libffi
                  pkgs.libopcodes
                  pkgs.libpcap
                  pkgs.libsystemtap
                  pkgs."llvmPackages_${toString llvmVersion}".libclang
                  pkgs."llvmPackages_${toString llvmVersion}".lldb
                  pkgs."llvmPackages_${toString llvmVersion}".llvm
                  pkgs.pahole
                  pkgs.xxd
                  pkgs.zlib
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
                  bc
                  binutils
                  bpftools
                  coreutils
                  clang-tools  # Needed for the nix-aware "wrapped" clang-tidy
                  gawk
                  git
                  gnugrep
                  go  # For runtime tests
                  iproute2
                  kmod
                  # For git-clang-format
                  libclang.python
                  nftables
                  procps
                  python3
                  python3Packages.looseversion
                  qemu_kvm
                  rustc  # For runtime tests
                  strace
                  unixtools.ping
                  util-linux
                  vmtest
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
            bpftrace-llvm19 = mkBpftrace 19;
            bpftrace-llvm18 = mkBpftrace 18;
            bpftrace-llvm17 = mkBpftrace 17;
            bpftrace-llvm16 = mkBpftrace 16;
            bpftrace-llvm15 = mkBpftrace 15;
            bpftrace-llvm14 = mkBpftrace 14;

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

            # Kernels to run runtime tests against.
            #
            # Right now these just mirror the published kernels at
            # https://github.com/bpftrace/kernels. Over time we'll firm up our
            # kernel test policy.
            kernel-5_15 = mkKernel "5.15" "sha256:05awbz25mbiy47zl7xvaf9c37zb6z71sk12flbqli7yppi7ryd13";
            kernel-6_1 = mkKernel "6.1" "sha256:1b7bal1l8zy2fkr1dbp0jxsrzjas4yna78psj9bwwbs9qzrcf5m9";
            kernel-6_6 = mkKernel "6.6" "sha256:19chnfwv84mc0anyf263vgg2x7sczypx8rangd34nf3sywb5cv5y";
            kernel-6_12 = mkKernel "6.12" "sha256:1va2jx3w70gaiqxa8mfl3db7axk2viys8qf65l9qyjy024vn26ib";
          };

          # Define apps that can be run with `nix run`
          apps.default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/bpftrace";
          };

          devShells = rec {
            default = self.devShells.${system}."bpftrace-llvm${toString defaultLlvmVersion}";

            bpftrace-llvm19 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm19;
            bpftrace-llvm18 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm18;
            bpftrace-llvm17 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm17;
            bpftrace-llvm16 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm16;
            bpftrace-llvm15 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm15;
            bpftrace-llvm14 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm14;
          };
        });
}
