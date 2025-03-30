{
  description = "High-level tracing language for Linux";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nix-appimage = {
      # We're maintaining a fork b/c upstream is missing support for unstable
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
    naersk = {
      url = "github:nix-community/naersk";
      # See above
      inputs.nixpkgs.follows = "nixpkgs";
    };
    blazesym = {
      url = "github:libbpf/blazesym/6beb39ebc8e3a604c7b483951c85c831c1bbe0d1";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, nix-appimage, naersk, blazesym, ... }:
    # This flake only supports 64-bit linux systems.
    # Note bpftrace support aarch32 but for simplicity we'll omit it for now.
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ]
      (system:
        let
          pkgs = import nixpkgs { inherit system; };

          # The default LLVM version is the latest supported release
          defaultLlvmVersion = 20;

          # Override to specify the libbpf build we want
          libbpfVersion = "1.5.0";
          libbpf = pkgs.libbpf.overrideAttrs {
            version = libbpfVersion;
            src = pkgs.fetchFromGitHub {
              owner = "libbpf";
              repo = "libbpf";
              rev = "v${libbpfVersion}";
              # Nix uses the hash to do lookups in its cache as well as check that the
              # download from the internet hasn't changed. Therefore, it's necessary to
              # update the hash every time you update the source. Failure to update the
              # hash in a cached environment (warm development host and CI) will cause
              # nix to use the old source and then fail at some point in the future when
              # the stale cached content is evicted.
              #
              # If you don't know the hash, set:
              #   sha256 = "";
              # then nix will fail the build with such an error message:
              #   hash mismatch in fixed-output derivation '/nix/store/m1ga09c0z1a6n7rj8ky3s31dpgalsn0n-source':
              #   specified: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
              # got:    sha256-173gxk0ymiw94glyjzjizp8bv8g72gwkjhacigd1an09jshdrjb4
              sha256 = "sha256-+L/rbp0a3p4PHq1yTJmuMcNj0gT5sqAPeaNRo3Sh6U8=";
            };
          };

          # Override to specify the bcc build we want.
          # First overrides with the above libbpf and then overrides the rev.
          bccVersion = "0.33.0";
          bcc = (pkgs.bcc.override {
            libbpf = libbpf;
            llvmPackages = pkgs."llvmPackages_${toString defaultLlvmVersion}";
          }).overridePythonAttrs {
            version = bccVersion;
            src = pkgs.fetchFromGitHub {
              owner = "iovisor";
              repo = "bcc";
              rev = "v${bccVersion}";
              # See above
              sha256 = "sha256-6dT3seLuEVQNKWiYGLK1ajXzW7pb62S/GQ0Lp4JdGjc=";
            };
          };

          # Download statically linked vmtest binary
          arch = pkgs.lib.strings.removeSuffix "-linux" system;
          vmtestVersion = "0.18.0";
          # Architecture-specific SHA values.
          # You can get the sha by using the trick above and running `nix develop --system aarch64-linux`.
          # It'll error out on the actual build, but the SHA check is done before that.
          vmtestSha = {
            "x86_64" = "sha256:1wv49fq7n820jj7zyvbvrrzg2vwvyy8kb3gfw1lg55rzfqzhl9v3";
            "aarch64" = "sha256:1nsq32bn6pd1gmij1qlry8ydn4gp0jdcqs030ba6yh2c30rhi02d";
          };
          vmtest = pkgs.stdenv.mkDerivation {
            name = "vmtest";
            version = vmtestVersion;
            src = builtins.fetchurl {
              url = "https://github.com/danobi/vmtest/releases/download/v${vmtestVersion}/vmtest-${arch}";
              sha256 = vmtestSha.${arch};
            };
            # Remove all other phases b/c we already have a prebuilt binary
            phases = [ "installPhase" ];
            installPhase = ''
              install -m755 -D $src $out/bin/vmtest
            '';
          };

          # Build blazesym
          blazesym_c = naersk.lib.${system}.buildPackage {
            root = blazesym;
            cargoBuildOptions = x: x ++ [ "-p" "blazesym-c" ];
            copyLibs = true;
            postInstall = ''
              # Export C headers
              mkdir -p $out/include
              cp capi/include/*.h $out/include/
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
              pkgs.stdenv.mkDerivation {
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
                  blazesym_c
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
            bpftrace-llvm20 = mkBpftrace 20;
            bpftrace-llvm19 = mkBpftrace 19;
            bpftrace-llvm18 = mkBpftrace 18;
            bpftrace-llvm17 = mkBpftrace 17;
            bpftrace-llvm16 = mkBpftrace 16;

            # Self-contained static binary with all dependencies
            appimage = nix-appimage.mkappimage.${system} {
              drv = default;
              entrypoint = pkgs.lib.getExe default;
              name = default.name;

              # Exclude the following groups to reduce appimage size:
              #
              # *.a: Static archives are not necessary at runtime
              # *.h: Header files are not necessary at runtime (some ARM headers for clang are large)
              # *.py, *.pyc, *.whl: bpftrace does not use python at runtime
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
                "... *.py"
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

            bpftrace-llvm20 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm20;
            bpftrace-llvm19 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm19;
            bpftrace-llvm18 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm18;
            bpftrace-llvm17 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm17;
            bpftrace-llvm16 = mkBpftraceDevShell self.packages.${system}.bpftrace-llvm16;
          };
        });
}
