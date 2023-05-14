{
  description = "High-level tracing language for Linux eBPF";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-22.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    # This flake only supports 64-bit linux systems.
    # Note bpftrace support aarch32 but for simplicity we'll omit it for now.
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ]
      (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          # Set formatter for `nix fmt` command
          formatter = pkgs.nixpkgs-fmt;

          # Define package set
          packages = rec {
            # Default package is bpftrace binary
            default = bpftrace;

            # Derivation for bpftrace binary
            bpftrace =
              with pkgs;
              pkgs.stdenv.mkDerivation rec {
                name = "bpftrace";

                src = self;

                nativeBuildInputs = [ cmake ninja bison flex gcc12 ];

                # TODO: use submoduled bcc + libbpf
                buildInputs = with llvmPackages_15;
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
                  "-DUSE_SYSTEM_BPF_BCC=ON"
                ];
              };
          };

          # Define apps that can be run with `nix run`
          apps.default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/bpftrace";
          };
        });
}
