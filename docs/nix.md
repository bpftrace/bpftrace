# Building and testing with Nix

Nix flakes are, in theory, guaranteed to be 100% reproducible on (nearly) any
system. It does this by fully managing every dependency. This also means that
you as a developer do not need to install _any_ build / runtime packages to
build bpftrace with Nix.

Rather than explain how Nix works (which is difficult to impossible in this
kind of document), the rest of this guide will be a series of examples.
Learning Nix flakes and the Nix language will be an exercise left to the
reader.

## Examples

These examples all assume you've already installed the `nix` CLI tool.  If not,
see: https://nixos.org/download.html.

Also note again that we require _no dependencies_ to be installed other than
`nix` itself.

### Enable flake support

Nix flakes are technically an experimental feature but it's widely used and
understood that the interface is unlikely to change. To enable flakes, run:

```
$ mkdir -p ~/.config/nix
$ echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf
```

### Build bpftrace

When invoking `nix build`, flakes reconstruct the source tree from Git metadata
but skip submodules, so append `.?submodules=1` (as below) to ensure libbpf is
present.

```
$ nix build .?submodules=1#
$ sudo ./result/bin/bpftrace -e 'BEGIN { print("hello world!") }'
Attached 1 probe
hello world!
^C
```

### Build bpftrace with a different LLVM version

```
$ nix build .?submodules=1#bpftrace-llvm13
$ sudo ./result/bin/bpftrace --info 2>&1 | grep LLVM
  LLVM: 13.0.1
```

### Build bpftrace as a statically linked binary

```
$ nix build .?submodules=1#appimage
$ ldd ./result
        not a dynamic executable
$ sudo ./result -e 'BEGIN { print("static!"); exit() }'
Attached 1 probe
static!
```

### Don't use Nix to build, but rather only manage dependencies

```
$ nix develop
[dxu@kashmir bpftrace]$ cmake -B build-nix -GNinja
[...]

[dxu@kashmir bpftrace]$ ninja -C build-nix
[...]

[dxu@kashmir bpftrace]$ exit

$ sudo ./build-nix/src/bpftrace --version
bpftrace v0.17.0-75-g68ea-dirty
```

`nix develop` opens a developer shell. We've configured the bpftrace flake
to be nearly the exact same as the default build environment except with a
few more tools available.

### Build bpftrace with a different LLVM in developer shell

```
$ nix develop .#bpftrace-llvm18
dxu@kashmir bpftrace]$ cmake -B build-nix -GNinja
[...]
-- Found LLVM 18.1.7: /nix/store/50fcd75v40wca7vdk9bypgcvv6xhkfhx-llvm-18.1.7-dev/lib/cmake/llvm
[...]
```

### Run test suite inside developer shell

```
$ nix develop
[dxu@kashmir bpftrace]$ cd build-nix; sudo ctest -V
[...]
```

### Setup an environment for fuzzing

```
$ nix develop .#bpftrace-fuzz
dxu@kashmir bpftrace]$ CC=afl-clang-fast CXX=afl-clang-fast++ cmake -B build-fuzz -DCMAKE_BUILD_TYPE=Debug -DBUILD_ASAN=1
[...]
```

## Internal examples

This section has a few examples on how to interact with the Nix configuration.

### Update flake inputs

Flakes have external inputs in the `inputs = { ... }` section of `flake.nix`.

To update a single input:
```
$ nix flake lock --update-input blazesym
warning: updating lock file '/home/dxu/dev/bpftrace/flake.lock':
• Updated input 'blazesym':
    'github:libbpf/blazesym/6beb39ebc8e3a604c7b483951c85c831c1bbe0d1' (2025-02-14)
  → 'github:libbpf/blazesym/285b17f15a12885544b21f1ae352928910656767' (2025-03-04)
```

To update a single input to a specific revision:
```
$ nix flake lock --override-input blazesym github:libbpf/blazesym/6beb39ebc8e3a604c7b483951c85c831c1bbe0d1
warning: updating lock file '/home/dxu/dev/bpftrace/flake.lock':
• Updated input 'blazesym':
    'github:libbpf/blazesym/285b17f15a12885544b21f1ae352928910656767' (2025-03-04)
  → 'github:libbpf/blazesym/6beb39ebc8e3a604c7b483951c85c831c1bbe0d1' (2025-02-14)
```

To update all inputs:
```
$ nix flake update
warning: updating lock file '/home/dxu/dev/bpftrace/flake.lock':
• Updated input 'nixpkgs':
    'github:NixOS/nixpkgs/d9b69c3ec2a2e2e971c534065bdd53374bd68b97' (2025-02-24)
  → 'github:NixOS/nixpkgs/02032da4af073d0f6110540c8677f16d4be0117f' (2025-03-03)
```

### Format `*.nix` files

```
$ nix fmt
0 / 1 have been reformatted
```

### Check `*.nix` files for errors

```
$ nix flake check
```
