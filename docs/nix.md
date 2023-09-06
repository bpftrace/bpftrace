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

```
$ nix build
$ sudo ./result/bin/bpftrace -e 'BEGIN { print("hello world!") }'
Attaching 1 probe...
hello world!
^C
```

### Build bpftrace with a different LLVM version

```
$ nix build .#bpftrace-llvm13
$ sudo ./result/bin/bpftrace --info 2>&1 | grep LLVM
  LLVM: 13.0.1
```

### Build bpftrace as a statically linked binary

```
$ nix build .#appimage
$ ldd ./result
        not a dynamic executable
$ sudo ./result -e 'BEGIN { print("static!"); exit() }'
Attaching 1 probe...
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
$ nix develop .#bpftrace-llvm12
dxu@kashmir bpftrace]$ cmake -B build-nix -GNinja
[...]
-- Found LLVM 12.0.1: ///nix/store/xs06qigbqln7piypm7dfj5wqd38ndgcz-llvm-12.0.1-dev/lib/cmake/llvm/
[...]
```

### Run test suite inside developer shell

```
$ nix develop
[dxu@kashmir bpftrace]$ cd build-nix; sudo ctest -V
[...]
```

## Internal examples

This section has a few examples on how to interact with the Nix configuration.

### Format `*.nix` files

```
$ nix fmt
0 / 1 have been reformatted
```

### Check `*.nix` files for errors

```
$ nix flake check
```
