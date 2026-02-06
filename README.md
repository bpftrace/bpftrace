<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="images/bpftrace_Full_Logo-White.svg"/>
    <img alt="bpftrace" src="images/bpftrace_Full_Logo-Black.svg" width="60%"/>
  </picture>
</p>

[![Build Status](https://github.com/bpftrace/bpftrace/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/bpftrace/bpftrace/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/bpftrace/bpftrace)](https://github.com/bpftrace/bpftrace/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/bpftrace/bpftrace/blob/master/LICENSE)

bpftrace is a general purpose tracing tool and language for Linux. It leverages [eBPF](https://ebpf.io/what-is-ebpf/) to provide powerful, efficient tracing capabilities with minimal overhead.
bpftrace uses [LLVM](https://llvm.org/) as a compiler backend, and [libbpf](https://github.com/libbpf/libbpf) for interacting with the Linux BPF subsystem, including kernel dynamic tracing ([kprobes](https://docs.kernel.org/trace/kprobes.html), [hardware and software perf events](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_PERF_EVENT/)), user-level dynamic tracing ([USDT](https://docs.ebpf.io/linux/concepts/usdt/), [uprobes](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/)), tracepoints ([regular](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACEPOINT/), [raw](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_RAW_TRACEPOINT/)), and [more](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_TRACING/).
The bpftrace language is inspired by awk, C, and predecessor tracers such as DTrace and SystemTap.

Visit **[bpftrace.org](https://bpftrace.org/)** for [tutorials](https://bpftrace.org/tutorial-one-liners), [documentation](https://bpftrace.org/docs), and [labs](https://bpftrace.org/hol/intro)!

This respository also contains some [canonical tools](tools/README.md).

For migrating from older versions, see the [migration guide](docs/migration_guide.md).

## Quick Start

Get started with bpftrace in just a few minutes! To build from source, see the [building](#building) section below. However, you can often install it using your distribution's [package manager](https://pkgs.org/search/?q=bpftrace).

> [!IMPORTANT]
> When using a distribution package, be sure to verify `bpftrace --version` when referencing documentation.

<table>
  <tr>
    <td valign="middle">Distributions</td>
    <td valign="middle">Command</td>
  </tr>
  <tr>
    <td valign="middle">
    <a href="https://packages.ubuntu.com/jammy/bpftrace"><img src="https://repology.org/badge/version-for-repo/ubuntu_22_04/bpftrace.svg" alt="Ubuntu 22.04"/></a>
    <a href="https://packages.ubuntu.com/noble/bpftrace"><img src="https://repology.org/badge/version-for-repo/ubuntu_24_04/bpftrace.svg" alt="Ubuntu 24.04"/></a>
    <a href="https://packages.ubuntu.com/plucky/bpftrace"><img src="https://repology.org/badge/version-for-repo/ubuntu_25_04/bpftrace.svg" alt="Ubuntu 25.04"/></a>
    <a href="https://packages.ubuntu.com/questing/bpftrace"><img src="https://repology.org/badge/version-for-repo/ubuntu_25_10/bpftrace.svg" alt="Ubuntu 25.10"/></a>
    <a href="https://packages.debian.org/trixie/bpftrace"><img src="https://repology.org/badge/version-for-repo/debian_13/bpftrace.svg" alt="Debian 13"/></a>
    <a href="https://packages.debian.org/forky/bpftrace"><img src="https://repology.org/badge/version-for-repo/debian_14/bpftrace.svg" alt="Debian 14"/></a>
    <a href="https://packages.debian.org/sid/bpftrace"><img src="https://repology.org/badge/version-for-repo/debian_unstable/bpftrace.svg" alt="Debian Unstable"/></a>
    </td>
    <td valign="middle">
    <pre lang="bash">sudo apt install bpftrace<pre>
    </td>
  </tr>
  <tr>
    <td valign="middle">
    <a href="https://packages.fedoraproject.org/pkgs/bpftrace/bpftrace/fedora-42-updates.html"><img src="https://repology.org/badge/version-for-repo/fedora_42/bpftrace.svg" alt="Fedora 42"/></a>
    <a href="https://packages.fedoraproject.org/pkgs/bpftrace/bpftrace/fedora-43.html"><img src="https://repology.org/badge/version-for-repo/fedora_43/bpftrace.svg" alt="Fedora 43"/></a>
    <a href="https://packages.fedoraproject.org/pkgs/bpftrace/bpftrace/fedora-rawhide.html"><img src="https://repology.org/badge/version-for-repo/fedora_rawhide/bpftrace.svg" alt="Fedora Rawhide"/></a>
    <a href="https://centos.pkgs.org/9/centos-crb-x86_64/"><img src="https://repology.org/badge/version-for-repo/centos_stream_9/bpftrace.svg" alt="CentOS 9"/></a>
    <a href="https://centos.pkgs.org/10/centos-crb-x86_64/"><img src="https://repology.org/badge/version-for-repo/centos_stream_10/bpftrace.svg" alt="CentOS 10"/></a>
    </td>
    <td valign="middle">
    <pre lang="bash">sudo dnf install bpftrace</pre>
    </td>
  </tr>
  <tr>
    <td valign="middle">
    <a href="https://pkgs.alpinelinux.org/packages?name=bpftrace&branch=v3.21"><img src="https://repology.org/badge/version-for-repo/alpine_3_21/bpftrace.svg" alt="Alpine 3.21"/></a>
    <a href="https://pkgs.alpinelinux.org/packages?name=bpftrace&branch=v3.22"><img src="https://repology.org/badge/version-for-repo/alpine_3_22/bpftrace.svg" alt="Alpine 3.22"/></a>
    <a href="https://pkgs.alpinelinux.org/packages?name=bpftrace&branch=edge"><img src="https://repology.org/badge/version-for-repo/alpine_edge/bpftrace.svg" alt="Alpine Edge"/></a>
    </td>
    <td valign="middle">
    <pre lang="bash">sudo apk add bpftrace</pre>
    </td>
  </tr>
  <tr>
    <td valign="middle">
    <a href="https://archlinux.org/packages/extra/x86_64/bpftrace/"><img src="https://repology.org/badge/version-for-repo/arch/bpftrace.svg" alt="Arch Linux"/></a>
    </td>
    <td valign="middle">
    <pre lang="bash">sudo pacman -S bpftrace</pre>
    </td>
  </tr>
  <tr>
    <td valign="middle">
    <a href="https://packages.gentoo.org/packages/dev-util/bpftrace"><img src="https://repology.org/badge/version-for-repo/gentoo/bpftrace.svg" alt="Gentoo"/></a>
    </td>
    <td valign="middle">
    <pre lang="bash">sudo emerge -av bpftrace</pre>
    </td>
  </tr>
  <tr>
    <td valign="middle">
    <a href="https://search.nixos.org/packages?query=bpftrace"><img src="https://repology.org/badge/version-for-repo/nix_unstable/bpftrace.svg" alt="nixpkgs"/></a>
    </td>
    <td valign="middle">
    <pre lang="bash">nix-shell -p bpftrace</pre>
    </td>
  </tr>
  <tr>
    <td valign="middle">
    <a href="https://software.opensuse.org/package/bpftrace"><img src="https://repology.org/badge/version-for-repo/opensuse_tumbleweed/bpftrace.svg" alt="openSUSE Tumbleweed"/></a>
    </td>
    <td valign="middle">
    <pre lang="bash">sudo zypper install bpftrace</pre>
    </td>
  </tr>
  <tr>
    <td valign="middle">
    <a href="https://github.com/bpftrace/bpftrace/actions/workflows/binary.yml"><img src="https://img.shields.io/badge/AppImage-nightly-green" alt="AppImage (nightly)"></a>
    </td>
    <td valign="middle">
<pre lang="bash">declare -A suffixes=([x86_64]="X64" [amd64]="AMD64");
declare prefix="bpftrace/bpftrace/workflows/binary/master/bpftrace";
declare url="https://nightly.link/${prefix}-${suffixes[$(uname -m)]}.zip";
curl -L -o bpftrace.zip "${url}" && unzip bpftrace.zip</pre>
    </td>
  </tr>
</table>

## Contributing

See our [contributing guide](CONTRIBUTING.md) for details on how to contribute, and our [governance](GOVERNANCE.md) document for details on how the project is run.

If you have tools built with bpftrace that you'd like to submit, please contribute to the [user-tools repository](https://github.com/bpftrace/user-tools/blob/master/CONTRIBUTING.md).

## Building

For minimum kernel version requirements, see our [dependency support policy](docs/dependency_support.md#linux-kernel). Your kernel should be built with the necessary BPF options enabled. Verify this by running the `check_kernel_features` script from the `scripts` directory.

bpftrace also uses [git submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules), so ensure they are initialized when checking out the code. See [dependency support](docs/dependency_support.md) for details.

```bash
git clone --recurse-submodules https://github.com/bpftrace/bpftrace
cd bpftrace
```

bpftrace provides a [Nix](https://nixos.org/nix/) [flake](https://wiki.nixos.org/wiki/Flakes), which is recommended for building and testing.

```bash
nix develop
```

For a suitable build environment without Nix, see our Dockerfiles for detailed build examples:
- [Ubuntu](https://github.com/bpftrace/bpftrace/blob/master/docker/Dockerfile.ubuntu)
- [Fedora](https://github.com/bpftrace/bpftrace/blob/master/docker/Dockerfile.fedora)
- [Debian](https://github.com/bpftrace/bpftrace/blob/master/docker/Dockerfile.debian)

If all dependencies are installed correctly, you should be able to configure and build using [CMake](https://cmake.org).

```bash
cmake -DCMAKE_BUILD_TYPE=Release -B build .
make -C build -j$(nproc)
```

<details>
<summary>Troubleshooting</summary>

**Kernel Lockdown:** If your system has kernel lockdown enabled (often with Secure Boot), bpftrace will be blocked. To disable:
- Disable Secure Boot in UEFI, or
- Run `sudo mokutil --disable-validation` and reboot, or
- Temporarily lift lockdown with `SysRQ+x` (until next boot)
</details>

## Community & Support

bpftrace is built and maintained by a diverse community of contributors, users, and organizations who rely on it for production tracing and debugging.

**Get help or get involved:**
- 💬 [GitHub Discussions](https://github.com/bpftrace/bpftrace/discussions) - Ask questions
- 🐛 [Issue Tracker](https://github.com/bpftrace/bpftrace/issues) - Report bugs and request features
- 📅 [Monthly Office Hours](https://docs.google.com/document/d/1nt010RfL4s4gydhCPSJ-Z5mnFMFuD4NrcpVmUcyvu2E/edit?usp=sharing) - Open to everyone
- 💬 [Discord](https://discord.gg/3tnjU2fTWr) - Open to everyone (if the link expired, write to #4916)
