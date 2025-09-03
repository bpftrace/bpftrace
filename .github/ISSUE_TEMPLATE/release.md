---
name: Release tracker
about: Create a tracker issue for the upcoming release. Should be used by maintainers only.

---

<!--
The title of the issue should be "Release v0.<minor>.0".

Fill in the placeholders in the checklist below:

- <minor> is the release minor number
- <llvm> is the LLVM major number
- <deprecated-llvm> is the LLVM version becoming deprecated (<llvm> - 5)
- <branching-date> is the date of creating the release branch
- <release-date> is date of bpftrace release

For details on the release process, see docs/release_process.md.
For LLVM release schedule, see https://llvm.org/.
-->

### Release progress

- [ ] Create release branch `release/v0.<minor>.x` (<branching-date>)
- [ ] Add support for LLVM <llvm>
  - [ ] Bump `MAX_LLVM_MAJOR` in [CMakeLists.txt](https://github.com/bpftrace/bpftrace/blob/master/CMakeLists.txt)
  - [ ] Add new Nix target in [flake.nix](https://github.com/bpftrace/bpftrace/blob/master/flake.nix)
  - [ ] Add CI job to [.github/workflows/ci.yml](https://github.com/bpftrace/bpftrace/blob/master/.github/workflows/ci.yml)
- [ ] Drop support for LLVM <deprecated-llvm>
- [ ] Update LLVM in Nixpkgs to <llvm>.1.0
- [ ] **Release bpftrace 0.<minor>.0 (<release-date>)**
  - [ ] Mark the release in [CHANGELOG.md](https://github.com/bpftrace/bpftrace/blob/master/CHANGELOG.md)
  - [ ] Update `bpftrace_VERSION_*` in [CMakeLists.txt](https://github.com/bpftrace/bpftrace/blob/master/CMakeLists.txt)
  - [ ] Draft a new release in GitHub
  - [ ] Update the docs on the bpftrace website. [Instructions](https://github.com/bpftrace/website?#updating-the-docs).
  - [ ] Add a new tools version link on the [tools readme](https://github.com/bpftrace/bpftrace/blob/master/tools/README.md) to the master branch.
- [ ] Forward-port [CHANGELOG.md](https://github.com/bpftrace/bpftrace/blob/master/CHANGELOG.md) and [CMakeLists.txt](https://github.com/bpftrace/bpftrace/blob/master/CMakeLists.txt) changes to the master branch.

See [Release Process](https://github.com/bpftrace/bpftrace/blob/master/docs/release_process.md) for general information on the
release process.
