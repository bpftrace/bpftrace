# Upcoming release schedule

The schedule for the upcoming v0.23 release is:
- February 25, 2025: Create release branch `release/0.23.x`.
- **March 25, 2025: Release v0.23.0.**

# Release procedure

This document describes the bpftrace release process.

## Semantic versioning

We choose to follow semantic versioning. Note that this doesn't matter much for
major version < 1 but will matter a lot for >= 1.0.0 releases.

See https://semver.org/.

## Release cadence

bpftrace is released twice a year. Since our biggest dependency, which also
tends to break things, is LLVM, we align with the [LLVM release
schedule](https://llvm.org/docs/HowToReleaseLLVM.html). In particular, a minor
bpftrace release should happen **two weeks after a major LLVM release**.

In addition, four weeks before the bpftrace release, we create a stabilized
release branch, which will only receive bug fixes affecting the release itself.
The branch will also serve as a target for future (post-release) bug fixes that
should get into that minor release (by creating a new "patch" release).

Overview of the release cadence is as follows:

| Task                   | Approximate date                    | Details                                                              |
| ---------------------- | ----------------------------------- | -------------------------------------------------------------------- |
| release branch created | **2 weeks before the LLVM release** | [Creating a release branch](#creating-a-release-branch)              |
| LLVM release           | usually second Tuesday of Mar/Sep   | [LLVM release schedule](https://llvm.org/docs/HowToReleaseLLVM.html) |
| bpftrace release       | **2 weeks after the LLVM release**  | [Tagging a release](#tagging-a-release)                              |

## Creating a release branch

A release branch should be created four weeks before the planned bpftrace
release. From that moment, only relevant bug fixes should be backported to the
branch.

The purpose of this release branch is to give sufficient time to test features
in the upcoming bpftrace release without blocking the development on the master
branch.

When creating a branch, the following steps should be performed. Any changes to
the code should be done in the master branch first and then backported to the
release branch. In the rare case when the master-first approach is not possible
(e.g. a feature present exclusively on master blocks the LLVM update), the
changes can be done in the release branch first and forward-ported to master
afterwards.

1. Create a new branch according to the [Branching model](#branching-model).
1. Update Nixpkgs to the latest version to get the latest (pre-release) LLVM by
   running
   ```
   nix flake update
   ```
   and committing the `flake.lock` changes to the repo. At this time, the `-rc2`
   or `-rc3` version of LLVM should be available.
1. Bump the supported LLVM version in [CMakeLists.txt](../CMakeLists.txt) and
   [flake.nix](../flake.nix), resolve any potential issues, and add a CI job to
   [.github/workflows/ci.yml](../.github/workflows/ci.yml) for the new version.
1. Once the final LLVM is released and present in Nixpkgs (usually 2-5 days
   after the LLVM release), repeat step 2 to get the released LLVM in the CI
   environment.

### Branching model

There should be one release branch per "major release" (we are currently
pre-1.0, "major" refers to semver minor version). The name should follow the
format `release/<major>.<minor>.x`.

Example branch names:

    * release/0.21.x
    * release/1.0.x
    * release/1.1.x

## Tagging a release

You must do the following steps to formally release a version.

In the release branch:

1. Mark the release in [CHANGELOG.md](../CHANGELOG.md) by replacing the `##
   Unreleased` header with `## [VERSION] date`.
1. Update `bpftrace_VERSION_MAJOR`, `bpftrace_VERSION_MINOR`, and
   `bpftrace_VERSION_PATCH` in [CMakeLists.txt](../CMakeLists.txt) to the target
   version.
1. Tag a release. We do this in the github UI by clicking "releases" (on same
   line as "commits"), then "Draft a new release". The tag version and release
   title should be the same and in `vX.Y.Z` format. The tag description should
   be the same as what you added to CHANGELOG.md.
1. Check that automation picks up the new release and uploads release assets to
   the release.
1. If automation fails, please fix the automation for next time and also
   manually build+upload artifacts by running `scripts/create-assets.sh` from
   bpftrace root dir and attach the generated archives to the release.

Once the release is out:
1. Forward-port the CHANGELOG.md changes from the release branch to master.
