# Release procedure

This document describes the bpftrace release process.

## Semantic versioning

We choose to follow semantic versioning. Note that this doesn't matter much for
major version < 1 but will matter a lot for >= 1.0.0 releases.

See https://semver.org/ .

## Branching model

There should be one release branch per "major release" (we are currently
pre-1.0, "major" refers to semver minor version). The name should follow the
format `release/<major>.<minor>.x`.

Example branch names:

    * release/0.21.x
    * release/1.0.x
    * release/1.1.x

Backport PRs should be opened against the relevant release branch.

## Tagging a release

You must do these things to formally release a version:

1. Create a new release branch if one does not already exist.
1. Mark the release in the CHANGELOG by replacing the `## Unreleased` header
   with `## [VERSION] date`.
1. Update `bpftrace_VERSION_MAJOR`, `bpftrace_VERSION_MINOR`, and
   `bpftrace_VERSION_PATCH` in `CMakeLists.txt` to the target version.
1. Tag a release. We do this in the github UI by clicking "releases" (on same line
   as "commits"), then "Draft a new release". The tag version and release title
   should be the same and in `vX.Y.Z` format. The tag description should
   be the same as what you added to `CHANGELOG.md`.
1. Check that automation picks up the new release and uploads release assets
   to the release.
1. If automation fails, please fix the automation for next time and also manually
   build+upload artifacts by running `scripts/create-assets.sh` from bpftrace root
   dir and attach the generated archives to the release.
