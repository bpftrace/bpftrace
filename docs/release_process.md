# Release procedure

This document describes how to release a new bpftrace version.

The "release manager" (RM) can be one or more person. Usually whoever is motivated
enough to drive a release.

## Branching model

In the usual case, we release directly from master. Reasoning is that bpftrace
isn't a huge project yet so complicated branching models and release strategies
more get in the way than provide order. If master is really busy or really buggy,
the RM can choose to cut a release branch (titled `X.Y.Z_release`) to try and
stabilize the code without including work in progress into the release.

## Merging pull requests

Please squash + rebase all pull requests (with no merge commit). In other words,
there should be one commit in master per pull request. This makes generating
changelogs both trivial and precise with the least amount of noise.

The exception to this is PRs with complicated changes. If this is the case and
the commits are well structured, a rebase + merge (no merge commit) is acceptable.
The rule of thumb is the commit titles should make sense in a changelog.

## Semantic versioning

We choose to follow semantic versioning. Note that this doesn't matter much for
major version < 1 but will matter a lot for >= 1.0.0 releases.

See https://semver.org/ .

## Tagging a release

You must do 3 things to formally release a version:

1. Update `CHANGELOG.md`. Use the following git command to generate the appropriate
   data format:
   ```
   git log --oneline ${PREVIOUS_VER}..upstream/master --no-merges --format=" - %s (%h) by %aN &lt;%aE&gt;"
   ```
   where `${PREVIOUS_VER}` is the last release tag, eg `v0.9.3`. Please see previous
   releases for the final formatting.
1. Update `bpftrace_VERSION_MAJOR`, `bpftrace_VERSION_MINOR`, and
   `bpftrace_VERSION_PATCH` in `CMakeLists.txt` to the target version.
1. Tag a release. We do this in the github UI by clicking "releases" (on same line
   as "commits"), then "Draft a new release". The tag version and release title
   should be the same and in `vX.Y.Z` format. The tag description should
   be the same as what you added to `CHANGELOG.md`.
