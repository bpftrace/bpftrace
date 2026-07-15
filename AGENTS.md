# AGENTS.md

This file is an index for AI agents working in the bpftrace repository. Treat
the linked documents below as the source of truth, and prefer improving them
over duplicating their contents here.

## Start here

- [`README.md`](README.md): project overview, installation paths, community
  links, and contributor entry points
- [`docs/developers.md`](docs/developers.md): repository setup, build flows,
  test environment expectations, CI notes, formatting, changelog, and internals
- [`tests/README.md`](tests/README.md): test categories, how to pick the right
  test suite, runtime test directives, and test helper conventions
- [`docs/coding_guidelines.md`](docs/coding_guidelines.md): semantic coding
  rules, naming, error handling, and logging expectations
- [`CONTRIBUTING.md`](CONTRIBUTING.md): RFC process, contributor workflow, DCO,
  and tool contribution guidance

## Task-oriented index

### Build, test, and CI

- Build setup, Nix usage, distro builds, and CI reproduction:
  [`docs/developers.md`](docs/developers.md)
- Test selection and runtime test authoring: [`tests/README.md`](tests/README.md)

### Code changes

- Coding semantics and logging:
  [`docs/coding_guidelines.md`](docs/coding_guidelines.md)
- Formatting and comment style: [`docs/developers.md`](docs/developers.md)
- Architecture and internals:
  [`docs/internals_development.md`](docs/internals_development.md)

### User-visible behavior changes

- Language reference: [`docs/language.md`](docs/language.md)
- Standard library reference: [`docs/stdlib.md`](docs/stdlib.md)
- Man page: [`man/adoc/bpftrace.adoc`](man/adoc/bpftrace.adoc)
- Release notes: [`CHANGELOG.md`](CHANGELOG.md)

### Process and contribution rules

- Contribution workflow and RFC expectations:
  [`CONTRIBUTING.md`](CONTRIBUTING.md)
- PR checklist expectations for docs, changelog entries, and tests:
  [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md)
- Changelog policy, including when entries are required:
  [`docs/developers.md`](docs/developers.md)
- Review and maintainer approval expectations: [`GOVERNANCE.md`](GOVERNANCE.md)
- Project design principles:
  [`docs/design_principles.md`](docs/design_principles.md)

## Maintenance rule

If this index and a referenced document disagree, follow the referenced
document and update this file only to improve navigation.
