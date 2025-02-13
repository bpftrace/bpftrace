# Contributing

Contributions are welcome! Please see the [development section](#development) below for more information. For new bpftrace tools, please add them to the new [user-tools repository](https://github.com/bpftrace/user-tools/blob/master/CONTRIBUTING.md). The tools that exist in this repository are a small collection curated by the bpftrace maintainers.

* Bug reports and feature requests: [Issue Tracker](https://github.com/bpftrace/bpftrace/issues)

* Development IRC: #bpftrace at irc.oftc.net

* [Good first issues](https://github.com/bpftrace/bpftrace/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)

## Development

* [Coding Guidelines](docs/coding_guidelines.md)
* [Development Guide](docs/developers.md)
* [Development Roadmap](https://docs.google.com/document/d/17729Rlyo1xzlJObzHpFLDzeCVgvwRh0ktAmMEJLK-EU/edit)
* [Fuzzing](docs/fuzzing.md)
* [Nix](docs/nix.md)
* [Release Process](docs/release_process.md)
* [Tests](tests/README.md)

## Developer's Certificate of Origin

To improve tracking of who did what we’ve introduced a “sign-off” procedure.

The sign-off is a simple line at the end of every commit, which certifies that
you wrote it or otherwise have the right to pass it on as an open-source
contribution.

The rules are pretty simple: [Developer's Certificate of Origin](https://developercertificate.org/).

If you can certify those rules then sign-off all commits with the `--signoff`
option provided by `git commit`. For example:

```
git commit --signoff --message "This is the commit message"
```

This option adds a `Signed-off-by` trailer at the end of the commit log message.

Please use your real name and an actual email address (sorry, no anonymous
contributions, github logins, etc.).
