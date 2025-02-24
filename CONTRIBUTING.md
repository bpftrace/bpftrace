# Contributing

Contributions are welcome! Please see the [development section](#development) below for more information. For new bpftrace tools, please add them to the new [user-tools repository](https://github.com/bpftrace/user-tools/blob/master/CONTRIBUTING.md). The tools that exist in this repository are a small collection curated by the bpftrace maintainers.

* Bug reports and feature requests: [Issue Tracker](https://github.com/bpftrace/bpftrace/issues)

* Development IRC: #bpftrace at irc.oftc.net

* [Good first issues](https://github.com/bpftrace/bpftrace/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22)

## Development

* [Design Principles](docs/design_principles.md)
* [Coding Guidelines](docs/coding_guidelines.md)
* [RFC Process](#rfc-process)
* [Development Guide](docs/developers.md)
* [Development Roadmap](https://docs.google.com/document/d/17729Rlyo1xzlJObzHpFLDzeCVgvwRh0ktAmMEJLK-EU/edit)
* [Fuzzing](docs/fuzzing.md)
* [Nix](docs/nix.md)
* [Release Process](docs/release_process.md)
* [Tests](tests/README.md)
* [DCO](#developers-certificate-of-origin)

## RFC Process

This is for "substantial" or breaking changes. Bug fixes, doc updates, small features, and issues tagged with "good first issue" can utilize the normal github pull request workflow.

1. Create a new issue, where the title is prefixed with "RFC" and apply the RFC tag ([example](https://github.com/bpftrace/bpftrace/issues/2954)). Be sure to include the goal(s) of this change, potential downsides (if applicable), and other solutions you've considered. This issue is where discussions can be had about the overall design and approach. For the most part implementation details should NOT be discussed as they often lead to bike-shedding of the overall proposal.

1. If there is either positive signal from one or more of the maintainers or a lack of negative signal feel free to create a POC and, when you're ready, submit a pull request (linking to the original RFC). This is a good place to have others experiment with your POC and discuss implementation details. 
  - It's entirely possible that this POC exposes underlying issues in the original, approved RFC. That's OK! Return to the original RFC and explain why the approved solution does not work or needs adjustment. If the changes are significant enough, the maintainers might ask for an additional approval of the new approach on the RFC. It's also possible that the RFC then gets rejected; these things happen and they are a normal part of the development process.
  - Depending on the change, you might be asked to gate this behind a "config flag". Meaning that users have to explicitly opt-in to this feature via the addition of a config flag in their script e.g. ```config = { experimental_my_feature=true }``` This allows us to increase development velocity and wait for more user feedback without permanently adding it to bpftrace. Now, it is possible that this feature still may end up getting removed and not added to the language due to user issues or changes in design direction. However, there will be plenty of communication between the maintainers and the original author if this is the case.
  
1. If the POC is approved by two or more maintainers, please follow the current pull request checklist:
 - add it to the CHANGELOG
 - update the adoc
 - ensure there are unit tests, runtime tests, and codegen tests
 
**Note**:  

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
