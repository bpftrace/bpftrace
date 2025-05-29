# Governance

This document describes the governance model for bpftrace. It is intended to be a living document that is updated as the project evolves.

## Overview

bpftrace is a meritocratic, consensus-based community project. Anyone with an interest in the project can join the community, contribute to the project design and participate in the decision making process. This document describes how that participation takes place and how to set about earning merit within the bpftrace community.

## Roles and responsibilities

### Users
Users are community members who have a need for the project. They are the most important members of the community and without them the project would have no purpose. Anyone can be a user; there are no special requirements.

The project asks its users to participate in the project and community as much as possible. User contributions enable the project team to ensure that they are satisfying the needs of those users. Common user contributions include (but are not limited to):

- evangelising about the project (e.g. a link on a website and word-of-mouth awareness raising)
- informing developers of strengths and weaknesses from a new user perspective
- providing moral support (a ‘thank you’ goes a long way)

Users who continue to engage with the project and its community will often become more and more involved. Such users may find themselves becoming contributors, as described in the next section.

### Contributors
Contributors are community members who contribute in concrete ways to the project. Anyone can become a contributor. There is no expectation of commitment to the project, no specific skill requirements and no selection process.

In addition to their actions as users, contributors may also find themselves doing one or more of the following:

- supporting new users (existing users are often the best people to support new users)
- reporting bugs
- answering/responding to issues and discussions
- identifying requirements
- coding
- assisting with project infrastructure (e.g. Github CI)
- writing documentation
- fixing bugs
- adding features
- facilitating distrubtion (e.g. packaging for distributions)

Contributors primarily engage with the project through the mechanisms in Github. They submit changes to the project itself via Github Pull Requests, which will be considered for inclusion in the project by existing maintainers and committers (see sections below). The most appropriate place to ask for help when making a first contribution is on the issue itself; there is a curated [list of "good first issues"](https://github.com/bpftrace/bpftrace/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22).

As contributors gain experience and familiarity with the project, their profile within, and commitment to, the community will increase. At some stage, they may find themselves being nominated for committership.

### Committers
Committers are community members who have shown that they are committed to the continued development of the project through ongoing engagement with the community. Committership allows contributors to more easily carry on with their project related activities by giving them write access, meaning they can merge approved PRs themselves.

This does not mean that a committer is free to do what they want. In fact, committers have no more authority over the project than contributors. While committership indicates a valued member of the community who has demonstrated a healthy respect for the project’s aims and objectives, their work continues to be reviewed by the maintainers before acceptance. The key difference between a committer and a contributor is when this approval is sought from the community. A committer seeks approval after the contribution is made, rather than before.

Seeking approval after making a contribution is known as a commit-then-review process. It is more efficient to allow trusted people to make direct contributions, as the majority of those contributions will be accepted by the project. The project employs various communication mechanisms to ensure that all contributions are reviewed by the community as a whole. By the time a contributor is invited to become a committer, they will have become familiar with the project’s various tools as a user and then as a contributor.

Anyone can become a committer; there are no special requirements, other than to have shown a willingness and ability to participate in the project as a team player. Typically, a potential committer will need to show that they have an understanding of the project, its objectives and its strategy. They will also have provided valuable contributions to the project over a period of time.

New committers can be nominated by any existing maintainer (see below). Once they have been nominated, there will be an informal majority among the maintainers.

It is important to recognise that commitership is a privilege, not a right. That privilege must be earned and once earned it can be removed by the maintainers in extreme circumstances. However, under normal circumstances committership exists for as long as the committer wishes to continue engaging with the project.

A committer who shows an above-average level of contribution to the project, particularly with respect to its strategic direction and long-term health, may be nominated to become a maintainer. This role is described below.

### Maintainers
The maintainers of bpftrace consist of those individuals identified as [‘code owners’](https://github.com/bpftrace/bpftrace/blob/master/.github/CODEOWNERS). Maintainers have additional responsibilities over and above those of a committer. These responsibilities ensure the smooth running of the project. Maintainers are expected to:

- Review PRs. Since maintainer approval is required for any changes, the project's velocity hinges on speedy turnaround times for reviews. We also don’t want to discourage new contributors by having their PRs sit in Github purgatory.
- Attend monthly office hours.
- Respond to discussions, questions, and issues. Maintainers have a broader context than most and being responsive also keeps bpftrace users from getting discouraged.
- Mentor and teach new developers. Guide these folks on first issues.
- Participate in planning and larger design and project decisions.
- Help triage and groom the issue backlog.

Maintainers vote on new committers and new maintainers. They make decisions when community consensus cannot be reached. In addition, at least one approval from a maintainer is required for each submitted Pull Request.

To become a maintainer, you have to first be a committer. Any maintainer can nominate a committer for maintainership. Once they have been nominated, there will be an informal majority vote amongst maintainers only over email (see details below about voting).

## Support
All participants in the community are encouraged to provide support for new users within the project management infrastructure. This support is provided as a way of growing the community. Those seeking support should recognise that all support activity within the project is voluntary and is therefore provided as and when time allows. There are currently no mechanisms set up for users requiring guaranteed response times or results.

## Contribution process
Anyone can contribute to the project, regardless of their skills. First time contributors should look through the [list of "good first issues"](https://github.com/bpftrace/bpftrace/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22) and ask questions on the issue(s) they are interested in picking up.

Here is [a more detailed guide on contributing](CONTRIBUTING.md).

## Decision making process
Decisions about the future of the project are made through discussion with all members of the community, from the newest user to the most experienced maintainer. All non-sensitive project management discussion takes place on the bpftrace Github project, often times in the [issues](https://github.com/bpftrace/bpftrace/issues) themselves. Occasionally, sensitive discussion occurs offline among the maintainers.

### Merging Code
At least one approval from a maintainer is required for each submitted Pull Request; this also applies to maintainers in all cases where the changes are non-trivial.

If there is a disagreement among maintainers (or changes requested despite an approval from another maintainer), please allow time for the maintainers to work out the issue amongst themselves or do your best to answer/address the concerns of the dissenting maintainer.

### Proposals and RFCS
Any community member can make a proposal or RFC for consideration by the community via [this guide](CONTRIBUTING.md#rfc-process).

In general, as long as nobody explicitly opposes a proposal or patch, it is recognised as having the support of the community. This is called lazy consensus - that is, those who have not stated their opinion explicitly have implicitly agreed to the implementation of the proposal.

### Voting
Formal voting only occurs when the consensus-based process has been fully exhausted. Meaning if maintainers can't come to an agreement, there will be a vote amongst the maintainers. However, every member of the community is encouraged to express their opinions in all discussions, RFCs, and strategies. A simple majority wins the vote. If there is no majority the proposal or decision is rejected. Maintainers have 10 days to vote otherwise their vote is forfeit.

## Conclusion
A clear and transparent governance document is a key part of any open development project. It defines the rules of engagement within the community and describes what level of influence a community member can expect to have over a project. In addition, it enables members to decide their level of involvement with that community. In the case of a meritocracy, it also provides a clear way to contribute and a highly visible reward system.

Most of the language in this document was taken from [OSS Watch](http://oss-watch.ac.uk/resources/meritocraticgovernancemodel).
