# Design Principles

This document exists so that there is a clear understanding of what bpftrace does and does not do. While we are excited to see community contributions, we are not likely to choose a path that goes against these principles. This document is as much for current and future maintainers as it is for new and existing contributors. This is a living document and subject to change.

## bpftrace Mission Statement
Provide a quick and easy way for people to write observability-based BPF programs, especially for people unfamiliar with the complexities of eBPF (e.g. the verifier, kernel/userspace interaction, attachment, program loading, memory access, and the various types of BPF maps).

## Language Goals
These are in priority order:

1. conciseness / one-liners
1. readability / easy to understand
1. clean abstraction from eBPF
1. ability to quickly iterate
1. composability
1. good performance in both kernel and userspace
1. speed of program initialization/start-up

## Language Non-Goals

1. testability
1. debuggability (no gdb or self-tracing) 
1. dynamic typing
1. Classes / Inheritance
1. metaprogramming
1. exception handling
1. BPF security, LSM, XDP, Scheduling
1. BPF concepts that don't pertain to observability or can’t be abstracted cleanly

## Stability

We value API stability and we would like bpftrace to work on as many past versions of the Linux kernel as possible ([dependency support](./dependency_support.md)). However, due to the speed of kernel development, especially in the BPF space, we need to ~~keep up~~ PUSH the community forward, which means sometimes we need to break things.

We prefer the stability in the sense of “It is heavily used in production, and when something changes, there is a clear migration path” e.g. this [migration guide](./migration_guide.md).

When we deprecate a pattern, we study its usage and, when appropriate, add deprecation warnings in an upcoming release before removing/changing it completely.

We don’t deprecate anything without a good reason. We recognize that sometimes deprecations warnings cause frustration but we add them because deprecations clean up the road for the improvements and new features that we and many people in the community consider valuable.

## Implementation

We try to provide an elegant, intuitive, and surprise-free experience when users are writing/running bpftrace scripts. We are less concerned with the implementation being elegant. The real world is far from perfect, and to a reasonable extent we prefer to write ugly code if it means the user does not have to write it. When we evaluate new code, we are looking for an implementation that is correct, performant, tested, and will not lead to mounds of tech debt.

We prefer boring code to clever code. Code is disposable and often changes. So it is important that it doesn’t introduce new internal abstractions unless absolutely necessary. Verbose code that is easy to move around, change, and remove is preferred to elegant code that is prematurely abstracted and hard to change.

## Design Review

Many changes, including bug fixes and documentation improvements can be implemented and reviewed via the normal GitHub pull request workflow. Some changes, though, are "substantial" or breaking, and we ask that these be put through the [RFC process](../CONTRIBUTING.md#rfc-process) and produce a consensus among bpftrace's maintainers.

This process is intended to provide a consistent and controlled path for changes to bpftrace so that all stakeholders can be confident about the direction of the project.

## Evolution

Like many open source projects, bpftrace is evolving. As we learn more about our customers and what they need from a tool that promises fast kernel-based observability/tracing, we will adapt and grow bpftrace to meet those needs. We also want to grow the bpftrace community with transparency, responsiveness, kindness, and collaboration. Let's build something awesome together!
