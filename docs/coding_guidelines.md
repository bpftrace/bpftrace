# Coding guidelines

The goal of this document is to establish some common understanding of what
language features should and should not be used. This helps reduce mental
overhead while reading, developing, and reviewing code. In some cases, it
also helps present a more consistent user experience.

Discussions about this document should occur in a pull request making changes
to the text of this document. This helps keep track of why things are the way
they are. As well as providing a structured environment to participate.

If something is not called out in this document, defer to [the C++ core
guidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines).
In other words, this document supersedes the core guidelines.

Note that the checked in code may not adhere to these guidelines yet.
This document is intended to be referenced for new code. Ideally we also
modify checked-in code to follow these guidelines (if/when there is time).

## Error handling and exceptions

If an error is recoverable (meaning downstream callers of the code should
be able to selectively handle, ignore, or further propagate), pass the
error through the return value of the function.

Appropriate language features for this include:

* `std:optional`
* `int`
* `bool`

If an error is **not** recoverable, prefer throwing an exception. Broadly
speaking, if you want to immediately terminate and show a message to the
user, use an exception. Exceptions **should not** be used for recoverable
errors.

### Examples

An example of a recoverable error would be failure to write an entry into a
map. There are a number of reasons why writing to a map could fail (map is
full, insufficient privileges, map does not exist yet, etc.) and we can't know
for sure at the point of failure what the reason is. Additionally, this type of
error might not be a reason fail the whole program. So we need to propagate the
error.

An example of an unrecoverable error would be if `debugfs` is not mounted.
If debugfs isn't mounted, all bets are off b/c we cannot interact with
the kernel debug facilities. And we probably should not be mounting
filesystems on behalf of the user. So at the point of failure, we should
just throw an exception and let the user know their system is not ready
for bpftrace.
