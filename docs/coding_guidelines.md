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

If an error is **not** recoverable, prefer throwing `FatalUserException`.
Exceptions **should not** be used for recoverable errors.

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

## Struct vs. Class

Use a struct only for passive objects that carry data; everything else is a class.

All fields in a struct should be public. The struct must not have invariants
that imply relationships between different fields, since direct user access to
those fields may break those invariants. Structs should not have any associated
methods (including constructors and destructors).

## Variable naming

Variables should be in `snake_case` (all lowercase, with underscores between words).

Private members should have a trailing underscore. Public members should not have
a trailing underscore.

Struct data members should _not_ have a trailing underscore.

Examples:

```c++
class Foo {
public:
  int snake_case;      // good
  int secondone;       // bad
  int var_;            // bad
  int camelCase;       // bad

private:
  int another_var_;    // good
  int private_var;     // bad
  int priv_;           // good
};

struct Bar {
  int var;             // good
  int tailing_;        // bad
};
```

## Log Messages

Below are details about when to use each kind of log level:

- `DEBUG`: log info regardless of log level; like using stdout (comes with file
and line number)
- `V1`: log info only if verbose logging is enabled (-v); use this (among
  others) for printing warnings which may occur on every bpftrace execution
  (like BTF is not available)
- `WARNING`: log info that might affect bpftrace behavior or output but allows
the run to continue; like using stderr
- `ERROR`: log info to indicate that the user did something invalid, which will
(eventually) cause bpftrace to exit (via `exit(1)`); this should primarily get
used in main.cpp after catching `FatalUserException` from deeper parts of the
code base
- `BUG`: abort and log info to indicate that there is an internal/unexpected
issue (not caused by invalid user program code or CLI use)
