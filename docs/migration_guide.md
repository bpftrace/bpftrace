# Breaking changes (migration guide)

This document lists changes introduced in bpftrace which break backwards
compatibility in some way. Each entry should contain:
- a link to the PR introducing the change
- a brief description of the change
- an example of an error message
- a simple guide to fix existing scripts

## Versions 0.21.x (or earlier) to 0.22.x (or later)

### Added block scoping for scratch variables

https://github.com/bpftrace/bpftrace/pull/3367

Previously, scratch variables were "probe" scoped meaning the following
was valid syntax:
```
BEGIN {
    if (0) {
        $x = "hello";
    }
    print(($x));
}

// prints an empty line
```
However, the value of `$x` at the print statement was considered undefined
behavior. Issue: https://github.com/bpftrace/bpftrace/issues/3017

Now variables are "block" scoped and the the above will throw an error at the
print statement: "ERROR: Undefined or undeclared variable: $x".

If you see this error you can do multiple things to resolve it.

**Option 1: Initialize variable before use**
```
BEGIN {
    $x = "";
    if (0) {
        $x = "hello";
    }
    print(($x));
}
```

**Option 2: Declare variable before use**
```
BEGIN {
    let $x;
    // let $x = ""; is also valid
    if (0) {
        $x = "hello";
    }
    print(($x));
}
```
Declaring is useful for variables that hold internal bpftrace types
e.g. the type returned by the `macaddr` function.

This is also not valid even though `$x` is set in both branches (`$x` still
needs to exist in the outer scope):
```
BEGIN {
    if (0) {
        $x = "hello";
    } else {
        $x = "bye";
    }
    print(($x));
}
```

Additionally, scratch variable shadowing is not allowed e.g. this is not valid:
```
BEGIN {
    let $x;
    if (0) {
        let $x = "hello"; // shadows $x in the parent scope
    }
}
```

### multi-key `delete` removed

https://github.com/bpftrace/bpftrace/pull/3506

This map `delete` syntax is no longer valid:
```
delete(@b[1], @b[2], @b[3]);
```
And will yield this error:
```
# bpftrace -e 'BEGIN { @b[1] = 1; delete(@b[1], @b[2], @b[3]); }'
stdin:1:20-47: ERROR: delete() takes up to 2 arguments (3 provided)
BEGIN { @b[1] = 1; delete(@b[1], @b[2], @b[3]); }
                   ~~~~~~~~~~~~~~~~~~~~~~~~~~~
```

You might also see this error:
```
# bpftrace -e 'BEGIN { @b[1] = 1; delete(@b[1], @b[2]); }'
stdin:1:20-32: ERROR: delete() expects a map with no keys for the first argument
BEGIN { @b[1] = 1; delete(@b[1], @b[2]); }
                   ~~~~~~~~~~~~
```

`delete` now expects only two arguments: a map and a key. For example, the above
delete statement should be rewritten as this:
```
delete(@b, 1);
delete(@b, 2);
delete(@b, 3);
```

And for maps with multiple values as keys, which are represented as a tuple,
the delete call looks like this:
```
@c[1, "hello"] = 1;

delete(@c, (1, "hello"));
```

### `pid` and `tid` builtins return `uint32`

https://github.com/bpftrace/bpftrace/pull/3441

Previously, `pid` and `tid` builtins returned `uint64` so it is now possible to
get an error when storing the builtin in a variable and overriding it with
`uint64` later:
```
# bpftrace -e 'BEGIN { $x = pid; $x = cgroup; }'   # cgroup is uint64
stdin:1:19-30: ERROR: Integer size mismatch. Assignment type 'uint64' is larger than the variable type 'uint32'.
BEGIN { $x = pid; $x = cgroup; }
                  ~~~~~~~~~~~
```

To mitigate such an error, just typecast `pid` or `tid` to `uint64`:
```
# bpftrace -e 'BEGIN { $x = (uint64)pid; $x = cgroup; }'
Attaching 1 probe...
```

### default `SIGUSR1` handler removed

https://github.com/bpftrace/bpftrace/pull/3522

Previously, if the bpftrace process received a `SIGUSR1` signal, it would print all maps to stdout:
```
# bpftrace -e 'BEGIN { @b[1] = 2; }' & kill -s USR1 $(pidof bpftrace)
...
@b[1]: 2
```

This behavior is no longer supported and has been replaced with the ability
to define custom handling probes:
```
# bpftrace -e 'self:signal:SIGUSR1 { print("hello"); }' & kill -s USR1 $(pidof bpftrace)
...
hello
```

To retain the previous functionality of printing maps, you need to
manually include the print statements in your signal handler probe:
```
# bpftrace -e 'BEGIN { @b[1] = 2; } self:signal:SIGUSR1 { print(@b); }' & kill -s USR1 $(pidof bpftrace)
```

