# Breaking changes (migration guide)

This document lists changes introduced in bpftrace which break backwards
compatibility in some way. Each entry should contain:
- a link to the PR introducing the change
- a brief description of the change
- an example of an error message
- a simple guide to fix existing scripts

## Versions 0.21.x (or earlier) to 0.22.x (or later)

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

