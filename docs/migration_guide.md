# Breaking changes (migration guide)

This document lists changes introduced in bpftrace which break backwards
compatibility in some way. Each entry should contain:
- a link to the PR introducing the change
- a brief description of the change
- an example of an error message
- a simple guide to fix existing scripts

## Versions 0.21.x (or earlier) to 0.22.x (or later)

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

