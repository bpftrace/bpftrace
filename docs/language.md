# The bpftrace Language

The `bpftrace` (`bt`) language is inspired by the D language used by `dtrace` and uses the same program structure.
Each script consists of a [Preamble](#preamble) and one or more [Action Blocks](#action-blocks).

```
preamble

actionblock1
actionblock2
```

## Action Blocks

Each action block consists of three parts:

```
[name=]probe[,probe]
/predicate/ {
  action
}
```

* **Probes**\
  A probe specifies the event and event type to attach to. See [the probes section](#probes) for more detail.
* **Predicate**\
  The predicate is an optional condition that must be met for the action to be executed.
* **Action**\
  Actions are the programs that run when an event fires (and the predicate is met).
An action is a semicolon (`;`) separated list of statements and always enclosed by brackets `{}`.

A basic script that traces the `open(2)` and `openat(2)` system calls can be written as follows:

```
begin {
	printf("Tracing open syscalls... Hit Ctrl-C to end.\n");
}

tracepoint:syscalls:sys_enter_open,
tracepoint:syscalls:sys_enter_openat {
	printf("%-6d %-16s %s\n", pid, comm, str(args.filename));
}
```

The above script has two action blocks and a total of 3 probes.

The first action block uses the special `begin` probe, which fires once during `bpftrace` startup.
This probe is used to print a header, indicating that the tracing has started.

The second action block uses two probes, one for `open` and one for `openat`, and defines an action that prints the file being `open` ed as well as the `pid` and `comm` of the process that execute the syscall.
See the [Probes](#probes) section for details on the available probe types.

## Arguments

This refers to traced function and tracepoint arguments.

There are two ways to access these arguments and the way you choose depends on the [probe type](#probes).

- For `uprobe`, `kprobe`, and `usdt` use the `argN` format.
- For `rawtracepoint`, `tracepoint`, `fentry`, `fexit`, and `uprobe` (with DWARF) use the `args` format.

### argN

These keywords allow access to the nth argument passed to the function being traced.
For the first argument use `arg0`, for the second `arg1`, and so forth.
The type of each arg is an `int64` and will often require casting to non scalar types, e.g., `$x = (struct qstr *)arg1`.
These are extracted from the CPU registers.
The amount of args passed in registers depends on the CPU architecture.

### args

This keyword represents the struct of all arguments of the traced function.
You can print the entire structure via `print(args)` or access particular fields using the dot syntax, e.g., `$x = str(args.filename);`.
To see the args for a particular function, you can use [verbose listing mode](../man/adoc/bpftrace.adoc#listing-probes).
Example:
```
# bpftrace -lv 'fentry:tcp_reset'

fentry:tcp_reset
    struct sock * sk
    struct sk_buff * skb
```

## Arrays

bpftrace supports accessing one-dimensional arrays like those found in `C`.

Constructing arrays from scratch, like `int a[] = {1,2,3}` in `C`, is not supported.
They can only be read into a variable from a pointer.

The `[]` operator is used to access elements.

```
struct MyStruct {
  int y[4];
}

kprobe:dummy {
  $s = (struct MyStruct *) arg0;
  print($s.y[0]);
}
```

## Command Line Parameters

Custom options can be passed to a bpftrace program itself via positional or named parameters. It is recommended to use **named parameters** because they are less ambiguous in terms of their types and meaning (they have actual names).

### Named Parameters

Named parameters can be accessed in a bpftrace program via the `getopt` function call, e.g., `getopt("my_named_param", 5)`, `getopt("my_bool_param")`. The first argument is the parameter name and the second is the default value when that argument is not passed on the command line. If the second argument is not provided it indicates that the parameter is a `boolean` type.

Named parameters must come AFTER a double dash (`--`) when being passed on the command line, e.g.,
```
# bpftrace -e 'begin { print((getopt("aa", 1), getopt("bb"))); }' -- --aa=20 --bb
```
Here `getopt("aa", 1)` would evaluate to `20` and `getopt("bb")` would evaluate to `true`.

Named parameters require the `=` to set their value unless they are boolean parameters (like 'bb' above). The supported types are string, number, and boolean.

### Positional Parameters

Positional parameters can be accessed in a bpftrace program via, what looks like, a numbered scratch variable, e.g. `$1`, `$2`, ..., `$N`. So `$1` would be the first positional parameter and so on.

Positional parameters can be placed before or after a double dash, e.g.,
```
# bpftrace -e 'begin { print(($1, $2)); }' p1 -- 20
```

Here `$1` would evaluate to a string `p1` and `$2` would evaluate to a number `20`.

If a parameter is used that was not provided, it will default to zero for a numeric context, and "" for a string context.
Positional parameters may also be used in probe arguments and will be treated as a string parameter, e.g., `tracepoint:block:block_rq_issue
/args.bytes > $1/`.

If a positional parameter is used in `str()`, it is interpreted as a pointer to the actual given string literal, which allows to do pointer arithmetic on it.
Only addition of a single constant, less or equal to the length of the supplied string, is allowed. Example:

```
# bpftrace -e 'begin { printf("I got %d, %s (%d args)\n", $1, str($2), $#); }' 42 "hello"

I got 42, hello (2 args)

# bpftrace -e 'begin { printf("%s\n", str($1 + 1)) }' "hello"

ello
```

`$#` is a special builtin that returns the number of positional arguments supplied.

## Comments

Both single line and multi line comments are supported.

```
// A single line comment
interval:s:1 { // can also be used to comment inline
/*
 a multi line comment

*/
  print(/* inline comment block */ 1);
}
```

## Conditionals

Conditional expressions are supported in the form of if/else statements and the ternary operator.

The ternary operator consists of three operands: a condition followed by a `?`, the expression to execute when the condition is true followed by a `:` and the expression to execute if the condition is false.

```
condition ? ifTrue : ifFalse
```

Both the `ifTrue` and `ifFalse` expressions must be of the same type, mixing types is not allowed.

The ternary operator can be used as part of an assignment.

```
$a == 1 ? print("true") : print("false");
$b = $a > 0 ? $a : -1;
```

If/else statements are supported.

```
if (condition) {
  ifblock
} else if (condition) {
  if2block
} else {
  elseblock
}
```

## Config Block

To improve script portability, you can set bpftrace [Config Variables](#config-variables) via the config block,
which can only be placed at the top of the script (in the [preamble](#preamble)) before any action blocks.

```
config = {
    stack_mode=perf;
    max_map_keys=2
}

begin { ... }

uprobe:./testprogs/uprobe_test:uprobeFunction1 { ... }
```

The names of the config variables can be in the format of environment variables
or their lowercase equivalent without the `BPFTRACE_` prefix. For example,
`BPFTRACE_STACK_MODE`, `STACK_MODE`, and `stack_mode` are equivalent.

***Note***: Environment variables for the same config take precedence over those set
inside a script config block.

[List of All Config Variables](#config-variables)

## Config Variables

Some behavior can only be controlled through config variables, which are listed here.
These can be set via the [Config Block](#config-block) directly in a script (before any probes) or via their environment variable equivalent, which is upper case and includes the `BPFTRACE_` prefix e.g. ``stack_mode`’s environment variable would be `BPFTRACE_STACK_MODE`.

### cache_user_symbols

Default: PER_PROGRAM if ASLR disabled or `-c` option given, PER_PID otherwise.

* PER_PROGRAM - each program has its own cache. If there are more processes with enabled ASLR for a single program, this might produce incorrect results.
* PER_PID - each process has its own cache. This is accurate for processes with ASLR enabled, and enables bpftrace to preload caches for processes running at probe attachment time.
If there are many processes running, it will consume a lot of a memory.
* NONE - caching disabled. This saves the most memory, but at the cost of speed.

### cpp_demangle

Default: true

C++ symbol demangling in userspace stack traces is enabled by default.

This feature can be turned off by setting the value of this variable to `false`.

### lazy_symbolication

Default: false

For user space symbols, symbolicate lazily/on-demand (`true`) or symbolicate everything ahead of time (`false`).

### license

Default: "GPL"

The license bpftrace will use to load BPF programs into the linux kernel. Here is the list of accepted license strings:
- GPL
- GPL v2
- GPL and additional rights
- Dual BSD/GPL
- Dual MIT/GPL
- Dual MPL/GPL

[Read More about BPF licenses](#bpf-license)

### log_size

Default: 1000000

Log size in bytes.

### max_bpf_progs

Default: 1024

This is the maximum number of BPF programs (functions) that bpftrace can generate.
The main purpose of this limit is to prevent bpftrace from hanging since generating a lot of probes
takes a lot of resources (and it should not happen often).

### max_cat_bytes

Default: 10240

Maximum bytes read by cat builtin.

### max_map_keys

Default: 4096

This is the maximum number of keys that can be stored in a map.
Increasing the value will consume more memory and increase startup times.
There are some cases where you will want to, for example: sampling stack traces, recording timestamps for each page, etc.

### max_probes

Default: 1024

This is the maximum number of probes that bpftrace can attach to.
Increasing the value will consume more memory, increase startup times, and can incur high performance overhead or even freeze/crash the
system.

### max_strlen

Default: 1024

The maximum length (in bytes) for values created by `str()`, `buf()` and `path()`.

This limit is necessary because BPF requires the size of all dynamically-read strings (and similar) to be declared up front. This is the size for all strings (and similar) in bpftrace unless specified at the call site.
There is no artificial limit on what you can tune this to. But you may be wasting resources (memory and cpu) if you make this too high.

### missing_probes

Default: `error`

Controls handling of probes which cannot be attached because they do not exist (in the kernel or in the traced binary) or there was an issue during attachment.

The possible options are:
- `error` - always fail on missing probes
- `warn` - print a warning but continue execution
- `ignore` - silently ignore missing probes

### on_stack_limit

Default: 32

The maximum size (in bytes) of individual objects that will be stored on the BPF stack. If they are larger than this limit they will be stored in pre-allocated memory.

This exists because the BPF stack is limited to 512 bytes and large objects make it more likely that we’ll run out of space. bpftrace can store objects that are larger than the `on_stack_limit` in pre-allocated memory to prevent this stack error. However, storing in pre-allocated memory may be less memory efficient. Lower this default number if you are still seeing a stack memory error or increase it if you’re worried about memory consumption.

### perf_rb_pages

Default: Based on available system memory

Number of pages to allocate for each created ring or perf buffer (there is only one of each max).
The minimum is: 1 * the number of cpus on your machine.
If you’re getting a lot of dropped events bpftrace may not be processing events in the ring buffer (or perf buffer if you're using `skboutput`) fast enough.
It may be useful to bump the value higher so more events can be queued up.
The tradeoff is that bpftrace will use more memory.
The default value is based on available system memory; max is 4096 pages (16mb) and min is 64 pages (256kb), which presumes 4k page size.
If your system has a larger page size the amount of allocated memory will be the same but we'll just use fewer pages.

### show_debug_info

This is only available if the [Blazesym](https://github.com/libbpf/blazesym) library is available at build time. If it is available this defaults to `true`, meaning that when printing ustack and kstack symbols bpftrace will also show (if debug info is available) symbol file and line ('bpftrace' stack mode) and a label if the function was inlined ('bpftrace' and 'perf' stack modes).
There might be a performance difference when symbolicating, which is the only reason to disable this.

### stack_mode

Default: bpftrace

Output format for ustack and kstack builtins.
Available modes/formats:

* bpftrace
* perf
* raw: no symbolication (print instruction pointer)
* build_id: no symbolication (print build_id and file offset) (ustack only)

This can be overwritten at the call site.

### str_trunc_trailer

Default: `..`

Trailer to add to strings that were truncated.
Set to empty string to disable truncation trailers.

### print_maps_on_exit

Default: true

Controls whether maps are printed on exit. Set to `false` in order to change the default behavior and not automatically print maps at program exit.

### unstable features

These are the list of unstable features:
- `unstable_map_decl` - feature flag for map declarations
- `unstable_tseries` - feature flag for time series map type
- `unstable_addr` - feature flag for address of operator (&)

All of these accept the following options:

Default: warn

- `error` - fail if this feature is used
- `warn` - enable feature but print a warning
- `enable` - enable feature

## Data Types

The following fundamental types are provided by the language.

|     |     |
| --- | --- |
| **Type** | **Description** |
| bool | `true` or `false` |
| uint8 | Unsigned 8 bit integer |
| int8 | Signed 8 bit integer |
| uint16 | Unsigned 16 bit integer |
| int16 | Signed 16 bit integer |
| uint32 | Unsigned 32 bit integer |
| int32 | Signed 32 bit integer |
| uint64 | Unsigned 64 bit integer |
| int64 | Signed 64 bit integer |
| string | See below |

```
begin { $x = 1<<16; printf("%d %d\n", (uint16)$x, $x); }

/*
 * Output:
 * 0 65536
 */
```

Integers are by default represented as the smallest possible
type, e.g. `1` is a `uint8` and `-1` is an `int8`. However integers,
scratch variables, and map keys/values will be automatically upcast
when necessary, e.g.

```
$a = 1; // starts as uint8
$b = -1000; // starts as int16
$a = $b; // $a now becomes an int16

$c = (uint64)1;
$d = (int64)-1;

$c = $d; // ERROR: type mismatch because there isn't a larger type
         // that fits both.
```

Additionally, when vmlinux BTF is available, bpftrace supports
casting to some of the kernel's fixed integer types:
```
$a = (uint64_t)1; // $a is a uint64
```

### String

bpftrace also supports a `string` data type, which it uses for string literals, e.g. `"hello"`.
Similar to C this is represented as a well formed char array (NULL terminated).
Additionally, all BTF char arrays (`char[]` or `int8[]`) are automatically converted to a bpftrace string but can be casted back to an int array if needed, e.g. `$a = (int8[])"mystring"`;
It also may be necessary to utilize the [`str()`](stdlib.md#str) function if bpftrace can't determine the correct address space (user or kernel).

## Filters/Predicates

Filters (also known as predicates) can be added after probe names.
The probe still fires, but it will skip the action unless the filter is true.

```
kprobe:vfs_read /arg2 < 16/ {
  printf("small read: %d byte buffer\n", arg2);
}

kprobe:vfs_read /comm == "bash"/ {
  printf("read by %s\n", comm);
}
```

## Floating-point

Floating-point numbers are not supported by BPF and therefore not by bpftrace.

## Identifiers

Identifiers must match the following regular expression: `[_a-zA-Z][_a-zA-Z0-9]*`

## Keywords

`break`, `config`, `continue`, `else`, `for`, `if`, `import`, `let`, `macro`, `offsetof`, `return`, `sizeof`, `unroll`, `while` (deprecated).

* `return` - The return keyword is used to exit the current probe. This differs from `exit()` in that it doesn’t exit bpftrace.

## Literals

Integer and string literals are supported.

Integer literals can be defined in the following formats:

* decimal (base 10)
* octal (base 8)
* hexadecimal (base 16)
* scientific (base 10)

Octal literals have to be prefixed with a `0` e.g. `0123`.
Hexadecimal literals start with either `0x` or `0X` e.g. `0x10`.
Scientific literals are written in the `<m>e<n>` format which is a shorthand for `m*10^n` e.g. `$i = 2e3;`.
Note that scientific literals are integer only due to the lack of floating point support e.g. `1e-3` is not valid.

To improve the readability of big literals an underscore `_` can be used as field separator e.g. 1_000_123_000.

Integer suffixes as found in the C language are parsed by bpftrace to ensure compatibility with C headers/definitions but they’re not used as size specifiers.
`123UL`, `123U` and `123LL` all result in the same integer type with a value of `123`.

These duration suffixes are also supported: `ns`, `us`, `ms`, `s`, `m`, `h`, and `d`. All get turned into integer values in nanoseconds, e.g.
```
$a = 1m;
print($a); // prints 60000000000
```

Character literals are not supported at this time, and the corresponding ASCII code must be used instead:

```
begin {
  printf("Echo A: %c\n", 65);
}
```

String literals can be defined by enclosing the character string in double quotes e.g. `$str = "Hello world";`.

Strings support the following escape sequences:

|     |     |
| --- | --- |
| \n | Newline |
| \t | Tab |
| \0nn | Octal value nn |
| \xnn | Hexadecimal value nn |

## Loops

### For

`for` loops can be used to iterate over elements in a map, or over a range of integers, provided as two unary expressions separated by `..`.

```
for ($kv : @map) {
  block;
}
```

```
for ($i : start..end) {
  block;
}
```

The variable declared in the `for` loop will be initialised on each iteration.

If the iteration is over a map, the value will be a tuple containing a key and a value from the map, i.e. `$kv = (key, value)`:

```
@map[10] = 20;
for ($kv : @map) {
  print($kv.0); // key
  print($kv.1); // value
}
```

If a map has multiple keys, the loop variable will be initialised with nested tuple of the form: `((key1, key2, ...), value)`:

```
@map[10,11] = 20;
for ($kv : @map) {
  print($kv.0.0); // key 1
  print($kv.0.1); // key 2
  print($kv.1);   // value
}
```

If an integer range is provided, the value will be an integer value for each element in the range, inclusive of the start value and exclusive of the end value:

```
for ($cpu : 0..ncpus) {
  print($cpu); // current value in range
}
```

Note that you cannot adjust the range itself after the loop has started.
The `for` start and end values are evaluated once, not on each loop iteration.
For example, the following will print `0` through `9`:

```
$a = 10;
for ($i : 0..$a) {
  print($i);
  $a--;
}
```

Both `for` loops support the following control flow statements:

|     |     |
| --- | --- |
| continue | skip processing of the rest of the block and proceed to the next iteration |
| break | terminate the loop |
| return | return from the current probe |

### While

While loops are deprecated and may be removed in the future; please use `For` loops instead as these are more easily verified to be bounded.

### Unroll

Loop unrolling is also supported with the `unroll` statement.

```
unroll(n) {
  block;
}
```

The compiler will evaluate the block `n` times and generate the BPF code for the block `n` times.
As this happens at compile time `n` must be a constant greater than 0 (`n > 0`).

The following two probes compile into the same code:

```
interval:s:1 {
  unroll(3) {
    print("Unrolled")
  }
}

interval:s:1 {
  print("Unrolled")
  print("Unrolled")
  print("Unrolled")
}
```

## Macros

bpftrace macros (as opposed to C macros) provide a way for you to structure your script.
They can be useful when you want to factor out code into smaller, more understandable parts.
Or if you want to share code between probes.

At a high level, macros can be thought of as semantic aware text replacement.
They accept (optional) variable, map, and expression arguments.
The body of the macro may only access maps and external variables passed in through the arguments, which is why these are often referred to as "hygienic macros", but the macro body can create new variables which only exist inside the body.
A macro's parameter signature specifies how an argument will be used.
For example `macro test($a, b, @c)` indicates that `$a` needs to be a scratch variable (which might be mutated), that `b` needs to be an expression that will be inserted where ever `b` is used in the macro body, and that `@c` needs to be a map (which might be mutated).
A valid use of this macro could be `test($x, 1 + 2, @y)`.
Variables and maps can also be used for ident parameters that expect expressions and would be the same as writing `{ @y }` (Block Expression).

Here are some valid usages of macros:

```
macro one() {
  1
}

macro add_one(x) {
  x + 1
}

macro add_one_to_each($a, @b) {
  $a += 1;
  @b += 1;
}

macro side_effects(x) {
  x;
  x;
  x;
}

macro add_two(x) {
  add_one(x) + 1
}

begin {
  print(one());                   // prints 1
  print(one);                     // prints 1 (bare identifier works if the macro accepts 0 args)

  $a = 10;
  print(add_one($a));             // prints 11
  print(add_one(1 + 1));          // prints 3

  @b = 5;
  add_one_to_each($a, @b);
  print($a + @b)                  // prints 17

  side_effects({ printf("hi") })  // prints hihihi

  print(add_two(1));              // prints 3
}
```

Some examples of invalid macro usage:

```
macro unhygienic_access() {
  @x++                         // BAD: @x not passed in
}

macro wrong_parameter_type($x) {
  $x++
}

begin {
  @x = 1;
  unhygienic_access();

  wrong_parameter_type(@x);    // BAD: macro expects a scratch variable
  wrong_parameter_type(1 + 1); // BAD: macro expects a scratch variable
}
```

Note: If you want the passed in expression to only be executed once, simply bind it to a variable, e.g.,
```
macro add_one(x) {
  let $x = x;
  $x + 1
}
```

## Operators and Expressions

### Arithmetic Operators

The following operators are available for integer arithmetic:

|     |     |
| --- | --- |
| + | integer addition |
| - | integer subtraction |
| * | integer multiplication |
| / | integer division |
| % | integer modulo |

Operations between a signed and an unsigned integer are allowed providing
bpftrace can statically prove a safe conversion is possible. If safe conversion
is not guaranteed, the operation is undefined behavior and a corresponding
warning will be emitted.

If the two operands are different size, the smaller integer is implicitly
promoted to the size of the larger one. Sign is preserved in the promotion.
For example, `(uint32)5 + (uint8)3` is converted to `(uint32)5 + (uint32)3`
which results in `(uint32)8`.

Pointers may be used with arithmetic operators but only for addition and
subtraction. For subtraction, the pointer must appear on the left side of the
operator. Pointers may also be used with logical operators; they are considered
true when non-null.

### Logical Operators

|     |     |
| --- | --- |
| && | Logical AND |
| \|\| | Logical OR |
| ! | Logical NOT |

### Bitwise Operators

|     |     |
| --- | --- |
| & | AND |
| \| | OR |
| ^ | XOR |
| &lt;&lt; | Left shift the left-hand operand by the number of bits specified by the right-hand expression value |
| >> | Right shift the left-hand operand by the number of bits specified by the right-hand expression value |

### Relational Operators

The following relational operators are defined for integers and pointers.

|     |     |
| --- | --- |
| &lt; | left-hand expression is less than right-hand |
| &lt;= | left-hand expression is less than or equal to right-hand |
| > | left-hand expression is bigger than right-hand |
| >= | left-hand expression is bigger or equal to than right-hand |
| == | left-hand expression equal to right-hand |
| != | left-hand expression not equal to right-hand |

The following relation operators are available for comparing strings, integer arrays, and tuples.

|     |     |
| --- | --- |
| == | left-hand string equal to right-hand |
| != | left-hand string not equal to right-hand |

### Assignment Operators

The following assignment operators can be used on both `map` and `scratch` variables:

|     |     |
| --- | --- |
| = | Assignment, assign the right-hand expression to the left-hand variable |
| &lt;&lt;= | Update the variable with its value left shifted by the number of bits specified by the right-hand expression value |
| >>= | Update the variable with its value right shifted by the number of bits specified by the right-hand expression value |
| += | Increment the variable by the right-hand expression value |
| -= | Decrement the variable by the right-hand expression value |
| *= | Multiple the variable by the right-hand expression value |
| /= | Divide the variable by the right-hand expression value |
| %= | Modulo the variable by the right-hand expression value |
| &= | Bitwise AND the variable by the right-hand expression value |
| \|= | Bitwise OR the variable by the right-hand expression value |
| ^= | Bitwise XOR the variable by the right-hand expression value |

All these operators are syntactic sugar for combining assignment with the specified operator.
`@ -= 5` is equal to `@ = @ - 5`.

### Increment and Decrement Operators

The increment (`++`) and decrement (`--`) operators can be used on integer and pointer variables to increment their value by one.
They can only be used on variables and can either be applied as prefix or suffix.
The difference is that the expression `x++` returns the original value of `x`, before it got incremented while `++x` returns the value of `x` post increment.

```
$x = 10;
$y = $x--; // y = 10; x = 9
$a = 10;
$b = --$a; // a = 9; b = 9
```

Note that maps will be implicitly declared and initialized to 0 if not already declared or defined.
Scratch variables must be initialized before using these operators.

Note `++`/`--` on a shared global variable can lose updates. See [`count()`](stdlib.md#count) for more details.

### Block Expressions

A block can be used as expression, as long as the last statement of the block
is an expression with no trailing semi-colon.

```
let $a = {
  let $b = 1;
  $b
};
```

This can be used anywhere an expression can be used.

**Note:** There will be a warning for discarded expressions, e.g.,

```
{ 1 } // Warning
$a = { 1 } // No Warning
has_key(@a, 1); // Warning
$b = has_key(@a, 1); // No Warning
```
The warning can also be silenced by utilizing the Discard Expression:

```
_ = has_key(@a, 1); // No Warning
```

## Preamble

The preamble consists of multiple optional pieces:
- preprocessor definitions
- type definitions
- a [config block](#config-block)
- [map declarations](#map-declarations)

For example:

```
#include <linux/socket.h>
#define RED "\033[31m"

struct S {
  int x;
}

config = {
    stack_mode=perf
}

let @a = lruhash(100);

```

## Probes

bpftrace supports various probe types which allow the user to attach BPF programs to different types of events.
Each probe starts with a provider (e.g. `kprobe`) followed by a colon (`:`) separated list of options.
An optional name may precede the provider with an equals sign (e.g. `name=`), which is reserved for internal use and future features.
The amount of options and their meaning depend on the provider and are detailed below.
The valid values for options can depend on the system or binary being traced, e.g. for uprobes it depends on the binary.
Also see [Listing Probes](../man/adoc/bpftrace.adoc#listing-probes).

It is possible to associate multiple probes with a single action as long as the action is valid for all specified probes.
Multiple probes can be specified as a comma (`,`) separated list:

```
kprobe:tcp_reset,kprobe:tcp_v4_rcv {
  printf("Entered: %s\n", probe);
}
```

Wildcards are supported too:

```
kprobe:tcp_* {
  printf("Entered: %s\n", probe);
}
```

Both can be combined:

```
kprobe:tcp_reset,kprobe:*socket* {
  printf("Entered: %s\n", probe);
}
```

By default, bpftrace requires all probes to attach successfully or else an error is returned. However this can be changed using the `missing_probes` config variable.

Most providers also support a short name which can be used instead of the full name, e.g. `kprobe:f` and `k:f` are identical.

|     |     |     |
| --- | --- | --- |
| **Probe Name** | **Short Name** | **Description** |
| [`begin/end`](#beginend) | - | Built-in events |
| [`bench`](#bench) | - | Micro benchmarks |
| [`self`](#self) | - | Built-in events |
| [`hardware`](#hardware) | `h` | Processor-level events |
| [`interval`](#interval) | `i` | Timed output |
| [`iter`](#iterator) | `it` | Iterators tracing |
| [`fentry/fexit`](#fentry-and-fexit) | `f`/`fr` | Kernel functions tracing with BTF support |
| [`kprobe/kretprobe`](#kprobe-and-kretprobe) | `k`/`kr` | Kernel function start/return |
| [`profile`](#profile) | `p` | Timed sampling |
| [`rawtracepoint`](#rawtracepoint) | `rt` | Kernel static tracepoints with raw arguments |
| [`software`](#software) | `s` | Kernel software events |
| [`tracepoint`](#tracepoint) | `t` | Kernel static tracepoints |
| [`uprobe/uretprobe`](#uprobe-uretprobe) | `u`/`ur` | User-level function start/return |
| [`usdt`](#usdt) | `U` | User-level static tracepoints |
| [`watchpoint`](#watchpoint) | `w` | Memory watchpoints |

### begin/end

These are special built-in events provided by the bpftrace runtime.
`begin` is triggered before all other probes are attached.
`end` is triggered after all other probes are detached.
Each of these probes can be used any number of times, and they will be executed in the same order they are declared.
For imports containing `begin` and `end` probes, an effort is made to preserve the partial order implied by the import graph (e.g. if `A` depends on `B`, then `B` will have both its `begin` and `end` probes executed first), but this is not strictly guaranteed.

Note that specifying an `end` probe doesn’t override the printing of 'non-empty' maps at exit.
To prevent printing all used maps need be cleared in the `end` probe:

```
end {
    clear(@map1);
    clear(@map2);
}
```

### test

`test` is a special built-in probe type for creating tests.
bpftrace executes each `test` probe and checks the return value, error count and possible exit calls to determine a pass.
If multiple `test` probes exist in a script, bpftrace executes them sequentially in the order they are specified.
To run `test` probes, you must run bpftrace in test mode: `bpftrace --test ...`; otherwise `test` probes will be ignored.

```
test:okay {
  print("I'm okay! This output will be suppressed.");
}

test:failure {
  print("This is a failure! This output will be shown");
  return 1;
}
```

### bench

`bench` is a special built-in probe type for creating micro benchmarks.
bpftrace executes each `bench` probe repeatedly to measure the average execution time of the contained code.
If multiple `bench` probes exist in a script, bpftrace executes them sequentially in the order they are specified.
To run `bench` probes, you must run bpftrace in bench mode: `bpftrace --bench ...`; otherwise, `bench` probes will be ignored.

```
bench:lhist {
    @a = lhist(rand % 10, 1, 10, 1);
}

bench:count {
    @b = count();
}

bench:my_loop {
    $a = 0;
    for ($i : 0..10) {
        $a++;
    }
}
```

```
Attached 3 probes


+-----------+-------------+
| BENCHMARK | NANOSECONDS |
+-----------+-------------+
| count     | 40          |
| lhist     | 88          |
| my_loop   | 124         |
+-----------+-------------+
```

### self

**variants**

* `self:signal:SIGUSR1`

These are special built-in events provided by the bpftrace runtime.
The trigger function is called by the bpftrace runtime when the bpftrace process receives specific events, such as a `SIGUSR1` signal.

```
self:signal:SIGUSR1 {
  print("abc");
}
```

### hardware

**variants**

* `hardware:event_name:`
* `hardware:event_name:count`

**short name**

* `h`

These are the pre-defined hardware events provided by the Linux kernel, as commonly traced by the perf utility.
They are implemented using performance monitoring counters (PMCs): hardware resources on the processor.
There are about ten of these, and they are documented in the perf_event_open(2) man page.
The event names are:

* `cpu-cycles` or `cycles`
* `instructions`
* `cache-references`
* `cache-misses`
* `branch-instructions` or `branches`
* `branch-misses`
* `bus-cycles`
* `frontend-stalls`
* `backend-stalls`
* `ref-cycles`

The `count` option specifies how many events must happen before the probe fires (sampling interval).
If `count` is left unspecified a default value is used.

This will fire once for every 1,000,000 cache misses.

```
hardware:cache-misses:1e6 { @[pid] = count(); }
```

### interval

**variants**

* `interval:count`
* `interval:us:count`
* `interval:ms:count`
* `interval:s:count`
* `interval:hz:rate`

**short name**

* `i`

The interval probe fires at a fixed interval as specified by its time spec.
Interval fires on one CPU at a time, unlike [profile](#profile) probes.
If a unit of time is not specified in the second position, the number is interpreted as nanoseconds; e.g., `interval:1s`, `interval:1000000000`, and `interval:s:1` are all equivalent.

This prints the rate of syscalls per second.

```
tracepoint:raw_syscalls:sys_enter { @syscalls = count(); }
interval:1s { print(@syscalls); clear(@syscalls); }
```

### iterator

**variants**

* `iter:task`
* `iter:task:pin`
* `iter:task_file`
* `iter:task_file:pin`
* `iter:task_vma`
* `iter:task_vma:pin`

**short name**

* `it`

***Warning*** this feature is experimental and may be subject to interface changes.

These are eBPF iterator probes that allow iteration over kernel objects.
Iterator probe can’t be mixed with any other probe, not even another iterator.
Each iterator probe provides a set of fields that could be accessed with the
ctx pointer. Users can display the set of available fields for each iterator via
-lv options as described below.

```
iter:task { printf("%s:%d\n", ctx.task.comm, ctx.task.pid); }

/*
 * Sample output:
 * systemd:1
 * kthreadd:2
 * rcu_gp:3
 * rcu_par_gp:4
 * kworker/0:0H:6
 * mm_percpu_wq:8
 */
```

```
iter:task_file {
  printf("%s:%d %d:%s\n", ctx.task.comm, ctx.task.pid, ctx.fd, path(ctx.file.f_path));
}

/*
 * Sample output:
 * systemd:1 1:/dev/null
 * systemd:1 3:/dev/kmsg
 * ...
 * su:1622 2:/dev/pts/1
 * ...
 * bpftrace:1892 2:/dev/pts/1
 * bpftrace:1892 6:anon_inode:bpf-prog
 */
```

```
iter:task_vma {
  printf("%s %d %lx-%lx\n", comm, pid, ctx.vma.vm_start, ctx.vma.vm_end);
}

/*
 * Sample output:
 * bpftrace 119480 55b92c380000-55b92c386000
 * ...
 * bpftrace 119480 7ffd55dde000-7ffd55de2000
 */
```

It’s possible to pin an iterator by specifying the optional probe ':pin' part, that defines the pin file.
It can be specified as an absolute or relative path to /sys/fs/bpf.

**relative pin**

```
iter:task:list { printf("%s:%d\n", ctx.task.comm, ctx.task.pid); }

/*
 * Sample output:
 * Program pinned to /sys/fs/bpf/list
 */
```

**absolute pin**

```
iter:task_file:/sys/fs/bpf/files {
  printf("%s:%d %s\n", ctx.task.comm, ctx.task.pid, path(ctx.file.f_path));
}

/*
 * Sample output:
 * Program pinned to /sys/fs/bpf/files
 */
```

### fentry and fexit

**variants**

* `fentry[:module]:fn`
* `fexit[:module]:fn`
* `fentry:bpf[:prog_id]:prog_name`
* `fexit:bpf[:prog_id]:prog_name`

**short names**

* `f` (`fentry`)
* `fr` (`fexit`)

**requires (`--info`)**

* Kernel features:BTF
* Probe types:fentry

``fentry``/``fexit`` probes attach to kernel functions similar to [kprobe and kretprobe](#kprobe-and-kretprobe).
They make use of eBPF trampolines which allow kernel code to call into BPF programs with near zero overhead.
Originally, these were called `kfunc` and `kretfunc` but were later renamed to `fentry` and `fexit` to match
how these are referenced in the kernel and to prevent confusion with [BPF Kernel Functions](https://docs.kernel.org/bpf/kfuncs.html).
The original names are still supported for backwards compatibility.

``fentry``/``fexit`` probes make use of BTF type information to derive the type of function arguments at compile time.
This removes the need for manual type casting and makes the code more resilient against small signature changes in the kernel.
The function arguments are available in the `args` struct which can be inspected by doing verbose listing (see [Listing Probes](../man/adoc/bpftrace.adoc#listing-probes)).
These arguments are also available in the return probe (`fexit`), unlike `kretprobe`.

The bpf variants (e.g. `fentry:bpf[:prog_id]:prog_name`) allow attaching to running BPF programs and sub-programs.
For example, if bpftrace was already running with a script like `uprobe:./testprogs/uprobe_test:uprobeFunction1 { print("hello"); }` then you could attach to this program with `fexit:bpf:uprobe___testprogs_uprobe_test_uprobeFunction1_1 { print("bye"); }` and this probe would execute after (because it's `fexit`) the `print("hello")` probe executes.
You can specify just the program name, and in this case bpftrace will attach to all running programs and sub-programs with that name.
You can differentiate between them using the `probe` builtin.
You can also specify the program id (e.g. `fentry:bpf:123:*`) to attach to a specific running BPF program or sub-programs called in that running BPF program.
To see a list of running, valid BPF programs and sub-programs use `bpftrace -l 'fentry:bpf:*'`.
Note: only BPF programs with a BTF Id can be attached to.
Also, the `args` builtin is not yet available for this variant.

```
# bpftrace -lv 'fentry:tcp_reset'

fentry:tcp_reset
    struct sock * sk
    struct sk_buff * skb
```

```
fentry:x86_pmu_stop {
  printf("pmu %s stop\n", str(args.event.pmu.name));
}
```

The fget function takes one argument as file descriptor and you can access it via args.fd and the return value is accessible via retval:

```
fexit:fget {
  printf("fd %d name %s\n", args.fd, str(retval.f_path.dentry.d_name.name));
}

/*
 * Sample output:
 * fd 3 name ld.so.cache
 * fd 3 name libselinux.so.1
 */
```

### kprobe and kretprobe

**variants**

* `kprobe[:module]:fn`
* `kprobe[:module]:fn+offset`
* `kretprobe[:module]:fn`

**short names**

* `k`
* `kr`

``kprobe``s allow for dynamic instrumentation of kernel functions.
Each time the specified kernel function is executed the attached BPF programs are ran.

```
kprobe:tcp_reset {
  @tcp_resets = count()
}
```

Function arguments are available through the `argN` for register args. Arguments passed on stack are available using the stack pointer, e.g. `$stack_arg0 = **(int64**)reg("sp") + 16`.
Whether arguments passed on stack or in a register depends on the architecture and the number or arguments used, e.g. on x86_64 the first 6 non-floating point arguments are passed in registers and all following arguments are passed on the stack.
Note that floating point arguments are typically passed in special registers which don’t count as `argN` arguments which can cause confusion.
Consider a function with the following signature:

```
void func(int a, double d, int x)
```

Due to `d` being a floating point, `x` is accessed through `arg1` where one might expect `arg2`.

bpftrace does not detect the function signature so it is not aware of the argument count or their type.
It is up to the user to perform [Type conversion](#type-conversion) when needed, e.g.

```
#include <linux/path.h>
#include <linux/dcache.h>

kprobe:vfs_open
{
	printf("open path: %s\n", str(((struct path *)arg0).dentry.d_name.name));
}
```

Here arg0 was cast as a (struct path *), since that is the first argument to vfs_open.
The struct support is the same as bcc and based on available kernel headers.
This means that many, but not all, structs will be available, and you may need to manually define structs.

If the kernel has BTF (BPF Type Format) data, all kernel structs are always available without defining them. For example:

```
kprobe:vfs_open {
  printf("open path: %s\n", str(((struct path *)arg0).dentry.d_name.name));
}
```

You can optionally specify a kernel module, either to include BTF data from that module, or to specify that the traced function should come from that module.

```
kprobe:kvm:x86_emulate_insn
{
  $ctxt = (struct x86_emulate_ctxt *) arg0;
  printf("eip = 0x%lx\n", $ctxt.eip);
}
```

See [BTF Support](#btf-support) for more details.

`kprobe` s are not limited to function entry, they can be attached to any instruction in a function by specifying an offset from the start of the function.

`kretprobe` s trigger on the return from a kernel function.
Return probes do not have access to the function (input) arguments, only to the return value (through `retval`).
A common pattern to work around this is by storing the arguments in a map on function entry and retrieving in the return probe:

```
kprobe:d_lookup
{
	$name = (struct qstr *)arg1;
	@fname[tid] = $name.name;
}

kretprobe:d_lookup
/@fname[tid]/
{
	printf("%-8d %-6d %-16s M %s\n", elapsed / 1e6, pid, comm,
	    str(@fname[tid]));
}
```

### profile

**variants**

* `profile:count`
* `profile:us:count`
* `profile:ms:count`
* `profile:s:count`
* `profile:hz:rate`

**short name**

* `p`

Profile probes fire on each CPU on the specified interval.
These operate using perf_events (a Linux kernel facility, which is also used by the perf command).
If a unit of time is not specified in the second position, the number is interpreted as nanoseconds; e.g., `interval:1s`, `interval:1000000000`, and `interval:s:1` are all equivalent.

```
profile:hz:99 { @[tid] = count(); }
```

### rawtracepoint

**variants**

* `rawtracepoint[:module]:event`

**short name**

* `rt`

Raw tracepoints are attached to the same tracepoints as normal tracepoint programs.
The reason why you might want to use raw tracepoints over normal tracepoints is due to the performance improvement - [Read More](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_RAW_TRACEPOINT/).

`rawtracepoint` arguments can be accessed via the `argN` builtins AND via the `args` builtin.

```
rawtracepoint:vmlinux:kfree_skb {
  printf("%llx %llx\n", arg0, args.skb);
}
```
`arg0` and `args.skb` will print the same address.

`rawtracepoint` probes make use of BTF type information to derive the type of function arguments at compile time.
This removes the need for manual type casting and makes the code more resilient against small signature changes in the kernel.
The arguments accessible by a `rawtracepoint` are different from the arguments you can access from the `tracepoint` of the same name.
The function arguments are available in the `args` struct which can be inspected by doing verbose listing (see [Listing Probes](../man/adoc/bpftrace.adoc#listing-probes)).

### software

**variants**

* `software:event:`
* `software:event:count`

**short name**

* `s`

These are the pre-defined software events provided by the Linux kernel, as commonly traced via the perf utility.
They are similar to tracepoints, but there is only about a dozen of these, and they are documented in the perf_event_open(2) man page.
If the count is not provided, a default is used.

The event names are:

* `cpu-clock` or `cpu`
* `task-clock`
* `page-faults` or `faults`
* `context-switches` or `cs`
* `cpu-migrations`
* `minor-faults`
* `major-faults`
* `alignment-faults`
* `emulation-faults`
* `dummy`
* `bpf-output`

```
software:faults:100 { @[comm] = count(); }
```

This roughly counts who is causing page faults, by sampling the process name for every one in one hundred faults.

### tracepoint

**variants**

* `tracepoint:subsys:event`

**short name**

* `t`

Tracepoints are hooks into events in the kernel.
Tracepoints are defined in the kernel source and compiled into the kernel binary which makes them a form of static tracing.
Unlike `kprobe` s, new tracepoints cannot be added without modifying the kernel.

The advantage of tracepoints is that they generally provide a more stable interface than `kprobe` s do, they do not depend on the existence of a kernel function.

```
tracepoint:syscalls:sys_enter_openat {
  printf("%s %s\n", comm, str(args.filename));
}
```

Tracepoint arguments are available in the `args` struct which can be inspected with verbose listing, see the [Listing Probes](../man/adoc/bpftrace.adoc#listing-probes) section for more details.

```
# bpftrace -lv "tracepoint:*"

tracepoint:xhci-hcd:xhci_setup_device_slot
  u32 info
  u32 info2
  u32 tt_info
  u32 state
...
```

Alternatively members for each tracepoint can be listed from their /format file in /sys.

Apart from the filename member, we can also print flags, mode, and more.
After the "common" members listed first, the members are specific to the tracepoint.

**Additional information**

* https://www.kernel.org/doc/html/latest/trace/tracepoints.html

### uprobe, uretprobe

**variants**

* `uprobe:binary:func`
* `uprobe:binary:func+offset`
* `uprobe:binary:offset`
* `uretprobe:binary:func`

**short names**

* `u`
* `ur`

`uprobe` s or user-space probes are the user-space equivalent of `kprobe` s.
The same limitations that apply [kprobe and kretprobe](#kprobe-and-kretprobe) also apply to `uprobe` s and `uretprobe` s, namely: arguments are available via the `argN` builtins and can only be accessed with a uprobe.
retval is the return value for the instrumented function and can only be accessed with a uretprobe.
**Note**: When tracing some languages, like C++, `arg0` and even `arg1` may refer to runtime internals such as the current object instance (`this`) and/or the eventual return value for large returned objects where copy elision is used.
This will push the actual function arguments to possibly start at `arg1` or `arg2` - the only way to know is to experiment.

```
uprobe:/bin/bash:readline { printf("arg0: %d\n", arg0); }
```

What does arg0 of readline() in /bin/bash contain?
I don’t know, so I’ll need to look at the bash source code to find out what its arguments are.

When tracing libraries, it is sufficient to specify the library name instead of
a full path. The path will be then automatically resolved using `/etc/ld.so.cache`:

```
uprobe:libc:malloc { printf("Allocated %d bytes\n", arg0); }
```

If multiple versions of the same shared library exist (e.g. `libssl.so.3` and
`libssl.so.59`), bpftrace may resolve the wrong one. To fix this, you can specify
a versioned SONAME to ensure the correct library is traced:

```
uprobe:libssl.so.3:SSL_write { ... }
```

If the traced binary has DWARF included, function arguments are available in the `args` struct which can be inspected with verbose listing, see the [Listing Probes](../man/adoc/bpftrace.adoc#listing-probes) section for more details.

```
# bpftrace -lv 'uprobe:/bin/bash:rl_set_prompt'

uprobe:/bin/bash:rl_set_prompt
    const char* prompt
```

When tracing C++ programs, it’s possible to turn on automatic symbol demangling by using the `:cpp` prefix:

```
# bpftrace:cpp:"bpftrace::BPFtrace::add_probe" { ... }
```

It is important to note that for `uretprobe` s to work the kernel runs a special helper on user-space function entry which overrides the return address on the stack.
This can cause issues with languages that have their own runtime like Golang:

**example.go**

```
func myprint(s string) {
  fmt.Printf("Input: %s\n", s)
}

func main() {
  ss := []string{"a", "b", "c"}
  for _, s := range ss {
    go myprint(s)
  }
  time.Sleep(1*time.Second)
}
```

**bpftrace**

```
# bpftrace -e 'uretprobe:./test:main.myprint { @=count(); }' -c ./test
runtime: unexpected return pc for main.myprint called from 0x7fffffffe000
stack: frame={sp:0xc00008cf60, fp:0xc00008cfd0} stack=[0xc00008c000,0xc00008d000)
fatal error: unknown caller pc
```

### usdt

**variants**

* `usdt:binary_path:probe_name`
* `usdt:binary_path:[probe_namespace]:probe_name`
* `usdt:library_path:probe_name`
* `usdt:library_path:[probe_namespace]:probe_name`

**short name**

* `U`

Where probe_namespace is optional if probe_name is unique within the binary.

You can target the entire host (or an entire process’s address space by using the `-p` arg) by using a single wildcard in place of the binary_path/library_path:

```
usdt:*:loop { printf("hi\n"); }
```

Please note that if you use wildcards for the probe_name or probe_namespace and end up targeting multiple USDTs for the same probe you might get errors if you also utilize the USDT argument builtin (e.g. arg0) as they could be of different types.

Arguments are available via the `argN` builtins:

```
usdt:/root/tick:loop { printf("%s: %d\n", str(arg0), arg1); }
```

bpftrace also supports USDT semaphores.
If both your environment and bpftrace support uprobe refcounts, then USDT semaphores are automatically activated for all processes upon probe attachment (and --usdt-file-activation becomes a noop).
You can check if your system supports uprobe refcounts by running:

```
# bpftrace --info 2>&1 | grep "uprobe refcount"
bcc bpf_attach_uprobe refcount: yes
  uprobe refcount (depends on Build:bcc bpf_attach_uprobe refcount): yes
```

If your system does not support uprobe refcounts, you may activate semaphores by passing in -p $PID or --usdt-file-activation.
--usdt-file-activation looks through /proc to find processes that have your probe’s binary mapped with executable permissions into their address space and then tries to attach your probe.
Note that file activation occurs only once (during attach time).
In other words, if later during your tracing session a new process with your executable is spawned, your current tracing session will not activate the new process.
Also note that --usdt-file-activation matches based on file path.
This means that if bpftrace runs from the root host, things may not work as expected if there are processes execved from private mount namespaces or bind mounted directories.
One workaround is to run bpftrace inside the appropriate namespaces (i.e. the container).

### watchpoint

**variants**

* `watchpoint:absolute_address:length:mode`

**short names**

* `w`

This feature is experimental and may be subject to interface changes.
Memory watchpoints are also architecture dependent.

These are memory watchpoints provided by the kernel.
Whenever a memory address is written to (`w`), read
from (`r`), or executed (`x`), the kernel can generate an event.

Once the watchpoint is attached, an absolute address is monitored.

```
# bpftrace -e 'watchpoint:0x10000000:8:rw { printf("hit!\n"); }' -c ./testprogs/watchpoint
```

Print the call stack every time the `jiffies` variable is updated:

```
watchpoint:0x$(awk '$3 == "jiffies" {print $1}' /proc/kallsyms):8:w {
  @[kstack] = count();
}
```

## Pointers

Pointers in bpftrace are similar to those found in `C`.

## Structs

`C` like structs are supported by bpftrace.
Fields are accessed with the `.` operator.
If the `.` is used on a pointer, it is automatically dereferenced.
The legacy `->` operator may be used, but is purely an alias for the `.` operator.

Custom structs can be defined in the preamble.

Constructing structs from scratch, like `struct X var = {.f1 = 1}` in `C`, is not supported.
They can only be read into a variable from a pointer.

```
struct MyStruct {
  int a;
}

kprobe:dummy {
  $ptr = (struct MyStruct *) arg0;
  $st = *$ptr;
  print($st.a);
  print($ptr.a);
}
```

## Tuples

bpftrace has support for immutable N-tuples.
A tuple is a sequence type (like an array) where, unlike an array, every element can have a different type.

Tuples are a comma separated list of expressions, enclosed in brackets, `(1,"hello")`.
Individual fields can be accessed with the `.` operator or via array-style access.
The array index expression must evaluate to an integer literal at compile time (no variables but this is ok `(1, "hello")[1 - 1]`).
Tuples are zero indexed like arrays. Examples:

```
interval:s:1 {
  $a = (1,"hello");
  $b = (3,4, $a);
  print($a);     // (1, "hello")
  print($b);     // (3, 4, (1, "hello"))
  print($b.0);   // 3
  print($a[1]);  // "hello"
}
```

Single-element and empty tuples can be specified using Python-like syntax.
A single element tuple requires a trailing comma, `(1,)`, while the empty tuple is simply `()`.

## Type conversion

Integer and pointer types can be converted using explicit type conversion with an expression like:

```
$y = (uint32) $z;
$py = (int16 *) $pz;
```

Integer casts to a higher rank are sign extended.
Conversion to a lower rank is done by zeroing leading bits.

It is also possible to cast between integers and integer arrays using the same syntax:

```
$a = (uint8[8]) 12345;
$x = (uint64) $a;
```

Both the cast and the destination type must have the same size.
When casting to an array, it is possible to omit the size which will be determined automatically from the size of the cast value.

Integers are internally represented as 64 bit signed. If you need another representation, you may cast to the supported [Data Types](#data-types).

### Array casts

It is possible to cast between integer arrays and integers.
Both the source and the destination type must have the same size.
The main purpose of this is to allow casts from/to byte arrays.

```
begin {
  $a = (int8[8])12345;
  printf("%x %x\n", $a[0], $a[1]);
  printf("%d\n", (uint64)$a);
}

/*
 * Output:
 * 39 30
 * 12345
 */
```

When casting to an array, it is possible to omit the size which will be determined automatically from the size of the cast value.

This feature is especially useful when working with IP addresses since various libraries, builtins, and parts of the kernel use different approaches to represent addresses (usually byte arrays vs. integers).
Array casting allows seamless comparison of such representations:

```
fentry:tcp_connect {
    if (args.sk.__sk_common.skc_daddr == (uint32)pton("127.0.0.1"))
        ...
}
```

## Variables and Maps

bpftrace knows two types of variables, 'scratch' and 'map'.

'scratch' variables are kept on the BPF stack and their names always start
with a `$`, e.g. `$myvar`.
'scratch' variables cannot be accessed outside of their lexical block e.g.
```
$a = 1;
if ($a == 1) {
  $b = "hello"
  $a = 2;
}
```

'scratch' variables can also declared before or during initialization with `let` e.g.
```
let $a = 1;
let $b;
if ($a == 1) {
  $b = "hello"
  $a = 2;
}
```

If no assignment is specified variables will initialize to 0.

'map' variables use BPF 'maps'.
These exist for the lifetime of `bpftrace` itself and can be accessed from all action blocks and user-space.
Map names always start with a `@`, e.g. `@mymap`.

All valid identifiers can be used as `name`.

The data type of a variable is automatically determined during first assignment and cannot be changed afterwards.

### Map Declarations

***Warning*** this feature is experimental and may be subject to changes.
Stabilization is tracked in [#4077](https://github.com/bpftrace/bpftrace/issues/4077).

Maps can also be declared in the global scope, before probes and after the config e.g.
```
let @a = hash(100);
let @b = percpulruhash(20);

begin { ... }
```

The utility of this is that you can specify different underlying BPF map types.
Currently these are available in bpftrace:
- hash (BPF_MAP_TYPE_HASH)
- lruhash (BPF_MAP_TYPE_LRU_HASH)
- percpuhash (BPF_MAP_TYPE_PERCPU_HASH)
- percpulruhash (BPF_MAP_TYPE_LRU_PERCPU_HASH)

Additionally, map declarations must supply a single argument: ***max entries*** e.g. `let @a = lruhash(100);`
All maps that are not declared in the global scope utilize the default set in the config variable "max_map_keys".
However, it’s best practice to declare maps up front as using the default can lead to lost map update events (if the map is full) or over allocation of memory if the map is intended to only store a few entries.

***Warning*** The "lru" variants of hash and percpuhash evict the approximately least recently used elements. In other words, users should not rely on the accuracy on the part of the eviction algorithm. Adding a single new element may cause one or multiple elements to be deleted if the map is at capacity. [Read more about LRU internals](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_LRU_HASH/).

### Maps without Explicit Keys

Values can be assigned directly to maps without a key (sometimes refered to as scalar maps).
Note: you can’t iterate over these maps as they don’t have an accessible key.

```
@name = expression
```

### Map Keys

Setting single value map keys.

```
@name[key] = expression
```

Map keys that are composed of multiple values are represented as tuples e.g.

```
@name[(key1,key2)] = expression
```

However, this, more concise, syntax is supported and the same as the explicit
tuple above:

```
@name[key1,key2] = expression
```

Just like with any variable the type is determined on first use and cannot be modified afterwards.
This applies to both the key(s) and the value type.

The following snippets create a map with key signature `(int64, string)` and a value type of `int64`:

```
@[pid, comm]++
@[(pid, comm)]++
```

### Per-Thread Variables

These can be implemented as a map keyed on the thread ID. For example, `@start[tid]`:

```
kprobe:do_nanosleep {
  @start[tid] = nsecs;
}

kretprobe:do_nanosleep /has_key(@start, tid)/ {
  printf("slept for %d ms\n", (nsecs - @start[tid]) / 1000000);
  delete(@start, tid);
}

/*
 * Sample output:
 * slept for 1000 ms
 * slept for 1009 ms
 * slept for 2002 ms
 * ...
 */
```

This style of map may also be useful for capturing output parameters, or other context, between two different probes. For example:

```
tracepoint:syscalls:sys_enter_wait4
{
  @out[tid] = args.ru;
}

tracepoint:syscalls:sys_exit_wait4
{
  $ru = @out[tid];
  delete(@out, tid);
  if ($ru != 0) {
    printf("got usage ...", ...);
  }
}
```

---

## Advanced Topics

### Address Spaces

Kernel and user pointers live in different address spaces which, depending on the CPU architecture, might overlap.
Trying to read a pointer that is in the wrong address space results in a runtime error.
This error is hidden by default but can be enabled with the `-k` flag:

```
stdin:1:9-12: WARNING: Failed to probe_read_user: Bad address (-14)
begin { @=*uptr(kaddr("do_poweroff")) }
        ~~~
```

bpftrace tries to automatically set the correct address space for a pointer based on the probe type, but might fail in cases where it is unclear.
The address space can be changed with the [kptrs](stdlib.md#kptr) and [uptr](stdlib.md#uptr) functions.

### BPF License

By default bpftrace uses "GPL", which is actually "GPL version 2", as the license it uses to load BPF programs into the kernel.
Some other examples of compatible licenses are: "GPL v2" and "Dual MPL/GPL".
You can specify a different license using the "license" config variable.
[Read more about BPF programs and licensing](https://docs.kernel.org/bpf/bpf_licensing.html#using-bpf-programs-in-the-linux-kernel).

### BTF Support

If the kernel version has BTF support, kernel types are automatically available and there is no need to include additional headers to use them.
It is not recommended to mix definitions from multiple sources (ie. BTF and header files).
If your program mixes definitions, bpftrace will do its best but can easily get confused due to redefinition conflicts.
Prefer to exclusively use BTF as it can never get out of sync on a running system. BTF is also less susceptible to parsing failures (C is constantly evolving).
Almost all current linux deployments will support BTF.

To allow users to detect this situation in scripts, the preprocessor macro `BPFTRACE_HAVE_BTF` is defined if BTF is detected.
See `tools/` for examples of its usage.

Requirements for using BTF for vmlinux:

* Linux 4.18+ with CONFIG_DEBUG_INFO_BTF=y
  * Building requires dwarves with pahole v1.13+
* bpftrace v0.9.3+ with BTF support (built with libbpf v0.0.4+)

Additional requirements for using BTF for kernel modules:

* Linux 5.11+ with CONFIG_DEBUG_INFO_BTF_MODULES=y
  * Building requires dwarves with pahole v1.19+

See kernel documentation for more information on BTF.

### Clang Environment Variables

bpftrace parses header files using libclang, the C interface to Clang.
Thus environment variables affecting the clang toolchain can be used.
For example, if header files are included from a non-default directory, the `CPATH` or `C_INCLUDE_PATH` environment variables can be set to allow clang to locate the files.
See clang documentation for more information on these environment variables and their usage.

### Complex Tools

bpftrace can be used to create some powerful one-liners and some simple tools.
For complex tools, which may involve command line options, positional parameters, argument processing, and customized output, consider switching to bcc.
bcc provides Python (and other) front-ends, enabling usage of all the other Python libraries (including argparse), as well as a direct control of the kernel BPF program.
The down side is that bcc is much more verbose and laborious to program.
Together, bpftrace and bcc are complimentary.

An expected development path would be exploration with bpftrace one-liners, then and ad hoc scripting with bpftrace, then finally, when needed, advanced tooling with bcc.

As an example of bpftrace vs bcc differences, the bpftrace xfsdist.bt tool also exists in bcc as xfsdist.py. Both measure the same functions and produce the same summary of information.
However, the bcc version supports various arguments:

```
# ./xfsdist.py -h
usage: xfsdist.py [-h] [-T] [-m] [-p PID] [interval] [count]

Summarize XFS operation latency

positional arguments:
  interval            output interval, in seconds
  count               number of outputs

optional arguments:
  -h, --help          show this help message and exit
  -T, --notimestamp   don't include timestamp on interval output
  -m, --milliseconds  output in milliseconds
  -p PID, --pid PID   trace this PID only

examples:
    ./xfsdist            # show operation latency as a histogram
    ./xfsdist -p 181     # trace PID 181 only
    ./xfsdist 1 10       # print 1 second summaries, 10 times
    ./xfsdist -m 5       # 5s summaries, milliseconds
```

The bcc version is 131 lines of code. The bpftrace version is 22.

### Errors

1. Looks like the BPF stack limit of 512 bytes is exceeded BPF programs that operate on many data items may hit this limit.
There are a number of things you can try to stay within the limit:
   1. Find ways to reduce the size of the data used in the program. Eg, avoid strings if they are unnecessary: use pid instead of comm. Use fewer map keys.
   2. Split your program over multiple probes.
   3. Check the status of the BPF stack limit in Linux (it may be increased in the future, maybe as a tuneable).
   4. (advanced): Run -d and examine the LLVM IR, and look for ways to optimize src/ast/codegen_llvm.cpp.
2. Kernel headers not found
bpftrace requires kernel headers for certain features, which are searched for by default in: `/lib/modules/$(uname -r)`.
The default search directory can be overridden using the environment variable BPFTRACE_KERNEL_SOURCE and also BPFTRACE_KERNEL_BUILD if it is out-of-tree Linux kernel build.

### Map Printing

By default when a bpftrace program exits it will print all maps to stdout.
If you don’t want this, you can either override the `print_maps_on_exit` configuration option or you can specify an `end` probe and `clear` the maps you don’t want printed.

For example, these two scripts are equivalent and will print nothing on exit:
```
config = {
  print_maps_on_exit=0
}

begin {
  @a = 1;
  @b[1] = 1;
}
```

```
begin {
  @a = 1;
  @b[1] = 1;
}

end {
  clear(@a);
  clear(@b);
}
```

### PERCPU types

For bpftrace PERCPU map types (e.g., those created by using [`count()`](stdlib.md#count) or [`sum()`](stdlib.md#sum)) you may coerce
(and thus force a more expensive synchronous read) the type to an integer using
a cast or by doing a comparison. This is useful for when you need an integer
during comparisons, `printf()`, or other.

For example:

```
begin {
  @c = count();
  @s = sum(3);
  @s = sum(9);

  if (@s == 12) {                             // Coerces @s
    printf("%d %d\n", (int64)@c, (int64)@s);  // Coerces @c and @s and prints "1 12"
  }
}
```

### Supported architectures

x86_64, arm64, s390x, arm32, loongarch64, mips64, ppc64, riscv64

### Systemd support

If bpftrace has been built with `-DENABLE_SYSTEMD=1`, one can run bpftrace in
the background using systemd::
```
# systemd-run --unit=bpftrace --service-type=notify bpftrace -e 'kprobe:do_nanosleep { printf("%d sleeping\n", pid); }'
```

In the above example, systemd-run will not finish until bpftrace has attached
its probes, so you can be sure that all following commands will be traced. To
stop tracing, run `systemctl stop bpftrace`.

To debug early boot issues, bpftrace can be invoked via a systemd service
ordered before the service that needs to be traced. A basic unit file to run
bpftrace before another service looks as follows::
```
[Unit]
Before=service-i-want-to-trace.service

[Service]
Type=notify
ExecStart=bpftrace -e 'kprobe:do_nanosleep { printf("%d sleeping\n", pid); }'
```

Similarly to the systemd-run example, the service to be traced will not start
until bpftrace started by the systemd unit has attached its probes.

### Unstable Features

Some features added to bpftrace are not yet stable.
They are enabled by default but come with a warning if used.
If you explicitly add the config variable to your script the warning will not be shown e.g.
```
config = {
    unstable_map_decl=enable;
}
```

To opt-out of these unstable features (and ensure they are not used) add the config variable and set it to `error` e.g.
```
config = {
    unstable_map_decl=error;
}
```

Note: all unstable features are subject to change and/or removal.
