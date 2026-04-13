# Language Lexing and Parsing

This describes the technical design and implementation of bpftrace's
recursive descent parser (`src/parser`).

## Overview

The `Parser` class is a single-pass recursive descent parser that transforms bpftrace source text into an AST. There is no separate lexer/tokenizer phase.

Key design properties:
- **No separate lexer**: tokenization is done inline via helper methods (`consume_identifier`, `consume_string`, `match`,
  `expect`, etc.).
- **Single-pass**: the parser walks the input left-to-right once, building AST nodes as it goes.
- **Backtracking via SavePoint**: ambiguous constructs (casts vs. grouping, records vs. expressions, trailing expressions) use `SavePoint` to speculatively try one parse and rewind if it fails.
- **Precedence climbing** for binary expressions.
- **All AST nodes are allocated through `ASTContext`** (`ctx_.make_node<T>(...)`), which owns their memory.

## Entry Points

```
Parser::parse()      -> ast::Program*    // Full program parse
Parser::parse_expr() -> optional<Expression>  // Single expression (used by CMacroExpander)
```

## Grammar Structure

The parser is organized into four layers of grammar rules, roughly ordered
from outermost to innermost.

### 1. Program-level grammar (`parse_program`)

Parses the full top-level structure of a bpftrace script.
It enforces a strict ordering of sections:

```
Header     = "#!" ... "\n"           (shebang line)
Preamble   = Config | RootImport
CDefinitions = CPreprocessor | CDefinition
MainItems  = Probe | Macro | Subprog | MapDeclStmt
```

**Constructs at this level:**

| Method                  | Parses                                    |
|-------------------------|-------------------------------------------|
| `parse_c_preprocessor`  | `#include`, `#define`, etc. (line-based)  |
| `parse_c_definition`    | `struct/union/enum Name { ... }`          |
| `parse_config`          | `config = { key = value; ... }`           |
| `parse_root_import`     | `import "path";`                          |
| `parse_macro`           | `macro name(args) { ... }`                |
| `parse_subprog`         | `fn name($a: type, ...) : ret_type { ... }` |
| `parse_map_decl_stmt`   | `let @name = type(N);`                    |
| `parse_probe`           | `attach_points /predicate/ { ... }`       |

### 2. Block and statement grammar

**`parse_block`** parses a `{ ... }` block. It supports an optional trailing expression (no semi-colon).

Inside a block, the parser dispatches on keywords and sigil characters:

| Input starts with | Dispatches to                     |
|-------------------|-----------------------------------|
| `import`          | `parse_statement_import`          |
| `while`, `unroll` | `parse_while_or_unroll`           |
| `for`             | `parse_for`                       |
| `break`, `continue`,  `return` | Control flow         |
| `_ =`             | Discard expression (`DiscardExpr`) |
| `let`             | `parse_statement` (variable declaration) |
| `$` or `@`        | `parse_sigiled_stmt_or_trailing_expr` |
| anything else     | Parse as expression, then check for `;` or `}` |

**`parse_statement`** handles:
- `let $x`, `let $x = expr`, `let $x : type = expr` — variable declarations
- `$x = expr`, `$x += expr`, `$x++` — variable assignments/mutations
- `@m = expr`, `@m[k] = expr` — map assignments
- Fall-through to expression statements

**`make_assignment_or_expr`** is the core disambiguation function for
statements that begin with `$var` or `@map`. It tries, in order:
1. Simple assignment (`=`)
2. Compound assignment (`+=`, `-=`, `<<=`, etc. via `try_compound_op`)
3. Post-increment/decrement (`++`/`--`)
4. Otherwise, parse remaining postfix/binary operators and treat as an
   expression statement

**`parse_sigiled_stmt_or_trailing_expr`** handles the ambiguity when a `$`
or `@` expression appears at the end of a block. It speculatively parses as
a statement; if the result is an `ExprStatement` and the next token is `}`,
it backtracks and re-parses as a trailing expression.

### 3. Expression grammar

Expression parsing follows standard recursive descent with precedence
climbing for binary operators.

```
Expression = Ternary
Ternary    = Binary ("?" Ternary ":" Ternary)?
           | Binary ("?" ":" Ternary)?        // short form: expr ?: default
Binary     = Unary (BinOp Unary)*             // precedence climbing
Unary      = "++" Unary | "--" Unary | "&" Unary
           | "*" Unary | "-" Unary | "!" Unary | "~" Unary
           | Postfix
Postfix    = Primary ("." field | "->" field | "[" expr "]" | "++" | "--")*
Primary    = "(" ParenExpr ")"
           | "if" ... | "sizeof" ... | "offsetof" ... | "typeinfo" ...
           | "comptime" Unary
           | "{" Block "}"
           | Call | Builtin | Identifier
           | "@" MapWithKeys | "$" Variable | Integer | String
           | "true" | "false"
```

#### Precedence climbing (`parse_binary`)

Binary operator precedence is handled by the `get_binop` function, which
returns an `{operator, precedence}` pair. `parse_binary(min_prec)` consumes
operators at or above `min_prec`, recursing with `prec + 1` for the
right operand (left-to-right associativity).

Precedence levels (low to high):

| Prec | Operators          |
|------|--------------------|
| 1    | `\|\|`             |
| 2    | `&&`               |
| 3    | `\|` (bitwise)     |
| 4    | `^`                |
| 5    | `&` (bitwise)      |
| 6    | `==`, `!=`         |
| 7    | `<`, `>`, `<=`, `>=` |
| 8    | `<<`, `>>`         |
| 9    | `+`, `-`           |
| 10   | `*`, `/`, `%`      |

Compound assignment operators (`+=`, etc.) are explicitly excluded from `get_binop`.

#### Parenthesized expressions (`parse_paren_expr`)

A `(` can introduce four different constructs. `parse_paren_expr` disambiguates them in order:

1. **Empty tuple**: `()`
2. **Record literal**: `(name=expr, ...)`
3. **Cast expression**: `(type)expr` — lookahead sees a type name followed
   by `)`, then an expression-starting character
4. **Tuple or grouping**: `(expr, ...)` or `(expr)` — comma means tuple,
   no comma means grouping

Records and casts use `try_parse_record` / `try_parse_cast_expr`.

### 4. Type parsing

`try_parse_type_reference` handles type syntax: `int32`, `string[64]`, `struct foo *`, `void`, `bare_ident`, etc. It supports arrays (`type[N]`), pointers (`type *`), and composite type keywords (`struct`, `union`, `enum`).

`parse_type_annotation` parses type annotations in `let` declarations and function signatures. It accepts either a type name directly or `typeof(...)`.

## Comment and whitespace handling

`consume_layout()` handles `//` line comments, `/* */` block comments, and records both comments and vertical whitespace (blank lines) in the `ASTContext` via `ctx_.add_comment(loc)` and `ctx_.add_vspace(loc, count)`. This information is used by the formatter (`bpftrace --fmt`) to preserve comment placement and blank-line structure. Vertical space is suppressed after `{`, `}`, and `;` to avoid double-spacing.

## Backtracking with SavePoint

`SavePoint` captures `(pos_, line_, col_)` and can `restore()` them. This is used in several places to lookahead and restore the current state if there is no match.

## Error Handling and Recovery

Errors are reported via `ctx_.state_->diagnostics_->addError(...)`.

Parsing stops early when `has_errors()` returns true (checked in loops).
Several methods include error recovery, e.g. `skip_to_block_end()`.

## Debug Tracing

This requires both the `-d parse` command line option and a Debug build of bpftrace.
When active, the `PARSE_TRACE` macro logs which grammar rules are entered and what token is being examined, producing output like:

```
[parse] 1:1 parse_program
[parse] 1:1 parse_probe
[parse] 1:1 parse_attach_point
[parse] 1:9 parse_block
[parse] 1:11 parse_expression
[parse] 1:11 parse_primary, next='$'
```

Note: The debug flag is always disabled when parsing standard library `.bt` files in `resolve_imports.cpp`.

## Adding a New Syntactic Construct

1. **Define AST node(s)** in `src/ast/ast.h`.
2. **Add a `parse_*` method** to `Parser` (declare in the header, define
   in the `.cpp`).
3. **Wire it into the appropriate dispatch point**:
   - Program-level: add a keyword check in `parse_program`'s main loop.
   - Statement-level: add to `parse_block`'s keyword dispatch or
     `parse_statement`.
   - Expression-level: add to `parse_primary` or as a new precedence level
     in `parse_binary`.
4. **Handle ambiguity**: if your construct's syntax overlaps with existing
   constructs, use `SavePoint` for backtracking or add a `looks_like_*`
   lookahead helper.
5. **Add tests**: parser tests live in `tests/parser.cpp`.
