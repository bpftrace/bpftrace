# Type Resolution

This explains how bpftrace handles type inference and resolution resulting in static types at runtime. The pass that does this is called the `TypeResolver` (type_resolver.cpp) and inside this pass is the `TypeRuleCollector` visitor, which walks the AST and emits rules into a `TypeResolver`. The solver then propagates types through the rule graph using a worklist-based algorithm until a fixpoint is reached (basically a `TypeVariable` is fully resolved). However, there a lot of additional non-standard complexities that are included as part of the bpftrace language.

It consists of 4 different visitors:

#### `TypeRuleCollector`
Walks the AST and collects type rules into a `TypeResolver`. For leaf nodes with known types (e.g. integer literals), it seeds the solver directly. For compound nodes, it registers rules that compute output types from input types. Does not mutate the AST but may run multiple times due to AST transformations in the `AstTransformer`.

#### `AstTransformer`
Utilizes the resolve types from the `TypeRuleCollector`/`TypeResolver` to transform introspection functions (e.g. `sizeof`, `typeinfo`) and create/expand calls to memcmp (for tuples and records).

#### `TypeApplicator`
Utilizes the resolved Types from the *final* `TypeRuleCollector`/`TypeResolver` run to add the `SizedType` to the AST nodes themselves. Note: this may go away in the future if future passes just consume the map of resolved types instead of relying on state in the AST nodes.

#### `CastCreator`
Injects casts based on the resolved types of the AST, e.g. so the left and right of a binop are the same type and size.

## The Basics
The `TypeRuleCollector` visitor walks the AST and builds up a set of rules in a `TypeResolver`. Each rule has an output `TypeVariable`, a set of input `TypeVariable`s, and a `resolve` function (lambda) that computes the output type from the input types. A `TypeVariable` is a variant of `Node *`, `ScopedVariable`, or `std::string` (the last one being used for map keys/values, as these are often resolved separately by different statements/expressions, e.g. `@a = 1; $b = @b["str"]`).

For nodes with already-known types (e.g. integer literals, builtins), the collector calls `resolver.set_type()` to seed the resolver. For compound nodes (e.g. binops, field accesses), it calls `resolver.add_type_rule()` with a lambda describing how the output type derives from input types. For simple type forwarding (e.g. variable references), it calls `resolver.add_pass_through()`.

After all rules are collected, `resolver.resolve()` runs a worklist-based propagation algorithm:
1. Seed the worklist from nodes with known types by enqueuing all rules that depend on them.
2. Pop a rule from the worklist and check if all its inputs are resolved (non-NoneTy).
3. Invoke the rule's solve lambda with the resolved input types.
4. If the result differs from the rule's previous result, update the output type and enqueue all rules that depend on this output.
5. Repeat until the worklist is empty (fixpoint reached).

### Example Iteration
```
$a = 1; $b = $a;
```

**Collect (visiting the AST)**
1. the `ScopedVariable` `$a` depends on the `Node *` on the right side of the assignment (integer literal `1`) via a rule
1. variable `Node *` `$a` on the left side of the assignment depends on `ScopedVariable` `$a` via a pass-through rule
1. the integer literal `1` gets seeded with a known type (`uint8`) in the resolver
1. the `ScopedVariable` `$b` depends on the `Node *` on the right side of the assignment (Variable `$a`) via a rule
1. `$a` (on the right side of `$b`) depends on the `ScopedVariable` `$a` via a pass-through rule

Notice the distinction between the variable `Node *` `$a` and the `ScopedVariable` `$a`. The latter is not an AST object but something specific to the `TypeRuleCollector`. `ScopedVariable` is responsible for tracking the type of a variable and then updating the associated variable `Node *`s. This is needed because there are multiple variable AST objects associated with a single scratch variable (`ScopedVariable`), e.g., `$a = 1; print($a); $a = (uint32)2`.

**Resolve (rule propagation)**
1. start the worklist-based rule propagation
1. pop from the worklist a rule whose input (`1`) has type `uint8`
1. the rule's `resolve` function checks if `ScopedVariable` `$a` already has a compatible type
1. it sees `$a` has a `None` type (by looking it up in the `types_` map). The lambda (`resolve`) returns `uint8`.
1. the resolver sets `uint8` as the type for `ScopedVariable` `$a` in `types_` and enqueues all rules that depend on `$a`
1. it processes the pass-through rules for the two variable `Node *`s for `$a`, setting both to `uint8`
1. finally since `ScopedVariable` `$b` depends on Variable `Node *` `$a`, its type also gets set to `uint8` in the `types_` map

The reason we store all the types in a separate map as opposed to on the AST nodes themselves is because the `TypeRuleCollector` visitor may need to run multiple times to resolve things like comptime branches (more on this later). We need a clean state every time we run or else weird things happen that are hard to debug. When the `TypeRuleCollector` visitor is done running (possibly multiple times). This `types_` map is then passed to the `TypeApplicator` visitor which uses it to set the types on the AST nodes.

## Preventing Infinite Loops
There is a really easy example that demonstrates how we might end up with an infinite loop when propagating types through the rule worklist. Consider this example:
```
$a = 1; $a = $a + 1;
```
The second statement demonstrates that `$a` depends on the result of the binop on the right side. The binop depends on both `$a` and `1`. So when `$a` is resolved from the first statement and `1` is resolved, we enter the infinite loop of resolving `$a` then resolving the binop then resolving `$a` again and so forth. The solver does something very simple in that if it sees that the type returned by the rule's solve function is the same as the type already previously returned by that rule then it simply stops propagating. In this case the binop resolves to a `uint64` so when `$a` becomes a `uint64` and re-triggers the binop rule, it already has this result and stops.

## Breadth First Search
The resolver utilizes a BFS (worklist/queue) to propagate types instead of a DFS to prevent an issue with stale updates.
For example:
```
let $a; $a = $a + 1; $a = 1;
```
There are 4 `$a` variable `Node *`s that need types. They should all resolve to the same type with their input being the `ScopedVariable` `$a` in the rule graph. In a depth first search when we resolve the first integer literal `1` and set the type of the `ScopedVariable` `$a` to `uint8`, we have 4 rules to process. When we process the third one (the left operand in the binop) the binop resolves to a `uint64` setting this as the type of the `ScopedVariable` `$a`. We then process all 4 rules again setting the 4 `$a` variable nodes to type `uint64`. All is OK **BUT** we have one last rule left over from the first update to `ScopedVariable` `$a` which sets the last `$a` node (`$a = 1`) to a `uint8` - here is the stale update.

## Comptime branches
A large source of complication in the `TypeRuleCollector` visitor is the existance of `comptime` branches, e.g. `if comptime (...) { } else { }`. There are some `comptime` expressions that get resolved before we ever reach the `TypeRuleCollector` visitor (e.g. `if comptime (1 == 1)`) but some `comptime` expressions rely on knowing the types of things, e.g. `if comptime (typeinfo($a).full_ty == "uint64"))`. For these we need to wait to fully resolve the type of `$a` before we can evaluate this `comptime` expression. Additionally `comptime` branches may further expose parts of the rule graph that we couldn't visit before. For example:
```
$a = 1;
if comptime (typeinfo($a).full_ty == "uint64") {
  @map = 1;
} else {
  @map = "str";
}
$a = (uint64)2;
```
In this case the value type of map `@map` changes depending on which branch we take.

So in order to resolve the type of `$a` we need a full resolution of the `TypeRuleCollector` visitor (minus the `comptime` branches). We then call upon the `AstTransformer` to transform `typeinfo($a)` into a literal record (e.g. `(btf_id=0, base_ty="int", full_ty="uint64")`). We can then evaluate/fold the comptime expression and, if it's part of a conditional in an `if` statement (like above), decide what branch to keep.

We then need to re-run the `TypeRuleCollector` visitor because there are new branches to visit. We basically have to keep doing this until we either have no more `comptime` expressions (as they can be nested) OR we reach a point where we simply can't resolve them (and return an error).

## Locked `TypeVariable`s

Let's look at a slight variation to the `comptime` example above:
```
$a = 1;
if comptime (typeinfo($a).full_ty == "uint32") {
  $a = (uint64)3;
}
$a = (uint32)2;
```
Hopefully you spot the issue right away. We resolve the type of `$a` to be a `uint32`, the `comptime` expression evaluates to `true` and we take a branch that then sets the type of `ScopedVariable` `$a` to `uint64`. How can `$a` be both a `uint32` and a `uint64`? **It can't**. This is where `locked_nodes` comes in. It's a simple map that gets passed to subsequent `TypeRuleCollector` runs from former ones, indicating which `TypeVariable`s have "locked" types - meaning they can't be changed. In this case because `$a` was evaluated inside of a introspection function (`typeinfo`) it is locked and trying to change it's type results in an error.

However, `TypeVariable`s that are not used inside of introspection functions (`typeinfo`, `typeof`, `sizeof`, `offsetof`) CAN be changed inside of `comptime` branches.

## Variable Declarations
One neat thing we can do with the `TypeRuleCollector`'s design is around the handling of variables with explicit type declarations.
Example:
```
$b = 1;
let $a: typeof($b) = "str";
```
This is clearly an error as the type of `$a` is a `uint8` and we're trying to assign a string literal to it. However, the error itself doesn't manifest in the `TypeRuleCollector` visitor. This is because we completely ignore the right side of the assignment to determine the type of `$a` because it has a type declaration. Then in a later pass, we simply issue an error if the right side type is not compatible with the left side. This reduces some complication and added state required to track what variables have explicit type declarations. Except types with no size - in these cases we need the RHS to know how big the type is, e.g. `let $a: string = "hello"`.

## Casting
Inserted casts are reserved for `CastCreator` based on the types resolved in the `TypeRuleCollector` visitor.
Example:
```
$a = 1;
$b = 1;
$a = $b;
$a = (uint32)2;
```
In this example both `$a` and `$b` start off as `uint8` but the last assignment transforms `$a` into a `uint32` (propagating to all the `$a` variable `Node *`s). So the statement `$a = $b` is valid because `uint8` fits into `uint32` but the type of `$b` shouldn't change, we just need to add a cast so both sides are of the same type. So `$a = $b` becomes `$a = (uint32)$b`. This is done in the `CastCreator` for the purposes of not overcomplicating the `TypeRuleCollector` visitor and separating the concern of cast injection, which doesn't change the types of the `TypeVariable`s but just inserts an expression that doesn't require type evaluation (namely the cast to a specific type).
