# Type Resolution

This explains how bpftrace handles type inference and resolution resulting in static types at runtime. The complicated pass that does this is called the TypeGraphPass (type_graph.cpp) and inside this pass is the the TypeGraph visitor, which builds up a graph of types as it walks the AST and then resolves them with a breath first search approach.

## The Basics
The main TypeGraph visitor creates a type graph, which is a map of Sources to Consumers (a one to many relationship). When the Source's type resolves or changes then each Consumer "subscribing" to this Source will have their callback invoked (with this type as the argument), which returns another type or std::nullopt. The Source is a `GraphNode`, which is a variant (`Node *`, `Typeof *`, `ScopedVariable`, `std::string`). The `std::string` represents either a map key or a map value as these are often resolved separately by different statements/expressions (e.g. `@a = 1; $b = @b["str"]`).

In addition to a callback function, the Consumer struct consists of another `GraphNode` (the Consuming node) and after the callback returns we use this Consumer `GraphNode` as the next Source to lookup the next set of Consumers to call with the returned type in the graph/map.

### Example Iteration
```
$a = 1; $b = $a;
```

**visit**
1. the ScopedVariable `$a` subscribes to the Node on the right side of the assignment (integer literal `1`)
1. variable `Node` `$a` on the left side of the assignment subscribes to ScopedVariable `$a`
1. the integer literal `1` gets added to a queue of already resolved types (we already know it's a `uint8`)
1. the ScopedVariable `$b` subscribes to the Node on the right side of the assignment (Variable `$a`)
1. `$a` (on the right side of `$b`) subscribes to the ScopedVariable `$a`

Notice the distinction between the variable `Node` and a `ScopedVariable`. The latter is not an AST object but something specific to the TypeGraph. `ScopedVariable` is responsible for tracking the type of a variable and then updating the associated variable `Node`s.

**resolve**
1. start type propagation
1. pop from the queue of resolved types
1. finding `1` with a type of `uint8`, we see if this Node has any consumers in the graph
1. we find the ScopedVariable `$a` and in this case the Consumer callback does some checking to see if this ScopedVariable already has a type that is compatible with `uint8`
1. the callback sees that it has a `None` type (by looking it up in the `resolved_types_` map). It can safely forward/return `uint8`
1. the `propagate_resolved_types` logic gets the `uint8` from the returned Consumer callback and sets this as the value of the Consumer `GraphNode` in `resolved_types_`. In this case ScopedVariable `$a`.
1. it then looks to see if the graph has any Consumers for the ScopedVariable `$a` and finds two variable `Node`s for `$a`
1. the callbacks for Variable Node `$a` both return this new type
1. `propagate_resolved_types` sets the value for both variable `Node`s `$a` to `uint8` in the `resolved_types_` map
1. finally since ScopedVariable `$b` is subscribed to Variable `Node` `$a` it's type also gets set to `uint8` in the `resolved_types_` map

The reason we store all the types in a separate map as opposed to on the AST nodes themselves is because the TypeGraph visitor may need to run multiple times to resolve things like comptime branches (more on this later). We need a clean state every time we run or else weird/bad things happen that are hard to debug. When the TypeGraph visitor is done running (possibly multiple times). This `resolved_types` map is then passed to the TypeApplicator visitor which uses it to set the types on the AST nodes.

## Preventing Infinite Loops
There is a really easy example that demonstrates how we might end up with an infinite loop when propagating types through the graph. Consider this example:
```
$a = 1; $a = $a + 1;
```
The second statement demonstrates that `$a` is subscribed to the result of the binop on the right side. The binop is subscribed to both `$a` and `1`. So when `$a` is resolved from the first statement and `1` is resolved, we enter the infinite loop of resolving `$a` then resolving the binop then resolving `$a` again and so forth. The TypeGraph does something very simple in that if it sees that the type returned by the Consumer callback is the same as the type already previously set by that callback then it simply stops propagating. In this case the binop resolves to a `uint64` so when `$a` becomes a `uint64` and re-triggers the binop, it already has this type and therefore stops.

## Breath First Search
`propagate_resolved_types` utilizes a BFS to propagate types instead of a DFS to prevent an issue with stale updates.
For example:
```
let $a; $a = $a + 1; $a = 1;
```
There are 4 `$a` variable `Node`s that need types. They should all resolve to the same type with their Source being the ScopedVariable `$a` in the graph. In a depth first search when we resolve the first integer literal `1` and set the type of the ScopedVariable `$a` to `uint8`, we have 4 callbacks to fire. When we fire the third one (the left statement in the binop) the binop resolves to a `uint64` setting this as the type of the ScopedVariable `$a`. We then fire all 4 callbacks again setting the 4 `$a` variable nodes to type `uint64`. All is OK **BUT** we have one last callback left over from the first update to ScopedVariable `$a` which sets the last `$a` node (`$a = 1`) to a `uint8` - here is the stale update. Walk this example yourself to see why a BFS approach fixes this problem.

## Comptime branches
A large source of complication in the TypeGraph visitor is the existance of `comptime` branches, e.g. `if comptime (...) { } else { }`. There are some `comptime` expressions that get resolved before we ever reach the TypeGraph visitor (e.g. `if comptime (1 == 1)`) but some `comptime` expressions rely on knowing the types of things, e.g. `if comptime (typeinfo($a).full_ty == "uint64"))`. For these we need to wait to fully resolve the type of `$a` before we can evaluate this `comptime` expression. Additionally `comptime` branches may further expose parts of the type graph that we couldn't visit before. For example:
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

So in order to resolve the type of `$a` we need a full resolution of the TypeGraph visitor (minus the `comptime` branches). We then call upon the `AstTransformer` to transform `typeinfo($a)` into a literal record (e.g. `(btf_id=0, base_ty="int", full_ty="uint64")`). We can then evaluate the comptime expression and, if it's part of a conditional in an `if` statement (like above), decide what branch to keep.

We then need to re-run the TypeGraph visitor because there are new branches to visit. We basically have to keep doing this until we either have no more `comptime` expressions (as they can be nested) OR we reach a point where we simply can't resolve them (and return an error).

## Locked GraphNodes

Let's look at a slight variation to the `comptime` example above:
```
$a = 1;
if comptime (typeinfo($a).full_ty == "uint32") {
  $a = (uint64)3;
}
$a = (uint32)2;
```
Hopefully you spot the issue right away. We resolve the type of `$a` to be a `uint32`, the `comptime` expression evaluates to `true` and we take a branch that then sets the type of ScopedVariable `$a` to `uint64`. How can `$a` be both a `uint32` and a `uint64`? **It can't**. This is where `locked_nodes` comes in. It's a simple map that gets passed to subsequent TypeGraph visits from former ones, indicating which `GraphNode`s have "locked" types - meaning they can't be changed. In this case because `$a` was evaluated inside of a introspection function (`typeinfo`) it is locked and trying to change it's type results in an error.

However, `GraphNodes` that are not used inside of introspection functions (`typeinfo`, `typeof`, `sizeof`, `offsetof`) CAN be changed inside of `comptime` branches.

## Variable Declarations
One neat thing we can do with the TypeGraph's design is around the handling of variables with explicit type declarations.
Example:
```
$b = 1;
let $a: typeof($b) = "str";
```
This is clearly an error as the type of `$a` is a `uint8` and we're trying to assign a string literal to it. However, the error itself doesn't manifest in the TypeGraph visitor. This is because we completely ignore the right side of the assignment to determine the type of `$a` because it has a type declaration. Then in a later pass, we simply issue an error if the right side type is not compatible with the left side. This reduces some complication and added state required to track what variables have explicit type declarations. Except types with no size - in these cases we need the RHS to know how big the type is, e.g. `let $a: string = "hello"`.

## Casting
Inserted casts are reserved for a separate visitor, but still in the TypeGraphPass.
Example:
```
$a = 1;
$b = 1;
$a = $b;
$a = (uint32)2;
```
In this example both `$a` and `$b` start off as `uint8` but the last assignment transforms `$a` into a `uint32` (propagating to all the `$a` variable Nodes). So the statement `$a = $b` is valid because `uint8` fits into `uint32` but the type of `$b` shouldn't change, we just need to add a cast so both sides are of the same type. This is done in the CastCreator visitor. Again, for the purposes of not overcomplicating the TypeGraph visitor and separating the concern of cast injection, which doesn't change the types of the GraphNodes but just inserts an expression that doesn't require type evaluation (namely the cast to a specific type).

## Pointer Sources
TODO

## Small Regressions/Changes

$x = (int8)1; $x = 5; - This now becomes $x = (int16)(int8)1; $x = 5; because $x got promoted to int16 - we can fix this but it makes the logic more complicated.
