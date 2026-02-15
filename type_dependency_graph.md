# Variables

## Case 1

let $x: uint32 = $y;

$y = (uint32)2;

$y = (uint64)3;

**Result**: Error
**Reason**: Because $y was promoted to a uint64 but $x has a concrete type of uint32 and can't be resized

## Case 2

let $x: uint32 = $y;

$y = (uint8)2;
$y = (uint16)3;

**Result**: Success
**Reason**: Because $y was promoted to a uint16 which fits into uint32, the concrete type of $x

## Case 3

let $x;
let $y;

$x = $y;
$y = $x;

**Result**: Error
**Reason**: Cyclic type dependency

## Case 4

$x = $y + 1;

$y = (uint32)1;
$y = (uint64)2;

**Result**: Success
**Reason**: Both $x and $y are of type uint64

## Case 5

let $a;
let $x: typeof($a) = (uint64)10;

$a = (uint16)1;
$a = (uint32)2;

**Result**: Error
**Reason**: $a gets promoted to a uint32 so the `typeof($a)` resolves to a uint32 making the type of $x a concrete type of uint32 so the assignment on the right of a uint64 is invalid.

## Case 6

let $a;
let $x: uint32 = (typeof($a))10;

$a = (uint16)1;
$a = (uint64)2;

**Result**: Error
**Reason**: $a gets promoted to a uint64 so the `typeof($a)` cast resolves to a uint64 which is incompatible with the concrete type of $x which is uint32

## Case 6

let $a;
let $x = (typeof($a))10;

$a = (uint64)2;

**Result**: Success
**Reason**: $a gets promoted to a uint64 so the `typeof($a)` cast resolves to a uint64 so the type of $x is a uint64

## Case 7

let $a;
let $b;

if comptime typeinfo($b).base_ty == "str" {
    $a = "hello";
} else {
    $a = 1;
}

$b = 1;

**Result**: Success
**Reason**: The type of $a is a uint8 because `typeinfo($b).base_ty` resolves to "int" which is not equal to "str" so the else branch is taken assigning 1 to $a which is a uint8

## Case 8

let $a;
let $b;

if comptime typeinfo($b).base_ty == "str" {
    $a = "hello";
} else {
    $a = 1;
    $b = 1;
}

**Result**: Error
**Reason**: Because we never can resolve the type of $b because the assignment to $b is nested in a comptime branch that depends on knowing the type of $b

## Case 9

let $b;

if comptime typeinfo($b).full_type == "uint32" {
    $b = (uint64)1;
}

$b = (uint32)2;


**Result**: Error
**Reason**: Because in order to resolve the comptime expression and visit `$b = (uint64)1` we need the final type of `$b` but the type is changed from a uint32 to a uint64 in this nested assignment.

## Case 10

let $a;
$b = $a;
$c = (typeof($b))"reallylongstr";

$a = "hi";

**Result**: Error
**Reason**: Because $a resolves to a string[2] type making $b also have a type of string[2] therefore the cast expression resolve to `(string[2])"reallylongstr"` which is invalid because you can't cast a long string to a shorter string


## Case 11

let $b;

if comptime typeinfo($b).full_type == "uint32" {
    $b = (uint64)1;
}

**Result**: Error
**Reason**: We can't resolve the type of $b without evaluating the comptime branch which we can't do unless we know the type of $b


## Case 12

let $b;
let $a = (uint32)1;

if comptime typeinfo($a).full_type == "uint32" {
    $b = (uint64)1;
}

$z = $b;

**Result**: Success
**Reason**: We can resolve the comptime expression which then visits the branch which resolves the type of $b and then $z;

## Case 13

let $b;
let $a = (uint32)1;

if comptime true {
    $b = (uint64)1;
}

$z = $b;

**Result**: Success
**Reason**: We're able to resolve the comptime in the first pass so we can set the type of $b and $z.

## Case 14

$b = 2;
$z = (uint32)1;

if comptime typeinfo($z).full_type == "uint32" {
    $b = (uint64)1;
}

$z = $b;

**Result**: Error
**Reason**: $z becomes locked/stable to uint32 so when $b is updated to a uint64 and then tries to update the type of $z it's invalid


$a = 1;
$a = (uint32)2;
$a = "str";

[1].push($a); [$a].push(1);
[(uint32)2].push($a);
