# bpftrace Internals

This document is for bpftrace internals developers.

<center><a href="../images/bpftrace_internals_2018.png"><img src="../images/bpftrace_internals_2018.png" border=0 width=700></a></center>

# Codegen

This is the most difficult part of bpftrace. It involves writing code like this (from ast/codegen_llvm.cpp):

```C++
    AllocaInst *buf = b_.CreateAllocaBPF(call.type, "usym");
    b_.CreateMemSet(buf, b_.getInt8(0), call.type.size, 1);
    Value *pid = b_.CreateLShr(b_.CreateGetPidTgid(), 32);
    Value *addr_offset = b_.CreateGEP(buf, b_.getInt64(0));
    Value *pid_offset = b_.CreateGEP(buf, {b_.getInt64(0), b_.getInt64(8)});
    call.vargs->front()->accept(*this);
    b_.CreateStore(expr_, addr_offset);
    b_.CreateStore(pid, pid_offset);
    expr_ = buf;
```

These are llvm [Intermediate Representation](https://en.wikipedia.org/wiki/Intermediate_representation) \(IR\) functions that emit an llvm assembly-like language which can be compiled directly to BPF, thanks to llvm's BPF support. If you use bpftrace -d, you'll see this llvm assembly:

```shell
bpftrace -d -e 'kprobe:do_nanosleep { printf("%s is sleeping\n", comm); }'
```

Produces:

```ll
...
define i64 @"kprobe:do_nanosleep"(i8*) local_unnamed_addr section "s_kprobe:do_nanosleep" {
entry:
  %comm = alloca [64 x i8], align 1
  %printf_args = alloca %printf_t, align 8
  %1 = bitcast %printf_t* %printf_args to i8*
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
  store i64 0, %printf_t* %printf_args, align 8
  %2 = getelementptr inbounds [64 x i8], [64 x i8]* %comm, i64 0, i64 0
  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
  call void @llvm.memset.p0i8.i64(i8* nonnull %2, i8 0, i64 64, i32 1, i1 false)
  %get_comm = call i64 inttoptr (i64 16 to i64 (i8*, i64)*)([64 x i8]* nonnull %comm, i64 64)
  %3 = getelementptr inbounds %printf_t, %printf_t* %printf_args, i64 0, i32 1, i64 0
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull %3, i8* nonnull %2, i64 64, i32 1, i1 false)
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %get_cpu_id = call i64 inttoptr (i64 8 to i64 ()*)()
  %perf_event_output = call i64 inttoptr (i64 25 to i64 (i8*, i8*, i64, i8*, i64)*)(i8* %0, i64 %pseudo, i64 %get_cpu_id, %printf_t* nonnull %printf_args, i64 72)
  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
  ret i64 0
}
...
```

## References

Reference documentation for the codegen_llvm.cpp IR calls:

- [llvm::IRBuilderBase Class Reference](https://llvm.org/doxygen/classllvm_1_1IRBuilderBase.html)
- [llvm::IRBuilder Class Template Reference](https://llvm.org/doxygen/classllvm_1_1IRBuilder.html)

Reference documentation for the llvm assembly:

- [LLVM Language Reference Manual](https://llvm.org/docs/LangRef.html)

Reference documentation for eBPF kernel helpers:

- [Kernel Helpers](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#helpers)
- [`bpf.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h)

Reference for eBPF syscall and data structures (e.g. maps):

- [`bpf(2)` man page](http://man7.org/linux/man-pages/man2/bpf.2.html)

## Gotchas

If there's one gotcha I would like to mention, it's the use of CreateGEP() (Get Element Pointer). It's needed when dereferencing at an offset in a buffer, and it's tricky to use.

## Verifier

BPF programs are submitted to Linux's in-kernel BPF verifier. Read the large comment at the start of the source; it provides a good explanation.

Source code:

https://github.com/torvalds/linux/blob/master/kernel/bpf/verifier.c

Self-tests:

https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/test_verifier.c

If you see an error, it's often educational to look up the error message inside the source code or tests. The reasoning is easily understood if you work your way backwards from the message.

If you find a test which expects your error message: the name of the test may reveal a better explanation for what the error means. You may also find that nearby tests reveal the criteria for success.

Reading BPF instructions is difficult, but if you compare "successful tests" against their various "failure tests": you may see patterns and differences. For example, a successful test may perform a bitmask or conditional logic to provide guarantees about what range of inputs is possible.

Mostly the verifier is trying to check "are you allowed to read/write this memory?". Usually there's a notion of "if your read begins inside the BPF stack, it needs to end inside the BPF stack as well", or suchlike.

For example: if you've stack-allocated a buffer of 64 bytes for writing strings into, and you intend to parameterise "how many bytes might I copy into this buffer": you will need to add some minimum and maximum conditions, to constrain whichever variable is used to determine the length of data copied.

BPF load and store instructions may be picky about what locations they're happy to read/write to. For example, probe_read_str() will only permit writes into a PTR_TO_STACK.

I've documented some common errors you may encounter when the verifier bounds-checks your program. Most of this was learned during https://github.com/iovisor/bpftrace/pull/241.

### min value is negative

```
R2 min value is negative, either use unsigned or 'var &= const'
```

Probably you are using a variable to determine "how far should I jump, relative to this pointer". You need to prove that your variable is always positive.

You could try casting to unsigned integer (my notes say that this did not result in any improvement, but it feels like it's worth another try):

```c++
// where expr_ is the problematic Value*
b_.CreateIntCast(
  expr_,
  b_.getInt64Ty(),
  false)
```

Or you could bitmask it such that no negative number is possible:

```c++
b_.CreateAnd(
  expr_,
  0x7fffffffffffffff) // 64-bit number with all bits except the first set to 1
```

Or you could try [CreateMaxNum()](https://llvm.org/docs/LangRef.html#llvm-maxnum-intrinsic) (my notes say that this segfaulted, but it feels like it's worth another try):

```c++
b_.CreateMaxNum(
  b_.getInt64(0),
  expr_,
  "ensure_positive"),
```

Or you could try using if/else to provide bounds hints (my notes say that this did not result in any improvement, but it feels like it's worth another try):

```c++
// where expr_ is the problematic Value*

// allocate a variable in which to store your final result, after comparisons are completed
AllocaInst *mycoolvar = b_.CreateAllocaBPF(b_.getInt64Ty(), "mycoolvar");

Function *parent = b_.GetInsertBlock()->getParent();
BasicBlock *positive = BasicBlock::Create(module_->getContext(), "positive", parent);
BasicBlock *negative = BasicBlock::Create(module_->getContext(), "negative", parent);
BasicBlock *done = BasicBlock::Create(module_->getContext(), "done", parent);
b_.CreateCondBr(
  b_.CreateICmpUGE(expr_, b_.getInt64(0), "if_positive"),
  positive,
  negative);

// if expr_ is positive, store it into mycoolvar
b_.SetInsertPoint(positive);
b_.CreateStore(expr_, mycoolvar);
b_.CreateBr(done);

// if expr_ is negative, store a 0 into mycoolvar (or whatever you want to do)
b_.SetInsertPoint(negative);
b_.CreateStore(b_.getInt64(0), mycoolvar);
b_.CreateBr(done);

b_.SetInsertPoint(done);
```

**My favoured approach is to select the result of an unsigned comparison:**

```c++
// largest number we'll allow. choosing arbitrary maximum
// since this example just wants to take advantage of the comparison's unsignedness
Value *max = b_.getInt64(1024);
// integer comparison: unsigned less-than-or-equal-to
CmpInst::Predicate P = CmpInst::ICMP_ULE;
// check whether expr_ is less-than-or-equal-to maximum
Value *Cmp = b_.CreateICmp(P, expr_, max, "str.min.cmp");
// Select will contain expr_ if expr_ is sufficiently low, otherwise it will contain max
Value *Select = b_.CreateSelect(Cmp, expr_, max, "str.min.select");
```

### unbounded memory access

```
R2 unbounded memory access, use 'var &= const' or 'if (var < const)'
```

You need to prove that you don't jump too far from your pointer. This re-uses techniques from "min value is negative"; you just need to tighten the range even further.

How far is too far? You need to [stay below `BPF_MAX_VAR_SIZ`](https://github.com/iovisor/bpftrace/pull/241#issuecomment-440274294), `1ULL << 29`.

So, you could bitmask your variable with `(1ULL << 29) - 1` = `0x1FFFFFFF`:

```c++
b_.CreateAnd(
  expr_,
  0x1fffffff) // (1ULL << 29) - 1
```

### invalid stack

```
invalid stack type R1 off=-72 access_size=536870911
```

This means that it's possible for us to jump so far that we'd overflow our stack. Keep re-using techniques from above, and tighten the range even further.

But more likely, you have a fundamental problem: perhaps you're trying to allocate a buffer of arbitrary size (determined at runtime), and do arbitrarily-sized writes into it (determined at runtime).

If indeed that's what you're trying to do: you'll have to change your architecture. The BPF stack (512 bytes) can only accommodate tiny allocations and jumps. You need to move towards storing your data in BPF maps.

Consider this ongoing discussion on how to rearchitect to store stack data in a map: https://github.com/iovisor/bpftrace/issues/305

### expected=PTR_TO_STACK; actual=PTR_TO_MAP_VALUE

```
R1 type=map_value_or_null expected=fp
```

This was encountered when I invoked `probe_read_str(void *dst, int size, const void *unsafe_ptr)` with a `*dst` that pointed to a BPF map value.

It refused; `probe_read_str(3)` will only write into stack-allocated memory.

The workaround is probably to write data onto the BPF stack _first_, then transfer from BPF stack into BPF map. If you've a lot of data, then this will take a few trips.

### stack limit exceeded

```
Looks like the BPF stack limit of 512 bytes is exceeded. Please move large on stack variables into BPF per-cpu array map.
```

You're trying to stack-allocate a really big variable. Sadly you'll need to rearchitect; see above.

### call to 'memset' is not supported.

A call to built-in function 'memset' is not supported.

This occurs when you attempt to zero out a large amount of memory, e.g. 1024 bytes.

Probably the real problem is that you stack-allocated a really big variable. It just happens that (at large numbers): you'll get the error about memset _before_ you get the error about the allocation.

## Examples.

### 1. Codegen: Sum

We can explore and get the hang of llvm assembly by writing some simple C programs and compiling them using clang. Since llvm assembly maps to llvm IR, I've sometimes prototyped my codegen_llvm.cpp IR this way: writing a C program to produce the llvm assembly, and then manually mapping it back to llvm IR.

test.c:

```C
int test(int arg_a, int arg_b)
{
	int sum;
	sum = arg_a + arg_b;
	return sum;
}
```

Compiling into llvm assembly:

```
# /usr/bin/clang-6.0 -cc1 test.c -emit-llvm
```

Produces test.ll:

```ll
; ModuleID = 'test.c'
source_filename = "test.c"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: noinline nounwind optnone
define i32 @test(i32 %arg_a, i32 %arg_b) #0 {
  %arg_a.addr = alloca i32, align 4
  %arg_b.addr = alloca i32, align 4
  %sum = alloca i32, align 4
  store i32 %arg_a, i32* %arg_a.addr, align 4
  store i32 %arg_b, i32* %arg_b.addr, align 4
  %1 = load i32, i32* %arg_a.addr, align 4
  %2 = load i32, i32* %arg_b.addr, align 4
  %add = add nsw i32 %1, %2
  store i32 %add, i32* %sum, align 4
  %3 = load i32, i32* %sum, align 4
  ret i32 %3
}

attributes #0 = { noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "less-precise-fpmad"="false" "no-frame-pointer-elim"="false" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "target-features"="+mmx,+sse,+sse2,+x87" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.module.flags = !{!0}
!llvm.ident = !{!1}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{!"clang version 6.0.1-svn334776-1~exp1~20180726133222.87 (branches/release_60)"}
```

You can imagine now mapping this back, line by line, to IR. Eg:

```ll
  %arg_a.addr = alloca i32, align 4
  %arg_b.addr = alloca i32, align 4
  %sum = alloca i32, align 4
```

Becomes:

```C++
  AllocaInst *arg_a_alloc = b_.CreateAllocaBPF(SizedType(Type::integer, 4), "arg_a");
  AllocaInst *arg_a_alloc = b_.CreateAllocaBPF(SizedType(Type::integer, 4), "arg_a");
  AllocaInst *sum_alloc = b_.CreateAllocaBPF(SizedType(Type::integer, 4), "sum");
```

And then:

```ll
  store i32 %arg_a, i32* %arg_a.addr, align 4
  store i32 %arg_b, i32* %arg_b.addr, align 4
```

Becomes:

```C++
  Value *arg_a = test->arg_begin()+0;	// haven't explained this bit yet
  Value *arg_b = test->arg_begin()+1;	//   "   "
  b_.CreateStore(arg_a, arg_a_alloc);
  b_.CreateStore(arg_b, arg_b_alloc);
```

And then:

```ll
  %1 = load i32, i32* %arg_a.addr, align 4
  %2 = load i32, i32* %arg_b.addr, align 4
  %add = add nsw i32 %1, %2
  store i32 %add, i32* %sum, align 4
```

Becomes:

```
  Value *arg_a_load = b_.CreateLoad(arg_a_alloc);
  Value *arg_b_load = b_.CreateLoad(arg_b_alloc);
  Value *add = b_.CreateAdd(arg_a_load, arg_b_load);
  b_.CreateStore(add, sum_alloc);
```

Although I'd probably have written that on one line as:

```
   b_.CreateStore(b_.CreateAdd(b_.CreateLoad(arg_a_alloc, arg_b_alloc)), sum_alloc);
```

Finally:

```ll
  %3 = load i32, i32* %sum, align 4
  ret i32 %3
```

Becomes (I'll just do this on one line as well):

```
  b_.CreateRet(b_.CreateLoad(sum_alloc));
```

That's just my mental conversion. I haven't tested this and it may have a bug. But this should be enough to illustrate the idea.

### 2. Codegen: curtask

If you need to add support to a BPF kernel function that bpftrace does not yet call, this is a simple example. It adds a `curtask` builtin that calls BPF_FUNC_get_current_task. See [bcc Kernel Versions](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md) for documentation on these BPF functions. The commit is:

https://github.com/iovisor/bpftrace/commit/895ea46f2c800e2f283339d0c96b3c8209590498

The diff is as simple as such an addition gets, and shows the different files and locations that need to be updated:

```diff
diff --git a/README.md b/README.md
index 6d72e2a..9cf4d8b 100644
--- a/README.md
+++ b/README.md
@@ -218,6 +218,7 @@ Variables:
 - `arg0`, `arg1`, ... etc. - Arguments to the function being traced
 - `retval` - Return value from function being traced
 - `func` - Name of the function currently being traced
+- `curtask` - Current task_struct as a u64.
 
 Functions:
 - `hist(int n)` - Produce a log2 histogram of values of `n`
diff --git a/src/ast/codegen_llvm.cpp b/src/ast/codegen_llvm.cpp
index 27fa477..d3dd1ff 100644
--- a/src/ast/codegen_llvm.cpp
+++ b/src/ast/codegen_llvm.cpp
@@ -70,6 +70,10 @@ void CodegenLLVM::visit(Builtin &builtin)
   {
     expr_ = b_.CreateGetCpuId();
   }
+  else if (builtin.ident == "curtask")
+  {
+    expr_ = b_.CreateGetCurrentTask();
+  }
   else if (builtin.ident == "comm")
   {
     AllocaInst *buf = b_.CreateAllocaBPF(builtin.type, "comm");
diff --git a/src/ast/irbuilderbpf.cpp b/src/ast/irbuilderbpf.cpp
index ccae94c..3ccf1e6 100644
--- a/src/ast/irbuilderbpf.cpp
+++ b/src/ast/irbuilderbpf.cpp
@@ -307,6 +307,19 @@ CallInst *IRBuilderBPF::CreateGetCpuId()
   return CreateCall(getcpuid_func, {}, "get_cpu_id");
 }
 
+CallInst *IRBuilderBPF::CreateGetCurrentTask()
+{
+  // u64 bpf_get_current_task(void)
+  // Return: current task_struct
+  FunctionType *getcurtask_func_type = FunctionType::get(getInt64Ty(), false);
+  PointerType *getcurtask_func_ptr_type = PointerType::get(getcurtask_func_type, 0);
+  Constant *getcurtask_func = ConstantExpr::getCast(
+      Instruction::IntToPtr,
+      getInt64(BPF_FUNC_get_current_task),
+      getcurtask_func_ptr_type);
+  return CreateCall(getcurtask_func, {}, "get_cur_task");
+}
+
 CallInst *IRBuilderBPF::CreateGetStackId(Value *ctx, bool ustack, size_t limit)
 {
   Value *map_ptr = CreateBpfPseudoCall(bpftrace_.stackid_maps_[limit]->mapfd_);
diff --git a/src/ast/irbuilderbpf.h b/src/ast/irbuilderbpf.h
index 0321e9a..ce2e3b6 100644
--- a/src/ast/irbuilderbpf.h
+++ b/src/ast/irbuilderbpf.h
@@ -36,6 +36,7 @@ public:
   CallInst   *CreateGetPidTgid();
   CallInst   *CreateGetUidGid();
   CallInst   *CreateGetCpuId();
+  CallInst   *CreateGetCurrentTask();
   CallInst   *CreateGetStackId(Value *ctx, bool ustack);
   CallInst   *CreateGetJoinMap(Value *ctx);
   void        CreateGetCurrentComm(AllocaInst *buf, size_t size);
diff --git a/src/ast/semantic_analyser.cpp b/src/ast/semantic_analyser.cpp
index 8eb5744..64c9411 100644
--- a/src/ast/semantic_analyser.cpp
+++ b/src/ast/semantic_analyser.cpp
@@ -32,6 +32,7 @@ void SemanticAnalyser::visit(Builtin &builtin)
       builtin.ident == "uid" ||
       builtin.ident == "gid" ||
       builtin.ident == "cpu" ||
+      builtin.ident == "curtask" ||
       builtin.ident == "retval") {
     builtin.type = SizedType(Type::integer, 8);
   }
diff --git a/src/lexer.l b/src/lexer.l
index c5996b6..3bec616 100644
--- a/src/lexer.l
+++ b/src/lexer.l
@@ -38,7 +38,7 @@ header <(\\.|[_\-\./a-zA-Z0-9])*>
 {vspace}+               { loc.lines(yyleng); loc.step(); }
 "//".*$  // Comments
 
-pid|tid|uid|gid|nsecs|cpu|comm|stack|ustack|arg[0-9]|retval|func|name {
+pid|tid|uid|gid|nsecs|cpu|comm|stack|ustack|arg[0-9]|retval|func|name|curtask {
                           return Parser::make_BUILTIN(yytext, loc); }
 {ident}                 { return Parser::make_IDENT(yytext, loc); }
 {path}                  { return Parser::make_PATH(yytext, loc); }
diff --git a/tests/codegen.cpp b/tests/codegen.cpp
index 38918ca..c00d25f 100644
--- a/tests/codegen.cpp
+++ b/tests/codegen.cpp
@@ -489,6 +489,42 @@ attributes #1 = { argmemonly nounwind }
 )EXPECTED");
 }
 
+TEST(codegen, builtin_curtask)
+{
+  test("kprobe:f { @x = curtask }",
+
+R"EXPECTED(; Function Attrs: nounwind
+declare i64 @llvm.bpf.pseudo(i64, i64) #0
+
+; Function Attrs: argmemonly nounwind
+declare void @llvm.lifetime.start.p0i8(i64, i8* nocapture) #1
+
+define i64 @"kprobe:f"(i8* nocapture readnone) local_unnamed_addr section "s_kprobe:f" {
+entry:
+  %"@x_val" = alloca i64, align 8
+  %"@x_key" = alloca i64, align 8
+  %get_cur_task = tail call i64 inttoptr (i64 35 to i64 ()*)()
+  %1 = bitcast i64* %"@x_key" to i8*
+  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %1)
+  store i64 0, i64* %"@x_key", align 8
+  %2 = bitcast i64* %"@x_val" to i8*
+  call void @llvm.lifetime.start.p0i8(i64 -1, i8* nonnull %2)
+  store i64 %get_cur_task, i64* %"@x_val", align 8
+  %pseudo = tail call i64 @llvm.bpf.pseudo(i64 1, i64 1)
+  %update_elem = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i64 %pseudo, i64* nonnull %"@x_key", i64* nonnull %"@x_val", i64 0)
+  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %1)
+  call void @llvm.lifetime.end.p0i8(i64 -1, i8* nonnull %2)
+  ret i64 0
+}
+
+; Function Attrs: argmemonly nounwind
+declare void @llvm.lifetime.end.p0i8(i64, i8* nocapture) #1
+
+attributes #0 = { nounwind }
+attributes #1 = { argmemonly nounwind }
+)EXPECTED");
+}
+
 TEST(codegen, builtin_comm)
 {
   test("kprobe:f { @x = comm }",
diff --git a/tests/parser.cpp b/tests/parser.cpp
index cff201b..49b83be 100644
--- a/tests/parser.cpp
+++ b/tests/parser.cpp
@@ -29,6 +29,7 @@ TEST(Parser, builtin_variables)
   test("kprobe:f { gid }", "Program\n kprobe:f\n  builtin: gid\n");
   test("kprobe:f { nsecs }", "Program\n kprobe:f\n  builtin: nsecs\n");
   test("kprobe:f { cpu }", "Program\n kprobe:f\n  builtin: cpu\n");
+  test("kprobe:f { curtask }", "Program\n kprobe:f\n  builtin: curtask\n");
   test("kprobe:f { comm }", "Program\n kprobe:f\n  builtin: comm\n");
   test("kprobe:f { stack }", "Program\n kprobe:f\n  builtin: stack\n");
   test("kprobe:f { ustack }", "Program\n kprobe:f\n  builtin: ustack\n");
diff --git a/tests/semantic_analyser.cpp b/tests/semantic_analyser.cpp
index d6e26b8..d9b24e2 100644
--- a/tests/semantic_analyser.cpp
+++ b/tests/semantic_analyser.cpp
@@ -67,6 +67,7 @@ TEST(semantic_analyser, builtin_variables)
   test("kprobe:f { gid }", 0);
   test("kprobe:f { nsecs }", 0);
   test("kprobe:f { cpu }", 0);
+  test("kprobe:f { curtask }", 0);
   test("kprobe:f { comm }", 0);
   test("kprobe:f { stack }", 0);
   test("kprobe:f { ustack }", 0);
```

### 3. Codegen: arguments & return value

See the implementation of `lhist()` for an example of pulling in arguments. Commit:

https://github.com/iovisor/bpftrace/commit/6bdd1198e04392aa468b12357a051816f2cc50e4

You'll also notice that the builtins finish by setting `expr_` to the final result. This is taking the node in the AST and replacing it with the computed expression. Calls don't necessarily do this: for example, `reg()` sets `expr_` since it returns a value, but `printf()` sets `expr_` to `nullptr`, since it does not return a value.

### 4. Codegen: sum(), min(), max(), avg(), stats()

These are examples of adding new map functions, and the required components. Since the functions themselves are simple, they are good examples of codegen. They were all added in a single commit:

https://github.com/iovisor/bpftrace/commit/0746ff9c048ed503c606b736ad3a78e141c22890

This also shows the bpftrace components that were added to support these: `BPFtrace::print_map_stats()`, `BPFtrace::max_value()`, `BPFtrace::min_value()`.

# Probes

Probes are reasonably straightforward. We use libbpf/libbcc, both from [bcc](https://github.com/iovisor/bcc), to create the probes via functions such as `bpf_attach_kprobe()`, `bpf_attach_uprobe()`, and `bpf_attach_tracepoint()`. We also use USDT helpers such as `bcc_usdt_enable_probe()`

## 1. Probes: Interval

The addition of the `interval` probe type is a simple example of adding a probe, and the components required:

https://github.com/iovisor/bpftrace/commit/c1e7b05be917ad6fa23a210d047bf9387745bf32

diff:

```diff
diff --git a/README.md b/README.md
index b73a6d1..4654f65 100644
--- a/README.md
+++ b/README.md
@@ -157,8 +157,8 @@ Attach script to a statically defined tracepoint in the kernel:
 
 Tracepoints are guaranteed to be stable between kernel versions, unlike kprobes.
 
-### timers
-Run the script at specified time intervals:
+### profile
+Run the script on all CPUs at specified time intervals:
 
 `profile:hz:99 { ... }`
 
@@ -168,6 +168,13 @@ Run the script at specified time intervals:
 
 `profile:us:1500 { ... }`
 
+### interval
+Run the script once per interval, for printing interval output:
+
+`interval:s:1 { ... }`
+
+`interval:ms:20 { ... }`
+
 ### Multiple attachment points
 A single probe can be attached to multiple events:
 
diff --git a/src/ast/semantic_analyser.cpp b/src/ast/semantic_analyser.cpp
index a08eaf7..2a79553 100644
--- a/src/ast/semantic_analyser.cpp
+++ b/src/ast/semantic_analyser.cpp
@@ -478,6 +478,15 @@ void SemanticAnalyser::visit(AttachPoint &ap)
     else if (ap.freq <= 0)
       err_ << "profile frequency should be a positive integer" << std::endl;
   }
+  else if (ap.provider == "interval") {
+    if (ap.target == "")
+      err_ << "interval probe must have unit of time" << std::endl;
+    else if (ap.target != "ms" &&
+             ap.target != "s")
+      err_ << ap.target << " is not an accepted unit of time" << std::endl;
+    if (ap.func != "")
+      err_ << "interval probe must have an integer frequency" << std::endl;
+  }
   else if (ap.provider == "BEGIN" || ap.provider == "END") {
     if (ap.target != "" || ap.func != "")
       err_ << "BEGIN/END probes should not have a target" << std::endl;
diff --git a/src/attached_probe.cpp b/src/attached_probe.cpp
index 598ecdc..991111b 100644
--- a/src/attached_probe.cpp
+++ b/src/attached_probe.cpp
@@ -36,6 +36,7 @@ bpf_prog_type progtype(ProbeType t)
     case ProbeType::uretprobe:  return BPF_PROG_TYPE_KPROBE; break;
     case ProbeType::tracepoint: return BPF_PROG_TYPE_TRACEPOINT; break;
     case ProbeType::profile:      return BPF_PROG_TYPE_PERF_EVENT; break;
+    case ProbeType::interval:      return BPF_PROG_TYPE_PERF_EVENT; break;
     default: abort();
   }
 }
@@ -61,6 +62,9 @@ AttachedProbe::AttachedProbe(Probe &probe, std::tuple<uint8_t *, uintptr_t> &fun
     case ProbeType::profile:
       attach_profile();
       break;
+    case ProbeType::interval:
+      attach_interval();
+      break;
     default:
       abort();
   }
@@ -93,6 +97,7 @@ AttachedProbe::~AttachedProbe()
       err = bpf_detach_tracepoint(probe_.path.c_str(), eventname().c_str());
       break;
     case ProbeType::profile:
+    case ProbeType::interval:
       break;
     default:
       abort();
@@ -279,4 +284,35 @@ void AttachedProbe::attach_profile()
   }
 }
 
+void AttachedProbe::attach_interval()
+{
+  int pid = -1;
+  int group_fd = -1;
+  int cpu = 0;
+
+  uint64_t period, freq;
+  if (probe_.path == "s")
+  {
+    period = probe_.freq * 1e9;
+    freq = 0;
+  }
+  else if (probe_.path == "ms")
+  {
+    period = probe_.freq * 1e6;
+    freq = 0;
+  }
+  else
+  {
+    abort();
+  }
+
+  int perf_event_fd = bpf_attach_perf_event(progfd_, PERF_TYPE_SOFTWARE,
+      PERF_COUNT_SW_CPU_CLOCK, period, freq, pid, cpu, group_fd);
+
+  if (perf_event_fd < 0)
+    throw std::runtime_error("Error attaching probe: " + probe_.name);
+
+  perf_event_fds_.push_back(perf_event_fd);
+}
+
 } // namespace bpftrace
diff --git a/src/attached_probe.h b/src/attached_probe.h
index 86b610c..97036e3 100644
--- a/src/attached_probe.h
+++ b/src/attached_probe.h
@@ -27,6 +27,7 @@ private:
   void attach_uprobe();
   void attach_tracepoint();
   void attach_profile();
+  void attach_interval();
 
   Probe &probe_;
   std::tuple<uint8_t *, uintptr_t> &func_;
diff --git a/src/types.cpp b/src/types.cpp
index 6813c72..2abaad6 100644
--- a/src/types.cpp
+++ b/src/types.cpp
@@ -57,6 +57,8 @@ ProbeType probetype(const std::string &type)
     return ProbeType::tracepoint;
   else if (type == "profile")
     return ProbeType::profile;
+  else if (type == "interval")
+    return ProbeType::interval;
   abort();
 }
 
diff --git a/src/types.h b/src/types.h
index 4c4524a..6c94eac 100644
--- a/src/types.h
+++ b/src/types.h
@@ -52,6 +52,7 @@ enum class ProbeType
   uretprobe,
   tracepoint,
   profile,
+  interval,
 };
 
 std::string typestr(Type t);
diff --git a/tests/bpftrace.cpp b/tests/bpftrace.cpp
index 3c3b036..50b6538 100644
--- a/tests/bpftrace.cpp
+++ b/tests/bpftrace.cpp
@@ -59,6 +59,14 @@ void check_profile(Probe &p, const std::string &unit, int freq, const std::strin
   EXPECT_EQ("profile:" + unit + ":" + std::to_string(freq), p.name);
 }
 
+void check_interval(Probe &p, const std::string &unit, int freq, const std::string &prog_name)
+{
+  EXPECT_EQ(ProbeType::interval, p.type);
+  EXPECT_EQ(freq, p.freq);
+  EXPECT_EQ(prog_name, p.prog_name);
+  EXPECT_EQ("interval:" + unit + ":" + std::to_string(freq), p.name);
+}
+
 void check_special_probe(Probe &p, const std::string &attach_point, const std::string &prog_name)
 {
   EXPECT_EQ(ProbeType::uprobe, p.type);
@@ -309,6 +317,22 @@ TEST(bpftrace, add_probes_profile)
   check_profile(bpftrace.get_probes().at(0), "ms", 997, probe_prog_name);
 }
 
+TEST(bpftrace, add_probes_interval)
+{
+  ast::AttachPoint a("interval", "s", 1);
+  ast::AttachPointList attach_points = { &a };
+  ast::Probe probe(&attach_points, nullptr, nullptr);
+
+  StrictMock<MockBPFtrace> bpftrace;
+
+  EXPECT_EQ(0, bpftrace.add_probe(probe));
+  EXPECT_EQ(1, bpftrace.get_probes().size());
+  EXPECT_EQ(0, bpftrace.get_special_probes().size());
+
+  std::string probe_prog_name = "interval:s:1";
+  check_interval(bpftrace.get_probes().at(0), "s", 1, probe_prog_name);
+}
+
 std::pair<std::vector<uint8_t>, std::vector<uint8_t>> key_value_pair_int(std::vector<uint64_t> key, int val)
 {
   std::pair<std::vector<uint8_t>, std::vector<uint8_t>> pair;
diff --git a/tests/parser.cpp b/tests/parser.cpp
index 786f3d0..d2db79b 100644
--- a/tests/parser.cpp
+++ b/tests/parser.cpp
@@ -260,6 +260,14 @@ TEST(Parser, profile_probe)
       "  int: 1\n");
 }
 
+TEST(Parser, interval_probe)
+{
+  test("interval:s:1 { 1 }",
+      "Program\n"
+      " interval:s:1\n"
+      "  int: 1\n");
+}
+
 TEST(Parser, multiple_attach_points_kprobe)
 {
   test("BEGIN,kprobe:sys_open,uprobe:/bin/sh:foo,tracepoint:syscalls:sys_enter_* { 1 }",
```
