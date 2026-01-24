#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>

#include "ast/passes/ap_probe_expansion.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/builtins.h"
#include "ast/passes/fold_literals.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/pre_type_check.h"
#include "driver.h"
#include "mocks.h"

namespace bpftrace::test::pre_type_check {

using ::testing::HasSubstr;

std::string_view clean_prefix(std::string_view view)
{
  while (!view.empty() && view[0] == '\n')
    view.remove_prefix(1);
  return view;
}

void test(const std::string &input,
          const std::string &expected_error = "",
          const std::string &expected_warning = "",
          bool safe_mode = true)
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace &bpftrace = *mock_bpftrace;
  bpftrace.safe_mode_ = safe_mode;

  ast::ASTContext ast("stdin", input);
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .put(get_mock_function_info())
                .add(CreateParsePass())
                .add(ast::CreateMacroExpansionPass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateProbeAndApExpansionPass())
                .add(ast::CreateFoldLiteralsPass())
                .add(ast::CreateBuiltinsPass())
                .add(ast::CreateMapSugarPass())
                .add(ast::CreatePreTypeCheckPass())
                .run();
  ASSERT_TRUE(bool(ok));

  std::stringstream err_out;
  ast.diagnostics().emit(err_out, ast::Diagnostics::Severity::Error);
  std::stringstream warn_out;
  ast.diagnostics().emit(warn_out, ast::Diagnostics::Severity::Warning);

  if (expected_error.empty()) {
    EXPECT_EQ(err_out.str(), "") << "Unexpected error: " << err_out.str();
  } else {
    EXPECT_THAT(err_out.str(), HasSubstr(clean_prefix(expected_error)));
  }

  if (expected_warning.empty()) {
    EXPECT_EQ(warn_out.str(), "") << "Unexpected warning: " << warn_out.str();
  } else {
    EXPECT_THAT(warn_out.str(), HasSubstr(clean_prefix(expected_warning)));
  }
}

TEST(VariablePreCheck, shadowing)
{
  test("begin { let $x = 1 } end { let $x = 2 }");
  test("begin { let $x = 1; { let $y = 2; } }");
  test("begin { if (1) { let $x = 1 } else { let $x = 2 } }");
  test("begin { $x = 5; for ($i : 1..10) { print($i) } }");
  test("fn foo($x: int64): void { let $y = 1 }");
  test("fn foo($x: int64): void { let $y = 1 } fn bar($y: int64): void { let "
       "$x = 1 }");

  // Errors
  static const std::string error_str =
      "Variable $x was already declared. Variable shadowing is not allowed.";
  test("begin { let $x = 1; { let $x = 2 } }", error_str);
  test("begin { $x = 1; { let $x = 2 } }", error_str);
  test("begin { let $x = 1; let $x = 2 }", error_str);
  test("begin { let $x = 1; if (1) { let $x = 2 } }", error_str);
  test("begin { $i = 5; for ($i : 1..10) { print($i) } }",
       "Loop declaration shadows existing variable: $i");
  test("begin { let $i = 5; for ($i : 1..10) { print($i) } }",
       "Loop declaration shadows existing variable: $i");
  test("begin { for ($x : 1..10) { let $x = 1; } }", error_str);
  test("fn foo($x: int64): void { for ($x : 1..10) { print($x) } }",
       "Loop declaration shadows existing variable: $x");
  test("fn foo($x: int64): void { let $x = 1 }", error_str);
  // N.B. these are separate tests of error context so we don't have to include
  // the line/col in the error output
  test("begin { let $x = 1; { let $x = 2 } }",
       "This is the initial declaration.");
  test("begin { $x = 1; { let $x = 2 } }", "This is the initial assignment.");
  test("fn foo($x: int64): void { for ($x : 1..10) { print($x) } }",
       "This is the function parameter.");
  test("begin { for ($i : 1..10) { let $i = 1; } }",
       "This is the loop variable.");

  // Errors with source location
  test("begin { let $x = 1; { let $x = 2 } }",
       R"(
ERROR: Variable $x was already declared. Variable shadowing is not allowed.
begin { let $x = 1; { let $x = 2 } }
                      ~~~~~~
)");
  test("begin { $i = 5; for ($i : 1..10) { print($i) } }",
       R"(
ERROR: Loop declaration shadows existing variable: $i
begin { $i = 5; for ($i : 1..10) { print($i) } }
                     ~~
)");
  test("fn foo($x: int64): void { let $x = 1 }",
       R"(
ERROR: Variable $x was already declared. Variable shadowing is not allowed.
fn foo($x: int64): void { let $x = 1 }
                          ~~~~~~
)");

  // One test to show the full error context
  test("begin { let $x = 1; { let $x = 2 } }",
       R"(
stdin:1:23-29: ERROR: Variable $x was already declared. Variable shadowing is not allowed.
begin { let $x = 1; { let $x = 2 } }
                      ~~~~~~
stdin:1:9-15: ERROR: This is the initial declaration.
begin { let $x = 1; { let $x = 2 } }
        ~~~~~~
)");
}

TEST(VariablePreCheck, undefined)
{
  test("begin { $x = 1; print($x) }");
  test("begin { let $x = 1; print($x) }");
  test("begin { $x = 1; $y = $x + 1 }");
  test("fn foo($x: int64): void { print($x) }");
  test("begin { for ($i : 1..10) { print($i) } }");
  test("fn foo($z : typeof($x), $x : int64) : int64 { return 0; }");

  // Errors
  static const std::string error_str = "Undefined or undeclared variable: $x";
  test("begin { print($x) }", error_str);
  test("begin { $y = $x }", error_str);
  test("begin { $x = $x + 1 }", error_str);
  test("fn foo($x: int64): void { print($y) }",
       "Undefined or undeclared variable: $y");
  test("begin { $x += 0 }", error_str);
  test("begin { $x >>= 0 }", error_str);
  test(R"(
    begin {
      @map[0] = 1;
      for ($kv : @map) {
        $x = 2;
      }
      print($x);
    })",
       error_str);
  test("begin { for ($x : 0..5) { print($x); } print($x); }", error_str);
  test("begin { $a = 1; $b = &$x; }", error_str);
  test("begin { let $x = { let $y = $x; $y }; print($x) }", error_str);
  test("fn foo($z : int64, $y : typeof($x)) : int64 { return 0; }", error_str);
  test("fn foo($z : int64, $y : int64) : typeof($x) { return 0; }", error_str);

  // Errors with source location
  test("begin { $y = $x }", R"(
ERROR: Undefined or undeclared variable: $x
begin { $y = $x }
             ~~
)");
}

TEST(VariablePreCheck, used_before_assigned)
{
  test("begin { let $x = 1; print($x) }");
  test("begin { let $x; $x = 1; print($x) }");
  // We don't consider comptime for this warning
  test("begin { let $a; if comptime (typeinfo($a).base_ty == \"int\") { $a = "
       "1; } print($a); }");
  // No warning inside meta functions
  test("fn foo($z : typeof($x), $x : int64) : int64 { return 0; }");
  test("begin { let $x; let $y : typeof($x) = 1; $x = 1; }");
  test("begin { let $x; let $y : typeof({ print(1); $x }) = 1; $x = 1; }");
  test("begin { let $x; some_func(&$x); print($x); $x = 1; }");

  // Warnings
  test("begin { let $x; print($x); $x = 1; }",
       "",
       "Variable used before it was assigned: $x");
  test("begin { let $x; $y = $x; $x = 1; }",
       "",
       "Variable used before it was assigned: $x");

  // Warnings with source location
  test("begin { let $x; print($x); $x = 1; }",
       "",
       R"(
WARNING: Variable used before it was assigned: $x
begin { let $x; print($x); $x = 1; }
                      ~~
)");
}

TEST(VariablePreCheck, never_assigned)
{
  test("begin { let $x = 1; print($x) }");
  test("begin { let $x = 1; print($x) } end { print(1); }");
  test("begin { let $x; $x = 1; print($x) }");
  test("begin { let $x; some_func(&$x); print($x) }");
  test("k:f { $a = { let $x = 1; $x + 1 }; }");
  test("begin { print(1); } k:f { $a = { let $x = 1; $x + 1 }; }");
  test("fn foo($a : int64) : int8 { return 0; } begin { let $x; $x = 1; }");
  test("fn foo($a : int64) : int8 { return 0; } fn bar($a : int64) : int8 { "
       "let $x; $x = 2; return 0; }");

  // Warnings
  test("begin { let $x; }", "", "Variable $x was never assigned to.");
  test("fn foo(): void { let $x; }", "", "Variable $x was never assigned to.");

  // Warnings with source location
  test("begin { let $x; }", "", R"(
WARNING: Variable $x was never assigned to.
begin { let $x; }
        ~~~~~~
)");
}

TEST(CallPreCheck, unroll)
{
  test(R"(kprobe:f { $i = 0; unroll(5) { $i = $i + 1; } })");

  // Errors
  test(R"(kprobe:f { $i = 0; unroll(101) { $i = $i + 1; } })",
       "unroll maximum value is 100");
  test(R"(kprobe:f { $i = 0; unroll(0) { $i = $i + 1; } })",
       "unroll minimum value is 1");
}

TEST(CallPreCheck, safe_mode)
{
  test("kprobe:f { system(\"ls\") }", "", "", false);

  // Warnings
  test("kprobe:f { system(\"ls\") }",
       "system() is an unsafe function being used in safe mode");
}

TEST(CallPreCheck, probe_availability)
{
  // Errors
  test("kprobe:f { $ret = skboutput(\"one.pcap\", arg0, 1500, 0); }",
       "skboutput can not be used with \"kprobe\" probes");
  test("kprobe:f { $ret = socket_cookie(arg0); }",
       "socket_cookie can not be used with \"kprobe\" probes");
  test("kprobe:f { __builtin_uaddr(\"A\"); }",
       "__builtin_uaddr can not be used with \"kprobe\" probes");
  test("kprobe:f { $k = path(1) }",
       "The path function can only be used with "
       "'fentry', 'fexit', 'iter' probes");
  test("kretprobe:f { $k = path(1) }",
       "The path function can only be used with "
       "'fentry', 'fexit', 'iter' probes");
  test("tracepoint:category:event { $k = path(1) }",
       "The path function can only be used with "
       "'fentry', 'fexit', 'iter' probes");
  test("uprobe:/bin/sh:f { $k = path(1) }",
       "The path function can only be used with "
       "'fentry', 'fexit', 'iter' probes");
  test("begin { $k = path(1) }",
       "The path function can only be used with "
       "'fentry', 'fexit', 'iter' probes");
  test("end { $k = path(1) }",
       "The path function can only be used with "
       "'fentry', 'fexit', 'iter' probes");
}

TEST(CallPreCheck, nargs)
{
  // hist
  test("kprobe:f { @x = hist(1); }");

  // lhist
  test("kprobe:f { @ = lhist(5, 0, 10, 1); }");
  test("kprobe:f { @ = lhist(5, 0, 10); }",
       "lhist() requires 4 arguments (3 provided)");
  test("kprobe:f { @ = lhist(5, 0); }",
       "lhist() requires 4 arguments (2 provided)");
  test("kprobe:f { @ = lhist(5); }",
       "lhist() requires 4 arguments (1 provided)");
  test("kprobe:f { @ = lhist(); }",
       "lhist() requires 4 arguments (0 provided)");
  test("kprobe:f { @ = lhist(5, 0, 10, 1, 2); }",
       "lhist() requires 4 arguments (5 provided)");

  // tseries
  test("kprobe:f { @ = tseries(5, 10000000000, 1); }");
  test("kprobe:f { @ = tseries(5, 10000000000); }",
       "tseries() requires at least 3 arguments (2 provided)");
  test("kprobe:f { @ = tseries(5); }",
       "tseries() requires at least 3 arguments (1 provided)");
  test("kprobe:f { @ = tseries(); }",
       "tseries() requires at least 3 arguments (0 provided)");
  test("kprobe:f { @ = tseries(5, 10000000000, 1, 10, 10); }",
       "tseries() takes up to 4 arguments (5 provided)");

  // count
  test("kprobe:f { @x = count(); }");
  test("kprobe:f { @x = count(1); }",
       "count() requires no arguments (1 provided)");

  // sum
  test("kprobe:f { @x = sum(123); }");
  test("kprobe:f { @x = sum(123, 456); }",
       "sum() requires one argument (2 provided)");

  // min
  test("kprobe:f { @x = min(123); }");

  // max
  test("kprobe:f { @x = max(123); }");

  // avg
  test("kprobe:f { @x = avg(123); }");

  // stats
  test("kprobe:f { @x = stats(123); }");

  // exit
  test("kprobe:f { exit(); }");
  test("kprobe:f { exit(1); }");
  test("kprobe:f { exit(1, 2); }",
       "exit() takes up to one argument (2 provided)");

  // time
  test("kprobe:f { time(); }");
  test("kprobe:f { time(\"%M:%S\"); }");
  test("kprobe:f { time(\"%M:%S\", 1); }",
       "time() takes up to one argument (2 provided)");

  // strftime
  test("kprobe:f { strftime(\"%M:%S\", 1); }");
  test("kprobe:f { strftime(); }",
       "strftime() requires 2 arguments (0 provided)");
  test("kprobe:f { strftime(\"%M:%S\"); }",
       "strftime() requires 2 arguments (1 provided)");
  test("kprobe:f { strftime(\"%M:%S\", 1, 1); }",
       "strftime() requires 2 arguments (3 provided)");

  // str
  test("kprobe:f { str(arg0); }");

  // buf
  test("kprobe:f { buf(arg0, 1); }");

  // ksym
  test("kprobe:f { ksym(arg0); }");

  // usym
  test("kprobe:f { usym(arg0); }");

  // ntop
  test("kprobe:f { ntop(arg0); }");

  // pton
  test("kprobe:f { pton(\"127.0.0.1\"); }");

  // kaddr
  test("kprobe:f { kaddr(\"avenrun\"); }");

  // uaddr
  test("uprobe:/bin/sh:main { __builtin_uaddr(\"glob_asciirange\"); }");

  // cat
  test("kprobe:f { cat(\"/proc/loadavg\"); }");

  // stack
  test("kprobe:f { kstack(perf, 3) }");
  test("kprobe:f { kstack(perf, 3, 4) }",
       "kstack() takes up to 2 arguments (3 provided)");
  test("kprobe:f { ustack(perf, 3, 4) }",
       "ustack() takes up to 2 arguments (3 provided)");

  // macaddr
  test("kprobe:f { macaddr(arg0); }");

  // bswap
  test("kprobe:f { bswap(arg0); }");
  test("kprobe:f { bswap(0x12, 0x34); }",
       "bswap() requires one argument (2 provided)");

  // clear
  test("kprobe:f { @x = count(); clear(@x); }");
  test("kprobe:f { @x = count(); clear(@x, 1); }",
       "clear() requires one argument (2 provided)");

  // zero
  test("kprobe:f { @x = count(); zero(@x); }");
  test("kprobe:f { @x = count(); zero(@x, 1); }",
       "zero() requires one argument (2 provided)");

  // strncmp
  test(R"(i:s:1 { strncmp("foo", "bar", 1) })");
  test("i:s:1 { strncmp(1) }", "strncmp() requires 3 arguments (1 provided)");

  // skboutput
  test("kprobe:f { $ret = skboutput(); }",
       "skboutput() requires 4 arguments (0 provided)");
  test("kprobe:f { $ret = skboutput(\"one.pcap\"); }",
       "skboutput() requires 4 arguments (1 provided)");

  // pid and tid
  test("begin { $i = pid(curr_ns, curr_ns); }",
       "pid() takes up to one argument (2 provided)");
  test("begin { $i = tid(curr_ns, curr_ns); }",
       "tid() takes up to one argument (2 provided)");

  // clang-format off
  std::vector<std::pair<std::string, std::string>> requires_at_least_one_arg = {
    { "buf();",       "buf" },
    { "cat();",       "cat" },
    { "errorf();",    "errorf" },
    { "@x = hist();", "hist" },
    { "ntop();",      "ntop" },
    { "printf();",    "printf" },
    { "str();",       "str" },
    { "warnf();",     "warnf" },
    { "system();",    "system" },
  };
  // clang-format on
  for (const auto &[input, func] : requires_at_least_one_arg) {
    test("kprobe:f { " + input + "}",
         func + "() requires at least one argument (0 provided)");
  }

  // clang-format off
  std::vector<std::pair<std::string, std::string>> requires_one_arg = {
    { "@x = avg();",             "avg" },
    { "bswap();",                "bswap" },
    { "__builtin_uaddr();",      "__builtin_uaddr" },
    { "kaddr();",                "kaddr" },
    { "ksym();",                 "ksym" },
    { "macaddr();",              "macaddr" },
    { "@x = max();",             "max" },
    { "@x = min();",             "min" },
    { "pton();",                 "pton" },
    { "$ret = socket_cookie();", "socket_cookie" },
    { "@x = stats();",           "stats" },
    { "@x = sum();",             "sum" },
    { "usym();",                 "usym" },
  };
  // clang-format on
  for (const auto &[input, func] : requires_one_arg) {
    test("kprobe:f { " + input + "}",
         func + "() requires one argument (0 provided)");
  }
}

TEST(CallPreCheck, hist)
{
  test("kprobe:f { @x = hist(1); }");
  test("kprobe:f { @x = hist(1, 0); }");
  test("kprobe:f { @x = hist(1, 5); }");

  // Errors
  test("kprobe:f { @x = hist(1, 10); }", "hist: bits 10 must be 0..5");
}

TEST(CallPreCheck, lhist)
{
  test("kprobe:f { @ = lhist(5, 0, 10, 1); }");

  // Errors
  test("kprobe:f { @ = lhist(-10, -10, 10, 1); }",
       "lhist: invalid min value (must be non-negative literal)");
}

TEST(CallPreCheck, tseries)
{
  test("kprobe:f { @ = tseries(5, 10000000000, 1); }");
  test("kprobe:f { @ = tseries(-5, 10000000000, 1); }");
  test("kprobe:f { @ = tseries(-1, 10000000000, 5); }");
  test(R"(kprobe:f { @ = tseries(1, 10000000000, 5, "avg"); })");
  test(R"(kprobe:f { @ = tseries(1, 10000000000, 5, "max"); })");
  test(R"(kprobe:f { @ = tseries(1, 10000000000, 5, "min"); })");
  test(R"(kprobe:f { @ = tseries(1, 10000000000, 5, "sum"); })");

  // Errors
  test(R"(kprobe:f { @ = tseries(1, 10000000000, 5, "stats"); })",
       "tseries() expects one of the following aggregation functions: "
       "avg, max, min, sum (\"stats\" provided)");
  test("kprobe:f { @ = tseries(1, 0, 10); }",
       "tseries() interval_ns must be >= 1 (0 provided)");
  test("kprobe:f { @ = tseries(1, -1, 10); }",
       "tseries: invalid interval_ns value (must be non-negative literal)");
  test("kprobe:f { @ = tseries(1, 10000000000, 0); }",
       "tseries() num_intervals must be >= 1 (0 provided)");
  test("kprobe:f { @ = tseries(1, 10000000000, -1); }",
       "tseries: invalid num_intervals value (must be non-negative literal)");
  test("kprobe:f { @ = tseries(1, 10000000000, 1000001); }",
       "tseries() num_intervals must be < 1000000 (1000001 provided)");
}

TEST(CallPreCheck, debugf)
{
  // Warnings
  static const auto *warning =
      "The debugf() builtin is not recommended for production use.";
  test("kprobe:f { debugf(\"warning\") }", "", warning);
  test("kprobe:f { debugf(\"%d %d %d\", 1, 1, 1) }", "", warning);

  // Errors
  test("kprobe:f { debugf(\"%d %d %d %d\", 1, 1, 1, 1) }",
       "cannot use more than 3 conversion specifiers",
       warning);
}

TEST(CallPreCheck, path)
{
  test("fentry:f { path(\"adf\", 1); }");

  // Errors
  test(R"(fentry:f { path("adf", "Na"); })",
       "path: invalid size value, need non-negative literal");
  test("fentry:f { path(\"adf\", -1); }",
       "path: invalid size value, need non-negative literal");
}

TEST(CallPreCheck, strncmp)
{
  test(R"(i:s:1 { strncmp("foo", "bar", 1) })");

  // Errors
  test(R"(i:s:1 { strncmp("a","a","foo") })",
       "Builtin strncmp requires a non-negative literal");
}

TEST(CallPreCheck, signal)
{
  test(R"(begin { signal(current_pid) })");
  test(R"(begin { signal(current_tid) })");

  // Errors
  test(R"(begin { signal(bob) })",
       "Invalid signal target: bob (expects: current_pid or current_tid)");
}

TEST(CallPreCheck, pid_tid)
{
  test("begin { $i = tid(); }");
  test("begin { $i = pid(); }");
  test("begin { $i = tid(curr_ns); }");
  test("begin { $i = pid(curr_ns); }");
  test("begin { $i = tid(init); }");
  test("begin { $i = pid(init); }");

  // Errors
  test("begin { $i = tid(xxx); }",
       "Invalid PID namespace mode: xxx (expects: curr_ns or init)");
  test("begin { $i = tid(1); }",
       "tid() only supports curr_ns and init as the argument");
}

TEST(CallPreCheck, call_uaddr)
{
  test("u:/bin/sh:main { "
       "__builtin_uaddr(\"github.com/golang/"
       "glog.severityName\"); }");
  test("uprobe:/bin/sh:main { "
       "__builtin_uaddr(\"glob_asciirange\"); }");
  test("u:/bin/sh:main,u:/bin/sh:readline "
       "{ __builtin_uaddr(\"glob_asciirange\"); }");
  test("uprobe:/bin/sh:main { @x = "
       "__builtin_uaddr(\"glob_asciirange\"); }");

  // Errors
  test("uprobe:/bin/sh:main { __builtin_uaddr(123); }",
       "expects a string literal as the first argument");
  test("uprobe:/bin/sh:main { "
       "__builtin_uaddr(\"?\"); }",
       "expects a string that is a valid symbol");
  test("uprobe:/bin/sh:main { $str = "
       "\"glob_asciirange\"; __builtin_uaddr($str); }",
       "expects a string literal as the first argument");
  test("uprobe:/bin/sh:main { @str = "
       "\"glob_asciirange\"; __builtin_uaddr(@str); }",
       "expects a string literal as the first argument");
}

TEST(CallPreCheck, raw_map_arg_funcs)
{
  test("kprobe:f { @x[1,2] = count(); clear(@x); }");
  test("kprobe:f { @x[1,2] = count(); zero(@x); }");
  test("kprobe:f { @x[1,2] = count(); len(@x); }");

  // Errors
  test("kprobe:f { @x[1,2] = count(); clear(@x[3,4]); }",
       "expects a map argument");
  test("kprobe:f { @x[1,2] = count(); zero(@x[3,4]); }",
       "expects a map argument");
  test("kprobe:f { @x[1,2] = count(); len(@x[3,4]); }",
       "expects a map argument");
}

TEST(MapPreCheck, no_meta_map_assignments)
{
  test("begin { let $b : typeof({ @a = 1; 1 }) = 1; }",
       "Map assignments not allowed inside of typeof or typeinfo");
  test("begin { $b = typeinfo({ @a = 1; 1 }); }",
       "Map assignments not allowed inside of typeof or typeinfo");
  test("begin { print(sizeof({ @a = 1; 1 })); }",
       "Map assignments not allowed inside of sizeof");
  test("struct Foo { int x; }  begin { let $a : struct Foo* = 1; "
       "print(offsetof({ "
       "@a =1; *$a}, x)); }",
       "Map assignments not allowed inside of offsetof");
}

} // namespace bpftrace::test::pre_type_check
