#include "ast/passes/macro_expansion.h"
#include "ast/passes/import_scripts.h"
#include "ast/passes/printer.h"
#include "ast/passes/resolve_imports.h"
#include "mocks.h"
#include "parser.h"
#include "gtest/gtest.h"

namespace bpftrace::test::macro_expansion {

using ::testing::HasSubstr;

void test(const std::string& input,
          const std::string& expected_output = "",
          const std::string& error = "",
          const std::string& warn = "")
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;

  // The input provided here is embedded into an expression.
  ast::ASTContext ast("stdin", input);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  // N.B. No C macro or tracepoint expansion.
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(CreateParsePass())
                .add(ast::CreateResolveRootImportsPass({}))
                .add(ast::CreateImportInternalScriptsPass())
                .add(ast::CreateMacroExpansionPass())
                .run();

  std::ostringstream out;
  ast.diagnostics().emit(out);

  // Trim the prefix off the error and warning, since they may come with
  // a newline embedded which will cause the test fail.
  std::string trimmed_error = error;
  std::string trimmed_warn = warn;
  if (!error.empty()) {
    trimmed_error = error.substr(error.find_first_not_of("\n"));
  }
  if (!warn.empty()) {
    trimmed_warn = warn.substr(warn.find_first_not_of("\n"));
  }

  if (trimmed_error.empty()) {
    ASSERT_TRUE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    if (!expected_output.empty()) {
      std::stringstream printed;
      ast::Printer printer(ast, printed);
      printer.visit(ast.root);
      EXPECT_THAT(printed.str(), HasSubstr(expected_output))
          << msg.str() << printed.str();
    }
    if (!trimmed_warn.empty()) {
      EXPECT_THAT(out.str(), HasSubstr(trimmed_warn)) << msg.str() << out.str();
    }
  } else {
    ASSERT_FALSE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    EXPECT_THAT(out.str(), HasSubstr(trimmed_error)) << msg.str() << out.str();
  }
}

void test_error(const std::string& input, const std::string& error)
{
  test(input, "", error);
}

void test_warning(const std::string& input, const std::string& warn)
{
  test(input, "", "", warn);
}

TEST(macro_expansion, basic_checks)
{
  test("macro print_me() { print(\"me\"); } begin { print_me(); }");
  test("macro print_me() { print(\"me\"); } begin { print_me; }");
  test("macro add1(x) { x + 1 } macro add2(x) { x + add1(x) } macro "
       "add3(x) { x + add2(x) } begin { print(add3(1)); }");
  test("macro add1($x) { $x += 1; } begin { $y = 1; add1($y); }");
  test("macro add3($x) { $x += 1; $x += 1; $x += 1; } begin { $y = 1; "
       "add3($y); }");
  test("macro add1($x) { $x += 1; $x } begin { $y = 1; add1($y); }");
  test("macro add2($x) { $x += 2; $x } macro add1($x) { $x += 1; add2($x); } "
       "begin { $y = 1; add1($y); }");
  test("macro add1(x) { x + 1 } begin { $y = 1; add1($y); }");
  test("macro add1(x) { x + 1 } begin { @y = 1; add1(@y); }");

  // Note that these will ultimately result in semantic errors, because they
  // attempt to assign something with no value to a scratch variable. But they
  // are not strictly an error during macro expansion, as the type mismatch can
  // obviously go beyond none (to any kind of type mismatch).
  test("macro add1($x) { $x += 1; } begin { $y = 1; $z = add1($y); }");
  test("macro add2($y) { $y += 1; } macro add1($x) { $x += add2($x); } begin { "
       "$y = 1; add1($y); }");

  test_error("macro set($x) { $x += 1; $x } begin { $a = 1; set($a, 1); }",
             "The closest definition of set() has a different number of "
             "arguments. Expected: "
             "1 but got 2");
  test_error("macro set($x, $x) { $x += 1; $x } begin { $a = 1; set($a, 1); }",
             "Variable for macro argument has already been used: $x");
  test_error("macro set(@x, @x) { @x } begin { @a = 1; set(@a, @a); }",
             "Map for macro argument has already been used: @x");
  test_error("macro set(x, x) { x } begin { set(1, 1); }",
             "Ident for macro argument has already been used: x");
  test_error("macro set($x) { $x += 1; $x } macro set($x) { $x } begin { $a = "
             "1; set($a, 1); }",
             "Redefinition of macro: set");
  test_error(
      "macro add1(x) { x + add3(x) } macro add2(x) { x + add1(x) } macro "
      "add3(x) {$x + add2(x) } begin { print(add3(1)); }",
      "Recursive macro call detected. Call chain: add3 > add2 > add1 > add3");
  test_error("macro add1($x) { $x += 1; $x } begin { $y = 1; $z = add1; }",
             "ERROR: The closest definition of add1() has a different number "
             "of arguments. Expected: 1 "
             "but got 0");
}

TEST(macro_expansion, variables)
{
  test("macro set($x) { $x += 1; $x } begin { $a = 1; set($a); }");
  test("macro set($x, y) { $x + y } begin { $a = 1; set($a, 1); }");
  test("macro set($x) { $b = $x + 1; $b } begin { $a = 1; set($a); }");
  test("macro set($x) { let $b = $x + 1; $b } begin { $a = 1; set($a); }");

  test_error("macro set($x) { $x += 1; $x } begin { @a = 1; set(@a); }",
             "Mismatched arg. set() expects a variable for arg $x "
             "but got a map.");

  test_error("macro add1($x) { $x += 1; $x } begin { add1(1 + 1); }",
             "Mismatched arg. add1() expects a variable for arg "
             "$x but got an expression.");

  test_error("macro set($x) { let $x; $x } begin { $y = 1; set($y); }",
             "Variable declaration shadows macro arg $x");
}

TEST(macro_expansion, maps)
{
  test("macro set(@x) { @x[1] } begin { @a[1] = 0; set(@a); }");
  test("macro set(@x) { @x[1] = 1; @x[1] } begin { @a[1] = 0; set(@a); }");

  test_error("macro set(@x) { @x[1] = 1; @x[1] } begin { $a = 0; set($a); }",
             "Mismatched arg. set() expects a map for arg @x but "
             "got a variable.");
  test_error("macro set(@x) { @x[1] = 1; @x[1] } begin { $a = 0; set(1); }",
             "Mismatched arg. set() expects a map for arg @x but "
             "got an expression.");
  test_error("macro set() { @x[1] = 1; 1 } begin { @x[0] = 0; set(); }",
             "Unhygienic access to map: @x. Maps must be passed into the macro "
             "as arguments");
  test_error("macro set() { @x[1] } begin { @x[0] = 0; set(); }",
             "Unhygienic access to map: @x. Maps must be passed into the macro "
             "as arguments");
}

TEST(macro_expansion, misc)
{
  // type_checker will catch this undefined call/macro
  test("macro add3(x) { x + add5(x) } begin { print(add3(1)); }");
}

TEST(macro_expansion, overloading)
{
  // Check for overloading against types.
  test("macro add($x) { fail(\"var\") } macro add(@x) { fail(\"map\") } macro "
       "add(x) { true } begin { print(add(1)); }");
  test("macro add($x) { true } macro add(@x) { fail(\"map\") } macro add(x) { "
       "fail(\"exp\") } begin { let $x = 1; print(add($x)); }");
  test("macro add($x) { true } macro add(@x) { fail(\"map\") } macro add(x) { "
       "fail(\"exp\") } begin { @x = 1; print(add(@x)); }");

  // Check for overloading against argument counts.
  test("macro add() { true } macro add(x) { fail(\"one\") } macro add(x, y) { "
       "fail(\"two\") } begin { print(add); }");
  test("macro add() { fail(\"none\") } macro add(x) { true } macro add(x, y) { "
       "fail(\"two\") } begin { print(add(1)); }");
  test("macro add() { fail(\"none\") } macro add(x) { fail(\"one\") } macro "
       "add(x, y) { true } begin { print(add(1, 2)); }");

  // Check for hybrid matching.
  test("macro add($x, y) { true } macro add(x, $y) { fail(\"two\") } begin { "
       "let $x = 1; print(add($x, 1)); }");
  test("macro add($x, y) { fail(\"one\") } macro add(x, $y) { true } begin { "
       "let $x = 1; print(add(1, $x)); }");

  // Check for a close match.
  test_error("macro add($x, y) { $x + 1 } begin { add(1, 1); }", R"(
stdin:1:37-46: ERROR: Call to add() has arguments that do not match any definition.
macro add($x, y) { $x + 1 } begin { add(1, 1); }
                                    ~~~~~~~~~
stdin:1:41-42: ERROR: Mismatched arg. add() expects a variable for arg $x but got an expression.
macro add($x, y) { $x + 1 } begin { add(1, 1); }
                                        ~
stdin:1:11-13: ERROR: This is the argument in the closest definition.
macro add($x, y) { $x + 1 } begin { add(1, 1); }
          ~~
)");
  test_error("macro add(@x, y) { @x + 1 } begin { add(1, 1); }", R"(
stdin:1:37-46: ERROR: Call to add() has arguments that do not match any definition.
macro add(@x, y) { @x + 1 } begin { add(1, 1); }
                                    ~~~~~~~~~
stdin:1:41-42: ERROR: Mismatched arg. add() expects a map for arg @x but got an expression.
macro add(@x, y) { @x + 1 } begin { add(1, 1); }
                                        ~
stdin:1:11-13: ERROR: This is the argument in the closest definition.
macro add(@x, y) { @x + 1 } begin { add(1, 1); }
          ~~
)");
  test_error("macro add(x) { x + 1 } macro add(x, y) { x + y } begin { add(1, "
             "1, 1); }",
             R"(
stdin:1:58-70: ERROR: Call to add() has arguments that do not match any definition.
macro add(x) { x + 1 } macro add(x, y) { x + y } begin { add(1, 1, 1); }
                                                         ~~~~~~~~~~~~
stdin:1:24-33: ERROR: The closest definition of add() has a different number of arguments. Expected: 2 but got 3
macro add(x) { x + 1 } macro add(x, y) { x + y } begin { add(1, 1, 1); }
                       ~~~~~~~~~
)");
  test_error("macro test(pid) { } begin { }",
             R"(
stdin:1:12-15: ERROR: syntax: builtin 'pid' can't be used as a macro argument
macro test(pid) { } begin { }
           ~~~
)");
}

TEST(macro_expansion, stdlib_shadowing)
{
  // User macro with same name and signature shadows the stdlib version.
  test("macro cpu() { 42 } begin { print(cpu()); }");

  // User macro with same name but different signature coexists with stdlib.
  // cpu(x) is user-defined, cpu() is from stdlib — both should work.
  test("macro cpu(x) { x } begin { print(cpu(1)); print(cpu()); }");

  // User macro shadows matching stdlib overload but non-matching stdlib
  // overloads remain available. comm() has multiple stdlib overloads.
  test("macro comm() { \"me\" } begin { print(comm()); }");

  // User-to-user redefinitions should still error.
  test_error("macro cpu() { 1 } macro cpu() { 2 } begin { print(cpu()); }",
             "Redefinition of macro: cpu");

  // User macros should not poison builtin/function calls inside stdlib macros.
  test("macro fail(x) { x } begin { print(strlen(\"hi\")); }");
}

TEST(macro_expansion, type_params)
{
  test("macro sz[T]() { sizeof(T) } begin { print(sz[uint64]()); }",
       "sizeof(uint64)");
  test("macro sz[T]() { sizeof(T) } begin { print(sz[struct task_struct]()); }",
       "sizeof(struct task_struct)");
  test("macro sz[T]() { sizeof(T*) } begin { print(sz[uint64]()); }",
       "sizeof(uint64*)");
  test("macro sz[T]() { sizeof(T*[5]) } begin { print(sz[uint64]()); }",
       "sizeof(uint64*[5])");
  test("macro sz[T]() { let $x: T = 1 } begin { print(sz[uint32]()); }",
       ": uint32 = 1");
  test("macro two[T, U]() { sizeof(T) + sizeof(U) } "
       "begin { print(two[uint64, uint32]()); }",
       "sizeof(uint64) + sizeof(uint32)");
  test("macro foo() { 1 } macro foo[T]() { sizeof(T) } "
       "begin { print(foo()); print(foo[uint64]()); }",
       "sizeof(uint64)");
  test("macro foo[T]() { (T)1 } macro foo[T, U]() { sizeof(U) } "
       "begin { print(foo[uint64]()); print(foo[uint32, int8]()); }",
       "sizeof(int8)");
  test("macro inner[b](t) { sizeof(b*) } macro outer[a](t) { inner[a*](t) } "
       "begin { print(outer[uint64*](1)); }",
       "sizeof(uint64***)");

  test_error("macro foo[T]($x) { $x } "
             "begin { $y = 1; foo[uint64, uint32]($y); }",
             "The closest definition of foo() has a different number of type "
             "parameters. Expected: 1 but got 2");
  test_error("macro foo[T]($x) { $x } begin { $y = 1; foo($y); }",
             "The closest definition of foo() has a different number of type "
             "parameters. Expected: 1 but got 0");
  test_error("macro foo[T]($x) { $x } macro foo[U]($x) { $x } "
             "begin { $y = 1; foo[uint64]($y); }",
             "Redefinition of macro: foo");
  test_error("macro sz[T]() { sizeof(struct T) } begin { print(sz[struct "
             "task_struct]()); }",
             "Type arg 'struct task_struct' is incompatible with how the type "
             "param is used in the macro body.");
  test_error("macro sz[T]() { sizeof(enum T) } begin { print(sz[struct "
             "task_struct]()); }",
             "Type arg 'struct task_struct' is incompatible with how the type "
             "param is used in the macro body.");
  test_error("begin { $y = 1; foo[uint64, uint32]($y); }",
             "Type args are not supported for function calls only macros");
}

} // namespace bpftrace::test::macro_expansion
