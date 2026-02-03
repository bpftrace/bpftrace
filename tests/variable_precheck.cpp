#include "ast/passes/variable_precheck.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::variable_precheck {

using ::testing::HasSubstr;

std::string_view clean_prefix(std::string_view view)
{
  while (!view.empty() && view[0] == '\n')
    view.remove_prefix(1); // Remove initial '\n'
  return view;
}

void test(const std::string &input,
          const std::string &expected_error = "",
          const std::string &expected_warning = "")
{
  auto bpftrace = get_mock_bpftrace();
  ast::ASTContext ast("stdin", input);
  auto ok = ast::PassManager()
                .put(ast)
                .put(*bpftrace)
                .add(CreateParsePass())
                .add(ast::CreateVariablePreCheckPass())
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
  test("begin { let $a; if comptime (false) { $a = 1; } print($a); }");
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

} // namespace bpftrace::test::variable_precheck
