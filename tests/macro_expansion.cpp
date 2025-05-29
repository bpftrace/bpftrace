#include "ast/passes/macro_expansion.h"
#include "ast/passes/parser.h"
#include "ast/passes/printer.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::macro_expansion {

using ::testing::HasSubstr;

void test(const std::string& input,
          const std::string& error = "",
          const std::string& warn = "")
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;
  bpftrace.config_->unstable_macro = ConfigUnstable::enable;

  // The input provided here is embedded into an expression.
  ast::ASTContext ast("stdin", input);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  // N.B. No C macro or tracepoint expansion.
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(CreateParsePass())
                .add(ast::CreateMacroExpansionPass())
                .run();

  std::ostringstream out;
  ast::Printer printer(out);
  printer.visit(ast.root);
  ast.diagnostics().emit(out);

  if (error.empty()) {
    ASSERT_TRUE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    if (!warn.empty()) {
      EXPECT_THAT(out.str(), HasSubstr(warn)) << msg.str() << out.str();
    }
  } else {
    ASSERT_FALSE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    EXPECT_THAT(out.str(), HasSubstr(error)) << msg.str() << out.str();
  }
}

void test_error(const std::string& input, const std::string& error)
{
  test(input, error);
}

void test_warning(const std::string& input, const std::string& warn)
{
  test(input, "", warn);
}

TEST(macro_expansion, basic_checks)
{
  test("macro print_me() { print(\"me\"); } BEGIN { print_me(); }");
  test("macro add1($x) { $x + 1 } macro add2($x) { $x + add1($x) } macro "
       "add3($x) { $x + add2($x) } BEGIN { print(add3(1)); }");
  test("macro add1($x) { $x += 1; } BEGIN { $y = 1; add1($y); }");
  test("macro add3($x) { $x += 1; $x += 1; $x += 1; } BEGIN { $y = 1; "
       "add3($y); }");
  test("macro add1($x) { $x += 1; $x } BEGIN { $y = 1; add1($y); }");
  test("macro add2($x) { $x += 2; $x } macro add1($x) { $x += 1; add2($x); } "
       "BEGIN { $y = 1; add1($y); }");

  test_error("macro add1($x) { $x += 1; } BEGIN { $y = 1; $z = add1($y); }",
             "Macro 'add1' expanded to a block instead of a block expression. "
             "Try removing the semicolon from the end of the last statement in "
             "the macro body.");
  test_error("macro add2($y) { $y += 1; } macro add1($x) { $x += add2($x); } "
             "BEGIN { $y = 1; add1($y); }",
             "Macro 'add2' expanded to a block instead of a block expression. "
             "Try removing the semicolon from the end of the last statement in "
             "the macro body.");
  test_error("macro set($x) { $x += 1; $x } BEGIN { $a = 1; set($a, 1); }",
             "Call to macro has wrong number arguments. Expected: 1 but got 2");
  test_error("macro set($x, $x) { $x += 1; $x } BEGIN { $a = 1; set($a, 1); }",
             "Variable for macro argument has already been used: $x");
  test_error("macro set($x) { $x += 1; $x } macro set($x) { $x } BEGIN { $a = "
             "1; set($a, 1); }",
             "Redifinition of macro: set");
  test_error(
      "macro add1($x) { $x + add3($x) } macro add2($x) { $x + add1($x) } macro "
      "add3($x) { $x + add2($x) } BEGIN { print(add3(1)); }",
      "Recursive macro call detected. Call chain: add3 > add2 > add1 > add3");
}

TEST(macro_expansion, variables)
{
  test("macro set($x) { $x += 1; $x } BEGIN { $a = 1; set($a); }");
  test("macro set($x, $y) { $x + $y } BEGIN { $a = 1; set($a, 1); }");
  test("macro set($x) { $b = $x + 1; $b } BEGIN { $a = 1; set($a); }");
  test("macro set($x) { let $b = $x + 1; $b } BEGIN { $a = 1; set($a); }");

  test_error(
      "macro set($x) { $x += 1; $x } BEGIN { @a = 1; set(@a); }",
      "Mismatched arg to macro call. Macro expects a variable for arg $x "
      "but got a map.");

  test_error("macro add1($x) { $x += 1; $x } BEGIN { add1(1 + 1); }",
             "Macro 'add1' assigns to parameter '$x', meaning it expects a "
             "variable, not an expression.");
}

TEST(macro_expansion, maps)
{
  test("macro set(@x) { @x[1] } BEGIN { @a[1] = 0; set(@a); }");
  test("macro set(@x) { @x[1] = 1; @x[1] } BEGIN { @a[1] = 0; set(@a); }");

  test_error("macro set(@x) { @x[1] = 1; @x[1] } BEGIN { $a = 0; set($a); }",
             "Mismatched arg to macro call. Macro expects a map for arg @x but "
             "got a variable.");
  test_error("macro set(@x) { @x[1] = 1; @x[1] } BEGIN { $a = 0; set(1); }",
             "Mismatched arg to macro call. Macro expects a map for arg @x but "
             "got an expression.");
  test_error("macro set() { @x[1] = 1; 1 } BEGIN { @x[0] = 0; set(); }",
             "Unhygienic access to map: @x. Maps must be passed into the macro "
             "as arguments");
  test_error("macro set() { @x[1] } BEGIN { @x[0] = 0; set(); }",
             "Unhygienic access to map: @x. Maps must be passed into the macro "
             "as arguments");
}

TEST(macro_expansion, misc)
{
  // semantic_analyser will catch this undefined call/macro
  test("macro add3($x) { $x + add5($x) } BEGIN { print(add3(1)); }");
}

} // namespace bpftrace::test::macro_expansion
