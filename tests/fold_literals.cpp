#include "ast/passes/fold_literals.h"
#include "ast/passes/parser.h"
#include "ast/passes/printer.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::fold_literals {

using ::testing::HasSubstr;

void test(const std::string& input,
          const std::string& output,
          const std::string& error = "",
          const std::string& warn = "",
          bool negate = false)
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;

  // The input provided here is embedded into an expression.
  ast::ASTContext ast("stdin", "begin { " + input + " }");
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  // N.B. No macro or tracepoint expansion.
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(ast::AllParsePasses())
                .add(ast::CreateFoldLiteralsPass())
                .run();

  std::ostringstream out;
  ast::Printer printer(out);
  printer.visit(ast.root);
  ast.diagnostics().emit(out);

  if (!output.empty() || !warn.empty()) {
    ASSERT_TRUE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    if (!output.empty()) {
      if (negate) {
        EXPECT_THAT(out.str(), Not(HasSubstr(output)))
            << msg.str() << out.str();
      } else {
        EXPECT_THAT(out.str(), HasSubstr("begin\n  " + output))
            << msg.str() << out.str();
      }
    }
    if (!warn.empty()) {
      EXPECT_THAT(out.str(), HasSubstr(warn)) << msg.str() << out.str();
    }
  }
  if (!error.empty()) {
    ASSERT_FALSE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    EXPECT_THAT(out.str(), HasSubstr(error)) << msg.str() << out.str();
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

void test_not(const std::string& input, const std::string& output)
{
  test(input, output, "", "", true);
}

TEST(fold_literals, equals)
{
  test("0 == 0", "bool: true");
  test("0 == 1", "bool: false");
  test("-1 == 1", "bool: false");
  test("-1 == -1", "bool: true");
  test("true == true", "bool: true");
  test("false == false", "bool: true");
  test(R"("foo" == "bar")", "bool: false");
  test(R"("foo" == "foo")", "bool: true");
  test("\"foo\" == 1", "==");    // Left as is
  test("\"foo\" == true", "=="); // Left as is
  test("str($1) == \"\"", "bool: true");
  test("str($1) == \"foo\"", "bool: false");
  test("$1 == 0", "bool: true");
  test("$1 == 1", "bool: false");
  test(R"((1,-1,true,"foo") == (1,-1,true,"foo"))", "bool: true");
  test("(1,(2,(3,1+3))) == (1,(2,(4-1,4)))", "bool: true");
  test("(1,(2,(3,false))) == (1,(2,(4-1,4)))", "bool: false");
  test(R"((1,-1,true,"foo") == (1,-1,true,"bar"))", "bool: false");
  test(R"((-1,true,"foo",1) == (1,-1,true,"foo"))", "bool: false");
  test("(1,-1) == (1,-1,true)", "bool: false");
  test("($x,-1) == ($x,-1,true)", "bool: false");
  test("($x,-1) == ($x,-1)", "=="); // Left as is
}

TEST(fold_literals, not_equals)
{
  test("0 != 0", "bool: false");
  test("0 != 1", "bool: true");
  test("-1 != 1", "bool: true");
  test("-1 != -1", "bool: false");
  test("false != true", "bool: true");
  test("false != false", "bool: false");
  test(R"("foo" != "bar")", "bool: true");
  test(R"("foo" != "foo")", "bool: false");
  test(R"("foo" != 1)", "!=");     // Left as is
  test(R"("foo" != false)", "!="); // Left as is
  test(R"(str($1) != "")", "bool: false");
  test(R"(str($1) != "foo")", "bool: true");
  test("$1 != 0", "bool: false");
  test("$1 != 1", "bool: true");
  test(R"((1,-1,true,"foo") != (1,-1,true,"foo"))", "bool: false");
  test("(1,(2,(3,1+3))) != (1,(2,(4-1,4)))", "bool: false");
  test("(1,(2,(3,false))) != (1,(2,(4-1,4)))", "bool: true");
  test(R"((1,-1,true,"foo") != (1,-1,true,"bar"))", "bool: true");
  test(R"((-1,true,"foo",1) != (1,-1,true,"foo"))", "bool: true");
  test("(1,-1) != (1,-1,true)", "bool: true");
  test("($x,-1) != ($x,-1,true)", "bool: true");
  test("($x,-1) != ($x,-1)", "!="); // Left as is
}

TEST(fold_literals, comparison)
{
  test("0 < 1", "bool: true");
  test("1 < 0", "bool: false");
  test("0 < 0", "bool: false");
  test("-1 < 0", "bool: true");
  test("-1 < -2", "bool: false");
  test("true < false", "bool: false");
  test("0x7fffffffffffffff < 0x8000000000000000", "bool: true");
  test("0xffffffffffffffff < 0", "bool: false");
  test(R"("a" < "b")", "bool: true");
  test(R"("b" < "a")", "bool: false");
  test(R"("a" < "a")", "bool: false");
  test(R"("" < "a")", "bool: true");
  test(R"("abc" < "abd")", "bool: true");

  test("0 > 1", "bool: false");
  test("1 > 0", "bool: true");
  test("0 > 0", "bool: false");
  test("-1 > 0", "bool: false");
  test("-1 > -2", "bool: true");
  test("true > false", "bool: true");
  test("0x7fffffffffffffff > 0x8000000000000000", "bool: false");
  test("0xffffffffffffffff > 0", "bool: true");
  test(R"("a" > "b")", "bool: false");
  test(R"("b" > "a")", "bool: true");
  test(R"("a" > "a")", "bool: false");
  test(R"("" > "a")", "bool: false");
  test(R"("abc" > "abd")", "bool: false");

  test("0 <= 1", "bool: true");
  test("1 <= 0", "bool: false");
  test("0 <= 0", "bool: true");
  test("-1 <= 0", "bool: true");
  test("-1 <= -1", "bool: true");
  test("false <= true", "bool: true");
  test("0x7fffffffffffffff <= 0x8000000000000000", "bool: true");
  test("0xffffffffffffffff <= 0", "bool: false");
  test(R"("a" <= "b")", "bool: true");
  test(R"("b" <= "a")", "bool: false");
  test(R"("a" <= "a")", "bool: true");
  test(R"("" <= "a")", "bool: true");
  test(R"("abc" <= "abd")", "bool: true");

  test("0 >= 1", "bool: false");
  test("1 >= 0", "bool: true");
  test("0 >= 0", "bool: true");
  test("-1 >= 0", "bool: false");
  test("-1 >= -1", "bool: true");
  test("true <= false", "bool: false");
  test("0x7fffffffffffffff >= 0x8000000000000000", "bool: false");
  test("0xffffffffffffffff >= 0", "bool: true");
  test(R"("a" >= "b")", "bool: false");
  test(R"("b" >= "a")", "bool: true");
  test(R"("a" >= "a")", "bool: true");
  test(R"("" >= "a")", "bool: false");
  test(R"("abc" >= "abd")", "bool: false");
}

TEST(fold_literals, plus)
{
  test("0 + 0", "int: 0 :: [int64]");
  test("0 + 1", "int: 1 :: [int64]");
  test("1 + 2", "int: 3 :: [int64]");
  test("5 + 10", "int: 15 :: [int64]");
  test("-5 + 10", "int: 5 :: [int64]");
  test("-10 + -5", "negative int: -15");
  test("9223372036854775807 + 1", "int: 9223372036854775808 :: [uint64]");
  test("9223372036854775808 + 1", "int: 9223372036854775809 :: [uint64]");
  test("0 + (-1)", "negative int: -1");
  test("1 + (-2)", "negative int: -1");
  test("-5 + 5", "int: 0 :: [int64]");
  test("0xffffffffffffffff + 0", "int: 18446744073709551615 :: [uint64]");
  test("0x7fffffffffffffff + (-1)", "int: 9223372036854775806 :: [int64]");
  test_error("0xffffffffffffffff + 1", "overflow");
  test_error("0x8000000000000000 + (-1)", "overflow"); // Coerced to signed

  test(R"("foo" + "bar")", "string: foobar");
  test(R"("" + "test")", "string: test");
  test(R"("hello" + 3)", "string: lo");
  test_warning(R"("hello" + 8)", "literal string will always be empty");

  test("false + false", "bool: false");
  test("false + true", "bool: true");
  test("true + true", "bool: true");
}

TEST(fold_literals, minus)
{
  test("0 - 1", "negative int: -1");
  test("1 - 2", "negative int: -1");
  test("0 - 0", "int: 0 :: [int64]");
  test("1 - 1", "int: 0 :: [int64]");
  test("2 - 1", "int: 1 :: [int64]");
  test("0xffffffffffffffff - 1", "int: 18446744073709551614 :: [uint64]");
  test("0xffffffffffffffff - 0xffffffffffffffff", "int: 0 :: [uint64]");
  test("0x8000000000000000 - 1", "int: 9223372036854775807 :: [uint64]");
  test("0x7fffffffffffffff - 0x7fffffffffffffff", "int: 0 :: [int64]");
  test("0x7fffffffffffffff - 0x8000000000000000", "negative int: -1");
  test("0x8000000000000000 - 0x8000000000000001", "negative int: -1");
  test("0 - 0x8000000000000000", "negative int: -9223372036854775808");
  test("0x7fffffffffffffff - 0xffffffffffffffff",
       "negative int: -9223372036854775808",
       "");
  test("0-9223372036854775808", "negative int: -9223372036854775808");
  test("0x8000000000000000-0xffffffffffffffff",
       "negative int: -9223372036854775807",
       "");
  test("0x8000000000000000-0x7fffffffffffffff", "int: 1 :: [uint64]");
  test("0-0x8000000000000000", "negative int: -9223372036854775808");
  test("9223372036854775807-9223372036854775808", "negative int: -1");
  test_error("0 - 0x8000000000000001", "underflow");
  test_error("1 - 0xffffffffffffffff", "underflow");
  test_error("0-9223372036854775809", "underflow");
  test_error("10-9223372036854775819", "underflow");
  test_error("0x7fffffffffffffff - (-1)", "overflow"); // Coerced to signed
  test_error("0xffffffffffffffff - (-1)", "overflow");
  test_error("0 - 0xffffffffffffffff", "underflow");

  test("false - false", "bool: false");
  test("false - true", "bool: true");
  test("true - true", "bool: false");
  test("true - false", "bool: true");
}

TEST(fold_literals, multiply)
{
  test("0 * 0", "int: 0 :: [int64]");
  test("0 * 1", "int: 0 :: [int64]");
  test("1 * 0", "int: 0 :: [int64]");
  test("1 * 1", "int: 1 :: [int64]");
  test("2 * 3", "int: 6 :: [int64]");
  test("10 * 20", "int: 200 :: [int64]");
  test("-1 * 1", "negative int: -1");
  test("1 * -1", "negative int: -1");
  test("-1 * -1", "int: 1 :: [int64]");
  test("-10 * 5", "negative int: -50");
  test("5 * -10", "negative int: -50");
  test("-5 * -10", "int: 50 :: [int64]");
  test("0xffffffffffffffff * 0x1", "int: 18446744073709551615 :: [uint64]");
  test("0x7fffffffffffffff * 0x2", "int: 18446744073709551614 :: [uint64]");
  test("0xffffffffffffffff * 0x0", "int: 0 :: [uint64]");
  test("9223372036854775807 * 1", "int: 9223372036854775807 :: [int64]");
  test("9223372036854775808 * 1", "int: 9223372036854775808 :: [uint64]");
  test_error("0x8000000000000000 * 0x2", "overflow");
  test_error("0xffffffffffffffff * 0xffffffffffffffff", "overflow");

  test("false * false", "bool: false");
  test("false * true", "bool: false");
  test("true * true", "bool: true");
}

TEST(fold_literals, divide)
{
  test("10 / 2", "int: 5 :: [int64]");
  test("15 / 3", "int: 5 :: [int64]");
  test("100 / 10", "int: 10 :: [int64]");
  test("0 / 5", "int: 0 :: [int64]");
  test("-10 / 2", "negative int: -5");
  test("10 / -2", "negative int: -5");
  test("-10 / -2", "int: 5 :: [int64]");
  test("0xffffffffffffffff / 0x10", "int: 1152921504606846975 :: [uint64]");
  test("0x7fffffffffffffff / 0xff", "int: 36170086419038336 :: [int64]");
  test("0x8000000000000000 / 0xff", "int: 36170086419038336 :: [uint64]");
  test("9223372036854775807 / 1", "int: 9223372036854775807 :: [int64]");
  test("9223372036854775808 / 2", "int: 4611686018427387904 :: [uint64]");
  test("0xffffffffffffffff / 1", "int: 18446744073709551615 :: [uint64]");
  test_error("123 / 0", "unable to fold");
  test_error("-123 / 0", "unable to fold");

  test("false / true", "bool: false");
  test("true / true", "bool: true");
  test_error("false / false", "unable to fold");
  test_error("true / false", "unable to fold");
}

TEST(fold_literals, mod)
{
  test("10 % 3", "int: 1 :: [int64]");
  test("15 % 4", "int: 3 :: [int64]");
  test("0 % 5", "int: 0 :: [int64]");
  test("100 % 10", "int: 0 :: [int64]");
  test("-10 % 3", "negative int: -1");
  test("10 % -3", "int: 1 :: [int64]");
  test("-10 % -3", "negative int: -1");
  test("0xffffffffffffffff % 0x10", "int: 15 :: [uint64]");
  test("0x7fffffffffffffff % 0xff", "int: 127 :: [int64]");
  test("0x8000000000000000 % 0xff", "int: 128 :: [uint64]");
  test_error("123 % 0", "unable to fold");
  test_error("-123 % 0", "unable to fold");

  test("false % true", "bool: false");
  test("true % true", "bool: false");
  test_error("false % false", "unable to fold");
  test_error("true % false", "unable to fold");
}

TEST(fold_literals, binary)
{
  test("1 & 1", "int: 1 :: [int64]");
  test("1 & 0", "int: 0 :: [int64]");
  test("0 & 0", "int: 0 :: [int64]");
  test("0xffffffffffffffff & 0x1", "int: 1 :: [uint64]");
  test("0xffffffffffffffff & 0x0", "int: 0 :: [uint64]");
  test("0xffffffffffffffff & 0xffffffffffffffff",
       "int: 18446744073709551615 :: [uint64]",
       "");
  test("0x7fffffffffffffff & 0x1", "int: 1 :: [int64]");
  test("0x7fffffffffffffff & 0x0", "int: 0 :: [int64]");
  test("0x7fffffffffffffff & 0x7fffffffffffffff",
       "int: 9223372036854775807 :: [int64]",
       "");
  test("-1 & 1", "int: 1 :: [int64]");
  test("-1 & 0", "int: 0 :: [int64]");
  test("-1 & -1", "negative int: -1");
  test("0x8000000000000000 & 0x1", "int: 0 :: [uint64]");
  test("0x8000000000000000 & 0x8000000000000000",
       "int: 9223372036854775808 :: [uint64]",
       "");
  test_error("-1 & 0xffffffffffffffff", "overflow");

  test("1 | 1", "int: 1 :: [int64]");
  test("1 | 0", "int: 1 :: [int64]");
  test("0 | 0", "int: 0 :: [int64]");
  test("0xffffffffffffffff | 0x1", "int: 18446744073709551615 :: [uint64]");
  test("0xffffffffffffffff | 0x0", "int: 18446744073709551615 :: [uint64]");
  test("0x7fffffffffffffff | 0x1", "int: 9223372036854775807 :: [int64]");
  test("0x7fffffffffffffff | 0x0", "int: 9223372036854775807 :: [int64]");
  test("-1 | 1", "negative int: -1");
  test("-1 | 0", "negative int: -1");
  test("-1 | -1", "negative int: -1");
  test("0x8000000000000000 | 0x1", "int: 9223372036854775809 :: [uint64]");
  test("0x8000000000000000 | 0x8000000000000000",
       "int: 9223372036854775808 :: [uint64]",
       "");
  test("0xff | 0x0f", "int: 255 :: [int64]");
  test("0xff | 0xf0", "int: 255 :: [int64]");
  test("-10 | 0x0f", "negative int: -1");
  test("0x7fffffffffffffff | -1", "negative int: -1");
  test("0xffffffff | -0xf", "negative int: -1");
  test("-0xff | -0x0f", "negative int: -15");

  test("1 ^ 1", "int: 0 :: [int64]");
  test("1 ^ 0", "int: 1 :: [int64]");
  test("0 ^ 0", "int: 0 :: [int64]");
  test("0xffffffffffffffff ^ 0x1", "int: 18446744073709551614 :: [uint64]");
  test("0xffffffffffffffff ^ 0x0", "int: 18446744073709551615 :: [uint64]");
  test("0xffffffffffffffff ^ 0xffffffffffffffff", "int: 0 :: [uint64]");
  test("0x7fffffffffffffff ^ 0x1", "int: 9223372036854775806 :: [int64]");
  test("0x7fffffffffffffff ^ 0x0", "int: 9223372036854775807 :: [int64]");
  test("0x7fffffffffffffff ^ 0x7fffffffffffffff", "int: 0 :: [int64]");
  test("-1 ^ 1", "negative int: -2");
  test("-1 ^ 0", "negative int: -1");
  test("-1 ^ -1", "int: 0 :: [int64]");
  test("0x8000000000000000 ^ 0x1", "int: 9223372036854775809 :: [uint64]");
  test("0x8000000000000000 ^ 0x8000000000000000", "int: 0 :: [uint64]");
  test("0xff ^ 0x0f", "int: 240 :: [int64]");
  test("0xff ^ 0xf0", "int: 15 :: [int64]");
  test("-10 ^ 0x0f", "negative int: -7");
  test("0x7fffffffffffffff ^ -1", "negative int: -9223372036854775808");
  test("0xffffffff ^ -0xf", "negative int: -4294967282");
  test("-0xff ^ -0x0f", "int: 240 :: [int64]");

  test("1 << 0", "int: 1 :: [int64]");
  test("1 << 1", "int: 2 :: [int64]");
  test("1 << 2", "int: 4 :: [int64]");
  test("1 << 63", "int: 9223372036854775808 :: [uint64]");
  test("0xff << 8", "int: 65280 :: [int64]");
  test("0xff << 56", "int: 18374686479671623680 :: [uint64]");
  test("-1 << 1", "negative int: -2");
  test("-1 << 63", "negative int: -9223372036854775808");
  test("0x7fffffffffffffff << 1", "int: 18446744073709551614 :: [uint64]");
  test("0x8000000000000000 << 1", "int: 0 :: [uint64]"); // Legal overflow
  test_error("1 << 64", "overflow");

  test("8 >> 1", "int: 4 :: [int64]");
  test("8 >> 2", "int: 2 :: [int64]");
  test("8 >> 3", "int: 1 :: [int64]");
  test("8 >> 4", "int: 0 :: [int64]");
  test("0xff >> 4", "int: 15 :: [int64]");
  test("0xffffffffffffffff >> 32", "int: 4294967295 :: [uint64]");
  test("-1 >> 1", "negative int: -1"); // Sign extension
  test("-8 >> 2", "negative int: -2"); // Sign extension
  test("0x8000000000000000 >> 1", "int: 4611686018427387904 :: [uint64]");
  test("0x8000000000000000 >> 63", "int: 1 :: [uint64]");
  test_error("1 >> 64", "overflow");

  test("true & true", "bool: true");
  test("true & false", "bool: false");
  test("false & false", "bool: false");
  test("true | true", "bool: true");
  test("true | false", "bool: true");
  test("false | false", "bool: false");
  test("true ^ true", "bool: false");
  test("true ^ false", "bool: true");
  test("false ^ false", "bool: false");
  test("true << false", "bool: false");
  test("true << true", "bool: false");
  test("false << false", "bool: false");
  test("true >> false", "bool: true");
  test("true >> true", "bool: false");
  test("false >> false", "bool: false");
}

TEST(fold_literals, logical)
{
  test("1 && 1", "bool: true");
  test("0 && 1", "bool: false");
  test("0 && 0", "bool: false");
  test("-1 && 0", "bool: false");
  test("1 && -1", "bool: true");
  test("true && true", "bool: true");
  test("true && false", "bool: false");
  test("false && false", "bool: false");
  test("\"foo\" && true", "bool: true");
  test("\"\" && true", "bool: false");
  test("\"\" && false", "bool: false");
  test("1 && true", "bool: true");
  test("0 && true", "bool: false");
  test("1 && false", "bool: false");
  test("0 && false", "bool: false");
  test("-1 && true", "bool: true");
  test("-1 && false", "bool: false");
  test("\"foo\" && 1", "&&"); // Left as is

  test("1 || 1", "bool: true");
  test("0 || 1", "bool: true");
  test("0 || 0", "bool: false");
  test("-1 || 0", "bool: true");
  test("1 || -1", "bool: true");
  test("true || true", "bool: true");
  test("true || false", "bool: true");
  test("false || false", "bool: false");
  test("\"foo\" || true", "bool: true");
  test("\"\" || true", "bool: true");
  test("\"\" || false", "bool: false");
  test("1 || true", "bool: true");
  test("0 || true", "bool: true");
  test("1 || false", "bool: true");
  test("0 || false", "bool: false");
  test("-1 || true", "bool: true");
  test("-1 || false", "bool: true");
  test("\"foo\" || 1", "||"); // Left as is
}

TEST(fold_literals, unary)
{
  test("~(-1)", "int: 0 :: [int64]");
  test("~0xfffffffffffffffe", "int: 1 :: [uint64]");
  test("~0", "int: 18446744073709551615 :: [uint64]");

  test("!0", "bool: true");
  test("!1", "bool: false");
  test("!-1", "bool: false");
  test("!false", "bool: true");
  test("!true", "bool: false");

  test("-1", "negative int: -1");
  test("-0", "int: 0 :: [int64]");
  test("-0x7fffffffffffffff", "negative int: -9223372036854775807");
  test("-0x8000000000000000", "negative int: -9223372036854775808");
  test("-(-0x8000000000000000)", "int: 9223372036854775808 :: [uint64]");
  test_error("-0x8000000000000001", "underflow");
}

TEST(fold_literals, ternary)
{
  test("0 ? true : false", "bool: false");
  test("1 ? true : false", "bool: true");
  test("-1 ? true : false", "bool: true");
  test("\"foo\" ? true : false", "bool: true");
  test("\"\" ? true : false", "bool: false");
}

TEST(fold_literals, cast)
{
  test("(bool)0", "bool: false");
  test("(bool)\"\"", "bool: false");
  test("(bool)false", "bool: false");
  test("(bool)1", "bool: true");
  test("(bool)-1", "bool: true");
  test("(bool)\"str\"", "bool: true");
  test("(bool)true", "bool: true");
}

TEST(fold_literals, conditional)
{
  test_not("if (comptime 1) { }", "if");
  test_not("if (comptime -1) { }", "if");
  test_not("if (comptime 0) { }", "if");
  test_not("if comptime (1 + 1) { }", "if");
  test_not("if (comptime \"str\") { }", "if");
  test_not("if (comptime \"\") { }", "if");
  test_not("if (comptime true) { }", "if");
  test_not("if (comptime false) { }", "if");
  test("if (true) { }", "if");
  test("if (false) { }", "if");
}

TEST(fold_literals, tuple_access)
{
  test_not("comptime (1,0).0", "tuple:");
  test_not("comptime (1, 1 + 1).1", "tuple:");
  // This cannot be evaluated.
  test_error("comptime ($x, 1 + 1).0", "comptime");
  // Left as is.
  test("comptime (1,0).2", ".\n   tuple:"); // bad access
  test("$x = (1,0); $x.0",
       "=\n   variable: $x\n   tuple:\n    int: 1 :: [int64]\n    int: 0 :: "
       "[int64]\n  .\n   variable: $x"); // variable tuple
}

TEST(fold_literals, array_access)
{
  test("\"foo\"[0]", "int: 102 :: [int64]");
  test("\"foo\"[1]", "int: 111 :: [int64]");
}

TEST(fold_literals, comptime)
{
  // This are temporary restrictions, but enough that we error when we hit a
  // variable or map as part of a comptime expression.
  test_error("$x = 0; comptime $x + 1", "variable");
  test_error("@x = 0; comptime @x + 1", "map");
}

} // namespace bpftrace::test::fold_literals
