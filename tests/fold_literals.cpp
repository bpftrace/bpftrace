#include "ast/passes/fold_literals.h"
#include "ast/passes/parser.h"
#include "ast_matchers.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::fold_literals {

using ::testing::HasSubstr;

void test(const std::string& input,
          const Matcher<const ast::Expression&>& expr_matcher,
          const std::string& error = "",
          const std::string& warn = "")
{
  auto mock_bpftrace = get_mock_bpftrace();
  BPFtrace& bpftrace = *mock_bpftrace;

  // The input provided here is embedded into an expression.
  std::string code;
  if (input[input.size() - 1] == '}' || input[input.size() - 1] == ';') {
    code = "begin { " + input + " exit(); }";
  } else {
    code = "begin { " + input + "; exit(); }";
  }
  ast::ASTContext ast("stdin", code);
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
  ast.diagnostics().emit(out);

  if (error.empty()) {
    ASSERT_TRUE(ok && ast.diagnostics().ok()) << msg.str() << out.str();
    EXPECT_THAT(ast,
                Program().WithProbe(
                    Probe({ "begin" }, { ExprStatement(expr_matcher), _ })));
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
  test(input, _, error);
}

void test_warning(const std::string& input, const std::string& warn)
{
  test(input, _, "", warn);
}

void test_not(const std::string& input,
              const Matcher<const ast::Expression&>& expr_matcher)
{
  test(input, testing::Not(expr_matcher), "");
}

TEST(fold_literals, equals)
{
  test("0 == 0", Boolean(true));
  test("0 == 1", Boolean(false));
  test("-1 == 1", Boolean(false));
  test("-1 == -1", Boolean(true));
  test("true == true", Boolean(true));
  test("false == false", Boolean(true));
  test(R"("foo" == "bar")", Boolean(false));
  test(R"("foo" == "foo")", Boolean(true));
  test("str($1) == \"\"", Boolean(true));
  test("str($1) == \"foo\"", Boolean(false));
  test("$1 == 0", Boolean(true));
  test("$1 == 1", Boolean(false));
  test(R"((1,-1,true,"foo") == (1,-1,true,"foo"))", Boolean(true));
  test("(1,(2,(3,1+3))) == (1,(2,(4-1,4)))", Boolean(true));
  test("(1,(2,(3,false))) == (1,(2,(4-1,4)))", Boolean(false));
  test(R"((1,-1,true,"foo") == (1,-1,true,"bar"))", Boolean(false));
  test(R"((-1,true,"foo",1) == (1,-1,true,"foo"))", Boolean(false));
  test("(1,-1) == (1,-1,true)", Boolean(false));
  test("($x,-1) == ($x,-1,true)", Boolean(false));

  // These should be unexpanded.
  test("\"foo\" == 1", Binop(Operator::EQ, String("foo"), Integer(1)));
  test("\"foo\" == true", Binop(Operator::EQ, String("foo"), Boolean(true)));
  test("($x,-1) == ($x,-1)", testing::Not(Boolean(true)));
}

TEST(fold_literals, not_equals)
{
  test("0 != 0", Boolean(false));
  test("0 != 1", Boolean(true));
  test("-1 != 1", Boolean(true));
  test("-1 != -1", Boolean(false));
  test("false != true", Boolean(true));
  test("false != false", Boolean(false));
  test(R"("foo" != "bar")", Boolean(true));
  test(R"("foo" != "foo")", Boolean(false));
  test(R"(str($1) != "")", Boolean(false));
  test(R"(str($1) != "foo")", Boolean(true));
  test("$1 != 0", Boolean(false));
  test("$1 != 1", Boolean(true));
  test(R"((1,-1,true,"foo") != (1,-1,true,"foo"))", Boolean(false));
  test("(1,(2,(3,1+3))) != (1,(2,(4-1,4)))", Boolean(false));
  test("(1,(2,(3,false))) != (1,(2,(4-1,4)))", Boolean(true));
  test(R"((1,-1,true,"foo") != (1,-1,true,"bar"))", Boolean(true));
  test(R"((-1,true,"foo",1) != (1,-1,true,"foo"))", Boolean(true));
  test("(1,-1) != (1,-1,true)", Boolean(true));
  test("($x,-1) != ($x,-1,true)", Boolean(true));

  // These should be unexpanded.
  test(R"("foo" != 1)", Binop(Operator::NE, String("foo"), Integer(1)));
  test(R"("foo" != false)", Binop(Operator::NE, String("foo"), Boolean(false)));
  test("($x,-1) != ($x,-1)", testing::Not(Boolean(true)));
}

TEST(fold_literals, comparison)
{
  test("0 < 1", Boolean(true));
  test("1 < 0", Boolean(false));
  test("0 < 0", Boolean(false));
  test("-1 < 0", Boolean(true));
  test("-1 < -2", Boolean(false));
  test("true < false", Boolean(false));
  test("0x7fffffffffffffff < 0x8000000000000000", Boolean(true));
  test("0xffffffffffffffff < 0", Boolean(false));
  test(R"("a" < "b")", Boolean(true));
  test(R"("b" < "a")", Boolean(false));
  test(R"("a" < "a")", Boolean(false));
  test(R"("" < "a")", Boolean(true));
  test(R"("abc" < "abd")", Boolean(true));

  test("0 > 1", Boolean(false));
  test("1 > 0", Boolean(true));
  test("0 > 0", Boolean(false));
  test("-1 > 0", Boolean(false));
  test("-1 > -2", Boolean(true));
  test("true > false", Boolean(true));
  test("0x7fffffffffffffff > 0x8000000000000000", Boolean(false));
  test("0xffffffffffffffff > 0", Boolean(true));
  test(R"("a" > "b")", Boolean(false));
  test(R"("b" > "a")", Boolean(true));
  test(R"("a" > "a")", Boolean(false));
  test(R"("" > "a")", Boolean(false));
  test(R"("abc" > "abd")", Boolean(false));

  test("0 <= 1", Boolean(true));
  test("1 <= 0", Boolean(false));
  test("0 <= 0", Boolean(true));
  test("-1 <= 0", Boolean(true));
  test("-1 <= -1", Boolean(true));
  test("false <= true", Boolean(true));
  test("0x7fffffffffffffff <= 0x8000000000000000", Boolean(true));
  test("0xffffffffffffffff <= 0", Boolean(false));
  test(R"("a" <= "b")", Boolean(true));
  test(R"("b" <= "a")", Boolean(false));
  test(R"("a" <= "a")", Boolean(true));
  test(R"("" <= "a")", Boolean(true));
  test(R"("abc" <= "abd")", Boolean(true));

  test("0 >= 1", Boolean(false));
  test("1 >= 0", Boolean(true));
  test("0 >= 0", Boolean(true));
  test("-1 >= 0", Boolean(false));
  test("-1 >= -1", Boolean(true));
  test("true <= false", Boolean(false));
  test("0x7fffffffffffffff >= 0x8000000000000000", Boolean(false));
  test("0xffffffffffffffff >= 0", Boolean(true));
  test(R"("a" >= "b")", Boolean(false));
  test(R"("b" >= "a")", Boolean(true));
  test(R"("a" >= "a")", Boolean(true));
  test(R"("" >= "a")", Boolean(false));
  test(R"("abc" >= "abd")", Boolean(false));
}

TEST(fold_literals, plus)
{
  test("0 + 0", Integer(0));
  test("0 + 1", Integer(1));
  test("1 + 2", Integer(3));
  test("5 + 10", Integer(15));
  test("-5 + 10", Integer(5));
  test("-10 + -5", NegativeInteger(-15));
  test("9223372036854775807 + 1", Integer(9223372036854775808ULL));
  test("9223372036854775808 + 1", Integer(9223372036854775809ULL));
  test("0 + (-1)", NegativeInteger(-1));
  test("1 + (-2)", NegativeInteger(-1));
  test("-5 + 5", Integer(0));
  test("0xffffffffffffffff + 0", Integer(18446744073709551615ULL));
  test("0x7fffffffffffffff + (-1)", Integer(9223372036854775806));
  test_error("0xffffffffffffffff + 1", "overflow");
  test_error("0x8000000000000000 + (-1)", "overflow"); // Coerced to signed

  test(R"("foo" + "bar")", String("foobar"));
  test(R"("" + "test")", String("test"));
  test(R"("hello" + 3)", String("lo"));
  test_warning(R"("hello" + 8)", "literal string will always be empty");

  test("false + false", Boolean(false));
  test("false + true", Boolean(true));
  test("true + true", Boolean(true));
}

TEST(fold_literals, minus)
{
  test("0 - 1", NegativeInteger(-1));
  test("1 - 2", NegativeInteger(-1));
  test("0 - 0", Integer(0));
  test("1 - 1", Integer(0));
  test("2 - 1", Integer(1));
  test("0xffffffffffffffff - 1", Integer(18446744073709551614ULL));
  test("0xffffffffffffffff - 0xffffffffffffffff", Integer(0));
  test("0x8000000000000000 - 1", Integer(9223372036854775807));
  test("0x7fffffffffffffff - 0x7fffffffffffffff", Integer(0));
  test("0x7fffffffffffffff - 0x8000000000000000", NegativeInteger(-1));
  test("0x8000000000000000 - 0x8000000000000001", NegativeInteger(-1));
  test("0 - 0x8000000000000000", NegativeInteger(-9223372036854775808ULL));
  test("0x7fffffffffffffff - 0xffffffffffffffff",
       NegativeInteger(-9223372036854775808ULL),
       "");
  test("0-9223372036854775808", NegativeInteger(-9223372036854775808ULL));
  test("0x8000000000000000-0xffffffffffffffff",
       NegativeInteger(-9223372036854775807),
       "");
  test("0x8000000000000000-0x7fffffffffffffff", Integer(1));
  test("0-0x8000000000000000", NegativeInteger(-9223372036854775808ULL));
  test("9223372036854775807-9223372036854775808", NegativeInteger(-1));
  test_error("0 - 0x8000000000000001", "underflow");
  test_error("1 - 0xffffffffffffffff", "underflow");
  test_error("0-9223372036854775809", "underflow");
  test_error("10-9223372036854775819", "underflow");
  test_error("0x7fffffffffffffff - (-1)", "overflow"); // Coerced to signed
  test_error("0xffffffffffffffff - (-1)", "overflow");
  test_error("0 - 0xffffffffffffffff", "underflow");

  test("false - false", Boolean(false));
  test("false - true", Boolean(true));
  test("true - true", Boolean(false));
  test("true - false", Boolean(true));
}

TEST(fold_literals, multiply)
{
  test("0 * 0", Integer(0));
  test("0 * 1", Integer(0));
  test("1 * 0", Integer(0));
  test("1 * 1", Integer(1));
  test("2 * 3", Integer(6));
  test("10 * 20", Integer(200));
  test("-1 * 1", NegativeInteger(-1));
  test("1 * -1", NegativeInteger(-1));
  test("-1 * -1", Integer(1));
  test("-10 * 5", NegativeInteger(-50));
  test("5 * -10", NegativeInteger(-50));
  test("-5 * -10", Integer(50));
  test("0xffffffffffffffff * 0x1", Integer(18446744073709551615ULL));
  test("0x7fffffffffffffff * 0x2", Integer(18446744073709551614ULL));
  test("0xffffffffffffffff * 0x0", Integer(0));
  test("9223372036854775807 * 1", Integer(9223372036854775807));
  test("9223372036854775808 * 1", Integer(9223372036854775808ULL));
  test_error("0x8000000000000000 * 0x2", "overflow");
  test_error("0xffffffffffffffff * 0xffffffffffffffff", "overflow");

  test("false * false", Boolean(false));
  test("false * true", Boolean(false));
  test("true * true", Boolean(true));
}

TEST(fold_literals, divide)
{
  test("10 / 2", Integer(5));
  test("15 / 3", Integer(5));
  test("100 / 10", Integer(10));
  test("0 / 5", Integer(0));
  test("-10 / 2", NegativeInteger(-5));
  test("10 / -2", NegativeInteger(-5));
  test("-10 / -2", Integer(5));
  test("0xffffffffffffffff / 0x10", Integer(1152921504606846975));
  test("0x7fffffffffffffff / 0xff", Integer(36170086419038336));
  test("0x8000000000000000 / 0xff", Integer(36170086419038336));
  test("9223372036854775807 / 1", Integer(9223372036854775807));
  test("9223372036854775808 / 2", Integer(4611686018427387904));
  test("0xffffffffffffffff / 1", Integer(18446744073709551615ULL));
  test_error("123 / 0", "unable to fold");
  test_error("-123 / 0", "unable to fold");

  test("false / true", Boolean(false));
  test("true / true", Boolean(true));
  test_error("false / false", "unable to fold");
  test_error("true / false", "unable to fold");
}

TEST(fold_literals, mod)
{
  test("10 % 3", Integer(1));
  test("15 % 4", Integer(3));
  test("0 % 5", Integer(0));
  test("100 % 10", Integer(0));
  test("-10 % 3", NegativeInteger(-1));
  test("10 % -3", Integer(1));
  test("-10 % -3", NegativeInteger(-1));
  test("0xffffffffffffffff % 0x10", Integer(15));
  test("0x7fffffffffffffff % 0xff", Integer(127));
  test("0x8000000000000000 % 0xff", Integer(128));
  test_error("123 % 0", "unable to fold");
  test_error("-123 % 0", "unable to fold");

  test("false % true", Boolean(false));
  test("true % true", Boolean(false));
  test_error("false % false", "unable to fold");
  test_error("true % false", "unable to fold");
}

TEST(fold_literals, binary)
{
  test("1 & 1", Integer(1));
  test("1 & 0", Integer(0));
  test("0 & 0", Integer(0));
  test("0xffffffffffffffff & 0x1", Integer(1));
  test("0xffffffffffffffff & 0x0", Integer(0));
  test("0xffffffffffffffff & 0xffffffffffffffff",
       Integer(18446744073709551615ULL),
       "");
  test("0x7fffffffffffffff & 0x1", Integer(1));
  test("0x7fffffffffffffff & 0x0", Integer(0));
  test("0x7fffffffffffffff & 0x7fffffffffffffff",
       Integer(9223372036854775807),
       "");
  test("-1 & 1", Integer(1));
  test("-1 & 0", Integer(0));
  test("-1 & -1", NegativeInteger(-1));
  test("0x8000000000000000 & 0x1", Integer(0));
  test("0x8000000000000000 & 0x8000000000000000",
       Integer(9223372036854775808ULL),
       "");
  test_error("-1 & 0xffffffffffffffff", "overflow");

  test("1 | 1", Integer(1));
  test("1 | 0", Integer(1));
  test("0 | 0", Integer(0));
  test("0xffffffffffffffff | 0x1", Integer(18446744073709551615ULL));
  test("0xffffffffffffffff | 0x0", Integer(18446744073709551615ULL));
  test("0x7fffffffffffffff | 0x1", Integer(9223372036854775807));
  test("0x7fffffffffffffff | 0x0", Integer(9223372036854775807));
  test("-1 | 1", NegativeInteger(-1));
  test("-1 | 0", NegativeInteger(-1));
  test("-1 | -1", NegativeInteger(-1));
  test("0x8000000000000000 | 0x1", Integer(9223372036854775809ULL));
  test("0x8000000000000000 | 0x8000000000000000",
       Integer(9223372036854775808ULL),
       "");
  test("0xff | 0x0f", Integer(255));
  test("0xff | 0xf0", Integer(255));
  test("-10 | 0x0f", NegativeInteger(-1));
  test("0x7fffffffffffffff | -1", NegativeInteger(-1));
  test("0xffffffff | -0xf", NegativeInteger(-1));
  test("-0xff | -0x0f", NegativeInteger(-15));

  test("1 ^ 1", Integer(0));
  test("1 ^ 0", Integer(1));
  test("0 ^ 0", Integer(0));
  test("0xffffffffffffffff ^ 0x1", Integer(18446744073709551614ULL));
  test("0xffffffffffffffff ^ 0x0", Integer(18446744073709551615ULL));
  test("0xffffffffffffffff ^ 0xffffffffffffffff", Integer(0));
  test("0x7fffffffffffffff ^ 0x1", Integer(9223372036854775806));
  test("0x7fffffffffffffff ^ 0x0", Integer(9223372036854775807));
  test("0x7fffffffffffffff ^ 0x7fffffffffffffff", Integer(0));
  test("-1 ^ 1", NegativeInteger(-2));
  test("-1 ^ 0", NegativeInteger(-1));
  test("-1 ^ -1", Integer(0));
  test("0x8000000000000000 ^ 0x1", Integer(9223372036854775809ULL));
  test("0x8000000000000000 ^ 0x8000000000000000", Integer(0));
  test("0xff ^ 0x0f", Integer(240));
  test("0xff ^ 0xf0", Integer(15));
  test("-10 ^ 0x0f", NegativeInteger(-7));
  test("0x7fffffffffffffff ^ -1", NegativeInteger(-9223372036854775808ULL));
  test("0xffffffff ^ -0xf", NegativeInteger(-4294967282));
  test("-0xff ^ -0x0f", Integer(240));

  test("1 << 0", Integer(1));
  test("1 << 1", Integer(2));
  test("1 << 2", Integer(4));
  test("1 << 63", Integer(9223372036854775808ULL));
  test("0xff << 8", Integer(65280));
  test("0xff << 56", Integer(18374686479671623680ULL));
  test("-1 << 1", NegativeInteger(-2));
  test("-1 << 63", NegativeInteger(-9223372036854775808ULL));
  test("0x7fffffffffffffff << 1", Integer(18446744073709551614ULL));
  test("0x8000000000000000 << 1", Integer(0)); // Legal overflow
  test_error("1 << 64", "overflow");

  test("8 >> 1", Integer(4));
  test("8 >> 2", Integer(2));
  test("8 >> 3", Integer(1));
  test("8 >> 4", Integer(0));
  test("0xff >> 4", Integer(15));
  test("0xffffffffffffffff >> 32", Integer(4294967295));
  test("-1 >> 1", NegativeInteger(-1)); // Sign extension
  test("-8 >> 2", NegativeInteger(-2)); // Sign extension
  test("0x8000000000000000 >> 1", Integer(4611686018427387904));
  test("0x8000000000000000 >> 63", Integer(1));
  test_error("1 >> 64", "overflow");

  test("true & true", Boolean(true));
  test("true & false", Boolean(false));
  test("false & false", Boolean(false));
  test("true | true", Boolean(true));
  test("true | false", Boolean(true));
  test("false | false", Boolean(false));
  test("true ^ true", Boolean(false));
  test("true ^ false", Boolean(true));
  test("false ^ false", Boolean(false));
  test("true << false", Boolean(false));
  test("true << true", Boolean(false));
  test("false << false", Boolean(false));
  test("true >> false", Boolean(true));
  test("true >> true", Boolean(false));
  test("false >> false", Boolean(false));
}

TEST(fold_literals, logical)
{
  test("1 && 1", Boolean(true));
  test("0 && 1", Boolean(false));
  test("0 && 0", Boolean(false));
  test("-1 && 0", Boolean(false));
  test("1 && -1", Boolean(true));
  test("true && true", Boolean(true));
  test("true && false", Boolean(false));
  test("false && false", Boolean(false));
  test("\"foo\" && true", Boolean(true));
  test("\"\" && true", Boolean(false));
  test("\"\" && false", Boolean(false));
  test("1 && true", Boolean(true));
  test("0 && true", Boolean(false));
  test("1 && false", Boolean(false));
  test("0 && false", Boolean(false));
  test("-1 && true", Boolean(true));
  test("-1 && false", Boolean(false));

  test("1 || 1", Boolean(true));
  test("0 || 1", Boolean(true));
  test("0 || 0", Boolean(false));
  test("-1 || 0", Boolean(true));
  test("1 || -1", Boolean(true));
  test("true || true", Boolean(true));
  test("true || false", Boolean(true));
  test("false || false", Boolean(false));
  test("\"foo\" || true", Boolean(true));
  test("\"\" || true", Boolean(true));
  test("\"\" || false", Boolean(false));
  test("1 || true", Boolean(true));
  test("0 || true", Boolean(true));
  test("1 || false", Boolean(true));
  test("0 || false", Boolean(false));
  test("-1 || true", Boolean(true));
  test("-1 || false", Boolean(true));

  // These are unexpanded.
  test("\"foo\" && 1", Binop(Operator::LAND, String("foo"), Integer(1)));
  test("\"foo\" || 1", Binop(Operator::LOR, String("foo"), Integer(1)));
}

TEST(fold_literals, unary)
{
  test("~(-1)", Integer(0));
  test("~0xfffffffffffffffe", Integer(1));
  test("~0", Integer(18446744073709551615ULL));

  test("!0", Boolean(true));
  test("!1", Boolean(false));
  test("!-1", Boolean(false));
  test("!false", Boolean(true));
  test("!true", Boolean(false));

  test("-1", NegativeInteger(-1));
  test("-0", Integer(0));
  test("-0x7fffffffffffffff", NegativeInteger(-9223372036854775807));
  test("-0x8000000000000000", NegativeInteger(-9223372036854775808ULL));
  test("-(-0x8000000000000000)", Integer(9223372036854775808ULL));
  test_error("-0x8000000000000001", "underflow");
}

TEST(fold_literals, ternary)
{
  test("0 ? true : false", Boolean(false));
  test("1 ? true : false", Boolean(true));
  test("-1 ? true : false", Boolean(true));
  test("\"foo\" ? true : false", Boolean(true));
  test("\"\" ? true : false", Boolean(false));
}

TEST(fold_literals, cast)
{
  test("(bool)0", Boolean(false));
  test("(bool)\"\"", Boolean(false));
  test("(bool)false", Boolean(false));
  test("(bool)1", Boolean(true));
  test("(bool)-1", Boolean(true));
  test("(bool)\"str\"", Boolean(true));
  test("(bool)true", Boolean(true));
}

TEST(fold_literals, conditional)
{
  test_not("if (comptime 1) { }", IfExprMatcher());
  test_not("if (comptime -1) { }", IfExprMatcher());
  test_not("if (comptime 0) { }", IfExprMatcher());
  test_not("if comptime (1 + 1) { }", IfExprMatcher());
  test_not("if (comptime \"str\") { }", IfExprMatcher());
  test_not("if (comptime \"\") { }", IfExprMatcher());
  test_not("if (comptime true) { }", IfExprMatcher());
  test_not("if (comptime false) { }", IfExprMatcher());
  test("if (true) { }", IfExprMatcher());
  test("if (false) { }", IfExprMatcher());
}

TEST(fold_literals, tuple_access)
{
  test_not("comptime (1,0).0", ComptimeMatcher());
  test_not("comptime (1, 1 + 1).1", ComptimeMatcher());
  // This cannot be evaluated.
  test("comptime ($x, 1 + 1).0", ComptimeMatcher());
  // This should be left as is.
  test("{ $x = (1,0); $x.0 };", Block({ _ }, TupleAccess(Variable("$x"), 0)));
  // Left as is, since it is an error.
  test("comptime (1,0).2",
       Comptime(TupleAccess(Tuple({ Integer(1), Integer(0) }), 2)));
}

TEST(fold_literals, array_access)
{
  test("\"foo\"[0]", Integer(102));
  test("\"foo\"[1]", Integer(111));
}

TEST(fold_literals, comptime)
{
  // These can't be evaluated at compile time
  test("{ $x = 0; comptime ($x + 1) };", Block({ _ }, ComptimeMatcher()));
  test("{ @x = 0; comptime (@x + 1) };", Block({ _ }, ComptimeMatcher()));
}

} // namespace bpftrace::test::fold_literals
