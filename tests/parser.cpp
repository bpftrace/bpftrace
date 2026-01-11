#include <climits>
#include <gmock/gmock-matchers.h>
#include <sstream>

#include "ast/ast.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/c_macro_expansion.h"
#include "ast/passes/clang_parser.h"
#include "ast/passes/printer.h"
#include "ast_matchers.h"
#include "driver.h"
#include "gtest/gtest.h"

namespace bpftrace::test::parser {

using bpftrace::test::AssignMapStatement;
using bpftrace::test::AssignScalarMapStatement;
using bpftrace::test::AssignVarStatement;
using bpftrace::test::Block;
using bpftrace::test::Boolean;
using bpftrace::test::Builtin;
using bpftrace::test::Call;
using bpftrace::test::Cast;
using bpftrace::test::CStatement;
using bpftrace::test::ExprStatement;
using bpftrace::test::FieldAccess;
using bpftrace::test::Integer;
using bpftrace::test::Map;
using bpftrace::test::MapAddr;
using bpftrace::test::None;
using bpftrace::test::Offsetof;
using bpftrace::test::PositionalParameter;
using bpftrace::test::PositionalParameterCount;
using bpftrace::test::Probe;
using bpftrace::test::Program;
using bpftrace::test::SizedType;
using bpftrace::test::String;
using bpftrace::test::Tuple;
using bpftrace::test::Typeof;
using bpftrace::test::Unop;
using bpftrace::test::Variable;
using bpftrace::test::VariableAddr;
using bpftrace::test::While;

void test_parse_failure(BPFtrace &bpftrace,
                        const std::string &input,
                        std::string_view expected_error)
{
  std::stringstream out;
  ast::ASTContext ast("stdin", input);
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .run();
  ASSERT_TRUE(bool(ok));

  ASSERT_FALSE(ast.diagnostics().ok());
  ast.diagnostics().emit(out);

  if (expected_error.data()) {
    if (!expected_error.empty() && expected_error[0] == '\n')
      expected_error.remove_prefix(1); // Remove initial '\n'
    EXPECT_EQ(expected_error, out.str());
  }
}

void test_parse_failure(const std::string &input,
                        std::string_view expected_error)
{
  BPFtrace bpftrace;
  test_parse_failure(bpftrace, input, expected_error);
}

void test_macro_parse_failure(BPFtrace &bpftrace,
                              const std::string &input,
                              std::string_view expected_error)
{
  std::stringstream out;
  ast::ASTContext ast("stdin", input);
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(CreateParsePass())
                .add(ast::CreateClangParsePass())
                .add(ast::CreateCMacroExpansionPass())
                .run();
  ASSERT_TRUE(bool(ok));

  ASSERT_FALSE(ast.diagnostics().ok());
  ast.diagnostics().emit(out);

  if (expected_error.data()) {
    if (!expected_error.empty() && expected_error[0] == '\n')
      expected_error.remove_prefix(1); // Remove initial '\n'
    EXPECT_EQ(expected_error, out.str());
  }
}

void test_macro_parse_failure(const std::string &input,
                              std::string_view expected_error)
{
  BPFtrace bpftrace;
  test_macro_parse_failure(bpftrace, input, expected_error);
}

template <typename MatcherT>
void test(BPFtrace &bpftrace,
          const std::string &input,
          const MatcherT &matcher,
          bool reparse = true)
{
  std::ostringstream out;
  ast::ASTContext ast("stdin", input);
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .run();
  ASSERT_TRUE(bool(ok));

  ast.diagnostics().emit(out);
  ASSERT_TRUE(ast.diagnostics().ok()) << out.str() << input;

  EXPECT_THAT(ast, matcher) << input;

  // Generally, we format and reparse the same AST, to ensure that it parses
  // successfully in the same way. This is a test of both the formatter and
  // the parser, to ensure that they are consistent (at least for the tests).
  std::stringstream ss;
  ast::Printer printer(ast, ss);
  printer.visit(ast.root);
  if (reparse) {
    test(bpftrace, ss.str(), matcher, false);
  } else {
    EXPECT_EQ(input, ss.str());
  }
}

template <typename MatcherT>
void test(const std::string &input, const MatcherT &matcher)
{
  BPFtrace bpftrace;
  test(bpftrace, input, matcher);
}

TEST(Parser, builtin_variables)
{
  test("kprobe:sys_read { pid }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" }, { ExprStatement(Builtin("pid")) })));

  test("kprobe:f { tid }",
       Program().WithProbe(
           Probe({ "kprobe:f" }, { ExprStatement(Builtin("tid")) })));

  test("kprobe:f { __builtin_cgroup }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(Builtin("__builtin_cgroup")) })));

  test("kprobe:f { __builtin_uid }",
       Program().WithProbe(
           Probe({ "kprobe:f" }, { ExprStatement(Builtin("__builtin_uid")) })));

  test("kprobe:f { __builtin_username }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(Builtin("__builtin_username")) })));

  test("kprobe:f { __builtin_gid }",
       Program().WithProbe(
           Probe({ "kprobe:f" }, { ExprStatement(Builtin("__builtin_gid")) })));

  test("kprobe:f { nsecs }",
       Program().WithProbe(
           Probe({ "kprobe:f" }, { ExprStatement(Builtin("nsecs")) })));

  test("kprobe:f { __builtin_elapsed }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(Builtin("__builtin_elapsed")) })));

  test("kprobe:f { __builtin_cpu }",
       Program().WithProbe(
           Probe({ "kprobe:f" }, { ExprStatement(Builtin("__builtin_cpu")) })));

  test("kprobe:f { __builtin_curtask }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(Builtin("__builtin_curtask")) })));

  test("kprobe:f { __builtin_rand }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(Builtin("__builtin_rand")) })));

  test("kprobe:f { ctx }",
       Program().WithProbe(
           Probe({ "kprobe:f" }, { ExprStatement(Builtin("ctx")) })));

  test("kprobe:f { __builtin_comm }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(Builtin("__builtin_comm")) })));

  test("kprobe:f { kstack }",
       Program().WithProbe(
           Probe({ "kprobe:f" }, { ExprStatement(Builtin("kstack")) })));

  test("kprobe:f { ustack }",
       Program().WithProbe(
           Probe({ "kprobe:f" }, { ExprStatement(Builtin("ustack")) })));

  test("kprobe:f { arg0 }",
       Program().WithProbe(
           Probe({ "kprobe:f" }, { ExprStatement(Builtin("arg0")) })));

  test("kprobe:f { __builtin_retval }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(Builtin("__builtin_retval")) })));

  test("kprobe:f { __builtin_func }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(Builtin("__builtin_func")) })));

  test("kprobe:f { __builtin_probe }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(Builtin("__builtin_probe")) })));

  test("kprobe:f { args }",
       Program().WithProbe(
           Probe({ "kprobe:f" }, { ExprStatement(Builtin("args")) })));
}

TEST(Parser, positional_param)
{
  test("kprobe:f { $1 }",
       Program().WithProbe(
           Probe({ "kprobe:f" }, { ExprStatement(PositionalParameter(1)) })));

  test_parse_failure("kprobe:f { $0 }", R"(
stdin:1:12-14: ERROR: param $0 is out of integer range [1, 9223372036854775807]
kprobe:f { $0 }
           ~~
)");

  test_parse_failure("kprobe:f { $999999999999999999999999 }", R"(
stdin:1:12-37: ERROR: param $999999999999999999999999 is out of integer range [1, 9223372036854775807]
kprobe:f { $999999999999999999999999 }
           ~~~~~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, positional_param_count)
{
  test("kprobe:f { $# }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(PositionalParameterCount()) })));
}

TEST(Parser, positional_param_attachpoint)
{
  BPFtrace bpftrace;
  bpftrace.add_param("foo");
  bpftrace.add_param("bar");
  bpftrace.add_param("baz");

  test(bpftrace,
       "kprobe:$1 { 1 }",
       Program().WithProbe(
           Probe({ "kprobe:foo" }, { ExprStatement(Integer(1)) })));

  test(bpftrace,
       R"PROG(kprobe:$1"here" { 1 })PROG",
       Program().WithProbe(
           Probe({ "kprobe:foohere" }, { ExprStatement(Integer(1)) })));

  test(bpftrace,
       R"PROG(uprobe:zzzzzzz:$2 { 1 })PROG",
       Program().WithProbe(
           Probe({ "uprobe:zzzzzzz:bar" }, { ExprStatement(Integer(1)) })));

  test(bpftrace,
       R"PROG(uprobe:/$1/bash:readline { 1 })PROG",
       Program().WithProbe(Probe({ "uprobe:/foo/bash:readline" },
                                 { ExprStatement(Integer(1)) })));

  test(bpftrace,
       R"PROG(uprobe:$1:$2 { 1 })PROG",
       Program().WithProbe(
           Probe({ "uprobe:foo:bar" }, { ExprStatement(Integer(1)) })));

  test(bpftrace,
       R"PROG(uprobe:$2:$1 { 1 })PROG",
       Program().WithProbe(
           Probe({ "uprobe:bar:foo" }, { ExprStatement(Integer(1)) })));

  test(bpftrace,
       R"PROG(uprobe:"zz"$2"zz":"aa"$1 { 1 })PROG",
       Program().WithProbe(
           Probe({ "uprobe:zzbarzz:aafoo" }, { ExprStatement(Integer(1)) })));

  test(bpftrace,
       R"PROG(uprobe:$2:"aa"$1"aa" { 1 })PROG",
       Program().WithProbe(
           Probe({ "uprobe:bar:aafooaa" }, { ExprStatement(Integer(1)) })));

  test(bpftrace,
       R"PROG(uprobe:"$1":$2 { 1 })PROG",
       Program().WithProbe(
           Probe({ "uprobe:$1:bar" }, { ExprStatement(Integer(1)) })));

  test(bpftrace,
       R"PROG(uprobe:aa$1aa:$2 { 1 })PROG",
       Program().WithProbe(
           Probe({ "uprobe:aafooaa:bar" }, { ExprStatement(Integer(1)) })));

  test(bpftrace,
       R"PROG(uprobe:$1:$2func$4 { 1 })PROG",
       Program().WithProbe(
           Probe({ "uprobe:foo:barfunc" }, { ExprStatement(Integer(1)) })));

  test_parse_failure(bpftrace, R"(uprobe:/bin/bash:$0 { 1 })", R"(
stdin:1:1-20: ERROR: invalid trailing character for positional param: 0. Try quoting this entire part if this is intentional e.g. "$0".
uprobe:/bin/bash:$0 { 1 }
~~~~~~~~~~~~~~~~~~~
stdin:1:1-20: ERROR: No attach points for probe
uprobe:/bin/bash:$0 { 1 }
~~~~~~~~~~~~~~~~~~~
)");

  test_parse_failure(bpftrace, R"(uprobe:/bin/bash:$a { 1 })", R"(
stdin:1:1-20: ERROR: invalid trailing character for positional param: a. Try quoting this entire part if this is intentional e.g. "$a".
uprobe:/bin/bash:$a { 1 }
~~~~~~~~~~~~~~~~~~~
stdin:1:1-20: ERROR: No attach points for probe
uprobe:/bin/bash:$a { 1 }
~~~~~~~~~~~~~~~~~~~
)");

  test_parse_failure(bpftrace,
                     R"(uprobe:f:$999999999999999999999999 { 1 })",
                     R"(
stdin:1:1-35: ERROR: positional parameter is not valid: overflow error, maximum value is 18446744073709551615: 999999999999999999999999
uprobe:f:$999999999999999999999999 { 1 }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
stdin:1:1-35: ERROR: No attach points for probe
uprobe:f:$999999999999999999999999 { 1 }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, __comment)
{
  test("kprobe:f { /*** ***/0; }",
       Program().WithProbe(
           Probe({ "kprobe:f" }, { ExprStatement(Integer(0)) })));
}

TEST(Parser, map_assign)
{
  test("kprobe:sys_open { @x = 1; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { AssignScalarMapStatement(Map("@x"), Integer(1)) })));
  test("kprobe:sys_open { @x = @y; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { AssignScalarMapStatement(Map("@x"), Map("@y")) })));

  test("kprobe:sys_open { @x = arg0; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { AssignScalarMapStatement(Map("@x"), Builtin("arg0")) })));

  test("kprobe:sys_open { @x = count(); }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { AssignScalarMapStatement(Map("@x"), Call("count", {})) })));

  test("kprobe:sys_read { @x = sum(arg2); }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { AssignScalarMapStatement(
                     Map("@x"), Call("sum", { Builtin("arg2") })) })));
  test("kprobe:sys_read { @x = min(arg2); }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { AssignScalarMapStatement(
                     Map("@x"), Call("min", { Builtin("arg2") })) })));

  test("kprobe:sys_read { @x = max(arg2); }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { AssignScalarMapStatement(
                     Map("@x"), Call("max", { Builtin("arg2") })) })));

  test("kprobe:sys_read { @x = avg(arg2); }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { AssignScalarMapStatement(
                     Map("@x"), Call("avg", { Builtin("arg2") })) })));

  test("kprobe:sys_read { @x = stats(arg2); }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { AssignScalarMapStatement(
                     Map("@x"), Call("stats", { Builtin("arg2") })) })));

  test("kprobe:sys_open { @x = \"mystring\" }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { AssignScalarMapStatement(Map("@x"), String("mystring")) })));

  test("kprobe:sys_open { @x = $myvar; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { AssignScalarMapStatement(Map("@x"), Variable("$myvar")) })));
}

TEST(Parser, variable_assign)
{
  test("kprobe:sys_open { $x = 1; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { AssignVarStatement(Variable("$x"), Integer(1)) })));

  test("kprobe:sys_open { $x = -1; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { AssignVarStatement(Variable("$x"),
                                      Unop(Operator::MINUS, Integer(1))) })));

  char in_cstr[128];
  snprintf(in_cstr, sizeof(in_cstr), "kprobe:sys_open { $x = %ld; }", LONG_MIN);
  test(std::string(in_cstr),
       Program().WithProbe(Probe(
           { "kprobe:sys_open" },
           { AssignVarStatement(
               Variable("$x"),
               Unop(Operator::MINUS,
                    Integer(static_cast<unsigned long>(LONG_MAX) + 1))) })));
}

TEST(Parser, compound_variable_assignments)
{
  test("kprobe:f { $a = 0; $a <<= 1 }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignVarStatement(Variable("$a"), Integer(0)),
                   AssignVarStatement(
                       Variable("$a"),
                       Binop(Operator::LEFT, Variable("$a"), Integer(1))) })));

  test("kprobe:f { $a = 0; $a >>= 1 }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignVarStatement(Variable("$a"), Integer(0)),
                   AssignVarStatement(
                       Variable("$a"),
                       Binop(Operator::RIGHT, Variable("$a"), Integer(1))) })));

  test("kprobe:f { $a = 0; $a += 1 }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignVarStatement(Variable("$a"), Integer(0)),
                   AssignVarStatement(
                       Variable("$a"),
                       Binop(Operator::PLUS, Variable("$a"), Integer(1))) })));

  test("kprobe:f { $a = 0; $a -= 1 }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignVarStatement(Variable("$a"), Integer(0)),
                   AssignVarStatement(
                       Variable("$a"),
                       Binop(Operator::MINUS, Variable("$a"), Integer(1))) })));

  test("kprobe:f { $a = 0; $a *= 1 }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignVarStatement(Variable("$a"), Integer(0)),
                   AssignVarStatement(
                       Variable("$a"),
                       Binop(Operator::MUL, Variable("$a"), Integer(1))) })));

  test("kprobe:f { $a = 0; $a /= 1 }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignVarStatement(Variable("$a"), Integer(0)),
                   AssignVarStatement(
                       Variable("$a"),
                       Binop(Operator::DIV, Variable("$a"), Integer(1))) })));

  test("kprobe:f { $a = 0; $a %= 1 }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignVarStatement(Variable("$a"), Integer(0)),
                   AssignVarStatement(
                       Variable("$a"),
                       Binop(Operator::MOD, Variable("$a"), Integer(1))) })));

  test("kprobe:f { $a = 0; $a &= 1 }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignVarStatement(Variable("$a"), Integer(0)),
                   AssignVarStatement(
                       Variable("$a"),
                       Binop(Operator::BAND, Variable("$a"), Integer(1))) })));

  test("kprobe:f { $a = 0; $a |= 1 }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignVarStatement(Variable("$a"), Integer(0)),
                   AssignVarStatement(
                       Variable("$a"),
                       Binop(Operator::BOR, Variable("$a"), Integer(1))) })));

  test("kprobe:f { $a = 0; $a ^= 1 }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignVarStatement(Variable("$a"), Integer(0)),
                   AssignVarStatement(
                       Variable("$a"),
                       Binop(Operator::BXOR, Variable("$a"), Integer(1))) })));
}

TEST(Parser, compound_variable_assignment_binary_expr)
{
  test("kprobe:f { $a = 0; $a += 2 - 1 }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignVarStatement(Variable("$a"), Integer(0)),
             AssignVarStatement(
                 Variable("$a"),
                 Binop(Operator::PLUS,
                       Variable("$a"),
                       Binop(Operator::MINUS, Integer(2), Integer(1)))) })));
}

TEST(Parser, compound_map_assignments)
{
  test("kprobe:f { @a <<= 1 }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(
               Map("@a"), Binop(Operator::LEFT, Map("@a"), Integer(1))) })));

  test("kprobe:f { @a >>= 1 }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(
               Map("@a"), Binop(Operator::RIGHT, Map("@a"), Integer(1))) })));

  test("kprobe:f { @a += 1 }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(
               Map("@a"), Binop(Operator::PLUS, Map("@a"), Integer(1))) })));

  test("kprobe:f { @a -= 1 }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(
               Map("@a"), Binop(Operator::MINUS, Map("@a"), Integer(1))) })));

  test("kprobe:f { @a *= 1 }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(
               Map("@a"), Binop(Operator::MUL, Map("@a"), Integer(1))) })));

  test("kprobe:f { @a /= 1 }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(
               Map("@a"), Binop(Operator::DIV, Map("@a"), Integer(1))) })));

  test("kprobe:f { @a %= 1 }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(
               Map("@a"), Binop(Operator::MOD, Map("@a"), Integer(1))) })));

  test("kprobe:f { @a &= 1 }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(
               Map("@a"), Binop(Operator::BAND, Map("@a"), Integer(1))) })));

  test("kprobe:f { @a |= 1 }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(
               Map("@a"), Binop(Operator::BOR, Map("@a"), Integer(1))) })));

  test("kprobe:f { @a ^= 1 }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(
               Map("@a"), Binop(Operator::BXOR, Map("@a"), Integer(1))) })));
}

TEST(Parser, compound_map_assignment_binary_expr)
{
  test("kprobe:f { @a += 2 - 1 }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(
               Map("@a"),
               Binop(Operator::PLUS,
                     Map("@a"),
                     Binop(Operator::MINUS, Integer(2), Integer(1)))) })));
}

TEST(Parser, booleans)
{
  test("kprobe:do_nanosleep { $x = true; }",
       Program().WithProbe(
           Probe({ "kprobe:do_nanosleep" },
                 { AssignVarStatement(Variable("$x"), Boolean(true)) })));

  test("kprobe:do_nanosleep { $x = false; }",
       Program().WithProbe(
           Probe({ "kprobe:do_nanosleep" },
                 { AssignVarStatement(Variable("$x"), Boolean(false)) })));
}

TEST(Parser, map_key)
{
  test("kprobe:sys_open { @x[0] = 1; @x[0,1,2] = 1; }",
       Program().WithProbe(Probe(
           { "kprobe:sys_open" },
           { AssignMapStatement(Map("@x"), Integer(0), Integer(1)),
             AssignMapStatement(Map("@x"),
                                Tuple({ Integer(0), Integer(1), Integer(2) }),
                                Integer(1)) })));

  test("kprobe:sys_open { @x[(0,\"hi\",tid)] = 1; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { AssignMapStatement(
                     Map("@x"),
                     Tuple({ Integer(0), String("hi"), Builtin("tid") }),
                     Integer(1)) })));

  test("kprobe:sys_open { @x[@a] = 1; @x[@a,@b,@c] = 1; }",
       Program().WithProbe(Probe(
           { "kprobe:sys_open" },
           { AssignMapStatement(Map("@x"), Map("@a"), Integer(1)),
             AssignMapStatement(Map("@x"),
                                Tuple({ Map("@a"), Map("@b"), Map("@c") }),
                                Integer(1)) })));

  test("kprobe:sys_read { @x[pid] = 1; @x[tid,__builtin_uid,arg9] = 1; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { AssignMapStatement(Map("@x"), Builtin("pid"), Integer(1)),
                   AssignMapStatement(Map("@x"),
                                      Tuple({ Builtin("tid"),
                                              Builtin("__builtin_uid"),
                                              Builtin("arg9") }),
                                      Integer(1)) })));
}

TEST(Parser, predicate)
{
  test("kprobe:sys_open / @x / { 1; }",
       Program().WithProbe(Probe(
           { "kprobe:sys_open" }, Map("@x"), { ExprStatement(Integer(1)) })));
}

TEST(Parser, predicate_containing_division)
{
  test("kprobe:sys_open /100/25/ { 1; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 Binop(Operator::DIV, Integer(100), Integer(25)),
                 { ExprStatement(Integer(1)) })));
}

TEST(Parser, expressions)
{
  test(
      "kprobe:sys_open / 1 <= 2 && (9 - 4 != 5*10 || ~0) || __builtin_comm "
      "== "
      "\"string\" /\n"
      "{\n"
      "  1;\n"
      "}",
      Program().WithProbe(Probe(
          { "kprobe:sys_open" },
          Binop(
              Operator::LOR,
              Binop(Operator::LAND,
                    Binop(Operator::LE, Integer(1), Integer(2)),
                    Binop(Operator::LOR,
                          Binop(Operator::NE,
                                Binop(Operator::MINUS, Integer(9), Integer(4)),
                                Binop(Operator::MUL, Integer(5), Integer(10))),
                          Unop(Operator::BNOT, Integer(0)))),
              Binop(Operator::EQ, Builtin("__builtin_comm"), String("string"))),
          { ExprStatement(Integer(1)) })));
}

TEST(Parser, variable_post_increment_decrement)
{
  test("kprobe:sys_open { $x++; }",
       Program().WithProbe(Probe({ "kprobe:sys_open" },
                                 { ExprStatement(Unop(Operator::POST_INCREMENT,
                                                      Variable("$x"))) })));

  test("kprobe:sys_open { ++$x; }",
       Program().WithProbe(Probe({ "kprobe:sys_open" },
                                 { ExprStatement(Unop(Operator::PRE_INCREMENT,
                                                      Variable("$x"))) })));

  test("kprobe:sys_open { $x--; }",
       Program().WithProbe(Probe({ "kprobe:sys_open" },
                                 { ExprStatement(Unop(Operator::POST_DECREMENT,
                                                      Variable("$x"))) })));

  test("kprobe:sys_open { --$x; }",
       Program().WithProbe(Probe({ "kprobe:sys_open" },
                                 { ExprStatement(Unop(Operator::PRE_DECREMENT,
                                                      Variable("$x"))) })));
}

TEST(Parser, map_increment_decrement)
{
  test("kprobe:sys_open { @x++; }",
       Program().WithProbe(Probe({ "kprobe:sys_open" },
                                 { ExprStatement(Unop(Operator::POST_INCREMENT,
                                                      Map("@x"))) })));

  test("kprobe:sys_open { ++@x; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { ExprStatement(Unop(Operator::PRE_INCREMENT, Map("@x"))) })));

  test("kprobe:sys_open { @x--; }",
       Program().WithProbe(Probe({ "kprobe:sys_open" },
                                 { ExprStatement(Unop(Operator::POST_DECREMENT,
                                                      Map("@x"))) })));

  test("kprobe:sys_open { --@x; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { ExprStatement(Unop(Operator::PRE_DECREMENT, Map("@x"))) })));
}

TEST(Parser, bit_shifting)
{
  test("kprobe:do_nanosleep { @x = 1 << 10 }",
       Program().WithProbe(Probe(
           { "kprobe:do_nanosleep" },
           { AssignScalarMapStatement(
               Map("@x"), Binop(Operator::LEFT, Integer(1), Integer(10))) })));

  test("kprobe:do_nanosleep { @x = 1024 >> 9 }",
       Program().WithProbe(
           Probe({ "kprobe:do_nanosleep" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::RIGHT, Integer(1024), Integer(9))) })));

  test("kprobe:do_nanosleep / 2 < 1 >> 8 / { $x = 1 }",
       Program().WithProbe(
           Probe({ "kprobe:do_nanosleep" },
                 Binop(Operator::LT,
                       Integer(2),
                       Binop(Operator::RIGHT, Integer(1), Integer(8))),
                 { AssignVarStatement(Variable("$x"), Integer(1)) })));
}

TEST(Parser, ternary_int)
{
  test("kprobe:do_nanosleep { @x = pid < 10000 ? 1 : 2 }",
       Program().WithProbe(
           Probe({ "kprobe:do_nanosleep" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     If(Binop(Operator::LT, Builtin("pid"), Integer(10000)),
                        Integer(1),
                        Integer(2))) })));
}

TEST(Parser, if_block)
{
  test("kprobe:sys_open { if (pid > 10000) { printf(\"%d is high\\n\", pid); } "
       "}",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { ExprStatement(
                     If(Binop(Operator::GT, Builtin("pid"), Integer(10000)),
                        Block({ ExprStatement(Call("printf",
                                                   { String("%d is high\n"),
                                                     Builtin("pid") })) },
                              None()),
                        None())) })));
}

TEST(Parser, if_stmt_if)
{
  test("kprobe:sys_open { if (pid > 10000) { printf(\"%d is high\\n\", pid); } "
       "@pid = pid; if (pid < 1000) { printf(\"%d is low\\n\", pid); } }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { ExprStatement(
                       If(Binop(Operator::GT, Builtin("pid"), Integer(10000)),
                          Block({ ExprStatement(Call("printf",
                                                     { String("%d is high\n"),
                                                       Builtin("pid") })) },
                                None()),
                          None())),
                   AssignScalarMapStatement(Map("@pid"), Builtin("pid")),
                   ExprStatement(
                       If(Binop(Operator::LT, Builtin("pid"), Integer(1000)),
                          Block({ ExprStatement(Call("printf",
                                                     { String("%d is low\n"),
                                                       Builtin("pid") })) },
                                None()),
                          None())) })));
}

TEST(Parser, if_block_variable)
{
  test("kprobe:sys_open { if (pid > 10000) { $s = 10; } }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { ExprStatement(If(
                     Binop(Operator::GT, Builtin("pid"), Integer(10000)),
                     Block({ AssignVarStatement(Variable("$s"), Integer(10)) },
                           None()),
                     None())) })));
}

TEST(Parser, if_else)
{
  test("kprobe:sys_open { if (pid > 10000) { $s = \"a\"; } else { $s= \"b\"; } "
       "printf(\"%d is high\\n\", pid, $s); }",
       Program().WithProbe(Probe(
           { "kprobe:sys_open" },
           { ExprStatement(If(
                 Binop(Operator::GT, Builtin("pid"), Integer(10000)),
                 Block({ AssignVarStatement(Variable("$s"), String("a")) }),
                 Block({ AssignVarStatement(Variable("$s"), String("b")) }))),
             ExprStatement(Call("printf",
                                { String("%d is high\n"),
                                  Builtin("pid"),
                                  Variable("$s") })) })));
}

TEST(Parser, if_elseif)
{
  test("kprobe:f { if (pid > 10000) { $s = 10; } else if (pid < 10) { $s = 2; "
       "} }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { ExprStatement(
               If(Binop(Operator::GT, Builtin("pid"), Integer(10000)),
                  Block({ AssignVarStatement(Variable("$s"), Integer(10)) }),
                  If(Binop(Operator::LT, Builtin("pid"), Integer(10)),
                     { AssignVarStatement(Variable("$s"), Integer(2)) }))) })));
}

TEST(Parser, if_elseif_else)
{
  test("kprobe:f { if (pid > 10000) { $s = 10; } else if (pid < 10) { $s = 2; "
       "} else { $s = 1 } }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { ExprStatement(
               If(Binop(Operator::GT, Builtin("pid"), Integer(10000)),
                  Block({ AssignVarStatement(Variable("$s"), Integer(10)) }),
                  If(Binop(Operator::LT, Builtin("pid"), Integer(10)),
                     Block({ AssignVarStatement(Variable("$s"), Integer(2)) }),
                     Block({ AssignVarStatement(Variable("$s"),
                                                Integer(1)) })))) })));
}

TEST(Parser, if_elseif_elseif_else)
{
  test("kprobe:f { if (pid > 10000) { $s = 10; } else if (pid < 10) { $s = 2; "
       "} else if (pid > 999999) { $s = 0 } else { $s = 1 } }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { ExprStatement(If(
               Binop(Operator::GT, Builtin("pid"), Integer(10000)),
               Block({ AssignVarStatement(Variable("$s"), Integer(10)) }),
               If(Binop(Operator::LT, Builtin("pid"), Integer(10)),
                  Block({ AssignVarStatement(Variable("$s"), Integer(2)) }),
                  If(Binop(Operator::GT, Builtin("pid"), Integer(999999)),
                     Block({ AssignVarStatement(Variable("$s"), Integer(0)) }),
                     Block({ AssignVarStatement(Variable("$s"),
                                                Integer(1)) }))))) })));
}

TEST(Parser, unroll)
{
  test("kprobe:sys_open { $i = 0; unroll(5) { printf(\"i: %d\\n\", $i); $i = "
       "$i + 1; } }",
       Program().WithProbe(Probe(
           { "kprobe:sys_open" },
           { AssignVarStatement(Variable("$i"), Integer(0)),
             Unroll(Integer(5),
                    { ExprStatement(Call(
                          "printf", { String("i: %d\n"), Variable("$i") })),
                      AssignVarStatement(Variable("$i"),
                                         Binop(Operator::PLUS,
                                               Variable("$i"),
                                               Integer(1))) }) })));
}

TEST(Parser, ternary_str)
{
  test(R"(kprobe:sys_open { @x = pid < 10000 ? "lo" : "high" })",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     If(Binop(Operator::LT, Builtin("pid"), Integer(10000)),
                        String("lo"),
                        String("high"))) })));
}

TEST(Parser, ternary_nested)
{
  test("kprobe:do_nanosleep { @x = pid < 10000 ? pid < 5000 ? 1 : 2 : 3 }",
       Program().WithProbe(
           Probe({ "kprobe:do_nanosleep" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     If(Binop(Operator::LT, Builtin("pid"), Integer(10000)),
                        If(Binop(Operator::LT, Builtin("pid"), Integer(5000)),
                           Integer(1),
                           Integer(2)),
                        Integer(3))) })));
}

TEST(Parser, call)
{
  test("kprobe:sys_open { @x = count(); @y = hist(1,2,3); delete(@x); }",
       Program().WithProbe(
           Probe({ "kprobe:sys_open" },
                 { AssignScalarMapStatement(Map("@x"), Call("count", {})),
                   AssignScalarMapStatement(
                       Map("@y"),
                       Call("hist", { Integer(1), Integer(2), Integer(3) })),
                   ExprStatement(Call("delete", { Map("@x") })) })));
}

TEST(Parser, call_function)
{
  // builtin func
  test("kprobe:sys_open { ustack() }",
       Program().WithProbe(Probe({ "kprobe:sys_open" },
                                 { ExprStatement(Call("ustack", {})) })));

  // unknown func
  test("kprobe:sys_open { myfunc() }",
       Program().WithProbe(Probe({ "kprobe:sys_open" },
                                 { ExprStatement(Call("myfunc", {})) })));
}

TEST(Parser, call_kaddr)
{
  test("k:f { print(kaddr(\"avenrun\")); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call(
                     "print", { Call("kaddr", { String("avenrun") }) })) })));
}

TEST(Parser, multiple_probes)
{
  test("kprobe:sys_open { 1; } kretprobe:sys_open { 2; }",
       Program().WithProbes(
           { Probe({ "kprobe:sys_open" }, { ExprStatement(Integer(1)) }),
             Probe({ "kretprobe:sys_open" }, { ExprStatement(Integer(2)) }) }));
}

TEST(Parser, uprobe)
{
  test("uprobe:/my/program:func { 1; }",
       Program().WithProbe(Probe({ "uprobe:/my/program:func" },
                                 { ExprStatement(Integer(1)) })));
  test("uprobe:/my/go/program:\"pkg.func\u2C51\" { 1; }",
       Program().WithProbe(Probe({ "uprobe:/my/go/program:pkg.func\u2C51" },
                                 { ExprStatement(Integer(1)) })));
  test("uprobe:/with#hash:asdf { 1 }",
       Program().WithProbe(
           Probe({ "uprobe:/with#hash:asdf" }, { ExprStatement(Integer(1)) })));
  test("uprobe:/my/program:1234 { 1; }",
       Program().WithProbe(Probe({ "uprobe:/my/program:1234" },
                                 { ExprStatement(Integer(1)) })));
  // Trailing alnum chars are allowed (turns the entire arg into a symbol
  // name)
  test("uprobe:/my/program:1234abc { 1; }",
       Program().WithProbe(Probe({ "uprobe:/my/program:1234abc" },
                                 { ExprStatement(Integer(1)) })));
  // Test `:`s in quoted string
  test("uprobe:/my/program:\"A::f\" { 1; }",
       Program().WithProbe(Probe({ "uprobe:/my/program:A::f" },
                                 { ExprStatement(Integer(1)) })));

  // Language prefix
  test("uprobe:/my/program:cpp:func { 1; }",
       Program().WithProbe(Probe({ "uprobe:/my/program:cpp:func" },
                                 { ExprStatement(Integer(1)) })));

  test("uprobe:/my/dir+/program:1234abc { 1; }",
       Program().WithProbe(Probe({ "uprobe:/my/dir+/program:1234abc" },
                                 { ExprStatement(Integer(1)) })));

  test_parse_failure("uprobe:f { 1 }", R"(
stdin:1:1-9: ERROR: uprobe probe type requires 2 or 3 arguments, found 1
uprobe:f { 1 }
~~~~~~~~
)");

  test_parse_failure("uprobe { 1 }", R"(
stdin:1:1-7: ERROR: uprobe probe type requires 2 or 3 arguments, found 0
uprobe { 1 }
~~~~~~
)");

  test_parse_failure("uprobe:/my/program*:0x1234 { 1 }", R"(
stdin:1:1-27: ERROR: Cannot use wildcards with absolute address
uprobe:/my/program*:0x1234 { 1 }
~~~~~~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, usdt)
{
  test("usdt:/my/program:probe { 1; }",
       Program().WithProbe(
           Probe({ "usdt:/my/program:probe" }, { ExprStatement(Integer(1)) })));

  // Without the escapes needed for C++ to compile:
  //    usdt:/my/program:"\"probe\"" { 1; }
  //
  test(R"(usdt:/my/program:"\"probe\"" { 1; })",
       Program().WithProbe(Probe({ "usdt:/my/program:\"probe\"" },
                                 { ExprStatement(Integer(1)) })));

  test_parse_failure("usdt { 1 }", R"(
stdin:1:1-5: ERROR: usdt probe type requires 2 or 3 arguments, found 0
usdt { 1 }
~~~~
)");
}

TEST(Parser, usdt_namespaced_probe)
{
  test("usdt:/my/program:namespace:probe { 1; }",
       Program().WithProbe(Probe({ "usdt:/my/program:namespace:probe" },
                                 { ExprStatement(Integer(1)) })));
  test("usdt:/my/program*:namespace:probe { 1; }",
       Program().WithProbe(Probe({ "usdt:/my/program*:namespace:probe" },
                                 { ExprStatement(Integer(1)) })));
  test("usdt:/my/*program:namespace:probe { 1; }",
       Program().WithProbe(Probe({ "usdt:/my/*program:namespace:probe" },
                                 { ExprStatement(Integer(1)) })));
  test("usdt:*my/program*:namespace:probe { 1; }",
       Program().WithProbe(Probe({ "usdt:*my/program*:namespace:probe" },
                                 { ExprStatement(Integer(1)) })));
}

TEST(Parser, escape_chars)
{
  test("kprobe:sys_open { \"newline\\nand "
       "tab\\tcr\\rbackslash\\\\quote\\\"here oct\\1009hex\\x309\" }",
       Program().WithProbe(Probe(
           { "kprobe:sys_open" },
           { ExprStatement(String(
               "newline\nand tab\tcr\rbackslash\\quote\"here oct@9hex09")) })));
}

TEST(Parser, begin_probe)
{
  test("begin { 1 }",
       Program().WithProbe(Probe({ "begin" }, { ExprStatement(Integer(1)) })));

  test_parse_failure("begin:f { 1 }", R"(
stdin:1:1-8: ERROR: begin probe type requires 0 arguments, found 1
begin:f { 1 }
~~~~~~~
)");

  test_parse_failure("begin:path:f { 1 }", R"(
stdin:1:1-13: ERROR: begin probe type requires 0 arguments, found 2
begin:path:f { 1 }
~~~~~~~~~~~~
)");
}

TEST(Parser, end_probe)
{
  test("end { 1 }",
       Program().WithProbe(Probe({ "end" }, { ExprStatement(Integer(1)) })));

  test_parse_failure("end:f { 1 }", R"(
stdin:1:1-6: ERROR: end probe type requires 0 arguments, found 1
end:f { 1 }
~~~~~
)");

  test_parse_failure("end:path:f { 1 }", R"(
stdin:1:1-11: ERROR: end probe type requires 0 arguments, found 2
end:path:f { 1 }
~~~~~~~~~~
)");
}

TEST(Parser, bench_probe)
{
  test("bench:a { 1 }",
       Program().WithProbe(
           Probe({ "bench:a" }, { ExprStatement(Integer(1)) })));

  test_parse_failure("bench{ 1 }", R"(
stdin:1:1-6: ERROR: bench probe type requires 1 arguments, found 0
bench{ 1 }
~~~~~
)");

  test_parse_failure("bench:a:f { 1 }", R"(
stdin:1:1-10: ERROR: bench probe type requires 1 arguments, found 2
bench:a:f { 1 }
~~~~~~~~~
)");
}

TEST(Parser, tracepoint_probe)
{
  test("tracepoint:sched:sched_switch { 1 }",
       Program().WithProbe(Probe({ "tracepoint:sched:sched_switch" },
                                 { ExprStatement(Integer(1)) })));
  test("tracepoint:* { 1 }",
       Program().WithProbe(
           Probe({ "tracepoint:*:*" }, { ExprStatement(Integer(1)) })));

  test_parse_failure("tracepoint:f { 1 }", R"(
stdin:1:1-13: ERROR: tracepoint probe type requires 2 arguments, found 1
tracepoint:f { 1 }
~~~~~~~~~~~~
)");

  test_parse_failure("tracepoint { 1 }", R"(
stdin:1:1-11: ERROR: tracepoint probe type requires 2 arguments, found 0
tracepoint { 1 }
~~~~~~~~~~
)");
}

TEST(Parser, rawtracepoint_probe)
{
  test("rawtracepoint:sched:sched_switch { 1 }",
       Program().WithProbe(Probe({ "rawtracepoint:sched:sched_switch" },
                                 { ExprStatement(Integer(1)) })));
  test("rawtracepoint:* { 1 }",
       Program().WithProbe(
           Probe({ "rawtracepoint:*:*" }, { ExprStatement(Integer(1)) })));
  test("rawtracepoint:f { 1 }",
       Program().WithProbe(
           Probe({ "rawtracepoint:*:f" }, { ExprStatement(Integer(1)) })));

  test_parse_failure("rawtracepoint { 1 }", R"(
stdin:1:1-14: ERROR: rawtracepoint probe type requires 2 or 1 arguments, found 0
rawtracepoint { 1 }
~~~~~~~~~~~~~
)");
}

TEST(Parser, profile_probe)
{
  test("profile:ms:997 { 1 }",
       Program().WithProbe(
           Probe({ "profile:ms:997" }, { ExprStatement(Integer(1)) })));

  test("profile:1us { 1 }",
       Program().WithProbe(
           Probe({ "profile:us:1" }, { ExprStatement(Integer(1)) })));

  test("profile:5m { 1 }",
       Program().WithProbe(
           Probe({ "profile:us:300000000" }, { ExprStatement(Integer(1)) })));

  test_parse_failure("profile:ms:nan { 1 }", R"(
stdin:1:1-15: ERROR: Invalid rate of profile probe: invalid integer: nan
profile:ms:nan { 1 }
~~~~~~~~~~~~~~
)");

  test_parse_failure("profile:10 { 1 }", R"(
stdin:1:1-11: ERROR: Invalid rate of profile probe. Minimum is 1000 or 1us. Found: 10 nanoseconds
profile:10 { 1 }
~~~~~~~~~~
)");

  test_parse_failure("profile { 1 }", R"(
stdin:1:1-8: ERROR: profile probe type requires 1 or 2 arguments, found 0
profile { 1 }
~~~~~~~
)");

  test_parse_failure("profile:s:1b { 1 }", R"(
stdin:1:1-13: ERROR: Invalid rate of profile probe: invalid trailing bytes: 1b
profile:s:1b { 1 }
~~~~~~~~~~~~
)");
}

TEST(Parser, interval_probe)
{
  test("interval:s:1 { 1 }",
       Program().WithProbe(
           Probe({ "interval:s:1" }, { ExprStatement(Integer(1)) })));

  test("interval:s:1e3 { 1 }",
       Program().WithProbe(
           Probe({ "interval:s:1000" }, { ExprStatement(Integer(1)) })));

  test("interval:s:1_0_0_0 { 1 }",
       Program().WithProbe(
           Probe({ "interval:s:1000" }, { ExprStatement(Integer(1)) })));

  test("interval:1us { 1 }",
       Program().WithProbe(
           Probe({ "interval:us:1" }, { ExprStatement(Integer(1)) })));

  test("interval:5m { 1 }",
       Program().WithProbe(
           Probe({ "interval:us:300000000" }, { ExprStatement(Integer(1)) })));

  test_parse_failure("interval:s:1b { 1 }", R"(
stdin:1:1-14: ERROR: Invalid rate of interval probe: invalid trailing bytes: 1b
interval:s:1b { 1 }
~~~~~~~~~~~~~
)");

  test_parse_failure("interval:100 { 1 }", R"(
stdin:1:1-13: ERROR: Invalid rate of interval probe. Minimum is 1000 or 1us. Found: 100 nanoseconds
interval:100 { 1 }
~~~~~~~~~~~~
)");

  test_parse_failure("interval { 1 }", R"(
stdin:1:1-9: ERROR: interval probe type requires 1 or 2 arguments, found 0
interval { 1 }
~~~~~~~~
)");
}

TEST(Parser, software_probe)
{
  test("software:faults:1000 { 1 }",
       Program().WithProbe(
           Probe({ "software:faults:1000" }, { ExprStatement(Integer(1)) })));

  test("software:faults:1e3 { 1 }",
       Program().WithProbe(
           Probe({ "software:faults:1000" }, { ExprStatement(Integer(1)) })));

  test("software:faults:1_000 { 1 }",
       Program().WithProbe(
           Probe({ "software:faults:1000" }, { ExprStatement(Integer(1)) })));

  test_parse_failure("software:faults:1b { 1 }", R"(
stdin:1:1-19: ERROR: Invalid count for software probe: invalid trailing bytes: 1b
software:faults:1b { 1 }
~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, hardware_probe)
{
  test("hardware:cache-references:1000000 { 1 }",
       Program().WithProbe(Probe({ "hardware:cache-references:1000000" },
                                 { ExprStatement(Integer(1)) })));

  test("hardware:cache-references:1e6 { 1 }",
       Program().WithProbe(Probe({ "hardware:cache-references:1000000" },
                                 { ExprStatement(Integer(1)) })));

  test("hardware:cache-references:1_000_000 { 1 }",
       Program().WithProbe(Probe({ "hardware:cache-references:1000000" },
                                 { ExprStatement(Integer(1)) })));

  test_parse_failure("hardware:cache-references:1b { 1 }", R"(
stdin:1:1-29: ERROR: Invalid count for hardware probe: invalid trailing bytes: 1b
hardware:cache-references:1b { 1 }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, watchpoint_probe)
{
  test("watchpoint:1234:8:w { 1 }",
       Program().WithProbe(
           Probe({ "watchpoint:1234:8:w" }, { ExprStatement(Integer(1)) })));

  test_parse_failure("watchpoint:1b:8:w { 1 }", R"(
stdin:1:1-18: ERROR: Invalid function/address argument: invalid trailing bytes: 1b
watchpoint:1b:8:w { 1 }
~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("watchpoint:1:8a:w { 1 }", R"(
stdin:1:1-18: ERROR: Invalid length argument: invalid trailing bytes: 8a
watchpoint:1:8a:w { 1 }
~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("watchpoint:1b:8a:w { 1 }", R"(
stdin:1:1-19: ERROR: Invalid function/address argument: invalid trailing bytes: 1b
watchpoint:1b:8a:w { 1 }
~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, multiple_attach_points_kprobe)
{
  test("begin,kprobe:sys_open,uprobe:/bin/"
       "sh:foo,tracepoint:syscalls:sys_enter_* { 1 }",
       Program().WithProbe(Probe({ "begin",
                                   "kprobe:sys_open",
                                   "uprobe:/bin/sh:foo",
                                   "tracepoint:syscalls:sys_enter_*" },
                                 { ExprStatement(Integer(1)) })));
}

TEST(Parser, character_class_attach_point)
{
  test("kprobe:[Ss]y[Ss]_read { 1 }",
       Program().WithProbe(
           Probe({ "kprobe:[Ss]y[Ss]_read" }, { ExprStatement(Integer(1)) })));
}

TEST(Parser, wildcard_probetype)
{
  test("t*point:sched:sched_switch { 1; }",
       Program().WithProbe(Probe({ "tracepoint:sched:sched_switch" },
                                 { ExprStatement(Integer(1)) })));

  test("*ware:* { 1; }",
       Program().WithProbe(Probe({ "hardware:*", "software:*" },
                                 { ExprStatement(Integer(1)) })));

  test("*:/bin/sh:* { 1; }",
       Program().WithProbe(Probe({ "uprobe:/bin/sh:*", "usdt:/bin/sh:*" },
                                 { ExprStatement(Integer(1)) })));
}

TEST(Parser, wildcard_attach_points)
{
  test("kprobe:sys_* { 1 }",
       Program().WithProbe(
           Probe({ "kprobe:sys_*" }, { ExprStatement(Integer(1)) })));

  test("kprobe:*blah { 1 }",
       Program().WithProbe(
           Probe({ "kprobe:*blah" }, { ExprStatement(Integer(1)) })));

  test("kprobe:sys*blah { 1 }",
       Program().WithProbe(
           Probe({ "kprobe:sys*blah" }, { ExprStatement(Integer(1)) })));

  test("kprobe:* { 1 }",
       Program().WithProbe(
           Probe({ "kprobe:*" }, { ExprStatement(Integer(1)) })));

  test("kprobe:sys_* { @x = __builtin_cpu*__builtin_retval }",
       Program().WithProbe(Probe(
           { "kprobe:sys_*" },
           { AssignScalarMapStatement(Map("@x"),
                                      Binop(Operator::MUL,
                                            Builtin("__builtin_cpu"),
                                            Builtin("__builtin_retval"))) })));

  test("kprobe:sys_* { @x = *arg0 }",
       Program().WithProbe(
           Probe({ "kprobe:sys_*" },
                 { AssignScalarMapStatement(
                     Map("@x"), Unop(Operator::MUL, Builtin("arg0"))) })));
}

TEST(Parser, wildcard_path)
{
  test("uprobe:/my/program*:* { 1; }",
       Program().WithProbe(
           Probe({ "uprobe:/my/program*:*" }, { ExprStatement(Integer(1)) })));

  test("uprobe:/my/program*:func { 1; }",
       Program().WithProbe(Probe({ "uprobe:/my/program*:func" },
                                 { ExprStatement(Integer(1)) })));

  test("uprobe:*my/program*:func { 1; }",
       Program().WithProbe(Probe({ "uprobe:*my/program*:func" },
                                 { ExprStatement(Integer(1)) })));

  test("uprobe:/my/program*foo:func { 1; }",
       Program().WithProbe(Probe({ "uprobe:/my/program*foo:func" },
                                 { ExprStatement(Integer(1)) })));

  test("usdt:/my/program*:* { 1; }",
       Program().WithProbe(
           Probe({ "usdt:/my/program*:*" }, { ExprStatement(Integer(1)) })));

  test("usdt:/my/program*:func { 1; }",
       Program().WithProbe(
           Probe({ "usdt:/my/program*:func" }, { ExprStatement(Integer(1)) })));

  test("usdt:*my/program*:func { 1; }",
       Program().WithProbe(
           Probe({ "usdt:*my/program*:func" }, { ExprStatement(Integer(1)) })));

  test("usdt:/my/program*foo:func { 1; }",
       Program().WithProbe(Probe({ "usdt:/my/program*foo:func" },
                                 { ExprStatement(Integer(1)) })));

  // Make sure calls or builtins don't cause issues
  test("usdt:/my/program*avg:func { 1; }",
       Program().WithProbe(Probe({ "usdt:/my/program*avg:func" },
                                 { ExprStatement(Integer(1)) })));

  test("usdt:/my/program*nsecs:func { 1; }",
       Program().WithProbe(Probe({ "usdt:/my/program*nsecs:func" },
                                 { ExprStatement(Integer(1)) })));
}

TEST(Parser, dot_in_func)
{
  test("uprobe:/my/go/program:runtime.main.func1 { 1; }",
       Program().WithProbe(Probe({ "uprobe:/my/go/program:runtime.main.func1" },
                                 { ExprStatement(Integer(1)) })));
}

TEST(Parser, wildcard_func)
{
  test("usdt:/my/program:abc*cd { 1; }",
       Program().WithProbe(Probe({ "usdt:/my/program:abc*cd" },
                                 { ExprStatement(Integer(1)) })));

  test("usdt:/my/program:abc*c*d { 1; }",
       Program().WithProbe(Probe({ "usdt:/my/program:abc*c*d" },
                                 { ExprStatement(Integer(1)) })));

  std::string keywords[] = {
    "arg0",
    "args",
    "__builtin_curtask",
    "errorf",
    "warnf",
    "func",
    "__builtin_gid"
    "__builtin_rand",
    "uid",
    "avg",
    "cat",
    "exit",
    "kaddr",
    "min",
    "printf",
    "usym",
    "kstack",
    "ustack",
    "bpftrace",
    "perf",
    "raw",
    "uprobe",
    "kprobe",
  };
  for (auto kw : keywords) {
    test("usdt:/my/program:" + kw + "*c*d { 1; }",
         Program().WithProbe(Probe({ "usdt:/my/program:" + kw + "*c*d" },
                                   { ExprStatement(Integer(1)) })));
    test("usdt:/my/program:abc*" + kw + "*c*d { 1; }",
         Program().WithProbe(Probe({ "usdt:/my/program:abc*" + kw + "*c*d" },
                                   { ExprStatement(Integer(1)) })));
  }
}

TEST(Parser, short_map_name)
{
  test("kprobe:sys_read { @ = 1 }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { AssignScalarMapStatement(Map("@"), Integer(1)) })));
}

TEST(Parser, include)
{
  test("#include <stdio.h>\nkprobe:sys_read { @x = 1 }",
       Program()
           .WithCStatements({ CStatement("#include <stdio.h>") })
           .WithProbe(
               Probe({ "kprobe:sys_read" },
                     { AssignScalarMapStatement(Map("@x"), Integer(1)) })));
}

TEST(Parser, include_quote)
{
  test("#include \"stdio.h\"\nkprobe:sys_read { @x = 1 }",
       Program()
           .WithCStatements({ CStatement("#include \"stdio.h\"") })
           .WithProbe(
               Probe({ "kprobe:sys_read" },
                     { AssignScalarMapStatement(Map("@x"), Integer(1)) })));
}

TEST(Parser, include_multiple)
{
  test("#include <stdio.h>\n#include \"blah\"\n#include "
       "<foo.h>\nkprobe:sys_read { @x = 1 }",
       Program()
           .WithCStatements({ CStatement("#include <stdio.h>"),
                              CStatement("#include \"blah\""),
                              CStatement("#include <foo.h>") })
           .WithProbe(
               Probe({ "kprobe:sys_read" },
                     { AssignScalarMapStatement(Map("@x"), Integer(1)) })));
}

TEST(Parser, brackets)
{
  test("kprobe:sys_read { (arg0*arg1) }",
       Program().WithProbe(Probe({ "kprobe:sys_read" },
                                 { ExprStatement(Binop(Operator::MUL,
                                                       Builtin("arg0"),
                                                       Builtin("arg1"))) })));
}

TEST(Parser, cast_simple_type)
{
  test("kprobe:sys_read { (int32)arg0; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Cast(Typeof(SizedType(Type::integer)),
                                      Builtin("arg0"))) })));
}

TEST(Parser, cast_simple_type_pointer)
{
  test("kprobe:sys_read { (int32 *)arg0; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Cast(Typeof(SizedType(Type::pointer)),
                                      Builtin("arg0"))) })));
}

TEST(Parser, cast_sized_type)
{
  test("kprobe:sys_read { (string)arg0; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Cast(Typeof(SizedType(Type::string)),
                                      Builtin("arg0"))) })));
}

TEST(Parser, cast_sized_type_pointer)
{
  test("kprobe:sys_read { (string *)arg0; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Cast(Typeof(SizedType(Type::pointer)),
                                      Builtin("arg0"))) })));
}

TEST(Parser, cast_sized_type_pointer_with_size)
{
  test("kprobe:sys_read { (inet[1] *)arg0; }",
       Program().WithProbe(Probe(
           { "kprobe:sys_read" },
           { ExprStatement(Cast(Typeof(SizedType(Type::pointer)
                                           .WithElement(SizedType(Type::inet))),
                                Builtin("arg0"))) })));
}

TEST(Parser, cast_struct)
{
  test("kprobe:sys_read { (struct mytype)arg0; }",
       Program().WithProbe(Probe(
           { "kprobe:sys_read" },
           { ExprStatement(
               Cast(Typeof(SizedType(Type::c_struct).WithName("struct mytype")),
                    Builtin("arg0"))) })));
  test("kprobe:sys_read { (union mytype)arg0; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Cast(
                     Typeof(SizedType(Type::c_struct).WithName("union mytype")),
                     Builtin("arg0"))) })));
}

TEST(Parser, cast_struct_ptr)
{
  test("kprobe:sys_read { (struct mytype*)arg0; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Cast(Typeof(SizedType(Type::pointer)),
                                      Builtin("arg0"))) })));
  test("kprobe:sys_read { (union mytype*)arg0; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Cast(Typeof(SizedType(Type::pointer)),
                                      Builtin("arg0"))) })));
}

TEST(Parser, cast_typedef)
{
  test("kprobe:sys_read { (mytype)arg0; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(
                     Cast(Typeof(SizedType(Type::c_struct).WithName("mytype")),
                          Builtin("arg0"))) })));
}

TEST(Parser, cast_ptr_typedef)
{
  test("kprobe:sys_read { (mytype*)arg0; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Cast(Typeof(SizedType(Type::pointer)),
                                      Builtin("arg0"))) })));
}

TEST(Parser, cast_multiple_pointer)
{
  test("kprobe:sys_read { (int32 *****)arg0; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Cast(Typeof(SizedType(Type::pointer)),
                                      Builtin("arg0"))) })));
}

TEST(Parser, cast_or_expr1)
{
  test("kprobe:sys_read { (struct mytype)*arg0; }",
       Program().WithProbe(Probe(
           { "kprobe:sys_read" },
           { ExprStatement(
               Cast(Typeof(SizedType(Type::c_struct).WithName("struct mytype")),
                    Unop(Operator::MUL, Builtin("arg0")))) })));
}

TEST(Parser, cast_or_expr2)
{
  test("kprobe:sys_read { (arg1)*arg0; }",
       Program().WithProbe(Probe({ "kprobe:sys_read" },
                                 { ExprStatement(Binop(Operator::MUL,
                                                       Builtin("arg1"),
                                                       Builtin("arg0"))) })));
}

TEST(Parser, cast_precedence)
{
  test("kprobe:sys_read { (struct mytype)arg0.field; }",
       Program().WithProbe(Probe(
           { "kprobe:sys_read" },
           { ExprStatement(
               Cast(Typeof(SizedType(Type::c_struct).WithName("struct mytype")),
                    FieldAccess("field", Builtin("arg0")))) })));

  test("kprobe:sys_read { (struct mytype*)arg0->field; }",
       Program().WithProbe(Probe(
           { "kprobe:sys_read" },
           { ExprStatement(Cast(Typeof(SizedType(Type::pointer)),
                                FieldAccess("field", Builtin("arg0")))) })));

  test("kprobe:sys_read { (struct mytype)arg0+123; }",
       Program().WithProbe(Probe(
           { "kprobe:sys_read" },
           { ExprStatement(Binop(
               Operator::PLUS,
               Cast(Typeof(SizedType(Type::c_struct).WithName("struct mytype")),
                    Builtin("arg0")),
               Integer(123))) })));
}

TEST(Parser, cast_enum)
{
  test("enum Foo { ONE = 1 } kprobe:sys_read { (enum Foo)1; }",
       Program()
           .WithCStatements({ CStatement("enum Foo { ONE = 1 };") })
           .WithProbe(
               Probe({ "kprobe:sys_read" },
                     { ExprStatement(
                         Cast(Typeof(SizedType(Type::integer).WithName("Foo")),
                              Integer(1))) })));
}

TEST(Parser, sizeof_expression)
{
  test("kprobe:sys_read { sizeof(arg0); }",
       Program().WithProbe(Probe({ "kprobe:sys_read" },
                                 { ExprStatement(Sizeof(Builtin("arg0"))) })));
}

TEST(Parser, sizeof_type)
{
  test("kprobe:sys_read { sizeof(int32); }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Sizeof(SizedType(Type::integer))) })));
}

TEST(Parser, offsetof_type)
{
  test("struct Foo { int x; } begin { offsetof(struct Foo, x); }",
       Program()
           .WithCStatements({ CStatement("struct Foo { int x; };") })
           .WithProbe(
               Probe({ "begin" },
                     { ExprStatement(Offsetof(
                         SizedType(Type::c_struct).WithName("struct Foo"),
                         { "x" })) })));
  test("struct Foo { struct Bar { int x; } bar; } "
       "begin { offsetof(struct Foo, bar.x); }",
       Program()
           .WithCStatements(
               { CStatement("struct Foo { struct Bar { int x; } bar; };") })
           .WithProbe(
               Probe({ "begin" },
                     { ExprStatement(Offsetof(
                         SizedType(Type::c_struct).WithName("struct Foo"),
                         { "bar", "x" })) })));
  test_parse_failure("struct Foo { struct Bar { int x; } *bar; } "
                     "begin { offsetof(struct Foo, bar->x); }",
                     R"(
stdin:1:76-78: ERROR: syntax error, unexpected ->, expecting ) or .
struct Foo { struct Bar { int x; } *bar; } begin { offsetof(struct Foo, bar->x); }
                                                                           ~~
)");
}

TEST(Parser, offsetof_expression)
{
  test("struct Foo { int x; }; "
       "begin { $foo = (struct Foo *)0; offsetof(*$foo, x); }",
       Program()
           .WithCStatements({ CStatement("struct Foo { int x; };") })
           .WithProbe(Probe(
               { "begin" },
               { AssignVarStatement(Variable("$foo"),
                                    Cast(Typeof(SizedType(Type::pointer)),
                                         Integer(0))),
                 ExprStatement(Offsetof(Unop(Operator::MUL, Variable("$foo")),
                                        { "x" })) })));
}

TEST(Parser, offsetof_builtin_type)
{
  test("struct Foo { timestamp x; } begin { offsetof(struct Foo, timestamp); "
       "}",
       Program()
           .WithCStatements({ CStatement("struct Foo { timestamp x; };") })
           .WithProbe(
               Probe({ "begin" },
                     { ExprStatement(Offsetof(
                         SizedType(Type::c_struct).WithName("struct Foo"),
                         { "timestamp" })) })));
}

TEST(Parser, dereference_precedence)
{
  test("kprobe:sys_read { *@x+1 }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Binop(Operator::PLUS,
                                       Unop(Operator::MUL, Map("@x")),
                                       Integer(1))) })));

  test("kprobe:sys_read { *@x**@y }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Binop(Operator::MUL,
                                       Unop(Operator::MUL, Map("@x")),
                                       Unop(Operator::MUL, Map("@y")))) })));

  test("kprobe:sys_read { *@x*@y }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Binop(Operator::MUL,
                                       Unop(Operator::MUL, Map("@x")),
                                       Map("@y"))) })));

  test("kprobe:sys_read { *@x.myfield }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(Unop(Operator::MUL,
                                      FieldAccess("myfield", Map("@x")))) })));
}

TEST(Parser, field_access)
{
  test("kprobe:sys_read { @x.myfield; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(FieldAccess("myfield", Map("@x"))) })));

  test("kprobe:sys_read { @x->myfield; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(FieldAccess("myfield", Map("@x"))) })));
}

TEST(Parser, field_access_builtin)
{
  test("kprobe:sys_read { @x.count; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(FieldAccess("count", Map("@x"))) })));

  test("kprobe:sys_read { @x->count; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(FieldAccess("count", Map("@x"))) })));
}

TEST(Parser, field_access_builtin_type)
{
  test("kprobe:sys_read { @x.timestamp; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(FieldAccess("timestamp", Map("@x"))) })));

  test("kprobe:sys_read { @x->timestamp; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(FieldAccess("timestamp", Map("@x"))) })));
}

TEST(Parser, field_access_sized_type)
{
  test("kprobe:sys_read { @x.buffer; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(FieldAccess("buffer", Map("@x"))) })));

  test("kprobe:sys_read { @x->string; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(FieldAccess("string", Map("@x"))) })));
}

TEST(Parser, array_access)
{
  test("kprobe:sys_read { x[index]; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { ExprStatement(
                     ArrayAccess(Identifier("x"), Identifier("index"))) })));

  test("kprobe:sys_read { $val = x[index]; }",
       Program().WithProbe(
           Probe({ "kprobe:sys_read" },
                 { AssignVarStatement(Variable("$val"),
                                      ArrayAccess(Identifier("x"),
                                                  Identifier("index"))) })));
}

TEST(Parser, cstruct)
{
  test("struct Foo { int x, y; char *str; } kprobe:sys_read { 1; }",
       Program()
           .WithCStatements(
               { CStatement("struct Foo { int x, y; char *str; };") })
           .WithProbe(
               Probe({ "kprobe:sys_read" }, { ExprStatement(Integer(1)) })));
}

TEST(Parser, cstruct_semicolon)
{
  test("struct Foo { int x, y; char *str; }; kprobe:sys_read { 1; }",
       Program()
           .WithCStatements(
               { CStatement("struct Foo { int x, y; char *str; };") })
           .WithProbe(
               Probe({ "kprobe:sys_read" }, { ExprStatement(Integer(1)) })));
}

TEST(Parser, cstruct_nested)
{
  test("struct Foo { struct { int x; } bar; } kprobe:sys_read { 1; }",
       Program()
           .WithCStatements(
               { CStatement("struct Foo { struct { int x; } bar; };") })
           .WithProbe(
               Probe({ "kprobe:sys_read" }, { ExprStatement(Integer(1)) })));
}

TEST(Parser, unexpected_symbol)
{
  std::stringstream out;
  ast::ASTContext ast("stdin", "i:s:1 { < }");
  Driver driver(ast);
  ast.root = driver.parse_program();
  ASSERT_FALSE(ast.diagnostics().ok());
  ast.diagnostics().emit(out);
  std::string expected =
      R"(stdin:1:9-10: ERROR: syntax error, unexpected <
i:s:1 { < }
        ~
)";
  EXPECT_EQ(out.str(), expected);
}

TEST(Parser, string_with_tab)
{
  std::stringstream out;
  ast::ASTContext ast("stdin", "i:s:1\t\t\t$a");
  Driver driver(ast);
  ast.root = driver.parse_program();
  ASSERT_FALSE(ast.diagnostics().ok());
  ast.diagnostics().emit(out);
  std::string expected =
      R"(stdin:1:9-11: ERROR: syntax error, unexpected variable, expecting {
i:s:1            $a
                 ~~
)";
  EXPECT_EQ(out.str(), expected);
}

TEST(Parser, unterminated_string)
{
  std::stringstream out;
  ast::ASTContext ast("stdin", "kprobe:f { \"asdf }");
  Driver driver(ast);
  ast.root = driver.parse_program();
  ASSERT_FALSE(ast.diagnostics().ok());
  ast.diagnostics().emit(out);
  std::string expected =
      R"(stdin:1:13-19: ERROR: unterminated string
kprobe:f { "asdf }
            ~~~~~~
stdin:1:13-19: ERROR: syntax error, unexpected end of file
kprobe:f { "asdf }
            ~~~~~~
)";
  EXPECT_EQ(out.str(), expected);
}

TEST(Parser, kprobe_offset)
{
  test("k:fn+1 {}", Program().WithProbe(Probe({ "kprobe:fn+1" }, {})));
  test("k:fn+0x10 {}", Program().WithProbe(Probe({ "kprobe:fn+16" }, {})));

  test("k:\"fn.abc\"+1 {}",
       Program().WithProbe(Probe({ "kprobe:fn.abc+1" }, {})));
  test("k:\"fn.abc\"+0x10 {}",
       Program().WithProbe(Probe({ "kprobe:fn.abc+16" }, {})));

  test_parse_failure("k:asdf+123abc", R"(
stdin:1:2-14: ERROR: syntax error, unexpected end of file, expecting {
k:asdf+123abc
 ~~~~~~~~~~~~
)");
}

TEST(Parser, kretprobe_offset)
{
  // Not supported yet
  test_parse_failure("kr:fn+1 { 1 }", R"(
stdin:1:1-8: ERROR: Offset not allowed
kr:fn+1 { 1 }
~~~~~~~
)");
}

TEST(Parser, uprobe_offset)
{
  test("u:./test:fn+1 {}",
       Program().WithProbe(Probe({ "uprobe:./test:fn+1" }, {})));
  test("u:./test:fn+0x10 {}",
       Program().WithProbe(Probe({ "uprobe:./test:fn+16" }, {})));

  test("u:./test:\"fn.abc\"+1 {}",
       Program().WithProbe(Probe({ "uprobe:./test:fn.abc+1" }, {})));
  test("u:./test:\"fn.abc\"+0x10 {}",
       Program().WithProbe(Probe({ "uprobe:./test:fn.abc+16" }, {})));
}

TEST(Parser, uretprobe_offset)
{
  // Not supported yet
  test_parse_failure("ur:./test:fn+1 { 1 }", R"(
stdin:1:1-15: ERROR: Offset not allowed
ur:./test:fn+1 { 1 }
~~~~~~~~~~~~~~
)");

  test_parse_failure("uretprobe:/bin/sh:f+0x10 { 1 }", R"(
stdin:1:1-25: ERROR: Offset not allowed
uretprobe:/bin/sh:f+0x10 { 1 }
~~~~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, invalid_increment_decrement)
{
  test_parse_failure("i:s:1 { @=5++}", R"(
stdin:1:12-14: ERROR: syntax error, unexpected ++, expecting ; or }
i:s:1 { @=5++}
           ~~
)");

  test_parse_failure("i:s:1 { @=++5}", R"(
stdin:1:13-14: ERROR: syntax error, unexpected integer
i:s:1 { @=++5}
            ~
)");

  test_parse_failure("i:s:1 { @=5--}", R"(
stdin:1:12-14: ERROR: syntax error, unexpected --, expecting ; or }
i:s:1 { @=5--}
           ~~
)");

  test_parse_failure("i:s:1 { @=--5}", R"(
stdin:1:13-14: ERROR: syntax error, unexpected integer
i:s:1 { @=--5}
            ~
)");

  test_parse_failure("i:s:1 { @=\"a\"++}", R"(
stdin:1:14-16: ERROR: syntax error, unexpected ++, expecting ; or }
i:s:1 { @="a"++}
             ~~
)");
}

TEST(Parser, long_param_overflow)
{
  std::stringstream out;
  ast::ASTContext ast("stdin", "i:s:100 { @=$111111111111111111111111111 }");
  Driver driver(ast);
  EXPECT_NO_THROW(driver.parse_program());
  ASSERT_FALSE(ast.diagnostics().ok());
  ast.diagnostics().emit(out);
  std::string expected = "stdin:1:13-41: ERROR: param "
                         "$111111111111111111111111111 is out of "
                         "integer range [1, " +
                         std::to_string(std::numeric_limits<long>::max()) +
                         "]\n" +
                         "i:s:100 { @=$111111111111111111111111111 }\n" +
                         "            ~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
  EXPECT_EQ(out.str(), expected);
}

TEST(Parser, empty_arguments)
{
  test_parse_failure("::k::vfs_open:: { 1 }", R"(
stdin:1:1-16: ERROR: No attach points for probe
::k::vfs_open:: { 1 }
~~~~~~~~~~~~~~~
)");

  // Error location is incorrect: #3063
  test_parse_failure("k:vfs_open:: { 1 }", R"(
stdin:1:1-13: ERROR: kprobe probe type requires 1 or 2 arguments, found 3
k:vfs_open:: { 1 }
~~~~~~~~~~~~
)");

  test_parse_failure(":w:0x10000000:8:rw { 1 }", R"(
stdin:1:1-19: ERROR: No attach points for probe
:w:0x10000000:8:rw { 1 }
~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, int_notation)
{
  // Scientific notation tests
  test("k:f { print(1e6); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(1000000) })) })));

  test("k:f { print(5e9); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(5000000000) })) })));

  test("k:f { print(1e1_0); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(10000000000) })) })));

  // Underscore separator tests
  test("k:f { print(1_000_000_000_0); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(10000000000) })) })));

  test("k:f { print(1_0_0_0_00_0_000_0); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(10000000000) })) })));

  test("k:f { print(123_456_789_0); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(1234567890) })) })));

  // Hexadecimal tests
  test("k:f { print(0xe5); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(229) })) })));

  test("k:f { print(0x5e5); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(1509) })) })));

  test("k:f { print(0xeeee); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(61166) })) })));

  // Octal tests
  test("k:f { print(0777); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(511) })) })));

  test("k:f { print(0123); }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(Call("print", { Integer(83) })) })));

  // Integer suffix tests
  test("k:f { print(1_000u); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(1000) })) })));

  test("k:f { print(1_000ul); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(1000) })) })));

  test("k:f { print(1_000ull); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(1000) })) })));

  test("k:f { print(1_000l); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(1000) })) })));

  test("k:f { print(1_000ll); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(1000) })) })));

  // Time unit tests
  test("k:f { print(1ns); }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(Call("print", { Integer(1) })) })));

  test("k:f { print(1us); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(1000) })) })));

  test("k:f { print(1ms); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(1000000) })) })));

  test("k:f { print(1s); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(1000000000) })) })));

  test("k:f { print(1m); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Integer(60000000000) })) })));

  test("k:f { print(1h); }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { ExprStatement(Call("print", { Integer(3600000000000) })) })));

  test("k:f { print(1d); }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { ExprStatement(Call("print", { Integer(86400000000000) })) })));

  // Error tests
  test_parse_failure("k:f { print(5e-9); }", R"(
stdin:1:14-15: ERROR: syntax error, unexpected identifier, expecting ) or ","
k:f { print(5e-9); }
             ~
)");

  test_parse_failure("k:f { print(1e21); }", R"(
stdin:1:13-17: ERROR: overflow error, maximum value is 18446744073709551615: 1e21
k:f { print(1e21); }
            ~~~~
)");

  test_parse_failure("k:f { print(10000000000m); }", R"(
stdin:1:13-25: ERROR: overflow error, maximum value is 18446744073709551615: 10000000000m
k:f { print(10000000000m); }
            ~~~~~~~~~~~~
)");

  test_parse_failure("k:f { print(12e4); }", R"(
stdin:1:13-17: ERROR: coefficient part of scientific literal must be 1-9: 12e4
k:f { print(12e4); }
            ~~~~
)");

  test_parse_failure("k:f { print(1_1e100); }", R"(
stdin:1:13-20: ERROR: coefficient part of scientific literal must be 1-9: 1_1e100
k:f { print(1_1e100); }
            ~~~~~~~
)");

  test_parse_failure("k:f { print(1e1_1_); }", R"(
stdin:1:18-19: ERROR: syntax error, unexpected _, expecting ) or ","
k:f { print(1e1_1_); }
                 ~
)");

  test_parse_failure("k:f { print(1_1_e100); }", R"(
stdin:1:16-21: ERROR: syntax error, unexpected identifier, expecting ) or ","
k:f { print(1_1_e100); }
               ~~~~~
)");

  test_parse_failure("k:f { print(1_1_); }", R"(
stdin:1:16-17: ERROR: syntax error, unexpected _, expecting ) or ","
k:f { print(1_1_); }
               ~
)");

  test_parse_failure("k:f { print(1ulll); }", R"(
stdin:1:17-18: ERROR: syntax error, unexpected identifier, expecting ) or ","
k:f { print(1ulll); }
                ~
)");

  test_parse_failure("k:f { print(1lul); }", R"(
stdin:1:15-17: ERROR: syntax error, unexpected identifier, expecting ) or ","
k:f { print(1lul); }
              ~~
)");
}

TEST(Parser, while_loop)
{
  test("i:ms:100 { $a = 0; while($a < 10) { $a++ }}",
       Program().WithProbe(
           Probe({ "interval:ms:100" },
                 { AssignVarStatement(Variable("$a"), Integer(0)),
                   While(Binop(Operator::LT, Variable("$a"), Integer(10)),
                         { ExprStatement(Unop(Operator::POST_INCREMENT,
                                              Variable("$a"))) }) })));
}

TEST(Parser, tuples)
{
  test("k:f { print(()); }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(Call("print", { Tuple({}) })) })));

  // Not a tuple.
  test("k:f { print((1)); }",
       Program().WithProbe(Probe(
           { "kprobe:f" }, { ExprStatement(Call("print", { Integer(1) })) })));

  test("k:f{ print((1,)); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call("print", { Tuple({ Integer(1) }) })) })));

  test("k:f { print((1,2)); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(
                     Call("print", { Tuple({ Integer(1), Integer(2) }) })) })));

  test("k:f { print((1,2,)); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(
                     Call("print", { Tuple({ Integer(1), Integer(2) }) })) })));

  test_parse_failure("k:f { print((,)); }", R"(
stdin:1:14-15: ERROR: syntax error, unexpected ","
k:f { print((,)); }
             ~
)");
}

TEST(Parser, records)
{
  test("k:f{ print((a=1)); }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { ExprStatement(Call(
               "print", { Record({ NamedArgument("a", Integer(1)) }) })) })));

  test("k:f{ print((a=1, b=\"hello\")); }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { ExprStatement(Call(
                     "print",
                     { Record({ NamedArgument("a", Integer(1)),
                                NamedArgument("b", String("hello")) }) })) })));

  test("k:f{ print((a=(a=1))); }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { ExprStatement(Call(
               "print",
               { Record({ NamedArgument(
                   "a", Record({ NamedArgument("a", Integer(1)) })) }) })) })));

  test_parse_failure("k:f { print((hello=1, 5)); }", R"(
stdin:1:23-24: ERROR: syntax error, unexpected integer, expecting builtin or builtin type or sized type or identifier
k:f { print((hello=1, 5)); }
                      ~
)");
  test_parse_failure("k:f { print((hello=1,)); }", R"(
stdin:1:22-23: ERROR: syntax error, unexpected ), expecting builtin or builtin type or sized type or identifier
k:f { print((hello=1,)); }
                     ~
)");
  test_parse_failure("k:f { print((hello=1,hello=2)); }", R"(
stdin:1:22-29: ERROR: Named argument list already contains name: hello
k:f { print((hello=1,hello=2)); }
                     ~~~~~~~
)");
}

TEST(Parser, tuple_assignment_error_message)
{
  std::stringstream out;
  ast::ASTContext ast("stdin", "i:s:1 { @x = (1, 2); $x.1 = 1; }");
  Driver driver(ast);
  ast.root = driver.parse_program();
  ASSERT_FALSE(ast.diagnostics().ok());
  ast.diagnostics().emit(out);
  std::string expected =
      R"(stdin:1:22-30: ERROR: Tuples are immutable once created. Consider creating a new tuple and assigning it instead.
i:s:1 { @x = (1, 2); $x.1 = 1; }
                     ~~~~~~~~
)";
  EXPECT_EQ(out.str(), expected);
}

TEST(Parser, tuple_assignment_error)
{
  test_parse_failure("i:s:1 { (1, 0) = 0 }", R"(
stdin:1:16-17: ERROR: syntax error, unexpected =
i:s:1 { (1, 0) = 0 }
               ~
)");

  test_parse_failure("i:s:1 { ((1, 0), 3).0.0 = 3 }", R"(
stdin:1:9-28: ERROR: Tuples are immutable once created. Consider creating a new tuple and assigning it instead.
i:s:1 { ((1, 0), 3).0.0 = 3 }
        ~~~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("i:s:1 { ((1, 0), 3).0 = (0, 1) }", R"(
stdin:1:9-31: ERROR: Tuples are immutable once created. Consider creating a new tuple and assigning it instead.
i:s:1 { ((1, 0), 3).0 = (0, 1) }
        ~~~~~~~~~~~~~~~~~~~~~~
)");

  test_parse_failure(R"(i:s:1 { (1, "two", (3, 4)).5 = "six"; })", R"(
stdin:1:9-37: ERROR: Tuples are immutable once created. Consider creating a new tuple and assigning it instead.
i:s:1 { (1, "two", (3, 4)).5 = "six"; }
        ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("i:s:1 { $a = 1; $a.2 = 3 }", R"(
stdin:1:17-25: ERROR: Tuples are immutable once created. Consider creating a new tuple and assigning it instead.
i:s:1 { $a = 1; $a.2 = 3 }
                ~~~~~~~~
)");

  test_parse_failure("i:s:1 { 0.1 = 1.0 }", R"(
stdin:1:9-18: ERROR: Tuples are immutable once created. Consider creating a new tuple and assigning it instead.
i:s:1 { 0.1 = 1.0 }
        ~~~~~~~~~
)");
}

TEST(Parser, abs_knl_address)
{
  char hex_probe[64];
  char dec_probe[64];
  snprintf(hex_probe, sizeof(hex_probe), "watchpoint:0x%lx:4:w", ULONG_MAX);
  snprintf(dec_probe, sizeof(dec_probe), "watchpoint:%lu:4:w", ULONG_MAX);
  test(std::string(hex_probe) + R"( { 1; })",
       Program().WithProbe(
           Probe({ std::string(dec_probe) }, { ExprStatement(Integer(1)) })));
}

TEST(Parser, invalid_provider)
{
  test_parse_failure("asdf { }", R"(
stdin:1:1-5: ERROR: Invalid probe type: asdf
asdf { }
~~~~
)");

  test_parse_failure("asdf:xyz { }", R"(
stdin:1:1-9: ERROR: Invalid probe type: asdf
asdf:xyz { }
~~~~~~~~
)");

  test_parse_failure("asdf:xyz:www { }", R"(
stdin:1:1-13: ERROR: Invalid probe type: asdf
asdf:xyz:www { }
~~~~~~~~~~~~
)");
}

TEST(Parser, non_fatal_errors)
{
  // The non-fatal error from parsing "Stream" as an integer should not be
  // displayed
  test_parse_failure("uprobe:asdf:Stream {} tracepoint:only_one_arg {}",
                     R"(
stdin:1:23-46: ERROR: tracepoint probe type requires 2 arguments, found 1
uprobe:asdf:Stream {} tracepoint:only_one_arg {}
                      ~~~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, config)
{
  test("config = { blah = 5 } begin {}",
       Program()
           .WithConfig(Config({ AssignConfigVarStatement("blah", 5UL) }))
           .WithProbe(Probe({ "begin" }, {})));

  test("config = { blah = 5; } begin {}",
       Program()
           .WithConfig(Config({ AssignConfigVarStatement("blah", 5UL) }))
           .WithProbe(Probe({ "begin" }, {})));

  test("config = { blah = false; } begin {}",
       Program()
           .WithConfig(Config({ AssignConfigVarStatement("blah", false) }))
           .WithProbe(Probe({ "begin" }, {})));

  test("config = { blah = \"tomato\"; } begin {}",
       Program()
           .WithConfig(Config({ AssignConfigVarStatement("blah", "tomato") }))
           .WithProbe(Probe({ "begin" }, {})));

  test("config = { blah = 5; zoop = \"a\"; } begin {}",
       Program()
           .WithConfig(Config({ AssignConfigVarStatement("blah", 5UL),
                                AssignConfigVarStatement("zoop", "a") }))
           .WithProbe(Probe({ "begin" }, {})));

  test("config = {} begin {}",
       Program().WithConfig(Config({})).WithProbe(Probe({ "begin" }, {})));
}

TEST(Parser, config_error)
{
  test_parse_failure("i:s:1 { exit(); } config = { BPFTRACE_STACK_MODE=perf }",
                     R"(
stdin:1:19-25: ERROR: syntax error, unexpected config
i:s:1 { exit(); } config = { BPFTRACE_STACK_MODE=perf }
                  ~~~~~~
)");

  test_parse_failure("config = { exit(); } i:s:1 { exit(); }", R"(
stdin:1:16-17: ERROR: syntax error, unexpected (, expecting =
config = { exit(); } i:s:1 { exit(); }
               ~
)");

  test_parse_failure("config = { @start = nsecs; } i:s:1 { exit(); }", R"(
stdin:1:12-18: ERROR: syntax error, unexpected map, expecting } or identifier
config = { @start = nsecs; } i:s:1 { exit(); }
           ~~~~~~
)");

  test_parse_failure("begin { @start = nsecs; } config = { "
                     "BPFTRACE_STACK_MODE=perf } i:s:1 { exit(); }",
                     R"(
stdin:1:27-33: ERROR: syntax error, unexpected config
begin { @start = nsecs; } config = { BPFTRACE_STACK_MODE=perf } i:s:1 { exit(); }
                          ~~~~~~
)");

  test_parse_failure("config = { BPFTRACE_STACK_MODE=perf "
                     "BPFTRACE_MAX_PROBES=2 } i:s:1 { exit(); }",
                     R"(
stdin:1:37-56: ERROR: syntax error, unexpected identifier, expecting ; or }
config = { BPFTRACE_STACK_MODE=perf BPFTRACE_MAX_PROBES=2 } i:s:1 { exit(); }
                                    ~~~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("config = { BPFTRACE_STACK_MODE=perf } i:s:1 { "
                     "BPFTRACE_MAX_PROBES=2; exit(); }",
                     R"(
stdin:1:66-67: ERROR: syntax error, unexpected =, expecting ++ or --
config = { BPFTRACE_STACK_MODE=perf } i:s:1 { BPFTRACE_MAX_PROBES=2; exit(); }
                                                                 ~
)");

  test_parse_failure("config { BPFTRACE_STACK_MODE=perf } i:s:1 { exit(); }",
                     R"(
stdin:1:8-9: ERROR: syntax error, unexpected {, expecting =
config { BPFTRACE_STACK_MODE=perf } i:s:1 { exit(); }
       ~
)");

  test_parse_failure("BPFTRACE_STACK_MODE=perf; i:s:1 { exit(); }", R"(
stdin:1:20-21: ERROR: syntax error, unexpected =, expecting {
BPFTRACE_STACK_MODE=perf; i:s:1 { exit(); }
                   ~
)");
}

TEST(Parser, keywords_as_identifiers)
{
  std::vector<std::string> keywords = { "break",    "config", "continue",
                                        "else",     "for",    "if",
                                        "offsetof", "return", "sizeof",
                                        "unroll",   "while" };
  for (const auto &keyword : keywords) {
    test("begin { $x = (struct Foo*)0; $x->" + keyword + "; }",
         Program().WithProbe(
             Probe({ "begin" },
                   { AssignVarStatement(Variable("$x"),
                                        Cast(Typeof(SizedType(Type::pointer)),
                                             Integer(0))),
                     ExprStatement(FieldAccess(keyword, Variable("$x"))) })));
    test("begin { $x = (struct Foo)0; $x." + keyword + "; }",
         Program().WithProbe(Probe(
             { "begin" },
             { AssignVarStatement(Variable("$x"),
                                  Cast(Typeof(SizedType(Type::c_struct)
                                                  .WithName("struct Foo")),
                                       Integer(0))),
               ExprStatement(FieldAccess(keyword, Variable("$x"))) })));
    test("begin { $x = offsetof(*__builtin_curtask, " + keyword + "); }",
         Program().WithProbe(Probe(
             { "begin" },
             { AssignVarStatement(Variable("$x"),
                                  Offsetof(Unop(Operator::MUL,
                                                Builtin("__builtin_curtask")),
                                           { keyword })) })));
  }
}

TEST(Parser, prog_body_items)
{
  // This includes probes, subprogs, macros, and map declarations.
  // Note: macros are not printed in the AST.
  test("i:s:1 {} macro add_one() {} fn f1(): void {} let @a = hash(5); i:s:1 "
       "{} fn f2(): void {} macro add_two() {}",
       Program()
           .WithMapDecls({ MapDeclStatement("@a", "hash", 5) })
           .WithFunctions(
               { Subprog("f1", Typeof(SizedType(Type::voidtype)), {}, {}),
                 Subprog("f2", Typeof(SizedType(Type::voidtype)), {}, {}) })
           .WithProbes({ Probe({ "interval:s:1" }, {}),
                         Probe({ "interval:s:1" }, {}) }));
}

TEST(Parser, subprog_void_no_args)
{
  test("fn f(): void {}",
       Program().WithFunction(
           Subprog("f", Typeof(SizedType(Type::voidtype)), {}, {})));
}

TEST(Parser, subprog_invalid_return_type)
{
  // Error location is incorrect: #3063
  test_parse_failure("fn f(): nonexistent {}", R"(
stdin:1:9-20: ERROR: syntax error, unexpected identifier
fn f(): nonexistent {}
        ~~~~~~~~~~~
)");
}

TEST(Parser, subprog_one_arg)
{
  test("fn f($a : uint8): void {}",
       Program().WithFunction(Subprog(
           "f",
           Typeof(SizedType(Type::voidtype)),
           { SubprogArg(Variable("$a"), Typeof(SizedType(Type::integer))) },
           {})));
}

TEST(Parser, subprog_two_args)
{
  test("fn f($a : uint8, $b : uint8): void {}",
       Program().WithFunction(Subprog(
           "f",
           Typeof(SizedType(Type::voidtype)),
           { SubprogArg(Variable("$a"), Typeof(SizedType(Type::integer))),
             SubprogArg(Variable("$b"), Typeof(SizedType(Type::integer))) },
           {})));
}

TEST(Parser, subprog_string_arg)
{
  test("fn f($a : string): void {}",
       Program().WithFunction(Subprog(
           "f",
           Typeof(SizedType(Type::voidtype)),
           { SubprogArg(Variable("$a"), Typeof(SizedType(Type::string))) },
           {})));
}

TEST(Parser, subprog_struct_arg)
{
  test("fn f($a: struct x): void {}",
       Program().WithFunction(Subprog(
           "f",
           Typeof(SizedType(Type::voidtype)),
           { SubprogArg(Variable("$a"),
                        Typeof(
                            SizedType(Type::c_struct).WithName("struct x"))) },
           {})));
}

TEST(Parser, subprog_union_arg)
{
  test(
      "fn f($a : union x): void {}",
      Program().WithFunction(Subprog(
          "f",
          Typeof(SizedType(Type::voidtype)),
          { SubprogArg(Variable("$a"),
                       Typeof(SizedType(Type::c_struct).WithName("union x"))) },
          {})));
}

TEST(Parser, subprog_enum_arg)
{
  test("fn f($a : enum x): void {}",
       Program().WithFunction(Subprog(
           "f",
           Typeof(SizedType(Type::voidtype)),
           { SubprogArg(Variable("$a"),
                        Typeof(SizedType(Type::integer).WithName("x"))) },
           {})));
}

TEST(Parser, subprog_invalid_arg)
{
  // Error location is incorrect: #3063
  test_parse_failure("fn f($x : invalid): void {}", R"(
stdin:1:11-18: ERROR: syntax error, unexpected identifier
fn f($x : invalid): void {}
          ~~~~~~~
)");
}

TEST(Parser, subprog_return)
{
  test("fn f(): void { return 1 + 1; }",
       Program().WithFunction(
           Subprog("f",
                   Typeof(SizedType(Type::voidtype)),
                   {},
                   { Return(Binop(Operator::PLUS, Integer(1), Integer(1))) })));
}

TEST(Parser, subprog_string)
{
  test("fn f(): string {}",
       Program().WithFunction(
           Subprog("f", Typeof(SizedType(Type::string)), {}, {})));
}

TEST(Parser, subprog_struct)
{
  test("fn f(): struct x {}",
       Program().WithFunction(
           Subprog("f",
                   Typeof(SizedType(Type::c_struct).WithName("struct x")),
                   {},
                   {})));
}

TEST(Parser, subprog_union)
{
  test(
      "fn f(): union x {}",
      Program().WithFunction(Subprog(
          "f", Typeof(SizedType(Type::c_struct).WithName("union x")), {}, {})));
}

TEST(Parser, subprog_enum)
{
  test("fn f(): enum x {}",
       Program().WithFunction(Subprog(
           "f", Typeof(SizedType(Type::integer).WithName("x")), {}, {})));
}

TEST(Parser, for_loop)
{
  test("begin { for ($kv : @map) { print($kv) } }",
       Program().WithProbe(Probe(
           { "begin" },
           { For(Variable("$kv"),
                 Map("@map"),
                 { ExprStatement(Call("print", { Variable("$kv") })) }) })));

  // Error location is incorrect: #3063
  // No body
  test_parse_failure("begin { for ($kv : @map) print($kv); }", R"(
stdin:1:26-31: ERROR: syntax error, unexpected identifier, expecting {
begin { for ($kv : @map) print($kv); }
                         ~~~~~
)");

  // Map for decl
  test_parse_failure("begin { for (@kv : @map) { } }", R"(
stdin:1:14-17: ERROR: syntax error, unexpected map, expecting variable
begin { for (@kv : @map) { } }
             ~~~
)");
}

TEST(Parser, for_range)
{
  test("begin { for ($i : 0..10) { print($i) } }",
       Program().WithProbe(Probe(
           { "begin" },
           { For(Variable("$i"),
                 Range(Integer(0), Integer(10)),
                 { ExprStatement(Call("print", { Variable("$i") })) }) })));

  // Binary expressions must be wrapped.
  test_parse_failure("begin { for ($i : 1+1..10) { print($i) } }", R"(
stdin:1:20-21: ERROR: syntax error, unexpected +, expecting [ or . or ->
begin { for ($i : 1+1..10) { print($i) } }
                   ~
)");
  test_parse_failure("begin { for ($i : 0..1+1) { print($i) } }", R"(
stdin:1:23-24: ERROR: syntax error, unexpected +, expecting )
begin { for ($i : 0..1+1) { print($i) } }
                      ~
)");

  // Invalid range operator.
  test_parse_failure("begin { for ($i : 0...10) { print($i) } }", R"(
stdin:1:22-23: ERROR: syntax error, unexpected .
begin { for ($i : 0...10) { print($i) } }
                     ~
)");

  // Missing end range.
  test_parse_failure("begin { for ($i : 0..) { print($i) } }", R"(
stdin:1:22-23: ERROR: syntax error, unexpected )
begin { for ($i : 0..) { print($i) } }
                     ~
)");

  // Missing start range.
  test_parse_failure("begin { for ($i : ..10) { print($i) } }", R"(
stdin:1:19-20: ERROR: syntax error, unexpected .
begin { for ($i : ..10) { print($i) } }
                  ~
)");
}

TEST(Parser, variable_declarations)
{
  // N.B. we check that the variable decl is defined, and also that is does not
  // match any type matchers, because no type has been specified.
  test("begin { let $x; }",
       Program().WithProbe(
           Probe({ "begin" },
                 { testing::AllOf(VarDeclStatement(Variable("$x")),
                                  testing::Not(VarDeclStatement(Variable("$x"),
                                                                _))) })));

  test("begin { let $x: int8; }",
       Program().WithProbe(
           Probe({ "begin" },
                 { VarDeclStatement(Variable("$x"),
                                    Typeof(SizedType(Type::integer))) })));

  test("begin { let $x = 1; }",
       Program().WithProbe(Probe(
           { "begin" }, { AssignVarStatement(Variable("$x"), Integer(1)) })));

  test("begin { let $x: int8 = 1; }",
       Program().WithProbe(Probe(
           { "begin" }, { AssignVarStatement(Variable("$x"), Integer(1)) })));

  // Needs the let keyword
  test_parse_failure("begin { $x: int8; }", R"(
stdin:1:11-12: ERROR: syntax error, unexpected :
begin { $x: int8; }
          ~
)");

  // Needs the let keyword
  test_parse_failure("begin { $x: int8 = 1; }", R"(
stdin:1:11-12: ERROR: syntax error, unexpected :
begin { $x: int8 = 1; }
          ~
)");
}

TEST(Parser, variable_address)
{
  test("begin { $x = 1; &$x;  }",
       Program().WithProbe(
           Probe({ "begin" },
                 { AssignVarStatement(Variable("$x"), Integer(1)),
                   ExprStatement(VariableAddr(Variable("$x"))) })));
}

TEST(Parser, struct_save_nested)
{
  test(R"(struct Foo {
  int x;
  struct Bar {
    int y;
    struct Baz {
      int z;
    } baz;
  } bar;
} i:ms:100 { $s = (struct Foo)1; })",
       Program()
           .WithCStatements({ CStatement(R"(struct Foo {
  int x;
  struct Bar {
    int y;
    struct Baz {
      int z;
    } baz;
  } bar;
};)") })
           .WithProbe(Probe(
               { "interval:ms:100" },
               { AssignVarStatement(Variable("$s"),
                                    Cast(Typeof(SizedType(Type::c_struct)
                                                    .WithName("struct Foo")),
                                         Integer(1))) })));
}

TEST(Parser, map_address)
{
  test("begin { @a = 1; &@a;  }",
       Program().WithProbe(
           Probe({ "begin" },
                 { AssignScalarMapStatement(Map("@a"), Integer(1)),
                   ExprStatement(MapAddr(Map("@a"))) })));
}

TEST(Parser, bare_blocks)
{
  test("i:s:1 { $a = 1; { $b = 2; { $c = 3; } } }",
       Program().WithProbe(
           Probe({ "interval:s:1" },
                 { AssignVarStatement(Variable("$a"), Integer(1)),
                   ExprStatement(Block(
                       { AssignVarStatement(Variable("$b"), Integer(2)),
                         ExprStatement(Block(
                             { AssignVarStatement(Variable("$c"), Integer(3)) },
                             None())) },
                       None())) })));
}

TEST(Parser, block_expressions)
{
  // Non-legal trailing statement
  test_parse_failure("begin { $x = { $a = 1; $b = 2 } exit(); }", R"(
stdin:1:31-32: ERROR: syntax error, unexpected }, expecting ;
begin { $x = { $a = 1; $b = 2 } exit(); }
                              ~
)");

  // No expression, statement with trailing ;
  test_parse_failure("begin { $x = { $a = 1; $b = 2; } exit(); }", R"(
stdin:1:32-33: ERROR: syntax error, unexpected }
begin { $x = { $a = 1; $b = 2; } exit(); }
                               ~
)");

  // Missing ; after block expression
  test_parse_failure("begin { $x = { $a = 1; $a } exit(); }", R"(
stdin:1:29-33: ERROR: syntax error, unexpected identifier, expecting ; or }
begin { $x = { $a = 1; $a } exit(); }
                            ~~~~
)");

  // Illegal; no map assignment
  test_parse_failure("begin { $x = { $a = 1; count() } exit(); }", R"(
stdin:1:34-38: ERROR: syntax error, unexpected identifier, expecting ; or }
begin { $x = { $a = 1; count() } exit(); }
                                 ~~~~
)");

  // Good, no map assignment
  test("begin { $x = { $a = 1; $a }; exit(); }",
       Program().WithProbe(
           Probe({ "begin" },
                 { AssignVarStatement(Variable("$x"),
                                      Block({ AssignVarStatement(Variable("$a"),
                                                                 Integer(1)) },
                                            Variable("$a"))),
                   ExprStatement(Call("exit", {})) })));

  // Good, with map assignment
  test("begin { $x = { $a = 1; count() }; exit(); }",
       Program().WithProbe(
           Probe({ "begin" },
                 { AssignVarStatement(Variable("$x"),
                                      Block({ AssignVarStatement(Variable("$a"),
                                                                 Integer(1)) },
                                            Call("count", {}))),
                   ExprStatement(Call("exit", {})) })));
}

TEST(Parser, map_declarations)
{
  test("let @a = hash(5); begin { $x; }",
       Program()
           .WithMapDecls({ MapDeclStatement("@a", "hash", 5) })
           .WithProbe(Probe({ "begin" }, { ExprStatement(Variable("$x")) })));

  test("let @a = hash(2); let @b = per__cpuhash(7); begin { $x; }",
       Program()
           .WithMapDecls({ MapDeclStatement("@a", "hash", 2),
                           MapDeclStatement("@b", "per__cpuhash", 7) })
           .WithProbe(Probe({ "begin" }, { ExprStatement(Variable("$x")) })));

  test_parse_failure("@a = hash(); begin { $x; }", R"(
stdin:1:1-3: ERROR: syntax error, unexpected map
@a = hash(); begin { $x; }
~~
)");

  test_parse_failure("let @a = hash(); begin { $x; }", R"(
stdin:1:15-16: ERROR: syntax error, unexpected ), expecting integer
let @a = hash(); begin { $x; }
              ~
)");
}

TEST(Parser, macro_expansion_error)
{
  // A recursive macro expansion
  test_macro_parse_failure("#define M M+1\n"
                           "begin { M; }",
                           R"(
M:1:1-2: ERROR: Macro recursion: M
M+1
~
stdin:2:9-10: ERROR: expanded from
begin { M; }
        ~
)");

  // Invalid macro expression
  test_macro_parse_failure("#define M {\n"
                           "begin { M; }",
                           R"(
stdin:2:9-10: ERROR: unable to expand macro as an expression: {
begin { M; }
        ~
)");

  // Large source code doesn't cause any problem
  std::string padding(16384 * 2, 'p'); // Twice the default value of YY_BUF_SIZE
  test_macro_parse_failure("#define M M+1\n"
                           "begin { M; }\n"
                           "end { printf(\"" +
                               padding + "\"); }",
                           R"(
M:1:1-2: ERROR: Macro recursion: M
M+1
~
stdin:2:9-10: ERROR: expanded from
begin { M; }
        ~
)");
}

TEST(Parser, imports)
{
  test(R"(import "foo"; begin { })",
       Program()
           .WithRootImports({ RootImport("foo") })
           .WithProbe(Probe({ "begin" }, {})));

  test(R"(import "foo"; import "bar"; begin { })",
       Program()
           .WithRootImports({ RootImport("foo"), RootImport("bar") })
           .WithProbe(Probe({ "begin" }, {})));

  test_parse_failure(R"(begin { }; import "foo";)", R"(
stdin:1:10-11: ERROR: syntax error, unexpected ;
begin { }; import "foo";
         ~
)");

  test_parse_failure("import 0; begin { }", R"(
stdin:1:8-9: ERROR: syntax error, unexpected integer, expecting string
import 0; begin { }
       ~
)");

  test_parse_failure("import foo; begin { }", R"(
stdin:1:8-11: ERROR: syntax error, unexpected identifier, expecting string
import foo; begin { }
       ~~~
)");
}

TEST(Parser, order_of_operations)
{
  // Test multiplication has higher precedence than addition.
  test("kprobe:f { @x = 2 + 3 * 4; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::PLUS,
                           Integer(2),
                           Binop(Operator::MUL, Integer(3), Integer(4)))) })));

  // Test division has higher precedence than subtraction.
  test("kprobe:f { @x = 10 - 8 / 2; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::MINUS,
                           Integer(10),
                           Binop(Operator::DIV, Integer(8), Integer(2)))) })));

  // Test modulo has same precedence as multiplication and division.
  test("kprobe:f { @x = 2 * 3 % 4; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::MOD,
                           Binop(Operator::MUL, Integer(2), Integer(3)),
                           Integer(4))) })));

  // Test bit shifts have lower precedence than arithmetic.
  test("kprobe:f { @x = 1 + 2 << 3; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::LEFT,
                           Binop(Operator::PLUS, Integer(1), Integer(2)),
                           Integer(3))) })));

  test("kprobe:f { @x = 16 >> 2 + 1; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::RIGHT,
                           Integer(16),
                           Binop(Operator::PLUS, Integer(2), Integer(1)))) })));

  // Test relational operators have lower precedence than bit shifts.
  test("kprobe:f { @x = 1 << 2 < 8; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::LT,
                           Binop(Operator::LEFT, Integer(1), Integer(2)),
                           Integer(8))) })));

  test("kprobe:f { @x = 8 > 2 << 1; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::GT,
                           Integer(8),
                           Binop(Operator::LEFT, Integer(2), Integer(1)))) })));

  test("kprobe:f { @x = 5 <= 3 + 2; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::LE,
                           Integer(5),
                           Binop(Operator::PLUS, Integer(3), Integer(2)))) })));

  test("kprobe:f { @x = 5 >= 3 - 1; }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(
               Map("@x"),
               Binop(Operator::GE,
                     Integer(5),
                     Binop(Operator::MINUS, Integer(3), Integer(1)))) })));

  // Test equality operators have lower precedence than relational.
  test("kprobe:f { @x = 5 > 3 == 1; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::EQ,
                           Binop(Operator::GT, Integer(5), Integer(3)),
                           Integer(1))) })));

  test("kprobe:f { @x = 2 < 4 != 0; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::NE,
                           Binop(Operator::LT, Integer(2), Integer(4)),
                           Integer(0))) })));

  // Test bitwise AND has lower precedence than equality.
  test("kprobe:f { @x = 5 == 5 & 1; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::BAND,
                           Binop(Operator::EQ, Integer(5), Integer(5)),
                           Integer(1))) })));

  // Test bitwise XOR has lower precedence than bitwise AND.
  test("kprobe:f { @x = 1 & 3 ^ 2; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::BXOR,
                           Binop(Operator::BAND, Integer(1), Integer(3)),
                           Integer(2))) })));

  // Test bitwise OR has lower precedence than bitwise XOR.
  test("kprobe:f { @x = 1 ^ 2 | 4; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::BOR,
                           Binop(Operator::BXOR, Integer(1), Integer(2)),
                           Integer(4))) })));

  // Test logical AND has lower precedence than bitwise OR.
  test("kprobe:f { @x = 1 | 2 && 4; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::LAND,
                           Binop(Operator::BOR, Integer(1), Integer(2)),
                           Integer(4))) })));

  // Test logical OR has lower precedence than logical AND.
  test("kprobe:f { @x = 0 && 1 || 2; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::LOR,
                           Binop(Operator::LAND, Integer(0), Integer(1)),
                           Integer(2))) })));

  // Test ternary has lowest precedence.
  test("kprobe:f { @x = 1 || 0 ? 5 : 10; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     If(Binop(Operator::LOR, Integer(1), Integer(0)),
                        Integer(5),
                        Integer(10))) })));

  // Test complex expression with multiple precedence levels.
  test("kprobe:f { @x = 1 + 2 * 3 > 5 && 4 | 8 ? 10 : 20; }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(
               Map("@x"),
               If(Binop(
                      Operator::LAND,
                      Binop(Operator::GT,
                            Binop(Operator::PLUS,
                                  Integer(1),
                                  Binop(Operator::MUL, Integer(2), Integer(3))),
                            Integer(5)),
                      Binop(Operator::BOR, Integer(4), Integer(8))),
                  Integer(10),
                  Integer(20))) })));

  // Test left-associativity for operators of same precedence.
  test("kprobe:f { @x = 10 - 5 - 2; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::MINUS,
                           Binop(Operator::MINUS, Integer(10), Integer(5)),
                           Integer(2))) })));

  test("kprobe:f { @x = 20 / 4 / 2; }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignScalarMapStatement(
                     Map("@x"),
                     Binop(Operator::DIV,
                           Binop(Operator::DIV, Integer(20), Integer(4)),
                           Integer(2))) })));

  // Test ternary is right-associative.
  test("kprobe:f { @x = 1 ? 2 ? 3 : 4 : 5; }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignScalarMapStatement(Map("@x"),
                                      If(Integer(1),
                                         If(Integer(2), Integer(3), Integer(4)),
                                         Integer(5))) })));
}

TEST(Parser, naked_expression)
{
  std::stringstream out;
  ast::ASTContext ast("stdin", "1 + 2 + 3");
  Driver driver(ast);
  driver.parse_expr();
  ASSERT_TRUE(ast.diagnostics().ok());
  ASSERT_TRUE(std::holds_alternative<ast::Expression>(driver.result));
}

TEST(Parser, while_loop_unary_condition)
{
  test("kprobe:f { $a = 1; while !$a { $a++; } }",
       Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignVarStatement(Variable("$a"), Integer(1)),
                   While(Unop(Operator::LNOT, Variable("$a")),
                         { ExprStatement(Unop(Operator::POST_INCREMENT,
                                              Variable("$a"))) }) })));
}

TEST(Parser, if_block_unary_condition)
{
  test(R"(kprobe:f { if !pid { printf("zero pid\n"); } })",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { ExprStatement(If(Unop(Operator::LNOT, Builtin("pid")),
                              { ExprStatement(Call(
                                  "printf", { String("zero pid\n") })) })) })));
}

TEST(Parser, for_loop_unary_condition)
{
  test("kprobe:f { for $i : 0..10 { print($i); } }",
       Program().WithProbe(Probe(
           { "kprobe:f" },
           { For(Variable("$i"),
                 Range(Integer(0), Integer(10)),
                 { ExprStatement(Call("print", { Variable("$i") })) }) })));
}

TEST(Parser, discard)
{
  test("kprobe:f { _ = 1; }",
       Program().WithProbe(Probe({ "kprobe:f" }, { DiscardExpr(Integer(1)) })));
}
} // namespace bpftrace::test::parser
