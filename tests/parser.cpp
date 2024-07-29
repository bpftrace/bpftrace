#include <limits.h>
#include <sstream>

#include "ast/passes/printer.h"
#include "driver.h"
#include "gtest/gtest.h"

namespace bpftrace {
namespace test {
namespace parser {

using Printer = ast::Printer;

void test_parse_failure(BPFtrace &bpftrace,
                        std::string_view input,
                        std::string_view expected_error)
{
  std::stringstream out;
  Driver driver(bpftrace, out);
  EXPECT_EQ(driver.parse_str(input), 1);

  if (expected_error.data()) {
    if (!expected_error.empty() && expected_error[0] == '\n')
      expected_error.remove_prefix(1); // Remove initial '\n'
    EXPECT_EQ(expected_error, out.str());
  }
}

void test_parse_failure(std::string_view input, std::string_view expected_error)
{
  BPFtrace bpftrace;
  test_parse_failure(bpftrace, input, expected_error);
}

void test(BPFtrace &bpftrace, std::string_view input, std::string_view expected)
{
  Driver driver(bpftrace);
  ASSERT_EQ(driver.parse_str(input), 0);

  if (expected[0] == '\n')
    expected.remove_prefix(1); // Remove initial '\n'

  std::ostringstream out;
  Printer printer(out);
  printer.print(driver.ctx.root);
  EXPECT_EQ(expected, out.str());
}

void test(std::string_view input, std::string_view expected)
{
  BPFtrace bpftrace;
  test(bpftrace, input, expected);
}

TEST(Parser, builtin_variables)
{
  test("kprobe:f { pid }", R"(
Program
 kprobe:f
  builtin: pid
)");

  test("kprobe:f { tid }", R"(
Program
 kprobe:f
  builtin: tid
)");

  test("kprobe:f { cgroup }", R"(
Program
 kprobe:f
  builtin: cgroup
)");

  test("kprobe:f { uid }", R"(
Program
 kprobe:f
  builtin: uid
)");

  test("kprobe:f { username }", R"(
Program
 kprobe:f
  builtin: username
)");

  test("kprobe:f { gid }", R"(
Program
 kprobe:f
  builtin: gid
)");

  test("kprobe:f { nsecs }", R"(
Program
 kprobe:f
  builtin: nsecs
)");

  test("kprobe:f { elapsed }", R"(
Program
 kprobe:f
  builtin: elapsed
)");

  test("kprobe:f { numaid }", R"(
Program
 kprobe:f
  builtin: numaid
)");

  test("kprobe:f { cpu }", R"(
Program
 kprobe:f
  builtin: cpu
)");

  test("kprobe:f { curtask }", R"(
Program
 kprobe:f
  builtin: curtask
)");

  test("kprobe:f { rand }", R"(
Program
 kprobe:f
  builtin: rand
)");

  test("kprobe:f { ctx }", R"(
Program
 kprobe:f
  builtin: ctx
)");

  test("kprobe:f { comm }", R"(
Program
 kprobe:f
  builtin: comm
)");

  test("kprobe:f { kstack }", R"(
Program
 kprobe:f
  builtin: kstack
)");

  test("kprobe:f { ustack }", R"(
Program
 kprobe:f
  builtin: ustack
)");

  test("kprobe:f { arg0 }", R"(
Program
 kprobe:f
  builtin: arg0
)");

  test("kprobe:f { sarg0 }", R"(
Program
 kprobe:f
  builtin: sarg0
)");

  test("kprobe:f { retval }", R"(
Program
 kprobe:f
  builtin: retval
)");

  test("kprobe:f { func }", R"(
Program
 kprobe:f
  builtin: func
)");

  test("kprobe:f { probe }", R"(
Program
 kprobe:f
  builtin: probe
)");

  test("kprobe:f { args }", R"(
Program
 kprobe:f
  builtin: args
)");
}

TEST(Parser, positional_param)
{
  test("kprobe:f { $1 }", R"(
Program
 kprobe:f
  param: $1
)");

  test_parse_failure("kprobe:f { $0 }", R"(
stdin:1:12-14: ERROR: param $0 is out of integer range [1, 9223372036854775807]
kprobe:f { $0 }
           ~~
)");
}

TEST(Parser, positional_param_count)
{
  test("kprobe:f { $# }", R"(
Program
 kprobe:f
  param: $#
)");
}

TEST(Parser, positional_param_attachpoint)
{
  BPFtrace bpftrace;
  bpftrace.add_param("foo");
  bpftrace.add_param("bar");
  bpftrace.add_param("baz");

  test(bpftrace,
       "kprobe:$1 { 1 }",
       R"PROG(Program
 kprobe:foo
  int: 1
)PROG");

  test(bpftrace,
       R"PROG(kprobe:$1"here" { 1 })PROG",
       R"PROG(Program
 kprobe:foohere
  int: 1
)PROG");

  test(bpftrace,
       R"PROG(uprobe:zzzzzzz:$2 { 1 })PROG",
       R"PROG(Program
 uprobe:zzzzzzz:bar
  int: 1
)PROG");

  test(bpftrace,
       R"PROG(uprobe:$1:$2 { 1 })PROG",
       R"PROG(Program
 uprobe:foo:bar
  int: 1
)PROG");

  test(bpftrace,
       R"PROG(uprobe:$2:$1 { 1 })PROG",
       R"PROG(Program
 uprobe:bar:foo
  int: 1
)PROG");

  test(bpftrace,
       R"PROG(uprobe:"zz"$2"zz":"aa"$1 { 1 })PROG",
       R"PROG(Program
 uprobe:zzbarzz:aafoo
  int: 1
)PROG");

  test(bpftrace,
       R"PROG(uprobe:$2:"aa"$1"aa" { 1 })PROG",
       R"PROG(Program
 uprobe:bar:aafooaa
  int: 1
)PROG");

  test(bpftrace,
       R"PROG(uprobe:"$1":$2 { 1 })PROG",
       R"PROG(Program
 uprobe:$1:bar
  int: 1
)PROG");

  test(bpftrace,
       R"PROG(uprobe:aa$1:$2 { 1 })PROG",
       R"PROG(Program
 uprobe:aafoo:bar
  int: 1
)PROG");

  // Error location is incorrect: #3063
  test_parse_failure(bpftrace, R"(uprobe:$1a { 1 })", R"(
stdin:1:1-12: ERROR: Found trailing text 'a' in positional parameter index. Try quoting the trailing text.
uprobe:$1a { 1 }
~~~~~~~~~~~
stdin:1:1-1: ERROR: No attach points for probe
uprobe:$1a { 1 }

)");

  test_parse_failure(bpftrace, R"(uprobe:$a { 1 })", R"(
stdin:1:1-11: ERROR: syntax error, unexpected variable, expecting {
uprobe:$a { 1 }
~~~~~~~~~~
)");

  test_parse_failure(bpftrace, R"(uprobe:$-1 { 1 })", R"(
stdin:1:1-10: ERROR: invalid character '$'
uprobe:$-1 { 1 }
~~~~~~~~~
stdin:1:1-11: ERROR: syntax error, unexpected -, expecting {
uprobe:$-1 { 1 }
~~~~~~~~~~
)");

  test_parse_failure(bpftrace, R"(uprobe:$999999999999999999999999 { 1 })", R"(
stdin:1:1-34: ERROR: param $999999999999999999999999 is out of integer range [1, 9223372036854775807]
uprobe:$999999999999999999999999 { 1 }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, comment)
{
  test("kprobe:f { /*** ***/0; }", "Program\n kprobe:f\n  int: 0\n");
}

TEST(Parser, map_assign)
{
  test("kprobe:sys_open { @x = 1; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   map: @x\n"
       "   int: 1\n");
  test("kprobe:sys_open { @x = @y; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   map: @x\n"
       "   map: @y\n");
  test("kprobe:sys_open { @x = arg0; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   map: @x\n"
       "   builtin: arg0\n");
  test("kprobe:sys_open { @x = count(); }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   map: @x\n"
       "   call: count\n");
  test("kprobe:sys_read { @x = sum(arg2); }",
       "Program\n"
       " kprobe:sys_read\n"
       "  =\n"
       "   map: @x\n"
       "   call: sum\n"
       "    builtin: arg2\n");
  test("kprobe:sys_read { @x = min(arg2); }",
       "Program\n"
       " kprobe:sys_read\n"
       "  =\n"
       "   map: @x\n"
       "   call: min\n"
       "    builtin: arg2\n");
  test("kprobe:sys_read { @x = max(arg2); }",
       "Program\n"
       " kprobe:sys_read\n"
       "  =\n"
       "   map: @x\n"
       "   call: max\n"
       "    builtin: arg2\n");
  test("kprobe:sys_read { @x = avg(arg2); }",
       "Program\n"
       " kprobe:sys_read\n"
       "  =\n"
       "   map: @x\n"
       "   call: avg\n"
       "    builtin: arg2\n");
  test("kprobe:sys_read { @x = stats(arg2); }",
       "Program\n"
       " kprobe:sys_read\n"
       "  =\n"
       "   map: @x\n"
       "   call: stats\n"
       "    builtin: arg2\n");
  test("kprobe:sys_open { @x = \"mystring\" }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   map: @x\n"
       "   string: mystring\n");
  test("kprobe:sys_open { @x = $myvar; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   map: @x\n"
       "   variable: $myvar\n");
}

TEST(Parser, variable_assign)
{
  test("kprobe:sys_open { $x = 1; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   variable: $x\n"
       "   int: 1\n");
  test("kprobe:sys_open { $x = -1; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   variable: $x\n"
       "   int: -1\n");

  char in_cstr[128];
  char out_cstr[128];

  snprintf(in_cstr, sizeof(in_cstr), "kprobe:sys_open { $x = %ld; }", LONG_MIN);
  snprintf(out_cstr,
           sizeof(out_cstr),
           "Program\n"
           " kprobe:sys_open\n"
           "  =\n"
           "   variable: $x\n"
           "   int: %ld\n",
           LONG_MIN);
  test(std::string(in_cstr), std::string(out_cstr));
}

TEST(semantic_analyser, compound_variable_assignments)
{
  test("kprobe:f { $a = 0; $a <<= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   variable: $a\n"
       "   int: 0\n"
       "  =\n"
       "   variable: $a\n"
       "   <<\n"
       "    variable: $a\n"
       "    int: 1\n");
  test("kprobe:f { $a = 0; $a >>= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   variable: $a\n"
       "   int: 0\n"
       "  =\n"
       "   variable: $a\n"
       "   >>\n"
       "    variable: $a\n"
       "    int: 1\n");
  test("kprobe:f { $a = 0; $a += 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   variable: $a\n"
       "   int: 0\n"
       "  =\n"
       "   variable: $a\n"
       "   +\n"
       "    variable: $a\n"
       "    int: 1\n");
  test("kprobe:f { $a = 0; $a -= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   variable: $a\n"
       "   int: 0\n"
       "  =\n"
       "   variable: $a\n"
       "   -\n"
       "    variable: $a\n"
       "    int: 1\n");
  test("kprobe:f { $a = 0; $a *= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   variable: $a\n"
       "   int: 0\n"
       "  =\n"
       "   variable: $a\n"
       "   *\n"
       "    variable: $a\n"
       "    int: 1\n");
  test("kprobe:f { $a = 0; $a /= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   variable: $a\n"
       "   int: 0\n"
       "  =\n"
       "   variable: $a\n"
       "   /\n"
       "    variable: $a\n"
       "    int: 1\n");
  test("kprobe:f { $a = 0; $a %= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   variable: $a\n"
       "   int: 0\n"
       "  =\n"
       "   variable: $a\n"
       "   %\n"
       "    variable: $a\n"
       "    int: 1\n");
  test("kprobe:f { $a = 0; $a &= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   variable: $a\n"
       "   int: 0\n"
       "  =\n"
       "   variable: $a\n"
       "   &\n"
       "    variable: $a\n"
       "    int: 1\n");
  test("kprobe:f { $a = 0; $a |= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   variable: $a\n"
       "   int: 0\n"
       "  =\n"
       "   variable: $a\n"
       "   |\n"
       "    variable: $a\n"
       "    int: 1\n");
  test("kprobe:f { $a = 0; $a ^= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   variable: $a\n"
       "   int: 0\n"
       "  =\n"
       "   variable: $a\n"
       "   ^\n"
       "    variable: $a\n"
       "    int: 1\n");
}

TEST(Parser, compound_variable_assignment_binary_expr)
{
  test("kprobe:f { $a = 0; $a += 2 - 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   variable: $a\n"
       "   int: 0\n"
       "  =\n"
       "   variable: $a\n"
       "   +\n"
       "    variable: $a\n"
       "    -\n"
       "     int: 2\n"
       "     int: 1\n");
}

TEST(Parser, compound_map_assignments)
{
  test("kprobe:f { @a <<= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   map: @a\n"
       "   <<\n"
       "    map: @a\n"
       "    int: 1\n");
  test("kprobe:f { @a >>= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   map: @a\n"
       "   >>\n"
       "    map: @a\n"
       "    int: 1\n");
  test("kprobe:f { @a += 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   map: @a\n"
       "   +\n"
       "    map: @a\n"
       "    int: 1\n");
  test("kprobe:f { @a -= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   map: @a\n"
       "   -\n"
       "    map: @a\n"
       "    int: 1\n");
  test("kprobe:f { @a *= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   map: @a\n"
       "   *\n"
       "    map: @a\n"
       "    int: 1\n");
  test("kprobe:f { @a /= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   map: @a\n"
       "   /\n"
       "    map: @a\n"
       "    int: 1\n");
  test("kprobe:f { @a %= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   map: @a\n"
       "   %\n"
       "    map: @a\n"
       "    int: 1\n");
  test("kprobe:f { @a &= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   map: @a\n"
       "   &\n"
       "    map: @a\n"
       "    int: 1\n");
  test("kprobe:f { @a |= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   map: @a\n"
       "   |\n"
       "    map: @a\n"
       "    int: 1\n");
  test("kprobe:f { @a ^= 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   map: @a\n"
       "   ^\n"
       "    map: @a\n"
       "    int: 1\n");
}

TEST(Parser, compound_map_assignment_binary_expr)
{
  test("kprobe:f { @a += 2 - 1 }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   map: @a\n"
       "   +\n"
       "    map: @a\n"
       "    -\n"
       "     int: 2\n"
       "     int: 1\n");
}

TEST(Parser, integer_sizes)
{
  test("kprobe:do_nanosleep { $x = 0x12345678; }",
       "Program\n"
       " kprobe:do_nanosleep\n"
       "  =\n"
       "   variable: $x\n"
       "   int: 305419896\n");
  test("kprobe:do_nanosleep { $x = 0x4444444412345678; }",
       "Program\n"
       " kprobe:do_nanosleep\n"
       "  =\n"
       "   variable: $x\n"
       "   int: 4919131752149309048\n");
}

TEST(Parser, map_key)
{
  test("kprobe:sys_open { @x[0] = 1; @x[0,1,2] = 1; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   map: @x\n"
       "    int: 0\n"
       "   int: 1\n"
       "  =\n"
       "   map: @x\n"
       "    int: 0\n"
       "    int: 1\n"
       "    int: 2\n"
       "   int: 1\n");

  test("kprobe:sys_open { @x[@a] = 1; @x[@a,@b,@c] = 1; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   map: @x\n"
       "    map: @a\n"
       "   int: 1\n"
       "  =\n"
       "   map: @x\n"
       "    map: @a\n"
       "    map: @b\n"
       "    map: @c\n"
       "   int: 1\n");

  test("kprobe:sys_open { @x[pid] = 1; @x[tid,uid,arg9] = 1; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   map: @x\n"
       "    builtin: pid\n"
       "   int: 1\n"
       "  =\n"
       "   map: @x\n"
       "    builtin: tid\n"
       "    builtin: uid\n"
       "    builtin: arg9\n"
       "   int: 1\n");
}

TEST(Parser, predicate)
{
  test("kprobe:sys_open / @x / { 1; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  pred\n"
       "   map: @x\n"
       "  int: 1\n");
}

TEST(Parser, predicate_containing_division)
{
  test("kprobe:sys_open /100/25/ { 1; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  pred\n"
       "   /\n"
       "    int: 100\n"
       "    int: 25\n"
       "  int: 1\n");
}

TEST(Parser, expressions)
{
  test("kprobe:sys_open / 1 <= 2 && (9 - 4 != 5*10 || ~0) || comm == "
       "\"string\" /\n"
       "{\n"
       "  1;\n"
       "}",
       "Program\n"
       " kprobe:sys_open\n"
       "  pred\n"
       "   ||\n"
       "    &&\n"
       "     <=\n"
       "      int: 1\n"
       "      int: 2\n"
       "     ||\n"
       "      !=\n"
       "       -\n"
       "        int: 9\n"
       "        int: 4\n"
       "       *\n"
       "        int: 5\n"
       "        int: 10\n"
       "      ~\n"
       "       int: 0\n"
       "    ==\n"
       "     builtin: comm\n"
       "     string: string\n"
       "  int: 1\n");
}

TEST(Parser, variable_post_increment_decrement)
{
  test("kprobe:sys_open { $x++; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  variable: $x\n"
       "   ++\n");
  test("kprobe:sys_open { ++$x; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  ++\n"
       "   variable: $x\n");
  test("kprobe:sys_open { $x--; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  variable: $x\n"
       "   --\n");
  test("kprobe:sys_open { --$x; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  --\n"
       "   variable: $x\n");
}

TEST(Parser, map_increment_decrement)
{
  test("kprobe:sys_open { @x++; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  map: @x\n"
       "   ++\n");
  test("kprobe:sys_open { ++@x; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  ++\n"
       "   map: @x\n");
  test("kprobe:sys_open { @x--; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  map: @x\n"
       "   --\n");
  test("kprobe:sys_open { --@x; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  --\n"
       "   map: @x\n");
}

TEST(Parser, bit_shifting)
{
  test("kprobe:do_nanosleep { @x = 1 << 10 }",
       "Program\n"
       " kprobe:do_nanosleep\n"
       "  =\n"
       "   map: @x\n"
       "   <<\n"
       "    int: 1\n"
       "    int: 10\n");
  test("kprobe:do_nanosleep { @x = 1024 >> 9 }",
       "Program\n"
       " kprobe:do_nanosleep\n"
       "  =\n"
       "   map: @x\n"
       "   >>\n"
       "    int: 1024\n"
       "    int: 9\n");
  test("kprobe:do_nanosleep / 2 < 1 >> 8 / { $x = 1 }",
       "Program\n"
       " kprobe:do_nanosleep\n"
       "  pred\n"
       "   <\n"
       "    int: 2\n"
       "    >>\n"
       "     int: 1\n"
       "     int: 8\n"
       "  =\n"
       "   variable: $x\n"
       "   int: 1\n");
}

TEST(Parser, ternary_int)
{
  test("kprobe:sys_open { @x = pid < 10000 ? 1 : 2 }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   map: @x\n"
       "   ?:\n"
       "    <\n"
       "     builtin: pid\n"
       "     int: 10000\n"
       "    int: 1\n"
       "    int: 2\n");
}

TEST(Parser, if_block)
{
  test("kprobe:sys_open { if (pid > 10000) { printf(\"%d is high\\n\", pid); } "
       "}",
       "Program\n"
       " kprobe:sys_open\n"
       "  if\n"
       "   >\n"
       "    builtin: pid\n"
       "    int: 10000\n"
       "   then\n"
       "    call: printf\n"
       "     string: %d is high\\n\n"
       "     builtin: pid\n");
}

TEST(Parser, if_stmt_if)
{
  test("kprobe:sys_open { if (pid > 10000) { printf(\"%d is high\\n\", pid); } "
       "@pid = pid; if (pid < 1000) { printf(\"%d is low\\n\", pid); } }",
       "Program\n"
       " kprobe:sys_open\n"
       "  if\n"
       "   >\n"
       "    builtin: pid\n"
       "    int: 10000\n"
       "   then\n"
       "    call: printf\n"
       "     string: %d is high\\n\n"
       "     builtin: pid\n"
       "  =\n"
       "   map: @pid\n"
       "   builtin: pid\n"
       "  if\n"
       "   <\n"
       "    builtin: pid\n"
       "    int: 1000\n"
       "   then\n"
       "    call: printf\n"
       "     string: %d is low\\n\n"
       "     builtin: pid\n");
}

TEST(Parser, if_block_variable)
{
  test("kprobe:sys_open { if (pid > 10000) { $s = 10; } }",
       "Program\n"
       " kprobe:sys_open\n"
       "  if\n"
       "   >\n"
       "    builtin: pid\n"
       "    int: 10000\n"
       "   then\n"
       "    =\n"
       "     variable: $s\n"
       "     int: 10\n");
}

TEST(Parser, if_else)
{
  test("kprobe:sys_open { if (pid > 10000) { $s = \"a\"; } else { $s= \"b\"; } "
       "printf(\"%d is high\\n\", pid, $s); }",
       "Program\n"
       " kprobe:sys_open\n"
       "  if\n"
       "   >\n"
       "    builtin: pid\n"
       "    int: 10000\n"
       "   then\n"
       "    =\n"
       "     variable: $s\n"
       "     string: a\n"
       "   else\n"
       "    =\n"
       "     variable: $s\n"
       "     string: b\n"
       "  call: printf\n"
       "   string: %d is high\\n\n"
       "   builtin: pid\n"
       "   variable: $s\n");
}

TEST(Parser, if_elseif)
{
  test("kprobe:f { if (pid > 10000) { $s = 10; } else if (pid < 10) { $s = 2; "
       "} }",
       "Program\n"
       " kprobe:f\n"
       "  if\n"
       "   >\n"
       "    builtin: pid\n"
       "    int: 10000\n"
       "   then\n"
       "    =\n"
       "     variable: $s\n"
       "     int: 10\n"
       "   else\n"
       "    if\n"
       "     <\n"
       "      builtin: pid\n"
       "      int: 10\n"
       "     then\n"
       "      =\n"
       "       variable: $s\n"
       "       int: 2\n");
}

TEST(Parser, if_elseif_else)
{
  test("kprobe:f { if (pid > 10000) { $s = 10; } else if (pid < 10) { $s = 2; "
       "} else { $s = 1 } }",
       "Program\n"
       " kprobe:f\n"
       "  if\n"
       "   >\n"
       "    builtin: pid\n"
       "    int: 10000\n"
       "   then\n"
       "    =\n"
       "     variable: $s\n"
       "     int: 10\n"
       "   else\n"
       "    if\n"
       "     <\n"
       "      builtin: pid\n"
       "      int: 10\n"
       "     then\n"
       "      =\n"
       "       variable: $s\n"
       "       int: 2\n"
       "     else\n"
       "      =\n"
       "       variable: $s\n"
       "       int: 1\n");
}

TEST(Parser, if_elseif_elseif_else)
{
  test("kprobe:f { if (pid > 10000) { $s = 10; } else if (pid < 10) { $s = 2; "
       "} else if (pid > 999999) { $s = 0 } else { $s = 1 } }",
       "Program\n"
       " kprobe:f\n"
       "  if\n"
       "   >\n"
       "    builtin: pid\n"
       "    int: 10000\n"
       "   then\n"
       "    =\n"
       "     variable: $s\n"
       "     int: 10\n"
       "   else\n"
       "    if\n"
       "     <\n"
       "      builtin: pid\n"
       "      int: 10\n"
       "     then\n"
       "      =\n"
       "       variable: $s\n"
       "       int: 2\n"
       "     else\n"
       "      if\n"
       "       >\n"
       "        builtin: pid\n"
       "        int: 999999\n"
       "       then\n"
       "        =\n"
       "         variable: $s\n"
       "         int: 0\n"
       "       else\n"
       "        =\n"
       "         variable: $s\n"
       "         int: 1\n");
}

TEST(Parser, unroll)
{
  test("kprobe:sys_open { $i = 0; unroll(5) { printf(\"i: %d\\n\", $i); $i = "
       "$i + 1; } }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   variable: $i\n"
       "   int: 0\n"
       "  unroll\n"
       "   int: 5\n"
       "   block\n"
       "    call: printf\n"
       "     string: i: %d\\n\n"
       "     variable: $i\n"
       "    =\n"
       "     variable: $i\n"
       "     +\n"
       "      variable: $i\n"
       "      int: 1\n");
}

TEST(Parser, ternary_str)
{
  test("kprobe:sys_open { @x = pid < 10000 ? \"lo\" : \"high\" }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   map: @x\n"
       "   ?:\n"
       "    <\n"
       "     builtin: pid\n"
       "     int: 10000\n"
       "    string: lo\n"
       "    string: high\n");
}

TEST(Parser, ternary_nested)
{
  test("kprobe:sys_open { @x = pid < 10000 ? pid < 5000 ? 1 : 2 : 3 }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   map: @x\n"
       "   ?:\n"
       "    <\n"
       "     builtin: pid\n"
       "     int: 10000\n"
       "    ?:\n"
       "     <\n"
       "      builtin: pid\n"
       "      int: 5000\n"
       "     int: 1\n"
       "     int: 2\n"
       "    int: 3\n");
}

TEST(Parser, call)
{
  test("kprobe:sys_open { @x = count(); @y = hist(1,2,3); delete(@x); }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   map: @x\n"
       "   call: count\n"
       "  =\n"
       "   map: @y\n"
       "   call: hist\n"
       "    int: 1\n"
       "    int: 2\n"
       "    int: 3\n"
       "  call: delete\n"
       "   map: @x\n");
}

TEST(Parser, call_unknown_function)
{
  test_parse_failure("kprobe:sys_open { myfunc() }", R"(
stdin:1:19-25: ERROR: Unknown function: myfunc
kprobe:sys_open { myfunc() }
                  ~~~~~~
)");

  test_parse_failure("k:f { probe(); }", R"(
stdin:1:7-12: ERROR: Unknown function: probe
k:f { probe(); }
      ~~~~~
)");
}

TEST(Parser, call_builtin)
{
  // Builtins should not be usable as function
  test_parse_failure("k:f { probe(\"blah\"); }", R"(
stdin:1:7-12: ERROR: Unknown function: probe
k:f { probe("blah"); }
      ~~~~~
)");

  test_parse_failure("k:f { probe(); }", R"(
stdin:1:7-12: ERROR: Unknown function: probe
k:f { probe(); }
      ~~~~~
)");

  test_parse_failure("k:f { probe(123); }", R"(
stdin:1:7-12: ERROR: Unknown function: probe
k:f { probe(123); }
      ~~~~~
)");
}

TEST(Parser, call_kaddr)
{
  test("kprobe:f { @ = kaddr(\"avenrun\") }",
       "Program\n"
       " kprobe:f\n"
       "  =\n"
       "   map: @\n"
       "   call: kaddr\n"
       "    string: avenrun\n");
}

TEST(Parser, multiple_probes)
{
  test("kprobe:sys_open { 1; } kretprobe:sys_open { 2; }",
       "Program\n"
       " kprobe:sys_open\n"
       "  int: 1\n"
       " kretprobe:sys_open\n"
       "  int: 2\n");
}

TEST(Parser, uprobe)
{
  test("uprobe:/my/program:func { 1; }",
       "Program\n"
       " uprobe:/my/program:func\n"
       "  int: 1\n");
  test("uprobe:/my/go/program:\"pkg.func\u2C51\" { 1; }",
       "Program\n"
       " uprobe:/my/go/program:pkg.func\u2C51\n"
       "  int: 1\n");
  test("uprobe:/with#hash:asdf { 1 }",
       "Program\n"
       " uprobe:/with#hash:asdf\n"
       "  int: 1\n");
  test("uprobe:/my/program:1234 { 1; }",
       "Program\n"
       " uprobe:/my/program:1234\n"
       "  int: 1\n");
  // Trailing alnum chars are allowed (turns the entire arg into a symbol name)
  test("uprobe:/my/program:1234abc { 1; }",
       "Program\n"
       " uprobe:/my/program:1234abc\n"
       "  int: 1\n");
  // Test `:`s in quoted string
  test("uprobe:/my/program:\"A::f\" { 1; }",
       "Program\n"
       " uprobe:/my/program:A::f\n"
       "  int: 1\n");

  // Language prefix
  test("uprobe:/my/program:cpp:func { 1; }",
       "Program\n"
       " uprobe:/my/program:cpp:func\n"
       "  int: 1\n");

  test("uprobe:/my/dir+/program:1234abc { 1; }",
       "Program\n"
       " uprobe:/my/dir+/program:1234abc\n"
       "  int: 1\n");

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
       "Program\n"
       " usdt:/my/program:probe\n"
       "  int: 1\n");
  // Without the escapes needed for C++ to compile:
  //    usdt:/my/program:"\"probe\"" { 1; }
  //
  test("usdt:/my/program:\"\\\"probe\\\"\" { 1; }",
       "Program\n"
       " usdt:/my/program:\"probe\"\n"
       "  int: 1\n");

  test_parse_failure("usdt { 1 }", R"(
stdin:1:1-5: ERROR: usdt probe type requires 2 or 3 arguments, found 0
usdt { 1 }
~~~~
)");
}

TEST(Parser, usdt_namespaced_probe)
{
  test("usdt:/my/program:namespace:probe { 1; }",
       "Program\n"
       " usdt:/my/program:namespace:probe\n"
       "  int: 1\n");
  test("usdt:/my/program*:namespace:probe { 1; }",
       "Program\n"
       " usdt:/my/program*:namespace:probe\n"
       "  int: 1\n");
  test("usdt:/my/*program:namespace:probe { 1; }",
       "Program\n"
       " usdt:/my/*program:namespace:probe\n"
       "  int: 1\n");
  test("usdt:*my/program*:namespace:probe { 1; }",
       "Program\n"
       " usdt:*my/program*:namespace:probe\n"
       "  int: 1\n");
}

TEST(Parser, escape_chars)
{
  test("kprobe:sys_open { \"newline\\nand "
       "tab\\tcr\\rbackslash\\\\quote\\\"here oct\\1009hex\\x309\" }",
       "Program\n"
       " kprobe:sys_open\n"
       "  string: newline\\nand tab\\tcr\\rbackslash\\\\quote\\\"here "
       "oct@9hex09\n");
}

TEST(Parser, begin_probe)
{
  test("BEGIN { 1 }",
       "Program\n"
       " BEGIN\n"
       "  int: 1\n");

  test_parse_failure("BEGIN:f { 1 }", R"(
stdin:1:1-8: ERROR: BEGIN probe type requires 0 arguments, found 1
BEGIN:f { 1 }
~~~~~~~
)");

  test_parse_failure("BEGIN:path:f { 1 }", R"(
stdin:1:1-13: ERROR: BEGIN probe type requires 0 arguments, found 2
BEGIN:path:f { 1 }
~~~~~~~~~~~~
)");
}

TEST(Parser, end_probe)
{
  test("END { 1 }",
       "Program\n"
       " END\n"
       "  int: 1\n");

  test_parse_failure("END:f { 1 }", R"(
stdin:1:1-6: ERROR: END probe type requires 0 arguments, found 1
END:f { 1 }
~~~~~
)");

  test_parse_failure("END:path:f { 1 }", R"(
stdin:1:1-11: ERROR: END probe type requires 0 arguments, found 2
END:path:f { 1 }
~~~~~~~~~~
)");
}

TEST(Parser, tracepoint_probe)
{
  test("tracepoint:sched:sched_switch { 1 }",
       "Program\n"
       " tracepoint:sched:sched_switch\n"
       "  int: 1\n");
  test("tracepoint:* { 1 }",
       "Program\n"
       " tracepoint:*:*\n"
       "  int: 1\n");

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

TEST(Parser, profile_probe)
{
  test("profile:ms:997 { 1 }",
       "Program\n"
       " profile:ms:997\n"
       "  int: 1\n");

  test_parse_failure("profile:ms:nan { 1 }", R"(
stdin:1:1-15: ERROR: stoull
Invalid rate of profile probe
profile:ms:nan { 1 }
~~~~~~~~~~~~~~
)");

  test_parse_failure("profile:f { 1 }", R"(
stdin:1:1-10: ERROR: profile probe type requires 2 arguments, found 1
profile:f { 1 }
~~~~~~~~~
)");

  test_parse_failure("profile { 1 }", R"(
stdin:1:1-8: ERROR: profile probe type requires 2 arguments, found 0
profile { 1 }
~~~~~~~
)");

  test_parse_failure("profile:s:1b { 1 }", R"(
stdin:1:1-13: ERROR: Found trailing non-numeric characters
Invalid rate of profile probe
profile:s:1b { 1 }
~~~~~~~~~~~~
)");
}

TEST(Parser, interval_probe)
{
  test("interval:s:1 { 1 }",
       "Program\n"
       " interval:s:1\n"
       "  int: 1\n");

  test("interval:s:1e3 { 1 }",
       "Program\n"
       " interval:s:1000\n"
       "  int: 1\n");

  test("interval:s:1_0_0_0 { 1 }",
       "Program\n"
       " interval:s:1000\n"
       "  int: 1\n");

  test_parse_failure("interval:s:1b { 1 }", R"(
stdin:1:1-14: ERROR: Found trailing non-numeric characters
Invalid rate of interval probe
interval:s:1b { 1 }
~~~~~~~~~~~~~
)");
}

TEST(Parser, software_probe)
{
  test("software:faults:1000 { 1 }",
       "Program\n"
       " software:faults:1000\n"
       "  int: 1\n");

  test("software:faults:1e3 { 1 }",
       "Program\n"
       " software:faults:1000\n"
       "  int: 1\n");

  test("software:faults:1_000 { 1 }",
       "Program\n"
       " software:faults:1000\n"
       "  int: 1\n");

  test_parse_failure("software:faults:1b { 1 }", R"(
stdin:1:1-19: ERROR: Found trailing non-numeric characters
Invalid count for software probe
software:faults:1b { 1 }
~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, hardware_probe)
{
  test("hardware:cache-references:1000000 { 1 }",
       "Program\n"
       " hardware:cache-references:1000000\n"
       "  int: 1\n");

  test("hardware:cache-references:1e6 { 1 }",
       "Program\n"
       " hardware:cache-references:1000000\n"
       "  int: 1\n");

  test("hardware:cache-references:1_000_000 { 1 }",
       "Program\n"
       " hardware:cache-references:1000000\n"
       "  int: 1\n");

  test_parse_failure("hardware:cache-references:1b { 1 }", R"(
stdin:1:1-29: ERROR: Found trailing non-numeric characters
Invalid count for hardware probe
hardware:cache-references:1b { 1 }
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, watchpoint_probe)
{
  test("watchpoint:1234:8:w { 1 }",
       "Program\n"
       " watchpoint:1234:8:w\n"
       "  int: 1\n");

  test_parse_failure("watchpoint:1b:8:w { 1 }", R"(
stdin:1:1-18: ERROR: Found trailing non-numeric characters
Invalid function/address argument
watchpoint:1b:8:w { 1 }
~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("watchpoint:1:8a:w { 1 }", R"(
stdin:1:1-18: ERROR: Found trailing non-numeric characters
Invalid length argument
watchpoint:1:8a:w { 1 }
~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("watchpoint:1b:8a:w { 1 }", R"(
stdin:1:1-19: ERROR: Found trailing non-numeric characters
Invalid function/address argument
watchpoint:1b:8a:w { 1 }
~~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("watchpoint:+arg0:8:rw { 1 }", R"(
stdin:1:1-22: ERROR: Invalid function/address argument
watchpoint:+arg0:8:rw { 1 }
~~~~~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("watchpoint:func1:8:rw { 1 }", R"(
stdin:1:1-22: ERROR: stoull
Invalid function/address argument
watchpoint:func1:8:rw { 1 }
~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, asyncwatchpoint_probe)
{
  test("asyncwatchpoint:1234:8:w { 1 }",
       "Program\n"
       " asyncwatchpoint:1234:8:w\n"
       "  int: 1\n");

  test_parse_failure("asyncwatchpoint:1b:8:w { 1 }", R"(
stdin:1:1-23: ERROR: Found trailing non-numeric characters
Invalid function/address argument
asyncwatchpoint:1b:8:w { 1 }
~~~~~~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("asyncwatchpoint:1:8a:w { 1 }", R"(
stdin:1:1-23: ERROR: Found trailing non-numeric characters
Invalid length argument
asyncwatchpoint:1:8a:w { 1 }
~~~~~~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("asyncwatchpoint:1b:8a:w { 1 }", R"(
stdin:1:1-24: ERROR: Found trailing non-numeric characters
Invalid function/address argument
asyncwatchpoint:1b:8a:w { 1 }
~~~~~~~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("asyncwatchpoint:+arg0:8:rw { 1 }", R"(
stdin:1:1-27: ERROR: Invalid function/address argument
asyncwatchpoint:+arg0:8:rw { 1 }
~~~~~~~~~~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("asyncwatchpoint:func1:8:rw { 1 }", R"(
stdin:1:1-27: ERROR: stoull
Invalid function/address argument
asyncwatchpoint:func1:8:rw { 1 }
~~~~~~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, multiple_attach_points_kprobe)
{
  test("BEGIN,kprobe:sys_open,uprobe:/bin/"
       "sh:foo,tracepoint:syscalls:sys_enter_* { 1 }",
       "Program\n"
       " BEGIN\n"
       " kprobe:sys_open\n"
       " uprobe:/bin/sh:foo\n"
       " tracepoint:syscalls:sys_enter_*\n"
       "  int: 1\n");
}

TEST(Parser, character_class_attach_point)
{
  test("kprobe:[Ss]y[Ss]_read { 1 }",
       "Program\n"
       " kprobe:[Ss]y[Ss]_read\n"
       "  int: 1\n");
}

TEST(Parser, wildcard_probetype)
{
  test("t*point:sched:sched_switch { 1; }",
       "Program\n"
       " tracepoint:sched:sched_switch\n"
       "  int: 1\n");
  test("*ware:* { 1; }",
       "Program\n"
       " hardware:*\n"
       " software:*\n"
       "  int: 1\n");
  test("*:/bin/sh:* { 1; }",
       "Program\n"
       " uprobe:/bin/sh:*\n"
       " usdt:/bin/sh:*\n"
       "  int: 1\n");

  test_parse_failure("iter:task* { }", R"(
stdin:1:1-11: ERROR: iter probe type does not support wildcards
iter:task* { }
~~~~~~~~~~
)");
}

TEST(Parser, wildcard_attach_points)
{
  test("kprobe:sys_* { 1 }",
       "Program\n"
       " kprobe:sys_*\n"
       "  int: 1\n");
  test("kprobe:*blah { 1 }",
       "Program\n"
       " kprobe:*blah\n"
       "  int: 1\n");
  test("kprobe:sys*blah { 1 }",
       "Program\n"
       " kprobe:sys*blah\n"
       "  int: 1\n");
  test("kprobe:* { 1 }",
       "Program\n"
       " kprobe:*\n"
       "  int: 1\n");
  test("kprobe:sys_* { @x = cpu*retval }",
       "Program\n"
       " kprobe:sys_*\n"
       "  =\n"
       "   map: @x\n"
       "   *\n"
       "    builtin: cpu\n"
       "    builtin: retval\n");
  test("kprobe:sys_* { @x = *arg0 }",
       "Program\n"
       " kprobe:sys_*\n"
       "  =\n"
       "   map: @x\n"
       "   dereference\n"
       "    builtin: arg0\n");
}

TEST(Parser, wildcard_path)
{
  test("uprobe:/my/program*:* { 1; }",
       "Program\n"
       " uprobe:/my/program*:*\n"
       "  int: 1\n");
  test("uprobe:/my/program*:func { 1; }",
       "Program\n"
       " uprobe:/my/program*:func\n"
       "  int: 1\n");
  test("uprobe:*my/program*:func { 1; }",
       "Program\n"
       " uprobe:*my/program*:func\n"
       "  int: 1\n");
  test("uprobe:/my/program*foo:func { 1; }",
       "Program\n"
       " uprobe:/my/program*foo:func\n"
       "  int: 1\n");
  test("usdt:/my/program*:* { 1; }",
       "Program\n"
       " usdt:/my/program*:*\n"
       "  int: 1\n");
  test("usdt:/my/program*:func { 1; }",
       "Program\n"
       " usdt:/my/program*:func\n"
       "  int: 1\n");
  test("usdt:*my/program*:func { 1; }",
       "Program\n"
       " usdt:*my/program*:func\n"
       "  int: 1\n");
  test("usdt:/my/program*foo:func { 1; }",
       "Program\n"
       " usdt:/my/program*foo:func\n"
       "  int: 1\n");
  // Make sure calls or builtins don't cause issues
  test("usdt:/my/program*avg:func { 1; }",
       "Program\n"
       " usdt:/my/program*avg:func\n"
       "  int: 1\n");
  test("usdt:/my/program*nsecs:func { 1; }",
       "Program\n"
       " usdt:/my/program*nsecs:func\n"
       "  int: 1\n");
}

TEST(Parser, dot_in_func)
{
  test("uprobe:/my/go/program:runtime.main.func1 { 1; }",
       "Program\n"
       " uprobe:/my/go/program:runtime.main.func1\n"
       "  int: 1\n");
}

TEST(Parser, wildcard_func)
{
  test("usdt:/my/program:abc*cd { 1; }",
       "Program\n"
       " usdt:/my/program:abc*cd\n"
       "  int: 1\n");
  test("usdt:/my/program:abc*c*d { 1; }",
       "Program\n"
       " usdt:/my/program:abc*c*d\n"
       "  int: 1\n");

  std::string keywords[] = {
    "arg0",
    "args",
    "curtask",
    "func",
    "gid"
    "rand",
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
         "Program\n"
         " usdt:/my/program:" +
             kw +
             "*c*d\n"
             "  int: 1\n");
    test("usdt:/my/program:abc*" + kw + "*c*d { 1; }",
         "Program\n"
         " usdt:/my/program:abc*" +
             kw +
             "*c*d\n"
             "  int: 1\n");
  }
}

TEST(Parser, short_map_name)
{
  test("kprobe:sys_read { @ = 1 }",
       "Program\n"
       " kprobe:sys_read\n"
       "  =\n"
       "   map: @\n"
       "   int: 1\n");
}

TEST(Parser, include)
{
  test("#include <stdio.h>\nkprobe:sys_read { @x = 1 }",
       "#include <stdio.h>\n"
       "\n"
       "Program\n"
       " kprobe:sys_read\n"
       "  =\n"
       "   map: @x\n"
       "   int: 1\n");
}

TEST(Parser, include_quote)
{
  test("#include \"stdio.h\"\nkprobe:sys_read { @x = 1 }",
       "#include \"stdio.h\"\n"
       "\n"
       "Program\n"
       " kprobe:sys_read\n"
       "  =\n"
       "   map: @x\n"
       "   int: 1\n");
}

TEST(Parser, include_multiple)
{
  test("#include <stdio.h>\n#include \"blah\"\n#include "
       "<foo.h>\nkprobe:sys_read { @x = 1 }",
       "#include <stdio.h>\n"
       "#include \"blah\"\n"
       "#include <foo.h>\n"
       "\n"
       "Program\n"
       " kprobe:sys_read\n"
       "  =\n"
       "   map: @x\n"
       "   int: 1\n");
}

TEST(Parser, brackets)
{
  test("kprobe:sys_read { (arg0*arg1) }",
       "Program\n"
       " kprobe:sys_read\n"
       "  *\n"
       "   builtin: arg0\n"
       "   builtin: arg1\n");
}

TEST(Parser, cast_simple_type)
{
  test("kprobe:sys_read { (int32)arg0; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (int32)\n"
       "   builtin: arg0\n");
}

TEST(Parser, cast_simple_type_pointer)
{
  test("kprobe:sys_read { (int32 *)arg0; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (int32 *)\n"
       "   builtin: arg0\n");
}

TEST(Parser, cast_sized_type)
{
  test("kprobe:sys_read { (str_t[1])arg0; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (string[1])\n"
       "   builtin: arg0\n");
}

TEST(Parser, cast_sized_type_pointer)
{
  test("kprobe:sys_read { (str_t[1] *)arg0; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (string[1] *)\n"
       "   builtin: arg0\n");
}

TEST(Parser, cast_struct)
{
  test("kprobe:sys_read { (struct mytype)arg0; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (struct mytype)\n"
       "   builtin: arg0\n");
  test("kprobe:sys_read { (union mytype)arg0; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (union mytype)\n"
       "   builtin: arg0\n");
}

TEST(Parser, cast_struct_ptr)
{
  test("kprobe:sys_read { (struct mytype*)arg0; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (struct mytype *)\n"
       "   builtin: arg0\n");
  test("kprobe:sys_read { (union mytype*)arg0; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (union mytype *)\n"
       "   builtin: arg0\n");
}

TEST(Parser, cast_typedef)
{
  test("kprobe:sys_read { (mytype)arg0; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (mytype)\n"
       "   builtin: arg0\n");
}

TEST(Parser, cast_ptr_typedef)
{
  test("kprobe:sys_read { (mytype*)arg0; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (mytype *)\n"
       "   builtin: arg0\n");
}

TEST(Parser, cast_multiple_pointer)
{
  test("kprobe:sys_read { (int32 *****)arg0; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (int32 * * * * *)\n"
       "   builtin: arg0\n");
}

TEST(Parser, cast_or_expr1)
{
  test("kprobe:sys_read { (struct mytype)*arg0; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (struct mytype)\n"
       "   dereference\n"
       "    builtin: arg0\n");
}

TEST(Parser, cast_or_expr2)
{
  test("kprobe:sys_read { (arg1)*arg0; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  *\n"
       "   builtin: arg1\n"
       "   builtin: arg0\n");
}

TEST(Parser, cast_precedence)
{
  test("kprobe:sys_read { (struct mytype)arg0.field; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (struct mytype)\n"
       "   .\n"
       "    builtin: arg0\n"
       "    field\n");

  test("kprobe:sys_read { (struct mytype*)arg0->field; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  (struct mytype *)\n"
       "   .\n"
       "    dereference\n"
       "     builtin: arg0\n"
       "    field\n");

  test("kprobe:sys_read { (struct mytype)arg0+123; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  +\n"
       "   (struct mytype)\n"
       "    builtin: arg0\n"
       "   int: 123\n");
}

TEST(Parser, sizeof_expression)
{
  test("kprobe:sys_read { sizeof(arg0); }",
       "Program\n"
       " kprobe:sys_read\n"
       "  sizeof: \n"
       "   builtin: arg0\n");
}

TEST(Parser, sizeof_type)
{
  test("kprobe:sys_read { sizeof(int32); }",
       "Program\n"
       " kprobe:sys_read\n"
       "  sizeof: \n");
}

TEST(Parser, offsetof_type)
{
  test("struct Foo { int x; } BEGIN { offsetof(struct Foo, x); }",
       "struct Foo { int x; };\n"
       "\n"
       "Program\n"
       " BEGIN\n"
       "  offsetof: \n"
       "   struct Foo\n"
       "   x\n");
}

TEST(Parser, offsetof_expression)
{
  test("struct Foo { int x; }; "
       "BEGIN { $foo = (struct Foo *)0; offsetof(*$foo, x); }",
       "struct Foo { int x; };;\n"
       "\n"
       "Program\n"
       " BEGIN\n"
       "  =\n"
       "   variable: $foo\n"
       "   (struct Foo *)\n"
       "    int: 0\n"
       "  offsetof: \n"
       "   dereference\n"
       "    variable: $foo\n"
       "   x\n");
}

TEST(Parser, dereference_precedence)
{
  test("kprobe:sys_read { *@x+1 }",
       "Program\n"
       " kprobe:sys_read\n"
       "  +\n"
       "   dereference\n"
       "    map: @x\n"
       "   int: 1\n");

  test("kprobe:sys_read { *@x**@y }",
       "Program\n"
       " kprobe:sys_read\n"
       "  *\n"
       "   dereference\n"
       "    map: @x\n"
       "   dereference\n"
       "    map: @y\n");

  test("kprobe:sys_read { *@x*@y }",
       "Program\n"
       " kprobe:sys_read\n"
       "  *\n"
       "   dereference\n"
       "    map: @x\n"
       "   map: @y\n");

  test("kprobe:sys_read { *@x.myfield }",
       "Program\n"
       " kprobe:sys_read\n"
       "  dereference\n"
       "   .\n"
       "    map: @x\n"
       "    myfield\n");
}

TEST(Parser, field_access)
{
  test("kprobe:sys_read { @x.myfield; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  .\n"
       "   map: @x\n"
       "   myfield\n");

  test("kprobe:sys_read { @x->myfield; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  .\n"
       "   dereference\n"
       "    map: @x\n"
       "   myfield\n");
}

TEST(Parser, field_access_builtin)
{
  test("kprobe:sys_read { @x.count; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  .\n"
       "   map: @x\n"
       "   count\n");

  test("kprobe:sys_read { @x->count; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  .\n"
       "   dereference\n"
       "    map: @x\n"
       "   count\n");
}

TEST(Parser, array_access)
{
  test("kprobe:sys_read { x[index]; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  []\n"
       "   identifier: x\n"
       "   identifier: index\n");

  test("kprobe:sys_read { $val = x[index]; }",
       "Program\n"
       " kprobe:sys_read\n"
       "  =\n"
       "   variable: $val\n"
       "   []\n"
       "    identifier: x\n"
       "    identifier: index\n");
}

TEST(Parser, cstruct)
{
  test("struct Foo { int x, y; char *str; } kprobe:sys_read { 1; }",
       "struct Foo { int x, y; char *str; };\n"
       "\n"
       "Program\n"
       " kprobe:sys_read\n"
       "  int: 1\n");
}

TEST(Parser, cstruct_semicolon)
{
  test("struct Foo { int x, y; char *str; }; kprobe:sys_read { 1; }",
       "struct Foo { int x, y; char *str; };;\n"
       "\n"
       "Program\n"
       " kprobe:sys_read\n"
       "  int: 1\n");
}

TEST(Parser, cstruct_nested)
{
  test("struct Foo { struct { int x; } bar; } kprobe:sys_read { 1; }",
       "struct Foo { struct { int x; } bar; };\n"
       "\n"
       "Program\n"
       " kprobe:sys_read\n"
       "  int: 1\n");
}

TEST(Parser, unexpected_symbol)
{
  BPFtrace bpftrace;
  std::stringstream out;
  Driver driver(bpftrace, out);
  EXPECT_EQ(driver.parse_str("i:s:1 { < }"), 1);
  std::string expected =
      R"(stdin:1:9-10: ERROR: syntax error, unexpected <
i:s:1 { < }
        ~
)";
  EXPECT_EQ(out.str(), expected);
}

TEST(Parser, string_with_tab)
{
  BPFtrace bpftrace;
  std::stringstream out;
  Driver driver(bpftrace, out);
  EXPECT_EQ(driver.parse_str("i:s:1\t\t\t$a"), 1);
  std::string expected =
      R"(stdin:1:9-11: ERROR: syntax error, unexpected variable, expecting {
i:s:1            $a
                 ~~
)";
  EXPECT_EQ(out.str(), expected);
}

TEST(Parser, unterminated_string)
{
  BPFtrace bpftrace;
  std::stringstream out;
  Driver driver(bpftrace, out);
  EXPECT_EQ(driver.parse_str("kprobe:f { \"asdf }"), 1);
  std::string expected =
      R"(stdin:1:12-19: ERROR: unterminated string
kprobe:f { "asdf }
           ~~~~~~~
stdin:1:12-19: ERROR: syntax error, unexpected end of file
kprobe:f { "asdf }
           ~~~~~~~
)";
  EXPECT_EQ(out.str(), expected);
}

TEST(Parser, kprobe_offset)
{
  test("k:fn+1 {}",
       "Program\n"
       " kprobe:fn+1\n");
  test("k:fn+0x10 {}",
       "Program\n"
       " kprobe:fn+16\n");

  test("k:\"fn.abc\"+1 {}",
       "Program\n"
       " kprobe:fn.abc+1\n");
  test("k:\"fn.abc\"+0x10 {}",
       "Program\n"
       " kprobe:fn.abc+16\n");

  test_parse_failure("k:asdf+123abc", R"(
stdin:1:1-14: ERROR: unexpected end of file, expected {
k:asdf+123abc
~~~~~~~~~~~~~
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
       "Program\n"
       " uprobe:./test:fn+1\n");
  test("u:./test:fn+0x10 {}",
       "Program\n"
       " uprobe:./test:fn+16\n");

  test("u:./test:\"fn.abc\"+1 {}",
       "Program\n"
       " uprobe:./test:fn.abc+1\n");
  test("u:./test:\"fn.abc\"+0x10 {}",
       "Program\n"
       " uprobe:./test:fn.abc+16\n");
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
stdin:1:9-14: ERROR: syntax error, unexpected ++, expecting ; or }
i:s:1 { @=5++}
        ~~~~~
)");

  test_parse_failure("i:s:1 { @=++5}", R"(
stdin:1:9-14: ERROR: syntax error, unexpected integer
i:s:1 { @=++5}
        ~~~~~
)");

  test_parse_failure("i:s:1 { @=5--}", R"(
stdin:1:9-14: ERROR: syntax error, unexpected --, expecting ; or }
i:s:1 { @=5--}
        ~~~~~
)");

  test_parse_failure("i:s:1 { @=--5}", R"(
stdin:1:9-14: ERROR: syntax error, unexpected integer
i:s:1 { @=--5}
        ~~~~~
)");

  test_parse_failure("i:s:1 { @=\"a\"++}", R"(
stdin:1:9-16: ERROR: syntax error, unexpected ++, expecting ; or }
i:s:1 { @="a"++}
        ~~~~~~~
)");
}

TEST(Parser, long_param_overflow)
{
  BPFtrace bpftrace;
  std::stringstream out;
  Driver driver(bpftrace, out);
  EXPECT_NO_THROW(
      driver.parse_str("i:s:100 { @=$111111111111111111111111111 }"));
  std::string expected = "stdin:1:11-41: ERROR: param "
                         "$111111111111111111111111111 is out of "
                         "integer range [1, " +
                         std::to_string(std::numeric_limits<long>::max()) +
                         "]\n" +
                         "i:s:100 { @=$111111111111111111111111111 }\n" +
                         "          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
  EXPECT_EQ(out.str(), expected);
}

TEST(Parser, empty_arguments)
{
  test_parse_failure("::k::vfs_open:: { 1 }", R"(
stdin:1:1-1: ERROR: No attach points for probe
::k::vfs_open:: { 1 }

)");

  // Error location is incorrect: #3063
  test_parse_failure("k:vfs_open:: { 1 }", R"(
stdin:1:1-14: ERROR: kprobe probe type requires 1 or 2 arguments, found 3
k:vfs_open:: { 1 }
~~~~~~~~~~~~~
)");

  test_parse_failure(":w:0x10000000:8:rw { 1 }", R"(
stdin:1:1-1: ERROR: No attach points for probe
:w:0x10000000:8:rw { 1 }

)");
}

TEST(Parser, int_notation)
{
  test("k:f { print(1e6); }",
       "Program\n kprobe:f\n  call: print\n   int: 1000000\n");
  test("k:f { print(5e9); }",
       "Program\n kprobe:f\n  call: print\n   int: 5000000000\n");
  test("k:f { print(1e1_0); }",
       "Program\n kprobe:f\n  call: print\n   int: 10000000000\n");
  test("k:f { print(1_000_000_000_0); }",
       "Program\n kprobe:f\n  call: print\n   int: 10000000000\n");
  test("k:f { print(1_0_0_0_00_0_000_0); }",
       "Program\n kprobe:f\n  call: print\n   int: 10000000000\n");
  test("k:f { print(123_456_789_0); }",
       "Program\n kprobe:f\n  call: print\n   int: 1234567890\n");
  test("k:f { print(0xe5); }",
       "Program\n kprobe:f\n  call: print\n   int: 229\n");
  test("k:f { print(0x5e5); }",
       "Program\n kprobe:f\n  call: print\n   int: 1509\n");
  test("k:f { print(0xeeee); }",
       "Program\n kprobe:f\n  call: print\n   int: 61166\n");
  test("k:f { print(0777); }",
       "Program\n kprobe:f\n  call: print\n   int: 511\n");
  test("k:f { print(0123); }",
       "Program\n kprobe:f\n  call: print\n   int: 83\n");

  test("k:f { print(1_000u); }",
       "Program\n kprobe:f\n  call: print\n   int: 1000\n");
  test("k:f { print(1_000ul); }",
       "Program\n kprobe:f\n  call: print\n   int: 1000\n");
  test("k:f { print(1_000ull); }",
       "Program\n kprobe:f\n  call: print\n   int: 1000\n");
  test("k:f { print(1_000l); }",
       "Program\n kprobe:f\n  call: print\n   int: 1000\n");
  test("k:f { print(1_000ll); }",
       "Program\n kprobe:f\n  call: print\n   int: 1000\n");

  test_parse_failure("k:f { print(5e-9); }", R"(
stdin:1:7-15: ERROR: syntax error, unexpected identifier, expecting ) or ","
k:f { print(5e-9); }
      ~~~~~~~~
)");

  test_parse_failure("k:f { print(1e17); }", R"(
stdin:1:7-17: ERROR: Exponent will overflow integer range: 17
k:f { print(1e17); }
      ~~~~~~~~~~
)");

  test_parse_failure("k:f { print(12e4); }", R"(
stdin:1:7-17: ERROR: Coefficient part of scientific literal must be in range (0,9), got: 12
k:f { print(12e4); }
      ~~~~~~~~~~
)");

  test_parse_failure("k:f { print(1_1e100); }", R"(
stdin:1:7-20: ERROR: Coefficient part of scientific literal must be in range (0,9), got: 11
k:f { print(1_1e100); }
      ~~~~~~~~~~~~~
)");

  test_parse_failure("k:f { print(1e1_1_); }", R"(
stdin:1:7-19: ERROR: syntax error, unexpected identifier, expecting ) or ","
k:f { print(1e1_1_); }
      ~~~~~~~~~~~~
)");

  test_parse_failure("k:f { print(1_1_e100); }", R"(
stdin:1:7-21: ERROR: syntax error, unexpected identifier, expecting ) or ","
k:f { print(1_1_e100); }
      ~~~~~~~~~~~~~~
)");

  test_parse_failure("k:f { print(1_1_); }", R"(
stdin:1:7-17: ERROR: syntax error, unexpected identifier, expecting ) or ","
k:f { print(1_1_); }
      ~~~~~~~~~~
)");

  test_parse_failure("k:f { print(1ulll); }", R"(
stdin:1:7-18: ERROR: syntax error, unexpected identifier, expecting ) or ","
k:f { print(1ulll); }
      ~~~~~~~~~~~
)");

  test_parse_failure("k:f { print(1lul); }", R"(
stdin:1:7-17: ERROR: syntax error, unexpected identifier, expecting ) or ","
k:f { print(1lul); }
      ~~~~~~~~~~
)");
}

TEST(Parser, while_loop)
{
  test("i:ms:100 { $a = 0; while($a < 10) { $a++ }}",
       R"PROG(Program
 interval:ms:100
  =
   variable: $a
   int: 0
  while(
   <
    variable: $a
    int: 10
   )
    variable: $a
     ++
)PROG");
}

TEST(Parser, tuple_assignment_error_message)
{
  BPFtrace bpftrace;
  std::stringstream out;
  Driver driver(bpftrace, out);
  EXPECT_EQ(driver.parse_str("i:s:1 { @x = (1, 2); $x.1 = 1; }"), 1);
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
stdin:1:16-17: ERROR: syntax error, unexpected =, expecting ; or }
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

  test_parse_failure("i:s:1 { (1, \"two\", (3, 4)).5 = \"six\"; }", R"(
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
  char in_cstr[64];
  char out_cstr[64];

  snprintf(in_cstr, sizeof(in_cstr), "watchpoint:0x%lx:4:w { 1; }", ULONG_MAX);
  snprintf(out_cstr,
           sizeof(out_cstr),
           "Program\n"
           " watchpoint:%lu:4:w\n"
           "  int: 1\n",
           ULONG_MAX);
  test(std::string(in_cstr), std::string(out_cstr));
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
stdin:1:22-46: ERROR: tracepoint probe type requires 2 arguments, found 1
uprobe:asdf:Stream {} tracepoint:only_one_arg {}
                     ~~~~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, config)
{
  test("config = { blah = 5 } BEGIN {}", R"(
Program
 config
  =
   config var: blah
   int: 5
 BEGIN
)");

  test("config = { blah = 5; } BEGIN {}", R"(
Program
 config
  =
   config var: blah
   int: 5
 BEGIN
)");

  test("config = { blah = 5; zoop = \"a\"; } BEGIN {}", R"(
Program
 config
  =
   config var: blah
   int: 5
  =
   config var: zoop
   string: a
 BEGIN
)");

  test("config = {} BEGIN {}", R"(
Program
 config
 BEGIN
)");
}

TEST(Parser, config_error)
{
  test_parse_failure("i:s:1 { exit(); } config = { BPFTRACE_STACK_MODE=perf }",
                     R"(
stdin:1:19-25: ERROR: syntax error, unexpected config, expecting {
i:s:1 { exit(); } config = { BPFTRACE_STACK_MODE=perf }
                  ~~~~~~
)");

  test_parse_failure("config = { exit(); } i:s:1 { exit(); }", R"(
stdin:1:12-16: ERROR: syntax error, unexpected call, expecting } or identifier
config = { exit(); } i:s:1 { exit(); }
           ~~~~
)");

  test_parse_failure("config = { @start = nsecs; } i:s:1 { exit(); }", R"(
stdin:1:12-18: ERROR: syntax error, unexpected map, expecting } or identifier
config = { @start = nsecs; } i:s:1 { exit(); }
           ~~~~~~
)");

  test_parse_failure("BEGIN { @start = nsecs; } config = { "
                     "BPFTRACE_STACK_MODE=perf } i:s:1 { exit(); }",
                     R"(
stdin:1:27-33: ERROR: syntax error, unexpected config, expecting {
BEGIN { @start = nsecs; } config = { BPFTRACE_STACK_MODE=perf } i:s:1 { exit(); }
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
stdin:1:47-67: ERROR: syntax error, unexpected =, expecting ; or }
config = { BPFTRACE_STACK_MODE=perf } i:s:1 { BPFTRACE_MAX_PROBES=2; exit(); }
                                              ~~~~~~~~~~~~~~~~~~~~
)");

  test_parse_failure("config { BPFTRACE_STACK_MODE=perf } i:s:1 { exit(); }",
                     R"(
stdin:1:8-9: ERROR: syntax error, unexpected {, expecting =
config { BPFTRACE_STACK_MODE=perf } i:s:1 { exit(); }
       ~
)");

  test_parse_failure("BPFTRACE_STACK_MODE=perf; i:s:1 { exit(); }", R"(
stdin:1:1-21: ERROR: syntax error, unexpected =, expecting {
BPFTRACE_STACK_MODE=perf; i:s:1 { exit(); }
~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(Parser, keywords_as_identifiers)
{
  std::vector<std::string> keywords = { "break",    "config", "continue",
                                        "else",     "for",    "if",
                                        "offsetof", "return", "sizeof",
                                        "unroll",   "while" };
  for (const auto &keyword : keywords) {
    test("BEGIN { $x = (struct Foo*)0; $x->" + keyword + "; }",
         "Program\n BEGIN\n  =\n   variable: $x\n   (struct Foo *)\n    int: "
         "0\n "
         " .\n   dereference\n    variable: $x\n   " +
             keyword + "\n");
    test("BEGIN { $x = (struct Foo)0; $x." + keyword + "; }",
         "Program\n BEGIN\n  =\n   variable: $x\n   (struct Foo)\n    int: 0\n "
         " .\n   variable: $x\n   " +
             keyword + "\n");
    test("BEGIN { $x = offsetof(*curtask, " + keyword + "); }",
         "Program\n BEGIN\n  =\n   variable: $x\n   offsetof: \n    "
         "dereference\n     builtin: curtask\n    " +
             keyword + "\n");
  }
}

TEST(Parser, subprog_probe_mixed)
{
  test("i:s:1 {} fn f1(): void {} i:s:1 {} fn f2(): void {}",
       "Program\n"
       " f1: void()\n"
       " f2: void()\n"
       " interval:s:1\n"
       " interval:s:1\n");
}

TEST(Parser, subprog_void_no_args)
{
  test("fn f(): void {}",
       "Program\n"
       " f: void()\n");
}

TEST(Parser, subprog_invalid_return_type)
{
  // Error location is incorrect: #3063
  test_parse_failure("fn f(): nonexistent {}", R"(
stdin:1:9-21: ERROR: syntax error, unexpected identifier, expecting struct or integer type or builtin type or sized type
fn f(): nonexistent {}
        ~~~~~~~~~~~~
)");
}

TEST(Parser, subprog_one_arg)
{
  test("fn f($a : uint8): void {}",
       "Program\n"
       " f: void($a : unsigned int8)\n");
}

TEST(Parser, subprog_two_args)
{
  test("fn f($a : uint8, $b : uint8): void {}",
       "Program\n"
       " f: void($a : unsigned int8, $b : unsigned int8)\n");
}

TEST(Parser, subprog_string_arg)
{
  test("fn f($a : str_t[16]): void {}",
       "Program\n"
       " f: void($a : string[16])\n");
}

TEST(Parser, subprog_struct_arg)
{
  test("fn f($a: struct x): void {}",
       "Program\n"
       " f: void($a : struct x)\n");
}

TEST(Parser, subprog_union_arg)
{
  test("fn f($a : union x): void {}",
       "Program\n"
       " f: void($a : union x)\n");
}

TEST(Parser, subprog_enum_arg)
{
  test("fn f($a : enum x): void {}",
       "Program\n"
       " f: void($a : enum x)\n");
}

TEST(Parser, subprog_invalid_arg)
{
  // Error location is incorrect: #3063
  test_parse_failure("fn f($x : invalid): void {}", R"(
stdin:1:11-19: ERROR: syntax error, unexpected identifier, expecting struct or integer type or builtin type or sized type
fn f($x : invalid): void {}
          ~~~~~~~~
)");
}

TEST(Parser, subprog_return)
{
  test("fn f(): void { return 1 + 1; }",
       "Program\n"
       " f: void()\n"
       "  return\n"
       "   +\n"
       "    int: 1\n"
       "    int: 1\n");
}

TEST(Parser, subprog_string)
{
  test("fn f(): str_t[16] {}",
       "Program\n"
       " f: string[16]()\n");
}

TEST(Parser, subprog_struct)
{
  test("fn f(): struct x {}",
       "Program\n"
       " f: struct x()\n");
}

TEST(Parser, subprog_union)
{
  test("fn f(): union x {}",
       "Program\n"
       " f: union x()\n");
}

TEST(Parser, subprog_enum)
{
  test("fn f(): enum x {}",
       "Program\n"
       " f: enum x()\n");
}

TEST(Parser, for_loop)
{
  test("BEGIN { for ($kv : @map) { print($kv) } }", R"(
Program
 BEGIN
  for
   decl
    variable: $kv
   expr
    map: @map
   stmts
    call: print
     variable: $kv
)");

  // Error location is incorrect: #3063
  // No body
  test_parse_failure("BEGIN { for ($kv : @map) print($kv); }", R"(
stdin:1:27-32: ERROR: syntax error, unexpected call, expecting {
BEGIN { for ($kv : @map) print($kv); }
                          ~~~~~
)");

  // Map for decl
  test_parse_failure("BEGIN { for (@kv : @map) { } }", R"(
stdin:1:13-17: ERROR: syntax error, unexpected map, expecting variable
BEGIN { for (@kv : @map) { } }
            ~~~~
)");
}

} // namespace parser
} // namespace test
} // namespace bpftrace
