#include <limits.h>
#include <sstream>

#include "gtest/gtest.h"
#include "driver.h"
#include "printer.h"

namespace bpftrace {
namespace test {
namespace parser {

using Printer = ast::Printer;

void test_parse_failure(BPFtrace &bpftrace, const std::string &input)
{
  std::stringstream out;
  Driver driver(bpftrace, out);
  ASSERT_EQ(driver.parse_str(input), 1);
}

void test_parse_failure(const std::string &input)
{
  BPFtrace bpftrace;
  test_parse_failure(bpftrace, input);
}

void test(BPFtrace &bpftrace,
          const std::string &input,
          const std::string &output)
{
  Driver driver(bpftrace);
  ASSERT_EQ(driver.parse_str(input), 0);

  std::ostringstream out;
  Printer printer(out);
  printer.print(driver.root_);
  EXPECT_EQ(output, out.str());
}

void test(const std::string &input, const std::string &output)
{
  BPFtrace bpftrace;
  test(bpftrace, input, output);
}

TEST(Parser, builtin_variables)
{
  test("kprobe:f { pid }", "Program\n kprobe:f\n  builtin: pid\n");
  test("kprobe:f { tid }", "Program\n kprobe:f\n  builtin: tid\n");
  test("kprobe:f { cgroup }", "Program\n kprobe:f\n  builtin: cgroup\n");
  test("kprobe:f { uid }", "Program\n kprobe:f\n  builtin: uid\n");
  test("kprobe:f { username }", "Program\n kprobe:f\n  builtin: username\n");
  test("kprobe:f { gid }", "Program\n kprobe:f\n  builtin: gid\n");
  test("kprobe:f { nsecs }", "Program\n kprobe:f\n  builtin: nsecs\n");
  test("kprobe:f { elapsed }", "Program\n kprobe:f\n  builtin: elapsed\n");
  test("kprobe:f { cpu }", "Program\n kprobe:f\n  builtin: cpu\n");
  test("kprobe:f { curtask }", "Program\n kprobe:f\n  builtin: curtask\n");
  test("kprobe:f { rand }", "Program\n kprobe:f\n  builtin: rand\n");
  test("kprobe:f { ctx }", "Program\n kprobe:f\n  builtin: ctx\n");
  test("kprobe:f { comm }", "Program\n kprobe:f\n  builtin: comm\n");
  test("kprobe:f { kstack }", "Program\n kprobe:f\n  builtin: kstack\n");
  test("kprobe:f { ustack }", "Program\n kprobe:f\n  builtin: ustack\n");
  test("kprobe:f { arg0 }", "Program\n kprobe:f\n  builtin: arg0\n");
  test("kprobe:f { sarg0 }", "Program\n kprobe:f\n  builtin: sarg0\n");
  test("kprobe:f { retval }", "Program\n kprobe:f\n  builtin: retval\n");
  test("kprobe:f { func }", "Program\n kprobe:f\n  builtin: func\n");
  test("kprobe:f { probe }", "Program\n kprobe:f\n  builtin: probe\n");
  test("kprobe:f { args }", "Program\n kprobe:f\n  builtin: args\n");
}

TEST(Parser, positional_param)
{
  test("kprobe:f { $1 }", "Program\n kprobe:f\n  param: $1\n");
  test_parse_failure("kprobe:f { $0 }");
}

TEST(Parser, positional_param_count)
{
  test("kprobe:f { $# }", "Program\n kprobe:f\n  param: $#\n");
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

  test_parse_failure(bpftrace, R"PROG(uprobe:$1a" { 1 })PROG");
  test_parse_failure(bpftrace, R"PROG(uprobe:$a" { 1 })PROG");
  test_parse_failure(bpftrace, R"PROG(uprobe:$-1" { 1 })PROG");
  test_parse_failure(bpftrace,
                     R"PROG(uprobe:$999999999999999999999999" { 1 })PROG");
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
  test("kprobe:sys_open / 1 <= 2 && (9 - 4 != 5*10 || ~0) || comm == \"string\" /\n"
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
  test("kprobe:sys_open { if (pid > 10000) { printf(\"%d is high\\n\", pid); } }",
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
  test("kprobe:sys_open { if (pid > 10000) { printf(\"%d is high\\n\", pid); } @pid = pid; if (pid < 1000) { printf(\"%d is low\\n\", pid); } }",
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
  test("kprobe:sys_open { if (pid > 10000) { $s = \"a\"; } else { $s= \"b\"; } printf(\"%d is high\\n\", pid, $s); }",
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
  test_parse_failure("kprobe:sys_open { myfunc() }");
  test_parse_failure("k:f { probe(); }");
}

TEST(Parser, call_builtin)
{
  // Builtins should not be usable as function
  test_parse_failure("k:f { nsecs(); }");
  test_parse_failure("k:f { nsecs  (); }");
  test_parse_failure("k:f { nsecs(\"abc\"); }");
  test_parse_failure("k:f { nsecs(123); }");

  test_parse_failure("k:f { probe(\"blah\"); }");
  test_parse_failure("k:f { probe(); }");
  test_parse_failure("k:f { probe(123); }");
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
  test ("uprobe:/with#hash:asdf { 1 }",
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

  test_parse_failure("uprobe:f { 1 }");
  test_parse_failure("uprobe { 1 }");
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

  test_parse_failure("usdt { 1 }");
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
  test("kprobe:sys_open { \"newline\\nand tab\\tcr\\rbackslash\\\\quote\\\"here oct\\1009hex\\x309\" }",
      "Program\n"
      " kprobe:sys_open\n"
      "  string: newline\\nand tab\\tcr\\rbackslash\\\\quote\\\"here oct@9hex09\n");
}

TEST(Parser, begin_probe)
{
  test("BEGIN { 1 }",
      "Program\n"
      " BEGIN\n"
      "  int: 1\n");

  test_parse_failure("BEGIN:f { 1 }");
  test_parse_failure("BEGIN:path:f { 1 }");
}

TEST(Parser, end_probe)
{
  test("END { 1 }",
       "Program\n"
       " END\n"
       "  int: 1\n");

  test_parse_failure("END:f { 1 }");
  test_parse_failure("END:path:f { 1 }");
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

  test_parse_failure("tracepoint:f { 1 }");
  test_parse_failure("tracepoint { 1 }");
}

TEST(Parser, profile_probe)
{
  test("profile:ms:997 { 1 }",
      "Program\n"
      " profile:ms:997\n"
      "  int: 1\n");

  test_parse_failure("profile:ms:nan { 1 }");
  test_parse_failure("profile:f { 1 }");
  test_parse_failure("profile { 1 }");
  test_parse_failure("profile:s:1b { 1 }");
}

TEST(Parser, interval_probe)
{
  test("interval:s:1 { 1 }",
      "Program\n"
      " interval:s:1\n"
      "  int: 1\n");

  test_parse_failure("interval:s:1b { 1 }");
}

TEST(Parser, software_probe)
{
  test("software:faults:1000 { 1 }",
      "Program\n"
      " software:faults:1000\n"
      "  int: 1\n");

  test_parse_failure("software:faults:1b { 1 }");
}

TEST(Parser, hardware_probe)
{
  test("hardware:cache-references:1000000 { 1 }",
      "Program\n"
      " hardware:cache-references:1000000\n"
      "  int: 1\n");

  test_parse_failure("hardware:cache-references:1b { 1 }");
}

TEST(Parser, watchpoint_probe)
{
  test("watchpoint:1234:8:w { 1 }",
       "Program\n"
       " watchpoint:1234:8:w\n"
       "  int: 1\n");

  test_parse_failure("watchpoint:1b:8:w { 1 }");
  test_parse_failure("watchpoint:1:8a:w { 1 }");
  test_parse_failure("watchpoint:1b:8a:w { 1 }");
  test_parse_failure("watchpoint:+arg0:8:rw { 1 }");
  test_parse_failure("watchpoint:func1:8:rw { 1 }");
}

TEST(Parser, asyncwatchpoint_probe)
{
  test("asyncwatchpoint:1234:8:w { 1 }",
       "Program\n"
       " asyncwatchpoint:1234:8:w\n"
       "  int: 1\n");

  test_parse_failure("asyncwatchpoint:1b:8:w { 1 }");
  test_parse_failure("asyncwatchpoint:1:8a:w { 1 }");
  test_parse_failure("asyncwatchpoint:1b:8a:w { 1 }");
  test_parse_failure("asyncwatchpoint:+arg0:8:rw { 1 }");
  test_parse_failure("asyncwatchpoint:func1:8:rw { 1 }");
}

TEST(Parser, multiple_attach_points_kprobe)
{
  test("BEGIN,kprobe:sys_open,uprobe:/bin/sh:foo,tracepoint:syscalls:sys_enter_* { 1 }",
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
    "arg0", "args", "curtask", "func", "gid" "rand", "uid",
    "avg", "cat", "exit", "kaddr", "min", "printf", "usym",
    "kstack", "ustack", "bpftrace", "perf", "uprobe", "kprobe",
  };
  for(auto kw : keywords)
  {
    test("usdt:/my/program:"+ kw +"*c*d { 1; }",
         "Program\n"
         " usdt:/my/program:"+ kw + "*c*d\n"
         "  int: 1\n");
    test("usdt:/my/program:abc*"+ kw +"*c*d { 1; }",
         "Program\n"
         " usdt:/my/program:abc*"+ kw + "*c*d\n"
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
  test("#include <stdio.h>\n#include \"blah\"\n#include <foo.h>\nkprobe:sys_read { @x = 1 }",
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

TEST(Parser, cast)
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

TEST(Parser, cast_ptr)
{
  test("kprobe:sys_read { (struct mytype*)arg0; }",
      "Program\n"
      " kprobe:sys_read\n"
      "  (struct mytype*)\n"
      "   builtin: arg0\n");
  test("kprobe:sys_read { (union mytype*)arg0; }",
      "Program\n"
      " kprobe:sys_read\n"
      "  (union mytype*)\n"
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
      "  (mytype*)\n"
      "   builtin: arg0\n");
}

TEST(Parser, cast_or_expr1)
{
  test("kprobe:sys_read { (mytype)*arg0; }",
      "Program\n"
      " kprobe:sys_read\n"
      "  (mytype)\n"
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
  test("kprobe:sys_read { (mytype)arg0.field; }",
      "Program\n"
      " kprobe:sys_read\n"
      "  (mytype)\n"
      "   .\n"
      "    builtin: arg0\n"
      "    field\n");

  test("kprobe:sys_read { (mytype*)arg0->field; }",
      "Program\n"
      " kprobe:sys_read\n"
      "  (mytype*)\n"
      "   .\n"
      "    dereference\n"
      "     builtin: arg0\n"
      "    field\n");

  test("kprobe:sys_read { (mytype)arg0+123; }",
      "Program\n"
      " kprobe:sys_read\n"
      "  +\n"
      "   (mytype)\n"
      "    builtin: arg0\n"
      "   int: 123\n");
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
      R"(stdin:1:9-10: ERROR: syntax error, unexpected <, expecting }
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
stdin:1:12-19: ERROR: syntax error, unexpected end of file, expecting }
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

  test_parse_failure("k:asdf+123abc");
}

TEST(Parser, kretprobe_offset)
{
  // Not supported yet
  test_parse_failure("kr:fn+1 { 1 }");
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
  test_parse_failure("ur:./test:fn+1 { 1 }");
  test_parse_failure("uretprobe:/bin/sh:f+0x10 { 1 }");
}

TEST(Parser, invalid_increment_decrement)
{
  test_parse_failure("i:s:1 { @=5++}");
  test_parse_failure("i:s:1 { @=++5}");
  test_parse_failure("i:s:1 { @=5--}");
  test_parse_failure("i:s:1 { @=--5}");
  test_parse_failure("i:s:1 { @=\"a\"++}");
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
  test_parse_failure("::k::vfs_open:: { 1 }");
  test_parse_failure("k:vfs_open: { 1 }");
  test_parse_failure(":w:0x10000000:8:rw { 1 }");
}

TEST(Parser, scientific_notation)
{
  test("k:f { print(1e6); }",
       "Program\n kprobe:f\n  call: print\n   int: 1000000\n");
  test("k:f { print(5e9); }",
       "Program\n kprobe:f\n  call: print\n   int: 5000000000\n");

  test_parse_failure("k:f { print(5e-9); }");
  test_parse_failure("k:f { print(1e100); }");
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
  test_parse_failure("i:s:1 { (1, 0) = 0 }");
  test_parse_failure("i:s:1 { ((1, 0), 3).0.0 = 3 }");
  test_parse_failure("i:s:1 { ((1, 0), 3).0 = (0, 1) }");
  test_parse_failure("i:s:1 { (1, \"two\", (3, 4)).5 = \"six\"; }");
  test_parse_failure("i:s:1 { $a = 1; $a.2 = 3 }");
  test_parse_failure("i:s:1 { 0.1 = 1.0 }");
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

} // namespace parser
} // namespace test
} // namespace bpftrace
