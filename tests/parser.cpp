#include <sstream>

#include "gtest/gtest.h"
#include "driver.h"
#include "printer.h"

namespace bpftrace {
namespace test {
namespace parser {

using Printer = ast::Printer;

void test(const std::string &input, const std::string &output)
{
  Driver driver;
  ASSERT_EQ(driver.parse_str(input), 0);

  std::ostringstream out;
  Printer printer(out);
  driver.root_->accept(printer);
  EXPECT_EQ(output, out.str());
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
  test("kprobe:sys_open { @x = mybuiltin; }",
      "Program\n"
      " kprobe:sys_open\n"
      "  =\n"
      "   map: @x\n"
      "   builtin: mybuiltin\n");
  test("kprobe:sys_open { @x = myfunc(); }",
      "Program\n"
      " kprobe:sys_open\n"
      "  =\n"
      "   map: @x\n"
      "   call: myfunc\n");
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

  test("kprobe:sys_open { @x[b1] = 1; @x[b1,b2,b3] = 1; }",
      "Program\n"
      " kprobe:sys_open\n"
      "  =\n"
      "   map: @x\n"
      "    builtin: b1\n"
      "   int: 1\n"
      "  =\n"
      "   map: @x\n"
      "    builtin: b1\n"
      "    builtin: b2\n"
      "    builtin: b3\n"
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
  test("kprobe:sys_open / 1 <= 2 && (9 - 4 != 5*10 || ~0) || poop == \"string\" /\n"
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
      "     builtin: poop\n"
      "     string: string\n"
      "  int: 1\n");
}

TEST(Parser, call)
{
  test("kprobe:sys_open { @x = foo(); @y = bar(1,2,3); myfunc(@x); }",
      "Program\n"
      " kprobe:sys_open\n"
      "  =\n"
      "   map: @x\n"
      "   call: foo\n"
      "  =\n"
      "   map: @y\n"
      "   call: bar\n"
      "    int: 1\n"
      "    int: 2\n"
      "    int: 3\n"
      "  call: myfunc\n"
      "   map: @x\n");
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
}

TEST(Parser, escape_chars)
{
  test("kprobe:sys_open { \"newline\\nand tab\\tbackslash\\\\quote\\\"here\" }",
      "Program\n"
      " kprobe:sys_open\n"
      "  string: newline\\nand tab\\tbackslash\\\\quote\\\"here\n");
}

TEST(Parser, begin_probe)
{
  test("BEGIN { 1 }",
      "Program\n"
      " BEGIN\n"
      "  int: 1\n");
}

TEST(Parser, tracepoint_probe)
{
  test("tracepoint:sched:sched_switch { 1 }",
      "Program\n"
      " tracepoint:sched:sched_switch\n"
      "  int: 1\n");
}

TEST(Parser, profile_probe)
{
  test("profile:ms:997 { 1 }",
      "Program\n"
      " profile:ms:997\n"
      "  int: 1\n");
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
  test("kprobe:sys_* { @x = y*z }",
      "Program\n"
      " kprobe:sys_*\n"
      "  =\n"
      "   map: @x\n"
      "   *\n"
      "    builtin: y\n"
      "    builtin: z\n");
  test("kprobe:sys_* { @x = *arg0 }",
      "Program\n"
      " kprobe:sys_*\n"
      "  =\n"
      "   map: @x\n"
      "   dereference\n"
      "    builtin: arg0\n");
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

} // namespace parser
} // namespace test
} // namespace bpftrace
