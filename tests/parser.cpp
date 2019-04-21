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
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  ASSERT_EQ(driver.parse_str(input), 0);

  std::ostringstream out;
  Printer printer(out);
  driver.root_->accept(printer);
  EXPECT_EQ(output, out.str());
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
  test("kprobe:f { stack }", "Program\n kprobe:f\n  builtin: kstack\n");
  test("kprobe:f { kstack }", "Program\n kprobe:f\n  builtin: kstack\n");
  test("kprobe:f { ustack }", "Program\n kprobe:f\n  builtin: ustack\n");
  test("kprobe:f { arg0 }", "Program\n kprobe:f\n  builtin: arg0\n");
  test("kprobe:f { retval }", "Program\n kprobe:f\n  builtin: retval\n");
  test("kprobe:f { func }", "Program\n kprobe:f\n  builtin: func\n");
  test("kprobe:f { probe }", "Program\n kprobe:f\n  builtin: probe\n");
  test("kprobe:f { args }", "Program\n kprobe:f\n  builtin: args\n");
  test("kprobe:f { $1 }", "Program\n kprobe:f\n  builtin: $1\n");
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
      "   -\n"
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

TEST(Parser, variable_increment)
{
  test("kprobe:sys_open { $x++; }",
      "Program\n"
      " kprobe:sys_open\n"
      "  =\n"
      "   variable: $x\n"
      "   +\n"
      "    variable: $x\n"
      "    int: 1\n");
  test("kprobe:sys_open { $x--; }",
      "Program\n"
      " kprobe:sys_open\n"
      "  =\n"
      "   variable: $x\n"
      "   -\n"
      "    variable: $x\n"
      "    int: 1\n");
}

TEST(Parser, map_increment)
{
  test("kprobe:sys_open { @++; }",
      "Program\n"
      " kprobe:sys_open\n"
      "  =\n"
      "   map: @\n"
      "   +\n"
      "    map: @\n"
      "    int: 1\n");
  test("kprobe:sys_open { @--; }",
      "Program\n"
      " kprobe:sys_open\n"
      "  =\n"
      "   map: @\n"
      "   -\n"
      "    map: @\n"
      "    int: 1\n");
  test("kprobe:sys_open { @[probe]++; }",
      "Program\n"
      " kprobe:sys_open\n"
      "  =\n"
      "   map: @\n"
      "    builtin: probe\n"
      "   +\n"
      "    map: @\n"
      "     builtin: probe\n"
      "    int: 1\n");
  test("kprobe:sys_open { @[probe]--; }",
      "Program\n"
      " kprobe:sys_open\n"
      "  =\n"
      "   map: @\n"
      "    builtin: probe\n"
      "   -\n"
      "    map: @\n"
      "     builtin: probe\n"
      "    int: 1\n");
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

TEST(Parser, unroll)
{
  test("kprobe:sys_open { $i = 0; unroll(5) { printf(\"i: %d\\n\", $i); $i = $i + 1; } }",
       "Program\n"
       " kprobe:sys_open\n"
       "  =\n"
       "   variable: $i\n"
       "   int: 0\n"
       "  unroll 5\n"
       "   call: printf\n"
       "    string: i: %d\\n\n"
       "    variable: $i\n"
       "   =\n"
       "    variable: $i\n"
       "    +\n"
       "     variable: $i\n"
       "     int: 1\n");
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
  test("kprobe:sys_open { myfunc() }",
      "Program\n"
      " kprobe:sys_open\n"
      "  call: myfunc\n");
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
}

TEST(Parser, usdt)
{
  test("usdt:/my/program:probe { 1; }",
      "Program\n"
      " usdt:/my/program:probe\n"
      "  int: 1\n");
}

TEST(Parser, usdt_namespaced_probe)
{
  test("usdt:/my/program:namespace:probe { 1; }",
      "Program\n"
      " usdt:/my/program:namespace:probe\n"
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

TEST(Parser, interval_probe)
{
  test("interval:s:1 { 1 }",
      "Program\n"
      " interval:s:1\n"
      "  int: 1\n");
}

TEST(Parser, software_probe)
{
  test("software:faults:1000 { 1 }",
      "Program\n"
      " software:faults:1000\n"
      "  int: 1\n");
}

TEST(Parser, hardware_probe)
{
  test("hardware:cache-references:1000000 { 1 }",
      "Program\n"
      " hardware:cache-references:1000000\n"
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
  test("kprobe:sys_read { (mytype)arg0; }",
      "Program\n"
      " kprobe:sys_read\n"
      "  (mytype)\n"
      "   builtin: arg0\n");
}

TEST(Parser, cast_ptr)
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

TEST(Parser, unterminated_string)
{
  // Make sure parser doesn't get stuck in an infinite loop
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  EXPECT_EQ(driver.parse_str("kprobe:f { \"asdf }"), 1);
}

} // namespace parser
} // namespace test
} // namespace bpftrace
