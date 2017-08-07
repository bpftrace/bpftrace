#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "bpftrace.h"
#include "driver.h"
#include "semantic_analyser.h"

namespace bpftrace {
namespace test {
namespace semantic_analyser {

class MockBPFtrace : public BPFtrace {
public:
MockBPFtrace() : BPFtrace("") { }
  MOCK_METHOD1(add_probe, int(ast::Probe &p));
};

using ::testing::_;

void test(BPFtrace &bpftrace, Driver &driver, const std::string &input, int expected_result=0)
{
  ASSERT_EQ(driver.parse_str(input), 0);

  std::stringstream out;
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, out);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";
  EXPECT_EQ(semantics.analyse(), expected_result) << msg.str() + out.str();
}

void test(BPFtrace &bpftrace, const std::string &input, int expected_result=0)
{
  Driver driver;
  test(bpftrace, driver, input, expected_result);
}

void test(Driver &driver, const std::string &input, int expected_result=0)
{
  BPFtrace bpftrace("");
  test(bpftrace, driver, input, expected_result);
}

void test(const std::string &input, int expected_result=0)
{
  BPFtrace bpftrace("");
  Driver driver;
  test(bpftrace, driver, input, expected_result);
}

TEST(semantic_analyser, probe_count)
{
  MockBPFtrace bpftrace;
  EXPECT_CALL(bpftrace, add_probe(_)).Times(2);

  test(bpftrace, "kprobe:f { 1; } kprobe:d { 1; }");
}

TEST(semantic_analyser, undefined_map)
{
  test("kprobe:f / @mymap == 123 / { @mymap = 0 }", 0);
  test("kprobe:f / @mymap == 123 / { 456; }", 10);
  test("kprobe:f / @mymap1 == 1234 / { 1234; @mymap1 = @mymap2; }", 10);
}

TEST(semantic_analyser, predicate_expressions)
{
  test("kprobe:f / 999 / { 123 }", 0);
  test("kprobe:f / \"str\" / { 123 }", 10);
  test("kprobe:f / stack / { 123 }", 10);
  test("kprobe:f / @mymap / { @mymap = \"str\" }", 10);
}

TEST(semantic_analyser, mismatched_call_types)
{
  test("kprobe:f { @x = 1; @x = count(); }", 1);
  test("kprobe:f { @x = 1; @x = quantize(0); }", 1);
  test("kprobe:f { @x = 1; @x = delete(); }", 0);
}

TEST(semantic_analyser, call_quantize)
{
  test("kprobe:f { @x = quantize(1); }", 0);
  test("kprobe:f { @x = quantize(); }", 1);
  test("kprobe:f { quantize(); }", 1);
}

TEST(semantic_analyser, call_count)
{
  test("kprobe:f { @x = count(); }", 0);
  test("kprobe:f { @x = count(1); }", 1);
  test("kprobe:f { count(); }", 1);
}

TEST(semantic_analyser, call_delete)
{
  test("kprobe:f { @x = delete(); }", 0);
  test("kprobe:f { @x = delete(1); }", 1);
  test("kprobe:f { delete(); }", 1);
}

TEST(semantic_analyser, call_str)
{
  test("kprobe:f { str(arg0); }", 0);
  test("kprobe:f { @x = str(arg0); }", 0);
  test("kprobe:f { str(); }", 1);
}

TEST(semantic_analyser, map_reassignment)
{
  test("kprobe:f { @x = 1; @x = 2; }", 0);
  test("kprobe:f { @x = 1; @x = \"foo\"; }", 1);
}

TEST(semantic_analyser, variable_reassignment)
{
  test("kprobe:f { $x = 1; $x = 2; }", 0);
  test("kprobe:f { $x = 1; $x = \"foo\"; }", 1);
}

TEST(semantic_analyser, map_use_before_assign)
{
  test("kprobe:f { @x = @y; @y = 2; }", 0);
}

TEST(semantic_analyser, variable_use_before_assign)
{
  test("kprobe:f { @x = $y; $y = 2; }", 1);
}

TEST(semantic_analyser, maps_are_global)
{
  test("kprobe:f { @x = 1 } kprobe:g { @y = @x }", 0);
}

TEST(semantic_analyser, variables_are_local)
{
  test("kprobe:f { $x = 1 } kprobe:g { @y = $x }", 1);
}

TEST(semantic_analyser, variable_type)
{
  Driver driver;
  test(driver, "kprobe:f { $x = 1 }", 0);
  SizedType st(Type::integer, 8);
  auto assignment = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(0));
  EXPECT_EQ(st, assignment->var->type);
}

TEST(semantic_analyser, printf)
{
  test("kprobe:f { printf(\"hi\") }", 0);
  test("kprobe:f { printf(1234) }", 1);
  test("kprobe:f { $fmt = \"mystring\"; printf($fmt) }", 1);
}

TEST(semantic_analyser, printf_format_int)
{
  test("kprobe:f { printf(\"int: %d\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %d\", pid) }", 0);
  test("kprobe:f { @x = 123; printf(\"int: %d\", @x) }", 0);
  test("kprobe:f { $x = 123; printf(\"int: %d\", $x) }", 0);

  test("kprobe:f { printf(\"int: %u\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %x\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %X\", 1234) }", 0);
}

TEST(semantic_analyser, printf_format_string)
{
  test("kprobe:f { printf(\"str: %s\", \"mystr\") }", 0);
  test("kprobe:f { printf(\"str: %s\", comm) }", 0);
  test("kprobe:f { printf(\"str: %s\", str(arg0)) }", 0);
  test("kprobe:f { @x = \"hi\"; printf(\"str: %s\", @x) }", 0);
  test("kprobe:f { $x = \"hi\"; printf(\"str: %s\", $x) }", 0);
}

TEST(semantic_analyser, printf_bad_format_string)
{
  test("kprobe:f { printf(\"%d\", \"mystr\") }", 10);
  test("kprobe:f { printf(\"%d\", str(arg0)) }", 10);

  test("kprobe:f { printf(\"%s\", 1234) }", 10);
  test("kprobe:f { printf(\"%s\", arg0) }", 10);
}

TEST(semantic_analyser, printf_format_multi)
{
  test("kprobe:f { printf(\"%d %d %s\", 1, 2, \"mystr\") }", 0);
  test("kprobe:f { printf(\"%d %s %d\", 1, 2, \"mystr\") }", 10);
}

TEST(semantic_analyser, kprobe)
{
  test("kprobe:f { 1 }", 0);
  test("kprobe:path:f { 1 }", 1);
  test("kprobe { 1 }", 1);

  test("kretprobe:f { 1 }", 0);
  test("kretprobe:path:f { 1 }", 1);
  test("kretprobe { 1 }", 1);
}

TEST(semantic_analyser, uprobe)
{
  test("uprobe:path:f { 1 }", 0);
  test("uprobe:f { 1 }", 1);
  test("uprobe { 1 }", 1);

  test("uretprobe:path:f { 1 }", 0);
  test("uretprobe:f { 1 }", 1);
  test("uretprobe { 1 }", 1);
}

TEST(semantic_analyser, begin_end_probes)
{
  test("BEGIN { 1 }", 0);
  test("BEGIN:f { 1 }", 1);
  test("BEGIN:path:f { 1 }", 1);
  test("BEGIN { 1 } BEGIN { 2 }", 10);

  test("END { 1 }", 0);
  test("END:f { 1 }", 1);
  test("END:path:f { 1 }", 1);
  test("END { 1 } END { 2 }", 10);
}

} // namespace semantic_analyser
} // namespace test
} // namespace bpftrace
