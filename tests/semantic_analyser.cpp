#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "bpftrace.h"
#include "driver.h"
#include "semantic_analyser.h"

namespace bpftrace {

class MockBPFtrace : public BPFtrace {
public:
  MOCK_METHOD1(add_probe, int(ast::Probe &p));
};

using ::testing::_;

void test(BPFtrace &bpftrace, const std::string &input, int result=0)
{
  Driver driver;
  ASSERT_EQ(driver.parse_str(input), 0);

  std::stringstream out;
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, out);

  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";
  EXPECT_EQ(semantics.analyse(), result) << msg.str() + out.str();
}

void test(const std::string &input, int result=0)
{
  BPFtrace bpftrace;
  test(bpftrace, input, result);
}

TEST(semantic_analyser, probe_count)
{
  MockBPFtrace bpftrace;
  EXPECT_CALL(bpftrace, add_probe(_)).Times(2);

  test(bpftrace, "a:f { 1; } c:d { 1; }");
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

} // namespace bpftrace
