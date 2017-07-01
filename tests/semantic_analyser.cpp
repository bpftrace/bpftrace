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

  std::ostringstream out;
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, out);
  EXPECT_EQ(semantics.analyse(), result);
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

  test(bpftrace, "a:b { 1; } c:d { 1; }");
}

TEST(semantic_analyser, undefined_map)
{
  test("a:b / @mymap == 123 / { 456; }", 10);
  test("a:b / @mymap1 == 1234 / { 1234; @mymap1 = @mymap2; }", 10);
}

} // namespace bpftrace
