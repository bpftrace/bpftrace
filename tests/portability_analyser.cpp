#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "ast/field_analyser.h"
#include "ast/portability_analyser.h"
#include "ast/semantic_analyser.h"
#include "clang_parser.h"
#include "driver.h"
#include "mocks.h"

namespace bpftrace {
namespace test {
namespace portability_analyser {

using ::testing::_;

void test(BPFtrace &bpftrace, const std::string &input, int expected_result = 0)
{
  Driver driver(bpftrace);
  std::stringstream out;
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  ASSERT_EQ(driver.parse_str(input), 0);

  ast::FieldAnalyser fields(driver.root_, bpftrace, out);
  ASSERT_EQ(fields.analyse(), 0) << msg.str() << out.str();

  ClangParser clang;
  ASSERT_TRUE(clang.parse(driver.root_, bpftrace));

  ASSERT_EQ(driver.parse_str(input), 0);
  out.str("");
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, out, false);
  ASSERT_EQ(semantics.analyse(), 0) << msg.str() << out.str();

  ast::PortabilityAnalyser portability(driver.root_, out);
  EXPECT_EQ(portability.analyse(), expected_result) << msg.str() << out.str();
}

void test(const std::string &input, int expected_result = 0)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  test(*bpftrace, input, expected_result);
}

TEST(portability_analyser, generic_field_access_disabled)
{
  test("struct Foo { int x;} BEGIN { $f = (struct Foo *)0; $f->x; }", 1);
}

TEST(portability_analyser, tracepoint_field_access)
{
  test("tracepoint:sched:sched_one { args }", 0);
  test("tracepoint:sched:sched_one { args->common_field }", 0);
  test("tracepoint:sched:sched_* { args->common_field }", 0);
}

#if defined(HAVE_LIBBPF_BTF_DUMP) && defined(HAVE_BCC_KFUNC)
#include "btf_common.h"
class portability_analyser_btf : public test_btf
{
};

TEST_F(portability_analyser_btf, kfunc_field_access)
{
  test("kfunc:func_1 { $x = args->a; $y = args->foo1; $z = args->foo2->f.a; }",
       0);
  test("kfunc:func_2 { args->foo1 }", 0);
  test("kfunc:func_2, kfunc:func_3 { $x = args->foo1; }", 0);
}
#endif

TEST(portability_analyser, positional_params_disabled)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("123");
  bpftrace->add_param("hello");

  test(*bpftrace, "BEGIN { $1 }", 1);
  test(*bpftrace, "BEGIN { str($2) }", 1);
}

TEST(portability_analyser, curtask_disabled)
{
  test("BEGIN { curtask }", 1);
  test("struct task_struct { char comm[16]; } BEGIN { curtask->comm }", 1);
}

TEST(portability_analyser, selective_probes_disabled)
{
  test("usdt:/bin/sh:probe { 1 }", 1);
  test("usdt:/bin/sh:namespace:probe { 1 }", 1);

  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, "watchpoint:0x10000000:8:rw { 1 }", 1);
  bpftrace->procmon_ = std::make_unique<MockProcMon>(123);
  test(*bpftrace, "watchpoint:0x10000000:8:rw { 1 }", 1);
  test(*bpftrace, "watchpoint:increment+arg1:4:w { 1 }", 1);
  test(*bpftrace, "asyncwatchpoint:increment+arg1:4:w { 1 }", 1);
}

} // namespace portability_analyser
} // namespace test
} // namespace bpftrace
