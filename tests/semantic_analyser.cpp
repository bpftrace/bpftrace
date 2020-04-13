#include "semantic_analyser.h"
#include "bpffeature.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "driver.h"
#include "field_analyser.h"
#include "mocks.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace bpftrace {
namespace test {
namespace semantic_analyser {

using ::testing::_;
using ::testing::HasSubstr;

void test_for_warning(
          BPFtrace &bpftrace,
          const std::string &input,
          const std::string &warning,
          bool invert = false,
          bool safe_mode = true)
{
  Driver driver(bpftrace);
  bpftrace.safe_mode_ = safe_mode;
  ASSERT_EQ(driver.parse_str(input), 0);

  ClangParser clang;
  clang.parse(driver.root_, bpftrace);

  ASSERT_EQ(driver.parse_str(input), 0);
  MockBPFfeature feature;
  std::stringstream out;
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, feature, out);
  semantics.analyse();
  if (invert)
    EXPECT_THAT(out.str(), Not(HasSubstr(warning)));
  else
    EXPECT_THAT(out.str(), HasSubstr(warning));
}

void test_for_warning(
                      const std::string &input,
                      const std::string &warning,
                      bool invert = false,
                      bool safe_mode = true)
{
  auto bpftrace = get_mock_bpftrace();
  test_for_warning(*bpftrace, input, warning, invert, safe_mode);
}

void test(BPFtrace &bpftrace,
          BPFfeature &feature,
          Driver &driver,
          const std::string &input,
          int expected_result = 0,
          bool safe_mode = true)
{
  bpftrace.safe_mode_ = safe_mode;
  ASSERT_EQ(driver.parse_str(input), 0);

  ast::FieldAnalyser fields(driver.root_, bpftrace);
  EXPECT_EQ(fields.analyse(), 0);

  ClangParser clang;
  clang.parse(driver.root_, bpftrace);

  ASSERT_EQ(driver.parse_str(input), 0);
  std::stringstream out;
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, feature, out);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";
  EXPECT_EQ(expected_result, semantics.analyse()) << msg.str() + out.str();
}

void test(BPFtrace &bpftrace,
    const std::string &input,
    int expected_result=0,
    bool safe_mode = true)
{
  Driver driver(bpftrace);
  MockBPFfeature feature;
  test(bpftrace, feature, driver, input, expected_result, safe_mode);
}

void test(Driver &driver,
    const std::string &input,
    int expected_result=0,
    bool safe_mode = true)
{
  auto bpftrace = get_mock_bpftrace();
  MockBPFfeature feature;
  test(*bpftrace, feature, driver, input, expected_result, safe_mode);
}

void test(BPFfeature &feature,
          const std::string &input,
          int expected_result = 0,
          bool safe_mode = true)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);
  test(*bpftrace, feature, driver, input, expected_result, safe_mode);
}

void test(const std::string &input,
    int expected_result=0,
    bool safe_mode = true)
{
  MockBPFfeature feature;
  test(feature, input, expected_result, safe_mode);
}

TEST(semantic_analyser, builtin_variables)
{
  // Just check that each builtin variable exists.
  test("kprobe:f { pid }", 0);
  test("kprobe:f { tid }", 0);
  test("kprobe:f { cgroup }", 0);
  test("kprobe:f { uid }", 0);
  test("kprobe:f { username }", 0);
  test("kprobe:f { gid }", 0);
  test("kprobe:f { nsecs }", 0);
  test("kprobe:f { elapsed }", 0);
  test("kprobe:f { cpu }", 0);
  test("kprobe:f { curtask }", 0);
  test("kprobe:f { rand }", 0);
  test("kprobe:f { ctx }", 0);
  test("kprobe:f { comm }", 0);
  test("kprobe:f { kstack }", 0);
  test("kprobe:f { ustack }", 0);
  test("kprobe:f { arg0 }", 0);
  test("kprobe:f { sarg0 }", 0);
  test("kretprobe:f { retval }", 0);
  test("kprobe:f { func }", 0);
  test("uprobe:/bin/sh:f { func }", 0);
  test("kprobe:f { probe }", 0);
  test("tracepoint:a:b { args }", 0);
  test("kprobe:f { fake }", 1);

  MockBPFfeature feature(false);
  test(feature, "k:f { cgroup }", 1);
}

TEST(semantic_analyser, builtin_cpid)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, "i:ms:100 { printf(\"%d\\n\", cpid); }", 1, false);
  test(*bpftrace, "i:ms:100 { @=cpid }", 1, false);
  test(*bpftrace, "i:ms:100 { $a=cpid }", 1, false);
  bpftrace->cmd_ = "sleep 1";
  test(*bpftrace, "i:ms:100 { printf(\"%d\\n\", cpid); }", 0, false);
  test(*bpftrace, "i:ms:100 { @=cpid }", 0, false);
  test(*bpftrace, "i:ms:100 { $a=cpid }", 0, false);
}

TEST(semantic_analyser, builtin_functions)
{
  // Just check that each function exists.
  // Each function should also get its own test case for more thorough testing
  test("kprobe:f { @x = hist(123) }", 0);
  test("kprobe:f { @x = lhist(123, 0, 123, 1) }", 0);
  test("kprobe:f { @x = count() }", 0);
  test("kprobe:f { @x = sum(pid) }", 0);
  test("kprobe:f { @x = min(pid) }", 0);
  test("kprobe:f { @x = max(pid) }", 0);
  test("kprobe:f { @x = avg(pid) }", 0);
  test("kprobe:f { @x = stats(pid) }", 0);
  test("kprobe:f { @x = 1; delete(@x) }", 0);
  test("kprobe:f { @x = 1; print(@x) }", 0);
  test("kprobe:f { @x = 1; clear(@x) }", 0);
  test("kprobe:f { @x = 1; zero(@x) }", 0);
  test("kprobe:f { time() }", 0);
  test("kprobe:f { exit() }", 0);
  test("kprobe:f { str(0xffff) }", 0);
  test("kprobe:f { buf(0xffff, 1) }", 0);
  test("kprobe:f { printf(\"hello\\n\") }", 0);
  test("kprobe:f { system(\"ls\\n\") }", 0, false /* safe_node */);
  test("kprobe:f { join(0) }", 0);
  test("kprobe:f { ksym(0xffff) }", 0);
  test("kprobe:f { usym(0xffff) }", 0);
  test("kprobe:f { kaddr(\"sym\") }", 0);
  test("kprobe:f { ntop(0xffff) }", 0);
  test("kprobe:f { ntop(2, 0xffff) }", 0);
  test("kprobe:f { reg(\"ip\") }", 0);
  test("kprobe:f { kstack(1) }", 0);
  test("kprobe:f { ustack(1) }", 0);
  test("kprobe:f { cat(\"/proc/uptime\") }", 0);
  test("uprobe:/bin/bash:main { uaddr(\"glob_asciirange\") }", 0);
  test("kprobe:f { cgroupid(\"/sys/fs/cgroup/unified/mycg\"); }", 0);
}

TEST(semantic_analyser, undefined_map)
{
  test("kprobe:f / @mymap == 123 / { @mymap = 0 }", 0);
  test("kprobe:f / @mymap == 123 / { 456; }", 10);
  test("kprobe:f / @mymap1 == 1234 / { 1234; @mymap1 = @mymap2; }", 10);
}

TEST(semantic_analyser, consistent_map_values)
{
  test("kprobe:f { @x = 0; @x = 1; }", 0);
  test("kprobe:f { @x = 0; @x = \"a\"; }", 1);
}

TEST(semantic_analyser, consistent_map_keys)
{
  test("kprobe:f { @x = 0; @x; }", 0);
  test("kprobe:f { @x[1] = 0; @x[2]; }", 0);

  test("kprobe:f { @x = 0; @x[1]; }", 10);
  test("kprobe:f { @x[1] = 0; @x; }", 10);

  test("kprobe:f { @x[1,2] = 0; @x[3,4]; }", 0);
  test("kprobe:f { @x[1,2] = 0; @x[3]; }", 10);
  test("kprobe:f { @x[1] = 0; @x[2,3]; }", 10);

  test("kprobe:f { @x[1,\"a\",kstack] = 0; @x[2,\"b\", kstack]; }", 0);
  test("kprobe:f { @x[1,\"a\",kstack] = 0; @x[\"b\", 2, kstack]; }", 10);
}

TEST(semantic_analyser, if_statements)
{
  test("kprobe:f { if(1) { 123 } }", 0);
  test("kprobe:f { if(1) { 123 } else { 456 } }", 0);
  test("kprobe:f { if(0) { 123 } else if(1) { 456 } else { 789 } }", 0);
  test("kprobe:f { if((int32)pid) { 123 } }", 0);
}

TEST(semantic_analyser, predicate_expressions)
{
  test("kprobe:f / 999 / { 123 }", 0);
  test("kprobe:f / \"str\" / { 123 }", 10);
  test("kprobe:f / kstack / { 123 }", 10);
  test("kprobe:f / @mymap / { @mymap = \"str\" }", 10);
}

TEST(semantic_analyser, ternary_expressions)
{
  test("kprobe:f { @x = pid < 10000 ? 1 : 2 }", 0);
  test("kprobe:f { @x = pid < 10000 ? \"lo\" : \"high\" }", 0);
  test("kprobe:f { @x = pid < 10000 ? 1 : \"high\" }", 10);
  test("kprobe:f { @x = pid < 10000 ? \"lo\" : 2 }", 10);
}

TEST(semantic_analyser, mismatched_call_types)
{
  test("kprobe:f { @x = 1; @x = count(); }", 1);
  test("kprobe:f { @x = count(); @x = sum(pid); }", 1);
  test("kprobe:f { @x = 1; @x = hist(0); }", 1);
}

TEST(semantic_analyser, compound_left)
{
  test("kprobe:f { $a <<= 0 }", 1);
  test("kprobe:f { $a = 0; $a <<= 1 }", 0);
  test("kprobe:f { @a <<= 1 }", 0);
}

TEST(semantic_analyser, compound_right)
{
  test("kprobe:f { $a >>= 0 }", 1);
  test("kprobe:f { $a = 0; $a >>= 1 }", 0);
  test("kprobe:f { @a >>= 1 }", 0);
}

TEST(semantic_analyser, compound_plus)
{
  test("kprobe:f { $a += 0 }", 1);
  test("kprobe:f { $a = 0; $a += 1 }", 0);
  test("kprobe:f { @a += 1 }", 0);
}

TEST(semantic_analyser, compound_minus)
{
  test("kprobe:f { $a -= 0 }", 1);
  test("kprobe:f { $a = 0; $a -= 1 }", 0);
  test("kprobe:f { @a -= 1 }", 0);
}

TEST(semantic_analyser, compound_mul)
{
  test("kprobe:f { $a *= 0 }", 1);
  test("kprobe:f { $a = 0; $a *= 1 }", 0);
  test("kprobe:f { @a *= 1 }", 0);
}

TEST(semantic_analyser, compound_div)
{
  test("kprobe:f { $a /= 0 }", 1);
  test("kprobe:f { $a = 0; $a /= 1 }", 0);
  test("kprobe:f { @a /= 1 }", 0);
}

TEST(semantic_analyser, compound_mod)
{
  test("kprobe:f { $a %= 0 }", 1);
  test("kprobe:f { $a = 0; $a %= 1 }", 0);
  test("kprobe:f { @a %= 1 }", 0);
}

TEST(semantic_analyser, compound_band)
{
  test("kprobe:f { $a &= 0 }", 1);
  test("kprobe:f { $a = 0; $a &= 1 }", 0);
  test("kprobe:f { @a &= 1 }", 0);
}

TEST(semantic_analyser, compound_bor)
{
  test("kprobe:f { $a |= 0 }", 1);
  test("kprobe:f { $a = 0; $a |= 1 }", 0);
  test("kprobe:f { @a |= 1 }", 0);
}

TEST(semantic_analyser, compound_bxor)
{
  test("kprobe:f { $a ^= 0 }", 1);
  test("kprobe:f { $a = 0; $a ^= 1 }", 0);
  test("kprobe:f { @a ^= 1 }", 0);
}

TEST(semantic_analyser, call_hist)
{
  test("kprobe:f { @x = hist(1); }", 0);
  test("kprobe:f { @x = hist(); }", 1);
  test("kprobe:f { hist(1); }", 1);
  test("kprobe:f { $x = hist(1); }", 1);
  test("kprobe:f { @x[hist(1)] = 1; }", 1);
}

TEST(semantic_analyser, call_lhist)
{
  test("kprobe:f { @ = lhist(5, 0, 10, 1); }", 0);
  test("kprobe:f { @ = lhist(5, 0, 10); }", 1);
  test("kprobe:f { @ = lhist(5, 0); }", 1);
  test("kprobe:f { @ = lhist(5); }", 1);
  test("kprobe:f { @ = lhist(); }", 1);
  test("kprobe:f { @ = lhist(5, 0, 10, 1, 2); }", 1);
  test("kprobe:f { lhist(-10, -10, 10, 1); }", 1);
  test("kprobe:f { @ = lhist(-10, -10, 10, 1); }", 10); // must be positive
  test("kprobe:f { $x = lhist(); }", 1);
  test("kprobe:f { @[lhist()] = 1; }", 1);
}

TEST(semantic_analyser, call_count)
{
  test("kprobe:f { @x = count(); }", 0);
  test("kprobe:f { @x = count(1); }", 1);
  test("kprobe:f { count(); }", 1);
  test("kprobe:f { $x = count(); }", 1);
  test("kprobe:f { @[count()] = 1; }", 1);
}

TEST(semantic_analyser, call_sum)
{
  test("kprobe:f { @x = sum(123); }", 0);
  test("kprobe:f { @x = sum(); }", 1);
  test("kprobe:f { @x = sum(123, 456); }", 1);
  test("kprobe:f { sum(123); }", 1);
  test("kprobe:f { $x = sum(123); }", 1);
  test("kprobe:f { @[sum(123)] = 1; }", 1);
}

TEST(semantic_analyser, call_min)
{
  test("kprobe:f { @x = min(123); }", 0);
  test("kprobe:f { @x = min(); }", 1);
  test("kprobe:f { min(123); }", 1);
  test("kprobe:f { $x = min(123); }", 1);
  test("kprobe:f { @[min(123)] = 1; }", 1);
}

TEST(semantic_analyser, call_max)
{
  test("kprobe:f { @x = max(123); }", 0);
  test("kprobe:f { @x = max(); }", 1);
  test("kprobe:f { max(123); }", 1);
  test("kprobe:f { $x = max(123); }", 1);
  test("kprobe:f { @[max(123)] = 1; }", 1);
}

TEST(semantic_analyser, call_avg)
{
  test("kprobe:f { @x = avg(123); }", 0);
  test("kprobe:f { @x = avg(); }", 1);
  test("kprobe:f { avg(123); }", 1);
  test("kprobe:f { $x = avg(123); }", 1);
  test("kprobe:f { @[avg(123)] = 1; }", 1);
}

TEST(semantic_analyser, call_stats)
{
  test("kprobe:f { @x = stats(123); }", 0);
  test("kprobe:f { @x = stats(); }", 1);
  test("kprobe:f { stats(123); }", 1);
  test("kprobe:f { $x = stats(123); }", 1);
  test("kprobe:f { @[stats(123)] = 1; }", 1);
}

TEST(semantic_analyser, call_delete)
{
  test("kprobe:f { @x = 1; delete(@x); }", 0);
  test("kprobe:f { delete(1); }", 1);
  test("kprobe:f { delete(); }", 1);
  test("kprobe:f { @y = delete(@x); }", 1);
  test("kprobe:f { $y = delete(@x); }", 1);
  test("kprobe:f { @[delete(@x)] = 1; }", 1);
}

TEST(semantic_analyser, call_exit)
{
  test("kprobe:f { exit(); }", 0);
  test("kprobe:f { exit(1); }", 1);
  test("kprobe:f { @a = exit(1); }", 1);
  test("kprobe:f { $a = exit(1); }", 1);
  test("kprobe:f { @[exit(1)] = 1; }", 1);
}

TEST(semantic_analyser, call_print)
{
  test("kprobe:f { @x = count(); print(@x); }", 0);
  test("kprobe:f { @x = count(); print(@x, 5); }", 0);
  test("kprobe:f { @x = count(); print(@x, 5, 10); }", 0);
  test("kprobe:f { @x = count(); print(@x, 5, 10, 1); }", 1);
  test("kprobe:f { @x = count(); @x = print(); }", 1);

  test("kprobe:f { print(@x); @x[1,2] = count(); }", 0);
  test("kprobe:f { @x[1,2] = count(); print(@x); }", 0);
  test("kprobe:f { @x[1,2] = count(); print(@x[3,4]); }", 1);

  test("kprobe:f { @x = count(); @ = print(@x); }", 1);
  test("kprobe:f { @x = count(); $y = print(@x); }", 1);
  test("kprobe:f { @x = count(); @[print(@x)] = 1; }", 1);
}

TEST(semantic_analyser, call_clear)
{
  test("kprobe:f { @x = count(); clear(@x); }", 0);
  test("kprobe:f { @x = count(); clear(@x, 1); }", 1);
  test("kprobe:f { @x = count(); @x = clear(); }", 1);

  test("kprobe:f { clear(@x); @x[1,2] = count(); }", 0);
  test("kprobe:f { @x[1,2] = count(); clear(@x); }", 0);
  test("kprobe:f { @x[1,2] = count(); clear(@x[3,4]); }", 1);

  test("kprobe:f { @x = count(); @ = clear(@x); }", 1);
  test("kprobe:f { @x = count(); $y = clear(@x); }", 1);
  test("kprobe:f { @x = count(); @[clear(@x)] = 1; }", 1);
}

TEST(semantic_analyser, call_zero)
{
  test("kprobe:f { @x = count(); zero(@x); }", 0);
  test("kprobe:f { @x = count(); zero(@x, 1); }", 1);
  test("kprobe:f { @x = count(); @x = zero(); }", 1);

  test("kprobe:f { zero(@x); @x[1,2] = count(); }", 0);
  test("kprobe:f { @x[1,2] = count(); zero(@x); }", 0);
  test("kprobe:f { @x[1,2] = count(); zero(@x[3,4]); }", 1);

  test("kprobe:f { @x = count(); @ = zero(@x); }", 1);
  test("kprobe:f { @x = count(); $y = zero(@x); }", 1);
  test("kprobe:f { @x = count(); @[zero(@x)] = 1; }", 1);
}

TEST(semantic_analyser, call_time)
{
  test("kprobe:f { time(); }", 0);
  test("kprobe:f { time(\"%M:%S\"); }", 0);
  test("kprobe:f { time(\"%M:%S\", 1); }", 1);
  test("kprobe:f { @x = time(); }", 1);
  test("kprobe:f { $x = time(); }", 1);
  test("kprobe:f { @[time()] = 1; }", 1);
  test("kprobe:f { time(1); }", 10);
  test("kprobe:f { $x = \"str\"; time($x); }", 10);
}

TEST(semantic_analyser, call_str)
{
  test("kprobe:f { str(arg0); }", 0);
  test("kprobe:f { @x = str(arg0); }", 0);
  test("kprobe:f { str(); }", 1);
  test("kprobe:f { str(\"hello\"); }", 10);
}

TEST(semantic_analyser, call_str_2_lit)
{
  test("kprobe:f { str(arg0, 3); }", 0);
  test("kprobe:f { @x = str(arg0, 3); }", 0);
  test("kprobe:f { str(arg0, \"hello\"); }", 10);
}

TEST(semantic_analyser, call_str_2_expr)
{
  test("kprobe:f { str(arg0, arg1); }", 0);
  test("kprobe:f { @x = str(arg0, arg1); }", 0);
}

TEST(semantic_analyser, call_buf)
{
  test("kprobe:f { buf(arg0, 1); }", 0);
  test("kprobe:f { @x = buf(arg0, 1); }", 0);
  test("kprobe:f { $x = buf(arg0, 1); }", 0);
  test("kprobe:f { buf(); }", 1);
  test("kprobe:f { buf(\"hello\"); }", 1);
  test("struct x { int c[4] }; kprobe:f { $foo = (struct x*)0; @x = "
       "buf($foo->c); }",
       0);
}

TEST(semantic_analyser, call_buf_lit)
{
  test("kprobe:f { @x = buf(arg0, 3); }", 0);
  test("kprobe:f { buf(arg0, \"hello\"); }", 10);
}

TEST(semantic_analyser, call_buf_expr)
{
  test("kprobe:f { buf(arg0, arg1); }", 0);
  test("kprobe:f { @x = buf(arg0, arg1); }", 0);
}

TEST(semantic_analyser, call_ksym)
{
  test("kprobe:f { ksym(arg0); }", 0);
  test("kprobe:f { @x = ksym(arg0); }", 0);
  test("kprobe:f { ksym(); }", 1);
  test("kprobe:f { ksym(\"hello\"); }", 1);
}

TEST(semantic_analyser, call_usym)
{
  test("kprobe:f { usym(arg0); }", 0);
  test("kprobe:f { @x = usym(arg0); }", 0);
  test("kprobe:f { usym(); }", 1);
  test("kprobe:f { usym(\"hello\"); }", 1);
}

TEST(semantic_analyser, call_ntop)
{
  std::string structs = "struct inet { unsigned char ipv4[4]; unsigned char ipv6[16]; unsigned char invalid[10]; } ";

  test("kprobe:f { ntop(2, arg0); }", 0);
  test("kprobe:f { ntop(arg0); }", 0);
  test(structs + "kprobe:f { ntop(10, ((struct inet*)0)->ipv4); }", 0);
  test(structs + "kprobe:f { ntop(10, ((struct inet*)0)->ipv6); }", 0);
  test(structs + "kprobe:f { ntop(((struct inet*)0)->ipv4); }", 0);
  test(structs + "kprobe:f { ntop(((struct inet*)0)->ipv6); }", 0);

  test("kprobe:f { @x = ntop(2, arg0); }", 0);
  test("kprobe:f { @x = ntop(arg0); }", 0);
  test("kprobe:f { @x = ntop(2, 0xFFFF); }", 0);
  test("kprobe:f { @x = ntop(0xFFFF); }", 0);
  test(structs + "kprobe:f { @x = ntop(((struct inet*)0)->ipv4); }", 0);
  test(structs + "kprobe:f { @x = ntop(((struct inet*)0)->ipv6); }", 0);

  test("kprobe:f { ntop(); }", 1);
  test("kprobe:f { ntop(2, \"hello\"); }", 1);
  test("kprobe:f { ntop(\"hello\"); }", 1);
  test(structs + "kprobe:f { ntop(((struct inet*)0)->invalid); }", 1);
}

TEST(semantic_analyser, call_kaddr)
{
  test("kprobe:f { kaddr(\"avenrun\"); }", 0);
  test("kprobe:f { @x = kaddr(\"avenrun\"); }", 0);
  test("kprobe:f { kaddr(); }", 1);
  test("kprobe:f { kaddr(123); }", 1);
}

TEST(semantic_analyser, call_uaddr)
{
  test("u:/bin/bash:main { uaddr(\"github.com/golang/glog.severityName\"); }", 0);
  test("uprobe:/bin/bash:main { uaddr(\"glob_asciirange\"); }", 0);
  test("u:/bin/bash:main,u:/bin/bash:readline { uaddr(\"glob_asciirange\"); }",
       0);
  test("uprobe:/bin/bash:main { @x = uaddr(\"glob_asciirange\"); }", 0);
  test("uprobe:/bin/bash:main { uaddr(); }", 1);
  test("uprobe:/bin/bash:main { uaddr(123); }", 1);
  test("uprobe:/bin/bash:main { uaddr(\"?\"); }", 1);
  test("uprobe:/bin/bash:main { $str = \"glob_asciirange\"; uaddr($str); }", 1);
  test("uprobe:/bin/bash:main { @str = \"glob_asciirange\"; uaddr(@str); }", 1);

  test("k:f { uaddr(\"A\"); }", 1);
  test("i:s:1 { uaddr(\"A\"); }", 1);

  // The C struct parser should set the is_signed flag on signed types
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  std::string prog = "uprobe:/bin/bash:main {"
                     "$a = uaddr(\"12345_1\");"
                     "$b = uaddr(\"12345_2\");"
                     "$c = uaddr(\"12345_4\");"
                     "$d = uaddr(\"12345_8\");"
                     "$e = uaddr(\"12345_5\");"
                     "$f = uaddr(\"12345_33\");"
                     "}";

  test(driver, prog, 0);

  std::vector<int> sizes = { 1, 2, 4, 8, 8, 8 };

  for (size_t i = 0; i < sizes.size(); i++)
  {
    auto v = static_cast<ast::AssignVarStatement *>(
        driver.root_->probes->at(0)->stmts->at(i));
    EXPECT_EQ(SizedType(Type::integer, 8, false), v->var->type);
    EXPECT_EQ(true, v->var->type.is_pointer);
    EXPECT_EQ((unsigned long int)sizes.at(i), v->var->type.pointee_size);
  }
}

TEST(semantic_analyser, call_cgroupid)
{
  // Handle args above STRING_SIZE
  test("kprobe:f { cgroupid("
       //          1         2         3         4         5         6
       "\"123456789/123456789/123456789/123456789/123456789/123456789/12345\""
       "); }",
       0);
}

TEST(semantic_analyser, call_reg)
{
  test("kprobe:f { reg(\"ip\"); }", 0);
  test("kprobe:f { @x = reg(\"ip\"); }", 0);
  test("kprobe:f { reg(\"blah\"); }", 1);
  test("kprobe:f { reg(); }", 1);
  test("kprobe:f { reg(123); }", 1);
}

TEST(semantic_analyser, call_func)
{
  test("kprobe:f { @[func] = count(); }", 0);
  test("kprobe:f { printf(\"%s\", func);  }", 0);
  test("uprobe:/bin/sh:f { @[func] = count(); }", 0);
  test("uprobe:/bin/sh:f { printf(\"%s\", func);  }", 0);
}

TEST(semantic_analyser, call_probe)
{
  test("kprobe:f { @[probe] = count(); }", 0);
  test("kprobe:f { printf(\"%s\", probe);  }", 0);
}

TEST(semantic_analyser, call_cat)
{
  test("kprobe:f { cat(\"/proc/loadavg\"); }", 0);
  test("kprobe:f { cat(\"/proc/%d/cmdline\", 1); }", 0);
  test("kprobe:f { cat(); }", 1);
  test("kprobe:f { cat(123); }", 1);
  test("kprobe:f { @x = cat(\"/proc/loadavg\"); }", 1);
  test("kprobe:f { $x = cat(\"/proc/loadavg\"); }", 1);
  test("kprobe:f { @[cat(\"/proc/loadavg\")] = 1; }", 1);
}

TEST(semantic_analyser, call_stack)
{
  test("kprobe:f { kstack() }", 0);
  test("kprobe:f { ustack() }", 0);
  test("kprobe:f { kstack(bpftrace) }", 0);
  test("kprobe:f { ustack(bpftrace) }", 0);
  test("kprobe:f { kstack(perf) }", 0);
  test("kprobe:f { ustack(perf) }", 0);
  test("kprobe:f { kstack(3) }", 0);
  test("kprobe:f { ustack(3) }", 0);
  test("kprobe:f { kstack(perf, 3) }", 0);
  test("kprobe:f { ustack(perf, 3) }", 0);

  // Wrong arguments
  test("kprobe:f { kstack(3, perf) }", 10);
  test("kprobe:f { ustack(3, perf) }", 10);
  test("kprobe:f { kstack(perf, 3, 4) }", 1);
  test("kprobe:f { ustack(perf, 3, 4) }", 1);
  test("kprobe:f { kstack(bob) }", 1);
  test("kprobe:f { ustack(bob) }", 1);
  test("kprobe:f { kstack(\"str\") }", 10);
  test("kprobe:f { ustack(\"str\") }", 10);
  test("kprobe:f { kstack(perf, \"str\") }", 10);
  test("kprobe:f { ustack(perf, \"str\") }", 10);
  test("kprobe:f { kstack(\"str\", 3) }", 10);
  test("kprobe:f { ustack(\"str\", 3) }", 10);

  // Non-literals
  test("kprobe:f { @x = perf; kstack(@x) }", 10);
  test("kprobe:f { @x = perf; ustack(@x) }", 10);
  test("kprobe:f { @x = perf; kstack(@x, 3) }", 10);
  test("kprobe:f { @x = perf; ustack(@x, 3) }", 10);
  test("kprobe:f { @x = 3; kstack(@x) }", 10);
  test("kprobe:f { @x = 3; ustack(@x) }", 10);
  test("kprobe:f { @x = 3; kstack(perf, @x) }", 10);
  test("kprobe:f { @x = 3; ustack(perf, @x) }", 10);
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
  test("kprobe:f { @x = 1 } kprobe:g { @x = \"abc\" }", 1);
}

TEST(semantic_analyser, variables_are_local)
{
  test("kprobe:f { $x = 1 } kprobe:g { $x = \"abc\"; }", 0);
  test("kprobe:f { $x = 1 } kprobe:g { @y = $x }", 1);
}

TEST(semantic_analyser, array_access) {
  test("kprobe:f { $s = arg0; @x = $s->y[0];}", 10);
  test("kprobe:f { $s = 0; @x = $s->y[0];}", 10);
  test("struct MyStruct { int y[4]; } kprobe:f { $s = (struct MyStruct *) "
       "arg0; @x = $s->y[5];}",
       10);
  test("struct MyStruct { int y[4]; } kprobe:f { $s = (struct MyStruct *) "
       "arg0; @x = $s->y[-1];}",
       10);
  test("struct MyStruct { int y[4]; } kprobe:f { $s = (struct MyStruct *) "
       "arg0; @x = $s->y[\"0\"];}",
       10);
  test("struct MyStruct { int y[4]; } kprobe:f { $s = (struct MyStruct *) "
       "arg0; $idx = 0; @x = $s->y[$idx];}",
       10);
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  test(driver,
       "struct MyStruct { int y[4]; } kprobe:f { $s = (struct MyStruct *) "
       "arg0; @x = $s->y[0];}",
       0);
  auto assignment = static_cast<ast::AssignMapStatement *>(
      driver.root_->probes->at(0)->stmts->at(1));
  EXPECT_EQ(SizedType(Type::integer, 8, true), assignment->map->type);
}

TEST(semantic_analyser, variable_type)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  test(driver, "kprobe:f { $x = 1 }", 0);
  SizedType st(Type::integer, 8, true);
  auto assignment = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(0));
  EXPECT_EQ(st, assignment->var->type);
}

TEST(semantic_analyser, unroll)
{
  test("kprobe:f { $i = 0; unroll(5) { printf(\"i: %d\\n\", $i); $i = $i + 1; } }", 0);
  test("kprobe:f { $i = 0; unroll(21) { printf(\"i: %d\\n\", $i); $i = $i + 1; } }", 1);
  test("kprobe:f { $i = 0; unroll(0) { printf(\"i: %d\\n\", $i); $i = $i + 1; } }", 1);
}

TEST(semantic_analyser, map_integer_sizes)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  std::string structs = "struct type1 { int x; }";
  test(driver, structs + "kprobe:f { $x = ((struct type1)0).x; @x = $x; }", 0);

  auto var_assignment = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(0));
  auto map_assignment = static_cast<ast::AssignMapStatement*>(driver.root_->probes->at(0)->stmts->at(1));
  EXPECT_EQ(SizedType(Type::integer, 4, true), var_assignment->var->type);
  EXPECT_EQ(SizedType(Type::integer, 8, true), map_assignment->map->type);
}

TEST(semantic_analyser, unop_dereference)
{
  test("kprobe:f { *0; }", 0);
  test("struct X { int n; } kprobe:f { $x = (struct X*)0; *$x; }", 0);
  test("struct X { int n; } kprobe:f { $x = (struct X)0; *$x; }", 1);
  test("kprobe:f { *\"0\"; }", 10);
}

TEST(semantic_analyser, unop_not)
{
  test("kprobe:f { ~0; }", 0);
  test("struct X { int n; } kprobe:f { $x = (struct X*)0; ~$x; }", 10);
  test("struct X { int n; } kprobe:f { $x = (struct X)0; ~$x; }", 10);
  test("kprobe:f { ~\"0\"; }", 10);
}

TEST(semantic_analyser, unop_increment_decrement)
{
  test("kprobe:f { $x = 0; $x++; }", 0);
  test("kprobe:f { $x = 0; $x--; }", 0);
  test("kprobe:f { $x = 0; ++$x; }", 0);
  test("kprobe:f { $x = 0; --$x; }", 0);

  test("kprobe:f { @x++; }", 0);
  test("kprobe:f { @x--; }", 0);
  test("kprobe:f { ++@x; }", 0);
  test("kprobe:f { --@x; }", 0);

  test("kprobe:f { $x++; }", 1);
  test("kprobe:f { @x = \"a\"; @x++; }", 1);
  test("kprobe:f { $x = \"a\"; $x++; }", 10);
}

TEST(semantic_analyser, printf)
{
  test("kprobe:f { printf(\"hi\") }", 0);
  test("kprobe:f { printf(1234) }", 1);
  test("kprobe:f { printf() }", 1);
  test("kprobe:f { $fmt = \"mystring\"; printf($fmt) }", 1);
  test("kprobe:f { printf(\"%s\", comm) }", 0);
  test("kprobe:f { printf(\"%-16s\", comm) }", 0);
  test("kprobe:f { printf(\"%-10.10s\", comm) }", 0);
  test("kprobe:f { printf(\"%A\", comm) }", 10);
  test("kprobe:f { @x = printf(\"hi\") }", 1);
  test("kprobe:f { $x = printf(\"hi\") }", 1);
}

TEST(semantic_analyser, system)
{
  test("kprobe:f { system(\"ls\") }", 0, false /* safe_mode */);
  test("kprobe:f { system(1234) }", 1, false /* safe_mode */);
  test("kprobe:f { system() }", 1, false /* safe_mode */);
  test("kprobe:f { $fmt = \"mystring\"; system($fmt) }", 1, false /* safe_mode */);
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

TEST(semantic_analyser, printf_format_int_with_length)
{
  test("kprobe:f { printf(\"int: %d\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %u\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %x\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %X\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %p\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %hhd\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hhu\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hhx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hhX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hhp\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %hd\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hu\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hp\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %ld\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %lu\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %lx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %lX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %lp\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %lld\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %llu\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %llx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %llX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %llp\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %jd\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %ju\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %jx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %jX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %jp\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %zd\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %zu\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %zx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %zX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %zp\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %td\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %tu\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %tx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %tX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %tp\", 1234) }", 0);
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

TEST(semantic_analyser, printf_format_buf)
{
  test("kprobe:f { printf(\"%r\", buf(\"mystr\", 5)) }", 0);
}

TEST(semantic_analyser, printf_bad_format_buf)
{
  test("kprobe:f { printf(\"%r\", \"mystr\") }", 10);
  test("kprobe:f { printf(\"%r\", arg0) }", 10);
}

TEST(semantic_analyser, printf_format_multi)
{
  test("kprobe:f { printf(\"%d %d %s\", 1, 2, \"mystr\") }", 0);
  test("kprobe:f { printf(\"%d %s %d\", 1, 2, \"mystr\") }", 10);
}

TEST(semantic_analyser, join)
{
  test("kprobe:f { join(arg0) }", 0);
  test("kprobe:f { printf(\"%s\", join(arg0)) }", 10);
  test("kprobe:f { join() }", 1);
  test("kprobe:f { $fmt = \"mystring\"; join($fmt) }", 10);
  test("kprobe:f { @x = join(arg0) }", 1);
  test("kprobe:f { $x = join(arg0) }", 1);
}

TEST(semantic_analyser, join_delimiter)
{
  test("kprobe:f { join(arg0, \",\") }", 0);
  test("kprobe:f { printf(\"%s\", join(arg0, \",\")) }", 10);
  test("kprobe:f { $fmt = \"mystring\"; join($fmt, \",\") }", 10);
  test("kprobe:f { @x = join(arg0, \",\") }", 1);
  test("kprobe:f { $x = join(arg0, \",\") }", 1);
  test("kprobe:f { join(arg0, 3) }", 10);
}

TEST(semantic_analyser, kprobe)
{
  test("kprobe:f { 1 }", 0);
  test("kretprobe:f { 1 }", 0);
}

TEST(semantic_analyser, uprobe)
{
  test("uprobe:/bin/sh:f { 1 }", 0);
  test("u:/bin/sh:f { 1 }", 0);
  test("uprobe:/bin/sh:0x10 { 1 }", 0);
  test("u:/bin/sh:0x10 { 1 }", 0);
  test("uprobe:/bin/sh:f+0x10 { 1 }", 0);
  test("u:/bin/sh:f+0x10 { 1 }", 0);
  test("uprobe:sh:f { 1 }", 0);
  test("uprobe:/notexistfile:f { 1 }", 1);
  test("uprobe:notexistfile:f { 1 }", 1);

  test("uretprobe:/bin/sh:f { 1 }", 0);
  test("ur:/bin/sh:f { 1 }", 0);
  test("uretprobe:sh:f { 1 }", 0);
  test("ur:sh:f { 1 }", 0);
  test("uretprobe:/bin/sh:0x10 { 1 }", 0);
  test("ur:/bin/sh:0x10 { 1 }", 0);
  test("uretprobe:/notexistfile:f { 1 }", 1);
  test("uretprobe:notexistfile:f { 1 }", 1);
}

TEST(semantic_analyser, usdt)
{
  test("usdt:/bin/sh:probe { 1 }", 0);
  test("usdt:sh:probe { 1 }", 0);
  test("usdt:/bin/sh:namespace:probe { 1 }", 0);
  test("usdt:/notexistfile:probe { 1 }", 1);
  test("usdt:notexistfile:probe { 1 }", 1);
}

TEST(semantic_analyser, begin_end_probes)
{
  test("BEGIN { 1 }", 0);
  test("BEGIN { 1 } BEGIN { 2 }", 10);

  test("END { 1 }", 0);
  test("END { 1 } END { 2 }", 10);
}

TEST(semantic_analyser, tracepoint)
{
  test("tracepoint:category:event { 1 }", 0);
}

TEST(semantic_analyser, watchpoint)
{
  test("watchpoint::0x1234:8:rw { 1 }", 0);
  test("watchpoint:/dev/null:0x1234:8:rw { 1 }", 0);
  test("watchpoint::0x1234:9:rw { 1 }", 1);
  test("watchpoint::0x1234:8:rwx { 1 }", 1);
  test("watchpoint::0x1234:8:rx { 1 }", 1);
  test("watchpoint::0x1234:8:b { 1 }", 1);
  test("watchpoint::0x1234:8:rww { 1 }", 1);
  test("watchpoint::0x0:8:rww { 1 }", 1);
}


TEST(semantic_analyser, args_builtin_wrong_use)
{
  test("BEGIN { args->foo }", 1);
  test("END { args->foo }", 1);
  test("kprobe:f { args->foo }", 1);
  test("kretprobe:f { args->foo }", 1);
  test("uprobe:/bin/sh:f { args->foo }", 1);
  test("uretprobe:/bin/sh/:f { args->foo }", 1);
  test("profile:ms:1 { args->foo }", 1);
  test("usdt:sh:probe { args->foo }", 1);
  test("profile:ms:100 { args->foo }", 1);
  test("hardware:cache-references:1000000 { args->foo }", 1);
  test("software:faults:1000 { args->foo }", 1);
  test("interval:s:1 { args->foo }", 1);
}

TEST(semantic_analyser, profile)
{
  test("profile:hz:997 { 1 }", 0);
  test("profile:s:10 { 1 }", 0);
  test("profile:ms:100 { 1 }", 0);
  test("profile:us:100 { 1 }", 0);
  test("profile:unit:100 { 1 }", 1);
}

TEST(semantic_analyser, variable_cast_types)
{
  std::string structs = "struct type1 { int field; } struct type2 { int field; }";
  test(structs + "kprobe:f { $x = (struct type1)cpu; $x = (struct type1)cpu; }", 0);
  test(structs + "kprobe:f { $x = (struct type1)cpu; $x = (struct type2)cpu; }", 1);
}

TEST(semantic_analyser, map_cast_types)
{
  std::string structs = "struct type1 { int field; } struct type2 { int field; }";
  test(structs + "kprobe:f { @x = (struct type1)cpu; @x = (struct type1)cpu; }", 0);
  test(structs + "kprobe:f { @x = (struct type1)cpu; @x = (struct type2)cpu; }", 1);
}

TEST(semantic_analyser, variable_casts_are_local)
{
  std::string structs = "struct type1 { int field; } struct type2 { int field; }";
  test(structs + "kprobe:f { $x = (struct type1)cpu } kprobe:g { $x = (struct type2)cpu; }", 0);
}

TEST(semantic_analyser, map_casts_are_global)
{
  std::string structs = "struct type1 { int field; } struct type2 { int field; }";
  test(structs + "kprobe:f { @x = (struct type1)cpu } kprobe:g { @x = (struct type2)cpu; }", 1);
}

TEST(semantic_analyser, cast_unknown_type)
{
  test("kprobe:f { (struct faketype)cpu }", 1);
}

TEST(semantic_analyser, field_access)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { ((struct type1)cpu).field }", 0);
  test(structs + "kprobe:f { $x = (struct type1)cpu; $x.field }", 0);
  test(structs + "kprobe:f { @x = (struct type1)cpu; @x.field }", 0);
  test("struct task_struct {int x;} kprobe:f { curtask->x }", 0);
}

TEST(semantic_analyser, field_access_wrong_field)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { ((struct type1)cpu).blah }", 1);
  test(structs + "kprobe:f { $x = (struct type1)cpu; $x.blah }", 1);
  test(structs + "kprobe:f { @x = (struct type1)cpu; @x.blah }", 1);
}

TEST(semantic_analyser, field_access_wrong_expr)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { 1234->field }", 10);
}

TEST(semantic_analyser, field_access_types)
{
  std::string structs = "struct type1 { int field; char mystr[8]; }"
                        "struct type2 { int field; }";

  test(structs + "kprobe:f { ((struct type1)0).field == 123 }", 0);
  test(structs + "kprobe:f { ((struct type1)0).field == \"abc\" }", 10);

  test(structs + "kprobe:f { ((struct type1)0).mystr == \"abc\" }", 0);
  test(structs + "kprobe:f { ((struct type1)0).mystr == 123 }", 10);

  test(structs + "kprobe:f { ((struct type1)0).field == ((struct type2)0).field }", 0);
  test(structs + "kprobe:f { ((struct type1)0).mystr == ((struct type2)0).field }", 10);
}

TEST(semantic_analyser, field_access_pointer)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { ((struct type1*)0)->field }", 0);
  test(structs + "kprobe:f { ((struct type1*)0).field }", 1);
  test(structs + "kprobe:f { *((struct type1*)0) }", 0);
}

TEST(semantic_analyser, field_access_sub_struct)
{
  std::string structs = "struct type2 { int field; } "
                        "struct type1 { struct type2 *type2ptr; struct type2 type2; }";

  test(structs + "kprobe:f { ((struct type1)0).type2ptr->field }", 0);
  test(structs + "kprobe:f { ((struct type1)0).type2.field }", 0);
  test(structs + "kprobe:f { $x = (struct type2)0; $x = ((struct type1)0).type2 }", 0);
  test(structs + "kprobe:f { $x = (struct type2*)0; $x = ((struct type1)0).type2ptr }", 0);
  test(structs + "kprobe:f { $x = (struct type1)0; $x = ((struct type1)0).type2 }", 1);
  test(structs + "kprobe:f { $x = (struct type1*)0; $x = ((struct type1)0).type2ptr }", 1);
}

TEST(semantic_analyser, field_access_is_internal)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  std::string structs = "struct type1 { int x; }";

  test(driver, structs + "kprobe:f { $x = ((struct type1)0).x }", 0);
  auto var_assignment1 = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(0));
  EXPECT_EQ(false, var_assignment1->var->type.is_internal);

  test(driver, structs + "kprobe:f { @type1 = (struct type1)0; $x = @type1.x }", 0);
  auto map_assignment = static_cast<ast::AssignMapStatement*>(driver.root_->probes->at(0)->stmts->at(0));
  auto var_assignment2 = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(1));
  EXPECT_EQ(true, map_assignment->map->type.is_internal);
  EXPECT_EQ(true, var_assignment2->var->type.is_internal);
}

TEST(semantic_analyser, probe_short_name)
{
  test("t:a:b { args }", 0);
  test("k:f { pid }", 0);
  test("kr:f { pid }", 0);
  test("u:sh:f { 1 }", 0);
  test("ur:sh:f { 1 }", 0);
  test("p:hz:997 { 1 }", 0);
  test("h:cache-references:1000000 { 1 }", 0);
  test("s:faults:1000 { 1 }", 0);
  test("i:s:1 { 1 }", 0);
}

TEST(semantic_analyser, positional_parameters)
{
  BPFtrace bpftrace;
  bpftrace.add_param("123");
  bpftrace.add_param("hello");
  bpftrace.add_param("0x123");

  test(bpftrace, "kprobe:f { printf(\"%d\", $0); }", 1);
  test(bpftrace, "kprobe:f { printf(\"%s\", str($0)); }", 1);

  test(bpftrace, "kprobe:f { printf(\"%d\", $1); }", 0);
  test(bpftrace, "kprobe:f { printf(\"%s\", str($1)); }", 10);

  test(bpftrace, "kprobe:f { printf(\"%s\", str($2)); }", 0);
  test(bpftrace, "kprobe:f { printf(\"%d\", $2); }", 10);

  test(bpftrace, "kprobe:f { printf(\"%d\", $3); }", 0);

  // Parameters are not required to exist to be used:
  test(bpftrace, "kprobe:f { printf(\"%s\", str($4)); }", 0);
  test(bpftrace, "kprobe:f { printf(\"%d\", $4); }", 0);

  test(bpftrace, "kprobe:f { printf(\"%d\", $#); }", 0);
  test(bpftrace, "kprobe:f { printf(\"%s\", str($#)); }", 10);

  Driver driver(bpftrace);
  test(driver, "k:f { $1 }", 0);
  auto stmt = static_cast<ast::ExprStatement *>(
      driver.root_->probes->at(0)->stmts->at(0));
  auto pp = static_cast<ast::PositionalParameter *>(stmt->expr);
  EXPECT_EQ(SizedType(Type::integer, 8, true), pp->type);
  EXPECT_TRUE(pp->is_literal);

  bpftrace.add_param("0999");
  test(bpftrace, "kprobe:f { printf(\"%d\", $4); }", 10);
}

TEST(semantic_analyser, macros)
{
  test("#define A 1\nkprobe:f { printf(\"%d\", A); }", 0);
  test("#define A A\nkprobe:f { printf(\"%d\", A); }", 1);
  test("enum { A = 1 }\n#define A A\nkprobe:f { printf(\"%d\", A); }", 0);
}

TEST(semantic_analyser, enums)
{
  test("enum { a = 1, b } kprobe:f { printf(\"%d\", a); }", 0);
}

TEST(semantic_analyser, signed_int_comparison_warnings)
{
  bool invert = true;
  std::string cmp_sign = "comparison of integers of different signs";
  test_for_warning("kretprobe:f /-1 < retval/ {}", cmp_sign);
  test_for_warning("kretprobe:f /-1 > retval/ {}", cmp_sign);
  test_for_warning("kretprobe:f /-1 >= retval/ {}", cmp_sign);
  test_for_warning("kretprobe:f /-1 <= retval/ {}", cmp_sign);
  test_for_warning("kretprobe:f /-1 != retval/ {}", cmp_sign);
  test_for_warning("kretprobe:f /-1 == retval/ {}", cmp_sign);
  test_for_warning("kretprobe:f /retval > -1/ {}", cmp_sign);
  test_for_warning("kretprobe:f /retval < -1/ {}", cmp_sign);

  // These should not trigger a warning
  test_for_warning("kretprobe:f /1 < retval/ {}", cmp_sign, invert);
  test_for_warning("kretprobe:f /1 > retval/ {}", cmp_sign, invert);
  test_for_warning("kretprobe:f /1 >= retval/ {}", cmp_sign, invert);
  test_for_warning("kretprobe:f /1 <= retval/ {}", cmp_sign, invert);
  test_for_warning("kretprobe:f /1 != retval/ {}", cmp_sign, invert);
  test_for_warning("kretprobe:f /1 == retval/ {}", cmp_sign, invert);
  test_for_warning("kretprobe:f /retval > 1/ {}", cmp_sign, invert);
  test_for_warning("kretprobe:f /retval < 1/ {}", cmp_sign, invert);
}

TEST(semantic_analyser, signed_int_arithmetic_warnings)
{
  // Test type warnings for arithmetic
  bool invert = true;
  std::string msg = "arithmetic on integers of different signs";

  test_for_warning("kprobe:f { @ = -1 - arg0 }", msg);
  test_for_warning("kprobe:f { @ = -1 + arg0 }", msg);
  test_for_warning("kprobe:f { @ = -1 * arg0 }", msg);
  test_for_warning("kprobe:f { @ = -1 / arg0 }", msg);

  test_for_warning("kprobe:f { @ = arg0 + 1 }", msg, invert);
  test_for_warning("kprobe:f { @ = arg0 - 1 }", msg, invert);
  test_for_warning("kprobe:f { @ = arg0 * 1 }", msg, invert);
  test_for_warning("kprobe:f { @ = arg0 / 1 }", msg, invert);
}

TEST(semantic_analyser, signed_int_division_warnings)
{
  bool invert = true;
  std::string msg = "signed operands";
  test_for_warning("kprobe:f { @ = -1 / 1 }", msg);
  test_for_warning("kprobe:f { @ = 1 / -1 }", msg);

  // These should not trigger a warning
  test_for_warning("kprobe:f { @ = 1 / 1 }", msg, invert);
  test_for_warning("kprobe:f { @ = -(1 / 1) }", msg, invert);
}

TEST(semantic_analyser, signed_int_modulo_warnings)
{
  bool invert = true;
  std::string msg = "signed operands";
  test_for_warning("kprobe:f { @ = -1 % 1 }", msg);
  test_for_warning("kprobe:f { @ = 1 % -1 }", msg);

  // These should not trigger a warning
  test_for_warning("kprobe:f { @ = 1 % 1 }", msg, invert);
  test_for_warning("kprobe:f { @ = -(1 % 1) }", msg, invert);
}

TEST(semantic_analyser, map_as_lookup_table)
{
  // Initializing a map should not lead to usage issues
  test("BEGIN { @[0] = \"abc\"; @[1] = \"def\" } kretprobe:f { printf(\"%s\\n\", @[retval])}");
}

TEST(semantic_analyser, cast_sign)
{
  // The C struct parser should set the is_signed flag on signed types
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  std::string prog =
    "struct t { int s; unsigned int us; long l; unsigned long ul }; "
    "kprobe:f { "
    "  $t = ((struct t *)0xFF);"
    "  $s = $t->s; $us = $t->us; $l = $t->l; $lu = $t->ul; }";
  test(driver, prog, 0);

  auto s  = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(1));
  auto us = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(2));
  auto l  = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(3));
  auto ul = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(4));
  EXPECT_EQ(SizedType(Type::integer, 4, true),  s->var->type);
  EXPECT_EQ(SizedType(Type::integer, 4, false), us->var->type);
  EXPECT_EQ(SizedType(Type::integer, 8, true),  l->var->type);
  EXPECT_EQ(SizedType(Type::integer, 8, false), ul->var->type);
}

TEST(semantic_analyser, binop_sign)
{
  // Make sure types are correct
  std::string prog_pre =
    "struct t { long l; unsigned long ul }; "
    "kprobe:f { "
    "  $t = ((struct t *)0xFF); ";

  std::string operators[] = { "==", "!=", "<", "<=", ">", ">=", "+", "-", "/", "*"};
  for(std::string op : operators)
  {
    BPFtrace bpftrace;
    Driver driver(bpftrace);
    std::string prog = prog_pre +
      "$varA = $t->l "  + op + " $t->l; "
      "$varB = $t->ul " + op + " $t->l; "
      "$varC = $t->ul " + op + " $t->ul;"
      "}";

    test(driver, prog, 0);
    auto varA = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(1));
    EXPECT_EQ(SizedType(Type::integer, 8, true), varA->var->type);
    auto varB = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(2));
    EXPECT_EQ(SizedType(Type::integer, 8, false), varB->var->type);
    auto varC = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(3));
    EXPECT_EQ(SizedType(Type::integer, 8, false), varC->var->type);
  }
}

TEST(semantic_analyser, int_cast_types)
{
  test("kretprobe:f { @ = (int8)retval }", 0);
  test("kretprobe:f { @ = (int16)retval }", 0);
  test("kretprobe:f { @ = (int32)retval }", 0);
  test("kretprobe:f { @ = (int64)retval }", 0);
  test("kretprobe:f { @ = (uint8)retval }", 0);
  test("kretprobe:f { @ = (uint16)retval }", 0);
  test("kretprobe:f { @ = (uint32)retval }", 0);
  test("kretprobe:f { @ = (uint64)retval }", 0);

  test("kretprobe:f { @ = (int2)retval }", 1);
  test("kretprobe:f { @ = (uint2)retval }", 1);
}

TEST(semantic_analyser, int_cast_usage)
{
  test("kretprobe:f /(int32) retval < 0 / {}", 0);
  test("kprobe:f /(int32) arg0 < 0 / {}", 0);
  test("kprobe:f { @=sum((int32)arg0) }", 0);
  test("kprobe:f { @=avg((int32)arg0) }", 0);
  test("kprobe:f { @=avg((int32)arg0) }", 0);

  test("kprobe:f { @=avg((int32)\"abc\") }", 1);
}

TEST(semantic_analyser, intptr_cast_types)
{
  test("kretprobe:f { @ = *(int8*)retval }", 0);
  test("kretprobe:f { @ = *(int16*)retval }", 0);
  test("kretprobe:f { @ = *(int32*)retval }", 0);
  test("kretprobe:f { @ = *(int64*)retval }", 0);
  test("kretprobe:f { @ = *(uint8*)retval }", 0);
  test("kretprobe:f { @ = *(uint16*)retval }", 0);
  test("kretprobe:f { @ = *(uint32*)retval }", 0);
  test("kretprobe:f { @ = *(uint64*)retval }", 0);

  test("kretprobe:f { @ = *(int2*)retval }", 1);
  test("kretprobe:f { @ = *(uint2*)retval }", 1);
}

TEST(semantic_analyser, intptr_cast_usage)
{
  test("kretprobe:f /(*(int32*) retval) < 0 / {}", 0);
  test("kprobe:f /(*(int32*) arg0) < 0 / {}", 0);
  test("kprobe:f { @=sum(*(int32*)arg0) }", 0);
  test("kprobe:f { @=avg(*(int32*)arg0) }", 0);
  test("kprobe:f { @=avg(*(int32*)arg0) }", 0);

  // This is OK (@ = 0x636261)
  test("kprobe:f { @=avg(*(int32*)\"abc\") }", 0);
  test("kprobe:f { @=avg(*(int32*)123) }", 0);
}

TEST(semantic_analyser, signal)
{
  // int literals
  test("k:f { signal(1); }", 0, false);
  test("kr:f { signal(1); }", 0, false);
  test("u:/bin/sh:f { signal(11); }", 0, false);
  test("ur:/bin/sh:f { signal(11); }", 0, false);
  test("p:hz:1 { signal(1); }", 0, false);

  // vars
  test("k:f { @=1; signal(@); }", 0, false);
  test("k:f { @=1; signal((int32)arg0); }", 0, false);

  // String
  test("k:f { signal(\"KILL\"); }", 0, false);
  test("k:f { signal(\"SIGKILL\"); }", 0, false);

  // Not allowed for:
  test("hardware:pcm:1000 { signal(1); }", 1, false);
  test("software:pcm:1000 { signal(1); }", 1, false);
  test("BEGIN { signal(1); }", 1, false);
  test("END { signal(1); }", 1, false);
  test("i:s:1 { signal(1); }", 1, false);

  // invalid signals
  test("k:f { signal(0); }", 1, false);
  test("k:f { signal(-100); }", 1, false);
  test("k:f { signal(100); }", 1, false);
  test("k:f { signal(\"SIGABC\"); }", 1, false);
  test("k:f { signal(\"ABC\"); }", 1, false);

  // Missing kernel support
  MockBPFfeature feature(false);
  test(feature, "k:f { signal(1) }", 1, false);
  test(feature, "k:f { signal(\"KILL\"); }", 1, false);
}

TEST(semantic_analyser, strncmp)
{
  // Test strncmp builtin
  test("i:s:1 { $a = \"bar\"; strncmp(\"foo\", $a, 1) }", 0);
  test("i:s:1 { strncmp(\"foo\", \"bar\", 1) }", 0);
  test("i:s:1 { strncmp(1) }", 1);
  test("i:s:1 { strncmp(1,1,1) }", 10);
  test("i:s:1 { strncmp(\"a\",1,1) }", 10);
  test("i:s:1 { strncmp(\"a\",\"a\",-1) }", 1);
  test("i:s:1 { strncmp(\"a\",\"a\",\"foo\") }", 1);
}

TEST(semantic_analyser, override)
{
  // literals
  test("k:f { override(-1); }", 0, false);

  // variables
  test("k:f { override(arg0); }", 0, false);

  // Probe types
  test("kr:f { override(-1); }", 1, false);
  test("u:/bin/sh:f { override(-1); }", 1, false);
  test("t:syscalls:sys_enter_openat { override(-1); }", 1, false);
  test("i:s:1 { override(-1); }", 1, false);
  test("p:hz:1 { override(-1); }", 1, false);
}

TEST(semantic_analyser, struct_member_keywords)
{
  std::string keywords[] = {
    "arg0", "args", "curtask", "func", "gid" "rand", "uid",
    "avg", "cat", "exit", "kaddr", "min", "printf", "usym",
    "kstack", "ustack", "bpftrace", "perf", "uprobe", "kprobe",
  };
  for(auto kw : keywords)
  {
    test("struct S{ int " + kw + ";}; k:f { ((struct S*)arg0)->" + kw + "}", 0);
    test("struct S{ int " + kw + ";}; k:f { ((struct S)arg0)." + kw + "}", 0);
  }
}

TEST(semantic_analyser, builtin_args)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, "t:sched:sched_one { args->common_field }", 0);
  test(*bpftrace, "t:sched:sched_two { args->common_field }", 0);
  test(*bpftrace, "t:sched:sched_one,"
                  "t:sched:sched_two { args->common_field }", 0);
  test(*bpftrace, "t:sched:sched_* { args->common_field }", 0);
  test(*bpftrace, "t:sched:sched_one { args->not_a_field }", 1);
}

TEST(semantic_analyser, type_ctx)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  std::string structs = "struct c {char c} struct x { long a; short b[4]; "
                        "struct c c; struct c *d;}";
  test(driver,
       structs + "kprobe:f { $x = (struct x*)ctx; $a = $x->a; $b = $x->b[0]; "
                 "$c = $x->c.c; $d = $x->d->c;}",
       0);
  auto &stmts = driver.root_->probes->at(0)->stmts;

  // $x = (struct x*)ctx;
  auto assignment = static_cast<ast::AssignVarStatement *>(stmts->at(0));
  EXPECT_EQ(SizedType(Type::ctx, 8, false), assignment->var->type);

  // $a = $x->a;
  assignment = static_cast<ast::AssignVarStatement *>(stmts->at(1));
  EXPECT_EQ(SizedType(Type::integer, 8, true), assignment->var->type);
  auto fieldaccess = static_cast<ast::FieldAccess *>(assignment->expr);
  EXPECT_EQ(SizedType(Type::integer, 8, true), fieldaccess->type);
  auto unop = static_cast<ast::Unop *>(fieldaccess->expr);
  EXPECT_EQ(SizedType(Type::ctx, 32, false), unop->type);
  auto var = static_cast<ast::Variable *>(unop->expr);
  EXPECT_EQ(SizedType(Type::ctx, 8, false), var->type);

  // $b = $x->b[0];
  assignment = static_cast<ast::AssignVarStatement *>(stmts->at(2));
  EXPECT_EQ(SizedType(Type::integer, 2, true), assignment->var->type);
  auto arrayaccess = static_cast<ast::ArrayAccess *>(assignment->expr);
  EXPECT_EQ(SizedType(Type::integer, 2, true), arrayaccess->type);
  fieldaccess = static_cast<ast::FieldAccess *>(arrayaccess->expr);
  EXPECT_EQ(SizedType(Type::ctx, 4, true), fieldaccess->type);
  unop = static_cast<ast::Unop *>(fieldaccess->expr);
  EXPECT_EQ(SizedType(Type::ctx, 32, false), unop->type);
  var = static_cast<ast::Variable *>(unop->expr);
  EXPECT_EQ(SizedType(Type::ctx, 8, false), var->type);

  // $c = $x->c.c;
  assignment = static_cast<ast::AssignVarStatement *>(stmts->at(3));
  EXPECT_EQ(SizedType(Type::integer, 1, true), assignment->var->type);
  fieldaccess = static_cast<ast::FieldAccess *>(assignment->expr);
  EXPECT_EQ(SizedType(Type::integer, 1, true), fieldaccess->type);
  fieldaccess = static_cast<ast::FieldAccess *>(fieldaccess->expr);
  EXPECT_EQ(SizedType(Type::ctx, 1, false), fieldaccess->type);
  unop = static_cast<ast::Unop *>(fieldaccess->expr);
  EXPECT_EQ(SizedType(Type::ctx, 32, false), unop->type);
  var = static_cast<ast::Variable *>(unop->expr);
  EXPECT_EQ(SizedType(Type::ctx, 8, false), var->type);

  // $d = $x->d->c;
  assignment = static_cast<ast::AssignVarStatement *>(stmts->at(4));
  EXPECT_EQ(SizedType(Type::integer, 1, true), assignment->var->type);
  fieldaccess = static_cast<ast::FieldAccess *>(assignment->expr);
  EXPECT_EQ(SizedType(Type::integer, 1, true), fieldaccess->type);
  unop = static_cast<ast::Unop *>(fieldaccess->expr);
  EXPECT_EQ(SizedType(Type::cast, 1, false), unop->type);
  fieldaccess = static_cast<ast::FieldAccess *>(unop->expr);
  EXPECT_EQ(SizedType(Type::cast, 8, false), fieldaccess->type);
  unop = static_cast<ast::Unop *>(fieldaccess->expr);
  EXPECT_EQ(SizedType(Type::ctx, 32, false), unop->type);
  var = static_cast<ast::Variable *>(unop->expr);
  EXPECT_EQ(SizedType(Type::ctx, 8, false), var->type);

  test(driver, "k:f, kr:f { @ = (uint64)ctx; }", 0);
  test(driver, "k:f, i:s:1 { @ = (uint64)ctx; }", 1);
  test(driver, "t:sched:sched_one { @ = (uint64)ctx; }", 1);
}

#ifdef HAVE_LIBBPF_BTF_DUMP

#include "btf_common.h"

class semantic_analyser_btf : public test_btf
{
};

TEST_F(semantic_analyser_btf, kfunc)
{
  test("kfunc:func_1 { 1 }", 0);
  test("kretfunc:func_1 { 1 }", 0);
  test("kfunc:func_1 { $x = args->a; $y = args->foo1; }", 0);
  test("kretfunc:func_1 { $x = retval; }", 0);
  test("kretfunc:func_1 { $x = args->foo; }", 1);
}

TEST_F(semantic_analyser_btf, short_name)
{
  test("f:func_1 { 1 }", 0);
  test("fr:func_1 { 1 }", 0);
}

#endif // HAVE_LIBBPF_BTF_DUMP

} // namespace semantic_analyser
} // namespace test
} // namespace bpftrace
