#include "ast/semantic_analyser.h"
#include "ast/field_analyser.h"
#include "bpffeature.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "driver.h"
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
  std::stringstream out;
  // Override to mockbpffeature.
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, out);
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
          bool mock_has_features,
          Driver &driver,
          const std::string &input,
          int expected_result = 0,
          bool safe_mode = true,
          bool has_child = false,
          int expected_field_analyser = 0,
          int expected_parse = 0)
{
  std::stringstream out;
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  bpftrace.safe_mode_ = safe_mode;
  ASSERT_EQ(driver.parse_str(input), expected_parse);

  // Can't continue if parsing failed
  if (expected_parse)
    return;

  ast::FieldAnalyser fields(driver.root_, bpftrace, out);
  EXPECT_EQ(fields.analyse(), expected_field_analyser) << msg.str() + out.str();

  ClangParser clang;
  clang.parse(driver.root_, bpftrace);

  ASSERT_EQ(driver.parse_str(input), 0);
  out.str("");
  // Override to mockbpffeature.
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(mock_has_features);
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, out, has_child);
  EXPECT_EQ(expected_result, semantics.analyse()) << msg.str() + out.str();
}

void test(BPFtrace &bpftrace,
    const std::string &input,
    int expected_result=0,
    bool safe_mode = true)
{
  Driver driver(bpftrace);
  test(bpftrace, true, driver, input, expected_result, safe_mode);
}

void test(Driver &driver,
    const std::string &input,
    int expected_result=0,
    bool safe_mode = true)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, true, driver, input, expected_result, safe_mode);
}

void test(MockBPFfeature &feature,
          const std::string &input,
          int expected_result = 0,
          bool safe_mode = true)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);
  bool mock_has_features = feature.has_features_;
  test(*bpftrace, mock_has_features, driver, input, expected_result, safe_mode);
}

void test(const std::string &input,
          int expected_result = 0,
          bool safe_mode = true,
          bool has_child = false,
          int expected_field_analyser = 0,
          int expected_parse = 0)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);
  test(*bpftrace,
       true,
       driver,
       input,
       expected_result,
       safe_mode,
       has_child,
       expected_field_analyser,
       expected_parse);
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
  test("i:ms:100 { printf(\"%d\\n\", cpid); }", 1, false, false);
  test("i:ms:100 { @=cpid }", 1, false, false);
  test("i:ms:100 { $a=cpid }", 1, false, false);

  test("i:ms:100 { printf(\"%d\\n\", cpid); }", 0, false, true);
  test("i:ms:100 { @=cpid }", 0, false, true);
  test("i:ms:100 { $a=cpid }", 0, false, true);
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
#ifdef ARCH_X86_64
  test("kprobe:f { reg(\"ip\") }", 0);
#endif
  test("kprobe:f { kstack(1) }", 0);
  test("kprobe:f { ustack(1) }", 0);
  test("kprobe:f { cat(\"/proc/uptime\") }", 0);
  test("uprobe:/bin/bash:main { uaddr(\"glob_asciirange\") }", 0);
  test("kprobe:f { cgroupid(\"/sys/fs/cgroup/unified/mycg\"); }", 0);
  test("kprobe:f { macaddr(0xffff) }", 0);
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
  test("kprobe:f { pid < 10000 ? printf(\"lo\") : exit() }", 0);
  test("kprobe:f { @x = pid < 10000 ? printf(\"lo\") : cat(\"/proc/uptime\") }",
       10);
  test("kprobe:f { pid < 10000 ? 3 : cat(\"/proc/uptime\") }", 10);
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
  test("kprobe:f { if(hist()) { 123 } }", 1);
  test("kprobe:f { hist() ? 0 : 1; }", 1);
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
  test("kprobe:f { if(lhist()) { 123 } }", 1);
  test("kprobe:f { lhist() ? 0 : 1; }", 1);
}

TEST(semantic_analyser, call_count)
{
  test("kprobe:f { @x = count(); }", 0);
  test("kprobe:f { @x = count(1); }", 1);
  test("kprobe:f { count(); }", 1);
  test("kprobe:f { $x = count(); }", 1);
  test("kprobe:f { @[count()] = 1; }", 1);
  test("kprobe:f { if(count()) { 123 } }", 1);
  test("kprobe:f { count() ? 0 : 1; }", 1);
}

TEST(semantic_analyser, call_sum)
{
  test("kprobe:f { @x = sum(123); }", 0);
  test("kprobe:f { @x = sum(); }", 1);
  test("kprobe:f { @x = sum(123, 456); }", 1);
  test("kprobe:f { sum(123); }", 1);
  test("kprobe:f { $x = sum(123); }", 1);
  test("kprobe:f { @[sum(123)] = 1; }", 1);
  test("kprobe:f { if(sum(1)) { 123 } }", 1);
  test("kprobe:f { sum(1) ? 0 : 1; }", 1);
}

TEST(semantic_analyser, call_min)
{
  test("kprobe:f { @x = min(123); }", 0);
  test("kprobe:f { @x = min(); }", 1);
  test("kprobe:f { min(123); }", 1);
  test("kprobe:f { $x = min(123); }", 1);
  test("kprobe:f { @[min(123)] = 1; }", 1);
  test("kprobe:f { if(min(1)) { 123 } }", 1);
  test("kprobe:f { min(1) ? 0 : 1; }", 1);
}

TEST(semantic_analyser, call_max)
{
  test("kprobe:f { @x = max(123); }", 0);
  test("kprobe:f { @x = max(); }", 1);
  test("kprobe:f { max(123); }", 1);
  test("kprobe:f { $x = max(123); }", 1);
  test("kprobe:f { @[max(123)] = 1; }", 1);
  test("kprobe:f { if(max(1)) { 123 } }", 1);
  test("kprobe:f { max(1) ? 0 : 1; }", 1);
}

TEST(semantic_analyser, call_avg)
{
  test("kprobe:f { @x = avg(123); }", 0);
  test("kprobe:f { @x = avg(); }", 1);
  test("kprobe:f { avg(123); }", 1);
  test("kprobe:f { $x = avg(123); }", 1);
  test("kprobe:f { @[avg(123)] = 1; }", 1);
  test("kprobe:f { if(avg(1)) { 123 } }", 1);
  test("kprobe:f { avg(1) ? 0 : 1; }", 1);
}

TEST(semantic_analyser, call_stats)
{
  test("kprobe:f { @x = stats(123); }", 0);
  test("kprobe:f { @x = stats(); }", 1);
  test("kprobe:f { stats(123); }", 1);
  test("kprobe:f { $x = stats(123); }", 1);
  test("kprobe:f { @[stats(123)] = 1; }", 1);
  test("kprobe:f { if(stats(1)) { 123 } }", 1);
  test("kprobe:f { stats(1) ? 0 : 1; }", 1);
}

TEST(semantic_analyser, call_delete)
{
  test("kprobe:f { @x = 1; delete(@x); }", 0);
  test("kprobe:f { delete(1); }", 1);
  test("kprobe:f { delete(); }", 1);
  test("kprobe:f { @y = delete(@x); }", 1);
  test("kprobe:f { $y = delete(@x); }", 1);
  test("kprobe:f { @[delete(@x)] = 1; }", 1);
  test("kprobe:f { @x = 1; if(delete(@x)) { 123 } }", 10);
  test("kprobe:f { @x = 1; delete(@x) ? 0 : 1; }", 10);
}

TEST(semantic_analyser, call_exit)
{
  test("kprobe:f { exit(); }", 0);
  test("kprobe:f { exit(1); }", 1);
  test("kprobe:f { @a = exit(); }", 1);
  test("kprobe:f { @a = exit(1); }", 1);
  test("kprobe:f { $a = exit(1); }", 1);
  test("kprobe:f { @[exit(1)] = 1; }", 1);
  test("kprobe:f { if(exit()) { 123 } }", 10);
  test("kprobe:f { exit() ? 0 : 1; }", 10);
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
  test("kprobe:f { @x = count(); if(print(@x)) { 123 } }", 10);
  test("kprobe:f { @x = count(); print(@x) ? 0 : 1; }", 10);

  test_for_warning("kprobe:f { @x = stats(10); print(@x, 2); }",
                   "top and div arguments are ignored");
  test_for_warning("kprobe:f { @x = stats(10); print(@x, 2, 3); }",
                   "top and div arguments are ignored");
}

TEST(semantic_analyser, call_print_non_map)
{
  test(R"_(BEGIN { print(1) })_", 0);
  test(R"_(BEGIN { print(comm) })_", 0);
  test(R"_(BEGIN { print(nsecs) })_", 0);
  test(R"_(BEGIN { print("string") })_", 0);
  test(R"_(BEGIN { print((1, 2, "tuple")) })_", 0);
  test(R"_(BEGIN { $x = 1; print($x) })_", 0);
  test(R"_(BEGIN { $x = 1; $y = $x + 3; print($y) })_", 0);

  test(R"_(BEGIN { print(3, 5) })_", 1);
  test(R"_(BEGIN { print(3, 5, 2) })_", 1);

  test(R"_(BEGIN { print(exit()) })_", 10);
  test(R"_(BEGIN { print(count()) })_", 1);
  test(R"_(BEGIN { print(ctx) })_", 10);
  test(R"_(BEGIN { print((int8 *)0) })_", 10);
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
  test("kprobe:f { @x = count(); if(clear(@x)) { 123 } }", 10);
  test("kprobe:f { @x = count(); clear(@x) ? 0 : 1; }", 10);
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
  test("kprobe:f { @x = count(); if(zero(@x)) { 123 } }", 10);
  test("kprobe:f { @x = count(); zero(@x) ? 0 : 1; }", 10);
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
  test("kprobe:f { if(time()) { 123 } }", 10);
  test("kprobe:f { time() ? 0 : 1; }", 10);
}

TEST(semantic_analyser, call_strftime)
{
  test("kprobe:f { strftime(\"%M:%S\", 1); }", 0);
  test("kprobe:f { strftime(\"%M:%S\", nsecs); }", 0);
  test("kprobe:f { strftime(\"%M:%S\", \"\"); }", 10);
  test("kprobe:f { strftime(1, nsecs); }", 10);
  test("kprobe:f { $var = \"str\"; strftime($var, nsecs); }", 10);
  test("kprobe:f { strftime(); }", 1);
  test("kprobe:f { strftime(\"%M:%S\"); }", 1);
  test("kprobe:f { strftime(\"%M:%S\", 1, 1); }", 1);
  test("kprobe:f { strftime(1, 1, 1); }", 1);
  test("kprobe:f { strftime(\"%M:%S\", \"\", 1); }", 1);
  test("kprobe:f { $ts = strftime(\"%M:%S\", 1); }", 0);
  test("kprobe:f { @ts = strftime(\"%M:%S\", nsecs); }", 0);
  test("kprobe:f { @[strftime(\"%M:%S\", nsecs)] = 1; }", 0);
  test("kprobe:f { printf(\"%s\", strftime(\"%M:%S\", nsecs)); }", 0);
  test("kprobe:f { strncmp(\"str\", strftime(\"%M:%S\", nsecs), 10); }", 10);
}

TEST(semantic_analyser, call_str)
{
  test("kprobe:f { str(arg0); }", 0);
  test("kprobe:f { @x = str(arg0); }", 0);
  test("kprobe:f { str(); }", 1);
  test("kprobe:f { str(\"hello\"); }", 1);
}

TEST(semantic_analyser, call_str_2_lit)
{
  test("kprobe:f { str(arg0, 3); }", 0);
  test("kprobe:f { str(arg0, -3); }", 10);
  test("kprobe:f { @x = str(arg0, 3); }", 0);
  test("kprobe:f { str(arg0, \"hello\"); }", 10);
}

TEST(semantic_analyser, call_str_2_expr)
{
  test("kprobe:f { str(arg0, arg1); }", 0);
  test("kprobe:f { @x = str(arg0, arg1); }", 0);
}

TEST(semantic_analyser, call_str_state_leak_regression_test)
{
  // Previously, the semantic analyser would leak state in the first str()
  // call. This would make the semantic analyser think it's still processing
  // a positional parameter in the second str() call causing confusing error
  // messages.
  test(R"PROG(kprobe:f { $x = str($1) == "asdf"; $y = str(arg0) })PROG", 0);
}

TEST(semantic_analyser, call_buf)
{
  test("kprobe:f { buf(arg0, 1); }", 0);
  test("kprobe:f { buf(arg0, -1); }", 1);
  test("kprobe:f { @x = buf(arg0, 1); }", 0);
  test("kprobe:f { $x = buf(arg0, 1); }", 0);
  test("kprobe:f { buf(); }", 1);
  test("kprobe:f { buf(\"hello\"); }", 10);
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

  // Regression test that ntop can use arguments from the prog context
  test("tracepoint:tcp:some_tcp_tp { ntop(args->saddr_v6); }", 0);

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

  std::vector<int> sizes = { 8, 16, 32, 64, 64, 64 };

  for (size_t i = 0; i < sizes.size(); i++)
  {
    auto v = static_cast<ast::AssignVarStatement *>(
        driver.root_->probes->at(0)->stmts->at(i));
    EXPECT_TRUE(v->var->type.IsPtrTy());
    EXPECT_TRUE(v->var->type.GetPointeeTy()->IsIntTy());
    EXPECT_EQ((unsigned long int)sizes.at(i),
              v->var->type.GetPointeeTy()->GetIntBitWidth());
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
#ifdef ARCH_X86_64
  test("kprobe:f { reg(\"ip\"); }", 0);
  test("kprobe:f { @x = reg(\"ip\"); }", 0);
#endif
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
  test("kprobe:f { if(cat(\"/proc/loadavg\")) { 123 } }", 10);
  test("kprobe:f { cat(\"/proc/loadavg\") ? 0 : 1; }", 10);
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
  test("kprobe:f { kstack(3, perf) }", 1);
  test("kprobe:f { ustack(3, perf) }", 1);
  test("kprobe:f { kstack(perf, 3, 4) }", 1);
  test("kprobe:f { ustack(perf, 3, 4) }", 1);
  test("kprobe:f { kstack(bob) }", 1);
  test("kprobe:f { ustack(bob) }", 1);
  test("kprobe:f { kstack(\"str\") }", 1);
  test("kprobe:f { ustack(\"str\") }", 1);
  test("kprobe:f { kstack(perf, \"str\") }", 1);
  test("kprobe:f { ustack(perf, \"str\") }", 1);
  test("kprobe:f { kstack(\"str\", 3) }", 1);
  test("kprobe:f { ustack(\"str\", 3) }", 1);

  // Non-literals
  test("kprobe:f { @x = perf; kstack(@x) }", 1);
  test("kprobe:f { @x = perf; ustack(@x) }", 1);
  test("kprobe:f { @x = perf; kstack(@x, 3) }", 1);
  test("kprobe:f { @x = perf; ustack(@x, 3) }", 1);
  test("kprobe:f { @x = 3; kstack(@x) }", 1);
  test("kprobe:f { @x = 3; ustack(@x) }", 1);
  test("kprobe:f { @x = 3; kstack(perf, @x) }", 1);
  test("kprobe:f { @x = 3; ustack(perf, @x) }", 1);
}

TEST(semantic_analyser, call_macaddr)
{
  std::string structs =
      "struct mac { char addr[6]; }; struct invalid { char addr[7]; }; ";

  test("kprobe:f { macaddr(arg0); }", 0);

  test(structs + "kprobe:f { macaddr((struct mac*)arg0); }", 0);

  test(structs + "kprobe:f { @x[macaddr((struct mac*)arg0)] = 1; }", 0);
  test(structs + "kprobe:f { @x = macaddr((struct mac*)arg0); }", 0);

  test(structs + "kprobe:f { printf(\"%s\", macaddr((struct mac*)arg0)); }", 0);

  test(structs + "kprobe:f { macaddr(((struct invalid*)arg0)->addr); }", 1);
  test(structs + "kprobe:f { macaddr(*(struct mac*)arg0); }", 1);

  test("kprobe:f { macaddr(); }", 1);
  test("kprobe:f { macaddr(\"hello\"); }", 1);
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
  test("kprobe:f { $s = arg0; @x = $s[0]; }", 10);
  test("struct MyStruct { void *y; } kprobe:f { $s = (struct MyStruct *) "
       "arg0; @x = $s->y[5];}",
       10);
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  test(driver,
       "struct MyStruct { int y[4]; } kprobe:f { $s = (struct MyStruct *) "
       "arg0; @x = $s->y[0];}",
       0);
  auto assignment = static_cast<ast::AssignMapStatement *>(
      driver.root_->probes->at(0)->stmts->at(1));
  EXPECT_EQ(CreateInt64(), assignment->map->type);

  test(driver,
       "struct MyStruct { int y[4]; } kprobe:f { $s = ((struct MyStruct *) "
       "arg0)->y; @x = $s[0];}",
       0);
  auto array_var_assignment = static_cast<ast::AssignVarStatement *>(
      driver.root_->probes->at(0)->stmts->at(0));
  EXPECT_EQ(CreateArray(4, CreateInt32()), array_var_assignment->var->type);

  test(driver,
       "struct MyStruct { int y[4]; } kprobe:f { @a[0] = ((struct MyStruct *) "
       "arg0)->y; @x = @a[0][0];}",
       0);
  auto array_map_assignment = static_cast<ast::AssignMapStatement *>(
      driver.root_->probes->at(0)->stmts->at(0));
  EXPECT_EQ(CreateArray(4, CreateInt32()), array_map_assignment->map->type);

  test(driver, "kprobe:f { $s = (int32 *) arg0; $x = $s[0]; }", 0);
  auto var_assignment = static_cast<ast::AssignVarStatement *>(
      driver.root_->probes->at(0)->stmts->at(1));
  EXPECT_EQ(CreateInt32(), var_assignment->var->type);
}

TEST(semantic_analyser, array_in_map)
{
  test("struct MyStruct { int x[2]; int y[4]; } "
       "kprobe:f { @ = ((struct MyStruct *)arg0)->x; }",
       0);
  test("struct MyStruct { int x[2]; int y[4]; } "
       "kprobe:f { @a[0] = ((struct MyStruct *)arg0)->x; }",
       0);
  // Mismatched map value types
  test("struct MyStruct { int x[2]; int y[4]; } "
       "kprobe:f { "
       "    @a[0] = ((struct MyStruct *)arg0)->x; "
       "    @a[1] = ((struct MyStruct *)arg0)->y; "
       "}",
       1);
  test("#include <stdint.h>\n"
       "struct MyStruct { uint8_t x[8]; uint32_t y[2]; }"
       "kprobe:f { "
       "    @a[0] = ((struct MyStruct *)arg0)->x; "
       "    @a[1] = ((struct MyStruct *)arg0)->y; "
       "}",
       1);
}

TEST(semantic_analyser, array_as_map_key)
{
  test("struct MyStruct { int x[2]; int y[4]; }"
       "kprobe:f { @x[((struct MyStruct *)arg0)->x] = 0; }",
       0);

  test("struct MyStruct { int x[2]; int y[4]; }"
       "kprobe:f { @x[((struct MyStruct *)arg0)->x, "
       "              ((struct MyStruct *)arg0)->y] = 0; }",
       0);

  // Mismatched key types
  test("struct MyStruct { int x[2]; int y[4]; }"
       "kprobe:f { "
       "    @x[((struct MyStruct *)arg0)->x] = 0; "
       "    @x[((struct MyStruct *)arg0)->y] = 1; "
       "}",
       10);
}

TEST(semantic_analyser, variable_type)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  test(driver, "kprobe:f { $x = 1 }", 0);
  auto st = CreateInt64();
  auto assignment = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(0));
  EXPECT_EQ(st, assignment->var->type);
}

TEST(semantic_analyser, unroll)
{
  test("kprobe:f { $i = 0; unroll(5) { printf(\"i: %d\\n\", $i); $i = $i + 1; } }", 0);
  test("kprobe:f { $i = 0; unroll(101) { printf(\"i: %d\\n\", $i); $i = $i + "
       "1; } }",
       1);
  test("kprobe:f { $i = 0; unroll(0) { printf(\"i: %d\\n\", $i); $i = $i + 1; } }", 1);

  BPFtrace bpftrace;
  bpftrace.add_param("10");
  bpftrace.add_param("hello");
  bpftrace.add_param("101");
  test(bpftrace, "kprobe:f { unroll($#) { printf(\"hi\\n\"); } }", 0);
  test(bpftrace, "kprobe:f { unroll($1) { printf(\"hi\\n\"); } }", 0);
  test(bpftrace, "kprobe:f { unroll($2) { printf(\"hi\\n\"); } }", 1);
  test(bpftrace, "kprobe:f { unroll($3) { printf(\"hi\\n\"); } }", 1);
}

TEST(semantic_analyser, map_integer_sizes)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  test(driver, "kprobe:f { $x = (int32) -1; @x = $x; }", 0);

  auto var_assignment = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(0));
  auto map_assignment = static_cast<ast::AssignMapStatement*>(driver.root_->probes->at(0)->stmts->at(1));
  EXPECT_EQ(CreateInt32(), var_assignment->var->type);
  EXPECT_EQ(CreateInt64(), map_assignment->map->type);
}

TEST(semantic_analyser, unop_dereference)
{
  test("kprobe:f { *0; }", 0);
  test("struct X { int n; } kprobe:f { $x = (struct X*)0; *$x; }", 0);
  test("struct X { int n; } kprobe:f { $x = *(struct X*)0; *$x; }", 1);
  test("kprobe:f { *\"0\"; }", 10);
}

TEST(semantic_analyser, unop_not)
{
  std::string structs = "struct X { int x; };";
  test("kprobe:f { ~0; }", 0);
  test(structs + "kprobe:f { $x = *(struct X*)0; ~$x; }", 10);
  test(structs + "kprobe:f { $x = (struct X*)0; ~$x; }", 10);
  test("kprobe:f { ~\"0\"; }", 10);
}

TEST(semantic_analyser, unop_lnot)
{
  test("kprobe:f { !0; }", 0);
  test("kprobe:f { !(int32)0; }", 0);
  test("struct X { int n; } kprobe:f { $x = (struct X*)0; !$x; }", 10);
  test("struct X { int n; } kprobe:f { $x = *(struct X*)0; !$x; }", 10);
  test("kprobe:f { !\"0\"; }", 1);
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
  test("kprobe:f { printf(\"%d %d %d %d %d %d %d %d %d\", 1, 2, 3, 4, 5, 6, 7, "
       "8, 9); }",
       0);
  test("kprobe:f { printf(\"%dns\", nsecs) }", 0);

  {
    // Long format string should be ok
    std::stringstream prog;

    prog << "i:ms:100 { printf(\"" << std::string(200, 'a')
         << " %d\\n\", 1); }";
    test(prog.str(), 0);
  }
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

#if defined(ARCH_X86_64) || defined(ARCH_AARCH64)
TEST(semantic_analyser, watchpoint_invalid_modes)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->procmon_ = std::make_unique<MockProcMon>(123);

#ifdef ARCH_X86_64
  test(*bpftrace, "watchpoint:0x1234:8:r { 1 }", 1);
#elif ARCH_AARCH64
  test(*bpftrace, "watchpoint:0x1234:8:r { 1 }", 0);
#endif
  test(*bpftrace, "watchpoint:0x1234:8:rx { 1 }", 1);
  test(*bpftrace, "watchpoint:0x1234:8:wx { 1 }", 1);
  test(*bpftrace, "watchpoint:0x1234:8:xw { 1 }", 1);
  test(*bpftrace, "watchpoint:0x1234:8:rwx { 1 }", 1);
  test(*bpftrace, "watchpoint:0x1234:8:xx { 1 }", 1);
  test(*bpftrace, "watchpoint:0x1234:8:b { 1 }", 1);
}

TEST(semantic_analyser, watchpoint_absolute)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->procmon_ = std::make_unique<MockProcMon>(123);

  test(*bpftrace, "watchpoint:0x1234:8:rw { 1 }", 0);
  test(*bpftrace, "watchpoint:0x1234:9:rw { 1 }", 1);
  test(*bpftrace, "watchpoint:0x0:8:rw { 1 }", 1);
}

TEST(semantic_analyser, watchpoint_function)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->procmon_ = std::make_unique<MockProcMon>(123);

  test(*bpftrace, "watchpoint:func1+arg2:8:rw { 1 }", 0);
  test(*bpftrace, "w:func1+arg2:8:rw { 1 }", 0);
  test(*bpftrace, "w:func1.one_two+arg2:8:rw { 1 }", 0);
  test(*bpftrace, "watchpoint:func1+arg99999:8:rw { 1 }", 1);

  bpftrace->procmon_ = std::make_unique<MockProcMon>(0);
  test(*bpftrace, "watchpoint:func1+arg2:8:rw { 1 }", 1);
}

TEST(semantic_analyser, asyncwatchpoint)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->procmon_ = std::make_unique<MockProcMon>(123);

  test(*bpftrace, "asyncwatchpoint:func1+arg2:8:rw { 1 }", 0);
  test(*bpftrace, "aw:func1+arg2:8:rw { 1 }", 0);
  test(*bpftrace, "aw:func1.one_two+arg2:8:rw { 1 }", 0);
  test(*bpftrace, "asyncwatchpoint:func1+arg99999:8:rw { 1 }", 1);

  // asyncwatchpoint's may not use absolute addresses
  test(*bpftrace, "asyncwatchpoint:0x1234:8:rw { 1 }", 1);

  bpftrace->procmon_ = std::make_unique<MockProcMon>(0);
  test(*bpftrace, "watchpoint:func1+arg2:8:rw { 1 }", 1);
}
#endif // if defined(ARCH_X86_64) || defined(ARCH_AARCH64)

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

TEST(semantic_analyser, interval)
{
  test("interval:hz:997 { 1 }", 0);
  test("interval:s:10 { 1 }", 0);
  test("interval:ms:100 { 1 }", 0);
  test("interval:us:100 { 1 }", 0);
  test("interval:unit:100 { 1 }", 1);
}

TEST(semantic_analyser, variable_cast_types)
{
  std::string structs = "struct type1 { int field; } struct type2 { int field; }";
  test(structs +
           "kprobe:f { $x = (struct type1*)cpu; $x = (struct type1*)cpu; }",
       0);
  test(structs +
           "kprobe:f { $x = (struct type1*)cpu; $x = (struct type2*)cpu; }",
       1);
}

TEST(semantic_analyser, map_cast_types)
{
  std::string structs = "struct type1 { int field; } struct type2 { int field; }";
  test(structs +
           "kprobe:f { @x = *(struct type1*)cpu; @x = *(struct type1*)cpu; }",
       0);
  test(structs +
           "kprobe:f { @x = *(struct type1*)cpu; @x = *(struct type2*)cpu; }",
       1);
}

TEST(semantic_analyser, variable_casts_are_local)
{
  std::string structs =
      "struct type1 { int field; } struct type2 { int field; }";
  test(structs + "kprobe:f { $x = *(struct type1 *)cpu } "
                 "kprobe:g { $x = *(struct type2 *)cpu; }",
       0);
}

TEST(semantic_analyser, map_casts_are_global)
{
  std::string structs =
      "struct type1 { int field; } struct type2 { int field; }";
  test(structs + "kprobe:f { @x = *(struct type1 *)cpu }"
                 "kprobe:g { @x = *(struct type2 *)cpu }",
       1);
}

TEST(semantic_analyser, cast_unknown_type)
{
  test("kprobe:f { (struct faketype *)cpu }", 1);
}

TEST(semantic_analyser, cast_struct)
{
  // Casting struct by value is forbidden
  test("struct type { int field; }"
       "kprobe:f { $s = (struct type *)cpu; $u = (uint32)*$s; }",
       1);
  test("struct type { int field; } kprobe:f { $s = (struct type)cpu }", 1);
}

TEST(semantic_analyser, field_access)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { $x = *(struct type1*)cpu; $x.field }", 0);
  test(structs + "kprobe:f { @x = *(struct type1*)cpu; @x.field }", 0);
  test("struct task_struct {int x;} kprobe:f { curtask->x }", 0);
}

TEST(semantic_analyser, field_access_wrong_field)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { ((struct type1 *)cpu)->blah }", 1);
  test(structs + "kprobe:f { $x = (struct type1 *)cpu; $x->blah }", 1);
  test(structs + "kprobe:f { @x = (struct type1 *)cpu; @x->blah }", 1);
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

  test(structs + "kprobe:f { (*((struct type1*)0)).field == 123 }", 0);
  test(structs + "kprobe:f { (*((struct type1*)0)).field == \"abc\" }", 10);

  test(structs + "kprobe:f { (*((struct type1*)0)).mystr == \"abc\" }", 0);
  test(structs + "kprobe:f { (*((struct type1*)0)).mystr == 123 }", 10);

  test(structs + "kprobe:f { (*((struct type1*)0)).field == (*((struct "
                 "type2*)0)).field }",
       0);
  test(structs + "kprobe:f { (*((struct type1*)0)).mystr == (*((struct "
                 "type2*)0)).field }",
       10);
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

  test(structs + "kprobe:f { (*(struct type1*)0).type2ptr->field }", 0);
  test(structs + "kprobe:f { (*(struct type1*)0).type2.field }", 0);
  test(
      structs +
          "kprobe:f { $x = *(struct type2*)0; $x = (*(struct type1*)0).type2 }",
      0);
  test(structs + "kprobe:f { $x = (struct type2*)0; $x = (*(struct "
                 "type1*)0).type2ptr }",
       0);
  test(
      structs +
          "kprobe:f { $x = *(struct type1*)0; $x = (*(struct type1*)0).type2 }",
      1);
  test(structs + "kprobe:f { $x = (struct type1*)0; $x = (*(struct "
                 "type1*)0).type2ptr }",
       1);
}

TEST(semantic_analyser, field_access_is_internal)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  std::string structs = "struct type1 { int x; }";

  {
    test(driver, structs + "kprobe:f { $x = (*(struct type1*)0).x }", 0);
    auto stmts = driver.root_->probes->at(0)->stmts;
    auto var_assignment1 = static_cast<ast::AssignVarStatement *>(stmts->at(0));
    EXPECT_FALSE(var_assignment1->var->type.is_internal);
  }

  {
    test(driver,
         structs + "kprobe:f { @type1 = *(struct type1*)0; $x = @type1.x }",
         0);
    auto stmts = driver.root_->probes->at(0)->stmts;
    auto map_assignment = static_cast<ast::AssignMapStatement *>(stmts->at(0));
    auto var_assignment2 = static_cast<ast::AssignVarStatement *>(stmts->at(1));
    EXPECT_TRUE(map_assignment->map->type.is_internal);
    EXPECT_TRUE(var_assignment2->var->type.is_internal);
  }
}

TEST(semantic_analyser, struct_as_map_key)
{
  test("struct A { int x; } struct B { char x; } "
       "kprobe:f { @x[*((struct A *)arg0)] = 0; }",
       0);

  test("struct A { int x; } struct B { char x; } "
       "kprobe:f { @x[*((struct A *)arg0), *((struct B *)arg1)] = 0; }",
       0);

  // Mismatched key types
  test("struct A { int x; } struct B { char x; } "
       "kprobe:f { "
       "    @x[*((struct A *)arg0)] = 0; "
       "    @x[*((struct B *)arg1)] = 1; "
       "}",
       10);
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

  test(bpftrace, "kprobe:f { printf(\"%d\", $1); }", 0);
  test(bpftrace, "kprobe:f { printf(\"%s\", str($1)); }", 0);

  test(bpftrace, "kprobe:f { printf(\"%s\", str($2)); }", 0);
  test(bpftrace, "kprobe:f { printf(\"%s\", str($2 + 1)); }", 0);
  test(bpftrace, "kprobe:f { printf(\"%d\", $2); }", 10);

  test(bpftrace, "kprobe:f { printf(\"%d\", $3); }", 0);

  // Pointer arithmetic in str() for parameters
  // Only str($1 + CONST) where CONST <= strlen($1) should be allowed
  test(bpftrace, "kprobe:f { printf(\"%s\", str($1 + 1)); }", 0);
  test(bpftrace, "kprobe:f { printf(\"%s\", str(1 + $1)); }", 0);
  test(bpftrace, "kprobe:f { printf(\"%s\", str($1 + 4)); }", 10);
  test(bpftrace, "kprobe:f { printf(\"%s\", str($1 * 2)); }", 10);
  test(bpftrace, "kprobe:f { printf(\"%s\", str($1 + 1 + 1)); }", 1);

  // Parameters are not required to exist to be used:
  test(bpftrace, "kprobe:f { printf(\"%s\", str($4)); }", 0);
  test(bpftrace, "kprobe:f { printf(\"%d\", $4); }", 0);

  test(bpftrace, "kprobe:f { printf(\"%d\", $#); }", 0);
  test(bpftrace, "kprobe:f { printf(\"%s\", str($#)); }", 1);
  test(bpftrace, "kprobe:f { printf(\"%s\", str($#+1)); }", 1);

  // Parameters can be used as string literals
  test(bpftrace, "kprobe:f { printf(\"%d\", cgroupid(str($2))); }", 0);

  Driver driver(bpftrace);
  test(driver, "k:f { $1 }", 0);
  auto stmt = static_cast<ast::ExprStatement *>(
      driver.root_->probes->at(0)->stmts->at(0));
  auto pp = static_cast<ast::PositionalParameter *>(stmt->expr);
  EXPECT_EQ(CreateInt64(), pp->type);
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

TEST(semantic_analyser, string_comparison)
{
  test("struct MyStruct {char y[4]; } kprobe:f { $s = (struct MyStruct*)arg0; "
       "$s->y == \"abc\"}",
       0);
  test("struct MyStruct {char y[4]; } kprobe:f { $s = (struct MyStruct*)arg0; "
       "\"abc\" != $s->y}",
       0);
  test("struct MyStruct {char y[4]; } kprobe:f { $s = (struct MyStruct*)arg0; "
       "\"abc\" == \"abc\"}",
       0);

  bool invert = true;
  std::string msg = "the condition is always false";
  test_for_warning("struct MyStruct {char y[4]; } kprobe:f { $s = (struct "
                   "MyStruct*)arg0; $s->y == \"long string\"}",
                   msg,
                   invert);
  test_for_warning("struct MyStruct {char y[4]; } kprobe:f { $s = (struct "
                   "MyStruct*)arg0; \"long string\" != $s->y}",
                   msg,
                   invert);
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
  EXPECT_EQ(CreateInt32(), s->var->type);
  EXPECT_EQ(CreateUInt32(), us->var->type);
  EXPECT_EQ(CreateInt64(), l->var->type);
  EXPECT_EQ(CreateUInt64(), ul->var->type);
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
    EXPECT_EQ(CreateInt64(), varA->var->type);
    auto varB = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(2));
    EXPECT_EQ(CreateUInt64(), varB->var->type);
    auto varC = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(3));
    EXPECT_EQ(CreateUInt64(), varC->var->type);
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

TEST(semantic_analyser, unwatch)
{
  test("i:s:1 { unwatch(12345) }", 0);
  test("i:s:1 { unwatch(0x1234) }", 0);
  test("i:s:1 { $x = 1; unwatch($x); }", 0);
  test("i:s:1 { @x = 1; @x++; unwatch(@x); }", 0);
  test("k:f { unwatch(arg0); }", 0);
  test("k:f { unwatch((int64)arg0); }", 0);
  test("k:f { unwatch(*(int64*)arg0); }", 0);

  test("i:s:1 { unwatch(\"asdf\") }", 10);
  test("i:s:1 { @x[\"hi\"] = \"world\"; unwatch(@x[\"hi\"]) }", 10);
  test("i:s:1 { printf(\"%d\", unwatch(2)) }", 10);
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
    test("struct S{ int " + kw + ";}; k:f { (*(struct S*)arg0)." + kw + "}", 0);
  }
}

TEST(semantic_analyser, jumps)
{
  test("i:s:1 { return; }", 0);
  // must be used in loops
  test("i:s:1 { break; }", 1);
  test("i:s:1 { continue; }", 1);
}

TEST(semantic_analyser, while_loop)
{
  test("i:s:1 { $a = 1; while ($a < 10) { $a++ }}", 0);
  test("i:s:1 { $a = 1; while (1) { if($a > 50) { break } $a++ }}", 0);
  test("i:s:1 { $a = 1; while ($a < 10) { $a++ }}", 0);
  test("i:s:1 { $a = 1; while (1) { if($a > 50) { break } $a++ }}", 0);
  test("i:s:1 { $a = 1; while (1) { if($a > 50) { return } $a++ }}", 0);
  test(R"PROG(
i:s:1 {
  $a = 1;
  while ($a < 10) {
    $a++; $j=0;
    while ($j < 10) {
      $j++;
    }
  }
})PROG",
       0);

  test_for_warning("i:s:1 { $a = 1; while ($a < 10) { break; $a++ }}",
                   "code after a 'break'");
  test_for_warning("i:s:1 { $a = 1; while ($a < 10) { continue; $a++ }}",
                   "code after a 'continue'");
  test_for_warning("i:s:1 { $a = 1; while ($a < 10) { return; $a++ }}",
                   "code after a 'return'");

  test_for_warning("i:s:1 { $a = 1; while ($a < 10) { @=$a++; print(@); }}",
                   "'print()' in a loop");
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
  EXPECT_TRUE(assignment->var->type.IsPtrTy());

  // $a = $x->a;
  assignment = static_cast<ast::AssignVarStatement *>(stmts->at(1));
  EXPECT_EQ(CreateInt64(), assignment->var->type);
  auto fieldaccess = static_cast<ast::FieldAccess *>(assignment->expr);
  EXPECT_EQ(CreateInt64(), fieldaccess->type);
  auto unop = static_cast<ast::Unop *>(fieldaccess->expr);
  EXPECT_TRUE(unop->type.IsCtxAccess());
  auto var = static_cast<ast::Variable *>(unop->expr);
  EXPECT_TRUE(var->type.IsPtrTy());

  // $b = $x->b[0];
  assignment = static_cast<ast::AssignVarStatement *>(stmts->at(2));
  EXPECT_EQ(CreateInt16(), assignment->var->type);
  auto arrayaccess = static_cast<ast::ArrayAccess *>(assignment->expr);
  EXPECT_EQ(CreateInt16(), arrayaccess->type);
  fieldaccess = static_cast<ast::FieldAccess *>(arrayaccess->expr);
  EXPECT_TRUE(fieldaccess->type.IsCtxAccess());
  unop = static_cast<ast::Unop *>(fieldaccess->expr);
  EXPECT_TRUE(unop->type.IsCtxAccess());
  var = static_cast<ast::Variable *>(unop->expr);
  EXPECT_TRUE(var->type.IsPtrTy());

#if ARCH_X86_64
  auto chartype = CreateInt8();
#else
  auto chartype = CreateUInt8();
#endif

  // $c = $x->c.c;
  assignment = static_cast<ast::AssignVarStatement *>(stmts->at(3));
  EXPECT_EQ(chartype, assignment->var->type);
  fieldaccess = static_cast<ast::FieldAccess *>(assignment->expr);
  EXPECT_EQ(chartype, fieldaccess->type);
  fieldaccess = static_cast<ast::FieldAccess *>(fieldaccess->expr);
  EXPECT_TRUE(fieldaccess->type.IsCtxAccess());
  unop = static_cast<ast::Unop *>(fieldaccess->expr);
  EXPECT_TRUE(unop->type.IsCtxAccess());
  var = static_cast<ast::Variable *>(unop->expr);
  EXPECT_TRUE(var->type.IsPtrTy());

  // $d = $x->d->c;
  assignment = static_cast<ast::AssignVarStatement *>(stmts->at(4));
  EXPECT_EQ(chartype, assignment->var->type);
  fieldaccess = static_cast<ast::FieldAccess *>(assignment->expr);
  EXPECT_EQ(chartype, fieldaccess->type);
  unop = static_cast<ast::Unop *>(fieldaccess->expr);
  EXPECT_TRUE(unop->type.IsRecordTy());
  fieldaccess = static_cast<ast::FieldAccess *>(unop->expr);
  EXPECT_TRUE(fieldaccess->type.IsPtrTy());
  unop = static_cast<ast::Unop *>(fieldaccess->expr);
  EXPECT_TRUE(unop->type.IsCtxAccess());
  var = static_cast<ast::Variable *>(unop->expr);
  EXPECT_TRUE(var->type.IsPtrTy());

  test(driver, "k:f, kr:f { @ = (uint64)ctx; }", 0);
  test(driver, "k:f, i:s:1 { @ = (uint64)ctx; }", 1);
  test(driver, "t:sched:sched_one { @ = (uint64)ctx; }", 1);
}

TEST(semantic_analyser, double_pointer_basic)
{
  test(R"_(BEGIN { $pp = (int8 **)0; $p = *$pp; $val = *$p; })_", 0);
  test(R"_(BEGIN { $pp = (int8 **)0; $val = **$pp; })_", 0);

  const std::string structs = "struct Foo { int x; }";
  test(structs + R"_(BEGIN { $pp = (struct Foo **)0; $val = (*$pp)->x; })_", 0);
}

TEST(semantic_analyser, double_pointer_int)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  test(driver, "kprobe:f { $pp = (int8 **)1; $p = *$pp; $val = *$p; }", 0);
  auto &stmts = driver.root_->probes->at(0)->stmts;

  // $pp = (int8 **)1;
  auto assignment = static_cast<ast::AssignVarStatement *>(stmts->at(0));
  ASSERT_TRUE(assignment->var->type.IsPtrTy());
  ASSERT_TRUE(assignment->var->type.GetPointeeTy()->IsPtrTy());
  ASSERT_TRUE(assignment->var->type.GetPointeeTy()->GetPointeeTy()->IsIntTy());
  EXPECT_EQ(
      assignment->var->type.GetPointeeTy()->GetPointeeTy()->GetIntBitWidth(),
      8ULL);

  // $p = *$pp;
  assignment = static_cast<ast::AssignVarStatement *>(stmts->at(1));
  ASSERT_TRUE(assignment->var->type.IsPtrTy());
  ASSERT_TRUE(assignment->var->type.GetPointeeTy()->IsIntTy());
  EXPECT_EQ(assignment->var->type.GetPointeeTy()->GetIntBitWidth(), 8ULL);

  // $val = *$p;
  assignment = static_cast<ast::AssignVarStatement *>(stmts->at(2));
  ASSERT_TRUE(assignment->var->type.IsIntTy());
  EXPECT_EQ(assignment->var->type.GetIntBitWidth(), 8ULL);
}

TEST(semantic_analyser, double_pointer_struct)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  test(driver,
       "struct Foo { char x; long y; }"
       "kprobe:f { $pp = (struct Foo **)1; $p = *$pp; $val = $p->x; }",
       0);
  auto &stmts = driver.root_->probes->at(0)->stmts;

  // $pp = (struct Foo **)1;
  auto assignment = static_cast<ast::AssignVarStatement *>(stmts->at(0));
  ASSERT_TRUE(assignment->var->type.IsPtrTy());
  ASSERT_TRUE(assignment->var->type.GetPointeeTy()->IsPtrTy());
  ASSERT_TRUE(
      assignment->var->type.GetPointeeTy()->GetPointeeTy()->IsRecordTy());
  EXPECT_EQ(assignment->var->type.GetPointeeTy()->GetPointeeTy()->GetName(),
            "struct Foo");

  // $p = *$pp;
  assignment = static_cast<ast::AssignVarStatement *>(stmts->at(1));
  ASSERT_TRUE(assignment->var->type.IsPtrTy());
  ASSERT_TRUE(assignment->var->type.GetPointeeTy()->IsRecordTy());
  EXPECT_EQ(assignment->var->type.GetPointeeTy()->GetName(), "struct Foo");

  // $val = $p->x;
  assignment = static_cast<ast::AssignVarStatement *>(stmts->at(2));
  ASSERT_TRUE(assignment->var->type.IsIntTy());
  EXPECT_EQ(assignment->var->type.GetIntBitWidth(), 8ULL);
}

// Basic functionality test
TEST(semantic_analyser, tuple)
{
  test(R"_(BEGIN { $t = (1)})_", 0);
  test(R"_(BEGIN { $t = (1, 2); $v = $t;})_", 0);
  test(R"_(BEGIN { $t = (1, 2, "string")})_", 0);
  test(R"_(BEGIN { $t = (1, 2, "string"); $t = (3, 4, "other"); })_", 0);
  test(R"_(BEGIN { $t = (1, kstack()) })_", 0);
  test(R"_(BEGIN { $t = (1, (2,3)) })_", 0);

  test(R"_(BEGIN { @t = (1)})_", 0);
  test(R"_(BEGIN { @t = (1, 2); @v = @t;})_", 0);
  test(R"_(BEGIN { @t = (1, 2, "string")})_", 0);
  test(R"_(BEGIN { @t = (1, 2, "string"); @t = (3, 4, "other"); })_", 0);
  test(R"_(BEGIN { @t = (1, kstack()) })_", 0);
  test(R"_(BEGIN { @t = (1, (2,3)) })_", 0);

  test(R"_(struct task_struct { int x; } BEGIN { $t = (1, curtask); })_", 0);
  test(R"_(struct task_struct { int x[4]; } BEGIN { $t = (1, curtask->x); })_",
       0);

  test(R"_(BEGIN { $t = (1, 2); $t = (4, "other"); })_", 10);
  test(R"_(BEGIN { $t = (1, 2); $t = 5; })_", 1);
  test(R"_(BEGIN { $t = (1, count()) })_", 1);
  test(R"_(BEGIN { $t = ((int32)1, (int64)2); $t = ((int64)1, (int32)2); })_",
       10);

  test(R"_(BEGIN { @t = (1, 2); @t = (4, "other"); })_", 1);
  test(R"_(BEGIN { @t = (1, 2); @t = 5; })_", 1);
  test(R"_(BEGIN { @t = (1, count()) })_", 1);
  test(R"_(BEGIN { @t = (1, (aaa)0) })_", 1);
  test(R"_(BEGIN { @t = (1, !(aaa)0) })_", 1);
}

TEST(semantic_analyser, tuple_indexing)
{
  test(R"_(BEGIN { (1,2).0 })_", 0);
  test(R"_(BEGIN { (1,2).1 })_", 0);
  test(R"_(BEGIN { (1,2,3).2 })_", 0);
  test(R"_(BEGIN { $t = (1,2,3).0 })_", 0);
  test(R"_(BEGIN { $t = (1,2,3); $v = $t.0; })_", 0);

  test(R"_(BEGIN { (1,2,3).3 })_", 10);
  test(R"_(BEGIN { (1,2,3).9999999999999 })_", 10);
}

// More in depth inspection of AST
TEST(semantic_analyser, tuple_assign_var)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  SizedType ty = CreateTuple(
      bpftrace.structs.AddTuple({ CreateInt64(), CreateString(64) }));
  test(bpftrace,
       true,
       driver,
       R"_(BEGIN { $t = (1, "str"); $t = (4, "other"); })_",
       0);

  auto &stmts = driver.root_->probes->at(0)->stmts;

  // $t = (1, "str");
  auto assignment = static_cast<ast::AssignVarStatement *>(stmts->at(0));
  EXPECT_EQ(ty, assignment->var->type);

  // $t = (4, "other");
  assignment = static_cast<ast::AssignVarStatement *>(stmts->at(1));
  EXPECT_EQ(ty, assignment->var->type);
}

// More in depth inspection of AST
TEST(semantic_analyser, tuple_assign_map)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  SizedType ty;
  test(bpftrace,
       true,
       driver,
       R"_(BEGIN { @ = (1, 3, 3, 7); @ = (0, 0, 0, 0); })_",
       0);

  auto &stmts = driver.root_->probes->at(0)->stmts;

  // $t = (1, 3, 3, 7);
  auto assignment = static_cast<ast::AssignMapStatement *>(stmts->at(0));
  ty = CreateTuple(bpftrace.structs.AddTuple(
      { CreateInt64(), CreateInt64(), CreateInt64(), CreateInt64() }));
  EXPECT_EQ(ty, assignment->map->type);

  // $t = (0, 0, 0, 0);
  assignment = static_cast<ast::AssignMapStatement *>(stmts->at(1));
  ty = CreateTuple(bpftrace.structs.AddTuple(
      { CreateInt64(), CreateInt64(), CreateInt64(), CreateInt64() }));
  EXPECT_EQ(ty, assignment->map->type);
}

// More in depth inspection of AST
TEST(semantic_analyser, tuple_nested)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  SizedType ty_inner = CreateTuple(
      bpftrace.structs.AddTuple({ CreateInt64(), CreateInt64() }));
  SizedType ty = CreateTuple(
      bpftrace.structs.AddTuple({ CreateInt64(), ty_inner }));
  test(bpftrace, true, driver, R"_(BEGIN { $t = (1,(1,2)); })_", 0);

  auto &stmts = driver.root_->probes->at(0)->stmts;

  // $t = (1, "str");
  auto assignment = static_cast<ast::AssignVarStatement *>(stmts->at(0));
  EXPECT_EQ(ty, assignment->var->type);
}

TEST(semantic_analyser, tuple_types_unique)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, R"_(BEGIN { $t = (1, "str"); $t = (4, "other"); })_", 0);

  EXPECT_EQ(bpftrace->structs.GetTuplesCnt(), 1ul);
}

TEST(semantic_analyser, multi_pass_type_inference_zero_size_int)
{
  auto bpftrace = get_mock_bpftrace();
  // The first pass on processing the Unop does not have enough information
  // to figure out size of `@i` yet. The analyzer figures out the size
  // after seeing the `@i++`. On the second pass the correct size is
  // determined.
  test(*bpftrace, "BEGIN { if (!@i) { @i++; } }", 0);
}

TEST(semantic_analyser, call_kptr_uptr)
{
  test("k:f { @  = kptr((int8*) arg0); }", 0);
  test("k:f { $a = kptr((int8*) arg0); }", 0);

  test("k:f { @ = kptr(arg0); }", 0);
  test("k:f { $a = kptr(arg0); }", 0);

  test("k:f { @  = uptr((int8*) arg0); }", 0);
  test("k:f { $a = uptr((int8*) arg0); }", 0);

  test("k:f { @ = uptr(arg0); }", 0);
  test("k:f { $a = uptr(arg0); }", 0);
}

TEST(semantic_analyser, call_path)
{
  test("kprobe:f { $k = path( arg0 ) }", 1);
  test("kretprobe:f { $k = path( arg0 ) }", 1);
  test("tracepoint:category:event { $k = path( NULL ) }", 1);
  test("kprobe:f { $k = path( arg0 ) }", 1);
  test("kretprobe:f{ $k = path( \"abc\" ) }", 1);
  test("tracepoint:category:event { $k = path( -100 ) }", 1);
  test("uprobe:/bin/bash:f { $k = path( arg0 ) }", 1);
  test("BEGIN { $k = path( 1 ) }", 1);
  test("END { $k = path( 1 ) }", 1);
}

TEST(semantic_analyser, int_ident)
{
  test("BEGIN { sizeof(int32) }", 0);
  test("BEGIN { print(int32) }", 1);
}

TEST(semantic_analyser, tracepoint_common_field)
{
  test("tracepoint:file:filename { args->filename }", 0);
  test("tracepoint:file:filename { args->common_field }", 1);
}

#ifdef HAVE_LIBBPF_BTF_DUMP

#include "btf_common.h"

class semantic_analyser_btf : public test_btf
{
};

#ifdef HAVE_BCC_KFUNC

TEST_F(semantic_analyser_btf, kfunc)
{
  test("kfunc:func_1 { 1 }", 0);
  test("kretfunc:func_1 { 1 }", 0);
  test("kfunc:func_1 { $x = args->a; $y = args->foo1; $z = args->foo2->f.a; }",
       0);
  test("kretfunc:func_1 { $x = retval; }", 0);
  test("kretfunc:func_1 { $x = args->foo; }", 1);
  test("kretfunc:func_1 { $x = args; }", 1);
  // func_1 and func_2 have different args, but none of them
  // is used in probe code, so we're good -> PASS
  test("kfunc:func_1, kfunc:func_2 { }", 0);
  // func_1 and func_2 have different args, one of them
  // is used in probe code, we can't continue -> FAIL
  test("kfunc:func_1, kfunc:func_2 { $x = args->foo; }", 1, true, false, 1);
  // func_2 and func_3 have same args -> PASS
  test("kfunc:func_2, kfunc:func_3 { }", 0);
  // func_2 and func_3 have same args -> PASS
  test("kfunc:func_2, kfunc:func_3 { $x = args->foo1; }", 0);
  // aaa does not exist -> PASS semantic analyser, FAIL field analyser
  test("kfunc:func_2, kfunc:aaa { $x = args->foo1; }", 0, true, false, 1);
  // func_* have different args, but none of them
  // is used in probe code, so we're good -> PASS
  test("kfunc:func_* { }", 0);
  // func_* have different args, one of them
  // is used in probe code, we can't continue -> FAIL
  test("kfunc:func_* { $x = args->foo1; }", 0, true, false, 1);
  // reg() is not available in kfunc
#ifdef ARCH_X86_64
  test("kfunc:func_1 { reg(\"ip\") }", 1);
  test("kretfunc:func_1 { reg(\"ip\") }", 1);
#endif
}

TEST_F(semantic_analyser_btf, short_name)
{
  test("f:func_1 { 1 }", 0);
  test("fr:func_1 { 1 }", 0);
}

TEST_F(semantic_analyser_btf, call_path)
{
  test("kfunc:func_1 { $k = path( args->foo1 ) }", 0);
  test("kretfunc:func_1 { $k = path( retval->foo1 ) }", 0);
}

#endif // HAVE_BCC_KFUNC

TEST_F(semantic_analyser_btf, iter)
{
  test("iter:task { 1 }", 0);
  test("iter:task_file { 1 }", 0);
  test("iter:task { $x = ctx->task->pid }", 0);
  test("iter:task_file { $x = ctx->file->ino }", 0);
  test("iter:task { $x = args->foo; }", 1);
  test("iter:task_file { $x = args->foo; }", 1);
  test("iter:task* { }", 1, true, false, 1, 1);
  test("iter:task { printf(\"%d\", ctx->task->pid); }", 0);
  test("iter:task_file { printf(\"%d\", ctx->file->ino); }", 0);
  test("iter:task,iter:task_file { 1 }", 1);
  test("iter:task,f:func_1 { 1 }", 1);
}

#endif // HAVE_LIBBPF_BTF_DUMP

} // namespace semantic_analyser
} // namespace test
} // namespace bpftrace
