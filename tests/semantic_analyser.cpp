#include "ast/passes/semantic_analyser.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/printer.h"
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

#include "btf_common.h"

using ::testing::_;
using ::testing::HasSubstr;

void test_for_warning(BPFtrace &bpftrace,
                      const std::string &input,
                      const std::string &warning,
                      bool invert = false,
                      bool safe_mode = true)
{
  Driver driver(bpftrace);
  bpftrace.safe_mode_ = safe_mode;
  ASSERT_EQ(driver.parse_str(input), 0);

  ClangParser clang;
  clang.parse(driver.ctx.root, bpftrace);

  ASSERT_EQ(driver.parse_str(input), 0);
  std::stringstream out;
  // Override to mockbpffeature.
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);
  ast::SemanticAnalyser semantics(driver.ctx, bpftrace, out);
  semantics.analyse();
  if (invert)
    EXPECT_THAT(out.str(), Not(HasSubstr(warning)));
  else
    EXPECT_THAT(out.str(), HasSubstr(warning));
}

void test_for_warning(const std::string &input,
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
          std::string_view input,
          int expected_result,
          std::string_view expected_error = {},
          bool safe_mode = true,
          bool has_child = false)
{
  if (!input.empty() && input[0] == '\n')
    input.remove_prefix(1); // Remove initial '\n'

  std::stringstream out;
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  bpftrace.safe_mode_ = safe_mode;
  ASSERT_EQ(driver.parse_str(input), 0);

  ast::FieldAnalyser fields(driver.ctx.root, bpftrace, out);
  ASSERT_EQ(fields.analyse(), 0) << msg.str() + out.str();

  ClangParser clang;
  clang.parse(driver.ctx.root, bpftrace);

  ASSERT_EQ(driver.parse_str(input), 0);
  out.str("");
  // Override to mockbpffeature.
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(mock_has_features);
  ast::SemanticAnalyser semantics(driver.ctx, bpftrace, out, has_child);
  if (expected_result == -1) {
    // Accept any failure result
    EXPECT_NE(0, semantics.analyse()) << msg.str() + out.str();
  } else {
    EXPECT_EQ(expected_result, semantics.analyse()) << msg.str() + out.str();
  }
  if (expected_error.data()) {
    if (!expected_error.empty() && expected_error[0] == '\n')
      expected_error.remove_prefix(1); // Remove initial '\n'
    EXPECT_EQ(expected_error, out.str());
  }
}

void test(BPFtrace &bpftrace, std::string_view input, bool safe_mode = true)
{
  Driver driver(bpftrace);
  test(bpftrace, true, driver, input, 0, {}, safe_mode, false);
}

void test(BPFtrace &bpftrace,
          std::string_view input,
          int expected_result,
          bool safe_mode = true)
{
  // This function will eventually be deprecated in favour of test_error()
  assert(expected_result != 0 &&
         "Use test(BPFtrace&, std::string_view) for expected successes");
  Driver driver(bpftrace);
  test(bpftrace, true, driver, input, expected_result, {}, safe_mode, false);
}

void test(Driver &driver, std::string_view input)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, true, driver, input, 0, {}, true, false);
}

void test(Driver &driver, std::string_view input, int expected_result)
{
  // This function will eventually be deprecated in favour of test_error()
  assert(expected_result != 0 &&
         "Use test(Driver&, std::string_view) for expected successes");
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, true, driver, input, expected_result, {}, true, false);
}

void test(MockBPFfeature &feature, std::string_view input)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);
  bool mock_has_features = feature.has_features_;
  test(*bpftrace, mock_has_features, driver, input, 0, {}, true, false);
}

void test(MockBPFfeature &feature,
          std::string_view input,
          int expected_result,
          bool safe_mode = true)
{
  // This function will eventually be deprecated in favour of test_error()
  assert(expected_result != 0 &&
         "Use test(MockBPFfeature&, std::string_view) for expected successes");
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);
  bool mock_has_features = feature.has_features_;
  test(*bpftrace,
       mock_has_features,
       driver,
       input,
       expected_result,
       {},
       safe_mode,
       false);
}

void test(std::string_view input,
          int expected_result,
          bool safe_mode,
          bool has_child = false)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);
  test(*bpftrace,
       true,
       driver,
       input,
       expected_result,
       {},
       safe_mode,
       has_child);
}

void test(std::string_view input, int expected_result)
{
  // This function will eventually be deprecated in favour of test_error()
  assert(expected_result != 0 &&
         "Use test(std::string_view) for expected successes");
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);
  test(*bpftrace, true, driver, input, expected_result, {}, true, false);
}

void test(std::string_view input)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);
  test(*bpftrace, true, driver, input, 0, {}, true, false);
}

void test(std::string_view input, std::string_view expected_ast)
{
  auto bpftrace = get_mock_bpftrace();
  Driver driver(*bpftrace);
  test(*bpftrace, true, driver, input, 0, {}, true, false);

  if (expected_ast[0] == '\n')
    expected_ast.remove_prefix(1); // Remove initial '\n'

  std::ostringstream out;
  ast::Printer printer(out);
  printer.print(driver.ctx.root);

  if (expected_ast[0] == '*' && expected_ast[expected_ast.size() - 1] == '*') {
    // Remove globs from beginning and end
    expected_ast.remove_prefix(1);
    expected_ast.remove_suffix(1);
    EXPECT_THAT(out.str(), HasSubstr(expected_ast));
    return;
  }

  EXPECT_EQ(expected_ast, out.str());
}

void test_error(BPFtrace &bpftrace,
                std::string_view input,
                std::string_view expected_error,
                bool has_features = true)
{
  Driver driver(bpftrace);
  test(bpftrace, has_features, driver, input, -1, expected_error, true, false);
}

void test_error(std::string_view input,
                std::string_view expected_error,
                bool has_features = true)
{
  auto bpftrace = get_mock_bpftrace();
  test_error(*bpftrace, input, expected_error, has_features);
}

TEST(semantic_analyser, builtin_variables)
{
  // Just check that each builtin variable exists.
  test("kprobe:f { pid }");
  test("kprobe:f { tid }");
  test("kprobe:f { cgroup }");
  test("kprobe:f { uid }");
  test("kprobe:f { username }");
  test("kprobe:f { gid }");
  test("kprobe:f { nsecs }");
  test("kprobe:f { elapsed }");
  test("kprobe:f { numaid }");
  test("kprobe:f { cpu }");
  test("kprobe:f { curtask }");
  test("kprobe:f { rand }");
  test("kprobe:f { ctx }");
  test("kprobe:f { comm }");
  test("kprobe:f { kstack }");
  test("kprobe:f { ustack }");
  test("kprobe:f { arg0 }");
  test("kprobe:f { sarg0 }");
  test("kretprobe:f { retval }");
  test("kprobe:f { func }");
  test("uprobe:/bin/sh:f { func }");
  test("kprobe:f { probe }");
  test("tracepoint:a:b { args }");
  test("kprobe:f { jiffies }");

  test_error("kprobe:f { fake }", R"(
stdin:1:12-16: ERROR: Unknown identifier: 'fake'
kprobe:f { fake }
           ~~~~
)");

  MockBPFfeature feature(false);
  test(feature, "k:f { cgroup }", 1);
  test(feature, "k:f { jiffies }", 1);
}

#ifdef HAVE_LIBLLDB
TEST(semantic_analyser, builtin_variables_inline)
{
  auto bpftrace = get_mock_bpftrace();
  ConfigSetter configs{ bpftrace->config_, ConfigSource::script };
  configs.set(ConfigKeyBool::probe_inline, true);

  // Check argument builtins are rejected when `probe_inline` is enabled.
  test_error(*bpftrace, "uprobe:/bin/sh:f { arg0 }", R"(
stdin:1:20-24: ERROR: The arg0 builtin can only be used when the probe_inline config is disabled.
uprobe:/bin/sh:f { arg0 }
                   ~~~~
)");
  test_error(*bpftrace, "uprobe:/bin/sh:f { sarg0 }", R"(
stdin:1:20-25: ERROR: The sarg0 builtin can only be used when the probe_inline config is disabled.
uprobe:/bin/sh:f { sarg0 }
                   ~~~~~
)");
  test_error(*bpftrace, "uprobe:/bin/sh:f { args }", R"(
stdin:1:20-24: ERROR: The args builtin can only be used when the probe_inline config is disabled.
uprobe:/bin/sh:f { args }
                   ~~~~
stdin:1:20-24: ERROR: Cannot read function parameters
uprobe:/bin/sh:f { args }
                   ~~~~
)");
}
#endif // HAVE_LIBLLDB

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
  test("kprobe:f { @x = hist(123) }");
  test("kprobe:f { @x = lhist(123, 0, 123, 1) }");
  test("kprobe:f { @x = count() }");
  test("kprobe:f { @x = sum(pid) }");
  test("kprobe:f { @x = min(pid) }");
  test("kprobe:f { @x = max(pid) }");
  test("kprobe:f { @x = avg(pid) }");
  test("kprobe:f { @x = stats(pid) }");
  test("kprobe:f { @x = 1; delete(@x) }");
  test("kprobe:f { @x = 1; print(@x) }");
  test("kprobe:f { @x = 1; clear(@x) }");
  test("kprobe:f { @x = 1; zero(@x) }");
  test("kprobe:f { @x = 1; @s = len(@x) }");
  test("kprobe:f { time() }");
  test("kprobe:f { exit() }");
  test("kprobe:f { str(0xffff) }");
  test("kprobe:f { buf(0xffff, 1) }");
  test("kprobe:f { printf(\"hello\\n\") }");
  test("kprobe:f { system(\"ls\\n\") }", 0, false /* safe_node */);
  test("kprobe:f { join(0) }");
  test("kprobe:f { ksym(0xffff) }");
  test("kprobe:f { usym(0xffff) }");
  test("kprobe:f { kaddr(\"sym\") }");
  test("kprobe:f { ntop(0xffff) }");
  test("kprobe:f { ntop(2, 0xffff) }");
  test("kprobe:f { pton(\"127.0.0.1\") }");
  test("kprobe:f { pton(\"::1\") }");
  test("kprobe:f { pton(\"0000:0000:0000:0000:0000:0000:0000:0001\") }");
#ifdef ARCH_X86_64
  test("kprobe:f { reg(\"ip\") }");
#endif
  test("kprobe:f { kstack(1) }");
  test("kprobe:f { ustack(1) }");
  test("kprobe:f { cat(\"/proc/uptime\") }");
  test("uprobe:/bin/bash:main { uaddr(\"glob_asciirange\") }");
  test("kprobe:f { cgroupid(\"/sys/fs/cgroup/unified/mycg\"); }");
  test("kprobe:f { macaddr(0xffff) }");
  test("kprobe:f { nsecs() }");
}

TEST(semantic_analyser, undefined_map)
{
  test("kprobe:f / @mymap == 123 / { @mymap = 0 }");
  test_error("kprobe:f / @mymap == 123 / { 456; }", R"(
stdin:1:12-18: ERROR: Undefined map: @mymap
kprobe:f / @mymap == 123 / { 456; }
           ~~~~~~
stdin:1:12-25: ERROR: Type mismatch for '==': comparing 'none' with 'int64'
kprobe:f / @mymap == 123 / { 456; }
           ~~~~~~~~~~~~~
)");
  test_error("kprobe:f / @mymap1 == 1234 / { 1234; @mymap1 = @mymap2; }", R"(
stdin:1:12-27: ERROR: Type mismatch for '==': comparing 'none' with 'int64'
kprobe:f / @mymap1 == 1234 / { 1234; @mymap1 = @mymap2; }
           ~~~~~~~~~~~~~~~
stdin:1:48-55: ERROR: Undefined map: @mymap2
kprobe:f / @mymap1 == 1234 / { 1234; @mymap1 = @mymap2; }
                                               ~~~~~~~
stdin:1:38-45: ERROR: Undefined map: @mymap1
kprobe:f / @mymap1 == 1234 / { 1234; @mymap1 = @mymap2; }
                                     ~~~~~~~
stdin:1:48-55: ERROR: Invalid expression for assignment: none
kprobe:f / @mymap1 == 1234 / { 1234; @mymap1 = @mymap2; }
                                               ~~~~~~~
)");
}

TEST(semantic_analyser, consistent_map_values)
{
  test("kprobe:f { @x = 0; @x = 1; }");
  test_error("kprobe:f { @x = 0; @x = \"a\"; }", R"(
stdin:1:20-22: ERROR: Type mismatch for @x: trying to assign value of type 'string[2]' when map already contains a value of type 'int64'
kprobe:f { @x = 0; @x = "a"; }
                   ~~
)");
  test_error("kprobe:f { @x = 0; @x = *curtask; }", R"(
stdin:1:20-22: ERROR: Type mismatch for @x: trying to assign value of type 'struct task_struct' when map already contains a value of type 'int64'
kprobe:f { @x = 0; @x = *curtask; }
                   ~~
)");
}

TEST(semantic_analyser, consistent_map_keys)
{
  test("BEGIN { @x = 0; @x; }");
  test("BEGIN { @x[1] = 0; @x[2]; }");

  test_error("BEGIN { @x = 0; @x[1]; }", R"(
stdin:1:17-22: ERROR: Argument mismatch for @x: trying to access with arguments: [unsigned int64] when map expects arguments: []
BEGIN { @x = 0; @x[1]; }
                ~~~~~
)");
  test_error("BEGIN { @x[1] = 0; @x; }", R"(
stdin:1:20-22: ERROR: Argument mismatch for @x: trying to access with arguments: [] when map expects arguments: [unsigned int64]
BEGIN { @x[1] = 0; @x; }
                   ~~
)");

  test("BEGIN { @x[1,2] = 0; @x[3,4]; }");

  test_error("BEGIN { @x[1,2] = 0; @x[3]; }", R"(
stdin:1:22-27: ERROR: Argument mismatch for @x: trying to access with arguments: [unsigned int64] when map expects arguments: [unsigned int64, unsigned int64]
BEGIN { @x[1,2] = 0; @x[3]; }
                     ~~~~~
)");
  test_error("BEGIN { @x[1] = 0; @x[2,3]; }", R"(
stdin:1:20-27: ERROR: Argument mismatch for @x: trying to access with arguments: [unsigned int64, unsigned int64] when map expects arguments: [unsigned int64]
BEGIN { @x[1] = 0; @x[2,3]; }
                   ~~~~~~~
)");

  test("BEGIN { @x[1,\"a\",kstack] = 0; @x[2,\"b\", kstack]; }");

  test_error(R"(
    BEGIN {
      @x[1,"a",kstack] = 0;
      @x["b", 2, kstack];
    })",
             R"(
stdin:3:7-25: ERROR: Argument mismatch for @x: trying to access with arguments: [string[2], unsigned int64, kstack] when map expects arguments: [unsigned int64, string[2], kstack]
      @x["b", 2, kstack];
      ~~~~~~~~~~~~~~~~~~
)");
}

TEST(semantic_analyser, if_statements)
{
  test("kprobe:f { if(1) { 123 } }");
  test("kprobe:f { if(1) { 123 } else { 456 } }");
  test("kprobe:f { if(0) { 123 } else if(1) { 456 } else { 789 } }");
  test("kprobe:f { if((int32)pid) { 123 } }");
}

TEST(semantic_analyser, predicate_expressions)
{
  test("kprobe:f / 999 / { 123 }");
  test_error("kprobe:f / \"str\" / { 123 }", R"(
stdin:1:10-19: ERROR: Invalid type for predicate: string
kprobe:f / "str" / { 123 }
         ~~~~~~~~~
)");
  test_error("kprobe:f / kstack / { 123 }", R"(
stdin:1:10-20: ERROR: Invalid type for predicate: kstack
kprobe:f / kstack / { 123 }
         ~~~~~~~~~~
)");
  test_error("kprobe:f / @mymap / { @mymap = \"str\" }", R"(
stdin:1:10-20: ERROR: Invalid type for predicate: string
kprobe:f / @mymap / { @mymap = "str" }
         ~~~~~~~~~~
)");
}

TEST(semantic_analyser, ternary_expressions)
{
  test("kprobe:f { @x = pid < 10000 ? 1 : 2 }");
  test("kprobe:f { @x = pid < 10000 ? \"lo\" : \"high\" }");
  test("kprobe:f { pid < 10000 ? printf(\"lo\") : exit() }");
  test("kprobe:f { @x = pid < 10000 ? printf(\"lo\") : cat(\"/proc/uptime\") }",
       10);
  // Error location is incorrect: #3063
  test_error("kprobe:f { pid < 10000 ? 3 : cat(\"/proc/uptime\") }", R"(
stdin:1:12-50: ERROR: Ternary operator must return the same type: have 'integer' and 'none'
kprobe:f { pid < 10000 ? 3 : cat("/proc/uptime") }
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)");
  // Error location is incorrect: #3063
  test_error("kprobe:f { @x = pid < 10000 ? 1 : \"high\" }", R"(
stdin:1:17-42: ERROR: Ternary operator must return the same type: have 'integer' and 'string'
kprobe:f { @x = pid < 10000 ? 1 : "high" }
                ~~~~~~~~~~~~~~~~~~~~~~~~~
)");
  // Error location is incorrect: #3063
  test_error("kprobe:f { @x = pid < 10000 ? \"lo\" : 2 }", R"(
stdin:1:17-40: ERROR: Ternary operator must return the same type: have 'string' and 'integer'
kprobe:f { @x = pid < 10000 ? "lo" : 2 }
                ~~~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(semantic_analyser, mismatched_call_types)
{
  test_error("kprobe:f { @x = 1; @x = count(); }", R"(
stdin:1:20-22: ERROR: Type mismatch for @x: trying to assign value of type 'count' when map already contains a value of type 'int64'
kprobe:f { @x = 1; @x = count(); }
                   ~~
)");
  test_error("kprobe:f { @x = count(); @x = sum(pid); }", R"(
stdin:1:26-28: ERROR: Type mismatch for @x: trying to assign value of type 'sum' when map already contains a value of type 'count'
kprobe:f { @x = count(); @x = sum(pid); }
                         ~~
)");
  test_error("kprobe:f { @x = 1; @x = hist(0); }", R"(
stdin:1:20-22: ERROR: Type mismatch for @x: trying to assign value of type 'hist' when map already contains a value of type 'int64'
kprobe:f { @x = 1; @x = hist(0); }
                   ~~
)");
}

TEST(semantic_analyser, compound_left)
{
  test_error("kprobe:f { $a <<= 0 }", R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a <<= 0 }
           ~~
)");
  test("kprobe:f { $a = 0; $a <<= 1 }");
  test("kprobe:f { @a <<= 1 }");
}

TEST(semantic_analyser, compound_right)
{
  test_error("kprobe:f { $a >>= 0 }", R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a >>= 0 }
           ~~
)");
  test("kprobe:f { $a = 0; $a >>= 1 }");
  test("kprobe:f { @a >>= 1 }");
}

TEST(semantic_analyser, compound_plus)
{
  test_error("kprobe:f { $a += 0 }", R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a += 0 }
           ~~
)");
  test("kprobe:f { $a = 0; $a += 1 }");
  test("kprobe:f { @a += 1 }");
}

TEST(semantic_analyser, compound_minus)
{
  test_error("kprobe:f { $a -= 0 }", R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a -= 0 }
           ~~
)");
  test("kprobe:f { $a = 0; $a -= 1 }");
  test("kprobe:f { @a -= 1 }");
}

TEST(semantic_analyser, compound_mul)
{
  test_error("kprobe:f { $a *= 0 }", R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a *= 0 }
           ~~
)");
  test("kprobe:f { $a = 0; $a *= 1 }");
  test("kprobe:f { @a *= 1 }");
}

TEST(semantic_analyser, compound_div)
{
  test_error("kprobe:f { $a /= 0 }", R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a /= 0 }
           ~~
)");
  test("kprobe:f { $a = 0; $a /= 1 }");
  test("kprobe:f { @a /= 1 }");
}

TEST(semantic_analyser, compound_mod)
{
  test_error("kprobe:f { $a %= 0 }", R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a %= 0 }
           ~~
)");
  test("kprobe:f { $a = 0; $a %= 1 }");
  test("kprobe:f { @a %= 1 }");
}

TEST(semantic_analyser, compound_band)
{
  test_error("kprobe:f { $a &= 0 }", R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a &= 0 }
           ~~
)");
  test("kprobe:f { $a = 0; $a &= 1 }");
  test("kprobe:f { @a &= 1 }");
}

TEST(semantic_analyser, compound_bor)
{
  test_error("kprobe:f { $a |= 0 }", R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a |= 0 }
           ~~
)");
  test("kprobe:f { $a = 0; $a |= 1 }");
  test("kprobe:f { @a |= 1 }");
}

TEST(semantic_analyser, compound_bxor)
{
  test_error("kprobe:f { $a ^= 0 }", R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a ^= 0 }
           ~~
)");
  test("kprobe:f { $a = 0; $a ^= 1 }");
  test("kprobe:f { @a ^= 1 }");
}

TEST(semantic_analyser, call_hist)
{
  test("kprobe:f { @x = hist(1); }");
  test("kprobe:f { @x = hist(1, 0); }");
  test("kprobe:f { @x = hist(1, 5); }");
  test_error("kprobe:f { @x = hist(1, 10); }", R"(
stdin:1:17-28: ERROR: hist: bits 10 must be 0..5
kprobe:f { @x = hist(1, 10); }
                ~~~~~~~~~~~
)");
  test_error("kprobe:f { $n = 3; @x = hist(1, $n); }", R"(
stdin:1:25-36: ERROR: hist() expects a integer literal (integer provided)
kprobe:f { $n = 3; @x = hist(1, $n); }
                        ~~~~~~~~~~~
)");
  test_error("kprobe:f { @x = hist(); }", R"(
stdin:1:17-23: ERROR: hist() requires at least one argument (0 provided)
kprobe:f { @x = hist(); }
                ~~~~~~
)");
  test_error("kprobe:f { hist(1); }", R"(
stdin:1:12-19: ERROR: hist() should be directly assigned to a map
kprobe:f { hist(1); }
           ~~~~~~~
)");
  test_error("kprobe:f { $x = hist(1); }", R"(
stdin:1:17-24: ERROR: hist() should be directly assigned to a map
kprobe:f { $x = hist(1); }
                ~~~~~~~
)");
  test_error("kprobe:f { @x[hist(1)] = 1; }", R"(
stdin:1:12-22: ERROR: hist() should be directly assigned to a map
kprobe:f { @x[hist(1)] = 1; }
           ~~~~~~~~~~
)");
  test_error("kprobe:f { if(hist()) { 123 } }", R"(
stdin:1:12-21: ERROR: hist() should be directly assigned to a map
kprobe:f { if(hist()) { 123 } }
           ~~~~~~~~~
stdin:1:12-21: ERROR: hist() requires at least one argument (0 provided)
kprobe:f { if(hist()) { 123 } }
           ~~~~~~~~~
)");
  test_error("kprobe:f { hist() ? 0 : 1; }", R"(
stdin:1:12-18: ERROR: hist() should be directly assigned to a map
kprobe:f { hist() ? 0 : 1; }
           ~~~~~~
stdin:1:12-18: ERROR: hist() requires at least one argument (0 provided)
kprobe:f { hist() ? 0 : 1; }
           ~~~~~~
)");
}

TEST(semantic_analyser, call_lhist)
{
  test("kprobe:f { @ = lhist(5, 0, 10, 1); }");
  test_error("kprobe:f { @ = lhist(5, 0, 10); }", R"(
stdin:1:16-31: ERROR: lhist() requires 4 arguments (3 provided)
kprobe:f { @ = lhist(5, 0, 10); }
               ~~~~~~~~~~~~~~~
)");
  test_error("kprobe:f { @ = lhist(5, 0); }", R"(
stdin:1:16-27: ERROR: lhist() requires 4 arguments (2 provided)
kprobe:f { @ = lhist(5, 0); }
               ~~~~~~~~~~~
)");
  test_error("kprobe:f { @ = lhist(5); }", R"(
stdin:1:16-24: ERROR: lhist() requires 4 arguments (1 provided)
kprobe:f { @ = lhist(5); }
               ~~~~~~~~
)");
  test_error("kprobe:f { @ = lhist(); }", R"(
stdin:1:16-23: ERROR: lhist() requires 4 arguments (0 provided)
kprobe:f { @ = lhist(); }
               ~~~~~~~
)");
  test_error("kprobe:f { @ = lhist(5, 0, 10, 1, 2); }", R"(
stdin:1:16-37: ERROR: lhist() requires 4 arguments (5 provided)
kprobe:f { @ = lhist(5, 0, 10, 1, 2); }
               ~~~~~~~~~~~~~~~~~~~~~
)");
  test_error("kprobe:f { lhist(-10, -10, 10, 1); }", R"(
stdin:1:12-34: ERROR: lhist() should be directly assigned to a map
kprobe:f { lhist(-10, -10, 10, 1); }
           ~~~~~~~~~~~~~~~~~~~~~~
)");
  test_error("kprobe:f { @ = lhist(-10, -10, 10, 1); }", R"(
stdin:1:16-38: ERROR: lhist() min must be non-negative (provided min -10)
kprobe:f { @ = lhist(-10, -10, 10, 1); }
               ~~~~~~~~~~~~~~~~~~~~~~
)");
  test_error("kprobe:f { $x = lhist(); }", R"(
stdin:1:17-24: ERROR: lhist() should be directly assigned to a map
kprobe:f { $x = lhist(); }
                ~~~~~~~
stdin:1:17-24: ERROR: lhist() requires 4 arguments (0 provided)
kprobe:f { $x = lhist(); }
                ~~~~~~~
)");
  test_error("kprobe:f { @[lhist()] = 1; }", R"(
stdin:1:12-21: ERROR: lhist() should be directly assigned to a map
kprobe:f { @[lhist()] = 1; }
           ~~~~~~~~~
stdin:1:12-21: ERROR: lhist() requires 4 arguments (0 provided)
kprobe:f { @[lhist()] = 1; }
           ~~~~~~~~~
)");
  test_error("kprobe:f { if(lhist()) { 123 } }", R"(
stdin:1:12-22: ERROR: lhist() should be directly assigned to a map
kprobe:f { if(lhist()) { 123 } }
           ~~~~~~~~~~
stdin:1:12-22: ERROR: lhist() requires 4 arguments (0 provided)
kprobe:f { if(lhist()) { 123 } }
           ~~~~~~~~~~
)");
  test_error("kprobe:f { lhist() ? 0 : 1; }", R"(
stdin:1:12-19: ERROR: lhist() should be directly assigned to a map
kprobe:f { lhist() ? 0 : 1; }
           ~~~~~~~
stdin:1:12-19: ERROR: lhist() requires 4 arguments (0 provided)
kprobe:f { lhist() ? 0 : 1; }
           ~~~~~~~
)");
}

TEST(semantic_analyser, call_lhist_posparam)
{
  BPFtrace bpftrace;
  bpftrace.add_param("0");
  bpftrace.add_param("10");
  bpftrace.add_param("1");
  bpftrace.add_param("hello");
  test(bpftrace, "kprobe:f { @ = lhist(5, $1, $2, $3); }");
  test(bpftrace, "kprobe:f { @ = lhist(5, $1, $2, $4); }", 10);
}

TEST(semantic_analyser, call_count)
{
  test("kprobe:f { @x = count(); }");
  test("kprobe:f { @x = count(1); }", 1);
  test("kprobe:f { count(); }", 1);
  test("kprobe:f { $x = count(); }", 1);
  test("kprobe:f { @[count()] = 1; }", 1);
  test("kprobe:f { if(count()) { 123 } }", 1);
  test("kprobe:f { count() ? 0 : 1; }", 1);
}

TEST(semantic_analyser, call_sum)
{
  test("kprobe:f { @x = sum(123); }");
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
  test("kprobe:f { @x = min(123); }");
  test("kprobe:f { @x = min(); }", 1);
  test("kprobe:f { min(123); }", 1);
  test("kprobe:f { $x = min(123); }", 1);
  test("kprobe:f { @[min(123)] = 1; }", 1);
  test("kprobe:f { if(min(1)) { 123 } }", 1);
  test("kprobe:f { min(1) ? 0 : 1; }", 1);
}

TEST(semantic_analyser, call_max)
{
  test("kprobe:f { @x = max(123); }");
  test("kprobe:f { @x = max(); }", 1);
  test("kprobe:f { max(123); }", 1);
  test("kprobe:f { $x = max(123); }", 1);
  test("kprobe:f { @[max(123)] = 1; }", 1);
  test("kprobe:f { if(max(1)) { 123 } }", 1);
  test("kprobe:f { max(1) ? 0 : 1; }", 1);
}

TEST(semantic_analyser, call_avg)
{
  test("kprobe:f { @x = avg(123); }");
  test("kprobe:f { @x = avg(); }", 1);
  test("kprobe:f { avg(123); }", 1);
  test("kprobe:f { $x = avg(123); }", 1);
  test("kprobe:f { @[avg(123)] = 1; }", 1);
  test("kprobe:f { if(avg(1)) { 123 } }", 1);
  test("kprobe:f { avg(1) ? 0 : 1; }", 1);
}

TEST(semantic_analyser, call_stats)
{
  test("kprobe:f { @x = stats(123); }");
  test("kprobe:f { @x = stats(); }", 1);
  test("kprobe:f { stats(123); }", 1);
  test("kprobe:f { $x = stats(123); }", 1);
  test("kprobe:f { @[stats(123)] = 1; }", 1);
  test("kprobe:f { if(stats(1)) { 123 } }", 1);
  test("kprobe:f { stats(1) ? 0 : 1; }", 1);
}

TEST(semantic_analyser, call_delete)
{
  test("kprobe:f { @x = 1; delete(@x); }");
  test("kprobe:f { @x = 1; @y = 2; delete(@x, @y); }");
  test("kprobe:f { @x = 1; @y[5] = 5; delete(@x, @y[5]); }");
  test("kprobe:f { delete(1); }", 1);
  test("kprobe:f { delete(); }", 1);
  test("kprobe:f { @y = delete(@x); }", 1);
  test("kprobe:f { $y = delete(@x); }", 1);
  test("kprobe:f { @[delete(@x)] = 1; }", 1);
  test("kprobe:f { @x = 1; if(delete(@x)) { 123 } }", 10);
  test("kprobe:f { @x = 1; delete(@x) ? 0 : 1; }", 10);

  test_error("kprobe:f { @x = 1; @y[5] = 5; delete(@x, @y); }", R"(
stdin:1:42-44: ERROR: Argument mismatch for @y: trying to access with arguments: [] when map expects arguments: [unsigned int64]
kprobe:f { @x = 1; @y[5] = 5; delete(@x, @y); }
                                         ~~
)");
  test_error("kprobe:f { @x = 1; $y = 2; $c = 3; delete(@x, $y, $c); }", R"(
stdin:1:47-49: ERROR: delete() only expects maps to be provided
kprobe:f { @x = 1; $y = 2; $c = 3; delete(@x, $y, $c); }
                                              ~~
stdin:1:51-53: ERROR: delete() only expects maps to be provided
kprobe:f { @x = 1; $y = 2; $c = 3; delete(@x, $y, $c); }
                                                  ~~
)");
}

TEST(semantic_analyser, call_exit)
{
  test("kprobe:f { exit(); }");
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
  test("kprobe:f { @x = count(); print(@x); }");
  test("kprobe:f { @x = count(); print(@x, 5); }");
  test("kprobe:f { @x = count(); print(@x, 5, 10); }");
  test("kprobe:f { @x = count(); print(@x, 5, 10, 1); }", 1);
  test("kprobe:f { @x = count(); @x = print(); }", 1);

  test("kprobe:f { print(@x); @x[1,2] = count(); }");
  test("kprobe:f { @x[1,2] = count(); print(@x); }");

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

TEST(semantic_analyser, call_print_map_item)
{
  test(R"_(BEGIN { @x[1] = 1; print(@x[1]); })_");
  test(R"_(BEGIN { @x[1] = 1; @x[2] = 2; print(@x[2]); })_");
  test(R"_(BEGIN { @x[1] = 1; print(@x[2]); })_");
  test(R"_(BEGIN { @x[3, 5] = 1; print(@x[3, 5]); })_");
  test(R"_(BEGIN { @x[1,2] = "asdf"; print((1, 2, @x[1,2])); })_");

  test_error("BEGIN { @x[1] = 1; print(@x[\"asdf\"]); }", R"(
stdin:1:20-36: ERROR: Argument mismatch for @x: trying to access with arguments: [string[5]] when map expects arguments: [unsigned int64]
BEGIN { @x[1] = 1; print(@x["asdf"]); }
                   ~~~~~~~~~~~~~~~~
)");
  test_error("BEGIN { print(@x[2]); }", R"(
stdin:1:9-20: ERROR: Undefined map: @x
BEGIN { print(@x[2]); }
        ~~~~~~~~~~~
)");
  test_error("BEGIN { @x[1] = 1; print(@x[1], 3, 5); }", R"(
stdin:1:20-38: ERROR: Single-value (i.e. indexed) map print cannot take additional arguments.
BEGIN { @x[1] = 1; print(@x[1], 3, 5); }
                   ~~~~~~~~~~~~~~~~~~
)");
}

TEST(semantic_analyser, call_print_non_map)
{
  test(R"_(BEGIN { print(1) })_");
  test(R"_(BEGIN { print(comm) })_");
  test(R"_(BEGIN { print(nsecs) })_");
  test(R"_(BEGIN { print("string") })_");
  test(R"_(BEGIN { print((1, 2, "tuple")) })_");
  test(R"_(BEGIN { $x = 1; print($x) })_");
  test(R"_(BEGIN { $x = 1; $y = $x + 3; print($y) })_");
  test(R"_(BEGIN { print((int8 *)0) })_");

  test(R"_(BEGIN { print(3, 5) })_", 1);
  test(R"_(BEGIN { print(3, 5, 2) })_", 1);

  test(R"_(BEGIN { print(exit()) })_", 10);
  test(R"_(BEGIN { print(count()) })_", 1);
  test(R"_(BEGIN { print(ctx) })_", 1);
}

TEST(semantic_analyser, call_clear)
{
  test("kprobe:f { @x = count(); clear(@x); }");
  test("kprobe:f { @x = count(); clear(@x, 1); }", 1);
  test("kprobe:f { @x = count(); @x = clear(); }", 1);

  test("kprobe:f { clear(@x); @x[1,2] = count(); }");
  test("kprobe:f { @x[1,2] = count(); clear(@x); }");
  test("kprobe:f { @x[1,2] = count(); clear(@x[3,4]); }", 1);

  test("kprobe:f { @x = count(); @ = clear(@x); }", 1);
  test("kprobe:f { @x = count(); $y = clear(@x); }", 1);
  test("kprobe:f { @x = count(); @[clear(@x)] = 1; }", 1);
  test("kprobe:f { @x = count(); if(clear(@x)) { 123 } }", 10);
  test("kprobe:f { @x = count(); clear(@x) ? 0 : 1; }", 10);
}

TEST(semantic_analyser, call_zero)
{
  test("kprobe:f { @x = count(); zero(@x); }");
  test("kprobe:f { @x = count(); zero(@x, 1); }", 1);
  test("kprobe:f { @x = count(); @x = zero(); }", 1);

  test("kprobe:f { zero(@x); @x[1,2] = count(); }");
  test("kprobe:f { @x[1,2] = count(); zero(@x); }");
  test("kprobe:f { @x[1,2] = count(); zero(@x[3,4]); }", 1);

  test("kprobe:f { @x = count(); @ = zero(@x); }", 1);
  test("kprobe:f { @x = count(); $y = zero(@x); }", 1);
  test("kprobe:f { @x = count(); @[zero(@x)] = 1; }", 1);
  test("kprobe:f { @x = count(); if(zero(@x)) { 123 } }", 10);
  test("kprobe:f { @x = count(); zero(@x) ? 0 : 1; }", 10);
}

TEST(semantic_analyser, call_len)
{
  test("kprobe:f { @x[0] = 0; len(@x); }");
  test("kprobe:f { @x[0] = 0; len(); }", 1);
  test("kprobe:f { @x[0] = 0; len(@x, 1); }", 1);
  test("kprobe:f { @x[0] = 0; len(@x[2]); }", 1);
  test("kprobe:f { $x = 0; len($x); }", 1);
}

TEST(semantic_analyser, call_time)
{
  test("kprobe:f { time(); }");
  test("kprobe:f { time(\"%M:%S\"); }");
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
  test("kprobe:f { strftime(\"%M:%S\", 1); }");
  test("kprobe:f { strftime(\"%M:%S\", nsecs); }");
  test("kprobe:f { strftime(\"%M:%S\", \"\"); }", 10);
  test("kprobe:f { strftime(1, nsecs); }", 10);
  test("kprobe:f { $var = \"str\"; strftime($var, nsecs); }", 10);
  test("kprobe:f { strftime(); }", 1);
  test("kprobe:f { strftime(\"%M:%S\"); }", 1);
  test("kprobe:f { strftime(\"%M:%S\", 1, 1); }", 1);
  test("kprobe:f { strftime(1, 1, 1); }", 1);
  test("kprobe:f { strftime(\"%M:%S\", \"\", 1); }", 1);
  test("kprobe:f { $ts = strftime(\"%M:%S\", 1); }");
  test("kprobe:f { @ts = strftime(\"%M:%S\", nsecs); }");
  test("kprobe:f { @[strftime(\"%M:%S\", nsecs)] = 1; }");
  test("kprobe:f { printf(\"%s\", strftime(\"%M:%S\", nsecs)); }");
  test("kprobe:f { strncmp(\"str\", strftime(\"%M:%S\", nsecs), 10); }", 10);

  test("kprobe:f { strftime(\"%M:%S\", nsecs(monotonic)); }", 10);
  test("kprobe:f { strftime(\"%M:%S\", nsecs(boot)); }");
  test("kprobe:f { strftime(\"%M:%S\", nsecs(tai)); }");
}

TEST(semantic_analyser, call_str)
{
  test("kprobe:f { str(arg0); }");
  test("kprobe:f { @x = str(arg0); }");
  test("kprobe:f { str(); }", 1);
  test("kprobe:f { str(\"hello\"); }", 1);
}

TEST(semantic_analyser, call_str_2_lit)
{
  test("kprobe:f { str(arg0, 3); }");
  test("kprobe:f { str(arg0, -3); }", 10);
  test("kprobe:f { @x = str(arg0, 3); }");
  test("kprobe:f { str(arg0, \"hello\"); }", 10);
}

TEST(semantic_analyser, call_str_2_expr)
{
  test("kprobe:f { str(arg0, arg1); }");
  test("kprobe:f { @x = str(arg0, arg1); }");
}

TEST(semantic_analyser, call_str_state_leak_regression_test)
{
  // Previously, the semantic analyser would leak state in the first str()
  // call. This would make the semantic analyser think it's still processing
  // a positional parameter in the second str() call causing confusing error
  // messages.
  test(R"PROG(kprobe:f { $x = str($1) == "asdf"; $y = str(arg0) })PROG");
}

TEST(semantic_analyser, call_buf)
{
  test("kprobe:f { buf(arg0, 1); }");
  test("kprobe:f { buf(arg0, -1); }", 1);
  test("kprobe:f { @x = buf(arg0, 1); }");
  test("kprobe:f { $x = buf(arg0, 1); }");
  test("kprobe:f { buf(); }", 1);
  test("kprobe:f { buf(\"hello\"); }", 10);
  test("struct x { int c[4] }; kprobe:f { $foo = (struct x*)0; @x = "
       "buf($foo->c); }");
}

TEST(semantic_analyser, call_buf_lit)
{
  test("kprobe:f { @x = buf(arg0, 3); }");
  test("kprobe:f { buf(arg0, \"hello\"); }", 10);
}

TEST(semantic_analyser, call_buf_expr)
{
  test("kprobe:f { buf(arg0, arg1); }");
  test("kprobe:f { @x = buf(arg0, arg1); }");
}

TEST(semantic_analyser, call_buf_posparam)
{
  BPFtrace bpftrace;
  bpftrace.add_param("1");
  bpftrace.add_param("hello");
  test(bpftrace, "kprobe:f { buf(arg0, $1); }");
  test(bpftrace, "kprobe:f { buf(arg0, $2); }", 1);
}

TEST(semantic_analyser, call_ksym)
{
  test("kprobe:f { ksym(arg0); }");
  test("kprobe:f { @x = ksym(arg0); }");
  test("kprobe:f { ksym(); }", 1);
  test("kprobe:f { ksym(\"hello\"); }", 1);
}

TEST(semantic_analyser, call_usym)
{
  test("kprobe:f { usym(arg0); }");
  test("kprobe:f { @x = usym(arg0); }");
  test("kprobe:f { usym(); }", 1);
  test("kprobe:f { usym(\"hello\"); }", 1);
}

TEST(semantic_analyser, call_ntop)
{
  std::string structs = "struct inet { unsigned char ipv4[4]; unsigned char "
                        "ipv6[16]; unsigned char invalid[10]; } ";

  test("kprobe:f { ntop(2, arg0); }");
  test("kprobe:f { ntop(arg0); }");
  test(structs + "kprobe:f { ntop(10, ((struct inet*)0)->ipv4); }");
  test(structs + "kprobe:f { ntop(10, ((struct inet*)0)->ipv6); }");
  test(structs + "kprobe:f { ntop(((struct inet*)0)->ipv4); }");
  test(structs + "kprobe:f { ntop(((struct inet*)0)->ipv6); }");

  test("kprobe:f { @x = ntop(2, arg0); }");
  test("kprobe:f { @x = ntop(arg0); }");
  test("kprobe:f { @x = ntop(2, 0xFFFF); }");
  test("kprobe:f { @x = ntop(0xFFFF); }");
  test(structs + "kprobe:f { @x = ntop(((struct inet*)0)->ipv4); }");
  test(structs + "kprobe:f { @x = ntop(((struct inet*)0)->ipv6); }");

  // Regression test that ntop can use arguments from the prog context
  test("tracepoint:tcp:some_tcp_tp { ntop(args.saddr_v6); }");

  test("kprobe:f { ntop(); }", 1);
  test("kprobe:f { ntop(2, \"hello\"); }", 1);
  test("kprobe:f { ntop(\"hello\"); }", 1);
  test(structs + "kprobe:f { ntop(((struct inet*)0)->invalid); }", 1);
}

TEST(semantic_analyser, call_pton)
{
  test("kprobe:f { $addr_v4 = pton(\"127.0.0.1\"); }");
  test("kprobe:f { $addr_v4 = pton(\"127.0.0.1\"); $b1 = $addr_v4[0]; }");
  test("kprobe:f { $addr_v6 = pton(\"::1\"); }");
  test("kprobe:f { $addr_v6 = pton(\"::1\"); $b1 = $addr_v6[0]; }");

  std::string def = "#define AF_INET 2\n #define AF_INET6 10\n";
  test("kprobe:f { $addr_v4_text = ntop(pton(\"127.0.0.1\")); }");
  test(def +
       "kprobe:f { $addr_v4_text = ntop(AF_INET, pton(\"127.0.0.1\")); }");
  test(def + "kprobe:f { $addr_v6_text = ntop(AF_INET6, pton(\"::1\")); }");

  test("kprobe:f { $addr_v4 = pton(); }", 1);
  test("kprobe:f { $addr_v4 = pton(\"\"); }", 1);
  test("kprobe:f { $addr_v4 = pton(\"127.0.1\"); }", 1);
  test("kprobe:f { $addr_v4 = pton(\"127.0.0.0.1\"); }", 1);
  test("kprobe:f { $addr_v6 = pton(\":\"); }", 1);
  test("kprobe:f { $addr_v6 = pton(\"1:1:1:1:1:1:1:1:1\"); }", 1);

  std::string structs = "struct inet { unsigned char non_literal_string[4]; } ";
  test("kprobe:f { $addr_v4 = pton(1); }", 1);
  test(structs + "kprobe:f { $addr_v4 = pton(((struct "
                 "inet*)0)->non_literal_string); }",
       1);
}

TEST(semantic_analyser, call_kaddr)
{
  test("kprobe:f { kaddr(\"avenrun\"); }");
  test("kprobe:f { @x = kaddr(\"avenrun\"); }");
  test("kprobe:f { kaddr(); }", 1);
  test("kprobe:f { kaddr(123); }", 1);
}

TEST(semantic_analyser, call_uaddr)
{
  test("u:/bin/bash:main { uaddr(\"github.com/golang/glog.severityName\"); }");
  test("uprobe:/bin/bash:main { uaddr(\"glob_asciirange\"); }");
  test("u:/bin/bash:main,u:/bin/bash:readline { uaddr(\"glob_asciirange\"); }");
  test("uprobe:/bin/bash:main { @x = uaddr(\"glob_asciirange\"); }");
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

  test(driver, prog);

  std::vector<int> sizes = { 8, 16, 32, 64, 64, 64 };

  for (size_t i = 0; i < sizes.size(); i++) {
    auto v = static_cast<ast::AssignVarStatement *>(
        driver.ctx.root->probes.at(0)->stmts.at(i));
    EXPECT_TRUE(v->var->type.IsPtrTy());
    EXPECT_TRUE(v->var->type.GetPointeeTy()->IsIntTy());
    EXPECT_EQ((unsigned long int)sizes.at(i),
              v->var->type.GetPointeeTy()->GetIntBitWidth());
  }
}

TEST(semantic_analyser, call_cgroupid)
{
  // Handle args above default max-string length (64)
  test("kprobe:f { cgroupid("
       //          1         2         3         4         5         6
       "\"123456789/123456789/123456789/123456789/123456789/123456789/12345\""
       "); }");
}

TEST(semantic_analyser, call_reg)
{
#ifdef ARCH_X86_64
  test("kprobe:f { reg(\"ip\"); }");
  test("kprobe:f { @x = reg(\"ip\"); }");
#endif
  test("kprobe:f { reg(\"blah\"); }", 1);
  test("kprobe:f { reg(); }", 1);
  test("kprobe:f { reg(123); }", 1);
}

TEST(semantic_analyser, call_func)
{
  test("kprobe:f { @[func] = count(); }");
  test("kprobe:f { printf(\"%s\", func);  }");
  test("uprobe:/bin/sh:f { @[func] = count(); }");
  test("uprobe:/bin/sh:f { printf(\"%s\", func);  }");

  test("kfunc:f { func }");
  test("kretfunc:f { func }");
  test("kretprobe:f { func }");
  test("uretprobe:/bin/sh:f { func }");

  // We only care about the BPF_FUNC_get_func_ip feature and error message here,
  // but don't have enough control over the mock features to only disable that.
  test_error("kfunc:f { func }",
             R"(
stdin:1:1-8: ERROR: kfunc/kretfunc not available for your kernel version.
kfunc:f { func }
~~~~~~~
stdin:1:11-15: ERROR: BPF_FUNC_get_func_ip not available for your kernel version
kfunc:f { func }
          ~~~~
)",
             false);

  test_error("kretfunc:f { func }",
             R"(
stdin:1:1-11: ERROR: kfunc/kretfunc not available for your kernel version.
kretfunc:f { func }
~~~~~~~~~~
stdin:1:14-18: ERROR: BPF_FUNC_get_func_ip not available for your kernel version
kretfunc:f { func }
             ~~~~
)",
             false);

  test_error("kretprobe:f { func }",
             R"(
stdin:1:15-19: ERROR: The 'func' builtin is not available for kretprobes on kernels without the get_func_ip BPF feature. Consider using the 'probe' builtin instead.
kretprobe:f { func }
              ~~~~
)",
             false);

  test_error("uretprobe:/bin/sh:f { func }",
             R"(
stdin:1:23-27: ERROR: The 'func' builtin is not available for uretprobes on kernels without the get_func_ip BPF feature. Consider using the 'probe' builtin instead.
uretprobe:/bin/sh:f { func }
                      ~~~~
)",
             false);
}

TEST(semantic_analyser, call_probe)
{
  test("kprobe:f { @[probe] = count(); }");
  test("kprobe:f { printf(\"%s\", probe);  }");
}

TEST(semantic_analyser, call_cat)
{
  test("kprobe:f { cat(\"/proc/loadavg\"); }");
  test("kprobe:f { cat(\"/proc/%d/cmdline\", 1); }");
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
  test("kprobe:f { kstack() }");
  test("kprobe:f { ustack() }");
  test("kprobe:f { kstack(bpftrace) }");
  test("kprobe:f { ustack(bpftrace) }");
  test("kprobe:f { kstack(perf) }");
  test("kprobe:f { ustack(perf) }");
  test("kprobe:f { kstack(3) }");
  test("kprobe:f { ustack(3) }");
  test("kprobe:f { kstack(perf, 3) }");
  test("kprobe:f { ustack(perf, 3) }");
  test("kprobe:f { kstack(raw, 3) }");
  test("kprobe:f { ustack(raw, 3) }");

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

  // Positional params
  BPFtrace bpftrace;
  bpftrace.add_param("3");
  bpftrace.add_param("hello");
  test(bpftrace, "kprobe:f { kstack($1) }");
  test(bpftrace, "kprobe:f { ustack($1) }");
  test(bpftrace, "kprobe:f { kstack(perf, $1) }");
  test(bpftrace, "kprobe:f { ustack(perf, $1) }");
  test(bpftrace, "kprobe:f { kstack($2) }", 1);
  test(bpftrace, "kprobe:f { ustack($2) }", 1);
  test(bpftrace, "kprobe:f { kstack(perf, $2) }", 1);
  test(bpftrace, "kprobe:f { ustack(perf, $2) }", 1);
}

TEST(semantic_analyser, call_macaddr)
{
  std::string structs =
      "struct mac { char addr[6]; }; struct invalid { char addr[7]; }; ";

  test("kprobe:f { macaddr(arg0); }");

  test(structs + "kprobe:f { macaddr((struct mac*)arg0); }");

  test(structs + "kprobe:f { @x[macaddr((struct mac*)arg0)] = 1; }");
  test(structs + "kprobe:f { @x = macaddr((struct mac*)arg0); }");

  test(structs + "kprobe:f { printf(\"%s\", macaddr((struct mac*)arg0)); }");

  test(structs + "kprobe:f { macaddr(((struct invalid*)arg0)->addr); }", 1);
  test(structs + "kprobe:f { macaddr(*(struct mac*)arg0); }", 1);

  test("kprobe:f { macaddr(); }", 1);
  test("kprobe:f { macaddr(\"hello\"); }", 1);
}

TEST(semantic_analyser, call_bswap)
{
  test("kprobe:f { bswap(arg0); }");

  test("kprobe:f { bswap(0x12); }");
  test("kprobe:f { bswap(0x12 + 0x34); }");

  test("kprobe:f { bswap((int8)0x12); }");
  test("kprobe:f { bswap((int16)0x12); }");
  test("kprobe:f { bswap((int32)0x12); }");
  test("kprobe:f { bswap((int64)0x12); }");

  test("kprobe:f { bswap(); }", 1);
  test("kprobe:f { bswap(0x12, 0x34); }", 1);

  test("kprobe:f { bswap(\"hello\"); }", 1);
}

TEST(semantic_analyser, call_cgroup_path)
{
  test("kprobe:f { cgroup_path(1) }");
  test("kprobe:f { cgroup_path(1, \"hello\") }");

  test("kprobe:f { cgroup_path(1, 2) }", 10);
  test("kprobe:f { cgroup_path(\"1\") }", 10);

  test("kprobe:f { printf(\"%s\", cgroup_path(1)) }");
  test("kprobe:f { printf(\"%s %s\", cgroup_path(1), cgroup_path(2)) }");
  test("kprobe:f { $var = cgroup_path(0); printf(\"%s %s\", $var, $var) }");

  test("kprobe:f { printf(\"%d\", cgroup_path(1)) }", 10);
}

TEST(semantic_analyser, call_strerror)
{
  test("kprobe:f { strerror(1) }");

  test("kprobe:f { strerror(1, 2) }", 1);
  test("kprobe:f { strerror(\"1\") }", 10);

  test("kprobe:f { printf(\"%s\", strerror(1)) }");
  test("kprobe:f { printf(\"%s %s\", strerror(1), strerror(2)) }");
  test("kprobe:f { $var = strerror(0); printf(\"%s %s\", $var, $var) }");

  test("kprobe:f { printf(\"%d\", strerror(1)) }", 10);
}

TEST(semantic_analyser, map_reassignment)
{
  test("kprobe:f { @x = 1; @x = 2; }");
  test("kprobe:f { @x = 1; @x = \"foo\"; }", 1);
}

TEST(semantic_analyser, variable_reassignment)
{
  test("kprobe:f { $x = 1; $x = 2; }");
  test("kprobe:f { $x = 1; $x = \"foo\"; }", 1);
}

TEST(semantic_analyser, map_use_before_assign)
{
  test("kprobe:f { @x = @y; @y = 2; }");
}

TEST(semantic_analyser, variable_use_before_assign)
{
  test("kprobe:f { @x = $y; $y = 2; }", 1);
}

TEST(semantic_analyser, maps_are_global)
{
  test("kprobe:f { @x = 1 } kprobe:g { @y = @x }");
  test("kprobe:f { @x = 1 } kprobe:g { @x = \"abc\" }", 1);
}

TEST(semantic_analyser, variables_are_local)
{
  test("kprobe:f { $x = 1 } kprobe:g { $x = \"abc\"; }");
  test("kprobe:f { $x = 1 } kprobe:g { @y = $x }", 1);
}

TEST(semantic_analyser, array_access)
{
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
       "arg0; @x = $s->y[0];}");
  auto assignment = static_cast<ast::AssignMapStatement *>(
      driver.ctx.root->probes.at(0)->stmts.at(1));
  EXPECT_EQ(CreateInt64(), assignment->map->type);

  test(driver,
       "struct MyStruct { int y[4]; } kprobe:f { $s = ((struct MyStruct *) "
       "arg0)->y; @x = $s[0];}");
  auto array_var_assignment = static_cast<ast::AssignVarStatement *>(
      driver.ctx.root->probes.at(0)->stmts.at(0));
  EXPECT_EQ(CreateArray(4, CreateInt32()), array_var_assignment->var->type);

  test(driver,
       "struct MyStruct { int y[4]; } kprobe:f { @a[0] = ((struct MyStruct *) "
       "arg0)->y; @x = @a[0][0];}");
  auto array_map_assignment = static_cast<ast::AssignMapStatement *>(
      driver.ctx.root->probes.at(0)->stmts.at(0));
  EXPECT_EQ(CreateArray(4, CreateInt32()), array_map_assignment->map->type);

  test(driver, "kprobe:f { $s = (int32 *) arg0; $x = $s[0]; }");
  auto var_assignment = static_cast<ast::AssignVarStatement *>(
      driver.ctx.root->probes.at(0)->stmts.at(1));
  EXPECT_EQ(CreateInt32(), var_assignment->var->type);

  // Positional parameter as index
  bpftrace.add_param("0");
  bpftrace.add_param("hello");
  test(bpftrace,
       "struct MyStruct { int y[4]; } "
       "kprobe:f { $s = ((struct MyStruct *)arg0)->y[$1]; }");
  test(bpftrace,
       "struct MyStruct { int y[4]; } "
       "kprobe:f { $s = ((struct MyStruct *)arg0)->y[$2]; }",
       10);

  test(bpftrace,
       "struct MyStruct { int x; int y[]; } "
       "kprobe:f { $s = (struct MyStruct *) "
       "arg0; @y = $s->y[0];}");
}

TEST(semantic_analyser, array_in_map)
{
  test("struct MyStruct { int x[2]; int y[4]; } "
       "kprobe:f { @ = ((struct MyStruct *)arg0)->x; }");
  test("struct MyStruct { int x[2]; int y[4]; } "
       "kprobe:f { @a[0] = ((struct MyStruct *)arg0)->x; }");
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
       "kprobe:f { @x[((struct MyStruct *)arg0)->x] = 0; }");

  test("struct MyStruct { int x[2]; int y[4]; }"
       "kprobe:f { @x[((struct MyStruct *)arg0)->x, "
       "              ((struct MyStruct *)arg0)->y] = 0; }");

  // Mismatched key types
  test_error(R"(
    struct MyStruct { int x[2]; int y[4]; }
    BEGIN {
      @x[((struct MyStruct *)0)->x] = 0;
      @x[((struct MyStruct *)0)->y] = 1;
    })",
             R"(
stdin:4:7-37: ERROR: Argument mismatch for @x: trying to access with arguments: [int32[4]] when map expects arguments: [int32[2]]
      @x[((struct MyStruct *)0)->y] = 1;
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(semantic_analyser, array_compare)
{
  test("#include <stdint.h>\n"
       "struct MyStruct { uint8_t x[4]; }"
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x == $s->x); }");
  test("#include <stdint.h>\n"
       "struct MyStruct { uint64_t x[4]; } "
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x == $s->x); }");
  test("struct MyStruct { int x[4]; } "
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x != $s->x); }");

  // unsupported operators
  test("struct MyStruct { int x[4]; } "
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x > $s->x); }",
       10);

  // different length
  test("struct MyStruct { int x[4]; int y[8]; }"
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x == $s->y); }",
       10);

  // different element type
  test("#include <stdint.h>\n"
       "struct MyStruct { uint8_t x[4]; uint16_t y[4]; } "
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x == $s->y); }",
       10);

  // compare with other type
  test("struct MyStruct { int x[4]; int y; } "
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x == $s->y); }",
       10);
}

TEST(semantic_analyser, variable_type)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  test(driver, "kprobe:f { $x = 1 }");
  auto st = CreateInt64();
  auto assignment = static_cast<ast::AssignVarStatement *>(
      driver.ctx.root->probes.at(0)->stmts.at(0));
  EXPECT_EQ(st, assignment->var->type);
}

TEST(semantic_analyser, unroll)
{
  test("kprobe:f { $i = 0; unroll(5) { printf(\"i: %d\\n\", $i); $i = $i + 1; "
       "} }");
  test("kprobe:f { $i = 0; unroll(101) { printf(\"i: %d\\n\", $i); $i = $i + "
       "1; } }",
       1);
  test("kprobe:f { $i = 0; unroll(0) { printf(\"i: %d\\n\", $i); $i = $i + 1; "
       "} }",
       1);

  BPFtrace bpftrace;
  bpftrace.add_param("10");
  bpftrace.add_param("hello");
  bpftrace.add_param("101");
  test(bpftrace, "kprobe:f { unroll($#) { printf(\"hi\\n\"); } }");
  test(bpftrace, "kprobe:f { unroll($1) { printf(\"hi\\n\"); } }");
  test(bpftrace, "kprobe:f { unroll($2) { printf(\"hi\\n\"); } }", 1);
  test(bpftrace, "kprobe:f { unroll($3) { printf(\"hi\\n\"); } }", 1);
}

TEST(semantic_analyser, map_integer_sizes)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  test(driver, "kprobe:f { $x = (int32) -1; @x = $x; }");

  auto var_assignment = static_cast<ast::AssignVarStatement *>(
      driver.ctx.root->probes.at(0)->stmts.at(0));
  auto map_assignment = static_cast<ast::AssignMapStatement *>(
      driver.ctx.root->probes.at(0)->stmts.at(1));
  EXPECT_EQ(CreateInt32(), var_assignment->var->type);
  EXPECT_EQ(CreateInt64(), map_assignment->map->type);
}

TEST(semantic_analyser, unop_dereference)
{
  test("kprobe:f { *0; }");
  test("struct X { int n; } kprobe:f { $x = (struct X*)0; *$x; }");
  test("struct X { int n; } kprobe:f { $x = *(struct X*)0; *$x; }", 1);
  test("kprobe:f { *\"0\"; }", 10);
}

TEST(semantic_analyser, unop_not)
{
  std::string structs = "struct X { int x; };";
  test("kprobe:f { ~0; }");
  test(structs + "kprobe:f { $x = *(struct X*)0; ~$x; }", 10);
  test(structs + "kprobe:f { $x = (struct X*)0; ~$x; }", 10);
  test("kprobe:f { ~\"0\"; }", 10);
}

TEST(semantic_analyser, unop_lnot)
{
  test("kprobe:f { !0; }");
  test("kprobe:f { !(int32)0; }");
  test("struct X { int n; } kprobe:f { $x = (struct X*)0; !$x; }", 10);
  test("struct X { int n; } kprobe:f { $x = *(struct X*)0; !$x; }", 10);
  test("kprobe:f { !\"0\"; }", 10);
}

TEST(semantic_analyser, unop_increment_decrement)
{
  test("kprobe:f { $x = 0; $x++; }");
  test("kprobe:f { $x = 0; $x--; }");
  test("kprobe:f { $x = 0; ++$x; }");
  test("kprobe:f { $x = 0; --$x; }");

  test("kprobe:f { @x++; }");
  test("kprobe:f { @x--; }");
  test("kprobe:f { ++@x; }");
  test("kprobe:f { --@x; }");

  test("kprobe:f { $x++; }", 1);
  test("kprobe:f { @x = \"a\"; @x++; }", 10);
  test("kprobe:f { $x = \"a\"; $x++; }", 10);
}

TEST(semantic_analyser, printf)
{
  test("kprobe:f { printf(\"hi\") }");
  test("kprobe:f { printf(1234) }", 1);
  test("kprobe:f { printf() }", 1);
  test("kprobe:f { $fmt = \"mystring\"; printf($fmt) }", 1);
  test("kprobe:f { printf(\"%s\", comm) }");
  test("kprobe:f { printf(\"%-16s\", comm) }");
  test("kprobe:f { printf(\"%-10.10s\", comm) }");
  test("kprobe:f { printf(\"%A\", comm) }", 10);
  test("kprobe:f { @x = printf(\"hi\") }", 1);
  test("kprobe:f { $x = printf(\"hi\") }", 1);
  test("kprobe:f { printf(\"%d %d %d %d %d %d %d %d %d\", 1, 2, 3, 4, 5, 6, 7, "
       "8, 9); }");
  test("kprobe:f { printf(\"%dns\", nsecs) }");

  {
    // Long format string should be ok
    std::stringstream prog;

    prog << "i:ms:100 { printf(\"" << std::string(200, 'a')
         << " %d\\n\", 1); }";
    test(prog.str());
  }
}

TEST(semantic_analyser, debugf)
{
  test_for_warning(
      "kprobe:f { debugf(\"warning\") }",
      "The debugf() builtin is not recommended for production use.");
  test("kprobe:f { debugf(\"hi\") }");
  test("kprobe:f { debugf(1234) }", 1);
  test("kprobe:f { debugf() }", 1);
  test("kprobe:f { $fmt = \"mystring\"; debugf($fmt) }", 1);
  test("kprobe:f { debugf(\"%s\", comm) }");
  test("kprobe:f { debugf(\"%-16s\", comm) }");
  test("kprobe:f { debugf(\"%-10.10s\", comm) }");
  test("kprobe:f { debugf(\"%lluns\", nsecs) }");
  test("kprobe:f { debugf(\"%A\", comm) }", 10);
  test("kprobe:f { @x = debugf(\"hi\") }", 1);
  test("kprobe:f { $x = debugf(\"hi\") }", 1);
  test("kprobe:f { debugf(\"%d\", 1) }");
  test("kprobe:f { debugf(\"%d %d\", 1, 1) }");
  test("kprobe:f { debugf(\"%d %d %d\", 1, 1, 1) }");
  test("kprobe:f { debugf(\"%d %d %d %d\", 1, 1, 1, 1) }", 10);

  {
    // Long format string should be ok
    std::stringstream prog;
    prog << "i:ms:100 { debugf(\"" << std::string(59, 'a')
         << "%s\\n\", \"a\"); }";
    test(prog.str());
  }
}

TEST(semantic_analyser, system)
{
  test("kprobe:f { system(\"ls\") }", 0, false /* safe_mode */);
  test("kprobe:f { system(1234) }", 1, false /* safe_mode */);
  test("kprobe:f { system() }", 1, false /* safe_mode */);
  test("kprobe:f { $fmt = \"mystring\"; system($fmt) }",
       1,
       false /* safe_mode */);
}

TEST(semantic_analyser, printf_format_int)
{
  test("kprobe:f { printf(\"int: %d\", 1234) }");
  test("kprobe:f { printf(\"int: %d\", pid) }");
  test("kprobe:f { @x = 123; printf(\"int: %d\", @x) }");
  test("kprobe:f { $x = 123; printf(\"int: %d\", $x) }");

  test("kprobe:f { printf(\"int: %u\", 1234) }");
  test("kprobe:f { printf(\"int: %o\", 1234) }");
  test("kprobe:f { printf(\"int: %x\", 1234) }");
  test("kprobe:f { printf(\"int: %X\", 1234) }");
}

TEST(semantic_analyser, printf_format_int_with_length)
{
  test("kprobe:f { printf(\"int: %d\", 1234) }");
  test("kprobe:f { printf(\"int: %u\", 1234) }");
  test("kprobe:f { printf(\"int: %o\", 1234) }");
  test("kprobe:f { printf(\"int: %x\", 1234) }");
  test("kprobe:f { printf(\"int: %X\", 1234) }");
  test("kprobe:f { printf(\"int: %p\", 1234) }");

  test("kprobe:f { printf(\"int: %hhd\", 1234) }");
  test("kprobe:f { printf(\"int: %hhu\", 1234) }");
  test("kprobe:f { printf(\"int: %hho\", 1234) }");
  test("kprobe:f { printf(\"int: %hhx\", 1234) }");
  test("kprobe:f { printf(\"int: %hhX\", 1234) }");
  test("kprobe:f { printf(\"int: %hhp\", 1234) }");

  test("kprobe:f { printf(\"int: %hd\", 1234) }");
  test("kprobe:f { printf(\"int: %hu\", 1234) }");
  test("kprobe:f { printf(\"int: %ho\", 1234) }");
  test("kprobe:f { printf(\"int: %hx\", 1234) }");
  test("kprobe:f { printf(\"int: %hX\", 1234) }");
  test("kprobe:f { printf(\"int: %hp\", 1234) }");

  test("kprobe:f { printf(\"int: %ld\", 1234) }");
  test("kprobe:f { printf(\"int: %lu\", 1234) }");
  test("kprobe:f { printf(\"int: %lo\", 1234) }");
  test("kprobe:f { printf(\"int: %lx\", 1234) }");
  test("kprobe:f { printf(\"int: %lX\", 1234) }");
  test("kprobe:f { printf(\"int: %lp\", 1234) }");

  test("kprobe:f { printf(\"int: %lld\", 1234) }");
  test("kprobe:f { printf(\"int: %llu\", 1234) }");
  test("kprobe:f { printf(\"int: %llo\", 1234) }");
  test("kprobe:f { printf(\"int: %llx\", 1234) }");
  test("kprobe:f { printf(\"int: %llX\", 1234) }");
  test("kprobe:f { printf(\"int: %llp\", 1234) }");

  test("kprobe:f { printf(\"int: %jd\", 1234) }");
  test("kprobe:f { printf(\"int: %ju\", 1234) }");
  test("kprobe:f { printf(\"int: %jo\", 1234) }");
  test("kprobe:f { printf(\"int: %jx\", 1234) }");
  test("kprobe:f { printf(\"int: %jX\", 1234) }");
  test("kprobe:f { printf(\"int: %jp\", 1234) }");

  test("kprobe:f { printf(\"int: %zd\", 1234) }");
  test("kprobe:f { printf(\"int: %zu\", 1234) }");
  test("kprobe:f { printf(\"int: %zo\", 1234) }");
  test("kprobe:f { printf(\"int: %zx\", 1234) }");
  test("kprobe:f { printf(\"int: %zX\", 1234) }");
  test("kprobe:f { printf(\"int: %zp\", 1234) }");

  test("kprobe:f { printf(\"int: %td\", 1234) }");
  test("kprobe:f { printf(\"int: %tu\", 1234) }");
  test("kprobe:f { printf(\"int: %to\", 1234) }");
  test("kprobe:f { printf(\"int: %tx\", 1234) }");
  test("kprobe:f { printf(\"int: %tX\", 1234) }");
  test("kprobe:f { printf(\"int: %tp\", 1234) }");
}

TEST(semantic_analyser, printf_format_string)
{
  test("kprobe:f { printf(\"str: %s\", \"mystr\") }");
  test("kprobe:f { printf(\"str: %s\", comm) }");
  test("kprobe:f { printf(\"str: %s\", str(arg0)) }");
  test("kprobe:f { @x = \"hi\"; printf(\"str: %s\", @x) }");
  test("kprobe:f { $x = \"hi\"; printf(\"str: %s\", $x) }");
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
  test("kprobe:f { printf(\"%r\", buf(\"mystr\", 5)) }");
}

TEST(semantic_analyser, printf_bad_format_buf)
{
  test("kprobe:f { printf(\"%r\", \"mystr\") }", 10);
  test("kprobe:f { printf(\"%r\", arg0) }", 10);
}

TEST(semantic_analyser, printf_format_buf_no_ascii)
{
  test("kprobe:f { printf(\"%rx\", buf(\"mystr\", 5)) }");
}

TEST(semantic_analyser, printf_bad_format_buf_no_ascii)
{
  test("kprobe:f { printf(\"%rx\", \"mystr\") }", 10);
  test("kprobe:f { printf(\"%rx\", arg0) }", 10);
}

TEST(semantic_analyser, printf_format_buf_nonescaped_hex)
{
  test("kprobe:f { printf(\"%rh\", buf(\"mystr\", 5)) }");
}

TEST(semantic_analyser, printf_bad_format_buf_nonescaped_hex)
{
  test("kprobe:f { printf(\"%rh\", \"mystr\") }", 10);
  test("kprobe:f { printf(\"%rh\", arg0) }", 10);
}

TEST(semantic_analyser, printf_format_multi)
{
  test("kprobe:f { printf(\"%d %d %s\", 1, 2, \"mystr\") }");
  test("kprobe:f { printf(\"%d %s %d\", 1, 2, \"mystr\") }", 10);
}

TEST(semantic_analyser, join)
{
  test("kprobe:f { join(arg0) }");
  test("kprobe:f { printf(\"%s\", join(arg0)) }", 10);
  test("kprobe:f { join() }", 1);
  test("kprobe:f { $fmt = \"mystring\"; join($fmt) }", 10);
  test("kprobe:f { @x = join(arg0) }", 1);
  test("kprobe:f { $x = join(arg0) }", 1);
}

TEST(semantic_analyser, join_delimiter)
{
  test("kprobe:f { join(arg0, \",\") }");
  test("kprobe:f { printf(\"%s\", join(arg0, \",\")) }", 10);
  test("kprobe:f { $fmt = \"mystring\"; join($fmt, \",\") }", 10);
  test("kprobe:f { @x = join(arg0, \",\") }", 1);
  test("kprobe:f { $x = join(arg0, \",\") }", 1);
  test("kprobe:f { join(arg0, 3) }", 10);
}

TEST(semantic_analyser, kprobe)
{
  test("kprobe:f { 1 }");
  test("kretprobe:f { 1 }");
}

TEST(semantic_analyser, uprobe)
{
  test("uprobe:/bin/sh:f { 1 }");
  test("u:/bin/sh:f { 1 }");
  test("uprobe:/bin/sh:0x10 { 1 }");
  test("u:/bin/sh:0x10 { 1 }");
  test("uprobe:/bin/sh:f+0x10 { 1 }");
  test("u:/bin/sh:f+0x10 { 1 }");
  test("uprobe:sh:f { 1 }");
  test("uprobe:/bin/sh:cpp:f { 1 }");
  test("uprobe:/notexistfile:f { 1 }", 1);
  test("uprobe:notexistfile:f { 1 }", 1);
  test("uprobe:/bin/sh:nolang:f { 1 }", 1);

  test("uretprobe:/bin/sh:f { 1 }");
  test("ur:/bin/sh:f { 1 }");
  test("uretprobe:sh:f { 1 }");
  test("ur:sh:f { 1 }");
  test("uretprobe:/bin/sh:0x10 { 1 }");
  test("ur:/bin/sh:0x10 { 1 }");
  test("uretprobe:/bin/sh:cpp:f { 1 }");
  test("uretprobe:/notexistfile:f { 1 }", 1);
  test("uretprobe:notexistfile:f { 1 }", 1);
  test("uretprobe:/bin/sh:nolang:f { 1 }", 1);
}

TEST(semantic_analyser, usdt)
{
  test("usdt:/bin/sh:probe { 1 }");
  test("usdt:sh:probe { 1 }");
  test("usdt:/bin/sh:namespace:probe { 1 }");
  test("usdt:/notexistfile:probe { 1 }", 1);
  test("usdt:notexistfile:probe { 1 }", 1);
}

TEST(semantic_analyser, begin_end_probes)
{
  test("BEGIN { 1 }");
  test("BEGIN { 1 } BEGIN { 2 }", 10);

  test("END { 1 }");
  test("END { 1 } END { 2 }", 10);
}

TEST(semantic_analyser, tracepoint)
{
  test("tracepoint:category:event { 1 }");
}

TEST(semantic_analyser, rawtracepoint)
{
  test("rawtracepoint:event { 1 }");
  test("rawtracepoint:event { args }", 1);
}

#if defined(ARCH_X86_64) || defined(ARCH_AARCH64)
TEST(semantic_analyser, watchpoint_invalid_modes)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->procmon_ = std::make_unique<MockProcMon>(123);

#ifdef ARCH_X86_64
  test(*bpftrace, "watchpoint:0x1234:8:r { 1 }", 1);
#elif ARCH_AARCH64
  test(*bpftrace, "watchpoint:0x1234:8:r { 1 }");
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

  test(*bpftrace, "watchpoint:0x1234:8:rw { 1 }");
  test(*bpftrace, "watchpoint:0x1234:9:rw { 1 }", 1);
  test(*bpftrace, "watchpoint:0x0:8:rw { 1 }", 1);
}

TEST(semantic_analyser, watchpoint_function)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->procmon_ = std::make_unique<MockProcMon>(123);

  test(*bpftrace, "watchpoint:func1+arg2:8:rw { 1 }");
  test(*bpftrace, "w:func1+arg2:8:rw { 1 }");
  test(*bpftrace, "w:func1.one_two+arg2:8:rw { 1 }");
  test(*bpftrace, "watchpoint:func1+arg99999:8:rw { 1 }", 1);

  bpftrace->procmon_ = std::make_unique<MockProcMon>(0);
  test(*bpftrace, "watchpoint:func1+arg2:8:rw { 1 }", 1);
}

TEST(semantic_analyser, asyncwatchpoint)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->procmon_ = std::make_unique<MockProcMon>(123);

  test(*bpftrace, "asyncwatchpoint:func1+arg2:8:rw { 1 }");
  test(*bpftrace, "aw:func1+arg2:8:rw { 1 }");
  test(*bpftrace, "aw:func1.one_two+arg2:8:rw { 1 }");
  test(*bpftrace, "asyncwatchpoint:func1+arg99999:8:rw { 1 }", 1);

  // asyncwatchpoint's may not use absolute addresses
  test(*bpftrace, "asyncwatchpoint:0x1234:8:rw { 1 }", 1);

  bpftrace->procmon_ = std::make_unique<MockProcMon>(0);
  test(*bpftrace, "watchpoint:func1+arg2:8:rw { 1 }", 1);
}
#endif // if defined(ARCH_X86_64) || defined(ARCH_AARCH64)

TEST(semantic_analyser, args_builtin_wrong_use)
{
  test("BEGIN { args.foo }", 1);
  test("END { args.foo }", 1);
  test("kprobe:f { args.foo }", 1);
  test("kretprobe:f { args.foo }", 1);
  test("uretprobe:/bin/sh/:f { args.foo }", 1);
  test("profile:ms:1 { args.foo }", 1);
  test("usdt:sh:probe { args.foo }", 1);
  test("profile:ms:100 { args.foo }", 1);
  test("hardware:cache-references:1000000 { args.foo }", 1);
  test("software:faults:1000 { args.foo }", 1);
  test("interval:s:1 { args.foo }", 1);
}

TEST(semantic_analyser, profile)
{
  test("profile:hz:997 { 1 }");
  test("profile:s:10 { 1 }");
  test("profile:ms:100 { 1 }");
  test("profile:us:100 { 1 }");
  test("profile:unit:100 { 1 }", 1);
}

TEST(semantic_analyser, interval)
{
  test("interval:hz:997 { 1 }");
  test("interval:s:10 { 1 }");
  test("interval:ms:100 { 1 }");
  test("interval:us:100 { 1 }");
  test("interval:unit:100 { 1 }", 1);
}

TEST(semantic_analyser, variable_cast_types)
{
  std::string structs =
      "struct type1 { int field; } struct type2 { int field; }";
  test(structs +
       "kprobe:f { $x = (struct type1*)cpu; $x = (struct type1*)cpu; }");
  test(structs +
           "kprobe:f { $x = (struct type1*)cpu; $x = (struct type2*)cpu; }",
       1);
}

TEST(semantic_analyser, map_cast_types)
{
  std::string structs =
      "struct type1 { int field; } struct type2 { int field; }";
  test(structs +
       "kprobe:f { @x = *(struct type1*)cpu; @x = *(struct type1*)cpu; }");
  test(structs +
           "kprobe:f { @x = *(struct type1*)cpu; @x = *(struct type2*)cpu; }",
       1);
}

TEST(semantic_analyser, map_aggregations_implicit_cast)
{
  test("kprobe:f { @ = count(); if (@ > 0) { print((1)); } }");
  test("kprobe:f { @ = sum(5); if (@ > 0) { print((1)); } }");
  test("kprobe:f { @ = min(5); if (@ > 0) { print((1)); } }");
  test("kprobe:f { @ = max(5); if (@ > 0) { print((1)); } }");
  test("kprobe:f { @ = avg(5); if (@ > 0) { print((1)); } }");

  test_error("kprobe:f { @ = hist(5); if (@ > 0) { print((1)); } }", R"(
stdin:1:28-34: ERROR: Type mismatch for '>': comparing 'hist' with 'int64'
kprobe:f { @ = hist(5); if (@ > 0) { print((1)); } }
                           ~~~~~~
)");
  test_error("kprobe:f { @ = count(); @ += 5 }", R"(
stdin:1:25-26: ERROR: Type mismatch for @: trying to assign value of type 'int64' when map already contains a value of type 'count'
kprobe:f { @ = count(); @ += 5 }
                        ~
)");
}

TEST(semantic_analyser, map_aggregations_explicit_cast)
{
  test("kprobe:f { @ = count(); print((1, (uint16)@)); }");
  test("kprobe:f { @ = sum(5); print((1, (uint16)@)); }");
  test("kprobe:f { @ = min(5); print((1, (uint16)@)); }");
  test("kprobe:f { @ = max(5); print((1, (uint16)@)); }");
  test("kprobe:f { @ = avg(5); print((1, (uint16)@)); }");

  test_error("kprobe:f { @ = hist(5); print((1, (uint16)@)); }", R"(
stdin:1:35-43: ERROR: Cannot cast from "hist" to "unsigned int16"
kprobe:f { @ = hist(5); print((1, (uint16)@)); }
                                  ~~~~~~~~
)");
}

TEST(semantic_analyser, variable_casts_are_local)
{
  std::string structs =
      "struct type1 { int field; } struct type2 { int field; }";
  test(structs + "kprobe:f { $x = *(struct type1 *)cpu } "
                 "kprobe:g { $x = *(struct type2 *)cpu; }");
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
  test(structs + "kprobe:f { $x = *(struct type1*)cpu; $x.field }");
  test(structs + "kprobe:f { @x = *(struct type1*)cpu; @x.field }");
  test("struct task_struct {int x;} kprobe:f { curtask->x }");
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

  test(structs + "kprobe:f { (*((struct type1*)0)).field == 123 }");
  test(structs + "kprobe:f { (*((struct type1*)0)).field == \"abc\" }", 10);

  test(structs + "kprobe:f { (*((struct type1*)0)).mystr == \"abc\" }");
  test(structs + "kprobe:f { (*((struct type1*)0)).mystr == 123 }", 10);

  test(structs + "kprobe:f { (*((struct type1*)0)).field == (*((struct "
                 "type2*)0)).field }");
  test(structs + "kprobe:f { (*((struct type1*)0)).mystr == (*((struct "
                 "type2*)0)).field }",
       10);
}

TEST(semantic_analyser, field_access_pointer)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { ((struct type1*)0)->field }");
  test(structs + "kprobe:f { ((struct type1*)0).field }", 1);
  test(structs + "kprobe:f { *((struct type1*)0) }");
}

TEST(semantic_analyser, field_access_sub_struct)
{
  std::string structs =
      "struct type2 { int field; } "
      "struct type1 { struct type2 *type2ptr; struct type2 type2; }";

  test(structs + "kprobe:f { (*(struct type1*)0).type2ptr->field }");
  test(structs + "kprobe:f { (*(struct type1*)0).type2.field }");
  test(structs +
       "kprobe:f { $x = *(struct type2*)0; $x = (*(struct type1*)0).type2 }");
  test(structs + "kprobe:f { $x = (struct type2*)0; $x = (*(struct "
                 "type1*)0).type2ptr }");
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
    test(driver, structs + "kprobe:f { $x = (*(struct type1*)0).x }");
    auto stmts = driver.ctx.root->probes.at(0)->stmts;
    auto var_assignment1 = static_cast<ast::AssignVarStatement *>(stmts.at(0));
    EXPECT_FALSE(var_assignment1->var->type.is_internal);
  }

  {
    test(driver,
         structs + "kprobe:f { @type1 = *(struct type1*)0; $x = @type1.x }");
    auto stmts = driver.ctx.root->probes.at(0)->stmts;
    auto map_assignment = static_cast<ast::AssignMapStatement *>(stmts.at(0));
    auto var_assignment2 = static_cast<ast::AssignVarStatement *>(stmts.at(1));
    EXPECT_TRUE(map_assignment->map->type.is_internal);
    EXPECT_TRUE(var_assignment2->var->type.is_internal);
  }
}

TEST(semantic_analyser, struct_as_map_key)
{
  test("struct A { int x; } struct B { char x; } "
       "kprobe:f { @x[*((struct A *)arg0)] = 0; }");

  test("struct A { int x; } struct B { char x; } "
       "kprobe:f { @x[*((struct A *)arg0), *((struct B *)arg1)] = 0; }");

  // Mismatched key types
  test_error(R"(
    struct A { int x; } struct B { char x; }
    BEGIN {
        @x[*((struct A *)0)] = 0;
        @x[*((struct B *)0)] = 1;
    })",
             R"(
stdin:4:9-30: ERROR: Argument mismatch for @x: trying to access with arguments: [struct B] when map expects arguments: [struct A]
        @x[*((struct B *)0)] = 1;
        ~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST(semantic_analyser, probe_short_name)
{
  test("t:a:b { args }");
  test("k:f { pid }");
  test("kr:f { pid }");
  test("u:sh:f { 1 }");
  test("ur:sh:f { 1 }");
  test("p:hz:997 { 1 }");
  test("h:cache-references:1000000 { 1 }");
  test("s:faults:1000 { 1 }");
  test("i:s:1 { 1 }");
}

TEST(semantic_analyser, positional_parameters)
{
  BPFtrace bpftrace;
  bpftrace.add_param("123");
  bpftrace.add_param("hello");
  bpftrace.add_param("0x123");

  test(bpftrace, "kprobe:f { printf(\"%d\", $1); }");
  test(bpftrace, "kprobe:f { printf(\"%s\", str($1)); }");

  test(bpftrace, "kprobe:f { printf(\"%s\", str($2)); }");
  test(bpftrace, "kprobe:f { printf(\"%s\", str($2 + 1)); }");
  test(bpftrace, "kprobe:f { printf(\"%d\", $2); }", 10);

  test(bpftrace, "kprobe:f { printf(\"%d\", $3); }");

  // Pointer arithmetic in str() for parameters
  // Only str($1 + CONST) where CONST <= strlen($1) should be allowed
  test(bpftrace, "kprobe:f { printf(\"%s\", str($1 + 1)); }");
  test(bpftrace, "kprobe:f { printf(\"%s\", str(1 + $1)); }");
  test(bpftrace, "kprobe:f { printf(\"%s\", str($1 + 4)); }", 10);
  test(bpftrace, "kprobe:f { printf(\"%s\", str($1 * 2)); }", 10);
  test(bpftrace, "kprobe:f { printf(\"%s\", str($1 + 1 + 1)); }", 1);

  // Parameters are not required to exist to be used:
  test(bpftrace, "kprobe:f { printf(\"%s\", str($4)); }");
  test(bpftrace, "kprobe:f { printf(\"%d\", $4); }");

  test(bpftrace, "kprobe:f { printf(\"%d\", $#); }");
  test(bpftrace, "kprobe:f { printf(\"%s\", str($#)); }", 1);
  test(bpftrace, "kprobe:f { printf(\"%s\", str($#+1)); }", 1);

  // Parameters can be used as string literals
  test(bpftrace, "kprobe:f { printf(\"%d\", cgroupid(str($2))); }");

  Driver driver(bpftrace);
  test(driver, "k:f { $1 }");
  auto stmt = static_cast<ast::ExprStatement *>(
      driver.ctx.root->probes.at(0)->stmts.at(0));
  auto pp = static_cast<ast::PositionalParameter *>(stmt->expr);
  EXPECT_EQ(CreateUInt64(), pp->type);
  EXPECT_TRUE(pp->is_literal);

  bpftrace.add_param("0999");
  test(bpftrace, "kprobe:f { printf(\"%d\", $4); }", 10);
}

TEST(semantic_analyser, macros)
{
  test("#define A 1\nkprobe:f { printf(\"%d\", A); }");
  test("#define A A\nkprobe:f { printf(\"%d\", A); }", 1);
  test("enum { A = 1 }\n#define A A\nkprobe:f { printf(\"%d\", A); }");
}

TEST(semantic_analyser, enums)
{
  test("enum { a = 1, b } kprobe:f { printf(\"%d\", a); }");
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
       "$s->y == \"abc\"}");
  test("struct MyStruct {char y[4]; } kprobe:f { $s = (struct MyStruct*)arg0; "
       "\"abc\" != $s->y}");
  test("struct MyStruct {char y[4]; } kprobe:f { $s = (struct MyStruct*)arg0; "
       "\"abc\" == \"abc\"}");

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
  test("BEGIN { @[0] = \"abc\"; @[1] = \"def\" } kretprobe:f { "
       "printf(\"%s\\n\", @[retval])}");
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
  test(driver, prog);

  auto s = static_cast<ast::AssignVarStatement *>(
      driver.ctx.root->probes.at(0)->stmts.at(1));
  auto us = static_cast<ast::AssignVarStatement *>(
      driver.ctx.root->probes.at(0)->stmts.at(2));
  auto l = static_cast<ast::AssignVarStatement *>(
      driver.ctx.root->probes.at(0)->stmts.at(3));
  auto ul = static_cast<ast::AssignVarStatement *>(
      driver.ctx.root->probes.at(0)->stmts.at(4));
  EXPECT_EQ(CreateInt32(), s->var->type);
  EXPECT_EQ(CreateUInt32(), us->var->type);
  EXPECT_EQ(CreateInt64(), l->var->type);
  EXPECT_EQ(CreateUInt64(), ul->var->type);
}

TEST(semantic_analyser, binop_sign)
{
  // Make sure types are correct
  std::string prog_pre = "struct t { long l; unsigned long ul }; "
                         "kprobe:f { "
                         "  $t = ((struct t *)0xFF); ";

  std::string operators[] = { "==", "!=", "<", "<=", ">",
                              ">=", "+",  "-", "/",  "*" };
  for (std::string op : operators) {
    BPFtrace bpftrace;
    Driver driver(bpftrace);
    std::string prog = prog_pre + "$varA = $t->l " + op +
                       " $t->l; "
                       "$varB = $t->ul " +
                       op +
                       " $t->l; "
                       "$varC = $t->ul " +
                       op +
                       " $t->ul;"
                       "}";

    test(driver, prog);
    auto varA = static_cast<ast::AssignVarStatement *>(
        driver.ctx.root->probes.at(0)->stmts.at(1));
    EXPECT_EQ(CreateInt64(), varA->var->type);
    auto varB = static_cast<ast::AssignVarStatement *>(
        driver.ctx.root->probes.at(0)->stmts.at(2));
    EXPECT_EQ(CreateUInt64(), varB->var->type);
    auto varC = static_cast<ast::AssignVarStatement *>(
        driver.ctx.root->probes.at(0)->stmts.at(3));
    EXPECT_EQ(CreateUInt64(), varC->var->type);
  }
}

TEST(semantic_analyser, int_cast_types)
{
  test("kretprobe:f { @ = (int8)retval }");
  test("kretprobe:f { @ = (int16)retval }");
  test("kretprobe:f { @ = (int32)retval }");
  test("kretprobe:f { @ = (int64)retval }");
  test("kretprobe:f { @ = (uint8)retval }");
  test("kretprobe:f { @ = (uint16)retval }");
  test("kretprobe:f { @ = (uint32)retval }");
  test("kretprobe:f { @ = (uint64)retval }");
}

TEST(semantic_analyser, int_cast_usage)
{
  test("kretprobe:f /(int32) retval < 0 / {}");
  test("kprobe:f /(int32) arg0 < 0 / {}");
  test("kprobe:f { @=sum((int32)arg0) }");
  test("kprobe:f { @=avg((int32)arg0) }");
  test("kprobe:f { @=avg((int32)arg0) }");

  test("kprobe:f { @=avg((int32)\"abc\") }", 1);
}

TEST(semantic_analyser, intptr_cast_types)
{
  test("kretprobe:f { @ = *(int8*)retval }");
  test("kretprobe:f { @ = *(int16*)retval }");
  test("kretprobe:f { @ = *(int32*)retval }");
  test("kretprobe:f { @ = *(int64*)retval }");
  test("kretprobe:f { @ = *(uint8*)retval }");
  test("kretprobe:f { @ = *(uint16*)retval }");
  test("kretprobe:f { @ = *(uint32*)retval }");
  test("kretprobe:f { @ = *(uint64*)retval }");
}

TEST(semantic_analyser, intptr_cast_usage)
{
  test("kretprobe:f /(*(int32*) retval) < 0 / {}");
  test("kprobe:f /(*(int32*) arg0) < 0 / {}");
  test("kprobe:f { @=sum(*(int32*)arg0) }");
  test("kprobe:f { @=avg(*(int32*)arg0) }");
  test("kprobe:f { @=avg(*(int32*)arg0) }");

  // This is OK (@ = 0x636261)
  test("kprobe:f { @=avg(*(int32*)\"abc\") }");
  test("kprobe:f { @=avg(*(int32*)123) }");
}

TEST(semantic_analyser, intarray_cast_types)
{
  test("kprobe:f { @ = (int8[8])1 }");
  test("kprobe:f { @ = (int16[4])1 }");
  test("kprobe:f { @ = (int32[2])1 }");
  test("kprobe:f { @ = (int64[1])1 }");
  test("kprobe:f { @ = (int8[4])(int32)1 }");
  test("kprobe:f { @ = (int8[2])(int16)1 }");
  test("kprobe:f { @ = (int8[1])(int8)1 }");
  test("kprobe:f { @ = (int8[])1 }");
  test("kprobe:f { @ = (uint8[8])1 }");
  test("kretprobe:f { @ = (int8[8])retval }");

  test("kprobe:f { @ = (int8[4])1 }", 1);
  test("kprobe:f { @ = (bool[64])1 }", 1);
  test("kprobe:f { @ = (int32[])(int16)1 }", 1);
  test("kprobe:f { @ = (int8[6])\"hello\" }", 1);
  test("struct Foo { int x; } kprobe:f { @ = (struct Foo [2])1 }", 1);
}

TEST(semantic_analyser, intarray_cast_usage)
{
  test("kprobe:f { $a=(int8[8])1; }");
  test("kprobe:f { @=(int8[8])1; }");
  test("kprobe:f { @[(int8[8])1] = 0; }");
  test("kprobe:f { if (((int8[8])1)[0] == 1) {} }");
}

TEST(semantic_analyser, intarray_to_int_cast)
{
  test("#include <stdint.h>\n"
       "struct Foo { uint8_t x[8]; } "
       "kprobe:f { @ = (int64)((struct Foo *)arg0)->x; }");
  test("#include <stdint.h>\n"
       "struct Foo { uint32_t x[2]; } "
       "kprobe:f { @ = (int64)((struct Foo *)arg0)->x; }");
  test("#include <stdint.h>\n"
       "struct Foo { uint8_t x[4]; } "
       "kprobe:f { @ = (int32)((struct Foo *)arg0)->x; }");

  test("#include <stdint.h>\n"
       "struct Foo { uint8_t x[8]; } "
       "kprobe:f { @ = (int32)((struct Foo *)arg0)->x; }",
       1);
  test("#include <stdint.h>\n"
       "struct Foo { uint8_t x[8]; } "
       "kprobe:f { @ = (int32 *)((struct Foo *)arg0)->x; }",
       1);
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

  // Positional parameter
  BPFtrace bpftrace;
  bpftrace.add_param("1");
  bpftrace.add_param("hello");
  test(bpftrace, "k:f { signal($1) }", false);
  test(bpftrace, "k:f { signal($2) }", 1, false);
}

TEST(semantic_analyser, strncmp)
{
  // Test strncmp builtin
  test("i:s:1 { $a = \"bar\"; strncmp(\"foo\", $a, 1) }");
  test("i:s:1 { strncmp(\"foo\", \"bar\", 1) }");
  test("i:s:1 { strncmp(1) }", 1);
  test("i:s:1 { strncmp(1,1,1) }", 10);
  test("i:s:1 { strncmp(\"a\",1,1) }", 10);
  test("i:s:1 { strncmp(\"a\",\"a\",-1) }", 1);
  test("i:s:1 { strncmp(\"a\",\"a\",\"foo\") }", 1);
}

TEST(semantic_analyser, strncmp_posparam)
{
  BPFtrace bpftrace;
  bpftrace.add_param("1");
  bpftrace.add_param("hello");
  test(bpftrace, "i:s:1 { strncmp(\"foo\", \"bar\", $1) }");
  test(bpftrace, "i:s:1 { strncmp(\"foo\", \"bar\", $2) }", 1);
}

TEST(semantic_analyser, strconrtains)
{
  // Test strcontains builtin
  test("i:s:1 { $a = \"bar\"; strcontains(\"foo\", $a) }");
  test("i:s:1 { strcontains(\"foo\", \"bar\") }");
  test("i:s:1 { strcontains(1) }", 1);
  test("i:s:1 { strcontains(1,1) }", 10);
  test("i:s:1 { strcontains(\"a\",1) }", 10);
}

TEST(semantic_analyser, strcontains_posparam)
{
  BPFtrace bpftrace;
  bpftrace.add_param("hello");
  test(bpftrace, "i:s:1 { strcontains(\"foo\", str($1)) }");
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
  test("i:s:1 { unwatch(12345) }");
  test("i:s:1 { unwatch(0x1234) }");
  test("i:s:1 { $x = 1; unwatch($x); }");
  test("i:s:1 { @x = 1; @x++; unwatch(@x); }");
  test("k:f { unwatch(arg0); }");
  test("k:f { unwatch((int64)arg0); }");
  test("k:f { unwatch(*(int64*)arg0); }");

  test("i:s:1 { unwatch(\"asdf\") }", 10);
  test("i:s:1 { @x[\"hi\"] = \"world\"; unwatch(@x[\"hi\"]) }", 10);
  test("i:s:1 { printf(\"%d\", unwatch(2)) }", 10);
}

TEST(semantic_analyser, struct_member_keywords)
{
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
    test("struct S{ int " + kw + ";}; k:f { ((struct S*)arg0)->" + kw + "}");
    test("struct S{ int " + kw + ";}; k:f { (*(struct S*)arg0)." + kw + "}");
  }
}

TEST(semantic_analyser, jumps)
{
  test("i:s:1 { return; }");
  // must be used in loops
  test("i:s:1 { break; }", 1);
  test("i:s:1 { continue; }", 1);
}

TEST(semantic_analyser, while_loop)
{
  test("i:s:1 { $a = 1; while ($a < 10) { $a++ }}");
  test("i:s:1 { $a = 1; while (1) { if($a > 50) { break } $a++ }}");
  test("i:s:1 { $a = 1; while ($a < 10) { $a++ }}");
  test("i:s:1 { $a = 1; while (1) { if($a > 50) { break } $a++ }}");
  test("i:s:1 { $a = 1; while (1) { if($a > 50) { return } $a++ }}");
  test(R"PROG(
i:s:1 {
  $a = 1;
  while ($a < 10) {
    $a++; $j=0;
    while ($j < 10) {
      $j++;
    }
  }
})PROG");

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
  test(*bpftrace, "t:sched:sched_one { args.common_field }");
  test(*bpftrace, "t:sched:sched_two { args.common_field }");
  test(*bpftrace,
       "t:sched:sched_one,"
       "t:sched:sched_two { args.common_field }");
  test(*bpftrace, "t:sched:sched_* { args.common_field }");
  test(*bpftrace, "t:sched:sched_one { args.not_a_field }", 1);
  // Backwards compatibility
  test(*bpftrace, "t:sched:sched_one { args->common_field }");
}

TEST(semantic_analyser, type_ctx)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  std::string structs = "struct c {char c} struct x { long a; short b[4]; "
                        "struct c c; struct c *d;}";
  test(driver,
       structs + "kprobe:f { $x = (struct x*)ctx; $a = $x->a; $b = $x->b[0]; "
                 "$c = $x->c.c; $d = $x->d->c;}");
  auto &stmts = driver.ctx.root->probes.at(0)->stmts;

  // $x = (struct x*)ctx;
  auto assignment = static_cast<ast::AssignVarStatement *>(stmts.at(0));
  EXPECT_TRUE(assignment->var->type.IsPtrTy());

  // $a = $x->a;
  assignment = static_cast<ast::AssignVarStatement *>(stmts.at(1));
  EXPECT_EQ(CreateInt64(), assignment->var->type);
  auto fieldaccess = static_cast<ast::FieldAccess *>(assignment->expr);
  EXPECT_EQ(CreateInt64(), fieldaccess->type);
  auto unop = static_cast<ast::Unop *>(fieldaccess->expr);
  EXPECT_TRUE(unop->type.IsCtxAccess());
  auto var = static_cast<ast::Variable *>(unop->expr);
  EXPECT_TRUE(var->type.IsPtrTy());

  // $b = $x->b[0];
  assignment = static_cast<ast::AssignVarStatement *>(stmts.at(2));
  EXPECT_EQ(CreateInt16(), assignment->var->type);
  auto arrayaccess = static_cast<ast::ArrayAccess *>(assignment->expr);
  EXPECT_EQ(CreateInt16(), arrayaccess->type);
  fieldaccess = static_cast<ast::FieldAccess *>(arrayaccess->expr);
  EXPECT_TRUE(fieldaccess->type.IsCtxAccess());
  unop = static_cast<ast::Unop *>(fieldaccess->expr);
  EXPECT_TRUE(unop->type.IsCtxAccess());
  var = static_cast<ast::Variable *>(unop->expr);
  EXPECT_TRUE(var->type.IsPtrTy());

#ifdef ARCH_X86_64
  auto chartype = CreateInt8();
#else
  auto chartype = CreateUInt8();
#endif

  // $c = $x->c.c;
  assignment = static_cast<ast::AssignVarStatement *>(stmts.at(3));
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
  assignment = static_cast<ast::AssignVarStatement *>(stmts.at(4));
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

  test(driver, "k:f, kr:f { @ = (uint64)ctx; }");
  test(driver, "k:f, i:s:1 { @ = (uint64)ctx; }", 1);
  test(driver, "t:sched:sched_one { @ = (uint64)ctx; }", 1);
}

TEST(semantic_analyser, double_pointer_basic)
{
  test(R"_(BEGIN { $pp = (int8 **)0; $p = *$pp; $val = *$p; })_");
  test(R"_(BEGIN { $pp = (int8 **)0; $val = **$pp; })_");

  const std::string structs = "struct Foo { int x; }";
  test(structs + R"_(BEGIN { $pp = (struct Foo **)0; $val = (*$pp)->x; })_");
}

TEST(semantic_analyser, double_pointer_int)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  test(driver, "kprobe:f { $pp = (int8 **)1; $p = *$pp; $val = *$p; }");
  auto &stmts = driver.ctx.root->probes.at(0)->stmts;

  // $pp = (int8 **)1;
  auto assignment = static_cast<ast::AssignVarStatement *>(stmts.at(0));
  ASSERT_TRUE(assignment->var->type.IsPtrTy());
  ASSERT_TRUE(assignment->var->type.GetPointeeTy()->IsPtrTy());
  ASSERT_TRUE(assignment->var->type.GetPointeeTy()->GetPointeeTy()->IsIntTy());
  EXPECT_EQ(
      assignment->var->type.GetPointeeTy()->GetPointeeTy()->GetIntBitWidth(),
      8ULL);

  // $p = *$pp;
  assignment = static_cast<ast::AssignVarStatement *>(stmts.at(1));
  ASSERT_TRUE(assignment->var->type.IsPtrTy());
  ASSERT_TRUE(assignment->var->type.GetPointeeTy()->IsIntTy());
  EXPECT_EQ(assignment->var->type.GetPointeeTy()->GetIntBitWidth(), 8ULL);

  // $val = *$p;
  assignment = static_cast<ast::AssignVarStatement *>(stmts.at(2));
  ASSERT_TRUE(assignment->var->type.IsIntTy());
  EXPECT_EQ(assignment->var->type.GetIntBitWidth(), 8ULL);
}

TEST(semantic_analyser, double_pointer_struct)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  test(driver,
       "struct Foo { char x; long y; }"
       "kprobe:f { $pp = (struct Foo **)1; $p = *$pp; $val = $p->x; }");
  auto &stmts = driver.ctx.root->probes.at(0)->stmts;

  // $pp = (struct Foo **)1;
  auto assignment = static_cast<ast::AssignVarStatement *>(stmts.at(0));
  ASSERT_TRUE(assignment->var->type.IsPtrTy());
  ASSERT_TRUE(assignment->var->type.GetPointeeTy()->IsPtrTy());
  ASSERT_TRUE(
      assignment->var->type.GetPointeeTy()->GetPointeeTy()->IsRecordTy());
  EXPECT_EQ(assignment->var->type.GetPointeeTy()->GetPointeeTy()->GetName(),
            "struct Foo");

  // $p = *$pp;
  assignment = static_cast<ast::AssignVarStatement *>(stmts.at(1));
  ASSERT_TRUE(assignment->var->type.IsPtrTy());
  ASSERT_TRUE(assignment->var->type.GetPointeeTy()->IsRecordTy());
  EXPECT_EQ(assignment->var->type.GetPointeeTy()->GetName(), "struct Foo");

  // $val = $p->x;
  assignment = static_cast<ast::AssignVarStatement *>(stmts.at(2));
  ASSERT_TRUE(assignment->var->type.IsIntTy());
  EXPECT_EQ(assignment->var->type.GetIntBitWidth(), 8ULL);
}

TEST(semantic_analyser, pointer_arith)
{
  test(R"_(BEGIN { $t = (int32*) 32; $t = $t + 1 })_");
  test(R"_(BEGIN { $t = (int32*) 32; $t +=1 })_");
  test(R"_(BEGIN { $t = (int32*) 32; $t++ })_");
  test(R"_(BEGIN { $t = (int32*) 32; ++$t })_");
  test(R"_(BEGIN { $t = (int32*) 32; $t = $t - 1 })_");
  test(R"_(BEGIN { $t = (int32*) 32; $t -=1 })_");
  test(R"_(BEGIN { $t = (int32*) 32; $t-- })_");
  test(R"_(BEGIN { $t = (int32*) 32; --$t })_");

  // pointer compare
  test(R"_(BEGIN { $t = (int32*) 32; @ = ($t > $t); })_");
  test(R"_(BEGIN { $t = (int32*) 32; @ = ($t < $t); })_");
  test(R"_(BEGIN { $t = (int32*) 32; @ = ($t >= $t); })_");
  test(R"_(BEGIN { $t = (int32*) 32; @ = ($t <= $t); })_");
  test(R"_(BEGIN { $t = (int32*) 32; @ = ($t == $t); })_");

  // map
  test(R"_(BEGIN { @ = (int32*) 32; @ = @ + 1 })_");
  test(R"_(BEGIN { @ = (int32*) 32; @ +=1 })_");
  test(R"_(BEGIN { @ = (int32*) 32; @++ })_");
  test(R"_(BEGIN { @ = (int32*) 32; ++@ })_");
  test(R"_(BEGIN { @ = (int32*) 32; @ = @ - 1 })_");
  test(R"_(BEGIN { @ = (int32*) 32; @ -=1 })_");
  test(R"_(BEGIN { @ = (int32*) 32; @-- })_");
  test(R"_(BEGIN { @ = (int32*) 32; --@ })_");

  // associativity
  test(R"_(BEGIN { $t = (int32*) 32; $t = $t + 1 })_");
  test(R"_(BEGIN { $t = (int32*) 32; $t = 1 + $t })_");
  test(R"_(BEGIN { $t = (int32*) 32; $t = $t - 1 })_");
  test(R"_(BEGIN { $t = (int32*) 32; $t = 1 - $t })_", 1);

  // invalid ops
  test(R"_(BEGIN { $t = (int32*) 32; $t *= 5 })_", 1);
  test(R"_(BEGIN { $t = (int32*) 32; $t /= 5 })_", 1);
  test(R"_(BEGIN { $t = (int32*) 32; $t %= 5 })_", 1);
  test(R"_(BEGIN { $t = (int32*) 32; $t <<= 5 })_", 1);
  test(R"_(BEGIN { $t = (int32*) 32; $t >>= 5 })_", 1);

  test(R"_(BEGIN { $t = (int32*) 32; $t -= $t })_", 1);
  test(R"_(BEGIN { $t = (int32*) 32; $t += $t })_", 1);

  // invalid types
  test(R"_(BEGIN { $t = (int32*) 32; $t += "abc" })_", 1);
  test(R"_(BEGIN { $t = (int32*) 32; $t += comm })_", 1);
  test(
      R"_(struct A {}; BEGIN { $t = (int32*) 32; $s = *(struct A*) 0; $t += $s })_",
      1);
}

TEST(semantic_analyser, pointer_compare)
{
  test(R"_(BEGIN { $t = (int32*) 32; $c = $t < 1 })_");
  test(R"_(BEGIN { $t = (int32*) 32; $c = $t > 1 })_");
  test(R"_(BEGIN { $t = (int32*) 32; $c = $t <= 1 })_");
  test(R"_(BEGIN { $t = (int32*) 32; $c = $t >= 1 })_");
  test(R"_(BEGIN { $t = (int32*) 32; $c = $t != 1 })_");

  test(R"_(BEGIN { $t = (int32*) 32; $c = $t < $t })_");
  test(R"_(BEGIN { $t = (int32*) 32; $c = $t > $t })_");
  test(R"_(BEGIN { $t = (int32*) 32; $c = $t <= $t })_");
  test(R"_(BEGIN { $t = (int32*) 32; $c = $t >= $t })_");
  test(R"_(BEGIN { $t = (int32*) 32; $c = $t != $t })_");

  // pointer compare diff types
  test(R"_(BEGIN { $t = (int32*) 32; $y = (int64*) 1024; @ = ($t > $y); })_");
  test(R"_(BEGIN { $t = (int32*) 32; $y = (int64*) 1024; @ = ($t < $y); })_");
  test(R"_(BEGIN { $t = (int32*) 32; $y = (int64*) 1024; @ = ($t >= $y); })_");
  test(R"_(BEGIN { $t = (int32*) 32; $y = (int64*) 1024; @ = ($t <= $y); })_");
  test(R"_(BEGIN { $t = (int32*) 32; $y = (int64*) 1024; @ = ($t == $y); })_");

  test_for_warning("k:f { $a = (int8*) 1; $b = (int16*) 2; $c = ($a == $b) }",
                   "comparison of distinct pointer types ('int8, 'int16')");
}

// Basic functionality test
TEST(semantic_analyser, tuple)
{
  test(R"_(BEGIN { $t = (1)})_");
  test(R"_(BEGIN { $t = (1, 2); $v = $t;})_");
  test(R"_(BEGIN { $t = (1, 2, "string")})_");
  test(R"_(BEGIN { $t = (1, 2, "string"); $t = (3, 4, "other"); })_");
  test(R"_(BEGIN { $t = (1, kstack()) })_");
  test(R"_(BEGIN { $t = (1, (2,3)) })_");

  test(R"_(BEGIN { @t = (1)})_");
  test(R"_(BEGIN { @t = (1, 2); @v = @t;})_");
  test(R"_(BEGIN { @t = (1, 2, "string")})_");
  test(R"_(BEGIN { @t = (1, 2, "string"); @t = (3, 4, "other"); })_");
  test(R"_(BEGIN { @t = (1, kstack()) })_");
  test(R"_(BEGIN { @t = (1, (2,3)) })_");

  test(R"_(struct task_struct { int x; } BEGIN { $t = (1, curtask); })_");
  test(R"_(struct task_struct { int x[4]; } BEGIN { $t = (1, curtask->x); })_");

  test(R"_(BEGIN { $t = (1, 2); $t = (4, "other"); })_", 10);
  test(R"_(BEGIN { $t = (1, 2); $t = 5; })_", 1);
  test(R"_(BEGIN { $t = (1, count()) })_", 1);
  test(R"_(BEGIN { $t = ((int32)1, (int64)2); $t = ((int64)1, (int32)2); })_",
       10);

  test(R"_(BEGIN { @t = (1, 2); @t = (4, "other"); })_", 10);
  test(R"_(BEGIN { @t = (1, 2); @t = 5; })_", 1);
  test(R"_(BEGIN { @t = (1, count()) })_", 1);
}

TEST(semantic_analyser, tuple_indexing)
{
  test(R"_(BEGIN { (1,2).0 })_");
  test(R"_(BEGIN { (1,2).1 })_");
  test(R"_(BEGIN { (1,2,3).2 })_");
  test(R"_(BEGIN { $t = (1,2,3).0 })_");
  test(R"_(BEGIN { $t = (1,2,3); $v = $t.0; })_");

  test(R"_(BEGIN { (1,2,3).3 })_", 10);
  test(R"_(BEGIN { (1,2,3).9999999999999 })_", 10);
}

// More in depth inspection of AST
TEST(semantic_analyser, tuple_assign_var)
{
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  SizedType ty = CreateTuple(
      bpftrace.structs.AddTuple({ CreateInt64(), CreateString(6) }));
  test(bpftrace,
       true,
       driver,
       R"_(BEGIN { $t = (1, "str"); $t = (4, "other"); })_",
       0);

  auto &stmts = driver.ctx.root->probes.at(0)->stmts;

  // $t = (1, "str");
  auto assignment = static_cast<ast::AssignVarStatement *>(stmts.at(0));
  EXPECT_EQ(ty, assignment->var->type);

  // $t = (4, "other");
  assignment = static_cast<ast::AssignVarStatement *>(stmts.at(1));
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

  auto &stmts = driver.ctx.root->probes.at(0)->stmts;

  // $t = (1, 3, 3, 7);
  auto assignment = static_cast<ast::AssignMapStatement *>(stmts.at(0));
  ty = CreateTuple(bpftrace.structs.AddTuple(
      { CreateInt64(), CreateInt64(), CreateInt64(), CreateInt64() }));
  EXPECT_EQ(ty, assignment->map->type);

  // $t = (0, 0, 0, 0);
  assignment = static_cast<ast::AssignMapStatement *>(stmts.at(1));
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

  auto &stmts = driver.ctx.root->probes.at(0)->stmts;

  // $t = (1, "str");
  auto assignment = static_cast<ast::AssignVarStatement *>(stmts.at(0));
  EXPECT_EQ(ty, assignment->var->type);
}

TEST(semantic_analyser, tuple_types_unique)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, R"_(BEGIN { $t = (1, "hello"); $t = (4, "other"); })_");

  EXPECT_EQ(bpftrace->structs.GetTuplesCnt(), 1ul);
}

TEST(semantic_analyser, multi_pass_type_inference_zero_size_int)
{
  auto bpftrace = get_mock_bpftrace();
  // The first pass on processing the Unop does not have enough information
  // to figure out size of `@i` yet. The analyzer figures out the size
  // after seeing the `@i++`. On the second pass the correct size is
  // determined.
  test(*bpftrace, "BEGIN { if (!@i) { @i++; } }");
}

TEST(semantic_analyser, call_kptr_uptr)
{
  test("k:f { @  = kptr((int8*) arg0); }");
  test("k:f { $a = kptr((int8*) arg0); }");

  test("k:f { @ = kptr(arg0); }");
  test("k:f { $a = kptr(arg0); }");

  test("k:f { @  = uptr((int8*) arg0); }");
  test("k:f { $a = uptr((int8*) arg0); }");

  test("k:f { @ = uptr(arg0); }");
  test("k:f { $a = uptr(arg0); }");
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

TEST(semantic_analyser, call_offsetof)
{
  test("struct Foo { int x; long l; char c; } \
        BEGIN { @x = offsetof(struct Foo, x); }");
  test("struct Foo { int comm; } \
        BEGIN { @x = offsetof(struct Foo, comm); }");
  test("struct Foo { int ctx; } \
        BEGIN { @x = offsetof(struct Foo, ctx); }");
  test("struct Foo { int args; } \
        BEGIN { @x = offsetof(struct Foo, args); }");
  test("struct Foo { int x; long l; char c; } \
        struct Bar { struct Foo foo; int x; } \
        BEGIN { @x = offsetof(struct Bar, x); }");
  test("struct Foo { int x; long l; char c; } \
        union Bar { struct Foo foo; int x; } \
        BEGIN { @x = offsetof(union Bar, x); }");
  test("struct Foo { int x; long l; char c; } \
        struct Fun { struct Foo foo; int (*call)(void); } \
        BEGIN { @x = offsetof(struct Fun, call); }");
  test("struct Foo { int x; long l; char c; } \
        BEGIN { $foo = (struct Foo *)0; \
        @x = offsetof(*$foo, x); }");
  test("struct Foo { int x; long l; char c; } \
        struct Ano { \
          struct { \
            struct Foo foo; \
            int a; \
          }; \
          long l; \
        } \
        BEGIN { @x = offsetof(struct Ano, a); }");
  test("struct Foo { int x; long l; char c; } \
        BEGIN { @x = offsetof(struct Foo, __notexistfield__); }",
       1);
  test("BEGIN { @x = offsetof(__passident__, x); }", 1);
  test("BEGIN { @x = offsetof(struct __notexiststruct__, x); }", 1);
}

TEST(semantic_analyser, int_ident)
{
  test("BEGIN { sizeof(int32) }");
}

TEST(semantic_analyser, tracepoint_common_field)
{
  test("tracepoint:file:filename { args.filename }");
  test("tracepoint:file:filename { args.common_field }", 1);
}

TEST(semantic_analyser, string_size)
{
  // Size of the variable should be the size of the larger string (incl. null)
  BPFtrace bpftrace;
  Driver driver(bpftrace);
  test(bpftrace, true, driver, R"_(BEGIN { $x = "hi"; $x = "hello"; })_", 0);
  auto stmt = driver.ctx.root->probes.at(0)->stmts.at(0);
  auto var_assign = dynamic_cast<ast::AssignVarStatement *>(stmt);
  ASSERT_TRUE(var_assign->var->type.IsStringTy());
  ASSERT_EQ(var_assign->var->type.GetSize(), 6UL);

  test(bpftrace, true, driver, R"_(k:f1 {@ = "hi";} k:f2 {@ = "hello";})_", 0);
  stmt = driver.ctx.root->probes.at(0)->stmts.at(0);
  auto map_assign = dynamic_cast<ast::AssignMapStatement *>(stmt);
  ASSERT_TRUE(map_assign->map->type.IsStringTy());
  ASSERT_EQ(map_assign->map->type.GetSize(), 6UL);

  test(bpftrace,
       true,
       driver,
       R"_(k:f1 {@["hi"] = 0;} k:f2 {@["hello"] = 1;})_",
       0);
  stmt = driver.ctx.root->probes.at(0)->stmts.at(0);
  map_assign = dynamic_cast<ast::AssignMapStatement *>(stmt);
  ASSERT_TRUE(map_assign->map->key_type.args_.at(0).IsStringTy());
  ASSERT_EQ(map_assign->map->key_type.args_.at(0).GetSize(), 6UL);

  test(bpftrace,
       true,
       driver,
       R"_(k:f1 {@["hi", 0] = 0;} k:f2 {@["hello", 1] = 1;})_",
       0);
  stmt = driver.ctx.root->probes.at(0)->stmts.at(0);
  map_assign = dynamic_cast<ast::AssignMapStatement *>(stmt);
  ASSERT_EQ(map_assign->map->key_type.size(), 14UL);
  ASSERT_TRUE(map_assign->map->key_type.args_.at(0).IsStringTy());
  ASSERT_EQ(map_assign->map->key_type.args_.at(0).GetSize(), 6UL);

  test(bpftrace,
       true,
       driver,
       R"_(k:f1 {$x = ("hello", 0);} k:f2 {$x = ("hi", 0); })_",
       0);
  stmt = driver.ctx.root->probes.at(0)->stmts.at(0);
  var_assign = dynamic_cast<ast::AssignVarStatement *>(stmt);
  ASSERT_TRUE(var_assign->var->type.IsTupleTy());
  ASSERT_TRUE(var_assign->var->type.GetField(0).type.IsStringTy());
  ASSERT_EQ(var_assign->var->type.GetSize(), 16UL); // tuples are not packed
  ASSERT_EQ(var_assign->var->type.GetField(0).type.GetSize(), 6UL);
}

TEST(semantic_analyser, call_nsecs)
{
  test("BEGIN { $ns = nsecs(); }");
  test("BEGIN { $ns = nsecs(monotonic); }");
  test("BEGIN { $ns = nsecs(boot); }");
  MockBPFfeature hasfeature(true);
  test(hasfeature, "BEGIN { $ns = nsecs(tai); }");
  test("BEGIN { $ns = nsecs(sw_tai); }");
  test_error("BEGIN { $ns = nsecs(xxx); }", R"(
stdin:1:15-24: ERROR: Invalid timestamp mode: xxx
BEGIN { $ns = nsecs(xxx); }
              ~~~~~~~~~
)");
}

TEST(semantic_analyser, config)
{
  test("config = { BPFTRACE_MAX_AST_NODES=1 } BEGIN { $ns = nsecs(); }");
  test("config = { BPFTRACE_MAX_AST_NODES=1; stack_mode=raw } BEGIN { $ns = "
       "nsecs(); }");
}

TEST(semantic_analyser, subprog_return)
{
  test("fn f(): void { return; }");
  test("fn f(): int64 { return 1; }");

  // Error location is incorrect: #3063
  test_error("fn f(): void { return 1; }", R"(
stdin:1:17-25: ERROR: Function f is of type void, cannot return int64
fn f(): void { return 1; }
                ~~~~~~~~
)");
  // Error location is incorrect: #3063
  test_error("fn f(): int64 { return; }", R"(
stdin:1:18-24: ERROR: Function f is of type int64, cannot return void
fn f(): int64 { return; }
                 ~~~~~~
)");
}

TEST(semantic_analyser, subprog_arguments)
{
  test("fn f($a : int64): int64 { return $a; }");
  // Error location is incorrect: #3063
  test_error("fn f($a : int64): str_t[16] { return $a; }", R"(
stdin:1:33-42: ERROR: Function f is of type string[16], cannot return int64
fn f($a : int64): str_t[16] { return $a; }
                                ~~~~~~~~~
)");
}

TEST(semantic_analyser, subprog_map)
{
  test("fn f(): void { @a = 0; }");
  test("fn f(): int64 { @a = 0; return @a + 1; }");
  test("fn f(): void { @a[0] = 0; }");
  test("fn f(): int64 { @a[0] = 0; return @a[0] + 1; }");
}

TEST(semantic_analyser, subprog_builtin)
{
  test("fn f(): void { print(\"Hello world\"); }");
  test("fn f(): uint64 { return sizeof(int64); }");
  test("fn f(): uint64 { return nsecs; }");
}

TEST(semantic_analyser, subprog_buildin_disallowed)
{
  // Error location is incorrect: #3063
  test_error("fn f(): int64 { return func; }", R"(
stdin:1:25-29: ERROR: Builtin func not supported outside probe
fn f(): int64 { return func; }
                        ~~~~
stdin:1:18-29: ERROR: Function f is of type int64, cannot return none
fn f(): int64 { return func; }
                 ~~~~~~~~~~~
)");
}

class semantic_analyser_btf : public test_btf {};

TEST_F(semantic_analyser_btf, kfunc)
{
  test("kfunc:func_1 { 1 }");
  test("kretfunc:func_1 { 1 }");
  test("kfunc:func_1 { $x = args.a; $y = args.foo1; $z = args.foo2->f.a; }");
  test("kretfunc:func_1 { $x = retval; }");
  test("kfunc:vmlinux:func_1 { 1 }");
  test("kfunc:*:func_1 { 1 }");

  test_error("kretfunc:func_1 { $x = args.foo; }", R"(
stdin:1:24-29: ERROR: Can't find function parameter foo
kretfunc:func_1 { $x = args.foo; }
                       ~~~~~
)");
  test("kretfunc:func_1 { $x = args; }");
  test("kfunc:func_1 { @ = args; }");
  test("kfunc:func_1 { @[args] = 1; }");
  // reg() is not available in kfunc
#ifdef ARCH_X86_64
  test_error("kfunc:func_1 { reg(\"ip\") }", R"(
stdin:1:16-25: ERROR: reg can not be used with "kfunc" probes
kfunc:func_1 { reg("ip") }
               ~~~~~~~~~
)");
  test_error("kretfunc:func_1 { reg(\"ip\") }", R"(
stdin:1:19-28: ERROR: reg can not be used with "kretfunc" probes
kretfunc:func_1 { reg("ip") }
                  ~~~~~~~~~
)");
#endif
  // Backwards compatibility
  test("kfunc:func_1 { $x = args->a; }");
}

TEST_F(semantic_analyser_btf, short_name)
{
  test("f:func_1 { 1 }");
  test("fr:func_1 { 1 }");
}

TEST_F(semantic_analyser_btf, call_path)
{
  test("kfunc:func_1 { $k = path( args.foo1 ) }");
  test("kretfunc:func_1 { $k = path( retval->foo1 ) }");
}

TEST_F(semantic_analyser_btf, call_skb_output)
{
  test("kfunc:func_1 { $ret = skboutput(\"one.pcap\", args.foo1, 1500, 0); }");
  test("kretfunc:func_1 { $ret = skboutput(\"one.pcap\", args.foo1, 1500, 0); "
       "}");

  test_error("kfunc:func_1 { $ret = skboutput(); }", R"(
stdin:1:23-34: ERROR: skboutput() requires 4 arguments (0 provided)
kfunc:func_1 { $ret = skboutput(); }
                      ~~~~~~~~~~~
)");
  test_error("kfunc:func_1 { $ret = skboutput(\"one.pcap\"); }", R"(
stdin:1:23-44: ERROR: skboutput() requires 4 arguments (1 provided)
kfunc:func_1 { $ret = skboutput("one.pcap"); }
                      ~~~~~~~~~~~~~~~~~~~~~
)");
  test_error("kfunc:func_1 { $ret = skboutput(\"one.pcap\", args.foo1); }", R"(
stdin:1:23-55: ERROR: skboutput() requires 4 arguments (2 provided)
kfunc:func_1 { $ret = skboutput("one.pcap", args.foo1); }
                      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)");
  test_error(
      "kfunc:func_1 { $ret = skboutput(\"one.pcap\", args.foo1, 1500); }", R"(
stdin:1:23-61: ERROR: skboutput() requires 4 arguments (3 provided)
kfunc:func_1 { $ret = skboutput("one.pcap", args.foo1, 1500); }
                      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)");
  test_error("kfunc:func_1 { skboutput(\"one.pcap\", args.foo1, 1500, 0); }",
             R"(
stdin:1:16-57: ERROR: skboutput() should be assigned to a variable
kfunc:func_1 { skboutput("one.pcap", args.foo1, 1500, 0); }
               ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)");
}

TEST_F(semantic_analyser_btf, iter)
{
  test("iter:task { 1 }");
  test("iter:task { $x = ctx->task->pid }");
  test("iter:task_file { $x = ctx->file->ino }");
  test("iter:task_vma { $x = ctx->vma->vm_start }");
  test("iter:task { printf(\"%d\", ctx->task->pid); }");
  test_error("iter:task { $x = args.foo; }", R"(
stdin:1:18-22: ERROR: The args builtin can only be used with tracepoint/kfunc/uprobeprobes (iter used here)
iter:task { $x = args.foo; }
                 ~~~~
)");
  test_error("iter:task,iter:task_file { 1 }", R"(
stdin:1:1-10: ERROR: Only single iter attach point is allowed.
iter:task,iter:task_file { 1 }
~~~~~~~~~
)");
  test_error("iter:task,f:func_1 { 1 }", R"(
stdin:1:1-10: ERROR: Only single iter attach point is allowed.
iter:task,f:func_1 { 1 }
~~~~~~~~~
)");
}

// Sanity check for fentry/fexit aliases
TEST_F(semantic_analyser_btf, fentry)
{
  test("fentry:func_1 { 1 }");
  test("fexit:func_1 { 1 }");
  test("fentry:func_1 { $x = args.a; $y = args.foo1; $z = args.foo2->f.a; }");
  test("fexit:func_1 { $x = retval; }");
  test("fentry:vmlinux:func_1 { 1 }");
  test("fentry:*:func_1 { 1 }");
  test("fentry:func_1 { @[func] = 1; }");

  test_error("fexit:func_1 { $x = args.foo; }", R"(
stdin:1:21-26: ERROR: Can't find function parameter foo
fexit:func_1 { $x = args.foo; }
                    ~~~~~
)");
  test("fexit:func_1 { $x = args; }");
  test("fentry:func_1 { @ = args; }");
  test("fentry:func_1 { @[args] = 1; }");
  // reg() is not available in fentry
#ifdef ARCH_X86_64
  test_error("fentry:func_1 { reg(\"ip\") }", R"(
stdin:1:17-26: ERROR: reg can not be used with "kfunc" probes
fentry:func_1 { reg("ip") }
                ~~~~~~~~~
)");
  test_error("fexit:func_1 { reg(\"ip\") }", R"(
stdin:1:16-25: ERROR: reg can not be used with "kretfunc" probes
fexit:func_1 { reg("ip") }
               ~~~~~~~~~
)");
#endif
  // Backwards compatibility
  test("fentry:func_1 { $x = args->a; }");
}

TEST(semantic_analyser, btf_type_tags)
{
  test("t:btf:tag { args.parent }");
  test_error("t:btf:tag { args.real_parent }", R"(
stdin:1:13-18: ERROR: Attempting to access pointer field 'real_parent' with unsupported tag attribute: percpu
t:btf:tag { args.real_parent }
            ~~~~~
)");
}

TEST(semantic_analyser, for_loop_map_one_key)
{
  test("BEGIN { @map[0] = 1; for ($kv : @map) { print($kv); } }", R"(
Program
 BEGIN
  =
   map: @map :: [int64]
    int: 0 :: [int64]
   int: 1 :: [int64]
  for
   decl
    variable: $kv :: [(unsigned int64,int64)]
   expr
    map: @map :: [int64]
   stmts
    call: print
     variable: $kv :: [(unsigned int64,int64)]
)");
}

TEST(semantic_analyser, for_loop_map_two_keys)
{
  test("BEGIN { @map[0,0] = 1; for ($kv : @map) { print($kv); } }", R"(
Program
 BEGIN
  =
   map: @map :: [int64]
    int: 0 :: [int64]
    int: 0 :: [int64]
   int: 1 :: [int64]
  for
   decl
    variable: $kv :: [((unsigned int64,unsigned int64),int64)]
   expr
    map: @map :: [int64]
   stmts
    call: print
     variable: $kv :: [((unsigned int64,unsigned int64),int64)]
)");
}

TEST(semantic_analyser, for_loop_map)
{
  test("BEGIN { @map[0] = 1; for ($kv : @map) { print($kv); } }");
  test("BEGIN { @map[0] = 1; for ($kv : @map) { print($kv.0); } }");
  test("BEGIN { @map[0] = 1; for ($kv : @map) { print($kv.1); } }");
}

TEST(semantic_analyser, for_loop_map_declared_after)
{
  // Regression test: What happens with @map[$kv.0] when @map hasn't been
  // defined yet?
  test("BEGIN { for ($kv : @map) { @map[$kv.0] } @map[0] = 1; }");
}

TEST(semantic_analyser, for_loop_map_no_key)
{
  // Error location is incorrect: #3063
  test_error("BEGIN { @map = 1; for ($kv : @map) { } }", R"(
stdin:1:30-35: ERROR: Maps used as for-loop expressions must have keys to iterate over
BEGIN { @map = 1; for ($kv : @map) { } }
                             ~~~~~
)");
}

TEST(semantic_analyser, for_loop_map_undefined)
{
  // Error location is incorrect: #3063
  test_error("BEGIN { for ($kv : @map) { } }", R"(
stdin:1:20-25: ERROR: Undefined map: @map
BEGIN { for ($kv : @map) { } }
                   ~~~~~
)");
}

TEST(semantic_analyser, for_loop_map_undefined2)
{
  // Error location is incorrect: #3063
  test_error("BEGIN { @map[0] = 1; for ($kv : @undef) { @map[$kv.0]; } }", R"(
stdin:1:33-40: ERROR: Undefined map: @undef
BEGIN { @map[0] = 1; for ($kv : @undef) { @map[$kv.0]; } }
                                ~~~~~~~
)");
}

TEST(semantic_analyser, for_loop_map_restricted_types)
{
  test_error("BEGIN { @map[0] = hist(10); for ($kv : @map) { } }", R"(
stdin:1:40-45: ERROR: Loop expression does not support type: hist
BEGIN { @map[0] = hist(10); for ($kv : @map) { } }
                                       ~~~~~
)");
  test_error("BEGIN { @map[0] = lhist(10, 0, 10, 1); for ($kv : @map) { } }",
             R"(
stdin:1:51-56: ERROR: Loop expression does not support type: lhist
BEGIN { @map[0] = lhist(10, 0, 10, 1); for ($kv : @map) { } }
                                                  ~~~~~
)");
  test_error("BEGIN { @map[0] = stats(10); for ($kv : @map) { } }", R"(
stdin:1:41-46: ERROR: Loop expression does not support type: stats
BEGIN { @map[0] = stats(10); for ($kv : @map) { } }
                                        ~~~~~
)");
}

TEST(semantic_analyser, for_loop_shadowed_decl)
{
  test_error(R"(
    BEGIN {
      $kv = 1;
      @map[0] = 1;
      for ($kv : @map) { }
    })",
             R"(
stdin:4:11-15: ERROR: Loop declaration shadows existing variable: $kv
      for ($kv : @map) { }
          ~~~~
)");
}

TEST(semantic_analyser, for_loop_variables_read_only)
{
  test(R"(
    BEGIN {
      $var = 0;
      @map[0] = 1;
      for ($kv : @map) {
        print($var);
      }
      print($var);
    })",
       R"(*
  for
   ctx
    $var :: [int64 *, AS(bpf)]
   decl
*)");
}

TEST(semantic_analyser, for_loop_variables_modified_during_loop)
{
  test(R"(
    BEGIN {
      $var = 0;
      @map[0] = 1;
      for ($kv : @map) {
        $var++;
      }
      print($var);
    })",
       R"(*
  for
   ctx
    $var :: [int64 *, AS(bpf)]
   decl
*)");
}

TEST(semantic_analyser, for_loop_variables_created_in_loop)
{
  // $var should not appear in ctx
  test(R"(
    BEGIN {
      @map[0] = 1;
      for ($kv : @map) {
        $var = 2;
        print($var);
      }
    })",
       R"(*
  for
   decl
*)");
}

TEST(semantic_analyser, for_loop_variables_multiple)
{
  test(R"(
    BEGIN {
      @map[0] = 1;
      $var1 = 123;
      $var2 = "abc";
      $var3 = "def";
      for ($kv : @map) {
        $var1 = 456;
        print($var3);
      }
    })",
       R"(*
  for
   ctx
    $var1 :: [int64 *, AS(bpf)]
    $var3 :: [string[4] *, AS(bpf)]
   decl
*)");
}

TEST(semantic_analyser, for_loop_variables_created_in_loop_used_after)
{
  test_error(R"(
    BEGIN {
      @map[0] = 1;
      for ($kv : @map) {
        $var = 2;
      }
      print($var);
    })",
             R"(
stdin:6:7-17: ERROR: Undefined or undeclared variable: $var
      print($var);
      ~~~~~~~~~~
)");

  test_error(R"(
    BEGIN {
      @map[0] = 1;
      for ($kv : @map) {
        print($kv);
      }
      print($kv);
    })",
             R"(
stdin:6:7-16: ERROR: Undefined or undeclared variable: $kv
      print($kv);
      ~~~~~~~~~
)");
}

TEST(semantic_analyser, for_loop_invalid_expr)
{
  // Error location is incorrect: #3063
  test_error("BEGIN { for ($x : $var) { } }", R"(
stdin:1:19-24: ERROR: Loop expression must be a map
BEGIN { for ($x : $var) { } }
                  ~~~~~
)");
  test_error("BEGIN { for ($x : 1+2) { } }", R"(
stdin:1:19-22: ERROR: Loop expression must be a map
BEGIN { for ($x : 1+2) { } }
                  ~~~
)");
  test_error("BEGIN { for ($x : \"abc\") { } }", R"(
stdin:1:19-25: ERROR: Loop expression must be a map
BEGIN { for ($x : "abc") { } }
                  ~~~~~~
)");
}

TEST(semantic_analyser, for_loop_multiple_errors)
{
  // Error location is incorrect: #3063
  test_error(R"(
    BEGIN {
      $kv = 1;
      @map[0] = 1;
      for ($kv : 1) { }
    })",
             R"(
stdin:4:11-15: ERROR: Loop declaration shadows existing variable: $kv
      for ($kv : 1) { }
          ~~~~
stdin:4:18-20: ERROR: Loop expression must be a map
      for ($kv : 1) { }
                 ~~
)");
}

TEST(semantic_analyser, for_loop_control_flow)
{
  // Error location is incorrect: #3063
  test_error("BEGIN { @map[0] = 1; for ($kv : @map) { break; } }", R"(
stdin:1:42-47: ERROR: 'break' statement is not allowed in a for-loop
BEGIN { @map[0] = 1; for ($kv : @map) { break; } }
                                         ~~~~~
)");
  // Error location is incorrect: #3063
  test_error("BEGIN { @map[0] = 1; for ($kv : @map) { continue; } }", R"(
stdin:1:42-50: ERROR: 'continue' statement is not allowed in a for-loop
BEGIN { @map[0] = 1; for ($kv : @map) { continue; } }
                                         ~~~~~~~~
)");
  // Error location is incorrect: #3063
  test_error("BEGIN { @map[0] = 1; for ($kv : @map) { return; } }", R"(
stdin:1:42-48: ERROR: 'return' statement is not allowed in a for-loop
BEGIN { @map[0] = 1; for ($kv : @map) { return; } }
                                         ~~~~~~
)");
}

TEST(semantic_analyser, for_loop_missing_feature)
{
  test_error("BEGIN { @map[0] = 1; for ($kv : @map) { print($kv); } }",
             R"(
stdin:1:22-25: ERROR: Missing required kernel feature: for_each_map_elem
BEGIN { @map[0] = 1; for ($kv : @map) { print($kv); } }
                     ~~~
)",
             false);
}

TEST(semantic_analyser, for_loop_no_ctx_access)
{
  test_error("kprobe:f { @map[0] = 1; for ($kv : @map) { arg0 } }",
             R"(
stdin:1:45-49: ERROR: 'arg0' builtin is not allowed in a for-loop
kprobe:f { @map[0] = 1; for ($kv : @map) { arg0 } }
                                            ~~~~
)");
}

TEST_F(semantic_analyser_btf, args_builtin_mixed_probes)
{
  test_error("kfunc:func_1,tracepoint:sched:sched_one { args }", R"(
stdin:1:43-47: ERROR: The args builtin can only be used within the context of a single probe type, e.g. "probe1 {args}" is valid while "probe1,probe2 {args}" is not.
kfunc:func_1,tracepoint:sched:sched_one { args }
                                          ~~~~
)");
}

TEST(semantic_analyser, buf_strlen_too_large)
{
  auto bpftrace = get_mock_bpftrace();
  ConfigSetter configs{ bpftrace->config_, ConfigSource::script };
  configs.set(ConfigKeyInt::max_strlen, 9999999999);

  test_error(*bpftrace, "uprobe:/bin/sh:f { buf(arg0, 4) }", R"(
stdin:1:20-32: ERROR: BPFTRACE_MAX_STRLEN too large to use on buffer (9999999999 > 4294967295)
uprobe:/bin/sh:f { buf(arg0, 4) }
                   ~~~~~~~~~~~~
)");

  test_error(*bpftrace, "uprobe:/bin/sh:f { buf(arg0) }", R"(
stdin:1:20-29: ERROR: BPFTRACE_MAX_STRLEN too large to use on buffer (9999999999 > 4294967295)
uprobe:/bin/sh:f { buf(arg0) }
                   ~~~~~~~~~
)");
}

} // namespace semantic_analyser
} // namespace test
} // namespace bpftrace
