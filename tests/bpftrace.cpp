#include <chrono>
#include <cstdint>
#include <cstring>

#include "ast/passes/ap_probe_expansion.h"
#include "ast/passes/args_resolver.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/clang_parser.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/control_flow_analyser.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/named_param.h"
#include "ast/passes/types/type_system.h"
#include "bpfmap.h"
#include "bpftrace.h"
#include "btf_common.h"
#include "driver.h"
#include "mocks.h"
#include "output/text.h"
#include "types.h"
#include "types_format.h"
#include "gmock/gmock-matchers.h"
#include "gmock/gmock-nice-strict.h"
#include "gtest/gtest.h"

using namespace std::chrono_literals;

namespace bpftrace::test::bpftrace {

using ::testing::_;
using ::testing::ContainerEq;
using ::testing::Contains;
using ::testing::StrictMock;

static const int STRING_SIZE = 64;

static const std::optional<int> no_pid = std::nullopt;

static ast::CDefinitions no_c_defs; // Not used for tests.

static std::string kprobe_name(const std::string &attach_point,
                               const std::string &target,
                               uint64_t func_offset)
{
  auto str = func_offset ? "+" + std::to_string(func_offset) : "";
  if (!target.empty()) {
    return "kprobe:" + target + ":" + attach_point + str;
  }
  return "kprobe:" + attach_point + str;
}

static auto parse_probe(const std::string &str, BPFtrace &bpftrace)
{
  ast::ASTContext ast("stdin", str);

  ast::TypeMetadata no_types; // No external types defined.

  // N.B. Don't use tracepoint format parser here.
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .put(get_mock_function_info())
                .put(no_types)
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateCheckAttachpointsPass())
                .add(ast::CreateControlFlowPass())
                .add(ast::CreateProbeAndApExpansionPass())
                .add(ast::CreateMacroExpansionPass())
                .add(ast::CreateArgsResolverPass())
                .add(ast::CreateFieldAnalyserPass())
                .add(ast::CreateClangParsePass())
                .add(ast::CreateMapSugarPass())
                .add(ast::CreateNamedParamsPass())
                .add(ast::CreateLLVMInitPass())
                .add(ast::CreateCompilePass())
                .run();
  ASSERT_TRUE(ok && ast.diagnostics().ok());
}

void check_kprobe(Probe &p,
                  const std::string &attach_point,
                  uint64_t func_offset = 0,
                  const std::string &target = "")
{
  EXPECT_EQ(ProbeType::kprobe, p.type);
  EXPECT_EQ(attach_point, p.attach_point);
  EXPECT_EQ(kprobe_name(attach_point, target, func_offset), p.name);
  EXPECT_EQ(func_offset, p.func_offset);
  EXPECT_TRUE(p.funcs.empty());
}

void check_uprobe(Probe &p,
                  const std::string &path,
                  const std::string &attach_point,
                  const std::string &name,
                  uint64_t address = 0,
                  uint64_t func_offset = 0)
{
  bool retprobe = attach_point.starts_with("uretprobe:") ||
                  attach_point.starts_with("ur:");
  EXPECT_EQ(retprobe ? ProbeType::uretprobe : ProbeType::uprobe, p.type);
  EXPECT_EQ(path, p.path);
  EXPECT_EQ(attach_point, p.attach_point);
  EXPECT_EQ(name, p.name);
  EXPECT_EQ(address, p.address);
  EXPECT_EQ(func_offset, p.func_offset);
  EXPECT_TRUE(p.funcs.empty());
}

void check_usdt(Probe &p,
                const std::string &path,
                const std::string &provider,
                const std::string &attach_point)
{
  EXPECT_EQ(ProbeType::usdt, p.type);
  EXPECT_EQ(attach_point, p.attach_point);
  EXPECT_EQ("usdt:" + path + ":" + provider + ":" + attach_point, p.name);
}

void check_tracepoint(Probe &p,
                      const std::string &target,
                      const std::string &func)
{
  EXPECT_EQ(ProbeType::tracepoint, p.type);
  EXPECT_EQ(func, p.attach_point);
  EXPECT_EQ("tracepoint:" + target + ":" + func, p.name);
}

void check_profile(Probe &p, const std::string &unit, int freq)
{
  EXPECT_EQ(ProbeType::profile, p.type);
  EXPECT_EQ(freq, p.freq);
  EXPECT_EQ("profile:" + unit + ":" + std::to_string(freq), p.name);
}

void check_interval(Probe &p, const std::string &unit, int freq)
{
  EXPECT_EQ(ProbeType::interval, p.type);
  EXPECT_EQ(freq, p.freq);
  EXPECT_EQ("interval:" + unit + ":" + std::to_string(freq), p.name);
}

void check_software(Probe &p, const std::string &unit, int freq)
{
  EXPECT_EQ(ProbeType::software, p.type);
  EXPECT_EQ(freq, p.freq);
  EXPECT_EQ("software:" + unit + ":" + std::to_string(freq), p.name);
}

void check_hardware(Probe &p, const std::string &unit, int freq)
{
  EXPECT_EQ(ProbeType::hardware, p.type);
  EXPECT_EQ(freq, p.freq);
  EXPECT_EQ("hardware:" + unit + ":" + std::to_string(freq), p.name);
}

void check_begin_probe(Probe &p)
{
  EXPECT_EQ(ProbeType::special, p.type);
}

void check_end_probe(Probe &p)
{
  EXPECT_EQ(ProbeType::special, p.type);
}

void check_test_probe(Probe &p, const std::string &test_name)
{
  EXPECT_EQ(ProbeType::test, p.type);
  EXPECT_EQ(test_name, p.path);
}

void check_benchmark_probe(Probe &p, const std::string &bench_name)
{
  EXPECT_EQ(ProbeType::benchmark, p.type);
  EXPECT_EQ(bench_name, p.path);
}

TEST(bpftrace, add_begin_probe)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("begin{}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(1U, bpftrace->get_begin_probes().size());

  check_begin_probe(bpftrace->get_begin_probes().front());
}

TEST(bpftrace, add_end_probe)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("end{}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(1U, bpftrace->get_end_probes().size());

  check_end_probe(bpftrace->get_end_probes().front());
}

TEST(bpftrace, add_test_probes)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("test:a{} test:b{} test:c{}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());
  ASSERT_EQ(0U, bpftrace->get_end_probes().size());
  ASSERT_EQ(3U, bpftrace->get_test_probes().size());

  check_test_probe(bpftrace->get_test_probes().at(0), "a");
  check_test_probe(bpftrace->get_test_probes().at(1), "b");
  check_test_probe(bpftrace->get_test_probes().at(2), "c");
}

TEST(bpftrace, add_bench_probes)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("bench:a{} bench:b{} bench:c{}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());
  ASSERT_EQ(0U, bpftrace->get_end_probes().size());
  ASSERT_EQ(3U, bpftrace->get_benchmark_probes().size());

  check_benchmark_probe(bpftrace->get_benchmark_probes().at(0), "a");
  check_benchmark_probe(bpftrace->get_benchmark_probes().at(1), "b");
  check_benchmark_probe(bpftrace->get_benchmark_probes().at(2), "c");
}

TEST(bpftrace, add_probes_single)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("kprobe:sys_read {}", *bpftrace);
  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_kprobe(bpftrace->get_probes().at(0), "sys_read");
}

TEST(bpftrace, add_probes_multiple)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("kprobe:sys_read,kprobe:sys_write{}", *bpftrace);
  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_kprobe(bpftrace->get_probes().at(0), "sys_read");
  check_kprobe(bpftrace->get_probes().at(1), "sys_write");
}

TEST(bpftrace, add_probes_kernel_module)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("kprobe:mod_func_1{}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_kprobe(bpftrace->get_probes().at(0), "mod_func_1");
}

TEST(bpftrace, add_probes_specify_kernel_module)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("kprobe:kernel_mod_1:mod_func_1{}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_kprobe(bpftrace->get_probes().at(0), "mod_func_1", 0, "kernel_mod_1");
}

TEST(bpftrace, add_probes_offset)
{
  auto offset = 10;
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("kprobe:sys_read+10{}", *bpftrace);
  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_kprobe(bpftrace->get_probes().at(0), "sys_read", offset);
}

TEST(bpftrace, add_probes_uprobe)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("uprobe:/bin/sh:f {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());
  check_uprobe(
      bpftrace->get_probes().at(0), "/bin/sh", "f", "uprobe:/bin/sh:f");
}

TEST(bpftrace, add_probes_uprobe_address)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("uprobe:/bin/sh:1024 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());
  check_uprobe(
      bpftrace->get_probes().at(0), "/bin/sh", "", "uprobe:/bin/sh:1024", 1024);
}

TEST(bpftrace, add_probes_uprobe_string_offset)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("uprobe:/bin/sh:f+10{}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());
  check_uprobe(bpftrace->get_probes().at(0),
               "/bin/sh",
               "f",
               "uprobe:/bin/sh:f+10",
               0,
               10);
}

TEST(bpftrace, add_probes_usdt)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("usdt:/bin/sh:prov1:tp1 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());
  check_usdt(bpftrace->get_probes().at(0), "/bin/sh", "prov1", "tp1");
}

TEST(bpftrace, add_probes_usdt_empty_namespace_conflict)
{
  auto bpftrace = get_strict_mock_bpftrace();

  parse_probe("usdt:/bin/sh:tp {}", *bpftrace);
}

TEST(bpftrace, add_probes_usdt_duplicate_markers)
{
  auto bpftrace = get_strict_mock_bpftrace();

  parse_probe("usdt:/bin/sh:prov1:tp1 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());
  check_usdt(bpftrace->get_probes().at(0), "/bin/sh", "prov1", "tp1");
}

TEST(bpftrace, add_probes_tracepoint)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("tracepoint:sched:sched_one {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_tracepoint(bpftrace->get_probes().at(0), "sched", "sched_one");
}

TEST(bpftrace, add_probes_profile)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("profile:ms:997 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_profile(bpftrace->get_probes().at(0), "ms", 997);
}

TEST(bpftrace, add_probes_interval)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("i:s:1 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_interval(bpftrace->get_probes().at(0), "s", 1);
}

TEST(bpftrace, add_probes_software)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("software:faults:1000 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_software(bpftrace->get_probes().at(0), "faults", 1000);
}

TEST(bpftrace, add_probes_hardware)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("hardware:cache-references:1000000 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_hardware(bpftrace->get_probes().at(0), "cache-references", 1000000);
}

TEST(bpftrace, trailing_comma)
{
  ast::ASTContext ast("stdin", "kprobe:f, {}");
  Driver driver(ast);

  // Trailing comma is fine
  driver.parse_program();
  std::stringstream ss;
  ast.diagnostics().emit(ss);
  ASSERT_TRUE(ast.diagnostics().ok()) << ss.str();
}

TEST(bpftrace, empty_attachpoint)
{
  ast::ASTContext ast("stdin", "{}");
  Driver driver(ast);

  // Empty attach point should fail...
  ast.root = driver.parse_program();

  // ... ah, but it doesn't really. What fails is the attachpoint parser. The
  // above is a valid program, it is just not a valid attachpoint.
  StrictMock<MockBPFtrace> bpftrace;
  ast::AttachPointParser ap_parser(ast, bpftrace, get_mock_function_info());
  ap_parser.parse();
  EXPECT_FALSE(ast.diagnostics().ok());
}

TEST(bpftrace, sort_by_key_int)
{
  auto bpftrace = get_strict_mock_bpftrace();

  SizedType key_arg = CreateUInt64();
  std::vector<std::pair<OpaqueValue, OpaqueValue>> values_by_key = {
    { OpaqueValue::from<uint64_t>(2), OpaqueValue::from<uint64_t>(12) },
    { OpaqueValue::from<uint64_t>(3), OpaqueValue::from<uint64_t>(11) },
    { OpaqueValue::from<uint64_t>(1), OpaqueValue::from<uint64_t>(10) },
  };
  sort_by_key(key_arg, values_by_key);

  std::vector<std::pair<OpaqueValue, OpaqueValue>> expected_values = {
    { OpaqueValue::from<uint64_t>(1), OpaqueValue::from<uint64_t>(10) },
    { OpaqueValue::from<uint64_t>(2), OpaqueValue::from<uint64_t>(12) },
    { OpaqueValue::from<uint64_t>(3), OpaqueValue::from<uint64_t>(11) },
  };

  EXPECT_THAT(values_by_key, ContainerEq(expected_values));
}

TEST(bpftrace, sort_by_key_int_int)
{
  auto bpftrace = get_strict_mock_bpftrace();

  SizedType key = CreateTuple(
      Struct::CreateTuple({ CreateInt64(), CreateInt64(), CreateInt64() }));

  std::vector<std::pair<OpaqueValue, OpaqueValue>> values_by_key = {
    { OpaqueValue::from<std::vector<uint64_t>>({ 5, 2, 1 }),
      OpaqueValue::from<uint64_t>(1) },
    { OpaqueValue::from<std::vector<uint64_t>>({ 5, 3, 1 }),
      OpaqueValue::from<uint64_t>(2) },
    { OpaqueValue::from<std::vector<uint64_t>>({ 5, 1, 1 }),
      OpaqueValue::from<uint64_t>(3) },
    { OpaqueValue::from<std::vector<uint64_t>>({ 2, 2, 2 }),
      OpaqueValue::from<uint64_t>(4) },
    { OpaqueValue::from<std::vector<uint64_t>>({ 2, 3, 2 }),
      OpaqueValue::from<uint64_t>(5) },
    { OpaqueValue::from<std::vector<uint64_t>>({ 2, 1, 2 }),
      OpaqueValue::from<uint64_t>(6) },
  };
  sort_by_key(key, values_by_key);

  std::vector<std::pair<OpaqueValue, OpaqueValue>> expected_values = {
    { OpaqueValue::from<std::vector<uint64_t>>({ 2, 1, 2 }),
      OpaqueValue::from<uint64_t>(6) },
    { OpaqueValue::from<std::vector<uint64_t>>({ 2, 2, 2 }),
      OpaqueValue::from<uint64_t>(4) },
    { OpaqueValue::from<std::vector<uint64_t>>({ 2, 3, 2 }),
      OpaqueValue::from<uint64_t>(5) },
    { OpaqueValue::from<std::vector<uint64_t>>({ 5, 1, 1 }),
      OpaqueValue::from<uint64_t>(3) },
    { OpaqueValue::from<std::vector<uint64_t>>({ 5, 2, 1 }),
      OpaqueValue::from<uint64_t>(1) },
    { OpaqueValue::from<std::vector<uint64_t>>({ 5, 3, 1 }),
      OpaqueValue::from<uint64_t>(2) },
  };

  EXPECT_THAT(values_by_key, ContainerEq(expected_values));
}

TEST(bpftrace, sort_by_key_str)
{
  auto bpftrace = get_strict_mock_bpftrace();

  SizedType key_arg = CreateString(STRING_SIZE);
  std::vector<std::pair<OpaqueValue, OpaqueValue>> values_by_key = {
    { OpaqueValue::string("z", STRING_SIZE), OpaqueValue::from<uint64_t>(1) },
    { OpaqueValue::string("a", STRING_SIZE), OpaqueValue::from<uint64_t>(2) },
    { OpaqueValue::string("x", STRING_SIZE), OpaqueValue::from<uint64_t>(3) },
    { OpaqueValue::string("d", STRING_SIZE), OpaqueValue::from<uint64_t>(4) },
  };
  sort_by_key(key_arg, values_by_key);

  std::vector<std::pair<OpaqueValue, OpaqueValue>> expected_values = {
    { OpaqueValue::string("a", STRING_SIZE), OpaqueValue::from<uint64_t>(2) },
    { OpaqueValue::string("d", STRING_SIZE), OpaqueValue::from<uint64_t>(4) },
    { OpaqueValue::string("x", STRING_SIZE), OpaqueValue::from<uint64_t>(3) },
    { OpaqueValue::string("z", STRING_SIZE), OpaqueValue::from<uint64_t>(1) },
  };

  EXPECT_THAT(values_by_key, ContainerEq(expected_values));
}

TEST(bpftrace, sort_by_key_str_str)
{
  auto bpftrace = get_strict_mock_bpftrace();

  SizedType key = CreateTuple(
      Struct::CreateTuple({ CreateString(STRING_SIZE),
                            CreateString(STRING_SIZE),
                            CreateString(STRING_SIZE) }));

  std::vector<std::pair<OpaqueValue, OpaqueValue>> values_by_key = {
    { OpaqueValue::string("z", STRING_SIZE) +
          OpaqueValue::string("a", STRING_SIZE) +
          OpaqueValue::string("l", STRING_SIZE),
      OpaqueValue::from<uint64_t>(1) },
    { OpaqueValue::string("a", STRING_SIZE) +
          OpaqueValue::string("a", STRING_SIZE) +
          OpaqueValue::string("m", STRING_SIZE),
      OpaqueValue::from<uint64_t>(2) },
    { OpaqueValue::string("z", STRING_SIZE) +
          OpaqueValue::string("c", STRING_SIZE) +
          OpaqueValue::string("n", STRING_SIZE),
      OpaqueValue::from<uint64_t>(3) },
    { OpaqueValue::string("a", STRING_SIZE) +
          OpaqueValue::string("c", STRING_SIZE) +
          OpaqueValue::string("o", STRING_SIZE),
      OpaqueValue::from<uint64_t>(4) },
    { OpaqueValue::string("z", STRING_SIZE) +
          OpaqueValue::string("b", STRING_SIZE) +
          OpaqueValue::string("p", STRING_SIZE),
      OpaqueValue::from<uint64_t>(5) },
    { OpaqueValue::string("a", STRING_SIZE) +
          OpaqueValue::string("b", STRING_SIZE) +
          OpaqueValue::string("q", STRING_SIZE),
      OpaqueValue::from<uint64_t>(6) },
  };
  sort_by_key(key, values_by_key);

  std::vector<std::pair<OpaqueValue, OpaqueValue>> expected_values = {
    { OpaqueValue::string("a", STRING_SIZE) +
          OpaqueValue::string("a", STRING_SIZE) +
          OpaqueValue::string("m", STRING_SIZE),
      OpaqueValue::from<uint64_t>(2) },
    { OpaqueValue::string("a", STRING_SIZE) +
          OpaqueValue::string("b", STRING_SIZE) +
          OpaqueValue::string("q", STRING_SIZE),
      OpaqueValue::from<uint64_t>(6) },
    { OpaqueValue::string("a", STRING_SIZE) +
          OpaqueValue::string("c", STRING_SIZE) +
          OpaqueValue::string("o", STRING_SIZE),
      OpaqueValue::from<uint64_t>(4) },
    { OpaqueValue::string("z", STRING_SIZE) +
          OpaqueValue::string("a", STRING_SIZE) +
          OpaqueValue::string("l", STRING_SIZE),
      OpaqueValue::from<uint64_t>(1) },
    { OpaqueValue::string("z", STRING_SIZE) +
          OpaqueValue::string("b", STRING_SIZE) +
          OpaqueValue::string("p", STRING_SIZE),
      OpaqueValue::from<uint64_t>(5) },
    { OpaqueValue::string("z", STRING_SIZE) +
          OpaqueValue::string("c", STRING_SIZE) +
          OpaqueValue::string("n", STRING_SIZE),
      OpaqueValue::from<uint64_t>(3) },
  };

  EXPECT_THAT(values_by_key, ContainerEq(expected_values));
}

TEST(bpftrace, sort_by_key_int_str)
{
  auto bpftrace = get_strict_mock_bpftrace();

  SizedType key = CreateTuple(
      Struct::CreateTuple({ CreateUInt64(), CreateString(STRING_SIZE) }));

  std::vector<std::pair<OpaqueValue, OpaqueValue>> values_by_key = {
    { OpaqueValue::from<uint64_t>(1) + OpaqueValue::string("b", STRING_SIZE),
      OpaqueValue::from<uint64_t>(1) },
    { OpaqueValue::from<uint64_t>(2) + OpaqueValue::string("b", STRING_SIZE),
      OpaqueValue::from<uint64_t>(2) },
    { OpaqueValue::from<uint64_t>(3) + OpaqueValue::string("b", STRING_SIZE),
      OpaqueValue::from<uint64_t>(3) },
    { OpaqueValue::from<uint64_t>(1) + OpaqueValue::string("a", STRING_SIZE),
      OpaqueValue::from<uint64_t>(4) },
    { OpaqueValue::from<uint64_t>(2) + OpaqueValue::string("a", STRING_SIZE),
      OpaqueValue::from<uint64_t>(5) },
    { OpaqueValue::from<uint64_t>(3) + OpaqueValue::string("a", STRING_SIZE),
      OpaqueValue::from<uint64_t>(6) },
  };
  sort_by_key(key, values_by_key);

  std::vector<std::pair<OpaqueValue, OpaqueValue>> expected_values = {
    { OpaqueValue::from<uint64_t>(1) + OpaqueValue::string("a", STRING_SIZE),
      OpaqueValue::from<uint64_t>(4) },
    { OpaqueValue::from<uint64_t>(1) + OpaqueValue::string("b", STRING_SIZE),
      OpaqueValue::from<uint64_t>(1) },
    { OpaqueValue::from<uint64_t>(2) + OpaqueValue::string("a", STRING_SIZE),
      OpaqueValue::from<uint64_t>(5) },
    { OpaqueValue::from<uint64_t>(2) + OpaqueValue::string("b", STRING_SIZE),
      OpaqueValue::from<uint64_t>(2) },
    { OpaqueValue::from<uint64_t>(3) + OpaqueValue::string("a", STRING_SIZE),
      OpaqueValue::from<uint64_t>(6) },
    { OpaqueValue::from<uint64_t>(3) + OpaqueValue::string("b", STRING_SIZE),
      OpaqueValue::from<uint64_t>(3) },
  };

  EXPECT_THAT(values_by_key, ContainerEq(expected_values));
}

class bpftrace_btf : public test_btf {};

void check_probe(Probe &p, ProbeType type, const std::string &name)
{
  EXPECT_EQ(type, p.type);
  EXPECT_EQ(name, p.name);
}

TEST_F(bpftrace_btf, add_probes_fentry)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("fentry:vmlinux:func_1,fexit:vmlinux:func_1 {}", *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_probe(bpftrace->get_probes().at(0),
              ProbeType::fentry,
              "fentry:vmlinux:func_1");
  check_probe(bpftrace->get_probes().at(1),
              ProbeType::fexit,
              "fexit:vmlinux:func_1");
}

TEST_F(bpftrace_btf, add_probes_fentry_bpf_func)
{
  auto bpftrace = get_mock_bpftrace();
  parse_probe("fentry:bpf:func_1 {}", *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_probe(bpftrace->get_probes().at(0),
              ProbeType::fentry,
              "fentry:bpf:123:func_1");
  check_probe(bpftrace->get_probes().at(1),
              ProbeType::fentry,
              "fentry:bpf:456:func_1");
}

TEST_F(bpftrace_btf, add_probes_fentry_bpf_id)
{
  auto bpftrace = get_mock_bpftrace();
  parse_probe("fentry:bpf:456:func_1 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_probe(bpftrace->get_probes().at(0),
              ProbeType::fentry,
              "fentry:bpf:456:func_1");
}

TEST_F(bpftrace_btf, add_probes_kprobe)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("kprobe:vmlinux:func_1,kretprobe:vmlinux:func_1 {}", *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_probe(bpftrace->get_probes().at(0),
              ProbeType::kprobe,
              "kprobe:vmlinux:func_1");
  check_probe(bpftrace->get_probes().at(1),
              ProbeType::kretprobe,
              "kretprobe:vmlinux:func_1");
}

TEST_F(bpftrace_btf, add_probes_iter_task)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("iter:task {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_probe(bpftrace->get_probes().at(0), ProbeType::iter, "iter:task");
}

TEST_F(bpftrace_btf, add_probes_iter_task_file)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("iter:task_file {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_probe(bpftrace->get_probes().at(0), ProbeType::iter, "iter:task_file");
}

TEST_F(bpftrace_btf, add_probes_iter_task_vma)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("iter:task_vma {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  check_probe(bpftrace->get_probes().at(0), ProbeType::iter, "iter:task_vma");
}

class bpftrace_bad_btf : public test_bad_btf {};

// Test that we can handle bad data and don't just crash
TEST_F(bpftrace_bad_btf, parse_invalid_btf)
{
  BPFtrace bpftrace;
  EXPECT_FALSE(bpftrace.has_btf_data());
}

TEST_F(bpftrace_btf, add_probes_rawtracepoint)
{
  auto bpftrace = get_mock_bpftrace();
  parse_probe("rawtracepoint:event_rt {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_begin_probes().size());

  auto probe = bpftrace->get_probes().at(0);
  EXPECT_EQ(ProbeType::rawtracepoint, probe.type);
  EXPECT_EQ("event_rt", probe.attach_point);
  EXPECT_EQ("rawtracepoint:vmlinux:event_rt", probe.name);
}

TEST(bpftrace, resolve_timestamp)
{
  static const auto bootmode = static_cast<uint32_t>(TimestampMode::boot);
  auto bpftrace = get_strict_mock_bpftrace();

  if (std::chrono::system_clock::period::den < 1000000000)
    GTEST_SKIP() << "Timestamp test requires nanosecond precision";

  // Basic sanity check
  bpftrace->boottime_ = { .tv_sec = 3, .tv_nsec = 0 };
  bpftrace->resources.strftime_args.emplace_back("%s.%f");
  EXPECT_EQ(bpftrace->format_timestamp(
                bpftrace->resolve_timestamp(bootmode, 1000), 0),
            "3.000001");

  // Check that boottime nsecs close to 1s doesn't trigger floating-point error.
  //
  // Due to the peculiarities of floating-point, not _any_ set of numbers
  // trigger the bug here. These values were discovered in the wild.
  bpftrace->boottime_ = { .tv_sec = 1736725826, .tv_nsec = 999999985 };
  bpftrace->resources.strftime_args.emplace_back("%s");
  EXPECT_EQ(bpftrace->format_timestamp(bpftrace->resolve_timestamp(bootmode, 0),
                                       1),
            "1736725826");

  // Now check that we handle rollover to a new second correctly
  bpftrace->resources.strftime_args.emplace_back("%s.%f");
  EXPECT_EQ(
      bpftrace->format_timestamp(bpftrace->resolve_timestamp(bootmode, 15), 2),
      "1736725827.000000");
}

static std::set<std::string> list_modules(std::string_view ap)
{
  ast::ASTContext ast("stdin", ap.data());
  auto bpftrace = get_mock_bpftrace();

  auto ok = ast::PassManager()
                .put(ast)
                .put<BPFtrace>(*bpftrace)
                .put(get_mock_function_info())
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .run();
  std::stringstream out;
  ast.diagnostics().emit(out);
  EXPECT_TRUE(ok && ast.diagnostics().ok()) << out.str();

  auto &func_info = get_mock_function_info();
  ProbeMatcher probe_matcher(bpftrace.get(),
                             func_info.kernel_info(),
                             func_info.user_info());
  return bpftrace->list_modules(ast, probe_matcher);
}

// Test modules are extracted when module is not explicit in attachpoint
TEST(bpftrace, list_modules_kprobe_implicit)
{
  auto modules = list_modules("k:queued_spin_lock_slowpath,kr:mod_func_1{}");
  EXPECT_EQ(modules.size(), 3);
  EXPECT_THAT(modules, Contains("vmlinux"));
  EXPECT_THAT(modules, Contains("kernel_mod_1"));
  EXPECT_THAT(modules, Contains("kernel_mod_2"));
}

// Inverse of above
TEST(bpftrace, list_modules_kprobe_explicit)
{
  auto modules = list_modules(
      "k:vmlinux:queued_spin_lock_slowpath,kr:kernel_mod_1:mod_func_1{}");
  EXPECT_EQ(modules.size(), 2);
  EXPECT_THAT(modules, Contains("vmlinux"));
  EXPECT_THAT(modules, Contains("kernel_mod_1"));
}

// Implicit fentry/fexit is not tested b/c the mocks are currently wired
// up in a somewhat rigid way. The mocked data source uses "vmlinux" module
// but another mock forces "mock_vmlinux" module. Anyone reading this comment
// is welcome to try it out again (in case it's been fixed in interim) or do
// a proper fix.

TEST_F(bpftrace_btf, list_modules_fentry_explicit)
{
  auto modules = list_modules("fentry:vmlinux:func_1,fexit:vmlinux:func_2{}");
  EXPECT_EQ(modules.size(), 1);
  EXPECT_THAT(modules, Contains("vmlinux"));
}

TEST_F(bpftrace_btf, list_modules_rawtracepoint_implicit)
{
  auto modules = list_modules("rawtracepoint:event_rt{}");
  EXPECT_EQ(modules.size(), 1);
  EXPECT_THAT(modules, Contains("vmlinux"));
}

TEST_F(bpftrace_btf, list_modules_rawtracepoint_explicit)
{
  auto modules = list_modules("rawtracepoint:vmlinux:event_rt{}");
  EXPECT_EQ(modules.size(), 1);
  EXPECT_THAT(modules, Contains("vmlinux"));
}

TEST(bpftrace, print_basic_map)
{
  struct TestCase {
    std::string name;
    uint32_t top;
    uint32_t div;
    std::string expected_output;
  };

  const MapElements key_values = {
    { OpaqueValue::from<uint64_t>(1), OpaqueValue::from<uint64_t>(5) },
    { OpaqueValue::from<uint64_t>(3), OpaqueValue::from<uint64_t>(10) },
    { OpaqueValue::from<uint64_t>(5), OpaqueValue::from<uint64_t>(4) },
    { OpaqueValue::from<uint64_t>(7), OpaqueValue::from<uint64_t>(11) },
    { OpaqueValue::from<uint64_t>(9), OpaqueValue::from<uint64_t>(7) },
  };
  auto map_info = MapInfo{
    .key_type = CreateInt64(),
    .value_type = CreateInt64(),
    .detail = std::monostate{},
  };

  std::vector<TestCase> test_cases = {
    { .name = "basic_map_1",
      .top = 3,
      .div = 0,
      .expected_output = R"(basic_map_1[9]: 7
basic_map_1[3]: 10
basic_map_1[7]: 11
)" },
    { .name = "basic_map_2",
      .top = 0,
      .div = 0,

      .expected_output = R"(basic_map_2[5]: 4
basic_map_2[1]: 5
basic_map_2[9]: 7
basic_map_2[3]: 10
basic_map_2[7]: 11
)" },
    { .name = "basic_map_3",
      .top = 0,
      .div = 2,
      .expected_output = R"(basic_map_3[5]: 2
basic_map_3[1]: 2
basic_map_3[9]: 3
basic_map_3[3]: 5
basic_map_3[7]: 5
)" },
    { .name = "basic_map_4",
      .top = 3,
      .div = 2,
      .expected_output = R"(basic_map_4[9]: 3
basic_map_4[3]: 5
basic_map_4[7]: 5
)" },
  };

  for (const auto &tc : test_cases) {
    std::stringstream out;
    output::TextOutput output(out, out);
    auto bpftrace = get_mock_bpftrace();
    auto mock_map = std::make_unique<MockBpfMap>(BPF_MAP_TYPE_HASH, tc.name);
    EXPECT_CALL(*mock_map, collect_elements(testing::_))
        .WillOnce(testing::Return(testing::ByMove(MapElements(key_values))));

    bpftrace->resources.maps_info[tc.name] = map_info;
    auto val = format(*bpftrace, no_c_defs, *mock_map, tc.top, tc.div);
    EXPECT_TRUE(bool(val));
    output.map(mock_map->name(), *val);

    EXPECT_EQ(out.str(), tc.expected_output);
  }
}

TEST(bpftrace, print_max_map)
{
  struct TestCase {
    std::string name;
    uint32_t top;
    uint32_t div;
    std::string expected_output;
  };

  const MapElements key_values = {
    { OpaqueValue::from<uint64_t>(1),
      OpaqueValue::from<std::vector<uint64_t>>({ 5, true }) +
          OpaqueValue::from<std::vector<uint64_t>>({ 8, true }) +
          OpaqueValue::from<std::vector<uint64_t>>({ 3, true }) },
    { OpaqueValue::from<uint64_t>(2),
      OpaqueValue::from<std::vector<uint64_t>>({ 15, false }) +
          OpaqueValue::from<std::vector<uint64_t>>({ 0, false }) +
          OpaqueValue::from<std::vector<uint64_t>>({ 12, true }) },
    { OpaqueValue::from<uint64_t>(3),
      OpaqueValue::from<std::vector<uint64_t>>({ 100, false }) +
          OpaqueValue::from<std::vector<uint64_t>>({ 80, false }) +
          OpaqueValue::from<std::vector<uint64_t>>({ 20, true }) },
  };

  auto map_info = MapInfo{ .key_type = CreateInt64(),
                           .value_type = CreateMax(false),
                           .detail = std::monostate{} };

  std::vector<TestCase> test_cases = {
    { .name = "max_map_1",
      .top = 0,
      .div = 0,
      .expected_output = R"(max_map_1[1]: 8
max_map_1[2]: 12
max_map_1[3]: 20
)" },
    { .name = "max_map_2",
      .top = 2,
      .div = 0,
      .expected_output = R"(max_map_2[2]: 12
max_map_2[3]: 20
)" },
    { .name = "max_map_3",
      .top = 0,
      .div = 2,
      .expected_output = R"(max_map_3[1]: 4
max_map_3[2]: 6
max_map_3[3]: 10
)" },
    { .name = "max_map_4",
      .top = 2,
      .div = 2,
      .expected_output = R"(max_map_4[2]: 6
max_map_4[3]: 10
)" },
  };

  for (const auto &tc : test_cases) {
    std::stringstream out;
    output::TextOutput output(out, out);
    auto bpftrace = get_mock_bpftrace();

    bpftrace->ncpus_ = 3;
    auto mock_map = std::make_unique<MockBpfMap>(BPF_MAP_TYPE_PERCPU_HASH,
                                                 tc.name);
    EXPECT_CALL(*mock_map, collect_elements(testing::_))
        .WillOnce(testing::Return(testing::ByMove(MapElements(key_values))));

    bpftrace->resources.maps_info[tc.name] = map_info;
    auto res = format(*bpftrace, no_c_defs, *mock_map, tc.top, tc.div);
    EXPECT_TRUE(bool(res));
    output.map(mock_map->name(), *res);

    EXPECT_EQ(out.str(), tc.expected_output);
  }
}

TEST(bpftrace, print_avg_map)
{
  struct TestCase {
    std::string name;
    uint32_t top;
    uint32_t div;
    std::string expected_output;
  };

  const MapElements key_values = {
    { OpaqueValue::from<uint64_t>(1),
      OpaqueValue::from<std::vector<uint64_t>>({ 5, true }) +
          OpaqueValue::from<std::vector<uint64_t>>({ 8, true }) +
          OpaqueValue::from<std::vector<uint64_t>>({ 3, true }) },
    { OpaqueValue::from<uint64_t>(2),
      OpaqueValue::from<std::vector<uint64_t>>({ 16, true }) +
          OpaqueValue::from<std::vector<uint64_t>>({ 0, false }) +
          OpaqueValue::from<std::vector<uint64_t>>({ 12, true }) },
    { OpaqueValue::from<uint64_t>(3),
      OpaqueValue::from<std::vector<uint64_t>>({ 100, false }) +
          OpaqueValue::from<std::vector<uint64_t>>({ 80, false }) +
          OpaqueValue::from<std::vector<uint64_t>>({ 20, true }) },
  };
  auto map_info = MapInfo{ .key_type = CreateInt64(),
                           .value_type = CreateAvg(false),
                           .detail = std::monostate{} };

  std::vector<TestCase> test_cases = {
    { .name = "avg_map_1",
      .top = 0,
      .div = 0,
      .expected_output = R"(avg_map_1[1]: 5
avg_map_1[2]: 14
avg_map_1[3]: 200
)" },
    { .name = "avg_map_2",
      .top = 2,
      .div = 0,
      .expected_output = R"(avg_map_2[2]: 14
avg_map_2[3]: 200
)" },
    { .name = "avg_map_3",
      .top = 0,
      .div = 2,
      .expected_output = R"(avg_map_3[1]: 2
avg_map_3[2]: 7
avg_map_3[3]: 100
)" },
    { .name = "avg_map_4",
      .top = 2,
      .div = 2,
      .expected_output = R"(avg_map_4[2]: 7
avg_map_4[3]: 100
)" },
  };

  for (const auto &tc : test_cases) {
    std::stringstream out;
    output::TextOutput output(out, out);
    auto bpftrace = get_mock_bpftrace();

    bpftrace->ncpus_ = 3;
    auto mock_map = std::make_unique<MockBpfMap>(BPF_MAP_TYPE_PERCPU_HASH,
                                                 tc.name);
    EXPECT_CALL(*mock_map, collect_elements(testing::_))
        .WillOnce(testing::Return(testing::ByMove(MapElements(key_values))));

    bpftrace->resources.maps_info[tc.name] = map_info;
    auto res = format(*bpftrace, no_c_defs, *mock_map, tc.top, tc.div);
    EXPECT_TRUE(bool(res));
    output.map(mock_map->name(), *res);

    EXPECT_EQ(out.str(), tc.expected_output);
  }
}

TEST(bpftrace, print_map_sort_by_key)
{
  struct TestCase {
    std::string name;
    uint32_t top;
    uint32_t div;
    std::string expected_output;
  };

  const MapElements key_values = {
    { OpaqueValue::from<uint64_t>(3),
      OpaqueValue::string("hello", STRING_SIZE) },
    { OpaqueValue::from<uint64_t>(1),
      OpaqueValue::string("world", STRING_SIZE) },
    { OpaqueValue::from<uint64_t>(2),
      OpaqueValue::string("bpftrace", STRING_SIZE) },
  };

  auto map_info = MapInfo{ .key_type = CreateInt64(),
                           .value_type = CreateString(32),
                           .detail = std::monostate{} };

  std::vector<TestCase> test_cases = {
    { .name = "string_map_1",
      .top = 0,
      .div = 0,
      .expected_output = R"(string_map_1[1]: world
string_map_1[2]: bpftrace
string_map_1[3]: hello
)" },
    { .name = "string_map_2",
      .top = 2,
      .div = 0,
      .expected_output = R"(string_map_2[2]: bpftrace
string_map_2[3]: hello
)" },
    { .name = "string_map_3",
      .top = 0,
      .div = 2,
      .expected_output = R"(string_map_3[1]: world
string_map_3[2]: bpftrace
string_map_3[3]: hello
)" },
    { .name = "string_map_4",
      .top = 2,
      .div = 2,
      .expected_output = R"(string_map_4[2]: bpftrace
string_map_4[3]: hello
)" },
  };

  for (const auto &tc : test_cases) {
    std::stringstream out;
    output::TextOutput output(out, out);
    auto bpftrace = get_mock_bpftrace();

    auto mock_map = std::make_unique<MockBpfMap>(BPF_MAP_TYPE_HASH, tc.name);
    EXPECT_CALL(*mock_map, collect_elements(testing::_))
        .WillOnce(testing::Return(testing::ByMove(MapElements(key_values))));

    bpftrace->resources.maps_info[tc.name] = map_info;
    auto res = format(*bpftrace, no_c_defs, *mock_map, tc.top, tc.div);
    EXPECT_TRUE(bool(res));
    output.map(mock_map->name(), *res);

    EXPECT_EQ(out.str(), tc.expected_output);
  }
}

TEST(bpftrace, print_lhist_map)
{
  struct TestCase {
    std::string name;
    uint32_t top;
    uint32_t div;
    std::string expected_output;
  };

  const HistogramMap values_by_key = {
    { OpaqueValue::from<uint64_t>(0), { 0, 10, 20, 30, 40, 50, 0 } },
    { OpaqueValue::from<uint64_t>(1), { 0, 2, 2, 2, 2, 2, 0 } },
  };
  auto map_info = MapInfo{
    .key_type = CreateInt64(),
    .value_type = CreateLhist(),
    .detail = LinearHistogramArgs{ .min = 0, .max = 5 * 1024, .step = 1024 },
    .id = {},
  };

  std::vector<TestCase> test_cases = {
    // Test case 1: print all buckets
    { .name = "lhist_map_1",
      .top = 0,
      .div = 0,
      .expected_output = R"(lhist_map_1[1]:
[0, 1K)                2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1K, 2K)               2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[2K, 3K)               2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[3K, 4K)               2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[4K, 5K)               2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

lhist_map_1[0]:
[0, 1K)               10 |@@@@@@@@@@                                          |
[1K, 2K)              20 |@@@@@@@@@@@@@@@@@@@@                                |
[2K, 3K)              30 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     |
[3K, 4K)              40 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           |
[4K, 5K)              50 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

)" },
    // Test case 2: print top 1 bucket
    { .name = "lhist_map_2",
      .top = 1,
      .div = 0,
      .expected_output = R"(lhist_map_2[0]:
[0, 1K)               10 |@@@@@@@@@@                                          |
[1K, 2K)              20 |@@@@@@@@@@@@@@@@@@@@                                |
[2K, 3K)              30 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     |
[3K, 4K)              40 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           |
[4K, 5K)              50 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

)" },
    // Test case 3: print all buckets with div = 2
    // Note: div parameter has no effect on linear histograms.
    // Therefore, this `expected_output` is the same as `lhist_map_1`.
    { .name = "lhist_map_3",
      .top = 0,
      .div = 2,
      .expected_output = R"(lhist_map_3[1]:
[0, 1K)                2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1K, 2K)               2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[2K, 3K)               2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[3K, 4K)               2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[4K, 5K)               2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

lhist_map_3[0]:
[0, 1K)               10 |@@@@@@@@@@                                          |
[1K, 2K)              20 |@@@@@@@@@@@@@@@@@@@@                                |
[2K, 3K)              30 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     |
[3K, 4K)              40 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           |
[4K, 5K)              50 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

)" },
  };

  for (const auto &tc : test_cases) {
    std::stringstream out;
    output::TextOutput output(out, out);
    auto bpftrace = get_mock_bpftrace();

    auto mock_map = std::make_unique<MockBpfMap>(BPF_MAP_TYPE_HASH, tc.name);
    EXPECT_CALL(*mock_map, collect_histogram_data(testing::_, testing::_))
        .WillOnce(
            testing::Return(testing::ByMove(HistogramMap(values_by_key))));

    bpftrace->resources.maps_info[tc.name] = map_info;
    auto res = format(*bpftrace, no_c_defs, *mock_map, tc.top, tc.div);
    EXPECT_TRUE(bool(res));
    output.map(mock_map->name(), *res);

    EXPECT_EQ(out.str(), tc.expected_output);
  }
}

TEST(bpftrace, print_hist_map)
{
  struct TestCase {
    std::string name;
    uint32_t top;
    uint32_t div;
    std::string expected_output;
  };

  const HistogramMap values_by_key = {
    { OpaqueValue::from<uint64_t>(0), { 0, 10, 20, 30, 40, 50, 0 } },
    { OpaqueValue::from<uint64_t>(1), { 0, 2, 2, 2, 2, 2, 0 } },
  };
  auto map_info = MapInfo{ .key_type = CreateInt64(),
                           .value_type = CreateHist(),
                           .detail = HistogramArgs{ .bits = 10 },
                           .id = {} };

  std::vector<TestCase> test_cases = {
    // Test case 1: print all buckets
    { .name = "hist_map_1",
      .top = 0,
      .div = 0,
      .expected_output = R"(hist_map_1[1]:
[0]                    2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1]                    2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[2]                    2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[3]                    2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[4]                    2 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

hist_map_1[0]:
[0]                   10 |@@@@@@@@@@                                          |
[1]                   20 |@@@@@@@@@@@@@@@@@@@@                                |
[2]                   30 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     |
[3]                   40 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           |
[4]                   50 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

)" },
    // Test case 2: print top 1 bucket
    { .name = "hist_map_2",
      .top = 1,
      .div = 0,
      .expected_output = R"(hist_map_2[0]:
[0]                   10 |@@@@@@@@@@                                          |
[1]                   20 |@@@@@@@@@@@@@@@@@@@@                                |
[2]                   30 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     |
[3]                   40 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           |
[4]                   50 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

)" },
    // Test case 3: print all buckets with div = 2
    { .name = "hist_map_3",
      .top = 0,
      .div = 2,
      .expected_output = R"(hist_map_3[1]:
[0]                    1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1]                    1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[2]                    1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[3]                    1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[4]                    1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

hist_map_3[0]:
[0]                    5 |@@@@@@@@@@                                          |
[1]                   10 |@@@@@@@@@@@@@@@@@@@@                                |
[2]                   15 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     |
[3]                   20 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           |
[4]                   25 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

)" },
    // Test case 4: print top 1 bucket with div = 2
    { .name = "hist_map_4",
      .top = 1,
      .div = 2,
      .expected_output = R"(hist_map_4[0]:
[0]                    5 |@@@@@@@@@@                                          |
[1]                   10 |@@@@@@@@@@@@@@@@@@@@                                |
[2]                   15 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                     |
[3]                   20 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           |
[4]                   25 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

)" },
  };

  for (const auto &tc : test_cases) {
    std::stringstream out;
    output::TextOutput output(out, out);
    auto bpftrace = get_mock_bpftrace();

    auto mock_map = std::make_unique<MockBpfMap>(BPF_MAP_TYPE_HASH, tc.name);
    EXPECT_CALL(*mock_map, collect_histogram_data(testing::_, testing::_))
        .WillOnce(
            testing::Return(testing::ByMove(HistogramMap(values_by_key))));

    bpftrace->resources.maps_info[tc.name] = map_info;
    auto res = format(*bpftrace, no_c_defs, *mock_map, tc.top, tc.div);
    EXPECT_TRUE(bool(res));
    output.map(mock_map->name(), *res);

    EXPECT_EQ(out.str(), tc.expected_output);
  }
}

TEST(bpftrace, print_tseries_map)
{
  struct TestCase {
    std::string name;
    std::string expected_output;
  };

  constexpr uint64_t base_time_ns = 173482610888837;
  constexpr int ns_in_ms = std::chrono::nanoseconds(1ms).count();
  constexpr int interval = ns_in_ms;
  constexpr auto first_epoch = base_time_ns / interval;

  std::vector<std::pair<uint64_t, OpaqueValue>> v1 = {
    { (first_epoch + 1), OpaqueValue::from<uint64_t>(1) },
    { (first_epoch + 2), OpaqueValue::from<uint64_t>(2) },
    { (first_epoch + 3), OpaqueValue::from<uint64_t>(3) },
    { (first_epoch + 4), OpaqueValue::from<uint64_t>(4) },
    { (first_epoch + 5), OpaqueValue::from<uint64_t>(5) },
  };

  std::vector<std::pair<uint64_t, OpaqueValue>> v2 = {
    { (first_epoch + 2), OpaqueValue::from<uint64_t>(1) },
    { (first_epoch + 3), OpaqueValue::from<uint64_t>(2) },
    { (first_epoch + 4), OpaqueValue::from<uint64_t>(3) },
    { (first_epoch + 5), OpaqueValue::from<uint64_t>(4) },
    { (first_epoch + 6), OpaqueValue::from<uint64_t>(5) },
  };

  const TSeriesMap values_by_key = {
    { OpaqueValue::from<uint64_t>(0), TSeries(v1.begin(), v1.end()) },
    { OpaqueValue::from<uint64_t>(1), TSeries(v2.begin(), v2.end()) },
  };

  auto map_info = MapInfo{ .key_type = CreateInt64(),
                           .value_type = CreateTSeries(),
                           .detail = TSeriesArgs{ .interval_ns = ns_in_ms,
                                                  .num_intervals = 5,
                                                  .value_type = CreateInt64(),
                                                  .agg = TSeriesAggFunc::none },
                           .id = {},
                           .is_scalar = false };

  std::vector<TestCase> test_cases = {
    { .name = "tseries_map_1", .expected_output = R"(tseries_map_1[0]:
             2                                                   5
hh:mm:ss.ms  |___________________________________________________|
%H:%M:22.612 *                                                   | 2
%H:%M:22.613 |                *                                  | 3
%H:%M:22.614 |                                 *                 | 4
%H:%M:22.615 |                                                   * 5
%H:%M:22.616 |                                                   | -
             v___________________________________________________v
             2                                                   5

tseries_map_1[1]:
             1                                                   5
hh:mm:ss.ms  |___________________________________________________|
%H:%M:22.612 *                                                   | 1
%H:%M:22.613 |            *                                      | 2
%H:%M:22.614 |                         *                         | 3
%H:%M:22.615 |                                      *            | 4
%H:%M:22.616 |                                                   * 5
             v___________________________________________________v
             1                                                   5

)" },
  };

  for (const auto &tc : test_cases) {
    std::stringstream out;
    output::TextOutput output(out, out);
    auto bpftrace = get_mock_bpftrace();

    auto mock_map = std::make_unique<MockBpfMap>(BPF_MAP_TYPE_HASH, tc.name);
    EXPECT_CALL(*mock_map, collect_tseries_data(testing::_, testing::_))
        .WillOnce(testing::Return(testing::ByMove(TSeriesMap(values_by_key))));

    bpftrace->resources.maps_info[tc.name] = map_info;
    auto val = format(*bpftrace, no_c_defs, *mock_map);
    EXPECT_TRUE(bool(val));
    output.map(mock_map->name(), *val);

    // Make sure strftime doesn't return 0, because the format string is too
    // long.
    bpftrace->config_->max_strlen = tc.expected_output.length() + 1;

    EXPECT_EQ(out.str(),
              bpftrace->format_timestamp(
                  bpftrace->resolve_timestamp(
                      static_cast<uint32_t>(TimestampMode::tai), base_time_ns),
                  tc.expected_output,
                  false));
  }
}

} // namespace bpftrace::test::bpftrace
