#include <chrono>
#include <cstdint>
#include <cstring>

#include "ast/attachpoint_parser.h"
#include "ast/passes/clang_parser.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/probe_expansion.h"
#include "ast/passes/semantic_analyser.h"
#include "ast/passes/type_system.h"
#include "bpfmap.h"
#include "bpftrace.h"
#include "btf_common.h"
#include "driver.h"
#include "mocks.h"
#include "output/text.h"
#include "tracefs/tracefs.h"
#include "types.h"
#include "types_format.h"
#include "gmock/gmock-matchers.h"
#include "gmock/gmock-nice-strict.h"
#include "gtest/gtest.h"

using namespace std::chrono_literals;

namespace bpftrace::test::bpftrace {

using ::testing::ContainerEq;
using ::testing::Contains;
using ::testing::StrictMock;

static const int STRING_SIZE = 64;

static const std::optional<int> no_pid = std::nullopt;

static ast::CDefinitions no_c_defs; // Not used for tests.

template <typename K, typename V>
MapElements generate_kv_pairs(const std::vector<K> &keys,
                              const std::vector<V> &values)
{
  MapElements kv_pairs;
  for (size_t i = 0; i < keys.size() && i < values.size(); ++i) {
    std::vector<uint8_t> key_bytes(sizeof(K));
    std::vector<uint8_t> value_bytes(sizeof(V));
    memcpy(key_bytes.data(), &keys[i], sizeof(K));
    memcpy(value_bytes.data(), &values[i], sizeof(V));
    kv_pairs.emplace_back(key_bytes, value_bytes);
  }
  return kv_pairs;
}

template <typename K>
MapElements generate_kv_pairs(const std::vector<K> &keys,
                              const std::vector<std::string> &values)
{
  MapElements kv_pairs;
  for (size_t i = 0; i < keys.size() && i < values.size(); ++i) {
    std::vector<uint8_t> key_bytes(sizeof(K));
    memcpy(key_bytes.data(), &keys[i], sizeof(K));
    std::vector<uint8_t> value_bytes(values[i].size() + 1);
    std::copy(values[i].begin(), values[i].end(), value_bytes.begin());
    value_bytes[values[i].size()] = '\0';
    kv_pairs.emplace_back(key_bytes, value_bytes);
  }
  return kv_pairs;
}

template <typename K>
MapElements generate_kv_pairs(const std::vector<K> &keys,
                              const std::vector<std::vector<uint8_t>> &values)
{
  MapElements kv_pairs;
  for (size_t i = 0; i < keys.size() && i < values.size(); ++i) {
    std::vector<uint8_t> key_bytes(sizeof(K));
    memcpy(key_bytes.data(), &keys[i], sizeof(K));
    kv_pairs.emplace_back(key_bytes, values[i]);
  }
  return kv_pairs;
}

std::vector<uint8_t> generate_percpu_data(
    const std::vector<std::pair<uint64_t, bool>> &values)
{
  std::vector<uint8_t> value;

  value.resize(values.size() * (sizeof(uint64_t) * 2), 0);
  for (size_t i = 0; i < values.size(); i++) {
    auto is_set = static_cast<uint32_t>(values[i].second);
    std::memcpy(value.data() + (i * (sizeof(uint64_t) * 2)),
                &values[i].first,
                sizeof(uint64_t));
    std::memcpy(value.data() +
                    (sizeof(uint64_t) + (i * (sizeof(uint64_t) * 2))),
                &is_set,
                sizeof(uint32_t));
  }
  return value;
}

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

static auto parse_probe(const std::string &str,
                        BPFtrace &bpftrace,
                        int usdt_num_locations = 0)
{
  ast::ASTContext ast("stdin", str);

  ast::TypeMetadata no_types; // No external types defined.

  // N.B. Don't use tracepoint format parser here.
  auto usdt = get_mock_usdt_helper(usdt_num_locations);
  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .put(no_types)
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateProbeExpansionPass())
                .add(ast::CreateFieldAnalyserPass())
                .add(ast::CreateClangParsePass())
                .add(ast::CreateMapSugarPass())
                .add(ast::CreateSemanticPass())
                .add(ast::CreateLLVMInitPass())
                .add(ast::CreateCompilePass(std::ref(*usdt)))
                .run();
  ASSERT_TRUE(ok && ast.diagnostics().ok());
}

void check_kprobe(Probe &p,
                  const std::string &attach_point,
                  const std::string &orig_name,
                  uint64_t func_offset = 0,
                  const std::string &target = "")
{
  EXPECT_EQ(ProbeType::kprobe, p.type);
  EXPECT_EQ(attach_point, p.attach_point);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ(kprobe_name(attach_point, target, func_offset), p.name);
  EXPECT_EQ(func_offset, p.func_offset);
  EXPECT_TRUE(p.funcs.empty());
}

void check_kprobe_multi(Probe &p,
                        const std::vector<std::string> &funcs,
                        const std::string &orig_name,
                        const std::string &name)
{
  EXPECT_EQ(ProbeType::kprobe, p.type);
  EXPECT_EQ(funcs, p.funcs);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ(name, p.name);
}

void check_uprobe(Probe &p,
                  const std::string &path,
                  const std::string &attach_point,
                  const std::string &orig_name,
                  const std::string &name,
                  uint64_t address = 0,
                  uint64_t func_offset = 0)
{
  bool retprobe = orig_name.starts_with("uretprobe:") ||
                  orig_name.starts_with("ur:");
  EXPECT_EQ(retprobe ? ProbeType::uretprobe : ProbeType::uprobe, p.type);
  EXPECT_EQ(path, p.path);
  EXPECT_EQ(attach_point, p.attach_point);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ(name, p.name);
  EXPECT_EQ(address, p.address);
  EXPECT_EQ(func_offset, p.func_offset);
  EXPECT_TRUE(p.funcs.empty());
}

void check_uprobe_multi(Probe &p,
                        const std::string &path,
                        const std::vector<std::string> &funcs,
                        const std::string &orig_name,
                        const std::string &name)
{
  bool retprobe = orig_name.starts_with("uretprobe:") ||
                  orig_name.starts_with("ur:");
  EXPECT_EQ(retprobe ? ProbeType::uretprobe : ProbeType::uprobe, p.type);
  EXPECT_EQ(path, p.path);
  EXPECT_EQ(funcs, p.funcs);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ(name, p.name);
}

void check_usdt(Probe &p,
                const std::string &path,
                const std::string &provider,
                const std::string &attach_point,
                const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::usdt, p.type);
  EXPECT_EQ(attach_point, p.attach_point);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ("usdt:" + path + ":" + provider + ":" + attach_point, p.name);
}

void check_tracepoint(Probe &p,
                      const std::string &target,
                      const std::string &func,
                      const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::tracepoint, p.type);
  EXPECT_EQ(func, p.attach_point);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ("tracepoint:" + target + ":" + func, p.name);
}

void check_profile(Probe &p,
                   const std::string &unit,
                   int freq,
                   const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::profile, p.type);
  EXPECT_EQ(freq, p.freq);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ("profile:" + unit + ":" + std::to_string(freq), p.name);
}

void check_interval(Probe &p,
                    const std::string &unit,
                    int freq,
                    const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::interval, p.type);
  EXPECT_EQ(freq, p.freq);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ("interval:" + unit + ":" + std::to_string(freq), p.name);
}

void check_software(Probe &p,
                    const std::string &unit,
                    int freq,
                    const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::software, p.type);
  EXPECT_EQ(freq, p.freq);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ("software:" + unit + ":" + std::to_string(freq), p.name);
}

void check_hardware(Probe &p,
                    const std::string &unit,
                    int freq,
                    const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::hardware, p.type);
  EXPECT_EQ(freq, p.freq);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ("hardware:" + unit + ":" + std::to_string(freq), p.name);
}

void check_special_probe(Probe &p, const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::special, p.type);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ(orig_name, p.name);
}

void check_benchmark_probe(Probe &p,
                           const std::string &orig_name,
                           const std::string &bench_name)
{
  EXPECT_EQ(ProbeType::benchmark, p.type);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ(orig_name, p.name);
  EXPECT_EQ(bench_name, p.path);
}

TEST(bpftrace, add_begin_probe)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("BEGIN{}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(1U, bpftrace->get_special_probes().size());

  check_special_probe(bpftrace->get_special_probes()["BEGIN"], "BEGIN");
}

TEST(bpftrace, add_end_probe)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("END{}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(1U, bpftrace->get_special_probes().size());

  check_special_probe(bpftrace->get_special_probes()["END"], "END");
}

TEST(bpftrace, add_bench_probes)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("BENCH:a{} BENCH:b{} BENCH:c{}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  ASSERT_EQ(3U, bpftrace->get_benchmark_probes().size());

  check_benchmark_probe(bpftrace->get_benchmark_probes().at(0), "BENCH:a", "a");
  check_benchmark_probe(bpftrace->get_benchmark_probes().at(1), "BENCH:b", "b");
  check_benchmark_probe(bpftrace->get_benchmark_probes().at(2), "BENCH:c", "c");
}

TEST(bpftrace, add_probes_single)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("kprobe:sys_read {}", *bpftrace);
  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_kprobe(bpftrace->get_probes().at(0), "sys_read", "kprobe:sys_read");
}

TEST(bpftrace, add_probes_multiple)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("kprobe:sys_read,kprobe:sys_write{}", *bpftrace);
  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "kprobe:sys_read,kprobe:sys_write";
  check_kprobe(bpftrace->get_probes().at(0), "sys_read", probe_orig_name);
  check_kprobe(bpftrace->get_probes().at(1), "sys_write", probe_orig_name);
}

TEST(bpftrace, add_probes_wildcard)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(false);
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_traceable_funcs(false))
      .Times(1);

  parse_probe("kprobe:sys_read,kprobe:my_*,kprobe:sys_write{}", *bpftrace);

  ASSERT_EQ(4U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "kprobe:sys_read,kprobe:my_*,kprobe:sys_write";
  check_kprobe(bpftrace->get_probes().at(0), "sys_read", probe_orig_name);
  check_kprobe(bpftrace->get_probes().at(1), "my_one", probe_orig_name);
  check_kprobe(bpftrace->get_probes().at(2), "my_two", probe_orig_name);
  check_kprobe(bpftrace->get_probes().at(3), "sys_write", probe_orig_name);
}

TEST(bpftrace, add_probes_wildcard_kprobe_multi)
{
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_traceable_funcs(false))
      .Times(2);

  parse_probe("kprobe:sys_read,kprobe:my_*,kprobe:sys_write{}", *bpftrace);

  ASSERT_EQ(3U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "kprobe:sys_read,kprobe:my_*,kprobe:sys_write";
  check_kprobe(bpftrace->get_probes().at(0), "sys_read", probe_orig_name);
  check_kprobe_multi(bpftrace->get_probes().at(1),
                     { "my_one", "my_two" },
                     probe_orig_name,
                     "kprobe:my_*");
  check_kprobe(bpftrace->get_probes().at(2), "sys_write", probe_orig_name);
}

TEST(bpftrace, add_probes_probe_builtin)
{
  auto bpftrace = get_mock_bpftrace();

  parse_probe("kprobe:sys_read,kprobe:my_*,kprobe:sys_write { probe }",
              *bpftrace);

  // Even though kprobe_multi is enabled, we should get full expansion due to
  // using the "probe" builtin.
  ASSERT_EQ(4U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "kprobe:sys_read,kprobe:my_*,kprobe:sys_write";
  check_kprobe(bpftrace->get_probes().at(0), "sys_read", probe_orig_name);
  check_kprobe(bpftrace->get_probes().at(1), "my_one", probe_orig_name);
  check_kprobe(bpftrace->get_probes().at(2), "my_two", probe_orig_name);
  check_kprobe(bpftrace->get_probes().at(3), "sys_write", probe_orig_name);
}

TEST(bpftrace, add_probes_wildcard_no_matches)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(false);
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_traceable_funcs(false))
      .Times(1);

  parse_probe("kprobe:sys_read,kprobe:not_here_*,kprobe:sys_write{}",
              *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name =
      "kprobe:sys_read,kprobe:not_here_*,kprobe:sys_write";
  check_kprobe(bpftrace->get_probes().at(0), "sys_read", probe_orig_name);
  check_kprobe(bpftrace->get_probes().at(1), "sys_write", probe_orig_name);
}

TEST(bpftrace, add_probes_wildcard_no_matches_kprobe_multi)
{
  auto bpftrace = get_strict_mock_bpftrace();

  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_traceable_funcs(false))
      .Times(1);

  parse_probe("kprobe:sys_read,kprobe:not_here_*,kprobe:sys_write{}",
              *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name =
      "kprobe:sys_read,kprobe:not_here_*,kprobe:sys_write";
  check_kprobe(bpftrace->get_probes().at(0), "sys_read", probe_orig_name);
  check_kprobe(bpftrace->get_probes().at(1), "sys_write", probe_orig_name);
}

TEST(bpftrace, add_probes_kernel_module)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("kprobe:func_in_mod{}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "kprobe:func_in_mod";
  check_kprobe(bpftrace->get_probes().at(0), "func_in_mod", probe_orig_name);
}

TEST(bpftrace, add_probes_specify_kernel_module)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("kprobe:kernel_mod:func_in_mod{}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "kprobe:kernel_mod:func_in_mod";
  check_kprobe(bpftrace->get_probes().at(0),
               "func_in_mod",
               probe_orig_name,
               0,
               "kernel_mod");
}

TEST(bpftrace, add_probes_kernel_module_wildcard)
{
  auto bpftrace = get_strict_mock_bpftrace();
  // We enable kprobe_multi here but it doesn't support the module:function
  // syntax so full expansion should be done anyways.

  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_traceable_funcs(true))
      .Times(1);

  parse_probe("kprobe:*kernel_mod:* {}", *bpftrace);

  ASSERT_EQ(3U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "kprobe:*kernel_mod:*";
  check_kprobe(bpftrace->get_probes().at(0),
               "func_in_mod",
               probe_orig_name,
               0,
               "kernel_mod");
  check_kprobe(bpftrace->get_probes().at(1),
               "other_func_in_mod",
               probe_orig_name,
               0,
               "kernel_mod");
  check_kprobe(bpftrace->get_probes().at(2),
               "func_in_mod",
               probe_orig_name,
               0,
               "other_kernel_mod");
}

TEST(bpftrace, add_probes_kernel_module_function_wildcard)
{
  auto bpftrace = get_strict_mock_bpftrace();
  // We enable kprobe_multi here but it doesn't support the module:function
  // syntax so full expansion should be done anyways.

  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_traceable_funcs(true))
      .Times(1);

  parse_probe("kprobe:kernel_mod:*func_in_mod {}", *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "kprobe:kernel_mod:*func_in_mod";
  check_kprobe(bpftrace->get_probes().at(0),
               "func_in_mod",
               probe_orig_name,
               0,
               "kernel_mod");
  check_kprobe(bpftrace->get_probes().at(1),
               "other_func_in_mod",
               probe_orig_name,
               0,
               "kernel_mod");
}

TEST(bpftrace, add_probes_offset)
{
  auto offset = 10;
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("kprobe:sys_read+10{}", *bpftrace);
  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "kprobe:sys_read+" + std::to_string(offset);
  check_kprobe(
      bpftrace->get_probes().at(0), "sys_read", probe_orig_name, offset);
}

TEST(bpftrace, add_probes_uprobe)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("uprobe:/bin/sh:foo {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  check_uprobe(bpftrace->get_probes().at(0),
               "/bin/sh",
               "foo",
               "uprobe:/bin/sh:foo",
               "uprobe:/bin/sh:foo");
}

TEST(bpftrace, add_probes_uprobe_wildcard)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(false);
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file(no_pid, "/bin/sh"))
      .Times(1);

  parse_probe("uprobe:/bin/sh:*open {}", *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "uprobe:/bin/sh:*open";
  check_uprobe(bpftrace->get_probes().at(0),
               "/bin/sh",
               "first_open",
               probe_orig_name,
               "uprobe:/bin/sh:first_open");
  check_uprobe(bpftrace->get_probes().at(1),
               "/bin/sh",
               "second_open",
               probe_orig_name,
               "uprobe:/bin/sh:second_open");
}

TEST(bpftrace, add_probes_uprobe_wildcard_uprobe_multi)
{
  auto bpftrace = get_strict_mock_bpftrace();

  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file(no_pid, "/bin/sh"))
      .Times(2);

  parse_probe("uprobe:/bin/sh:*open {}", *bpftrace);

  std::string probe_orig_name = "uprobe:/bin/sh:*open";
  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_uprobe_multi(bpftrace->get_probes().at(0),
                     "/bin/sh",
                     { "/bin/sh:first_open", "/bin/sh:second_open" },
                     probe_orig_name,
                     probe_orig_name);
}

TEST(bpftrace, add_probes_uprobe_wildcard_file)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(false);
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file(no_pid, "/bin/*sh"))
      .Times(1);

  parse_probe("uprobe:/bin/*sh:*open {}", *bpftrace);

  ASSERT_EQ(3U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "uprobe:/bin/*sh:*open";
  check_uprobe(bpftrace->get_probes().at(0),
               "/bin/bash",
               "first_open",
               probe_orig_name,
               "uprobe:/bin/bash:first_open");
  check_uprobe(bpftrace->get_probes().at(1),
               "/bin/sh",
               "first_open",
               probe_orig_name,
               "uprobe:/bin/sh:first_open");
  check_uprobe(bpftrace->get_probes().at(2),
               "/bin/sh",
               "second_open",
               probe_orig_name,
               "uprobe:/bin/sh:second_open");
}

TEST(bpftrace, add_probes_uprobe_wildcard_file_uprobe_multi)
{
  auto bpftrace = get_strict_mock_bpftrace();

  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file(no_pid, "/bin/*sh"))
      .Times(2);

  parse_probe("uprobe:/bin/*sh:*open {}", *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "uprobe:/bin/*sh:*open";
  check_uprobe_multi(bpftrace->get_probes().at(0),
                     "/bin/sh",
                     { "/bin/sh:first_open", "/bin/sh:second_open" },
                     probe_orig_name,
                     "uprobe:/bin/sh:*open");
  check_uprobe_multi(bpftrace->get_probes().at(1),
                     "/bin/bash",
                     { "/bin/bash:first_open" },
                     probe_orig_name,
                     "uprobe:/bin/bash:*open");
}

TEST(bpftrace, add_probes_uprobe_wildcard_no_matches)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(false);
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file(no_pid, "/bin/sh"))
      .Times(1);

  parse_probe("uprobe:/bin/sh:foo* {}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
}

TEST(bpftrace, add_probes_uprobe_wildcard_no_matches_multi)
{
  auto bpftrace = get_strict_mock_bpftrace();

  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file(no_pid, "/bin/sh"))
      .Times(1);

  parse_probe("uprobe:/bin/sh:foo* {}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
}

TEST(bpftrace, add_probes_uprobe_address)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("uprobe:/bin/sh:1024 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  check_uprobe(bpftrace->get_probes().at(0),
               "/bin/sh",
               "",
               "uprobe:/bin/sh:1024",
               "uprobe:/bin/sh:1024",
               1024);
}

TEST(bpftrace, add_probes_uprobe_string_offset)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("uprobe:/bin/sh:foo+10{}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  check_uprobe(bpftrace->get_probes().at(0),
               "/bin/sh",
               "foo",
               "uprobe:/bin/sh:foo+10",
               "uprobe:/bin/sh:foo+10",
               0,
               10);
}

TEST(bpftrace, add_probes_uprobe_cpp_symbol)
{
  for (const std::string provider : { "uprobe", "uretprobe" }) {
    auto bpftrace = get_strict_mock_bpftrace();
    bpftrace->feature_ = std::make_unique<MockBPFfeature>(false);
    EXPECT_CALL(*bpftrace->mock_probe_matcher,
                get_func_symbols_from_file(no_pid, "/bin/sh"))
        .Times(1);

    std::string prog = provider + ":/bin/sh:cpp:cpp_mangled{}";
    parse_probe(prog, *bpftrace);

    ASSERT_EQ(3U, bpftrace->get_probes().size());
    ASSERT_EQ(0U, bpftrace->get_special_probes().size());
    check_uprobe(bpftrace->get_probes().at(0),
                 "/bin/sh",
                 "_Z11cpp_mangledi",
                 provider + ":/bin/sh:cpp:cpp_mangled",
                 provider + ":/bin/sh:cpp:_Z11cpp_mangledi");
    check_uprobe(bpftrace->get_probes().at(1),
                 "/bin/sh",
                 "_Z11cpp_mangledv",
                 provider + ":/bin/sh:cpp:cpp_mangled",
                 provider + ":/bin/sh:cpp:_Z11cpp_mangledv");
    check_uprobe(bpftrace->get_probes().at(2),
                 "/bin/sh",
                 "cpp_mangled",
                 provider + ":/bin/sh:cpp:cpp_mangled",
                 provider + ":/bin/sh:cpp:cpp_mangled");
  }
}

TEST(bpftrace, add_probes_uprobe_cpp_symbol_full)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(false);
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file(no_pid, "/bin/sh"))
      .Times(1);

  parse_probe("uprobe:/bin/sh:cpp:\"cpp_mangled(int)\"{}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  check_uprobe(bpftrace->get_probes().at(0),
               "/bin/sh",
               "_Z11cpp_mangledi",
               "uprobe:/bin/sh:cpp:\"cpp_mangled(int)\"",
               "uprobe:/bin/sh:cpp:_Z11cpp_mangledi");
}

TEST(bpftrace, add_probes_uprobe_cpp_symbol_wildcard)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(false);
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file(no_pid, "/bin/sh"))
      .Times(1);

  parse_probe("uprobe:/bin/sh:cpp:cpp_man*{}", *bpftrace);

  ASSERT_EQ(4U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_uprobe(bpftrace->get_probes().at(0),
               "/bin/sh",
               "_Z11cpp_mangledi",
               "uprobe:/bin/sh:cpp:cpp_man*",
               "uprobe:/bin/sh:cpp:_Z11cpp_mangledi");
  check_uprobe(bpftrace->get_probes().at(1),
               "/bin/sh",
               "_Z11cpp_mangledv",
               "uprobe:/bin/sh:cpp:cpp_man*",
               "uprobe:/bin/sh:cpp:_Z11cpp_mangledv");
  check_uprobe(bpftrace->get_probes().at(2),
               "/bin/sh",
               "_Z18cpp_mangled_suffixv",
               "uprobe:/bin/sh:cpp:cpp_man*",
               "uprobe:/bin/sh:cpp:_Z18cpp_mangled_suffixv");
  check_uprobe(bpftrace->get_probes().at(3),
               "/bin/sh",
               "cpp_mangled",
               "uprobe:/bin/sh:cpp:cpp_man*",
               "uprobe:/bin/sh:cpp:cpp_mangled");
}

TEST(bpftrace, add_probes_uprobe_no_demangling)
{
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file(no_pid, "/bin/sh"))
      .Times(0);

  // Without the :cpp prefix, only look for non-mangled "cpp_mangled" symbol
  parse_probe("uprobe:/bin/sh:cpp_mangled {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  check_uprobe(bpftrace->get_probes().at(0),
               "/bin/sh",
               "cpp_mangled",
               "uprobe:/bin/sh:cpp_mangled",
               "uprobe:/bin/sh:cpp_mangled");
}

TEST(bpftrace, add_probes_usdt)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("usdt:/bin/sh:prov1:mytp {}", *bpftrace, 1);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  check_usdt(bpftrace->get_probes().at(0),
             "/bin/sh",
             "prov1",
             "mytp",
             "usdt:/bin/sh:prov1:mytp");
}

TEST(bpftrace, add_probes_usdt_wildcard)
{
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_usdt(no_pid, "/bin/*sh"))
      .Times(1);

  parse_probe("usdt:/bin/*sh:prov*:tp* {}", *bpftrace, 1);

  ASSERT_EQ(4U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  const std::string orig_name = "usdt:/bin/*sh:prov*:tp*";
  check_usdt(
      bpftrace->get_probes().at(0), "/bin/bash", "prov1", "tp3", orig_name);
  check_usdt(
      bpftrace->get_probes().at(1), "/bin/sh", "prov1", "tp1", orig_name);
  check_usdt(
      bpftrace->get_probes().at(2), "/bin/sh", "prov1", "tp2", orig_name);
  check_usdt(bpftrace->get_probes().at(3), "/bin/sh", "prov2", "tp", orig_name);
}

TEST(bpftrace, add_probes_usdt_empty_namespace)
{
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_usdt(no_pid, "/bin/sh"))
      .Times(1);

  parse_probe("usdt:/bin/sh:tp1 {}", *bpftrace, 1);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  check_usdt(bpftrace->get_probes().at(0),
             "/bin/sh",
             "prov1",
             "tp1",
             "usdt:/bin/sh:tp1");
}

TEST(bpftrace, add_probes_usdt_empty_namespace_conflict)
{
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_usdt(no_pid, "/bin/sh"))
      .Times(1);

  parse_probe("usdt:/bin/sh:tp {}", *bpftrace, 1);
}

TEST(bpftrace, add_probes_usdt_duplicate_markers)
{
  auto bpftrace = get_strict_mock_bpftrace();

  parse_probe("usdt:/bin/sh:prov1:mytp {}", *bpftrace, 3);

  ASSERT_EQ(3U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  check_usdt(bpftrace->get_probes().at(0),
             "/bin/sh",
             "prov1",
             "mytp",
             "usdt:/bin/sh:prov1:mytp");
  check_usdt(bpftrace->get_probes().at(1),
             "/bin/sh",
             "prov1",
             "mytp",
             "usdt:/bin/sh:prov1:mytp");
  check_usdt(bpftrace->get_probes().at(2),
             "/bin/sh",
             "prov1",
             "mytp",
             "usdt:/bin/sh:prov1:mytp");
}

TEST(bpftrace, add_probes_tracepoint)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("tracepoint:sched:sched_switch {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "tracepoint:sched:sched_switch";
  check_tracepoint(
      bpftrace->get_probes().at(0), "sched", "sched_switch", probe_orig_name);
}

TEST(bpftrace, add_probes_tracepoint_wildcard)
{
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_file(tracefs::available_events()))
      .Times(1);

  parse_probe("tracepoint:sched:sched_* {}", *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "tracepoint:sched:sched_*";
  check_tracepoint(
      bpftrace->get_probes().at(0), "sched", "sched_one", probe_orig_name);
  check_tracepoint(
      bpftrace->get_probes().at(1), "sched", "sched_two", probe_orig_name);
}

TEST(bpftrace, add_probes_tracepoint_category_wildcard)
{
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_file(tracefs::available_events()))
      .Times(1);

  parse_probe("tracepoint:sched*:sched_* {}", *bpftrace);

  ASSERT_EQ(3U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "tracepoint:sched*:sched_*";
  check_tracepoint(
      bpftrace->get_probes().at(0), "sched", "sched_one", probe_orig_name);
  check_tracepoint(
      bpftrace->get_probes().at(1), "sched", "sched_two", probe_orig_name);
  check_tracepoint(bpftrace->get_probes().at(2),
                   "sched_extra",
                   "sched_extra",
                   probe_orig_name);
}

TEST(bpftrace, add_probes_tracepoint_wildcard_no_matches)
{
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_file(tracefs::available_events()))
      .Times(1);

  parse_probe("tracepoint:type:typo_* {}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
}

TEST(bpftrace, add_probes_profile)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("profile:ms:997 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "profile:ms:997";
  check_profile(bpftrace->get_probes().at(0), "ms", 997, probe_orig_name);
}

TEST(bpftrace, add_probes_interval)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("i:s:1 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "i:s:1";
  check_interval(bpftrace->get_probes().at(0), "s", 1, probe_orig_name);
}

TEST(bpftrace, add_probes_software)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("software:faults:1000 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "software:faults:1000";
  check_software(bpftrace->get_probes().at(0), "faults", 1000, probe_orig_name);
}

TEST(bpftrace, add_probes_hardware)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("hardware:cache-references:1000000 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "hardware:cache-references:1000000";
  check_hardware(bpftrace->get_probes().at(0),
                 "cache-references",
                 1000000,
                 probe_orig_name);
}

TEST(bpftrace, trailing_comma)
{
  ast::ASTContext ast("stdin", "kprobe:f1, {}");
  Driver driver(ast);

  // Trailing comma is fine
  driver.parse_program();
  ASSERT_TRUE(ast.diagnostics().ok());
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
  ast::AttachPointParser ap_parser(ast, bpftrace, false);
  ap_parser.parse();
  EXPECT_FALSE(ast.diagnostics().ok());
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> key_value_pair_int(
    std::vector<uint64_t> key,
    int val)
{
  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> pair;
  pair.first = std::vector<uint8_t>(sizeof(uint64_t) * key.size());
  pair.second = std::vector<uint8_t>(sizeof(uint64_t));

  uint8_t *key_data = pair.first.data();
  uint8_t *val_data = pair.second.data();

  for (size_t i = 0; i < key.size(); i++) {
    uint64_t k = key.at(i);
    std::memcpy(key_data + (sizeof(uint64_t) * i), &k, sizeof(k));
  }
  uint64_t v = val;
  std::memcpy(val_data, &v, sizeof(v));

  return pair;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> key_value_pair_str(
    std::vector<std::string> key,
    int val)
{
  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> pair;
  pair.first = std::vector<uint8_t>(STRING_SIZE * key.size());
  pair.second = std::vector<uint8_t>(sizeof(uint64_t));

  uint8_t *key_data = pair.first.data();
  uint8_t *val_data = pair.second.data();

  for (size_t i = 0; i < key.size(); i++) {
    strncpy(reinterpret_cast<char *>(key_data) + (STRING_SIZE * i),
            key.at(i).c_str(),
            STRING_SIZE);
  }
  uint64_t v = val;
  std::memcpy(val_data, &v, sizeof(v));

  return pair;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> key_value_pair_int_str(
    int myint,
    std::string mystr,
    int val)
{
  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> pair;
  pair.first = std::vector<uint8_t>(sizeof(uint64_t) + STRING_SIZE);
  pair.second = std::vector<uint8_t>(sizeof(uint64_t));

  uint8_t *key_data = pair.first.data();
  uint8_t *val_data = pair.second.data();

  uint64_t k = myint, v = val;
  std::memcpy(key_data, &k, sizeof(k));
  strncpy(reinterpret_cast<char *>(key_data) + sizeof(uint64_t),
          mystr.c_str(),
          STRING_SIZE);
  std::memcpy(val_data, &v, sizeof(v));

  return pair;
}

TEST(bpftrace, sort_by_key_int)
{
  auto bpftrace = get_strict_mock_bpftrace();

  SizedType key_arg = CreateUInt64();
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      values_by_key = {
        key_value_pair_int({ 2 }, 12),
        key_value_pair_int({ 3 }, 11),
        key_value_pair_int({ 1 }, 10),
      };
  sort_by_key(key_arg, values_by_key);

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      expected_values = {
        key_value_pair_int({ 1 }, 10),
        key_value_pair_int({ 2 }, 12),
        key_value_pair_int({ 3 }, 11),
      };

  EXPECT_THAT(values_by_key, ContainerEq(expected_values));
}

TEST(bpftrace, sort_by_key_int_int)
{
  auto bpftrace = get_strict_mock_bpftrace();

  SizedType key = CreateTuple(
      Struct::CreateTuple({ CreateInt64(), CreateInt64(), CreateInt64() }));

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      values_by_key = {
        key_value_pair_int({ 5, 2, 1 }, 1), key_value_pair_int({ 5, 3, 1 }, 2),
        key_value_pair_int({ 5, 1, 1 }, 3), key_value_pair_int({ 2, 2, 2 }, 4),
        key_value_pair_int({ 2, 3, 2 }, 5), key_value_pair_int({ 2, 1, 2 }, 6),
      };
  sort_by_key(key, values_by_key);

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      expected_values = {
        key_value_pair_int({ 2, 1, 2 }, 6), key_value_pair_int({ 2, 2, 2 }, 4),
        key_value_pair_int({ 2, 3, 2 }, 5), key_value_pair_int({ 5, 1, 1 }, 3),
        key_value_pair_int({ 5, 2, 1 }, 1), key_value_pair_int({ 5, 3, 1 }, 2),
      };

  EXPECT_THAT(values_by_key, ContainerEq(expected_values));
}

TEST(bpftrace, sort_by_key_str)
{
  auto bpftrace = get_strict_mock_bpftrace();

  SizedType key_arg = CreateString(STRING_SIZE);
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      values_by_key = {
        key_value_pair_str({ "z" }, 1),
        key_value_pair_str({ "a" }, 2),
        key_value_pair_str({ "x" }, 3),
        key_value_pair_str({ "d" }, 4),
      };
  sort_by_key(key_arg, values_by_key);

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      expected_values = {
        key_value_pair_str({ "a" }, 2),
        key_value_pair_str({ "d" }, 4),
        key_value_pair_str({ "x" }, 3),
        key_value_pair_str({ "z" }, 1),
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

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      values_by_key = {
        key_value_pair_str({ "z", "a", "l" }, 1),
        key_value_pair_str({ "a", "a", "m" }, 2),
        key_value_pair_str({ "z", "c", "n" }, 3),
        key_value_pair_str({ "a", "c", "o" }, 4),
        key_value_pair_str({ "z", "b", "p" }, 5),
        key_value_pair_str({ "a", "b", "q" }, 6),
      };
  sort_by_key(key, values_by_key);

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      expected_values = {
        key_value_pair_str({ "a", "a", "m" }, 2),
        key_value_pair_str({ "a", "b", "q" }, 6),
        key_value_pair_str({ "a", "c", "o" }, 4),
        key_value_pair_str({ "z", "a", "l" }, 1),
        key_value_pair_str({ "z", "b", "p" }, 5),
        key_value_pair_str({ "z", "c", "n" }, 3),
      };

  EXPECT_THAT(values_by_key, ContainerEq(expected_values));
}

TEST(bpftrace, sort_by_key_int_str)
{
  auto bpftrace = get_strict_mock_bpftrace();

  SizedType key = CreateTuple(
      Struct::CreateTuple({ CreateUInt64(), CreateString(STRING_SIZE) }));

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      values_by_key = {
        key_value_pair_int_str(1, "b", 1), key_value_pair_int_str(2, "b", 2),
        key_value_pair_int_str(3, "b", 3), key_value_pair_int_str(1, "a", 4),
        key_value_pair_int_str(2, "a", 5), key_value_pair_int_str(3, "a", 6),
      };
  sort_by_key(key, values_by_key);

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      expected_values = {
        key_value_pair_int_str(1, "a", 4), key_value_pair_int_str(1, "b", 1),
        key_value_pair_int_str(2, "a", 5), key_value_pair_int_str(2, "b", 2),
        key_value_pair_int_str(3, "a", 6), key_value_pair_int_str(3, "b", 3),
      };

  EXPECT_THAT(values_by_key, ContainerEq(expected_values));
}

class bpftrace_btf : public test_btf {};

void check_probe(Probe &p, ProbeType type, const std::string &name)
{
  EXPECT_EQ(type, p.type);
  EXPECT_EQ(name, p.name);
}

void check_kprobe_session(Probe &p,
                          const std::vector<std::string> &funcs,
                          const std::string &name)
{
  check_kprobe_multi(p, funcs, name, name);
  EXPECT_TRUE(p.is_session);
}

TEST_F(bpftrace_btf, add_probes_fentry)
{
  auto bpftrace = get_strict_mock_bpftrace();

  parse_probe("fentry:func_1,fexit:func_1 {}", *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_probe(bpftrace->get_probes().at(0),
              ProbeType::fentry,
              "fentry:mock_vmlinux:func_1");
  check_probe(bpftrace->get_probes().at(1),
              ProbeType::fexit,
              "fexit:mock_vmlinux:func_1");
}

TEST_F(bpftrace_btf, add_probes_fentry_bpf_func)
{
  auto bpftrace = get_mock_bpftrace();

  parse_probe("fentry:bpf:func_1 {}", *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

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

  parse_probe("fentry:bpf:123:func_* {}", *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_probe(bpftrace->get_probes().at(0),
              ProbeType::fentry,
              "fentry:bpf:123:func_1");
  check_probe(bpftrace->get_probes().at(1),
              ProbeType::fentry,
              "fentry:bpf:123:func_2");
}

TEST_F(bpftrace_btf, add_probes_fentry_bpf_exact)
{
  auto bpftrace = get_mock_bpftrace();

  parse_probe("fentry:bpf:456:func_1 {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_probe(bpftrace->get_probes().at(0),
              ProbeType::fentry,
              "fentry:bpf:456:func_1");
}

TEST_F(bpftrace_btf, add_probes_kprobe)
{
  auto bpftrace = get_strict_mock_bpftrace();
  parse_probe("kprobe:mock_vmlinux:func_1,kretprobe:mock_vmlinux:func_1 {}",
              *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_probe(bpftrace->get_probes().at(0),
              ProbeType::kprobe,
              "kprobe:mock_vmlinux:func_1");
  check_probe(bpftrace->get_probes().at(1),
              ProbeType::kretprobe,
              "kretprobe:mock_vmlinux:func_1");
}

TEST_F(bpftrace_btf, add_probes_iter_task)
{
  auto bpftrace = get_strict_mock_bpftrace();

  parse_probe("iter:task {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_probe(bpftrace->get_probes().at(0), ProbeType::iter, "iter:task");
}

TEST_F(bpftrace_btf, add_probes_iter_task_file)
{
  auto bpftrace = get_strict_mock_bpftrace();

  parse_probe("iter:task_file {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_probe(bpftrace->get_probes().at(0), ProbeType::iter, "iter:task_file");
}

TEST_F(bpftrace_btf, add_probes_iter_task_vma)
{
  auto bpftrace = get_strict_mock_bpftrace();

  parse_probe("iter:task_vma {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_probe(bpftrace->get_probes().at(0), ProbeType::iter, "iter:task_vma");
}

TEST_F(bpftrace_btf, add_probes_wildcard_kprobe_session)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_traceable_funcs(false))
      .Times(2);

  parse_probe("kprobe:my_*{} kretprobe:my_*{}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_kprobe_session(bpftrace->get_probes().at(0),
                       { "my_one", "my_two" },
                       "kprobe:my_*");
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
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  auto probe = bpftrace->get_probes().at(0);
  EXPECT_EQ(ProbeType::rawtracepoint, probe.type);
  EXPECT_EQ("event_rt", probe.attach_point);
  EXPECT_EQ("rawtracepoint:event_rt", probe.orig_name);
  EXPECT_EQ("rawtracepoint:vmlinux:event_rt", probe.name);
}

TEST_F(bpftrace_btf, add_probes_rawtracepoint_wildcard)
{
  auto bpftrace = get_mock_bpftrace();
  parse_probe(("rawtracepoint:event_* {}"), *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
}

TEST_F(bpftrace_btf, add_probes_rawtracepoint_wildcard_no_matches)
{
  auto bpftrace = get_mock_bpftrace();
  parse_probe("rawtracepoint:typo_* {}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
}

TEST(bpftrace, resolve_timestamp)
{
  static const auto bootmode = static_cast<uint32_t>(TimestampMode::boot);
  auto bpftrace = get_strict_mock_bpftrace();

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
                .put(static_cast<BPFtrace &>(*bpftrace))
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .run();
  EXPECT_TRUE(ok && ast.diagnostics().ok());

  return bpftrace->list_modules(ast);
}

// Test modules are extracted when module is not explicit in attachpoint
TEST(bpftrace, list_modules_kprobe_implicit)
{
  auto modules = list_modules("k:queued_spin_lock_slowpath{},kr:func_in_mod{}");
  EXPECT_EQ(modules.size(), 3);
  EXPECT_THAT(modules, Contains("vmlinux"));
  EXPECT_THAT(modules, Contains("kernel_mod"));
  EXPECT_THAT(modules, Contains("other_kernel_mod"));
}

// Inverse of above
TEST(bpftrace, list_modules_kprobe_explicit)
{
  auto modules = list_modules(
      "k:vmlinux:queued_spin_lock_slowpath{},kr:kernel_mod:func_in_mod{}");
  EXPECT_EQ(modules.size(), 2);
  EXPECT_THAT(modules, Contains("vmlinux"));
  EXPECT_THAT(modules, Contains("kernel_mod"));
}

// Implicit fentry/fexit is not tested b/c the mocks are currently wired
// up in a somewhat rigid way. The mocked data source uses "vmlinux" module
// but another mock forces "mock_vmlinux" module. Anyone reading this comment
// is welcome to try it out again (in case it's been fixed in interim) or do
// a proper fix.

TEST_F(bpftrace_btf, list_modules_fentry_explicit)
{
  auto modules = list_modules("fentry:vmlinux:func_1{},fexit:vmlinux:func_2{}");
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

  const auto keys = std::vector<uint64_t>{ 1, 3, 5, 7, 9 };
  const auto values = std::vector<uint64_t>{ 5, 10, 4, 11, 7 };
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
    output::TextOutput output(out);
    auto bpftrace = get_mock_bpftrace();
    auto mock_map = std::make_unique<MockBpfMap>(libbpf::BPF_MAP_TYPE_HASH,
                                                 tc.name);
    auto returned_kvs = generate_kv_pairs(keys, values);
    EXPECT_CALL(*mock_map, collect_elements(testing::_))
        .WillOnce(testing::Return(
            testing::ByMove(Result<MapElements>(returned_kvs))));

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

  const auto keys = std::vector<uint64_t>{ 1, 2, 3 };
  const auto values = std::vector<std::vector<uint8_t>>{
    generate_percpu_data({ { 5, true }, { 8, true }, { 3, true } }),
    generate_percpu_data({ { 15, false }, { 0, false }, { 12, true } }),
    generate_percpu_data({ { 100, false }, { 80, false }, { 20, true } }),
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
    output::TextOutput output(out);
    auto bpftrace = get_mock_bpftrace();

    bpftrace->ncpus_ = 3;
    auto mock_map = std::make_unique<MockBpfMap>(
        libbpf::BPF_MAP_TYPE_PERCPU_HASH, tc.name);
    auto returned_kvs = generate_kv_pairs(keys, values);
    EXPECT_CALL(*mock_map, collect_elements(testing::_))
        .WillOnce(testing::Return(
            testing::ByMove(Result<MapElements>(returned_kvs))));

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

  const auto keys = std::vector<uint64_t>{ 1, 2, 3 };
  const auto values = std::vector<std::vector<uint8_t>>{
    generate_percpu_data({ { 5, true }, { 8, true }, { 3, true } }),
    generate_percpu_data({ { 16, true }, { 0, false }, { 12, true } }),
    generate_percpu_data({ { 100, false }, { 80, false }, { 20, true } }),
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
    output::TextOutput output(out);
    auto bpftrace = get_mock_bpftrace();

    bpftrace->ncpus_ = 3;
    auto mock_map = std::make_unique<MockBpfMap>(
        libbpf::BPF_MAP_TYPE_PERCPU_HASH, tc.name);
    auto returned_kvs = generate_kv_pairs(keys, values);
    EXPECT_CALL(*mock_map, collect_elements(testing::_))
        .WillOnce(testing::Return(
            testing::ByMove(Result<MapElements>(returned_kvs))));

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

  std::vector<uint64_t> keys{ 3, 1, 2 };
  std::vector<std::string> values{ "hello", "world", "bpftrace" };

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
    output::TextOutput output(out);
    auto bpftrace = get_mock_bpftrace();

    auto mock_map = std::make_unique<MockBpfMap>(libbpf::BPF_MAP_TYPE_HASH,
                                                 tc.name);
    auto returned_kvs = generate_kv_pairs(keys, values);
    EXPECT_CALL(*mock_map, collect_elements(testing::_))
        .WillOnce(testing::Return(
            testing::ByMove(Result<MapElements>(returned_kvs))));

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
    output::TextOutput output(out);
    auto bpftrace = get_mock_bpftrace();

    auto mock_map = std::make_unique<MockBpfMap>(libbpf::BPF_MAP_TYPE_HASH,
                                                 tc.name);
    HistogramMap values_by_key = {
      { { 0, 0, 0, 0, 0, 0, 0, 0 }, { 0, 10, 20, 30, 40, 50, 0 } },
      { { 1, 0, 0, 0, 0, 0, 0, 0 }, { 0, 2, 2, 2, 2, 2, 0 } },
    };
    EXPECT_CALL(*mock_map, collect_histogram_data(testing::_, testing::_))
        .WillOnce(testing::Return(
            testing::ByMove(Result<HistogramMap>(values_by_key))));

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
    output::TextOutput output(out);
    auto bpftrace = get_mock_bpftrace();

    auto mock_map = std::make_unique<MockBpfMap>(libbpf::BPF_MAP_TYPE_HASH,
                                                 tc.name);
    HistogramMap values_by_key = {
      { { 0, 0, 0, 0, 0, 0, 0, 0 }, { 0, 10, 20, 30, 40, 50, 0 } },
      { { 1, 0, 0, 0, 0, 0, 0, 0 }, { 0, 2, 2, 2, 2, 2, 0 } },
    };
    EXPECT_CALL(*mock_map, collect_histogram_data(testing::_, testing::_))
        .WillOnce(testing::Return(
            testing::ByMove(Result<HistogramMap>(values_by_key))));

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
  constexpr uint64_t first_epoch = base_time_ns / interval;

  std::vector<std::pair<EpochType, ValueType>> v1 = {
    { (first_epoch + 1), { 1, 0, 0, 0, 0, 0, 0, 0 } },
    { (first_epoch + 2), { 2, 0, 0, 0, 0, 0, 0, 0 } },
    { (first_epoch + 3), { 3, 0, 0, 0, 0, 0, 0, 0 } },
    { (first_epoch + 4), { 4, 0, 0, 0, 0, 0, 0, 0 } },
    { (first_epoch + 5), { 5, 0, 0, 0, 0, 0, 0, 0 } },
  };

  std::vector<std::pair<EpochType, ValueType>> v2 = {
    { (first_epoch + 2), { 1, 0, 0, 0, 0, 0, 0, 0 } },
    { (first_epoch + 3), { 2, 0, 0, 0, 0, 0, 0, 0 } },
    { (first_epoch + 4), { 3, 0, 0, 0, 0, 0, 0, 0 } },
    { (first_epoch + 5), { 4, 0, 0, 0, 0, 0, 0, 0 } },
    { (first_epoch + 6), { 5, 0, 0, 0, 0, 0, 0, 0 } },
  };

  TSeriesMap values_by_key;
  values_by_key[{ 0, 0, 0, 0, 0, 0, 0, 0 }] = TSeries(v1.begin(), v1.end());
  values_by_key[{ 1, 0, 0, 0, 0, 0, 0, 0 }] = TSeries(v2.begin(), v2.end());

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
    output::TextOutput output(out);
    auto bpftrace = get_mock_bpftrace();

    auto mock_map = std::make_unique<MockBpfMap>(libbpf::BPF_MAP_TYPE_HASH,
                                                 tc.name);
    EXPECT_CALL(*mock_map, collect_tseries_data(testing::_, testing::_))
        .WillOnce(testing::Return(values_by_key));

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
