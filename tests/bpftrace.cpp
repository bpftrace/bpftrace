#include <cstring>

#include "ast/passes/codegen_llvm.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/semantic_analyser.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "driver.h"
#include "mocks.h"
#include "tracefs.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace bpftrace {
namespace test {
namespace bpftrace {

#include "btf_common.h"

using ::testing::ContainerEq;
using ::testing::StrictMock;

static const int STRING_SIZE = 64;

static const std::string kprobe_name(const std::string &attach_point,
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
  Driver driver(bpftrace);
  ASSERT_EQ(driver.parse_str(str), 0);

  ast::FieldAnalyser fields(driver.ctx.root, bpftrace);
  ASSERT_EQ(fields.analyse(), 0);

  ClangParser clang;
  clang.parse(driver.ctx.root, bpftrace);

  ast::SemanticAnalyser semantics(driver.ctx, bpftrace);
  ASSERT_EQ(semantics.analyse(), 0);

  auto usdt_helper = get_mock_usdt_helper(usdt_num_locations);
  std::stringstream out;
  ast::CodegenLLVM codegen(driver.ctx.root, bpftrace, std::move(usdt_helper));
  codegen.generate_ir();
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
  bool retprobe = orig_name.find("uretprobe:") == 0 ||
                  orig_name.find("ur:") == 0;
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
  bool retprobe = orig_name.find("uretprobe:") == 0 ||
                  orig_name.find("ur:") == 0;
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

void check_rawtracepoint(Probe &p,
                         const std::string &func,
                         const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::rawtracepoint, p.type);
  EXPECT_EQ(func, p.attach_point);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ("rawtracepoint:" + func, p.name);
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

void check_special_probe(Probe &p,
                         const std::string &attach_point,
                         const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::special, p.type);
  EXPECT_EQ(attach_point, p.attach_point);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ(orig_name, p.name);
}

TEST(bpftrace, add_begin_probe)
{
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("BEGIN{}", bpftrace);

  ASSERT_EQ(0U, bpftrace.get_probes().size());
  ASSERT_EQ(1U, bpftrace.get_special_probes().size());

  check_special_probe(bpftrace.get_special_probes().at(0),
                      "BEGIN_trigger",
                      "BEGIN");
}

TEST(bpftrace, add_end_probe)
{
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("END{}", bpftrace);

  ASSERT_EQ(0U, bpftrace.get_probes().size());
  ASSERT_EQ(1U, bpftrace.get_special_probes().size());

  check_special_probe(bpftrace.get_special_probes().at(0),
                      "END_trigger",
                      "END");
}

TEST(bpftrace, add_probes_single)
{
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("kprobe:sys_read {}", bpftrace);
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  check_kprobe(bpftrace.get_probes().at(0), "sys_read", "kprobe:sys_read");
}

TEST(bpftrace, add_probes_multiple)
{
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("kprobe:sys_read,kprobe:sys_write{}", bpftrace);
  ASSERT_EQ(2U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "kprobe:sys_read,kprobe:sys_write";
  check_kprobe(bpftrace.get_probes().at(0), "sys_read", probe_orig_name);
  check_kprobe(bpftrace.get_probes().at(1), "sys_write", probe_orig_name);
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
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_traceable_funcs(false))
      .Times(1);

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
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
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
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
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
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
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
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("kprobe:sys_read+10{}", bpftrace);
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "kprobe:sys_read+" + std::to_string(offset);
  check_kprobe(
      bpftrace.get_probes().at(0), "sys_read", probe_orig_name, offset);
}

TEST(bpftrace, add_probes_uprobe)
{
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("uprobe:/bin/sh:foo {}", bpftrace);

  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());
  check_uprobe(bpftrace.get_probes().at(0),
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
              get_func_symbols_from_file(0, "/bin/sh"))
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
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file(0, "/bin/sh"))
      .Times(1);

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
              get_func_symbols_from_file(0, "/bin/*sh"))
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
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file(0, "/bin/*sh"))
      .Times(1);

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
              get_func_symbols_from_file(0, "/bin/sh"))
      .Times(1);

  parse_probe("uprobe:/bin/sh:foo* {}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
}

TEST(bpftrace, add_probes_uprobe_wildcard_no_matches_multi)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file(0, "/bin/sh"))
      .Times(1);

  parse_probe("uprobe:/bin/sh:foo* {}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
}

TEST(bpftrace, add_probes_uprobe_address)
{
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("uprobe:/bin/sh:1024 {}", bpftrace);

  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());
  check_uprobe(bpftrace.get_probes().at(0),
               "/bin/sh",
               "",
               "uprobe:/bin/sh:1024",
               "uprobe:/bin/sh:1024",
               1024);
}

TEST(bpftrace, add_probes_uprobe_string_offset)
{
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("uprobe:/bin/sh:foo+10{}", bpftrace);

  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());
  check_uprobe(bpftrace.get_probes().at(0),
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
                get_func_symbols_from_file(0, "/bin/sh"))
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
              get_func_symbols_from_file(0, "/bin/sh"))
      .Times(1);

  parse_probe("uprobe:/bin/sh:cpp:\"cpp_mangled(int)\"{}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  check_uprobe(bpftrace->get_probes().at(0),
               "/bin/sh",
               "_Z11cpp_mangledi",
               "uprobe:/bin/sh:cpp:cpp_mangled(int)",
               "uprobe:/bin/sh:cpp:_Z11cpp_mangledi");
}

TEST(bpftrace, add_probes_uprobe_cpp_symbol_wildcard)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(false);
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file(0, "/bin/sh"))
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
              get_func_symbols_from_file(0, "/bin/sh"))
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
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("usdt:/bin/sh:prov1:mytp {}", bpftrace, 1);

  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());
  check_usdt(bpftrace.get_probes().at(0),
             "/bin/sh",
             "prov1",
             "mytp",
             "usdt:/bin/sh:prov1:mytp");
}

TEST(bpftrace, add_probes_usdt_wildcard)
{
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_usdt(0, "/bin/*sh"))
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
              get_symbols_from_usdt(0, "/bin/sh"))
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
              get_symbols_from_usdt(0, "/bin/sh"))
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
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("tracepoint:sched:sched_switch {}", bpftrace);

  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "tracepoint:sched:sched_switch";
  check_tracepoint(
      bpftrace.get_probes().at(0), "sched", "sched_switch", probe_orig_name);
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
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("profile:ms:997 {}", bpftrace);

  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "profile:ms:997";
  check_profile(bpftrace.get_probes().at(0), "ms", 997, probe_orig_name);
}

TEST(bpftrace, add_probes_interval)
{
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("i:s:1 {}", bpftrace);

  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "interval:s:1";
  check_interval(bpftrace.get_probes().at(0), "s", 1, probe_orig_name);
}

TEST(bpftrace, add_probes_software)
{
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("software:faults:1000 {}", bpftrace);

  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "software:faults:1000";
  check_software(bpftrace.get_probes().at(0), "faults", 1000, probe_orig_name);
}

TEST(bpftrace, add_probes_hardware)
{
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("hardware:cache-references:1000000 {}", bpftrace);

  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "hardware:cache-references:1000000";
  check_hardware(bpftrace.get_probes().at(0),
                 "cache-references",
                 1000000,
                 probe_orig_name);
}

TEST(bpftrace, empty_attachpoints)
{
  StrictMock<MockBPFtrace> bpftrace;
  Driver driver(bpftrace);

  // Trailing comma is fine
  ASSERT_EQ(driver.parse_str("kprobe:f1, {}"), 0);
  // Empty attach point should fail
  ASSERT_EQ(driver.parse_str("{}"), 1);
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
    std::memcpy(key_data + sizeof(uint64_t) * i, &k, sizeof(k));
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
    strncpy((char *)key_data + STRING_SIZE * i, key.at(i).c_str(), STRING_SIZE);
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
  strncpy((char *)key_data + sizeof(uint64_t), mystr.c_str(), STRING_SIZE);
  std::memcpy(val_data, &v, sizeof(v));

  return pair;
}

TEST(bpftrace, sort_by_key_int)
{
  StrictMock<MockBPFtrace> bpftrace;

  std::vector<SizedType> key_args = { CreateUInt64() };
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      values_by_key = {
        key_value_pair_int({ 2 }, 12),
        key_value_pair_int({ 3 }, 11),
        key_value_pair_int({ 1 }, 10),
      };
  bpftrace.sort_by_key(key_args, values_by_key);

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
  StrictMock<MockBPFtrace> bpftrace;

  std::vector<SizedType> key_args = {
    CreateUInt64(),
    CreateUInt64(),
    CreateUInt64(),
  };
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      values_by_key = {
        key_value_pair_int({ 5, 2, 1 }, 1), key_value_pair_int({ 5, 3, 1 }, 2),
        key_value_pair_int({ 5, 1, 1 }, 3), key_value_pair_int({ 2, 2, 2 }, 4),
        key_value_pair_int({ 2, 3, 2 }, 5), key_value_pair_int({ 2, 1, 2 }, 6),
      };
  bpftrace.sort_by_key(key_args, values_by_key);

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
  StrictMock<MockBPFtrace> bpftrace;

  std::vector<SizedType> key_args = {
    CreateString(STRING_SIZE),
  };
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      values_by_key = {
        key_value_pair_str({ "z" }, 1),
        key_value_pair_str({ "a" }, 2),
        key_value_pair_str({ "x" }, 3),
        key_value_pair_str({ "d" }, 4),
      };
  bpftrace.sort_by_key(key_args, values_by_key);

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
  StrictMock<MockBPFtrace> bpftrace;

  std::vector<SizedType> key_args = {
    CreateString(STRING_SIZE),
    CreateString(STRING_SIZE),
    CreateString(STRING_SIZE),
  };
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      values_by_key = {
        key_value_pair_str({ "z", "a", "l" }, 1),
        key_value_pair_str({ "a", "a", "m" }, 2),
        key_value_pair_str({ "z", "c", "n" }, 3),
        key_value_pair_str({ "a", "c", "o" }, 4),
        key_value_pair_str({ "z", "b", "p" }, 5),
        key_value_pair_str({ "a", "b", "q" }, 6),
      };
  bpftrace.sort_by_key(key_args, values_by_key);

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
  StrictMock<MockBPFtrace> bpftrace;

  std::vector<SizedType> key_args = {
    CreateUInt64(),
    CreateString(STRING_SIZE),
  };
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
      values_by_key = {
        key_value_pair_int_str(1, "b", 1), key_value_pair_int_str(2, "b", 2),
        key_value_pair_int_str(3, "b", 3), key_value_pair_int_str(1, "a", 4),
        key_value_pair_int_str(2, "a", 5), key_value_pair_int_str(3, "a", 6),
      };
  bpftrace.sort_by_key(key_args, values_by_key);

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

TEST_F(bpftrace_btf, add_probes_kfunc)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  parse_probe("kfunc:func_1,kretfunc:func_1 {}", *bpftrace);

  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_probe(bpftrace->get_probes().at(0),
              ProbeType::kfunc,
              "kfunc:mock_vmlinux:func_1");
  check_probe(bpftrace->get_probes().at(1),
              ProbeType::kretfunc,
              "kretfunc:mock_vmlinux:func_1");
}

TEST_F(bpftrace_btf, add_probes_kprobe)
{
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("kprobe:mock_vmlinux:func_1,kretprobe:mock_vmlinux:func_1 {}",
              bpftrace);

  ASSERT_EQ(2U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  check_probe(bpftrace.get_probes().at(0),
              ProbeType::kprobe,
              "kprobe:mock_vmlinux:func_1");
  check_probe(bpftrace.get_probes().at(1),
              ProbeType::kretprobe,
              "kretprobe:mock_vmlinux:func_1");
}

TEST_F(bpftrace_btf, add_probes_iter_task)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  parse_probe("iter:task {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_probe(bpftrace->get_probes().at(0), ProbeType::iter, "iter:task");
}

TEST_F(bpftrace_btf, add_probes_iter_task_file)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  parse_probe("iter:task_file {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_probe(bpftrace->get_probes().at(0), ProbeType::iter, "iter:task_file");
}

TEST_F(bpftrace_btf, add_probes_iter_task_vma)
{
  auto bpftrace = get_strict_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  parse_probe("iter:task_vma {}", *bpftrace);

  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  check_probe(bpftrace->get_probes().at(0), ProbeType::iter, "iter:task_vma");
}

TEST(bpftrace, add_probes_rawtracepoint)
{
  StrictMock<MockBPFtrace> bpftrace;
  parse_probe("rawtracepoint:sched_switch {}", bpftrace);

  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "rawtracepoint:sched_switch";
  check_rawtracepoint(bpftrace.get_probes().at(0),
                      "sched_switch",
                      probe_orig_name);
}

TEST(bpftrace, add_probes_rawtracepoint_wildcard)
{
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_file(tracefs::available_events()))
      .Times(1);

  parse_probe(("rawtracepoint:sched_* {}"), *bpftrace);

  ASSERT_EQ(3U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
}

TEST(bpftrace, add_probes_rawtracepoint_wildcard_no_matches)
{
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_file(tracefs::available_events()))
      .Times(1);

  parse_probe("rawtracepoint:typo_* {}", *bpftrace);

  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
}

} // namespace bpftrace
} // namespace test
} // namespace bpftrace
