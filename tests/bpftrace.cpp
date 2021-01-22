#include <cstring>

#include "bpftrace.h"
#include "driver.h"
#include "mocks.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace bpftrace {
namespace test {
namespace bpftrace {

using ::testing::ContainerEq;
using ::testing::StrictMock;

static const std::string kprobe_name(const std::string &attach_point,
                                     uint64_t func_offset)
{
  auto str = func_offset ? "+" + std::to_string(func_offset) : "";
  return "kprobe:" + attach_point + str;
}

void check_kprobe(Probe &p,
                  const std::string &attach_point,
                  const std::string &orig_name,
                  uint64_t func_offset = 0)
{
  EXPECT_EQ(ProbeType::kprobe, p.type);
  EXPECT_EQ(attach_point, p.attach_point);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ(kprobe_name(attach_point, func_offset), p.name);
  EXPECT_EQ(func_offset, p.func_offset);
}

static auto make_probe(std::vector<ast::AttachPoint *> elems)
{
  auto apl = new ast::AttachPointList(elems);
  return new ast::Probe(apl, nullptr, nullptr);
}

static auto make_usdt_probe(const std::string &target,
                            const std::string &ns,
                            const std::string &func,
                            bool need_expansion = false,
                            int locations = 0)
{
  auto a = new ast::AttachPoint("");
  a->provider = "usdt";
  a->target = target;
  a->ns = ns;
  a->func = func;
  a->need_expansion = need_expansion;
  a->usdt.num_locations = locations;
  return make_probe({ a });
}

static auto parse_probe(const std::string &str)
{
  StrictMock<MockBPFtrace> b;
  Driver d(b);

  if (d.parse_str(str))
  {
    throw std::runtime_error("Parser failed");
  }
  auto probe = d.root_->probes->front();
  d.root_->probes->clear();
  return probe;
}

static const std::string uprobe_name(const std::string &path,
                                     const std::string &attach_point,
                                     uint64_t address,
                                     uint64_t func_offset,
                                     bool retprobe = false)
{
  auto provider = retprobe ? "uretprobe:" : "uprobe:";
  if (attach_point.empty()) {
    return provider + path + ":" + std::to_string(address);
  } else {
    auto str = func_offset ? "+" + std::to_string(func_offset) : "";
    return provider + path + ":" + attach_point + str;
  }
}

void check_uprobe(Probe &p, const std::string &path, const std::string &attach_point, const std::string &orig_name,
                  uint64_t address = 0, uint64_t func_offset = 0)
{
  bool retprobe = orig_name.find("uretprobe:") == 0 ||
                  orig_name.find("ur:") == 0;
  EXPECT_EQ(retprobe ? ProbeType::uretprobe : ProbeType::uprobe, p.type);
  EXPECT_EQ(attach_point, p.attach_point);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ(uprobe_name(path, attach_point, address, func_offset, retprobe),
            p.name);
  EXPECT_EQ(address, p.address);
  EXPECT_EQ(func_offset, p.func_offset);
}

void check_usdt(Probe &p, const std::string &path, const std::string &provider, const std::string &attach_point, const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::usdt, p.type);
  EXPECT_EQ(attach_point, p.attach_point);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ("usdt:" + path + ":" + provider + ":" + attach_point, p.name);
}

void check_tracepoint(Probe &p, const std::string &target, const std::string &func, const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::tracepoint, p.type);
  EXPECT_EQ(func, p.attach_point);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ("tracepoint:" + target + ":" + func, p.name);
}

void check_profile(Probe &p, const std::string &unit, int freq, const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::profile, p.type);
  EXPECT_EQ(freq, p.freq);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ("profile:" + unit + ":" + std::to_string(freq), p.name);
}

void check_interval(Probe &p, const std::string &unit, int freq, const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::interval, p.type);
  EXPECT_EQ(freq, p.freq);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ("interval:" + unit + ":" + std::to_string(freq), p.name);
}

void check_software(Probe &p, const std::string &unit, int freq, const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::software, p.type);
  EXPECT_EQ(freq, p.freq);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ("software:" + unit + ":" + std::to_string(freq), p.name);
}

void check_hardware(Probe &p, const std::string &unit, int freq, const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::hardware, p.type);
  EXPECT_EQ(freq, p.freq);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ("hardware:" + unit + ":" + std::to_string(freq), p.name);
}

void check_special_probe(Probe &p, const std::string &attach_point, const std::string &orig_name)
{
  EXPECT_EQ(ProbeType::uprobe, p.type);
  EXPECT_EQ(attach_point, p.attach_point);
  EXPECT_EQ(orig_name, p.orig_name);
  EXPECT_EQ(orig_name, p.name);
}

TEST(bpftrace, add_begin_probe)
{
  ast::Probe *probe = parse_probe("BEGIN{}");

  StrictMock<MockBPFtrace> bpftrace;
  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(0U, bpftrace.get_probes().size());
  ASSERT_EQ(1U, bpftrace.get_special_probes().size());

  check_special_probe(bpftrace.get_special_probes().at(0), "BEGIN_trigger", "BEGIN");
}

TEST(bpftrace, add_end_probe)
{
  ast::Probe *probe = parse_probe("END{}");

  StrictMock<MockBPFtrace> bpftrace;
  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(0U, bpftrace.get_probes().size());
  ASSERT_EQ(1U, bpftrace.get_special_probes().size());

  check_special_probe(bpftrace.get_special_probes().at(0), "END_trigger", "END");
}

TEST(bpftrace, add_probes_single)
{
  ast::Probe *probe = parse_probe("kprobe:sys_read {}");
  StrictMock<MockBPFtrace> bpftrace;
  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  check_kprobe(bpftrace.get_probes().at(0), "sys_read", "kprobe:sys_read");
}

TEST(bpftrace, add_probes_multiple)
{
  ast::Probe *probe = parse_probe("kprobe:sys_read,kprobe:sys_write{}");
  StrictMock<MockBPFtrace> bpftrace;
  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(2U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "kprobe:sys_read,kprobe:sys_write";
  check_kprobe(bpftrace.get_probes().at(0), "sys_read", probe_orig_name);
  check_kprobe(bpftrace.get_probes().at(1), "sys_write", probe_orig_name);
}

TEST(bpftrace, add_probes_wildcard)
{
  ast::Probe *probe = parse_probe(
      "kprobe:sys_read,kprobe:my_*,kprobe:sys_write{}");

  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_file(
                  "/sys/kernel/debug/tracing/available_filter_functions"))
      .Times(1);

  ASSERT_EQ(0, bpftrace->add_probe(*probe));
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
  ast::Probe *probe = parse_probe(
      "kprobe:sys_read,kprobe:not_here_*,kprobe:sys_write{}");

  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_file(
                  "/sys/kernel/debug/tracing/available_filter_functions"))
      .Times(1);

  ASSERT_EQ(0, bpftrace->add_probe(*probe));
  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "kprobe:sys_read,kprobe:not_here_*,kprobe:sys_write";
  check_kprobe(bpftrace->get_probes().at(0), "sys_read", probe_orig_name);
  check_kprobe(bpftrace->get_probes().at(1), "sys_write", probe_orig_name);
}

TEST(bpftrace, add_probes_kernel_module)
{
  ast::Probe *probe = parse_probe("kprobe:func_in_mod{}");

  auto bpftrace = get_strict_mock_bpftrace();
  ASSERT_EQ(0, bpftrace->add_probe(*probe));
  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "kprobe:func_in_mod";
  check_kprobe(bpftrace->get_probes().at(0), "func_in_mod", probe_orig_name);
}

TEST(bpftrace, add_probes_kernel_module_wildcard)
{
  ast::Probe *probe = parse_probe("kprobe:func_in_mo*{}");
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_file(
                  "/sys/kernel/debug/tracing/available_filter_functions"))
      .Times(1);

  ASSERT_EQ(0, bpftrace->add_probe(*probe));
  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "kprobe:func_in_mo*";
  check_kprobe(bpftrace->get_probes().at(0), "func_in_mod", probe_orig_name);
}

TEST(bpftrace, add_probes_offset)
{
  auto offset = 10;
  ast::Probe *probe = parse_probe("kprobe:sys_read+10{}");
  StrictMock<MockBPFtrace> bpftrace;
  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "kprobe:sys_read+" + std::to_string(offset);
  check_kprobe(
      bpftrace.get_probes().at(0), "sys_read", probe_orig_name, offset);
}

TEST(bpftrace, add_probes_uprobe)
{
  StrictMock<MockBPFtrace> bpftrace;
  ast::Probe *probe = parse_probe("uprobe:/bin/sh:foo {}");

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());
  check_uprobe(bpftrace.get_probes().at(0), "/bin/sh", "foo", "uprobe:/bin/sh:foo");
}

TEST(bpftrace, add_probes_uprobe_wildcard)
{
  ast::Probe *probe = parse_probe("uprobe:/bin/sh:*open {}");

  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file("/bin/sh"))
      .Times(1);

  ASSERT_EQ(0, bpftrace->add_probe(*probe));
  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "uprobe:/bin/sh:*open";
  check_uprobe(bpftrace->get_probes().at(0), "/bin/sh", "first_open", probe_orig_name);
  check_uprobe(bpftrace->get_probes().at(1), "/bin/sh", "second_open", probe_orig_name);
}

TEST(bpftrace, add_probes_uprobe_wildcard_file)
{
  ast::Probe *probe = parse_probe("uprobe:/bin/*sh:first_open {}");
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file("/bin/*sh"))
      .Times(1);

  ASSERT_EQ(0, bpftrace->add_probe(*probe));
  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "uprobe:/bin/*sh:first_open";
  check_uprobe(
      bpftrace->get_probes().at(0), "/bin/bash", "first_open", probe_orig_name);
  check_uprobe(
      bpftrace->get_probes().at(1), "/bin/sh", "first_open", probe_orig_name);
}

TEST(bpftrace, add_probes_uprobe_wildcard_no_matches)
{
  ast::Probe *probe = parse_probe("uprobe:/bin/sh:foo* {}");
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file("/bin/sh"))
      .Times(1);

  ASSERT_EQ(0, bpftrace->add_probe(*probe));
  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
}

TEST(bpftrace, add_probes_uprobe_string_literal)
{
  auto a = new ast::AttachPoint("");
  a->provider = "uprobe";
  a->target = "/bin/sh";
  a->func = "foo*";

  auto probe = make_probe({ a });
  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());
  check_uprobe(bpftrace.get_probes().at(0), "/bin/sh", "foo*", "uprobe:/bin/sh:foo*");
}

TEST(bpftrace, add_probes_uprobe_address)
{
  ast::Probe *probe = parse_probe("uprobe:/bin/sh:1024 {}");
  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());
  check_uprobe(bpftrace.get_probes().at(0), "/bin/sh", "", "uprobe:/bin/sh:1024", 1024);
}

TEST(bpftrace, add_probes_uprobe_string_offset)
{
  ast::Probe *probe = parse_probe("uprobe:/bin/sh:foo+10{}");
  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());
  check_uprobe(bpftrace.get_probes().at(0), "/bin/sh", "foo", "uprobe:/bin/sh:foo+10", 0, 10);
}

TEST(bpftrace, add_probes_uprobe_cpp_symbol)
{
  for (auto &provider : { "uprobe", "uretprobe" })
  {
    std::stringstream prog;
    prog << provider << ":/bin/sh:cpp_mangled{}";
    ast::Probe *probe = parse_probe(prog.str());

    auto bpftrace = get_strict_mock_bpftrace();
    EXPECT_CALL(*bpftrace->mock_probe_matcher,
                get_func_symbols_from_file("/bin/sh"))
        .Times(1);

    ASSERT_EQ(0, bpftrace->add_probe(*probe));
    ASSERT_EQ(2U, bpftrace->get_probes().size());
    ASSERT_EQ(0U, bpftrace->get_special_probes().size());
    auto orig_name = std::string(provider) + ":/bin/sh:cpp_mangled";
    check_uprobe(
        bpftrace->get_probes().at(0), "/bin/sh", "_Z11cpp_mangledi", orig_name);
    check_uprobe(
        bpftrace->get_probes().at(1), "/bin/sh", "_Z11cpp_mangledv", orig_name);
  }
}

TEST(bpftrace, add_probes_uprobe_cpp_symbol_full)
{
  auto probe = parse_probe("uprobe:/bin/sh:\"cpp_mangled(int)\"{}");

  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file("/bin/sh"))
      .Times(1);

  ASSERT_EQ(0, bpftrace->add_probe(*probe));
  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  check_uprobe(bpftrace->get_probes().at(0),
               "/bin/sh",
               "_Z11cpp_mangledi",
               "uprobe:/bin/sh:cpp_mangled(int)");
}

TEST(bpftrace, add_probes_uprobe_cpp_symbol_wildcard)
{
  auto probe = parse_probe("uprobe:/bin/sh:cpp_man*{}");

  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_func_symbols_from_file("/bin/sh"))
      .Times(1);

  ASSERT_EQ(0, bpftrace->add_probe(*probe));
  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  check_uprobe(bpftrace->get_probes().at(0),
               "/bin/sh",
               "_Z11cpp_mangledi",
               "uprobe:/bin/sh:cpp_man*");
  check_uprobe(bpftrace->get_probes().at(1),
               "/bin/sh",
               "_Z11cpp_mangledv",
               "uprobe:/bin/sh:cpp_man*");
}

TEST(bpftrace, add_probes_usdt)
{
  auto probe = parse_probe("usdt:/bin/sh:prov1:mytp{}");
  probe->attach_points->front()->usdt.num_locations = 1;

  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());
  check_usdt(bpftrace.get_probes().at(0),
             "/bin/sh", "prov1", "mytp",
             "usdt:/bin/sh:prov1:mytp");
}

TEST(bpftrace, add_probes_usdt_wildcard)
{
  auto probe = make_usdt_probe("/bin/*sh", "prov*", "tp*", true, 1);
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_usdt(0, "/bin/*sh"))
      .Times(1);

  ASSERT_EQ(0, bpftrace->add_probe(*probe));
  ASSERT_EQ(4U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  check_usdt(bpftrace->get_probes().at(0),
             "/bin/bash",
             "prov1",
             "tp3",
             "usdt:/bin/bash:prov1:tp3");
  check_usdt(bpftrace->get_probes().at(1),
             "/bin/sh",
             "prov1",
             "tp1",
             "usdt:/bin/sh:prov1:tp1");
  check_usdt(bpftrace->get_probes().at(2),
             "/bin/sh",
             "prov1",
             "tp2",
             "usdt:/bin/sh:prov1:tp2");
  check_usdt(bpftrace->get_probes().at(3),
             "/bin/sh",
             "prov2",
             "tp",
             "usdt:/bin/sh:prov2:tp");
}

TEST(bpftrace, add_probes_usdt_empty_namespace)
{
  auto probe = make_usdt_probe("/bin/sh", "", "tp1", true, 1);

  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_usdt(0, "/bin/sh"))
      .Times(1);

  ASSERT_EQ(0, bpftrace->add_probe(*probe));
  ASSERT_EQ(1U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
  check_usdt(bpftrace->get_probes().at(0),
             "/bin/sh",
             "prov1",
             "tp1",
             "usdt:/bin/sh:prov1:tp1");
}

TEST(bpftrace, add_probes_usdt_empty_namespace_conflict)
{
  auto probe = make_usdt_probe("/bin/sh", "", "tp", true, 1);
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_usdt(0, "/bin/sh"))
      .Times(1);

  ASSERT_EQ(1, bpftrace->add_probe(*probe));
}

TEST(bpftrace, add_probes_usdt_duplicate_markers)
{
  auto probe = make_usdt_probe("/bin/sh", "prov1", "mytp", false, 3);

  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(3U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());
  check_usdt(bpftrace.get_probes().at(0),
             "/bin/sh",
             "prov1",
             "mytp",
             "usdt:/bin/sh:prov1:mytp");
  check_usdt(bpftrace.get_probes().at(1),
             "/bin/sh",
             "prov1",
             "mytp",
             "usdt:/bin/sh:prov1:mytp");
  check_usdt(bpftrace.get_probes().at(2),
             "/bin/sh",
             "prov1",
             "mytp",
             "usdt:/bin/sh:prov1:mytp");
}

TEST(bpftrace, add_probes_tracepoint)
{
  auto probe = parse_probe(("tracepoint:sched:sched_switch {}"));
  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "tracepoint:sched:sched_switch";
  check_tracepoint(bpftrace.get_probes().at(0), "sched", "sched_switch", probe_orig_name);
}

TEST(bpftrace, add_probes_tracepoint_wildcard)
{
  auto probe = parse_probe(("tracepoint:sched:sched_* {}"));
  auto bpftrace = get_strict_mock_bpftrace();
  std::set<std::string> matches = { "sched_one", "sched_two" };
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_file(
                  "/sys/kernel/debug/tracing/available_events"))
      .Times(1);

  ASSERT_EQ(0, bpftrace->add_probe(*probe));
  ASSERT_EQ(2U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());

  std::string probe_orig_name = "tracepoint:sched:sched_*";
  check_tracepoint(bpftrace->get_probes().at(0), "sched", "sched_one", probe_orig_name);
  check_tracepoint(bpftrace->get_probes().at(1), "sched", "sched_two", probe_orig_name);
}

TEST(bpftrace, add_probes_tracepoint_category_wildcard)
{
  auto probe = parse_probe(("tracepoint:sched*:sched_* {}"));
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_file(
                  "/sys/kernel/debug/tracing/available_events"))
      .Times(1);

  ASSERT_EQ(0, bpftrace->add_probe(*probe));
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
  auto probe = parse_probe("tracepoint:type:typo_* {}");
  /*
  ast::AttachPoint a("");
  a.provider = "tracepoint";
  a.target = "typo";
  a.func = "typo_*";
  a.need_expansion = true;
  ast::AttachPointList attach_points = { &a };
  ast::Probe probe(&attach_points, nullptr, nullptr);
*/
  auto bpftrace = get_strict_mock_bpftrace();
  EXPECT_CALL(*bpftrace->mock_probe_matcher,
              get_symbols_from_file(
                  "/sys/kernel/debug/tracing/available_events"))
      .Times(1);

  ASSERT_EQ(0, bpftrace->add_probe(*probe));
  ASSERT_EQ(0U, bpftrace->get_probes().size());
  ASSERT_EQ(0U, bpftrace->get_special_probes().size());
}

TEST(bpftrace, add_probes_profile)
{
  /*
  ast::AttachPoint a("");
  a.provider = "profile";
  a.target = "ms";
  a.freq = 997;
  ast::AttachPointList attach_points = { &a };
  ast::Probe probe(&attach_points, nullptr, nullptr);
  */
  auto probe = parse_probe("profile:ms:997 {}");

  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "profile:ms:997";
  check_profile(bpftrace.get_probes().at(0), "ms", 997, probe_orig_name);
}

TEST(bpftrace, add_probes_interval)
{
  // ast::AttachPoint a("");
  // a.provider = "interval";
  // a.target = "s";
  // a.freq = 1;
  // ast::AttachPointList attach_points = { &a };
  // ast::Probe probe(&attach_points, nullptr, nullptr);
  auto probe = parse_probe("i:s:1 {}");

  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "interval:s:1";
  check_interval(bpftrace.get_probes().at(0), "s", 1, probe_orig_name);
}

TEST(bpftrace, add_probes_software)
{
  // ast::AttachPoint a("");
  // a.provider = "software";
  // a.target = "faults";
  // a.freq = 1000;
  // ast::AttachPointList attach_points = { &a };
  // ast::Probe probe(&attach_points, nullptr, nullptr);
  auto probe = parse_probe("software:faults:1000 {}");

  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "software:faults:1000";
  check_software(bpftrace.get_probes().at(0), "faults", 1000, probe_orig_name);
}

TEST(bpftrace, add_probes_hardware)
{
  // ast::AttachPoint a("");
  // a.provider = "hardware";
  // a.target = "cache-references";
  // a.freq = 1000000;
  // ast::AttachPointList attach_points = { &a };
  // ast::Probe probe(&attach_points, nullptr, nullptr);
  auto probe = parse_probe("hardware:cache-references:1000000 {}");

  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  std::string probe_orig_name = "hardware:cache-references:1000000";
  check_hardware(bpftrace.get_probes().at(0), "cache-references", 1000000, probe_orig_name);
}

TEST(bpftrace, invalid_provider)
{
  auto a = new ast::AttachPoint("");
  a->provider = "lookatme";
  a->func = "invalid";
  auto probe = make_probe({ a });

  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> key_value_pair_int(std::vector<uint64_t> key, int val)
{
  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> pair;
  pair.first  = std::vector<uint8_t>(sizeof(uint64_t)*key.size());
  pair.second = std::vector<uint8_t>(sizeof(uint64_t));

  uint8_t *key_data = pair.first.data();
  uint8_t *val_data = pair.second.data();

  for (size_t i=0; i<key.size(); i++)
  {
    uint64_t k = key.at(i);
    std::memcpy(key_data + sizeof(uint64_t) * i, &k, sizeof(k));
  }
  uint64_t v = val;
  std::memcpy(val_data, &v, sizeof(v));

  return pair;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> key_value_pair_str(std::vector<std::string> key, int val)
{
  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> pair;
  pair.first  = std::vector<uint8_t>(STRING_SIZE*key.size());
  pair.second = std::vector<uint8_t>(sizeof(uint64_t));

  uint8_t *key_data = pair.first.data();
  uint8_t *val_data = pair.second.data();

  for (size_t i=0; i<key.size(); i++)
  {
    strncpy((char*)key_data + STRING_SIZE*i, key.at(i).c_str(), STRING_SIZE);
  }
  uint64_t v = val;
  std::memcpy(val_data, &v, sizeof(v));

  return pair;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> key_value_pair_int_str(int myint, std::string mystr, int val)
{
  std::pair<std::vector<uint8_t>, std::vector<uint8_t>> pair;
  pair.first  = std::vector<uint8_t>(sizeof(uint64_t) + STRING_SIZE);
  pair.second = std::vector<uint8_t>(sizeof(uint64_t));

  uint8_t *key_data = pair.first.data();
  uint8_t *val_data = pair.second.data();

  uint64_t k = myint, v = val;
  std::memcpy(key_data, &k, sizeof(k));
  strncpy((char*)key_data + sizeof(uint64_t), mystr.c_str(), STRING_SIZE);
  std::memcpy(val_data, &v, sizeof(v));

  return pair;
}

TEST(bpftrace, sort_by_key_int)
{
  StrictMock<MockBPFtrace> bpftrace;

  std::vector<SizedType> key_args = { CreateUInt64() };
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> values_by_key =
  {
    key_value_pair_int({2}, 12),
    key_value_pair_int({3}, 11),
    key_value_pair_int({1}, 10),
  };
  bpftrace.sort_by_key(key_args, values_by_key);

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> expected_values =
  {
    key_value_pair_int({1}, 10),
    key_value_pair_int({2}, 12),
    key_value_pair_int({3}, 11),
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
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> values_by_key =
  {
    key_value_pair_int({5,2,1}, 1),
    key_value_pair_int({5,3,1}, 2),
    key_value_pair_int({5,1,1}, 3),
    key_value_pair_int({2,2,2}, 4),
    key_value_pair_int({2,3,2}, 5),
    key_value_pair_int({2,1,2}, 6),
  };
  bpftrace.sort_by_key(key_args, values_by_key);

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> expected_values =
  {
    key_value_pair_int({2,1,2}, 6),
    key_value_pair_int({2,2,2}, 4),
    key_value_pair_int({2,3,2}, 5),
    key_value_pair_int({5,1,1}, 3),
    key_value_pair_int({5,2,1}, 1),
    key_value_pair_int({5,3,1}, 2),
  };

  EXPECT_THAT(values_by_key, ContainerEq(expected_values));
}

TEST(bpftrace, sort_by_key_str)
{
  StrictMock<MockBPFtrace> bpftrace;

  std::vector<SizedType> key_args = {
    CreateString(STRING_SIZE),
  };
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> values_by_key =
  {
    key_value_pair_str({"z"}, 1),
    key_value_pair_str({"a"}, 2),
    key_value_pair_str({"x"}, 3),
    key_value_pair_str({"d"}, 4),
  };
  bpftrace.sort_by_key(key_args, values_by_key);

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> expected_values =
  {
    key_value_pair_str({"a"}, 2),
    key_value_pair_str({"d"}, 4),
    key_value_pair_str({"x"}, 3),
    key_value_pair_str({"z"}, 1),
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
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> values_by_key =
  {
    key_value_pair_str({"z", "a", "l"}, 1),
    key_value_pair_str({"a", "a", "m"}, 2),
    key_value_pair_str({"z", "c", "n"}, 3),
    key_value_pair_str({"a", "c", "o"}, 4),
    key_value_pair_str({"z", "b", "p"}, 5),
    key_value_pair_str({"a", "b", "q"}, 6),
  };
  bpftrace.sort_by_key(key_args, values_by_key);

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> expected_values =
  {
    key_value_pair_str({"a", "a", "m"}, 2),
    key_value_pair_str({"a", "b", "q"}, 6),
    key_value_pair_str({"a", "c", "o"}, 4),
    key_value_pair_str({"z", "a", "l"}, 1),
    key_value_pair_str({"z", "b", "p"}, 5),
    key_value_pair_str({"z", "c", "n"}, 3),
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
  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> values_by_key =
  {
    key_value_pair_int_str(1, "b", 1),
    key_value_pair_int_str(2, "b", 2),
    key_value_pair_int_str(3, "b", 3),
    key_value_pair_int_str(1, "a", 4),
    key_value_pair_int_str(2, "a", 5),
    key_value_pair_int_str(3, "a", 6),
  };
  bpftrace.sort_by_key(key_args, values_by_key);

  std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> expected_values =
  {
    key_value_pair_int_str(1, "a", 4),
    key_value_pair_int_str(1, "b", 1),
    key_value_pair_int_str(2, "a", 5),
    key_value_pair_int_str(2, "b", 2),
    key_value_pair_int_str(3, "a", 6),
    key_value_pair_int_str(3, "b", 3),
  };

  EXPECT_THAT(values_by_key, ContainerEq(expected_values));
}

#ifdef HAVE_LIBBPF_BTF_DUMP

#include "btf_common.h"

class bpftrace_btf : public test_btf
{
};

void check_probe(Probe &p, ProbeType type, const std::string &name)
{
  EXPECT_EQ(type, p.type);
  EXPECT_EQ(name, p.name);
}

TEST_F(bpftrace_btf, add_probes_kfunc)
{
  ast::Probe *probe = parse_probe("kfunc:func_1,kretfunc:func_1 {}");

  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(2U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  check_probe(bpftrace.get_probes().at(0), ProbeType::kfunc, "kfunc:func_1");
  check_probe(bpftrace.get_probes().at(1),
              ProbeType::kretfunc,
              "kretfunc:func_1");
}

TEST_F(bpftrace_btf, add_probes_iter_task)
{
  ast::Probe *probe = parse_probe("iter:task {}");

  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  check_probe(bpftrace.get_probes().at(0), ProbeType::iter, "iter:task");
}

TEST_F(bpftrace_btf, add_probes_iter_task_file)
{
  ast::Probe *probe = parse_probe("iter:task_file {}");

  StrictMock<MockBPFtrace> bpftrace;

  ASSERT_EQ(0, bpftrace.add_probe(*probe));
  ASSERT_EQ(1U, bpftrace.get_probes().size());
  ASSERT_EQ(0U, bpftrace.get_special_probes().size());

  check_probe(bpftrace.get_probes().at(0), ProbeType::iter, "iter:task_file");
}

#endif // HAVE_LIBBPF_BTF_DUMP

} // namespace bpftrace
} // namespace test
} // namespace bpftrace
