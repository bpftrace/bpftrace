#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "bpftrace.h"

namespace bpftrace {
namespace test {
namespace bpftrace {

class MockBPFtrace : public BPFtrace {
public:
  MOCK_METHOD2(find_wildcard_matches, std::set<std::string>(std::string attach_point, std::string file));
  std::vector<Probe> get_probes()
  {
    return probes_;
  }
  std::vector<Probe> get_special_probes()
  {
    return special_probes_;
  }
};

using ::testing::_;
using ::testing::Return;
using ::testing::StrictMock;

void check_kprobe(Probe &p, const std::string &attach_point, const std::string &prog_name)
{
  EXPECT_EQ(p.type, ProbeType::kprobe);
  EXPECT_EQ(p.attach_point, attach_point);
  EXPECT_EQ(p.prog_name, prog_name);
  EXPECT_EQ(p.name, "kprobe:" + attach_point);
}

void check_uprobe(Probe &p, const std::string &path, const std::string &attach_point, const std::string &prog_name)
{
  EXPECT_EQ(p.type, ProbeType::uprobe);
  EXPECT_EQ(p.attach_point, attach_point);
  EXPECT_EQ(p.prog_name, prog_name);
  EXPECT_EQ(p.name, "uprobe:" + path + ":" + attach_point);
}

void check_special_probe(Probe &p, const std::string &attach_point, const std::string &prog_name)
{
  EXPECT_EQ(p.type, ProbeType::uprobe);
  EXPECT_EQ(p.attach_point, attach_point);
  EXPECT_EQ(p.prog_name, prog_name);
  EXPECT_EQ(p.name, prog_name);
}

TEST(bpftrace, add_begin_probe)
{
  ast::Probe probe("BEGIN", nullptr, nullptr);

  StrictMock<MockBPFtrace> bpftrace;
  EXPECT_EQ(bpftrace.add_probe(probe), 0);
  EXPECT_EQ(bpftrace.get_probes().size(), 0);
  EXPECT_EQ(bpftrace.get_special_probes().size(), 1);

  check_special_probe(bpftrace.get_special_probes().at(0), "BEGIN_trigger", "BEGIN");
}

TEST(bpftrace, add_end_probe)
{
  ast::Probe probe("END", nullptr, nullptr);

  StrictMock<MockBPFtrace> bpftrace;
  EXPECT_EQ(bpftrace.add_probe(probe), 0);
  EXPECT_EQ(bpftrace.get_probes().size(), 0);
  EXPECT_EQ(bpftrace.get_special_probes().size(), 1);

  check_special_probe(bpftrace.get_special_probes().at(0), "END_trigger", "END");
}

TEST(bpftrace, add_probes_single)
{
  ast::AttachPointList attach_points = {"sys_read"};
  ast::Probe probe("kprobe", &attach_points, nullptr, nullptr);

  StrictMock<MockBPFtrace> bpftrace;
  EXPECT_EQ(bpftrace.add_probe(probe), 0);
  EXPECT_EQ(bpftrace.get_probes().size(), 1);
  EXPECT_EQ(bpftrace.get_special_probes().size(), 0);

  check_kprobe(bpftrace.get_probes().at(0), "sys_read", "kprobe:sys_read");
}

TEST(bpftrace, add_probes_multiple)
{
  ast::AttachPointList attach_points = {"sys_read", "sys_write"};
  ast::Probe probe("kprobe", &attach_points, nullptr, nullptr);

  StrictMock<MockBPFtrace> bpftrace;
  EXPECT_EQ(bpftrace.add_probe(probe), 0);
  EXPECT_EQ(bpftrace.get_probes().size(), 2);
  EXPECT_EQ(bpftrace.get_special_probes().size(), 0);

  std::string probe_prog_name = "kprobe:sys_read,sys_write";
  check_kprobe(bpftrace.get_probes().at(0), "sys_read", probe_prog_name);
  check_kprobe(bpftrace.get_probes().at(1), "sys_write", probe_prog_name);
}

TEST(bpftrace, add_probes_wildcard)
{
  ast::AttachPointList attach_points = {"sys_read", "my_*", "sys_write"};
  ast::Probe probe("kprobe", &attach_points, nullptr, nullptr);

  StrictMock<MockBPFtrace> bpftrace;
  std::set<std::string> matches = { "my_one", "my_two" };
  ON_CALL(bpftrace, find_wildcard_matches(_, _))
    .WillByDefault(Return(matches));
  EXPECT_CALL(bpftrace,
      find_wildcard_matches("my_*",
        "/sys/kernel/debug/tracing/available_filter_functions"))
    .Times(1);

  EXPECT_EQ(bpftrace.add_probe(probe), 0);
  EXPECT_EQ(bpftrace.get_probes().size(), 4);
  EXPECT_EQ(bpftrace.get_special_probes().size(), 0);

  std::string probe_prog_name = "kprobe:sys_read,my_*,sys_write";
  check_kprobe(bpftrace.get_probes().at(0), "sys_read", probe_prog_name);
  check_kprobe(bpftrace.get_probes().at(1), "my_one", probe_prog_name);
  check_kprobe(bpftrace.get_probes().at(2), "my_two", probe_prog_name);
  check_kprobe(bpftrace.get_probes().at(3), "sys_write", probe_prog_name);
}

TEST(bpftrace, add_probes_wildcard_no_matches)
{
  ast::AttachPointList attach_points = {"sys_read", "my_*", "sys_write"};
  ast::Probe probe("kprobe", &attach_points, nullptr, nullptr);

  StrictMock<MockBPFtrace> bpftrace;
  std::set<std::string> matches;
  ON_CALL(bpftrace, find_wildcard_matches(_, _))
    .WillByDefault(Return(matches));
  EXPECT_CALL(bpftrace,
      find_wildcard_matches("my_*",
        "/sys/kernel/debug/tracing/available_filter_functions"))
    .Times(1);

  EXPECT_EQ(bpftrace.add_probe(probe), 0);
  EXPECT_EQ(bpftrace.get_probes().size(), 2);
  EXPECT_EQ(bpftrace.get_special_probes().size(), 0);

  std::string probe_prog_name = "kprobe:sys_read,my_*,sys_write";
  check_kprobe(bpftrace.get_probes().at(0), "sys_read", probe_prog_name);
  check_kprobe(bpftrace.get_probes().at(1), "sys_write", probe_prog_name);
}

TEST(bpftrace, add_probes_uprobe)
{
  ast::AttachPointList attach_points = {"foo"};
  ast::Probe probe("uprobe", "/bin/sh", &attach_points, nullptr, nullptr);

  StrictMock<MockBPFtrace> bpftrace;

  EXPECT_EQ(bpftrace.add_probe(probe), 0);
  EXPECT_EQ(bpftrace.get_probes().size(), 1);
  EXPECT_EQ(bpftrace.get_special_probes().size(), 0);
  check_uprobe(bpftrace.get_probes().at(0), "/bin/sh", "foo", "uprobe:/bin/sh:foo");
}

TEST(bpftrace, add_probes_uprobe_wildcard)
{
  ast::AttachPointList attach_points = {"foo*"};
  ast::Probe probe("uprobe", "/bin/sh", &attach_points, nullptr, nullptr);

  StrictMock<MockBPFtrace> bpftrace;

  EXPECT_NE(bpftrace.add_probe(probe), 0);
  EXPECT_EQ(bpftrace.get_probes().size(), 0);
  EXPECT_EQ(bpftrace.get_special_probes().size(), 0);
}

} // namespace bpftrace
} // namespace test
} // namespace bpftrace
