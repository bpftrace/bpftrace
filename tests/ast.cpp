#include "gtest/gtest.h"
#include "ast.h"

namespace bpftrace {
namespace test {
namespace ast {

using bpftrace::ast::AttachPoint;
using bpftrace::ast::AttachPointList;
using bpftrace::ast::Probe;

TEST(ast, probe_name_special)
{
  // Can't allocate these on the stack
  AttachPoint *ap1 = new AttachPoint("BEGIN");
  AttachPointList *attach_points1 = new AttachPointList({ ap1 });
  Probe begin(attach_points1, nullptr, nullptr);
  EXPECT_EQ(begin.name(), "BEGIN");

  AttachPoint *ap2 = new AttachPoint("END");
  AttachPointList *attach_points2 = new AttachPointList({ ap2 });
  Probe end(attach_points2, nullptr, nullptr);
  EXPECT_EQ(end.name(), "END");
}

TEST(ast, probe_name_kprobe)
{
  AttachPoint *ap1 = new AttachPoint("kprobe", "sys_read");
  AttachPointList *attach_points1 = new AttachPointList({ ap1 });
  Probe kprobe1(attach_points1, nullptr, nullptr);
  EXPECT_EQ(kprobe1.name(), "kprobe:sys_read");

  AttachPoint *ap1_copy = new AttachPoint("kprobe", "sys_read");
  AttachPoint *ap2 = new AttachPoint("kprobe", "sys_write");
  AttachPointList *attach_points2 = new AttachPointList({ ap1_copy, ap2 });
  Probe kprobe2(attach_points2, nullptr, nullptr);
  EXPECT_EQ(kprobe2.name(), "kprobe:sys_read,kprobe:sys_write");
}

TEST(ast, probe_name_uprobe)
{
  AttachPoint *ap1 = new AttachPoint("uprobe", "/bin/sh", "readline", true);
  AttachPointList *attach_points1 = new AttachPointList({ ap1 });
  Probe uprobe1(attach_points1, nullptr, nullptr);
  EXPECT_EQ(uprobe1.name(), "uprobe:/bin/sh:readline");

  ap1 = new AttachPoint("uprobe", "/bin/sh", "readline", true);
  AttachPoint *ap2 = new AttachPoint("uprobe", "/bin/sh", "somefunc", true);
  AttachPointList *attach_points2 = new AttachPointList({ ap1, ap2 });
  Probe uprobe2(attach_points2, nullptr, nullptr);
  EXPECT_EQ(uprobe2.name(), "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc");

  ap1 = new AttachPoint("uprobe", "/bin/sh", "readline", true);
  ap2 = new AttachPoint("uprobe", "/bin/sh", "somefunc", true);
  AttachPoint *ap3 = new AttachPoint("uprobe", "/bin/sh", 1000);
  AttachPointList *attach_points3 = new AttachPointList({ ap1, ap2, ap3 });
  Probe uprobe3(attach_points3, nullptr, nullptr);
  EXPECT_EQ(uprobe3.name(), "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc,uprobe:/bin/sh:1000");

  ap1 = new AttachPoint("uprobe", "/bin/sh", "readline", true);
  ap2 = new AttachPoint("uprobe", "/bin/sh", "somefunc", true);
  ap3 = new AttachPoint("uprobe", "/bin/sh", 1000);
  AttachPoint *ap4 =
      new AttachPoint("uprobe", "/bin/sh", "somefunc", (uint64_t)10);
  AttachPointList *attach_points4 = new AttachPointList({ ap1, ap2, ap3, ap4 });
  Probe uprobe4(attach_points4, nullptr, nullptr);
  EXPECT_EQ(uprobe4.name(), "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc,uprobe:/bin/sh:1000,uprobe:/bin/sh:somefunc+10");

  AttachPoint *ap5 = new AttachPoint("u", "/bin/sh", (uint64_t)10);
  AttachPointList *attach_points5 = new AttachPointList({ ap5 });
  Probe uprobe5(attach_points5, nullptr, nullptr);
  EXPECT_EQ(uprobe5.name(), "uprobe:/bin/sh:10");

  AttachPoint *ap6 = new AttachPoint("ur", "/bin/sh", (uint64_t)10);
  AttachPointList *attach_points6 = new AttachPointList({ ap6 });
  Probe uprobe6(attach_points6, nullptr, nullptr);
  EXPECT_EQ(uprobe6.name(), "uretprobe:/bin/sh:10");

  AttachPoint *ap7 = new AttachPoint("uretprobe", "/bin/sh", (uint64_t)1000);
  AttachPointList *attach_points7 = new AttachPointList({ ap7 });
  Probe uprobe7(attach_points7, nullptr, nullptr);
  EXPECT_EQ(uprobe7.name(), "uretprobe:/bin/sh:1000");
}

TEST(ast, probe_name_usdt)
{
  AttachPoint *ap1 = new AttachPoint("usdt", "/bin/sh", "probe1", true);
  AttachPointList *attach_points1 = new AttachPointList({ ap1 });
  Probe usdt1(attach_points1, nullptr, nullptr);
  EXPECT_EQ(usdt1.name(), "usdt:/bin/sh:probe1");

  ap1 = new AttachPoint("usdt", "/bin/sh", "probe1", true);
  AttachPoint *ap2 = new AttachPoint("usdt", "/bin/sh", "probe2", true);
  AttachPointList *attach_points2 = new AttachPointList({ ap1, ap2 });
  Probe usdt2(attach_points2, nullptr, nullptr);
  EXPECT_EQ(usdt2.name(), "usdt:/bin/sh:probe1,usdt:/bin/sh:probe2");
}

TEST(ast, attach_point_name)
{
  AttachPoint *ap2 = new AttachPoint("kprobe", "sys_thisone");
  AttachPoint *ap3 = new AttachPoint("uprobe", "/bin/sh", "readline", true);
  EXPECT_EQ(ap2->name("sys_thisone"), "kprobe:sys_thisone");
  EXPECT_EQ(ap3->name("readline"), "uprobe:/bin/sh:readline");
}

} // namespace ast
} // namespace test
} // namespace bpftrace
