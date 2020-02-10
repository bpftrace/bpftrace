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
  AttachPoint ap1("BEGIN");
  AttachPointList attach_points1 = { &ap1 };
  Probe begin(&attach_points1, nullptr, nullptr);
  EXPECT_EQ(begin.name(), "BEGIN");

  AttachPoint ap2("END");
  AttachPointList attach_points2 = { &ap2 };
  Probe end(&attach_points2, nullptr, nullptr);
  EXPECT_EQ(end.name(), "END");
}

TEST(ast, probe_name_kprobe)
{
  AttachPoint ap1("kprobe", "sys_read");
  AttachPointList attach_points1 = { &ap1 };
  Probe kprobe1(&attach_points1, nullptr, nullptr);
  EXPECT_EQ(kprobe1.name(), "kprobe:sys_read");

  AttachPoint ap2("kprobe", "sys_write");
  AttachPointList attach_points2 = { &ap1, &ap2 };
  Probe kprobe2(&attach_points2, nullptr, nullptr);
  EXPECT_EQ(kprobe2.name(), "kprobe:sys_read,kprobe:sys_write");

  AttachPoint ap3("kprobe", "sys_read", (uint64_t)10);
  AttachPointList attach_points3 = { &ap1, &ap2, &ap3 };
  Probe kprobe3(&attach_points3, nullptr, nullptr);
  EXPECT_EQ(kprobe3.name(),
            "kprobe:sys_read,kprobe:sys_write,kprobe:sys_read+10");
}

TEST(ast, probe_name_uprobe)
{
  AttachPoint ap1("uprobe", "/bin/sh", "readline", true);
  AttachPointList attach_points1 = { &ap1 };
  Probe uprobe1(&attach_points1, nullptr, nullptr);
  EXPECT_EQ(uprobe1.name(), "uprobe:/bin/sh:readline");

  AttachPoint ap2("uprobe", "/bin/sh", "somefunc", true);
  AttachPointList attach_points2 = { &ap1, &ap2 };
  Probe uprobe2(&attach_points2, nullptr, nullptr);
  EXPECT_EQ(uprobe2.name(), "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc");

  AttachPoint ap3("uprobe", "/bin/sh", 1000);
  AttachPointList attach_points3 = { &ap1, &ap2, &ap3 };
  Probe uprobe3(&attach_points3, nullptr, nullptr);
  EXPECT_EQ(uprobe3.name(), "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc,uprobe:/bin/sh:1000");

  AttachPoint ap4("uprobe", "/bin/sh", "somefunc", (uint64_t) 10);
  AttachPointList attach_points4 = { &ap1, &ap2, &ap3, &ap4 };
  Probe uprobe4(&attach_points4, nullptr, nullptr);
  EXPECT_EQ(uprobe4.name(), "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc,uprobe:/bin/sh:1000,uprobe:/bin/sh:somefunc+10");

  AttachPoint ap5("u", "/bin/sh", (uint64_t) 10);
  AttachPointList attach_points5 = { &ap5 };
  Probe uprobe5(&attach_points5, nullptr, nullptr);
  EXPECT_EQ(uprobe5.name(), "uprobe:/bin/sh:10");

  AttachPoint ap6("ur", "/bin/sh", (uint64_t) 10);
  AttachPointList attach_points6 = { &ap6 };
  Probe uprobe6(&attach_points6, nullptr, nullptr);
  EXPECT_EQ(uprobe6.name(), "uretprobe:/bin/sh:10");

  AttachPoint ap7("uretprobe", "/bin/sh", (uint64_t)1000);
  AttachPointList attach_points7 = { &ap7 };
  Probe uprobe7(&attach_points7, nullptr, nullptr);
  EXPECT_EQ(uprobe7.name(), "uretprobe:/bin/sh:1000");
}

TEST(ast, probe_name_usdt)
{
  AttachPoint ap1("usdt", "/bin/sh", "probe1", true);
  AttachPointList attach_points1 = { &ap1 };
  Probe usdt1(&attach_points1, nullptr, nullptr);
  EXPECT_EQ(usdt1.name(), "usdt:/bin/sh:probe1");

  AttachPoint ap2("usdt", "/bin/sh", "probe2", true);
  AttachPointList attach_points2 = { &ap1, &ap2 };
  Probe usdt2(&attach_points2, nullptr, nullptr);
  EXPECT_EQ(usdt2.name(), "usdt:/bin/sh:probe1,usdt:/bin/sh:probe2");
}

TEST(ast, attach_point_name)
{
  AttachPoint ap1("kprobe", "sys_read");
  AttachPoint ap2("kprobe", "sys_thisone");
  AttachPoint ap3("uprobe", "/bin/sh", "readline", true);
  AttachPointList attach_points = { &ap1, &ap2, &ap3 };
  Probe kprobe(&attach_points, nullptr, nullptr);
  EXPECT_EQ(ap2.name("sys_thisone"), "kprobe:sys_thisone");

  Probe uprobe(&attach_points, nullptr, nullptr);
  EXPECT_EQ(ap3.name("readline"), "uprobe:/bin/sh:readline");
}

} // namespace ast
} // namespace test
} // namespace bpftrace
