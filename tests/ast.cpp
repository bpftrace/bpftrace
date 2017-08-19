#include "gtest/gtest.h"
#include "ast.h"

namespace bpftrace {
namespace test {
namespace ast {

using bpftrace::ast::AttachPointList;
using bpftrace::ast::Probe;

TEST(ast, probe_name_special)
{
  Probe begin("BEGIN", nullptr, nullptr);
  EXPECT_EQ(begin.name(), "BEGIN");

  Probe end("END", nullptr, nullptr);
  EXPECT_EQ(end.name(), "END");
}

TEST(ast, probe_name_kprobe)
{
  AttachPointList attach_points1 = { "sys_read" };
  Probe kprobe1("kprobe", &attach_points1, nullptr, nullptr);
  EXPECT_EQ(kprobe1.name(), "kprobe:sys_read");

  AttachPointList attach_points2 = { "sys_read", "sys_write" };
  Probe kprobe2("kprobe", &attach_points2, nullptr, nullptr);
  EXPECT_EQ(kprobe2.name(), "kprobe:sys_read,sys_write");
}

TEST(ast, probe_name_uprobe)
{
  AttachPointList attach_points1 = { "readline" };
  Probe uprobe1("uprobe", "/bin/sh", &attach_points1, nullptr, nullptr);
  EXPECT_EQ(uprobe1.name(), "uprobe:/bin/sh:readline");

  AttachPointList attach_points2 = { "readline", "somefunc" };
  Probe uprobe2("uprobe", "/bin/sh", &attach_points2, nullptr, nullptr);
  EXPECT_EQ(uprobe2.name(), "uprobe:/bin/sh:readline,somefunc");
}

TEST(ast, probe_name_singular)
{
  AttachPointList attach_points = { "sys_read", "sys_thisone", "readline" };
  Probe kprobe("kprobe", &attach_points, nullptr, nullptr);
  EXPECT_EQ(kprobe.name("sys_thisone"), "kprobe:sys_thisone");

  Probe uprobe("uprobe", "/bin/sh", &attach_points, nullptr, nullptr);
  EXPECT_EQ(uprobe.name("readline"), "uprobe:/bin/sh:readline");
}

} // namespace ast
} // namespace test
} // namespace bpftrace
