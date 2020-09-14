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
  auto ap1 = std::make_unique<AttachPoint>("");
  ap1->provider = "BEGIN";
  auto attach_points1 = std::make_unique<AttachPointList>();
  attach_points1->emplace_back(std::move(ap1));
  Probe begin(std::move(attach_points1), nullptr, nullptr);
  EXPECT_EQ(begin.name(), "BEGIN");

  auto ap2 = std::make_unique<AttachPoint>("");
  ap2->provider = "END";
  auto attach_points2 = std::make_unique<AttachPointList>();
  attach_points2->emplace_back(std::move(ap2));
  Probe end(std::move(attach_points2), nullptr, nullptr);
  EXPECT_EQ(end.name(), "END");
}

TEST(ast, probe_name_kprobe)
{
  auto ap1 = std::make_unique<AttachPoint>("");
  ap1->provider = "kprobe";
  ap1->func = "sys_read";
  auto attach_points1 = std::make_unique<AttachPointList>();
  attach_points1->emplace_back(std::move(ap1));
  Probe kprobe1(std::move(attach_points1), nullptr, nullptr);
  EXPECT_EQ(kprobe1.name(), "kprobe:sys_read");

  auto ap2 = std::make_unique<AttachPoint>("");
  ap2->provider = "kprobe";
  ap2->func = "sys_write";
  auto attach_points2 = std::make_unique<AttachPointList>();
  attach_points2->emplace_back(std::move(ap1));
  attach_points2->emplace_back(std::move(ap2));
  Probe kprobe2(std::move(attach_points2), nullptr, nullptr);
  EXPECT_EQ(kprobe2.name(), "kprobe:sys_read,kprobe:sys_write");

  auto ap3 = std::make_unique<AttachPoint>("");
  ap3->provider = "kprobe";
  ap3->func = "sys_read";
  ap3->func_offset = 10;
  auto attach_points3 = std::make_unique<AttachPointList>();
  attach_points3->emplace_back(std::move(ap1));
  attach_points3->emplace_back(std::move(ap2));
  attach_points3->emplace_back(std::move(ap3));
  Probe kprobe3(std::move(attach_points3), nullptr, nullptr);
  EXPECT_EQ(kprobe3.name(),
            "kprobe:sys_read,kprobe:sys_write,kprobe:sys_read+10");
}

TEST(ast, probe_name_uprobe)
{
  auto ap1 = std::make_unique<AttachPoint>("");
  ap1->provider = "uprobe";
  ap1->target = "/bin/sh";
  ap1->func = "readline";
  auto attach_points1 = std::make_unique<AttachPointList>();
  attach_points1->emplace_back(std::move(ap1));
  Probe uprobe1(std::move(attach_points1), nullptr, nullptr);
  EXPECT_EQ(uprobe1.name(), "uprobe:/bin/sh:readline");

  auto ap2 = std::make_unique<AttachPoint>("");
  ap2->provider = "uprobe";
  ap2->target = "/bin/sh";
  ap2->func = "somefunc";
  auto attach_points2 = std::make_unique<AttachPointList>();
  attach_points2->emplace_back(std::move(ap1));
  attach_points2->emplace_back(std::move(ap2));
  Probe uprobe2(std::move(attach_points2), nullptr, nullptr);
  EXPECT_EQ(uprobe2.name(), "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc");

  auto ap3 = std::make_unique<AttachPoint>("");
  ap3->provider = "uprobe";
  ap3->target = "/bin/sh";
  ap3->address = 1000;
  auto attach_points3 = std::make_unique<AttachPointList>();
  attach_points3->emplace_back(std::move(ap1));
  attach_points3->emplace_back(std::move(ap2));
  attach_points3->emplace_back(std::move(ap3));
  Probe uprobe3(std::move(attach_points3), nullptr, nullptr);
  EXPECT_EQ(uprobe3.name(), "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc,uprobe:/bin/sh:1000");

  auto ap4 = std::make_unique<AttachPoint>("");
  ap4->provider = "uprobe";
  ap4->target = "/bin/sh";
  ap4->func = "somefunc";
  ap4->func_offset = 10;
  auto attach_points4 = std::make_unique<AttachPointList>();
  attach_points4->emplace_back(std::move(ap1));
  attach_points4->emplace_back(std::move(ap2));
  attach_points4->emplace_back(std::move(ap3));
  attach_points4->emplace_back(std::move(ap4));
  Probe uprobe4(std::move(attach_points4), nullptr, nullptr);
  EXPECT_EQ(uprobe4.name(), "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc,uprobe:/bin/sh:1000,uprobe:/bin/sh:somefunc+10");

  auto ap5 = std::make_unique<AttachPoint>("");
  ap5->provider = "uprobe";
  ap5->target = "/bin/sh";
  ap5->address = 10;
  auto attach_points5 = std::make_unique<AttachPointList>();
  attach_points5->emplace_back(std::move(ap5));
  Probe uprobe5(std::move(attach_points5), nullptr, nullptr);
  EXPECT_EQ(uprobe5.name(), "uprobe:/bin/sh:10");

  auto ap6 = std::make_unique<AttachPoint>("");
  ap6->provider = "uretprobe";
  ap6->target = "/bin/sh";
  ap6->address = 10;
  auto attach_points6 = std::make_unique<AttachPointList>();
  attach_points6->emplace_back(std::move(ap6));
  Probe uprobe6(std::move(attach_points6), nullptr, nullptr);
  EXPECT_EQ(uprobe6.name(), "uretprobe:/bin/sh:10");
}

TEST(ast, probe_name_usdt)
{
  auto ap1 = std::make_unique<AttachPoint>("");
  ap1->provider = "usdt";
  ap1->target = "/bin/sh";
  ap1->func = "probe1";
  auto attach_points1 = std::make_unique<AttachPointList>();
  attach_points1->emplace_back(std::move(ap1));
  Probe usdt1(std::move(attach_points1), nullptr, nullptr);
  EXPECT_EQ(usdt1.name(), "usdt:/bin/sh:probe1");

  auto ap2 = std::make_unique<AttachPoint>("");
  ap2->provider = "usdt";
  ap2->target = "/bin/sh";
  ap2->func = "probe2";
  auto attach_points2 = std::make_unique<AttachPointList>();
  attach_points2->emplace_back(std::move(ap1));
  attach_points2->emplace_back(std::move(ap2));
  Probe usdt2(std::move(attach_points2), nullptr, nullptr);
  EXPECT_EQ(usdt2.name(), "usdt:/bin/sh:probe1,usdt:/bin/sh:probe2");
}

TEST(ast, attach_point_name)
{
  auto ap1 = std::make_unique<AttachPoint>("");
  ap1->provider = "kprobe";
  ap1->func = "sys_read";
  auto ap2 = std::make_unique<AttachPoint>("");
  ap2->provider = "kprobe";
  ap2->func = "sys_thisone";
  auto ap3 = std::make_unique<AttachPoint>("");
  ap3->provider = "uprobe";
  ap3->target = "/bin/sh";
  ap3->func = "readline";
  auto attach_points = std::make_unique<AttachPointList>();
  attach_points->emplace_back(std::move(ap1));
  attach_points->emplace_back(std::move(ap2));
  attach_points->emplace_back(std::move(ap3));
  Probe kprobe(std::move(attach_points), nullptr, nullptr);
  EXPECT_EQ(ap2->name("sys_thisone"), "kprobe:sys_thisone");

  Probe uprobe(std::move(attach_points), nullptr, nullptr);
  EXPECT_EQ(ap3->name("readline"), "uprobe:/bin/sh:readline");
}

} // namespace ast
} // namespace test
} // namespace bpftrace
