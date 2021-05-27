#include "ast/ast.h"

#include "gtest/gtest.h"

namespace bpftrace {
namespace test {
namespace ast {

using bpftrace::ast::AttachPoint;
using bpftrace::ast::AttachPointList;
using bpftrace::ast::Probe;

static AttachPointList *APL(std::vector<AttachPoint *> list)
{
  auto apl = new AttachPointList();
  for (auto l : list)
    apl->push_back(l->leafcopy());
  return apl;
}

TEST(ast, probe_name_special)
{
  auto ap1 = new AttachPoint("");
  ap1->provider = "BEGIN";
  auto attach_points1 = APL({ ap1 });
  Probe begin(attach_points1, nullptr, nullptr);
  EXPECT_EQ(begin.name(), "BEGIN");

  auto ap2 = new AttachPoint("");
  ap2->provider = "END";
  auto attach_points2 = APL({ ap2 });
  Probe end(attach_points2, nullptr, nullptr);
  EXPECT_EQ(end.name(), "END");
}

TEST(ast, probe_name_kprobe)
{
  auto ap1 = new AttachPoint("");
  ap1->provider = "kprobe";
  ap1->func = "sys_read";

  auto ap2 = new AttachPoint("");
  ap2->provider = "kprobe";
  ap2->func = "sys_write";

  auto ap3 = new AttachPoint("");
  ap3->provider = "kprobe";
  ap3->func = "sys_read";
  ap3->func_offset = 10;

  auto attach_points1 = APL({ ap1 });
  Probe kprobe1(attach_points1, nullptr, nullptr);
  EXPECT_EQ(kprobe1.name(), "kprobe:sys_read");

  auto ap2_copy1 = ap2->leafcopy();
  auto attach_points2 = APL({ ap1, ap2 });
  Probe kprobe2(attach_points2, nullptr, nullptr);
  EXPECT_EQ(kprobe2.name(), "kprobe:sys_read,kprobe:sys_write");

  auto attach_points3 = APL({ ap1, ap2_copy1, ap3 });
  Probe kprobe3(attach_points3, nullptr, nullptr);
  EXPECT_EQ(kprobe3.name(),
            "kprobe:sys_read,kprobe:sys_write,kprobe:sys_read+10");
}

TEST(ast, probe_name_uprobe)
{
  auto ap1 = new AttachPoint("");
  ap1->provider = "uprobe";
  ap1->target = "/bin/sh";
  ap1->func = "readline";
  auto attach_points1 = APL({ ap1 });
  Probe uprobe1(attach_points1, nullptr, nullptr);
  EXPECT_EQ(uprobe1.name(), "uprobe:/bin/sh:readline");

  auto ap2 = new AttachPoint("");
  ap2->provider = "uprobe";
  ap2->target = "/bin/sh";
  ap2->func = "somefunc";
  auto attach_points2 = APL({ ap1, ap2 });
  Probe uprobe2(attach_points2, nullptr, nullptr);
  EXPECT_EQ(uprobe2.name(), "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc");

  auto ap3 = new AttachPoint("");
  ap3->provider = "uprobe";
  ap3->target = "/bin/sh";
  ap3->address = 1000;
  auto attach_points3 = APL({ ap1, ap2, ap3 });
  Probe uprobe3(attach_points3, nullptr, nullptr);
  EXPECT_EQ(uprobe3.name(), "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc,uprobe:/bin/sh:1000");

  auto ap4 = new AttachPoint("");
  ap4->provider = "uprobe";
  ap4->target = "/bin/sh";
  ap4->func = "somefunc";
  ap4->func_offset = 10;
  auto attach_points4 = APL({ ap1, ap2, ap3, ap4 });
  Probe uprobe4(attach_points4, nullptr, nullptr);
  EXPECT_EQ(uprobe4.name(), "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc,uprobe:/bin/sh:1000,uprobe:/bin/sh:somefunc+10");

  auto ap5 = new AttachPoint("");
  ap5->provider = "uprobe";
  ap5->target = "/bin/sh";
  ap5->address = 10;
  auto attach_points5 = APL({ ap5 });
  Probe uprobe5(attach_points5, nullptr, nullptr);
  EXPECT_EQ(uprobe5.name(), "uprobe:/bin/sh:10");

  auto ap6 = new AttachPoint("");
  ap6->provider = "uretprobe";
  ap6->target = "/bin/sh";
  ap6->address = 10;
  auto attach_points6 = APL({ ap6 });
  Probe uprobe6(attach_points6, nullptr, nullptr);
  EXPECT_EQ(uprobe6.name(), "uretprobe:/bin/sh:10");
}

TEST(ast, probe_name_usdt)
{
  auto ap1 = new AttachPoint("");
  ap1->provider = "usdt";
  ap1->target = "/bin/sh";
  ap1->func = "probe1";
  auto attach_points1 = APL({ ap1 });
  Probe usdt1(attach_points1, nullptr, nullptr);
  EXPECT_EQ(usdt1.name(), "usdt:/bin/sh:probe1");

  auto ap2 = new AttachPoint("");
  ap2->provider = "usdt";
  ap2->target = "/bin/sh";
  ap2->func = "probe2";
  auto attach_points2 = APL({ ap1, ap2 });
  Probe usdt2(attach_points2, nullptr, nullptr);
  EXPECT_EQ(usdt2.name(), "usdt:/bin/sh:probe1,usdt:/bin/sh:probe2");
}

TEST(ast, attach_point_name)
{
  auto ap1 = new AttachPoint("");
  ap1->provider = "kprobe";
  ap1->func = "sys_read";
  auto ap2 = new AttachPoint("");
  ap2->provider = "kprobe";
  ap2->func = "sys_thisone";
  auto ap3 = new AttachPoint("");
  ap3->provider = "uprobe";
  ap3->target = "/bin/sh";
  ap3->func = "readline";
  auto attach_points = APL({ ap1, ap2, ap3 });
  Probe kprobe(attach_points, nullptr, nullptr);
  EXPECT_EQ(ap2->name("sys_thisone"), "kprobe:sys_thisone");

  attach_points = APL({ ap1, ap2, ap3 });
  Probe uprobe(attach_points, nullptr, nullptr);
  EXPECT_EQ(ap3->name("readline"), "uprobe:/bin/sh:readline");
}

} // namespace ast
} // namespace test
} // namespace bpftrace
