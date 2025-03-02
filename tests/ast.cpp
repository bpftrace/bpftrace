#include "ast/ast.h"
#include "ast/context.h"

#include "gtest/gtest.h"

namespace bpftrace::test::ast {

using bpftrace::ast::ASTContext;
using bpftrace::ast::AttachPoint;
using bpftrace::ast::AttachPointList;
using bpftrace::ast::Diagnostics;
using bpftrace::ast::Probe;

TEST(ast, probe_name_special)
{
  ASTContext ast;
  auto &ap1 = *ast.make_node<AttachPoint>("", false, location());
  ap1.provider = "BEGIN";
  auto &begin = *ast.make_node<Probe>(
      AttachPointList({ &ap1 }), nullptr, nullptr, location());
  EXPECT_EQ(begin.name(), "BEGIN");

  auto &ap2 = *ast.make_node<AttachPoint>("", false, location());
  ap2.provider = "END";
  auto &end = *ast.make_node<Probe>(
      AttachPointList({ &ap2 }), nullptr, nullptr, location());
  EXPECT_EQ(end.name(), "END");
}

TEST(ast, probe_name_kprobe)
{
  ASTContext ast;
  auto &ap1 = *ast.make_node<AttachPoint>("", false, location());
  ap1.provider = "kprobe";
  ap1.func = "sys_read";

  auto &ap2 = *ast.make_node<AttachPoint>("", false, location());
  ap2.provider = "kprobe";
  ap2.func = "sys_write";

  auto &ap3 = *ast.make_node<AttachPoint>("", false, location());
  ap3.provider = "kprobe";
  ap3.func = "sys_read";
  ap3.func_offset = 10;

  auto &kprobe1 = *ast.make_node<Probe>(
      AttachPointList({ &ap1 }), nullptr, nullptr, location());
  EXPECT_EQ(kprobe1.name(), "kprobe:sys_read");

  auto &kprobe2 = *ast.make_node<Probe>(
      AttachPointList({ &ap1, &ap2 }), nullptr, nullptr, location());
  EXPECT_EQ(kprobe2.name(), "kprobe:sys_read,kprobe:sys_write");

  auto &kprobe3 = *ast.make_node<Probe>(
      AttachPointList({ &ap1, &ap2, &ap3 }), nullptr, nullptr, location());
  EXPECT_EQ(kprobe3.name(),
            "kprobe:sys_read,kprobe:sys_write,kprobe:sys_read+10");
}

TEST(ast, probe_name_uprobe)
{
  ASTContext ast;
  auto &ap1 = *ast.make_node<AttachPoint>("", false, location());
  ap1.provider = "uprobe";
  ap1.target = "/bin/sh";
  ap1.func = "readline";
  auto &uprobe1 = *ast.make_node<Probe>(
      AttachPointList({ &ap1 }), nullptr, nullptr, location());
  EXPECT_EQ(uprobe1.name(), "uprobe:/bin/sh:readline");

  auto &ap2 = *ast.make_node<AttachPoint>("", false, location());
  ap2.provider = "uprobe";
  ap2.target = "/bin/sh";
  ap2.func = "somefunc";
  auto &uprobe2 = *ast.make_node<Probe>(
      AttachPointList({ &ap1, &ap2 }), nullptr, nullptr, location());
  EXPECT_EQ(uprobe2.name(), "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc");

  auto &ap3 = *ast.make_node<AttachPoint>("", false, location());
  ap3.provider = "uprobe";
  ap3.target = "/bin/sh";
  ap3.address = 1000;
  auto &uprobe3 = *ast.make_node<Probe>(
      AttachPointList({ &ap1, &ap2, &ap3 }), nullptr, nullptr, location());
  EXPECT_EQ(
      uprobe3.name(),
      "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc,uprobe:/bin/sh:1000");

  auto &ap4 = *ast.make_node<AttachPoint>("", false, location());
  ap4.provider = "uprobe";
  ap4.target = "/bin/sh";
  ap4.func = "somefunc";
  ap4.func_offset = 10;
  auto &uprobe4 = *ast.make_node<Probe>(AttachPointList(
                                            { &ap1, &ap2, &ap3, &ap4 }),
                                        nullptr,
                                        nullptr,
                                        location());
  EXPECT_EQ(uprobe4.name(),
            "uprobe:/bin/sh:readline,uprobe:/bin/sh:somefunc,uprobe:/bin/"
            "sh:1000,uprobe:/bin/sh:somefunc+10");

  auto &ap5 = *ast.make_node<AttachPoint>("", false, location());
  ap5.provider = "uprobe";
  ap5.target = "/bin/sh";
  ap5.address = 10;
  auto &uprobe5 = *ast.make_node<Probe>(
      AttachPointList({ &ap5 }), nullptr, nullptr, location());
  EXPECT_EQ(uprobe5.name(), "uprobe:/bin/sh:10");

  auto &ap6 = *ast.make_node<AttachPoint>("", false, location());
  ap6.provider = "uretprobe";
  ap6.target = "/bin/sh";
  ap6.address = 10;
  auto &uprobe6 = *ast.make_node<Probe>(
      AttachPointList({ &ap6 }), nullptr, nullptr, location());
  EXPECT_EQ(uprobe6.name(), "uretprobe:/bin/sh:10");
}

TEST(ast, probe_name_usdt)
{
  ASTContext ast;
  auto &ap1 = *ast.make_node<AttachPoint>("", false, location());
  ap1.provider = "usdt";
  ap1.target = "/bin/sh";
  ap1.func = "probe1";
  auto &usdt1 = *ast.make_node<Probe>(
      AttachPointList({ &ap1 }), nullptr, nullptr, location());
  EXPECT_EQ(usdt1.name(), "usdt:/bin/sh:probe1");

  auto &ap2 = *ast.make_node<AttachPoint>("", false, location());
  ap2.provider = "usdt";
  ap2.target = "/bin/sh";
  ap2.func = "probe2";
  auto &usdt2 = *ast.make_node<Probe>(
      AttachPointList({ &ap1, &ap2 }), nullptr, nullptr, location());
  EXPECT_EQ(usdt2.name(), "usdt:/bin/sh:probe1,usdt:/bin/sh:probe2");
}

TEST(ast, attach_point_name)
{
  ASTContext ast;
  auto &ap1 = *ast.make_node<AttachPoint>("", false, location());
  ap1.provider = "kprobe";
  ap1.func = "sys_read";
  auto &ap2 = *ast.make_node<AttachPoint>("", false, location());
  ap2.provider = "kprobe";
  ap2.func = "sys_thisone";
  auto &ap3 = *ast.make_node<AttachPoint>("", false, location());
  ap3.provider = "uprobe";
  ap3.target = "/bin/sh";
  ap3.func = "readline";

  ast.make_node<Probe>(
      AttachPointList({ &ap1, &ap2, &ap3 }), nullptr, nullptr, location());
  EXPECT_EQ(ap2.name(), "kprobe:sys_thisone");

  ast.make_node<Probe>(
      AttachPointList({ &ap1, &ap2, &ap3 }), nullptr, nullptr, location());
  EXPECT_EQ(ap3.name(), "uprobe:/bin/sh:readline");
}

} // namespace bpftrace::test::ast
