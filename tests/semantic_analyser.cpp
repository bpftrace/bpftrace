#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "bpftrace.h"
#include "parser.tab.hh"
#include "semantic_analyser.h"

namespace bpftrace {

class MockBPFtrace : public BPFtrace {
public:
  MOCK_METHOD1(add_probe, int(ast::Probe &p));
};

namespace ast {

using ::testing::_;

TEST(semantic_analyser, probe_count)
{
  MockBPFtrace bpftrace;
  EXPECT_CALL(bpftrace, add_probe(_)).Times(2);

  // kprobe:kprobe { 123; }
  // kprobe:kprobe { 123; }
  Integer expr(123);
  ExprStatement stmt(&expr);
  StatementList stmts = {&stmt};
  std::string str = "kprobe";
  Probe p1(str, str, &stmts);
  Probe p2(str, str, &stmts);
  ProbeList pl = {&p1, &p2};
  Program root(&pl);

  bpftrace::ast::SemanticAnalyser semantics(&root, bpftrace);
  semantics.analyse();
}

TEST(semantic_analyser, undefined_map)
{
  BPFtrace bpftrace;

  // kprobe:kprobe / @mymap1 == 123 / { 123; }
  std::string str = "kprobe";
  std::string mapstr1 = "mymap1";
  Integer myint(123);
  Map map1(mapstr1);
  Binop binop(&map1, bpftrace::Parser::token::EQ, &myint);
  Predicate pred(&binop);
  ExprStatement stmt(&myint);
  StatementList stmts = {&stmt};
  Probe p(str, str, &pred, &stmts);
  ProbeList pl = {&p};
  Program root(&pl);

  std::ostringstream out1;
  bpftrace::ast::SemanticAnalyser semantics1(&root, bpftrace, out1);
  EXPECT_EQ(semantics1.analyse(), 10);

  // kprobe:kprobe / @mymap1 == 123 / { 123; @mymap1 = @mymap2; }
  std::string mapstr2 = "mymap2";
  Map map2(mapstr2);
  AssignMapStatement assign(&map1, &map2);
  stmts.push_back(&assign);

  std::ostringstream out2;
  bpftrace::ast::SemanticAnalyser semantics2(&root, bpftrace, out2);
  EXPECT_EQ(semantics2.analyse(), 10);
}

} // namespace ast
} // namespace bpftrace
