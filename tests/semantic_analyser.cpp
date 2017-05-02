#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "bpftrace.h"
#include "semantic_analyser.h"

using ::testing::_;
using ebpf::bpftrace::ast::ExprStatement;
using ebpf::bpftrace::ast::Integer;
using ebpf::bpftrace::ast::Probe;
using ebpf::bpftrace::ast::ProbeList;
using ebpf::bpftrace::ast::Program;
using ebpf::bpftrace::ast::StatementList;

class MockBPFtrace : public ebpf::bpftrace::BPFtrace {
public:
  MOCK_METHOD1(add_probe, int(Probe &p));
};

TEST(semantic_analyser, probe_count)
{
  MockBPFtrace bpftrace;
  EXPECT_CALL(bpftrace, add_probe(_)).Times(2);

  Integer expr(123);
  ExprStatement stmt(&expr);
  StatementList stmts = {&stmt};
  std::string str = "kprobe";
  Probe p1(str, str, &stmts);
  Probe p2(str, str, &stmts);
  ProbeList pl = {&p1, &p2};
  Program root(&pl);
  ebpf::bpftrace::ast::SemanticAnalyser semantics(&root, bpftrace);
  semantics.analyse();
}
