#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "bpftrace.h"
#include "semantic_analyser.h"

namespace ebpf {
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

} // namespace ast
} // namespace bpftrace
} // namespace ebpf
