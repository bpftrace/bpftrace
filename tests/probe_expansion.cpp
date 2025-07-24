#include "ast/passes/probe_expansion.h"
#include "ast/attachpoint_parser.h"
#include "ast/passes/printer.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::probe_expansion {

static void test(const std::string &prog, std::string_view expected_ast)
{
  auto mock_bpftrace = get_mock_bpftrace();

  BPFtrace &bpftrace = *mock_bpftrace;
  ast::ASTContext ast("stdin", prog);

  auto ok = ast::PassManager()
                .put(ast)
                .put(bpftrace)
                .add(CreateParsePass())
                .add(ast::CreateParseAttachpointsPass())
                .add(ast::CreateProbeExpansionPass())
                .run();
  ASSERT_TRUE(ok && ast.diagnostics().ok());

  if (expected_ast[0] == '\n')
    expected_ast.remove_prefix(1);

  std::stringstream out;
  ast::Printer printer(out);
  printer.visit(ast.root);
  EXPECT_EQ(out.str(), expected_ast);
}

TEST(probe_expansion, session_ast)
{
  test("kprobe:sys_* { @entry = 1 } kretprobe:sys_* { @exit = 1 }", R"(
Program
 kprobe:sys_*
  if
   builtin: __session_is_return
   then
    =
     map: @exit
     int: 1
   else
    =
     map: @entry
     int: 1
)");
}

} // namespace bpftrace::test::probe_expansion
