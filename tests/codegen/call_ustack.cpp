#include "ast/passes/named_param.h"
#include "common.h"

#include <iterator>

namespace bpftrace::test::codegen {

TEST(codegen, call_ustack)
{
  const auto *result = NAME;

  test("kprobe:f { @x = ustack(); @y = ustack(6); @z = ustack(perf) }", result);
}

TEST(codegen, call_ustack_mapids)
{
  ast::ASTContext ast("stdin", R"(
kprobe:f {
  @x = ustack(5);
  @y = ustack(6);
  @z = ustack(6)
})");
  auto bpftrace = get_mock_bpftrace();
  auto ok = ast::PassManager()
                .put(ast)
                .put<BPFtrace>(*bpftrace)
                .add(ast::AllParsePasses())
                .add(ast::CreateNamedParamsPass())
                .add(ast::CreateSemanticPass())
                .add(ast::CreateResourcePass())
                .add(ast::AllCompilePasses())
                .run();
  ASSERT_TRUE(ok && ast.diagnostics().ok());
  bpftrace->bytecode_ = std::move(ok->get<BpfBytecode>());

  ASSERT_EQ(bpftrace->bytecode_.maps().size(), 7);
  ASSERT_EQ(bpftrace->bytecode_.countStackMaps(), 3U);

  StackType stack_type;
  stack_type.limit = 5;
  ASSERT_TRUE(bpftrace->bytecode_.hasMap(stack_type));
  stack_type.limit = 6;
  ASSERT_TRUE(bpftrace->bytecode_.hasMap(stack_type));
}

TEST(codegen, call_ustack_modes_mapids)
{
  ast::ASTContext ast("stdin", R"(
kprobe:f {
  @w = ustack(raw);
  @x = ustack(perf);
  @y = ustack(bpftrace);
  @z = ustack()
})");
  auto bpftrace = get_mock_bpftrace();
  auto ok = ast::PassManager()
                .put(ast)
                .put<BPFtrace>(*bpftrace)
                .add(ast::AllParsePasses())
                .add(ast::CreateNamedParamsPass())
                .add(ast::CreateSemanticPass())
                .add(ast::CreateResourcePass())
                .add(ast::AllCompilePasses())
                .run();
  ASSERT_TRUE(ok && ast.diagnostics().ok());
  bpftrace->bytecode_ = std::move(ok->get<BpfBytecode>());

  ASSERT_EQ(bpftrace->bytecode_.maps().size(), 9);
  ASSERT_EQ(bpftrace->bytecode_.countStackMaps(), 4U);

  StackType stack_type;
  stack_type.mode = StackMode::perf;
  ASSERT_TRUE(bpftrace->bytecode_.hasMap(stack_type));
  stack_type.mode = StackMode::bpftrace;
  ASSERT_TRUE(bpftrace->bytecode_.hasMap(stack_type));
  stack_type.mode = StackMode::raw;
  ASSERT_TRUE(bpftrace->bytecode_.hasMap(stack_type));
}

} // namespace bpftrace::test::codegen
