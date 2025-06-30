#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "ast/ast.h"
#include "ast/context.h"
#include "common.h"

namespace bpftrace::test::codegen {

using ::testing::_;

class MockBPFtrace : public BPFtrace {
public:
#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Winconsistent-missing-override"
#endif
  MOCK_METHOD4(add_probe,
               int(ast::ASTContext &,
                   const ast::AttachPoint &,
                   const ast::Probe &,
                   int));
#pragma GCC diagnostic pop

  int resolve_uname(const std::string &name,
                    struct symbol *sym,
                    const std::string &path) const override
  {
    (void)path;
    sym->name = name;
    sym->address = 12345;
    sym->size = 4;
    return 0;
  }

  bool is_traceable_func(
      const std::string &__attribute__((unused)) /*func_name*/) const override
  {
    return true;
  }

  bool has_kprobe_multi()
  {
    return feature_->has_kprobe_multi();
  }
};

TEST(codegen, printf_offsets)
{
  ast::ASTContext ast("stdin", R"(
struct Foo { char c; int i; char str[10]; }
kprobe:f
{
  $foo = (struct Foo*)arg0;
  printf("%c %u %s %p\n", $foo->c, $foo->i, $foo->str, 0)
})");
  auto bpftrace = get_mock_bpftrace();
  auto ok = ast::PassManager()
                .put(ast)
                .put<BPFtrace>(*bpftrace)
                .add(ast::AllParsePasses())
                .add(ast::CreateSemanticPass())
                .add(ast::CreateResourcePass())
                .add(ast::AllCompilePasses())
                .run();
  ASSERT_TRUE(ok && ast.diagnostics().ok());

  EXPECT_EQ(bpftrace->resources.printf_args.size(), 1U);
  auto fmt = std::get<0>(bpftrace->resources.printf_args[0]).str();
  auto &args = std::get<1>(bpftrace->resources.printf_args[0]);

  EXPECT_EQ(fmt, "%c %u %s %p\n");

  EXPECT_EQ(args.size(), 4U);

  // Note that scalar types are promoted to 64-bits when put into
  // a perf event buffer
  EXPECT_TRUE(args[0].type.IsIntTy());
  EXPECT_EQ(args[0].type.GetSize(), 8U);
  EXPECT_EQ(args[0].offset, 8);

  EXPECT_TRUE(args[1].type.IsIntTy());
  EXPECT_EQ(args[1].type.GetSize(), 8U);
  EXPECT_EQ(args[1].offset, 16);

  EXPECT_TRUE(args[2].type.IsStringTy());
  EXPECT_EQ(args[2].type.GetSize(), 10U);
  EXPECT_EQ(args[2].offset, 24);

  EXPECT_TRUE(args[3].type.IsIntTy());
  EXPECT_EQ(args[3].type.GetSize(), 8U);
  EXPECT_EQ(args[3].offset, 40);
}

TEST(codegen, probe_count)
{
  ast::ASTContext ast("stdin", R"(
kprobe:f { 1; } kprobe:d { 1; }
)");
  MockBPFtrace bpftrace;
  EXPECT_CALL(bpftrace, add_probe(_, _, _, _)).Times(2);

  // Override to mockbpffeature.
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);

  auto ok = ast::PassManager()
                .put(ast)
                .put<BPFtrace>(bpftrace)
                .add(ast::AllParsePasses())
                .add(ast::CreateSemanticPass())
                .add(ast::AllCompilePasses())
                .run();
  ASSERT_TRUE(ok && ast.diagnostics().ok());
}

TEST(codegen, clear_map_desugars_to_loop_delete)
{
  ast::ASTContext ast("stdin", R"(
interval:s:1 {
  clear(@m);
})");

  auto bpftrace = get_mock_bpftrace(); // Use the helper to get mock with resources
  auto ok = ast::PassManager()
                .put(ast)
                .put<BPFtrace>(*bpftrace)
                .add(ast::AllParsePasses())
                .add(ast::CreateSemanticPass())
                .add(ast::CreateResourcePass())
                .add(ast::AllCompilePasses())
                .run();

  ASSERT_TRUE(ok && ast.diagnostics().ok());
}

} // namespace bpftrace::test::codegen
