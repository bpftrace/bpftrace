#include "benchmark/benchmark.h"
#include "gmock/gmock.h"

#include "mocks.h"

#include "ast/passes/clone.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/resource_analyser.h"
#include "ast/passes/semantic_analyser.h"

#include "bpffeature.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "driver.h"

namespace bpftrace::test {

// We break the benchmarks into several phases, in order to track issues
// separately. Note that currently each meaningful pass has its own phase, but
// these could be logically merged as "optimizations" or some other passes with
// some minor code restructuring.
enum class Phase {
  Parse,
  FieldAnalyser,
  ClangParser,
  SemanticAnalyser,
  ResourceAnalyser,
  Codegen,
};

template <Phase P, Phase Is, typename Func>
void measure(benchmark::State &state, Driver &driver, Func fn)
{
  // Run once only if we are not in the benchmark.
  if constexpr (P != Is) {
    fn();
    return;
  }

  auto orig = std::move(driver.ctx);
  for (auto _ : state) {
    {
      // Clone the AST in its current exact form. This should be relatively
      // inexpensive (at least on the order of the pass itself), but we need to
      // exclude this time.
      state.PauseTiming();
      if (orig.root != nullptr) {
        bpftrace::ast::ASTContext newctx;
        bpftrace::ast::Clone cloner(newctx);
        newctx.root = orig.root;
        cloner.clone(&newctx.root);
        driver.ctx = std::move(newctx);
      }
      state.ResumeTiming();
    }

    // Run the function.
    fn();
  }
}

template <Phase P>
void BM_compile(benchmark::State &state, const std::string &input)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  Driver driver(*bpftrace);

  measure<Phase::Parse, P>(state, driver, [&] {
    ASSERT_EQ(driver.parse_str(input), 0);
  });

  std::unique_ptr<ast::FieldAnalyser> fields;
  measure<Phase::FieldAnalyser, P>(state, driver, [&] {
    fields = std::make_unique<ast::FieldAnalyser>(driver.ctx.root, *bpftrace);
    ASSERT_EQ(fields->analyse(), 0);
  });

  std::unique_ptr<ClangParser> clang;
  measure<Phase::ClangParser, P>(state, driver, [&] {
    clang = std::make_unique<ClangParser>();
    clang->parse(driver.ctx.root, *bpftrace);
  });

  std::unique_ptr<ast::SemanticAnalyser> semantics;
  measure<Phase::SemanticAnalyser, P>(state, driver, [&] {
    semantics = std::make_unique<ast::SemanticAnalyser>(driver.ctx, *bpftrace);
    ASSERT_EQ(semantics->analyse(), 0);
  });

  std::unique_ptr<ast::ResourceAnalyser> resources;
  std::optional<RequiredResources> required_resources;
  measure<Phase::ResourceAnalyser, P>(state, driver, [&] {
    resources = std::make_unique<ast::ResourceAnalyser>(driver.ctx.root,
                                                        *bpftrace);
    required_resources = resources->analyse();
    ASSERT_TRUE(required_resources.has_value());
  });

  std::unique_ptr<ast::CodegenLLVM> codegen;
  measure<Phase::Codegen, P>(state, driver, [&] {
    bpftrace->resources = required_resources.value();
    codegen = std::make_unique<ast::CodegenLLVM>(driver.ctx.root, *bpftrace);
    codegen->generate_ir();
    codegen->optimize();
    codegen->emit(false);
  });
}

} // namespace bpftrace::test

#define COMPILE_BENCHMARK_DEFINE(name, phase_name, phase)                      \
  BENCHMARK_F(name, phase_name)(benchmark::State & st)                         \
  {                                                                            \
    bpftrace::test::BM_compile<phase>(st, input);                              \
  }

#define COMPILE_BENCHMARK(name, prog)                                          \
  class name : public benchmark::Fixture {                                     \
  public:                                                                      \
    const std::string input = prog;                                            \
  };                                                                           \
  COMPILE_BENCHMARK_DEFINE(name, parser, bpftrace::test::Phase::Parse);        \
  COMPILE_BENCHMARK_DEFINE(name,                                               \
                           field_analyser,                                     \
                           bpftrace::test::Phase::FieldAnalyser);              \
  COMPILE_BENCHMARK_DEFINE(name,                                               \
                           clang_parser,                                       \
                           bpftrace::test::Phase::ClangParser);                \
  COMPILE_BENCHMARK_DEFINE(name,                                               \
                           semantic_analyser,                                  \
                           bpftrace::test::Phase::SemanticAnalyser);           \
  COMPILE_BENCHMARK_DEFINE(name,                                               \
                           resource_analyser,                                  \
                           bpftrace::test::Phase::ResourceAnalyser);           \
  COMPILE_BENCHMARK_DEFINE(name, codegen, bpftrace::test::Phase::Codegen);

COMPILE_BENCHMARK(hello_world, R"(
BEGIN
{
    printf("hello world!\n");
    exit();
}
)");

BENCHMARK_MAIN();
