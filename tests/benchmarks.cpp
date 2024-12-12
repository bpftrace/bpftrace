#include "benchmark/benchmark.h"
#include "gmock/gmock.h"

#include "mocks.h"

#include "ast/passes/codegen_llvm.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/resource_analyser.h"
#include "ast/passes/semantic_analyser.h"

#include "bpffeature.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "driver.h"

namespace bpftrace {
namespace test {

static void BM_compile(benchmark::State &state, bool parse, std::string &&input)
{
  std::ostringstream out;

  for (auto _ : state) {
    state.PauseTiming();

    auto bpftrace = get_mock_bpftrace();
    Driver driver(*bpftrace);

    if (parse) {
      state.ResumeTiming();
    }

    ASSERT_EQ(driver.parse_str(input), 0);

    if (parse) {
      state.PauseTiming();
    } else {
      state.ResumeTiming();
    }

    ast::FieldAnalyser fields(driver.ctx.root, *bpftrace);
    EXPECT_EQ(fields.analyse(), 0);

    ClangParser clang;
    clang.parse(driver.ctx.root, *bpftrace);

    bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
    ast::SemanticAnalyser semantics(driver.ctx, *bpftrace);
    ASSERT_EQ(semantics.analyse(), 0);

    ast::ResourceAnalyser resource_analyser(driver.ctx.root, *bpftrace);
    auto resources_optional = resource_analyser.analyse();
    ASSERT_TRUE(resources_optional.has_value());
    bpftrace->resources = resources_optional.value();

    ast::CodegenLLVM codegen(driver.ctx.root, *bpftrace);
    codegen.generate_ir();

    if (!parse) {
      state.PauseTiming();
    }
    out.clear();
  }
}

BENCHMARK_CAPTURE(BM_compile, parse_while_loop, true, std::string(R"(
i:s:1 { $a = 1; while ($a <= 150) { @=$a++; }}
)"));

BENCHMARK_CAPTURE(BM_compile, passes_while_loop, false, std::string(R"(
i:s:1 { $a = 1; while ($a <= 150) { @=$a++; }}
)"));

} // namespace test
} // namespace bpftrace

BENCHMARK_MAIN();
