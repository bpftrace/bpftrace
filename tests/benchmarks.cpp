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
  CodegenGenerateIR,
  CodegenOptimize,
  CodegenEmit,

  // U
  PhaseCount,
};

constexpr const char *phaseName(Phase p)
{
  switch (p) {
    case Phase::Parse:
      return "parse";
    case Phase::FieldAnalyser:
      return "field_analyser";
    case Phase::ClangParser:
      return "clang_parser";
    case Phase::SemanticAnalyser:
      return "semantic_analyser";
    case Phase::ResourceAnalyser:
      return "resource_analyser";
    case Phase::CodegenGenerateIR:
      return "codegen_generate_ir";
    case Phase::CodegenOptimize:
      return "codegen_optimize";
    case Phase::CodegenEmit:
      return "codegen_emit";
    default:
      LOG(BUG) << "Unknown phase: " << static_cast<int>(p);
      __builtin_unreachable();
  };
}

template <Phase P, typename Func>
void measure(benchmark::State &state, Func fn)
{
  auto start = std::chrono::high_resolution_clock::now();
  fn();
  auto end = std::chrono::high_resolution_clock::now();

  // Add this component into the overall benchmark.
  //
  // Note that in an ideal world, we could track the aggregate process CPU time
  // and break this down per component as well. Unfortunately, these APIs are
  // not readily available through the benchmark APIs, and may be too expensive
  // to do in the context of this loop (whereas VDSO-based time is cheap).
  // Therefore, we frame everything in terms of real-time, including the
  // overall benchmarks themselves. This may be subject to plenty of noise and
  // side effects, but at least it is also representative of a user's
  // interactive experience.
  auto duration = std::chrono::duration<double>(end - start);
  constexpr const char *name = phaseName(P);
  auto counter = state.counters.find(name);
  if (counter != state.counters.end()) {
    counter->second += duration.count();
  } else {
    state.counters[name] = benchmark::Counter(duration.count());
  }
}

template <typename Arg>
void BM_compile(benchmark::State &state, const Arg &input)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);

  for (auto _ : state) {
    std::unique_ptr<Driver> driver;
    std::unique_ptr<ast::FieldAnalyser> fields;
    std::unique_ptr<ClangParser> clang;
    std::unique_ptr<ast::SemanticAnalyser> semantics;
    std::unique_ptr<ast::ResourceAnalyser> resources;
    std::optional<RequiredResources> required_resources;
    std::unique_ptr<ast::CodegenLLVM> codegen;

    measure<Phase::Parse>(state, [&] {
      driver = std::make_unique<Driver>(*bpftrace);
      ASSERT_EQ(driver->parse_str(input), 0);
    });
    measure<Phase::FieldAnalyser>(state, [&] {
      fields = std::make_unique<ast::FieldAnalyser>(driver->ctx.root,
                                                    *bpftrace);
      ASSERT_EQ(fields->analyse(), 0);
    });
    measure<Phase::ClangParser>(state, [&] {
      clang = std::make_unique<ClangParser>();
      clang->parse(driver->ctx.root, *bpftrace);
    });
    measure<Phase::SemanticAnalyser>(state, [&] {
      semantics = std::make_unique<ast::SemanticAnalyser>(driver->ctx,
                                                          *bpftrace);
      ASSERT_EQ(semantics->analyse(), 0);
    });
    measure<Phase::ResourceAnalyser>(state, [&] {
      resources = std::make_unique<ast::ResourceAnalyser>(driver->ctx.root,
                                                          *bpftrace);
      required_resources = resources->analyse();
      ASSERT_TRUE(required_resources.has_value());
    });
    measure<Phase::CodegenGenerateIR>(state, [&] {
      bpftrace->resources = required_resources.value();
      codegen = std::make_unique<ast::CodegenLLVM>(driver->ctx.root, *bpftrace);
      codegen->generate_ir();
    });
    measure<Phase::CodegenOptimize>(state, [&] { codegen->optimize(); });
    measure<Phase::CodegenEmit>(state, [&] { codegen->emit(false); });
  }

  // Normalize all counters to milliseconds from the existing nanoseconds. This
  // is still expressed in terms of real time, but will allow us to capture
  // sub-microsecond phases with some level of accurate (not all lost). Note
  // that this is going to be meaningful because we explicitly override the
  // main time unit to be milliseconds on the individual benchmarks.
  for (auto &counter : state.counters) {
    counter.second /= state.iterations();
    counter.second *= 1000;
  }
}

} // namespace bpftrace::test

BENCHMARK_CAPTURE(bpftrace::test::BM_compile, hello_world, R"(
BEGIN
{
    printf("hello world!\n");
    exit();
}
)")
    ->MeasureProcessCPUTime()
    ->UseRealTime()
    ->Unit(benchmark::kMillisecond);

BENCHMARK_MAIN();
