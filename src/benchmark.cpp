#include <benchmark/benchmark.h>
#include <sstream>

#include "ast/ast.h"
#include "ast/context.h"
#include "ast/passes/printer.h"
#include "benchmark.h"

namespace bpftrace {

static Result<> benchmark(benchmark::State &state,
                          ast::PassManager &mgr,
                          std::string name)
{
  ast::PassContext ctx;
  return mgr.foreach([&](auto &pass) -> Result<> {
    // Is this the pass we care about?
    if (pass.name() != name) {
      return pass.run(ctx);
    }

    // Copy out the AST. We allow passes to mutate the AST, and therefore we
    // copy this out and reset it each time.
    ast::ASTContext saved;
    if (ctx.has<ast::ASTContext>()) {
      auto &ast = ctx.get<ast::ASTContext>();
      saved.root = saved.clone_node(ast.root, ast::Location());
    }

    // Run the pass N times.
    for (auto _ : state) {
      // Restore the AST, if needed.
      if (saved.root != nullptr) {
        state.PauseTiming();
        auto &ast = ctx.get<ast::ASTContext>();
        ast.clear();
        ast.root = clone(ast, saved.root, ast::Location());
        state.ResumeTiming();
      }
      auto ok = pass.run(ctx);
      if (!ok) {
        return ok.takeError();
      }
    }
    return OK();
  });
}

Result<OK> benchmark(ast::PassManager &mgr)
{
  // Ensure that the passes can run once, and record their names. We create a
  // separate benchmark for each passes, registered as the same of the pass.
  auto ok = mgr.foreach([&](auto &pass) -> Result<> {
    benchmark::RegisterBenchmark(pass.name(), [&](benchmark::State &state) {
      auto ok = benchmark(state, mgr, pass.name());
      if (!ok) {
        std::stringstream ss;
        ss << ok.takeError();
        state.SkipWithError(ss.str());
      }
    });
    return OK();
  });
  if (!ok) {
    return ok.takeError();
  }

  char *argv[] = { static_cast<char *>(nullptr) };
  benchmark::Initialize(nullptr, argv);
  benchmark::RunSpecifiedBenchmarks();
  return OK();
}

} // namespace bpftrace
