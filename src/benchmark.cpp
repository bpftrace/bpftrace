#include <chrono>
#include <cmath>
#include <ctime>
#include <iomanip>
#include <iostream>

#include "ast/ast.h"
#include "ast/context.h"
#include "benchmark.h"
#include "util/time.h"

namespace bpftrace {

char TimerError::ID;
void TimerError::log(llvm::raw_ostream &OS) const
{
  OS << "timer error: " << strerror(err_);
}

using time_point = std::chrono::time_point<std::chrono::steady_clock,
                                           std::chrono::nanoseconds>;

static Result<time_point> processor_time()
{
  struct timespec ts = {};
  int rc = clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
  if (rc < 0) {
    return make_error<TimerError>(errno);
  }
  return time_point(std::chrono::seconds(ts.tv_sec) +
                    std::chrono::nanoseconds(ts.tv_nsec));
}

static int64_t delta(time_point start, time_point end)
{
  return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
      .count();
}

Result<> benchmark(std::ostream &out, ast::PassManager &mgr)
{
  ast::PassContext ctx;

  // See below; we aggregate at the end.
  int64_t full_mean = 0;
  double full_variance = 0;
  size_t full_count = 0;

  // We print out the confidence interval at p95, which corresponds to a
  // z-score of 1.96 (see the `err` value below).
  auto emit = [&](const std::string &name,
                  int64_t total,
                  int64_t count,
                  double variance) {
    size_t mean = total / count;
    auto stddev = std::sqrt(variance);
    auto err = static_cast<int64_t>(1.96 * stddev /
                                    std::sqrt(static_cast<double>(count)));
    auto [unit, scale] = util::duration_str(std::chrono::nanoseconds(mean));
    out << std::left << std::setw(30) << name;
    out << std::left << std::setw(8) << count;
    out << std::left << std::setw(14) << total;
    out << mean / scale << " ± " << err / scale << " " << unit << std::endl;
  };

  auto ok = mgr.foreach([&](auto &pass) -> Result<> {
    // Copy out the AST. We allow passes to mutate the AST, and therefore we
    // copy this out and reset it each time.
    ast::ASTContext saved;
    if (ctx.has<ast::ASTContext>()) {
      auto &ast = ctx.get<ast::ASTContext>();
      saved.root = saved.clone_node(ast::Location(), ast.root);
    }

    // We run the function until we are able to accumulate at least three
    // iterations, and 100 milliseconds (but we never bother doing more than
    // 10,000). This should provide reasonable data for the below. The times
    // are all recorded in process CPU time, only while the pass itself is
    // running. We may accumulate additional time rebuilding the AST, etc.
    int64_t goal = std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::milliseconds(100))
                       .count();
    std::vector<int64_t> samples;
    int64_t total = 0;
    while (true) {
      auto start = processor_time();
      if (!start) {
        return start.takeError();
      }
      auto ok = pass.run(ctx);
      if (!ok) {
        return ok.takeError();
      }
      auto end = processor_time();
      if (!end) {
        return end.takeError();
      }
      int64_t current = delta(*start, *end);
      samples.push_back(current);
      total += current;

      // Do we have enough (or too much)?
      if (samples.size() >= 10000 || (samples.size() > 3 && total >= goal)) {
        break;
      }

      // Restore the original tree.
      auto &ast = ctx.get<ast::ASTContext>();
      ast.clear();
      ast.root = clone(ast, ast::Location(), saved.root);
    }

    // Compute the variance of the samples.
    int64_t mean = total / samples.size();
    double variance = 0;
    for (const auto &sample : samples) {
      variance += std::pow(static_cast<double>(sample - mean), 2);
    }
    emit(pass.name(), total, samples.size(), variance);

    // Aggregate for printing the final stats. Note that we treat each pass as
    // independent, therefore the final variance is the sum of the variances.
    full_mean += mean;
    full_variance += variance;
    full_count++;
    return OK();
  });
  if (!ok) {
    out << "FAIL\n"; // See below.
    return ok.takeError();
  }

  // The final `PASS` is emitted when all passes have finished correctly. This
  // makes the output format compatible with `gobench` or other aggregation
  // tools that can compare benchmarks.
  emit("total", full_mean * full_count, full_count, full_variance);
  out << "PASS\n";
  return OK();
}

} // namespace bpftrace
