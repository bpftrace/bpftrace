#pragma once

#include "output/output.h"

namespace bpftrace::output {

class CaptureOutput : public Output {
public:
  CaptureOutput(Output &output) : nested_(output) {};

  // Simple passthrough.
  void map(const std::string &name, const Value &value) override
  {
    nested_.map(name, value);
  }
  void value(const Value &value) override
  {
    nested_.value(value);
  }
  void empty() override { nested_.empty(); }
  void time(const std::string &time) override
  {
    nested_.time(time);
  }
  void cat(const std::string &cat) override
  {
    nested_.cat(cat);
  }
  void join(const std::string &join) override
  {
    nested_.join(join);
  }
  void syscall(const std::string &syscall) override
  {
    nested_.syscall(syscall);
  }

  // Special case: treat errorf as errors.
  void printf(const std::string &str,
              const SourceInfo &info,
              PrintfSeverity severity) override
  {
    if (severity == PrintfSeverity::ERROR) {
      error_count++;
    }
    nested_.printf(str, info, severity);
  }
  void test_result(const std::vector<std::string> &all_tests,
                   size_t index,
                   std::chrono::nanoseconds duration,
                   const std::vector<bool> &passed,
                   std::string output) override
  {
    nested_.test_result(all_tests, index, duration, passed, output);
  }
  void benchmark_result(const std::vector<std::string> &all_benches,
                        size_t index,
                        std::chrono::nanoseconds average,
                        size_t iters) override
  {
    nested_.benchmark_result(all_benches, index, average, iters);
  }

  // Increment our counters.
  void lost_events(uint64_t lost) override
  {
    lost_events_count += lost;
    nested_.lost_events(lost);
  }
  void attached_probes(uint64_t num_probes) override
  {
    attached_probes_count += num_probes;
    nested_.attached_probes(num_probes);
  }
  void runtime_error(int retcode, const RuntimeErrorInfo &info) override
  {
    error_count++;
    nested_.runtime_error(retcode, info);
  }

  size_t error_count = 0;
  size_t lost_events_count = 0;
  size_t attached_probes_count = 0;

private:
  Output &nested_;
};

} // namespace bpftrace::output
