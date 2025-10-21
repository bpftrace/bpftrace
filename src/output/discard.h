#pragma once

#include "output/output.h"

namespace bpftrace::output {

class DiscardOutput : public Output {
public:
  DiscardOutput() = default;

  void map([[maybe_unused]] const std::string &name,
           [[maybe_unused]] const Value &value) override
  {
  }
  void value([[maybe_unused]] const Value &value) override
  {
  }
  void time([[maybe_unused]] const std::string &time) override
  {
  }
  void cat([[maybe_unused]] const std::string &cat) override
  {
  }
  void join([[maybe_unused]] const std::string &join) override
  {
  }
  void syscall([[maybe_unused]] const std::string &syscall) override
  {
  }
  void printf([[maybe_unused]] const std::string &str,
              [[maybe_unused]] const SourceInfo &info,
              [[maybe_unused]] PrintfSeverity severity) override
  {
  }
  void test_result([[maybe_unused]] const std::vector<std::string> &all_tests,
                   [[maybe_unused]] size_t index,
                   [[maybe_unused]] std::chrono::nanoseconds duration,
                   [[maybe_unused]] const std::vector<bool> &passed,
                   [[maybe_unused]] std::string output) override
  {
  }
  void benchmark_result(
      [[maybe_unused]] const std::vector<std::string> &all_benches,
      [[maybe_unused]] size_t index,
      [[maybe_unused]] std::chrono::nanoseconds average,
      [[maybe_unused]] size_t iters) override
  {
  }
  void end() override
  {
  }
  void lost_events([[maybe_unused]] uint64_t lost) override
  {
  }
  void attached_probes([[maybe_unused]] uint64_t num_probes) override
  {
  }
  void runtime_error([[maybe_unused]] int retcode,
                     [[maybe_unused]] const RuntimeErrorInfo &info) override
  {
  }
};

} // namespace bpftrace::output
