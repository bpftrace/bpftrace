#pragma once

#include <iostream>

#include "output/output.h"

namespace bpftrace::output {

class TextOutput : public Output {
public:
  explicit TextOutput(std::ostream &out = std::cout,
                      std::ostream &err = std::cerr)
      : out_(out), err_(err) {};

  void map(const std::string &name, const Value &value) override;
  void value(const Value &value) override;
  void empty() override;
  void printf(const std::string &str,
              const SourceInfo &info,
              PrintfSeverity severity) override;
  void time(const std::string &time) override;
  void cat(const std::string &cat) override;
  void join(const std::string &join) override;
  void syscall(const std::string &syscall) override;

  void lost_events(uint64_t lost) override;
  void attached_probes(uint64_t num_probes) override;
  void runtime_error(int retcode, const RuntimeErrorInfo &info) override;

  void test_result(const std::vector<std::string> &all_tests,
                   size_t index,
                   std::chrono::nanoseconds duration,
                   const std::vector<bool> &passed,
                   std::string output) override;

  void benchmark_result(const std::vector<std::string> &all_benches,
                        size_t index,
                        std::chrono::nanoseconds average,
                        size_t iters) override;

  // Allows formatting of a specific primitive.
  void primitive(const Primitive &p);

private:
  std::ostream &out_;
  std::ostream &err_;
};

} // namespace bpftrace::output
