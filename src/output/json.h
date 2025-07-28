#pragma once

#include <iostream>

#include "output/output.h"

namespace bpftrace::output {

class JsonOutput : public Output {
public:
  explicit JsonOutput(std::ostream &out = std::cout) : out_(out) {};

  void map(const std::string &name, const Value &value) override;
  void value(const Value &value) override;
  void print_error(const std::string &str,
                   const RuntimeErrorInfo &info) override;
  void printf(const std::string &str) override;
  void time(const std::string &time) override;
  void cat(const std::string &cat) override;
  void join(const std::string &join) override;
  void syscall(const std::string &syscall) override;
  void lost_events(uint64_t lost) override;
  void attached_probes(uint64_t num_probes) override;
  void runtime_error(int retcode, const RuntimeErrorInfo &info) override;
  void benchmark_results(
      const std::vector<std::pair<std::string, uint32_t>> &results) override;
  void end() override;

private:
  std::ostream &out_;
};

} // namespace bpftrace::output
