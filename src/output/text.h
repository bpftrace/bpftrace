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
  void printf(const std::string &str) override;
  void errorf(const std::string &str, const SourceInfo &info) override;
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

  // Allows formatting of a specific primitive.
  void primitive(const Primitive &p);

private:
  std::ostream &out_;
  std::ostream &err_;
};

} // namespace bpftrace::output
