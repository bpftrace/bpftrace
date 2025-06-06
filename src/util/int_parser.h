#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unistd.h>
#include <utility>
#include <variant>

#include "util/result.h"

namespace bpftrace::util {

class OverflowError : public ErrorInfo<OverflowError> {
public:
  OverflowError(std::string num, uint64_t max)
      : num_(std::move(num)), max_(max) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  std::string num_;
  uint64_t max_;
};

class NumberFormatError : public ErrorInfo<NumberFormatError> {
public:
  NumberFormatError(std::string msg, std::string num)
      : msg_(std::move(msg)), num_(std::move(num)) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  std::string msg_;
  std::string num_;
};

//   String -> int conversion specific to bpftrace
//
//   - error when trailing characters are found
//   - supports scientific notation, e.g. 1e6
//    - error when out of int range (1e20)
//    - error when base > 9 (12e3)
//   - support underscore as separator, e.g. 1_234_000
Result<uint64_t> to_uint(const std::string &num, int base = 0);

} // namespace bpftrace::util
