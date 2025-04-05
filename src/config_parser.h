#pragma once

#include <string>

#include "util/result.h"

namespace bpftrace {

// If you want to be able to parse custom configuration, then simply
// provide a specialization of the `ConfigParser` class that specifies
// the implementation of the operators to parse any string and integers.
template <typename T>
struct ConfigParser;

// Generic parse error for a specific key. This should be returned by
// the `ConfigParser` implementations if the value cannot be parsed.
class ParseError : public ErrorInfo<ParseError> {
public:
  static char ID;
  ParseError(std::string key, std::string &&detail)
      : key_(std::move(key)), detail_(std::move(detail)) {};
  void log(llvm::raw_ostream &OS) const override;

private:
  std::string key_;
  std::string detail_;
};

} // namespace bpftrace
