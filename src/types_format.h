#pragma once

#include <utility>

#include "bpftrace.h"
#include "output/output.h"
#include "types.h"
#include "util/result.h"

namespace bpftrace {

// TypeFormatError means that the type is not convertible.
//
// This should never happen and is generally indicative of a bug.
class TypeFormatError : public ErrorInfo<TypeFormatError> {
public:
  TypeFormatError(SizedType ty) : ty_(std::move(ty)) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  SizedType ty_;
};

// sorts map data by key. This is exposed as a function for testability,
// but it is generally an internal implementation detail.
void sort_by_key(
    const SizedType &key,
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
        &values_by_key);

// format is responsible for translating from a `SizedType` value,
// pointed at by `data` (with `sz` bytes), into an `output::Value`
// that can be printed by the output plugin.
//
// Note that this does not specifically handle histograms, which
// require computation of a set of labels.
Result<output::Primitive> format(BPFtrace &bpftrace,
                                 const ast::CDefinitions &c_definitions,
                                 const SizedType &ty,
                                 const std::vector<uint8_t> &value,
                                 size_t nvalues = 1,
                                 uint32_t div = 1);

// format, when providing some `MapInfo&` is capable of formatting
// additional types, such as histograms or stats.
Result<output::Value> format(BPFtrace &bpftrace,
                             const ast::CDefinitions &c_definitions,
                             const BpfMap &map,
                             size_t top = 0,
                             uint32_t div = 1);

} // namespace bpftrace
