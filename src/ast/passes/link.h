#pragma once

#include <filesystem>

#include "ast/pass_manager.h"
#include "util/result.h"

namespace bpftrace::ast {

class BpfExternObjects : public ast::State<"bpf-extern"> {
public:
  std::vector<std::filesystem::path> objects;
};

// Produces a set of no-op external objects. This will be replaced in the
// future by actual import passes. This produces `BpfExternObjects`.
Pass CreateExternObjectPass();

class LinkError : public ErrorInfo<LinkError> {
public:
  LinkError(std::string origin, int err)
      : origin_(std::move(origin)), err_(err) {};
  static char ID;
  void log(llvm::raw_ostream &OS) const override;

private:
  std::string origin_;
  int err_;
};

// Produces the final output `BpfBytecode` object from `BpfObject` and the
// `BpfExternObjects` provided.
Pass CreateLinkPass();

} // namespace bpftrace::ast
