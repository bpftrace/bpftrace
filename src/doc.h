#pragma once

#include <ostream>
#include <string>
#include <vector>

#include "ast/context.h"

namespace bpftrace::doc {

enum class Kind {
  Macro,
  Function,
  Probe,
};

struct Entry {
  std::string name;
  Kind kind = Kind::Function;
  std::vector<std::string> variants;
  std::vector<std::string> deprecated_variants;
  std::string description;
  std::string source_file;
  unsigned int line = 0;
};

std::vector<Entry> extract(const ast::ASTContext &ast);

void write_markdown(std::ostream &out, const std::vector<Entry> &entries);

} // namespace bpftrace::doc
