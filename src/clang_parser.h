#pragma once

#include "struct.h"
#include "bpftrace.h"

namespace bpftrace {

namespace ast { class Program; }

using StructMap = std::map<std::string, Struct>;

class ClangParser
{
public:
  void parse(ast::Program *program, BPFtrace &bpftrace, std::vector<std::string> extra_flags = {});
};

} // namespace bpftrace
