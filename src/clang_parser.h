#pragma once

#include "struct.h"

namespace bpftrace {

namespace ast { class Program; }

using StructMap = std::map<std::string, Struct>;

class ClangParser
{
public:
  void parse(ast::Program *program, StructMap &structs);
};

} // namespace bpftrace
