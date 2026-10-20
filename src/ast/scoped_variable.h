#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <utility>

namespace bpftrace::ast {

class Node;

using ScopedVariable = std::pair<Node *, std::string>;

struct ScopedVariableHash {
  std::size_t operator()(const ScopedVariable &sv) const
  {
    auto h1 = std::hash<Node *>{}(sv.first);
    auto h2 = std::hash<std::string>{}(sv.second);
    h1 ^= h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2);
    return h1;
  }
};

} // namespace bpftrace::ast
