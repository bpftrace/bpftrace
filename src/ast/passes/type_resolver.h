#pragma once

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "types.h"

#include <string>
#include <unordered_map>
#include <utility>
#include <variant>

namespace bpftrace::ast {

using ScopedVariable = std::pair<Node *, std::string>;
// Node * is a pointer to an AST node
// ScopedVariable is for tracking the type of a scratch variable referenced in many AST nodes
// std::string is for map key and value names as these are often resolved separately by different statements/expressions
using TypeVariable = std::variant<Node *, ScopedVariable, std::string>;

struct ScopedVariableHash {
  std::size_t operator()(const ScopedVariable &sv) const
  {
    auto h1 = std::hash<Node *>{}(sv.first);
    auto h2 = std::hash<std::string>{}(sv.second);
    // Boost-style hash combine for better distribution
    h1 ^= h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2);
    return h1;
  }
};

struct TypeVariableHash {
  std::size_t operator()(const TypeVariable &gn) const
  {
    return std::visit(
        [](const auto &val) -> std::size_t {
          using T = std::decay_t<decltype(val)>;
          if constexpr (std::is_same_v<T, Node *>) {
            return std::hash<Node *>{}(val);
          } else if constexpr (std::is_same_v<T, std::string>) {
            return std::hash<std::string>{}(val);
          } else {
            return ScopedVariableHash{}(val);
          }
        },
        gn);
  }
};

using ResolvedTypes = std::unordered_map<TypeVariable, SizedType, TypeVariableHash>;

inline std::string get_map_value_name(const std::string &ident)
{
  return ident + "__val";
}

inline std::string get_map_key_name(const std::string &ident)
{
  return ident + "__key";
}

Pass CreateTypeResolverPass();

} // namespace bpftrace::ast
