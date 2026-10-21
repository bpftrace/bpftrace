#pragma once

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "ast/scoped_variable.h"
#include "types.h"

#include <string>
#include <unordered_map>
#include <utility>
#include <variant>

namespace bpftrace::ast {

// Node * is a pointer to an AST node
// ScopedVariable is for tracking the type of a scratch variable referenced in
// many AST nodes std::string is for map key and value names as these are often
// resolved separately by different statements/expressions
using TypeVariable = std::variant<Node *, ScopedVariable, std::string>;

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

using ResolvedTypes =
    std::unordered_map<TypeVariable, SizedType, TypeVariableHash>;

inline std::string get_map_value_name(const std::string &ident)
{
  return ident + "__val";
}

inline std::string get_map_key_name(const std::string &ident)
{
  return ident + "__key";
}

class TypeMap;

Pass CreateTypeResolverPass();

} // namespace bpftrace::ast
