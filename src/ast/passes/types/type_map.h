#pragma once

#include "ast/ast.h"
#include "ast/pass_manager.h"
#include "ast/passes/types/type_resolver.h"
#include "log.h"

namespace bpftrace::ast {

class TypeMap : public State<"resolved-types"> {
public:
  explicit TypeMap(ResolvedTypes resolved_types)
      : resolved_types_(std::move(resolved_types))
  {
  }

  TypeMap(TypeMap &&) = default;
  TypeMap &operator=(TypeMap &&) = default;

  const SizedType &type(Node *node) const
  {
    auto it = resolved_types_.find(node);
    if (it != resolved_types_.end()) {
      return it->second;
    }
    return none_type();
  }

  const SizedType &type(const Expression &expr) const
  {
    return type(&expr.node());
  }

  const SizedType &map_key_type(const std::string &ident) const
  {
    auto it = resolved_types_.find(get_map_key_name(ident));
    if (it != resolved_types_.end()) {
      return it->second;
    }
    return none_type();
  }

  const SizedType &map_value_type(const std::string &ident) const
  {
    auto it = resolved_types_.find(get_map_value_name(ident));
    if (it != resolved_types_.end()) {
      return it->second;
    }
    return none_type();
  }

  const SizedType *find_map_key_type(const std::string &ident) const
  {
    auto it = resolved_types_.find(get_map_key_name(ident));
    return it != resolved_types_.end() ? &it->second : nullptr;
  }

  const SizedType *find_map_value_type(const std::string &ident) const
  {
    auto it = resolved_types_.find(get_map_value_name(ident));
    return it != resolved_types_.end() ? &it->second : nullptr;
  }

private:
  static const SizedType &none_type()
  {
    static const SizedType none_ty = CreateNone();
    return none_ty;
  }

  ResolvedTypes resolved_types_;
};

} // namespace bpftrace::ast
