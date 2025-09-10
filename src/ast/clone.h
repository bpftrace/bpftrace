#pragma once

#include <variant>

#include "ast/ast.h"
#include "ast/context.h"

namespace bpftrace {

class SizedType;

namespace ast {

class Expression;
class Statement;
class Iterable;
class RootStatement;

template <typename T>
struct Cloner;

template <typename T>
  requires(std::is_same_v<T, SizedType>)
struct Cloner<T> {
  T operator()([[maybe_unused]] ASTContext &ctx,
               const T &v,
               [[maybe_unused]] const Location &loc)
  {
    return v;
  }
};

template <typename T>
  requires(std::is_same_v<T, Expression> || std::is_same_v<T, Statement> || std::is_same_v<T, Iterable> || std::is_same_v<T, RootStatement>)
struct Cloner<T> {
  T operator()(ASTContext &ctx, const T &v, const Location &loc)
  {
    return std::visit([&](const auto &v) -> T { return clone(ctx, v, loc); },
                      v.value);
  }
};

template <typename T>
struct Cloner<std::vector<T>> {
  std::vector<T> operator()(ASTContext &ctx,
                            const std::vector<T> &obj,
                            const Location &loc)
  {
    std::vector<T> ret;
    for (const auto &v : obj) {
      ret.emplace_back(clone(ctx, v, loc));
    }
    return ret;
  }
};

template <typename... Ts>
struct Cloner<std::variant<Ts...>> {
  std::variant<Ts...> operator()(ASTContext &ctx,
                                 const std::variant<Ts...> &obj,
                                 const Location &loc)
  {
    return std::visit([&](const auto &v)
                          -> std::variant<Ts...> { return clone(ctx, v, loc); },
                      obj);
  }
};

template <typename T>
struct Cloner<std::optional<T>> {
  std::optional<T> operator()(ASTContext &ctx,
                              const std::optional<T> &obj,
                              const Location &loc)
  {
    if (!obj.has_value()) {
      return std::nullopt;
    }
    return clone(ctx, obj.value(), std::move(loc));
  }
};

template <typename T>
  requires std::derived_from<T, Node>
struct Cloner<T> {
  T *operator()(ASTContext &ctx, const T *obj, const Location &loc)
  {
    return ctx.clone_node<T>(obj, loc);
  }
};

template <typename T>
T clone(ASTContext &ctx, const T &t, const Location &loc = Location())
{
  using V = std::remove_const_t<std::decay_t<std::remove_pointer_t<T>>>;
  return Cloner<V>()(ctx, t, loc);
}

} // namespace ast
} // namespace bpftrace
