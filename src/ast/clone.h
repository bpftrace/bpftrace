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
               [[maybe_unused]] const Location &loc,
               const T &v)
  {
    return v;
  }
};

template <typename T>
  requires(std::is_same_v<T, Expression> || std::is_same_v<T, Statement> ||
           std::is_same_v<T, Iterable> || std::is_same_v<T, RootStatement>)
struct Cloner<T> {
  T operator()(ASTContext &ctx, const Location &loc, const T &v)
  {
    return std::visit([&](const auto &v) -> T { return clone(ctx, loc, v); },
                      v.value);
  }
};

template <typename T>
struct Cloner<std::vector<T>> {
  std::vector<T> operator()(ASTContext &ctx,
                            const Location &loc,
                            const std::vector<T> &obj)
  {
    std::vector<T> ret;
    for (const auto &v : obj) {
      ret.emplace_back(clone(ctx, loc, v));
    }
    return ret;
  }
};

template <typename... Ts>
struct Cloner<std::variant<Ts...>> {
  std::variant<Ts...> operator()(ASTContext &ctx,
                                 const Location &loc,
                                 const std::variant<Ts...> &obj)
  {
    return std::visit([&](const auto &v)
                          -> std::variant<Ts...> { return clone(ctx, loc, v); },
                      obj);
  }
};

template <typename T>
struct Cloner<std::optional<T>> {
  std::optional<T> operator()(ASTContext &ctx,
                              const Location &loc,
                              const std::optional<T> &obj)
  {
    if (!obj.has_value()) {
      return std::nullopt;
    }
    return clone(ctx, std::move(loc), obj.value());
  }
};

template <typename T>
  requires std::derived_from<T, Node>
struct Cloner<T> {
  T *operator()(ASTContext &ctx, const Location &loc, const T *obj)
  {
    return ctx.clone_node<T>(loc, obj);
  }
};

template <typename T>
T clone(ASTContext &ctx, const Location &loc, const T &t)
{
  using V = std::remove_const_t<std::decay_t<std::remove_pointer_t<T>>>;
  return Cloner<V>()(ctx, loc, t);
}

} // namespace ast
} // namespace bpftrace
