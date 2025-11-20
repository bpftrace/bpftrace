#pragma once

#include <charconv>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "ast/clone.h"
#include "ast/context.h"
#include "ast/integer_types.h"
#include "diagnostic.h"
#include "probe_types.h"
#include "types.h"
#include "usdt.h"
#include "util/strings.h"

namespace bpftrace::ast {

enum class JumpType {
  RETURN,
  CONTINUE,
  BREAK,
};

enum class Operator {
  ASSIGN,
  EQ,
  NE,
  LE,
  GE,
  LEFT,
  RIGHT,
  LT,
  GT,
  LAND,
  LOR,
  PLUS,
  PRE_INCREMENT,
  PRE_DECREMENT,
  POST_INCREMENT,
  POST_DECREMENT,
  MINUS,
  MUL,
  DIV,
  MOD,
  BAND,
  BOR,
  BXOR,
  LNOT,
  BNOT,
};

inline bool operator==(Operator lhs, Operator rhs)
{
  return static_cast<int>(lhs) == static_cast<int>(rhs);
}
inline std::strong_ordering operator<=>(Operator lhs, Operator rhs)
{
  return static_cast<int>(lhs) <=> static_cast<int>(rhs);
}

class Node {
public:
  Node(ASTContext &ctx, Location &&loc) : state_(*ctx.state_), loc(loc) {};
  virtual ~Node() = default;

  Node(const Node &) = delete;
  Node &operator=(const Node &) = delete;
  Node(Node &&) = delete;
  Node &operator=(Node &&) = delete;

  Diagnostic &addError() const;
  Diagnostic &addWarning() const;

private:
  // N.B. it is not legal to hold on to a long-term reference to `ASTContext&`,
  // as this is generally movable. Therefore, we hold on to the internal state
  // only, which will not be moving.
  //
  // See `ASTContext::State` for more information.
  ASTContext::State &state_;

public:
  // This is temporarily accessible by other classes because we don't have a
  // clear `clone` operation at this time. Eventually this should be made
  // private and we should rely on a clear model for cloning nodes.
  Location loc;
};

template <typename... Ts>
class VariantNode {
public:
  template <typename T>
  VariantNode(T *value)
    requires(std::is_same_v<T, Ts> || ...)
      : value(value){};

  template <typename T>
  bool is() const
  {
    return std::holds_alternative<T *>(value);
  }

  template <typename T>
  T *as() const
  {
    if (is<T>()) {
      return std::get<T *>(value);
    }
    return nullptr;
  }

  Node &node() const
  {
    return std::visit([](auto *v) -> Node & { return *v; }, value);
  }

  const Location &loc() const
  {
    return std::visit([](const auto *v) -> const Location & { return v->loc; },
                      value);
  }

  bool operator==(const VariantNode &other) const
  {
    if (value.index() != other.value.index())
      return false;
    return std::visit(
        [&other](auto *v) {
          using T = std::decay_t<decltype(*v)>;
          auto *other_v = std::get<T *>(other.value);
          return *v == *other_v;
        },
        value);
  }

  std::strong_ordering operator<=>(const VariantNode &other) const
  {
    if (auto cmp = value.index() <=> other.value.index(); cmp != 0)
      return cmp;
    return std::visit(
        [&other](auto *v) {
          using T = std::decay_t<decltype(*v)>;
          auto *other_v = std::get<T *>(other.value);
          return *v <=> *other_v;
        },
        value);
  }

  std::variant<Ts *...> value;
};

class Integer;
class NegativeInteger;
class Boolean;
class PositionalParameter;
class PositionalParameterCount;
class String;
class None;
class Identifier;
class Builtin;
class Call;
class Sizeof;
class Offsetof;
class Map;
class Variable;
class VariableAddr;
class MapAddr;
class Binop;
class Unop;
class FieldAccess;
class ArrayAccess;
class TupleAccess;
class MapAccess;
class Cast;
class Tuple;
class IfExpr;
class BlockExpr;
class Typeinfo;
class Comptime;

class Expression : public VariantNode<Integer,
                                      NegativeInteger,
                                      Boolean,
                                      PositionalParameter,
                                      PositionalParameterCount,
                                      String,
                                      None,
                                      Identifier,
                                      Builtin,
                                      Call,
                                      Sizeof,
                                      Offsetof,
                                      Map,
                                      Variable,
                                      VariableAddr,
                                      MapAddr,
                                      Binop,
                                      Unop,
                                      FieldAccess,
                                      ArrayAccess,
                                      TupleAccess,
                                      MapAccess,
                                      Cast,
                                      Tuple,
                                      IfExpr,
                                      BlockExpr,
                                      Typeinfo,
                                      Comptime> {
public:
  using VariantNode::VariantNode;
  Expression() : Expression(static_cast<BlockExpr *>(nullptr)) {};

  // The `type` method is the only common thing required by all expression
  // types. This will on the variant types.
  const SizedType &type() const;
  bool is_literal() const;
};
using ExpressionList = std::vector<Expression>;

class ExprStatement;
class VarDeclStatement;
class AssignScalarMapStatement;
class AssignMapStatement;
class AssignVarStatement;
class DiscardExpr;
class Unroll;
class Jump;
class While;
class For;
class StatementImport;

class Statement : public VariantNode<ExprStatement,
                                     VarDeclStatement,
                                     AssignScalarMapStatement,
                                     AssignMapStatement,
                                     AssignVarStatement,
                                     DiscardExpr,
                                     Unroll,
                                     Jump,
                                     While,
                                     For,
                                     StatementImport> {
public:
  using VariantNode::VariantNode;
  Statement() : Statement(static_cast<ExprStatement *>(nullptr)) {};
};
using StatementList = std::vector<Statement>;

class Config;
class CStatement;
class Macro;
class MapDeclStatement;
class Probe;
class Subprog;
class RootImport;

class RootStatement : public VariantNode<Config,
                                         RootImport,
                                         CStatement,
                                         Probe,
                                         Subprog,
                                         Macro,
                                         MapDeclStatement> {
public:
  using VariantNode::VariantNode;
  RootStatement() : RootStatement(static_cast<Probe *>(nullptr)) {};
};
using RootStatements = std::vector<RootStatement>;

class Integer : public Node {
public:
  explicit Integer(ASTContext &ctx,
                   Location &&loc,
                   uint64_t n,
                   std::optional<std::string> &&original = std::nullopt)
      : Node(ctx, std::move(loc)),
        value(n),
        original(std::move(original)),
        integer_type(get_integer_type(n)) {};
  explicit Integer(ASTContext &ctx,
                   Location &&loc,
                   uint64_t n,
                   SizedType integer_ty,
                   std::optional<std::string> &&original = std::nullopt)
      : Node(ctx, std::move(loc)),
        value(n),
        original(std::move(original)),
        integer_type(std::move(integer_ty)) {
          assert(integer_type.IsIntTy());
        };
  explicit Integer(ASTContext &ctx, const Location &loc, const Integer &other)
      : Node(ctx, loc + other.loc),
        value(other.value),
        original(other.original),
        integer_type(other.integer_type) {};

  const SizedType &type() const
  {
    return integer_type;
  }

  bool operator==(const Integer &other) const
  {
    return value == other.value && integer_type == other.integer_type;
  }
  std::strong_ordering operator<=>(const Integer &other) const
  {
    if (auto cmp = value <=> other.value; cmp != 0)
      return cmp;
    return integer_type <=> other.integer_type;
  }

  // This literal has a dynamic type, but it is not mutable. The type is
  // generally signed if the signed value is capable of holding the literal,
  // otherwise it is unsigned and the smallest possible sizedType.
  //
  // However, the `force_unsigned` parameter can override this. This can be
  // used for small cases that are explicitly unsigned (e.g. `sizeof`), and is
  // preserved when folding literals in order to provide the intuitive type.
  const uint64_t value;
  const std::optional<std::string> original;
  const SizedType integer_type;
};

class NegativeInteger : public Node {
public:
  explicit NegativeInteger(ASTContext &ctx, Location &&loc, int64_t n)
      : Node(ctx, std::move(loc)), value(n), integer_type(get_signed_integer_type(n)) {};
  explicit NegativeInteger(ASTContext &ctx, Location &&loc, int64_t n, SizedType integer_ty)
      : Node(ctx, std::move(loc)), value(n), integer_type(std::move(integer_ty)) {
        assert(integer_type.IsIntTy() && integer_type.IsSigned());
      };
  explicit NegativeInteger(ASTContext &ctx,
                           const Location &loc,
                           const NegativeInteger &other)
      : Node(ctx, loc + other.loc), value(other.value), integer_type(other.integer_type) {};

  const SizedType &type() const
  {
    return integer_type;
  }

  bool operator==(const NegativeInteger &other) const
  {
     return value == other.value && integer_type == other.integer_type;
  }
  std::strong_ordering operator<=>(const NegativeInteger &other) const
  {
    if (auto cmp = value <=> other.value; cmp != 0)
      return cmp;
    return integer_type <=> other.integer_type;
  }

  const int64_t value;
  const SizedType integer_type;
};

class Boolean : public Node {
public:
  explicit Boolean(ASTContext &ctx, Location &&loc, bool val)
      : Node(ctx, std::move(loc)), value(val) {};
  explicit Boolean(ASTContext &ctx, const Location &loc, const Boolean &other)
      : Node(ctx, loc + other.loc), value(other.value) {};

  const SizedType &type() const
  {
    static SizedType boolean = CreateBool();
    return boolean;
  }

  bool operator==(const Boolean &other) const
  {
    return value == other.value;
  }
  std::strong_ordering operator<=>(const Boolean &other) const
  {
    return value <=> other.value;
  }

  const bool value;
};

class None : public Node {
public:
  explicit None(ASTContext &ctx, Location &&loc) : Node(ctx, std::move(loc)) {};
  explicit None(ASTContext &ctx, const Location &loc, const None &other)
      : Node(ctx, loc + other.loc) {};

  const SizedType &type() const
  {
    static SizedType none = CreateNone();
    return none;
  }

  bool operator==([[maybe_unused]] const None &other) const
  {
    return true;
  }
  std::strong_ordering operator<=>([[maybe_unused]] const None &other) const
  {
    return std::strong_ordering::equal;
  }
};

class PositionalParameter : public Node {
public:
  explicit PositionalParameter(ASTContext &ctx, Location &&loc, long n)
      : Node(ctx, std::move(loc)), n(n) {};
  explicit PositionalParameter(ASTContext &ctx,
                               const Location &loc,
                               const PositionalParameter &other)
      : Node(ctx, loc + other.loc), n(other.n) {};

  const SizedType &type() const
  {
    static SizedType none = CreateNone();
    return none;
  }

  bool operator==(const PositionalParameter &other) const
  {
    return n == other.n;
  }
  std::strong_ordering operator<=>(const PositionalParameter &other) const
  {
    return n <=> other.n;
  }

  const long n;
};

class PositionalParameterCount : public Node {
public:
  explicit PositionalParameterCount(ASTContext &ctx, Location &&loc)
      : Node(ctx, std::move(loc)) {};
  explicit PositionalParameterCount(
      ASTContext &ctx,
      const Location &loc,
      [[maybe_unused]] const PositionalParameterCount &other)
      : Node(ctx, loc + other.loc) {};

  const SizedType &type() const
  {
    static SizedType none = CreateNone();
    return none;
  }

  bool operator==([[maybe_unused]] const PositionalParameterCount &other) const
  {
    return true;
  }
  std::strong_ordering operator<=>(
      [[maybe_unused]] const PositionalParameterCount &other) const
  {
    return std::strong_ordering::equal;
  }
};

class String : public Node {
public:
  explicit String(ASTContext &ctx, Location &&loc, std::string str)
      : Node(ctx, std::move(loc)),
        value(std::move(str)),
        string_type(CreateString(value.size() + 1)) {};
  explicit String(ASTContext &ctx, const Location &loc, const String &other)
      : Node(ctx, loc + other.loc),
        value(other.value),
        string_type(other.string_type) {};

  const SizedType &type() const
  {
    return string_type;
  }

  bool operator==(const String &other) const
  {
    return value == other.value && string_type == other.string_type;
  }
  std::strong_ordering operator<=>(const String &other) const
  {
    if (auto cmp = value <=> other.value; cmp != 0)
      return cmp;
    return string_type <=> other.string_type;
  }

  const std::string value;
  SizedType string_type;
};

class Identifier : public Node {
public:
  explicit Identifier(ASTContext &ctx, Location &&loc, std::string ident)
      : Node(ctx, std::move(loc)), ident(std::move(ident)) {};
  explicit Identifier(ASTContext &ctx,
                      const Location &loc,
                      const Identifier &other)
      : Node(ctx, loc + other.loc),
        ident(other.ident),
        ident_type(other.ident_type) {};

  const SizedType &type() const
  {
    return ident_type;
  }

  bool operator==(const Identifier &other) const
  {
    return ident == other.ident && ident_type == other.ident_type;
  }
  std::strong_ordering operator<=>(const Identifier &other) const
  {
    if (auto cmp = ident <=> other.ident; cmp != 0)
      return cmp;
    return ident_type <=> other.ident_type;
  }

  std::string ident;
  SizedType ident_type;
};

class Builtin : public Node {
public:
  explicit Builtin(ASTContext &ctx, Location &&loc, std::string ident)
      : Node(ctx, std::move(loc)), ident(std::move(ident)) {};
  explicit Builtin(ASTContext &ctx, const Location &loc, const Builtin &other)
      : Node(ctx, loc + other.loc),
        ident(other.ident),
        probe_id(other.probe_id),
        builtin_type(other.builtin_type) {};

  const SizedType &type() const
  {
    return builtin_type;
  }

  // Check if the builtin is 'arg0' - 'arg255'
  bool is_argx() const
  {
    if (ident.size() < 4 || ident.size() > 6 || !ident.starts_with("arg"))
      return false;

    std::string num_part = ident.substr(3);

    // no leading zeros
    if (num_part.size() > 1 && num_part.front() == '0')
      return false;

    int arg_num = 0;
    auto [ptr, ec] = std::from_chars(num_part.data(),
                                     num_part.data() + num_part.size(),
                                     arg_num);
    return ec == std::errc() && ptr == num_part.data() + num_part.size() &&
           arg_num >= 0 && arg_num < 256;
  }

  bool operator==(const Builtin &other) const
  {
    return ident == other.ident && probe_id == other.probe_id &&
           builtin_type == other.builtin_type;
  }
  std::strong_ordering operator<=>(const Builtin &other) const
  {
    if (auto cmp = ident <=> other.ident; cmp != 0)
      return cmp;
    if (auto cmp = probe_id <=> other.probe_id; cmp != 0)
      return cmp;
    return builtin_type <=> other.builtin_type;
  }

  std::string ident;
  int probe_id;
  SizedType builtin_type;
};

class Call : public Node {
public:
  explicit Call(ASTContext &ctx,
                Location &&loc,
                std::string func,
                ExpressionList &&vargs)
      : Node(ctx, std::move(loc)),
        func(std::move(func)),
        vargs(std::move(vargs)) {};
  explicit Call(ASTContext &ctx, const Location &loc, const Call &other)
      : Node(ctx, loc + other.loc),
        func(other.func),
        vargs(clone(ctx, loc, other.vargs)),
        return_type(other.return_type),
        injected_args(other.injected_args) {};

  const SizedType &type() const
  {
    return return_type;
  }

  bool operator==(const Call &other) const
  {
    return func == other.func && vargs == other.vargs &&
           injected_args == other.injected_args &&
           return_type == other.return_type;
  }
  std::strong_ordering operator<=>(const Call &other) const
  {
    if (auto cmp = func <=> other.func; cmp != 0)
      return cmp;
    if (vargs.size() != other.vargs.size())
      return vargs.size() <=> other.vargs.size();
    for (size_t i = 0; i < vargs.size(); ++i) {
      if (auto cmp = vargs[i] <=> other.vargs[i]; cmp != 0)
        return cmp;
    }
    if (auto cmp = injected_args <=> other.injected_args; cmp != 0)
      return cmp;
    return return_type <=> other.return_type;
  }

  std::string func;
  ExpressionList vargs;
  SizedType return_type;

  // Some passes may inject new arguments to the call, which is always
  // done at the beginning (in order to support variadic arguments) for
  // later passes. This is a result of "desugaring" some syntax. When this
  // happens, this number is increased so that later error reporting can
  // correctly account for this.
  size_t injected_args = 0;
};

class Sizeof : public Node {
public:
  explicit Sizeof(ASTContext &ctx, Location &&loc, SizedType type)
      : Node(ctx, std::move(loc)), record(type) {};
  explicit Sizeof(ASTContext &ctx, Location &&loc, Expression expr)
      : Node(ctx, std::move(loc)), record(expr) {};
  explicit Sizeof(ASTContext &ctx, const Location &loc, const Sizeof &other)
      : Node(ctx, loc + other.loc), record(clone(ctx, loc, other.record)) {};

  const SizedType &type() const
  {
    // See exception for Integer type construction.
    static SizedType uint64 = CreateUInt64();
    return uint64;
  }

  bool operator==(const Sizeof &other) const
  {
    if (record.index() != other.record.index())
      return false;
    return std::visit(
        [&other](const auto &v) {
          using T = std::decay_t<decltype(v)>;
          return v == std::get<T>(other.record);
        },
        record);
  }
  std::strong_ordering operator<=>(const Sizeof &other) const
  {
    if (auto cmp = record.index() <=> other.record.index(); cmp != 0)
      return cmp;
    return std::visit(
        [&other](const auto &v) -> std::strong_ordering {
          using T = std::decay_t<decltype(v)>;
          return v <=> std::get<T>(other.record);
        },
        record);
  }

  std::variant<Expression, SizedType> record;
};

class Offsetof : public Node {
public:
  explicit Offsetof(ASTContext &ctx,
                    Location &&loc,
                    SizedType record,
                    std::vector<std::string> field)
      : Node(ctx, std::move(loc)), record(record), field(std::move(field)) {};
  explicit Offsetof(ASTContext &ctx,
                    Location &&loc,
                    Expression expr,
                    std::vector<std::string> field)
      : Node(ctx, std::move(loc)), record(expr), field(std::move(field)) {};
  explicit Offsetof(ASTContext &ctx, const Location &loc, const Offsetof &other)
      : Node(ctx, loc + other.loc),
        record(clone(ctx, loc + other.loc, other.record)),
        field(other.field) {};

  const SizedType &type() const
  {
    // See exception for Integer type construction.
    static SizedType uint64 = CreateUInt64();
    return uint64;
  }

  bool operator==(const Offsetof &other) const
  {
    if (record.index() != other.record.index())
      return false;
    bool record_equal = std::visit(
        [&other](const auto &v) {
          using T = std::decay_t<decltype(v)>;
          return v == std::get<T>(other.record);
        },
        record);
    return record_equal && field == other.field;
  }
  std::strong_ordering operator<=>(const Offsetof &other) const
  {
    if (auto cmp = record.index() <=> other.record.index(); cmp != 0)
      return cmp;
    auto record_cmp = std::visit(
        [&other](const auto &v) -> std::strong_ordering {
          using T = std::decay_t<decltype(v)>;
          return v <=> std::get<T>(other.record);
        },
        record);
    if (record_cmp != 0)
      return record_cmp;
    return field <=> other.field;
  }

  std::variant<Expression, SizedType> record;
  std::vector<std::string> field;
};

class Map : public Node {
public:
  explicit Map(ASTContext &ctx, Location &&loc, std::string ident)
      : Node(ctx, std::move(loc)), ident(std::move(ident)) {};
  explicit Map(ASTContext &ctx, const Location &loc, const Map &other)
      : Node(ctx, loc + other.loc),
        ident(other.ident),
        key_type(other.key_type),
        value_type(other.value_type) {};

  const SizedType &type() const
  {
    return value_type;
  }

  bool operator==(const Map &other) const
  {
    return ident == other.ident && key_type == other.key_type &&
           value_type == other.value_type;
  }
  std::strong_ordering operator<=>(const Map &other) const
  {
    if (auto cmp = ident <=> other.ident; cmp != 0)
      return cmp;
    if (auto cmp = key_type <=> other.key_type; cmp != 0)
      return cmp;
    return value_type <=> other.value_type;
  }

  std::string ident;
  SizedType key_type;
  SizedType value_type;
};

class Typeof : public Node {
public:
  explicit Typeof(ASTContext &ctx, Location &&loc, SizedType record)
      : Node(ctx, std::move(loc)), record(record) {};
  explicit Typeof(ASTContext &ctx, Location &&loc, Expression expr)
      : Node(ctx, std::move(loc)), record(expr) {};
  explicit Typeof(ASTContext &ctx, const Location &loc, const Typeof &other)
      : Node(ctx, loc + other.loc),
        record(clone(ctx, loc + other.loc, other.record)) {};

  const SizedType &type() const
  {
    if (std::holds_alternative<SizedType>(record)) {
      return std::get<SizedType>(record);
    } else {
      const auto &expr = std::get<Expression>(record);
      // If this is a scalar map, it will be automatically deusgared and
      // turned into a map access. Otherwise, it is left as a raw map
      // and this case is handled as a special path.
      if (auto *map = expr.as<Map>()) {
        return map->key_type;
      } else {
        return expr.type();
      }
    }
  }

  bool operator==(const Typeof &other) const
  {
    return record == other.record;
  }
  std::strong_ordering operator<=>(const Typeof &other) const
  {
    return record <=> other.record;
  }

  std::variant<Expression, SizedType> record;
};

class Typeinfo : public Node {
public:
  explicit Typeinfo(ASTContext &ctx, Location &&loc, Typeof *typeof)
      : Node(ctx, std::move(loc)), typeof(typeof) {};
  explicit Typeinfo(ASTContext &ctx, const Location &loc, const Typeinfo &other)
      : Node(ctx, loc + other.loc),
        typeof(clone(ctx, loc + other.loc, other.typeof)) {};

  const SizedType &type() const
  {
    // This must always be resolved inline, and when used as an expression will
    // be replaced during semantic analysis with a suitable tuple.
    static SizedType none = CreateNone();
    return none;
  }

  bool operator==(const Typeinfo &other) const
  {
    return *typeof == *other.typeof;
  }
  std::strong_ordering operator<=>(const Typeinfo &other) const
  {
    return *typeof <=> *other.typeof;
  }

  Typeof *typeof = nullptr;
};

class Comptime : public Node {
public:
  explicit Comptime(ASTContext &ctx, Location &&loc, Expression expr)
      : Node(ctx, std::move(loc)), expr(std::move(expr)) {};
  explicit Comptime(ASTContext &ctx, const Location &loc, const Comptime &other)
      : Node(ctx, loc + other.loc),
        expr(clone(ctx, loc + other.loc, other.expr)) {};

  const SizedType &type() const
  {
    return expr.type();
  }

  bool operator==([[maybe_unused]] const Comptime &other) const
  {
    return expr == other.expr;
  }
  std::strong_ordering operator<=>([[maybe_unused]] const Comptime &other) const
  {
    return expr <=> other.expr;
  }

  Expression expr;
};

class MapDeclStatement : public Node {
public:
  explicit MapDeclStatement(ASTContext &ctx,
                            Location &&loc,
                            std::string ident,
                            std::string bpf_type,
                            int max_entries)
      : Node(ctx, std::move(loc)),
        ident(std::move(ident)),
        bpf_type(std::move(bpf_type)),
        max_entries(max_entries) {};
  explicit MapDeclStatement(ASTContext &ctx,
                            const Location &loc,
                            const MapDeclStatement &other)
      : Node(ctx, loc + other.loc),
        ident(other.ident),
        bpf_type(other.bpf_type),
        max_entries(other.max_entries) {};

  bool operator==(const MapDeclStatement &other) const
  {
    return ident == other.ident && bpf_type == other.bpf_type &&
           max_entries == other.max_entries;
  }
  std::strong_ordering operator<=>(const MapDeclStatement &other) const
  {
    if (auto cmp = ident <=> other.ident; cmp != 0)
      return cmp;
    if (auto cmp = bpf_type <=> other.bpf_type; cmp != 0)
      return cmp;
    return max_entries <=> other.max_entries;
  }

  const std::string ident;
  const std::string bpf_type;
  const int max_entries;
};
using MapDeclList = std::vector<MapDeclStatement *>;

class Variable : public Node {
public:
  explicit Variable(ASTContext &ctx, Location &&loc, std::string ident)
      : Node(ctx, std::move(loc)), ident(std::move(ident)) {};
  explicit Variable(ASTContext &ctx, const Location &loc, const Variable &other)
      : Node(ctx, loc + other.loc),
        ident(other.ident),
        var_type(other.var_type) {};

  const SizedType &type() const
  {
    return var_type;
  }

  bool operator==(const Variable &other) const
  {
    return ident == other.ident && var_type == other.var_type;
  }
  std::strong_ordering operator<=>(const Variable &other) const
  {
    if (auto cmp = ident <=> other.ident; cmp != 0)
      return cmp;
    return var_type <=> other.var_type;
  }

  std::string ident;
  SizedType var_type;
};

class VariableAddr : public Node {
public:
  explicit VariableAddr(ASTContext &ctx, Location &&loc, Variable *var)
      : Node(ctx, std::move(loc)), var(var), var_addr_type(CreateNone()) {};
  explicit VariableAddr(ASTContext &ctx,
                        const Location &loc,
                        const VariableAddr &other)
      : Node(ctx, loc + other.loc),
        var(clone(ctx, loc, other.var)),
        var_addr_type(other.var_addr_type) {};

  const SizedType &type() const
  {
    return var_addr_type;
  }

  bool operator==(const VariableAddr &other) const
  {
    return *var == *other.var && var_addr_type == other.var_addr_type;
  }
  std::strong_ordering operator<=>(const VariableAddr &other) const
  {
    if (auto cmp = *var <=> *other.var; cmp != 0)
      return cmp;
    return var_addr_type <=> other.var_addr_type;
  }

  Variable *var = nullptr;
  SizedType var_addr_type;
};

class MapAddr : public Node {
public:
  explicit MapAddr(ASTContext &ctx, Location &&loc, Map *map)
      : Node(ctx, std::move(loc)), map(map) {};
  explicit MapAddr(ASTContext &ctx, const Location &loc, const MapAddr &other)
      : Node(ctx, loc + other.loc), map(clone(ctx, loc, other.map)) {};

  const SizedType &type() const
  {
    return map_addr_type;
  }

  bool operator==(const MapAddr &other) const
  {
    return *map == *other.map;
  }
  std::strong_ordering operator<=>(const MapAddr &other) const
  {
    return *map <=> *other.map;
  }

  Map *map = nullptr;
  SizedType map_addr_type;
};

class Binop : public Node {
public:
  explicit Binop(ASTContext &ctx,
                 Location &&loc,
                 Expression left,
                 Operator op,
                 Expression right)
      : Node(ctx, std::move(loc)),
        left(std::move(left)),
        right(std::move(right)),
        op(op) {};
  explicit Binop(ASTContext &ctx, const Location &loc, const Binop &other)
      : Node(ctx, loc + other.loc),
        left(clone(ctx, loc, other.left)),
        right(clone(ctx, loc, other.right)),
        op(other.op),
        result_type(other.result_type) {};

  const SizedType &type() const
  {
    return result_type;
  }

  bool operator==(const Binop &other) const
  {
    return op == other.op && left == other.left && right == other.right &&
           result_type == other.result_type;
  }
  std::strong_ordering operator<=>(const Binop &other) const
  {
    if (auto cmp = op <=> other.op; cmp != 0)
      return cmp;
    if (auto cmp = left <=> other.left; cmp != 0)
      return cmp;
    if (auto cmp = right <=> other.right; cmp != 0)
      return cmp;
    return result_type <=> other.result_type;
  }

  Expression left;
  Expression right;
  Operator op;
  SizedType result_type;
};

class Unop : public Node {
public:
  explicit Unop(ASTContext &ctx, Location &&loc, Expression expr, Operator op)
      : Node(ctx, std::move(loc)), expr(std::move(expr)), op(op) {};
  explicit Unop(ASTContext &ctx, const Location &loc, const Unop &other)
      : Node(ctx, loc + other.loc),
        expr(clone(ctx, loc, other.expr)),
        op(other.op) {};

  const SizedType &type() const
  {
    return result_type;
  }

  bool operator==(const Unop &other) const
  {
    return op == other.op && expr == other.expr &&
           result_type == other.result_type;
  }
  std::strong_ordering operator<=>(const Unop &other) const
  {
    if (auto cmp = op <=> other.op; cmp != 0)
      return cmp;
    if (auto cmp = expr <=> other.expr; cmp != 0)
      return cmp;
    return result_type <=> other.result_type;
  }

  Expression expr;
  Operator op;
  SizedType result_type;
};

class FieldAccess : public Node {
public:
  explicit FieldAccess(ASTContext &ctx,
                       Location &&loc,
                       Expression expr,
                       std::string field)
      : Node(ctx, std::move(loc)),
        expr(std::move(expr)),
        field(std::move(field)) {};
  explicit FieldAccess(ASTContext &ctx,
                       const Location &loc,
                       const FieldAccess &other)
      : Node(ctx, loc + other.loc),
        expr(clone(ctx, loc, other.expr)),
        field(other.field),
        field_type(other.field_type) {};

  const SizedType &type() const
  {
    return field_type;
  }

  bool operator==(const FieldAccess &other) const
  {
    return field == other.field && expr == other.expr &&
           field_type == other.field_type;
  }
  std::strong_ordering operator<=>(const FieldAccess &other) const
  {
    if (auto cmp = field <=> other.field; cmp != 0)
      return cmp;
    if (auto cmp = expr <=> other.expr; cmp != 0)
      return cmp;
    return field_type <=> other.field_type;
  }

  Expression expr;
  std::string field;
  SizedType field_type;
};

class ArrayAccess : public Node {
public:
  explicit ArrayAccess(ASTContext &ctx,
                       Location &&loc,
                       Expression expr,
                       Expression indexpr)
      : Node(ctx, std::move(loc)),
        expr(std::move(expr)),
        indexpr(std::move(indexpr)) {};
  explicit ArrayAccess(ASTContext &ctx,
                       const Location &loc,
                       const ArrayAccess &other)
      : Node(ctx, loc + other.loc),
        expr(clone(ctx, loc, other.expr)),
        indexpr(clone(ctx, loc, other.indexpr)) {};

  const SizedType &type() const
  {
    return element_type;
  }

  bool operator==(const ArrayAccess &other) const
  {
    return expr == other.expr && indexpr == other.indexpr &&
           element_type == other.element_type;
  }
  std::strong_ordering operator<=>(const ArrayAccess &other) const
  {
    if (auto cmp = expr <=> other.expr; cmp != 0)
      return cmp;
    if (auto cmp = indexpr <=> other.indexpr; cmp != 0)
      return cmp;
    return element_type <=> other.element_type;
  }

  Expression expr;
  Expression indexpr;
  SizedType element_type;
};

class TupleAccess : public Node {
public:
  explicit TupleAccess(ASTContext &ctx,
                       Location &&loc,
                       Expression expr,
                       ssize_t index)
      : Node(ctx, std::move(loc)), expr(std::move(expr)), index(index) {};
  explicit TupleAccess(ASTContext &ctx,
                       const Location &loc,
                       const TupleAccess &other)
      : Node(ctx, loc + other.loc),
        expr(clone(ctx, loc, other.expr)),
        index(other.index),
        element_type(other.element_type) {};

  const SizedType &type() const
  {
    return element_type;
  }

  bool operator==(const TupleAccess &other) const
  {
    return index == other.index && expr == other.expr &&
           element_type == other.element_type;
  }
  std::strong_ordering operator<=>(const TupleAccess &other) const
  {
    if (auto cmp = index <=> other.index; cmp != 0)
      return cmp;
    if (auto cmp = expr <=> other.expr; cmp != 0)
      return cmp;
    return element_type <=> other.element_type;
  }

  Expression expr;
  size_t index;
  SizedType element_type;
};

class MapAccess : public Node {
public:
  explicit MapAccess(ASTContext &ctx, Location &&loc, Map *map, Expression key)
      : Node(ctx, std::move(loc)), map(map), key(std::move(key)) {};
  explicit MapAccess(ASTContext &ctx,
                     const Location &loc,
                     const MapAccess &other)
      : Node(ctx, loc + other.loc),
        map(clone(ctx, loc, other.map)),
        key(clone(ctx, loc, other.key)) {};

  const SizedType &type() const
  {
    return map->type();
  }

  bool operator==(const MapAccess &other) const
  {
    return *map == *other.map && key == other.key;
  }
  std::strong_ordering operator<=>(const MapAccess &other) const
  {
    if (auto cmp = *map <=> *other.map; cmp != 0)
      return cmp;
    return key <=> other.key;
  }

  Map *map = nullptr;
  Expression key;
};

class Cast : public Node {
public:
  explicit Cast(ASTContext &ctx,
                Location &&loc,
                Typeof *typeof,
                Expression expr)
      : Node(ctx, std::move(loc)), typeof(typeof), expr(std::move(expr)) {};
  explicit Cast(ASTContext &ctx, const Location &loc, const Cast &other)
      : Node(ctx, loc + other.loc),
        typeof(clone(ctx, loc, other.typeof)),
        expr(clone(ctx, loc, other.expr)) {};

  const SizedType &type() const
  {
    return typeof->type();
  }

  bool operator==(const Cast &other) const
  {
    return *typeof == *other.typeof && expr == other.expr;
  }
  std::strong_ordering operator<=>(const Cast &other) const
  {
    if (auto cmp = *typeof <=> *other.typeof; cmp != 0)
      return cmp;
    return expr <=> other.expr;
  }

  Typeof *typeof;
  Expression expr;
};

class Tuple : public Node {
public:
  explicit Tuple(ASTContext &ctx, Location &&loc, ExpressionList &&elems)
      : Node(ctx, std::move(loc)), elems(std::move(elems)) {};
  explicit Tuple(ASTContext &ctx, const Location &loc, const Tuple &other)
      : Node(ctx, loc + other.loc), elems(clone(ctx, loc, other.elems)) {};

  const SizedType &type() const
  {
    return tuple_type;
  }

  bool operator==(const Tuple &other) const
  {
    return elems == other.elems && tuple_type == other.tuple_type;
  }
  std::strong_ordering operator<=>(const Tuple &other) const
  {
    if (auto cmp = elems <=> other.elems; cmp != 0)
      return cmp;
    return tuple_type <=> other.tuple_type;
  }

  ExpressionList elems;
  SizedType tuple_type;
};

class ExprStatement : public Node {
public:
  explicit ExprStatement(ASTContext &ctx, Location &&loc, Expression expr)
      : Node(ctx, std::move(loc)), expr(expr) {};
  explicit ExprStatement(ASTContext &ctx,
                         const Location &loc,
                         const ExprStatement &other)
      : Node(ctx, loc + other.loc), expr(clone(ctx, loc, other.expr)) {};

  bool operator==(const ExprStatement &other) const
  {
    return expr == other.expr;
  }
  std::strong_ordering operator<=>(const ExprStatement &other) const
  {
    return expr <=> other.expr;
  }

  Expression expr;
};

class VarDeclStatement : public Node {
public:
  explicit VarDeclStatement(ASTContext &ctx,
                            Location &&loc,
                            Variable *var,
                            Typeof *typeof)
      : Node(ctx, std::move(loc)), var(var), typeof(typeof) {};
  explicit VarDeclStatement(ASTContext &ctx, Location &&loc, Variable *var)
      : Node(ctx, std::move(loc)), var(var) {};
  explicit VarDeclStatement(ASTContext &ctx,
                            const Location &loc,
                            const VarDeclStatement &other)
      : Node(ctx, loc + other.loc),
        var(clone(ctx, loc, other.var)),
        typeof(clone(ctx, loc, other.typeof)) {};

  bool operator==(const VarDeclStatement &other) const
  {
    return *var == *other.var && *typeof == *other.typeof;
  }
  std::strong_ordering operator<=>(const VarDeclStatement &other) const
  {
    if (auto cmp = *var <=> *other.var; cmp != 0)
      return cmp;
    return *typeof <=> *other.typeof;
  }

  Variable *var = nullptr;
  Typeof *typeof = nullptr;
};

// Scalar map assignment is purely syntactic sugar that is removed by the pass
// returned by`CreateMapSugarPass`. This is replaced by the expansion of
// default keys, so that later steps (semantic analysis, code generation),
// don't need to worry about this. Maps whose accesses are bound to a single
// key will be automatically collapsed into scalar values on the output side.
class AssignScalarMapStatement : public Node {
public:
  explicit AssignScalarMapStatement(ASTContext &ctx,
                                    Location &&loc,
                                    Map *map,
                                    Expression expr)
      : Node(ctx, std::move(loc)), map(map), expr(std::move(expr)) {};
  explicit AssignScalarMapStatement(ASTContext &ctx,
                                    const Location &loc,
                                    const AssignScalarMapStatement &other)
      : Node(ctx, loc + other.loc),
        map(clone(ctx, loc, other.map)),
        expr(clone(ctx, loc, other.expr)) {};

  bool operator==(const AssignScalarMapStatement &other) const
  {
    return *map == *other.map && expr == other.expr;
  }
  std::strong_ordering operator<=>(const AssignScalarMapStatement &other) const
  {
    if (auto cmp = *map <=> *other.map; cmp != 0)
      return cmp;
    return expr <=> other.expr;
  }

  Map *map = nullptr;
  Expression expr;
};

class AssignMapStatement : public Node {
public:
  explicit AssignMapStatement(ASTContext &ctx,
                              Location &&loc,
                              MapAccess *map,
                              Expression expr)
      : Node(ctx, std::move(loc)), map_access(map), expr(std::move(expr)) {};
  explicit AssignMapStatement(ASTContext &ctx,
                              const Location &loc,
                              const AssignMapStatement &other)
      : Node(ctx, loc + other.loc),
        map_access(clone(ctx, loc, other.map_access)),
        expr(clone(ctx, loc, other.expr)) {};

  bool operator==(const AssignMapStatement &other) const
  {
    return *map_access == *other.map_access && expr == other.expr;
  }
  std::strong_ordering operator<=>(const AssignMapStatement &other) const
  {
    if (auto cmp = *map_access <=> *other.map_access; cmp != 0)
      return cmp;
    return expr <=> other.expr;
  }

  MapAccess *map_access = nullptr;
  Expression expr;
};

class AssignVarStatement : public Node {
public:
  explicit AssignVarStatement(ASTContext &ctx,
                              Location &&loc,
                              Variable *var,
                              Expression expr)
      : Node(ctx, std::move(loc)), var_decl(var), expr(std::move(expr)) {};
  explicit AssignVarStatement(ASTContext &ctx,
                              Location &&loc,
                              VarDeclStatement *var_decl_stmt,
                              Expression expr)
      : Node(ctx, std::move(loc)),
        var_decl(var_decl_stmt),
        expr(std::move(expr)) {};
  explicit AssignVarStatement(ASTContext &ctx,
                              const Location &loc,
                              const AssignVarStatement &other)
      : Node(ctx, loc + other.loc),
        var_decl(clone(ctx, loc, other.var_decl)),
        expr(clone(ctx, loc, other.expr)) {};

  Variable *var() const
  {
    if (std::holds_alternative<VarDeclStatement *>(var_decl)) {
      return std::get<VarDeclStatement *>(var_decl)->var;
    } else {
      return std::get<Variable *>(var_decl);
    }
  }

  bool operator==(const AssignVarStatement &other) const
  {
    if (var_decl.index() != other.var_decl.index())
      return false;
    bool var_decl_equal = std::visit(
        [&other](const auto &v) {
          using T = std::decay_t<decltype(v)>;
          return *v == *std::get<T>(other.var_decl);
        },
        var_decl);
    return var_decl_equal && expr == other.expr;
  }
  std::strong_ordering operator<=>(const AssignVarStatement &other) const
  {
    if (auto cmp = var_decl.index() <=> other.var_decl.index(); cmp != 0)
      return cmp;
    auto var_decl_cmp = std::visit(
        [&other](const auto &v) {
          using T = std::decay_t<decltype(v)>;
          return *v <=> *std::get<T>(other.var_decl);
        },
        var_decl);
    if (var_decl_cmp != 0)
      return var_decl_cmp;
    return expr <=> other.expr;
  }

  std::variant<VarDeclStatement *, Variable *> var_decl;
  Expression expr;
};

class AssignConfigVarStatement : public Node {
public:
  explicit AssignConfigVarStatement(ASTContext &ctx,
                                    Location &&loc,
                                    std::string var,
                                    uint64_t value)
      : Node(ctx, std::move(loc)), var(std::move(var)), value(value) {};
  explicit AssignConfigVarStatement(ASTContext &ctx,
                                    Location &&loc,
                                    std::string var,
                                    std::string value)
      : Node(ctx, std::move(loc)),
        var(std::move(var)),
        value(std::move(value)) {};
  explicit AssignConfigVarStatement(ASTContext &ctx,
                                    Location &&loc,
                                    std::string var,
                                    bool value)
      : Node(ctx, std::move(loc)), var(std::move(var)), value(value) {};
  explicit AssignConfigVarStatement(ASTContext &ctx,
                                    const Location &loc,
                                    const AssignConfigVarStatement &other)
      : Node(ctx, loc + other.loc), var(other.var), value(other.value) {};

  bool operator==(const AssignConfigVarStatement &other) const
  {
    return var == other.var && value == other.value;
  }
  std::strong_ordering operator<=>(const AssignConfigVarStatement &other) const
  {
    if (auto cmp = var <=> other.var; cmp != 0)
      return cmp;
    return value <=> other.value;
  }

  std::string var;
  std::variant<uint64_t, std::string, bool> value;
};
using ConfigStatementList = std::vector<AssignConfigVarStatement *>;

class BlockExpr : public Node {
public:
  explicit BlockExpr(ASTContext &ctx,
                     Location &&loc,
                     StatementList &&stmts,
                     Expression expr)
      : Node(ctx, std::move(loc)),
        stmts(std::move(stmts)),
        expr(std::move(expr)) {};
  explicit BlockExpr(ASTContext &ctx,
                     const Location &loc,
                     const BlockExpr &other)
      : Node(ctx, loc + other.loc),
        stmts(clone(ctx, loc, other.stmts)),
        expr(clone(ctx, loc, other.expr)) {};

  const SizedType &type() const
  {
    return expr.type();
  }

  bool operator==(const BlockExpr &other) const
  {
    return stmts == other.stmts && expr == other.expr;
  }
  std::strong_ordering operator<=>(const BlockExpr &other) const
  {
    if (auto cmp = stmts <=> other.stmts; cmp != 0)
      return cmp;
    return expr <=> other.expr;
  }

  StatementList stmts;
  Expression expr;
};

class DiscardExpr : public Node {
public:
  explicit DiscardExpr(ASTContext &ctx,
                              Location &&loc,
                              Expression expr)
      : Node(ctx, std::move(loc)), expr(std::move(expr)) {};
  explicit DiscardExpr(ASTContext &ctx,
                              const Location &loc,
                              const DiscardExpr &other)
      : Node(ctx, loc + other.loc),
        expr(clone(ctx, loc, other.expr)) {};

  bool operator==(const DiscardExpr &other) const
  {
    return expr == other.expr;
  }
  std::strong_ordering operator<=>(const DiscardExpr &other) const
  {
    return expr <=> other.expr;
  }

  Expression expr;
};

class Unroll : public Node {
public:
  explicit Unroll(ASTContext &ctx,
                  Location &&loc,
                  Expression expr,
                  BlockExpr *block)
      : Node(ctx, std::move(loc)), expr(std::move(expr)), block(block) {};
  explicit Unroll(ASTContext &ctx, const Location &loc, const Unroll &other)
      : Node(ctx, loc + other.loc),
        expr(clone(ctx, loc, other.expr)),
        block(clone(ctx, loc, other.block)) {};

  bool operator==(const Unroll &other) const
  {
    return expr == other.expr && *block == *other.block;
  }
  std::strong_ordering operator<=>(const Unroll &other) const
  {
    if (auto cmp = expr <=> other.expr; cmp != 0)
      return cmp;
    return *block <=> *other.block;
  }

  Expression expr;
  BlockExpr *block = nullptr;
};

class Jump : public Node {
public:
  explicit Jump(ASTContext &ctx,
                Location &&loc,
                JumpType ident,
                Expression return_value)
      : Node(ctx, std::move(loc)),
        ident(ident),
        return_value(std::move(return_value)) {};
  explicit Jump(ASTContext &ctx, Location &&loc, JumpType ident)
      : Node(ctx, std::move(loc)), ident(ident) {};
  explicit Jump(ASTContext &ctx, const Location &loc, const Jump &other)
      : Node(ctx, loc + other.loc),
        ident(other.ident),
        return_value(clone(ctx, loc, other.return_value)) {};

  bool operator==(const Jump &other) const
  {
    return ident == other.ident && return_value == other.return_value;
  }
  std::strong_ordering operator<=>(const Jump &other) const
  {
    if (auto cmp = ident <=> other.ident; cmp != 0)
      return cmp;
    return return_value <=> other.return_value;
  }

  JumpType ident;
  std::optional<Expression> return_value;
};

class IfExpr : public Node {
public:
  explicit IfExpr(ASTContext &ctx,
                  Location &&loc,
                  Expression cond,
                  Expression left,
                  Expression right)
      : Node(ctx, std::move(loc)),
        cond(std::move(cond)),
        left(std::move(left)),
        right(std::move(right)) {};
  explicit IfExpr(ASTContext &ctx, const Location &loc, const IfExpr &other)
      : Node(ctx, loc + other.loc),
        cond(clone(ctx, loc, other.cond)),
        left(clone(ctx, loc, other.left)),
        right(clone(ctx, loc, other.right)),
        result_type(other.result_type) {};

  const SizedType &type() const
  {
    return result_type;
  }

  bool operator==(const IfExpr &other) const
  {
    return cond == other.cond && left == other.left && right == other.right &&
           result_type == other.result_type;
  }
  std::strong_ordering operator<=>(const IfExpr &other) const
  {
    if (auto cmp = cond <=> other.cond; cmp != 0)
      return cmp;
    if (auto cmp = left <=> other.left; cmp != 0)
      return cmp;
    if (auto cmp = right <=> other.right; cmp != 0)
      return cmp;
    return result_type <=> other.result_type;
  }

  Expression cond;
  Expression left;
  Expression right;
  SizedType result_type;
};

class While : public Node {
public:
  explicit While(ASTContext &ctx,
                 Location &&loc,
                 Expression cond,
                 BlockExpr *block)
      : Node(ctx, std::move(loc)), cond(cond), block(block) {};
  explicit While(ASTContext &ctx, const Location &loc, const While &other)
      : Node(ctx, loc + other.loc),
        cond(clone(ctx, loc, other.cond)),
        block(clone(ctx, loc, other.block)) {};

  bool operator==(const While &other) const
  {
    return cond == other.cond && *block == *other.block;
  }
  std::strong_ordering operator<=>(const While &other) const
  {
    if (auto cmp = cond <=> other.cond; cmp != 0)
      return cmp;
    return *block <=> *other.block;
  }

  Expression cond;
  BlockExpr *block = nullptr;
};

class Range : public Node {
public:
  explicit Range(ASTContext &ctx,
                 Location &&loc,
                 Expression start,
                 Expression end)
      : Node(ctx, std::move(loc)), start(start), end(end) {};
  explicit Range(ASTContext &ctx, const Location &loc, const Range &other)
      : Node(ctx, loc + other.loc),
        start(clone(ctx, loc, other.start)),
        end(clone(ctx, loc, other.end)) {};

  bool operator==(const Range &other) const
  {
    return start == other.start && end == other.end;
  }
  std::strong_ordering operator<=>(const Range &other) const
  {
    if (auto cmp = start <=> other.start; cmp != 0)
      return cmp;
    return end <=> other.end;
  }

  Expression start;
  Expression end;
};

class Iterable : public VariantNode<Map, Range> {
public:
  using VariantNode::VariantNode;
  Iterable() : Iterable(static_cast<Map *>(nullptr)) {};
};

class For : public Node {
public:
  explicit For(ASTContext &ctx,
               Location &&loc,
               Variable *decl,
               Iterable iterable,
               BlockExpr *block)
      : Node(ctx, std::move(loc)),
        decl(decl),
        iterable(iterable),
        block(block) {};
  explicit For(ASTContext &ctx, const Location &loc, const For &other)
      : Node(ctx, loc + other.loc),
        decl(clone(ctx, loc, other.decl)),
        iterable(clone(ctx, loc, other.iterable)),
        block(clone(ctx, loc, other.block)) {};

  bool operator==(const For &other) const
  {
    return *decl == *other.decl && iterable == other.iterable &&
           *block == *other.block && ctx_type == other.ctx_type;
  }
  std::strong_ordering operator<=>(const For &other) const
  {
    if (auto cmp = *decl <=> *other.decl; cmp != 0)
      return cmp;
    if (auto cmp = iterable <=> other.iterable; cmp != 0)
      return cmp;
    if (auto cmp = *block <=> *other.block; cmp != 0)
      return cmp;
    return ctx_type <=> other.ctx_type;
  }

  Variable *decl = nullptr;
  Iterable iterable;
  BlockExpr *block = nullptr;
  SizedType ctx_type;
};

class Config : public Node {
public:
  explicit Config(ASTContext &ctx, Location &&loc, ConfigStatementList &&stmts)
      : Node(ctx, std::move(loc)), stmts(std::move(stmts)) {};
  explicit Config(ASTContext &ctx, const Location &loc, const Config &other)
      : Node(ctx, loc + other.loc), stmts(clone(ctx, loc, other.stmts)) {};

  bool operator==(const Config &other) const
  {
    return stmts == other.stmts;
  }
  std::strong_ordering operator<=>(const Config &other) const
  {
    return stmts <=> other.stmts;
  }

  ConfigStatementList stmts;
};

class Probe;
class AttachPoint : public Node {
public:
  explicit AttachPoint(ASTContext &ctx,
                       Location &&loc,
                       std::string raw_input,
                       bool ignore_invalid)
      : Node(ctx, std::move(loc)),
        raw_input(std::move(raw_input)),
        ignore_invalid(ignore_invalid) {};
  explicit AttachPoint(ASTContext &ctx,
                       const Location &loc,
                       const AttachPoint &other)
      : Node(ctx, loc + other.loc),
        raw_input(other.raw_input),
        provider(other.provider),
        target(other.target),
        lang(other.lang),
        ns(other.ns),
        func(other.func),
        pin(other.pin),
        usdt(other.usdt),
        freq(other.freq),
        len(other.len),
        mode(other.mode),
        async(other.async),
        address(other.address),
        func_offset(other.func_offset),
        ignore_invalid(other.ignore_invalid) {};

  bool operator==(const AttachPoint &other) const
  {
    return raw_input == other.raw_input && provider == other.provider &&
           target == other.target && lang == other.lang && ns == other.ns &&
           func == other.func && pin == other.pin && freq == other.freq &&
           len == other.len && mode == other.mode && async == other.async &&
           address == other.address && func_offset == other.func_offset &&
           ignore_invalid == other.ignore_invalid;
  }
  std::strong_ordering operator<=>(const AttachPoint &other) const
  {
    if (auto cmp = raw_input <=> other.raw_input; cmp != 0)
      return cmp;
    if (auto cmp = provider <=> other.provider; cmp != 0)
      return cmp;
    if (auto cmp = target <=> other.target; cmp != 0)
      return cmp;
    if (auto cmp = lang <=> other.lang; cmp != 0)
      return cmp;
    if (auto cmp = ns <=> other.ns; cmp != 0)
      return cmp;
    if (auto cmp = func <=> other.func; cmp != 0)
      return cmp;
    if (auto cmp = pin <=> other.pin; cmp != 0)
      return cmp;
    if (auto cmp = freq <=> other.freq; cmp != 0)
      return cmp;
    if (auto cmp = len <=> other.len; cmp != 0)
      return cmp;
    if (auto cmp = mode <=> other.mode; cmp != 0)
      return cmp;
    if (auto cmp = async <=> other.async; cmp != 0)
      return cmp;
    if (auto cmp = address <=> other.address; cmp != 0)
      return cmp;
    if (auto cmp = func_offset <=> other.func_offset; cmp != 0)
      return cmp;
    return ignore_invalid <=> other.ignore_invalid;
  }

  // Currently, the AST node itself is used to store metadata related to probe
  // expansion and attachment. This is done through `create_expansion_copy`
  // below.  Since the nodes are not currently copyable by default (this is
  // currently fraught, as nodes may have backreferences that are not updated
  // in these cases), these fields are copied manually. *Until this is fixed,
  // if you are adding new fields, be sure to update `create_expansion_copy`.
  //
  // FIXME(amscanne): We are not currently cloning AttachPoints correctly, as
  // they refer to the existing ret probe.

  // Raw, unparsed input from user, eg. kprobe:vfs_read
  std::string raw_input;

  // The unique, user-provided name for this specific attachpoint. This is
  // the string the comes before the probe itself, e.g. foo=kprobe:xyz. If
  // this is not provided, then the attachpoint string is the unique name.
  std::optional<std::string> user_provided_name;

  std::string provider;
  std::string target;
  std::string lang; // for userspace probes, enable language-specific features
  std::string ns;
  std::string func;
  std::string pin;
  util::usdt_probe_entry usdt; // resolved USDT entry, used to support arguments with
                         // wildcard matches
  int64_t freq = 0;
  uint64_t len = 0;   // for watchpoint probes, the width of watched addr
  std::string mode;   // for watchpoint probes, the watch mode
  bool async = false; // for watchpoint probes, if it's an async watchpoint

  uint64_t address = 0;
  uint64_t func_offset = 0;
  uint64_t bpf_prog_id = 0;
  bool ignore_invalid = false;

  std::string name() const;

  AttachPoint *create_expansion_copy(ASTContext &ctx,
                                     const std::string &match) const;

  bool check_available(const std::string &identifier) const;
};
using AttachPointList = std::vector<AttachPoint *>;

class Probe : public Node {
public:
  explicit Probe(ASTContext &ctx,
                 Location &&loc,
                 AttachPointList &&attach_points,
                 BlockExpr *block)
      : Node(ctx, std::move(loc)),
        attach_points(std::move(attach_points)),
        block(block) {};
  explicit Probe(ASTContext &ctx, const Location &loc, const Probe &other)
      : Node(ctx, loc + other.loc),
        attach_points(clone(ctx, loc, other.attach_points)),
        block(clone(ctx, loc, other.block)),
        index_(other.index_) {};

  bool operator==(const Probe &other) const
  {
    return attach_points == other.attach_points && *block == *other.block;
  }
  std::strong_ordering operator<=>(const Probe &other) const
  {
    if (auto cmp = attach_points <=> other.attach_points; cmp != 0)
      return cmp;
    return *block <=> *other.block;
  }

  AttachPointList attach_points;
  BlockExpr *block = nullptr;

  // If the probes have multiple attachpoints, then neither attachpoint_name
  // nor args_typename will return a value; this must be handled by the
  // caller (although it will typically be a failure).
  std::optional<std::string> attachpoint_name() const;
  std::optional<std::string> args_typename() const;

  int index() const;
  void set_index(int index);

  bool has_ap_of_probetype(ProbeType probe_type);
  ProbeType get_probetype();

private:
  int index_ = 0;
};
using ProbeList = std::vector<Probe *>;

class SubprogArg : public Node {
public:
  explicit SubprogArg(ASTContext &ctx,
                      Location &&loc,
                      Variable *var,
                      Typeof *typeof)
      : Node(ctx, std::move(loc)), var(var), typeof(typeof) {};
  explicit SubprogArg(ASTContext &ctx,
                      const Location &loc,
                      const SubprogArg &other)
      : Node(ctx, loc + other.loc),
        var(clone(ctx, loc, other.var)),
        typeof(clone(ctx, loc, other.typeof)) {};

  bool operator==(const SubprogArg &other) const
  {
    return *var == *other.var && *typeof == *other.typeof;
  }
  std::strong_ordering operator<=>(const SubprogArg &other) const
  {
    if (auto cmp = *var <=> *other.var; cmp != 0)
      return cmp;
    return *typeof <=> *other.typeof;
  }

  Variable *var = nullptr;
  Typeof *typeof = nullptr;
};
using SubprogArgList = std::vector<SubprogArg *>;

class Subprog : public Node {
public:
  explicit Subprog(ASTContext &ctx,
                   Location &&loc,
                   std::string name,
                   Typeof *return_type,
                   SubprogArgList &&args,
                   BlockExpr *block)
      : Node(ctx, std::move(loc)),
        name(std::move(name)),
        return_type(return_type),
        args(std::move(args)),
        block(block) {};
  explicit Subprog(ASTContext &ctx, const Location &loc, const Subprog &other)
      : Node(ctx, loc + other.loc),
        name(other.name),
        return_type(clone(ctx, loc, other.return_type)),
        args(clone(ctx, loc, other.args)),
        block(clone(ctx, loc, other.block)) {};

  bool operator==(const Subprog &other) const
  {
    return name == other.name && return_type == other.return_type &&
           args == other.args && *block == *other.block;
  }
  std::strong_ordering operator<=>(const Subprog &other) const
  {
    if (auto cmp = name <=> other.name; cmp != 0)
      return cmp;
    if (auto cmp = return_type <=> other.return_type; cmp != 0)
      return cmp;
    if (auto cmp = args <=> other.args; cmp != 0)
      return cmp;
    return *block <=> *other.block;
  }

  const std::string name;
  Typeof *return_type;
  SubprogArgList args;
  BlockExpr *block = nullptr;
};
using SubprogList = std::vector<Subprog *>;

// N.B. These two import nodes are effectively the same
// except there are restrictions on the StatementImport
// which can exist in probe bodies, macros, and sub-progs.
// Having a separate AST node reduces needing stateful logic
// in the pass visitors if they were the same.
class RootImport : public Node {
public:
  explicit RootImport(ASTContext &ctx, Location &&loc, std::string name)
      : Node(ctx, std::move(loc)), name(std::move(name)) {};
  explicit RootImport(ASTContext &ctx, const Location &loc, const RootImport &other)
      : Node(ctx, loc + other.loc), name(other.name) {};

  bool operator==(const RootImport &other) const
  {
    return name == other.name;
  }
  std::strong_ordering operator<=>(const RootImport &other) const
  {
    return name <=> other.name;
  }

  const std::string name;
};

class StatementImport : public Node {
public:
  explicit StatementImport(ASTContext &ctx, Location &&loc, std::string name)
      : Node(ctx, std::move(loc)), name(std::move(name)) {};
  explicit StatementImport(ASTContext &ctx, const Location &loc, const StatementImport &other)
      : Node(ctx, loc + other.loc), name(other.name) {};

  bool operator==(const StatementImport &other) const
  {
    return name == other.name;
  }
  std::strong_ordering operator<=>(const StatementImport &other) const
  {
    return name <=> other.name;
  }

  const std::string name;
};

using RootImportList = std::vector<RootImport *>;

class Macro : public Node {
public:
  Macro(ASTContext &ctx,
        Location &&loc,
        std::string name,
        ExpressionList &&vargs,
        BlockExpr *block)
      : Node(ctx, std::move(loc)),
        name(std::move(name)),
        vargs(std::move(vargs)),
        block(block) {};
  explicit Macro(ASTContext &ctx, const Location &loc, const Macro &other)
      : Node(ctx, loc + other.loc),
        name(other.name),
        vargs(clone(ctx, loc, other.vargs)),
        block(clone(ctx, loc, other.block)) {};

  bool operator==(const Macro &other) const
  {
    if (name != other.name || vargs != other.vargs)
      return false;
    if (vargs != other.vargs)
      return false;
    return *block == *other.block;
  }
  std::strong_ordering operator<=>(const Macro &other) const
  {
    if (auto cmp = name <=> other.name; cmp != 0)
      return cmp;
    if (vargs.size() != other.vargs.size())
      return vargs.size() <=> other.vargs.size();
    for (size_t i = 0; i < vargs.size(); ++i) {
      if (auto cmp = vargs[i] <=> other.vargs[i]; cmp != 0)
        return cmp;
    }
    return *block <=> *other.block;
  }

  std::string name;
  ExpressionList vargs;
  BlockExpr *block = nullptr;
};
using MacroList = std::vector<Macro *>;

class CStatement : public Node {
public:
  CStatement(ASTContext &ctx, Location &&loc, std::string data)
      : Node(ctx, std::move(loc)), data(std::move(data)) {};
  explicit CStatement(ASTContext &ctx,
                      const Location &loc,
                      const CStatement &other)
      : Node(ctx, loc + other.loc), data(other.data) {};

  bool operator==(const CStatement &other) const
  {
    return data == other.data;
  }
  std::strong_ordering operator<=>(const CStatement &other) const
  {
    return data <=> other.data;
  }

  std::string data;
};
using CStatementList = std::vector<CStatement *>;

class Program : public Node {
public:
  explicit Program(ASTContext &ctx,
                   Location &&loc,
                   CStatementList &&c_statements,
                   Config *config,
                   RootImportList &&imports,
                   RootStatements &&root_statements,
                   std::optional<std::string> &&header = std::nullopt)
      : Node(ctx, std::move(loc)),
        c_statements(std::move(c_statements)),
        config(config),
        imports(std::move(imports)),
        header(std::move(header))
  {
    for (auto &stmt : root_statements) {
      if (auto *map_decl = stmt.as<MapDeclStatement>()) {
        map_decls.push_back(map_decl);
      } else if (auto *macro = stmt.as<Macro>()) {
        macros.push_back(macro);
      } else if (auto *function = stmt.as<Subprog>()) {
        functions.push_back(function);
      } else if (auto *probe = stmt.as<Probe>()) {
        probes.push_back(probe);
      }
    }
  };
  explicit Program(ASTContext &ctx, const Location &loc, const Program &other)
      : Node(ctx, loc + other.loc),
        c_statements(clone(ctx, loc, other.c_statements)),
        config(clone(ctx, loc, other.config)),
        imports(clone(ctx, loc, other.imports)),
        map_decls(clone(ctx, loc, other.map_decls)),
        macros(clone(ctx, loc, other.macros)),
        functions(clone(ctx, loc, other.functions)),
        probes(clone(ctx, loc, other.probes)),
        header(other.header) {};

  bool operator==(const Program &other) const
  {
    return c_statements == other.c_statements && *config == *other.config &&
           imports == other.imports && map_decls == other.map_decls &&
           macros == other.macros && functions == other.functions &&
           probes == other.probes;
  }
  std::strong_ordering operator<=>(const Program &other) const
  {
    if (auto cmp = c_statements <=> other.c_statements; cmp != 0)
      return cmp;
    if (auto cmp = *config <=> *other.config; cmp != 0)
      return cmp;
    if (auto cmp = imports <=> other.imports; cmp != 0)
      return cmp;
    if (auto cmp = map_decls <=> other.map_decls; cmp != 0)
      return cmp;
    if (auto cmp = macros <=> other.macros; cmp != 0)
      return cmp;
    if (auto cmp = functions <=> other.functions; cmp != 0)
      return cmp;
    return probes <=> other.probes;
  }

  CStatementList c_statements;
  Config *config = nullptr;
  RootImportList imports;
  MapDeclList map_decls;
  MacroList macros;
  SubprogList functions;
  ProbeList probes;
  std::optional<std::string> header;

  void clear_empty_probes();
};

std::string opstr(const Binop &binop);
std::string opstr(const Unop &unop);
std::string opstr(const Jump &jump);
bool is_comparison_op(Operator op);

SizedType ident_to_record(const std::string &ident, int pointer_level = 0);
SizedType ident_to_sized_type(const std::string &ident);

} // namespace bpftrace::ast
