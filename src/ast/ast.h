#pragma once

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "ast/clone.h"
#include "ast/context.h"
#include "diagnostic.h"
#include "probe_types.h"
#include "types.h"
#include "usdt.h"
#include "util/strings.h"

namespace bpftrace::ast {

enum class JumpType {
  INVALID = 0,
  RETURN,
  CONTINUE,
  BREAK,
};

enum class Operator {
  INVALID = 0,
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
  INCREMENT,
  DECREMENT,
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

  std::variant<Ts *...> value;
};

class Integer;
class NegativeInteger;
class Boolean;
class PositionalParameter;
class PositionalParameterCount;
class String;
class Identifier;
class Builtin;
class Call;
class Sizeof;
class Offsetof;
class Map;
class Variable;
class VariableAddr;
class Binop;
class Unop;
class FieldAccess;
class ArrayAccess;
class TupleAccess;
class MapAccess;
class Cast;
class Tuple;
class Ternary;
class BlockExpr;

class Expression : public VariantNode<Integer,
                                      NegativeInteger,
                                      Boolean,
                                      PositionalParameter,
                                      PositionalParameterCount,
                                      String,
                                      Identifier,
                                      Builtin,
                                      Call,
                                      Sizeof,
                                      Offsetof,
                                      Map,
                                      Variable,
                                      VariableAddr,
                                      Binop,
                                      Unop,
                                      FieldAccess,
                                      ArrayAccess,
                                      TupleAccess,
                                      MapAccess,
                                      Cast,
                                      Tuple,
                                      Ternary,
                                      BlockExpr> {
public:
  using VariantNode::VariantNode;
  Expression() : Expression(static_cast<BlockExpr *>(nullptr)) {};

  // The `type` method is the only common thing required by all expression
  // types. This will on the variant types.
  const SizedType &type() const;
};
using ExpressionList = std::vector<Expression>;

class ExprStatement;
class VarDeclStatement;
class AssignScalarMapStatement;
class AssignMapStatement;
class AssignVarStatement;
class If;
class Unroll;
class Jump;
class While;
class For;
class Block;

class Statement : public VariantNode<ExprStatement,
                                     VarDeclStatement,
                                     AssignScalarMapStatement,
                                     AssignMapStatement,
                                     AssignVarStatement,
                                     If,
                                     Unroll,
                                     Jump,
                                     While,
                                     For,
                                     Block> {
public:
  using VariantNode::VariantNode;
  Statement() : Statement(static_cast<ExprStatement *>(nullptr)) {};
};
using StatementList = std::vector<Statement>;

class Macro;
class MapDeclStatement;
class Probe;
class Subprog;

class RootStatement
    : public VariantNode<Probe, Subprog, Macro, MapDeclStatement> {
public:
  using VariantNode::VariantNode;
  RootStatement() : RootStatement(static_cast<Probe *>(nullptr)) {};
};
using RootStatements = std::vector<RootStatement>;

class Integer : public Node {
public:
  explicit Integer(ASTContext &ctx, uint64_t n, Location &&loc)
      : Node(ctx, std::move(loc)),
        integer_type(n >= std::numeric_limits<int64_t>::max() ? CreateUInt64()
                                                              : CreateInt64()),
        value(n) {};
  explicit Integer(ASTContext &ctx, const Integer &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        integer_type(other.integer_type),
        value(other.value) {};

  const SizedType &type() const
  {
    return integer_type;
  }

  // This literal has a dynamic type, but it is not mutable. The type is always
  // signed if the signed value is capable of holding the literal, otherwise it
  // is unsigned.
  const SizedType integer_type;
  const uint64_t value;
};

class NegativeInteger : public Node {
public:
  explicit NegativeInteger(ASTContext &ctx, int64_t n, Location &&loc)
      : Node(ctx, std::move(loc)), value(n) {};
  explicit NegativeInteger(ASTContext &ctx,
                           const NegativeInteger &other,
                           const Location &loc)
      : Node(ctx, loc + other.loc), value(other.value) {};

  const SizedType &type() const
  {
    static SizedType int64 = CreateInt64();
    return int64;
  }

  const int64_t value;
};

class Boolean : public Node {
public:
  explicit Boolean(ASTContext &ctx, bool val, Location &&loc)
      : Node(ctx, std::move(loc)), value(val) {};
  explicit Boolean(ASTContext &ctx, const Boolean &other, const Location &loc)
      : Node(ctx, loc + other.loc), value(other.value) {};

  const SizedType &type() const
  {
    static SizedType boolean = CreateBool();
    return boolean;
  }

  const bool value;
};

class PositionalParameter : public Node {
public:
  explicit PositionalParameter(ASTContext &ctx, long n, Location &&loc)
      : Node(ctx, std::move(loc)), n(n) {};
  explicit PositionalParameter(ASTContext &ctx,
                               const PositionalParameter &other,
                               const Location &loc)
      : Node(ctx, loc + other.loc), n(other.n) {};

  const SizedType &type() const
  {
    static SizedType none = CreateNone();
    return none;
  }

  const long n;
};

class PositionalParameterCount : public Node {
public:
  explicit PositionalParameterCount(ASTContext &ctx, Location &&loc)
      : Node(ctx, std::move(loc)) {};
  explicit PositionalParameterCount(
      ASTContext &ctx,
      [[maybe_unused]] const PositionalParameterCount &other,
      const Location &loc)
      : Node(ctx, loc + other.loc) {};

  const SizedType &type() const
  {
    static SizedType none = CreateNone();
    return none;
  }
};

class String : public Node {
public:
  explicit String(ASTContext &ctx, std::string str, Location &&loc)
      : Node(ctx, std::move(loc)),
        value(std::move(str)),
        string_type(CreateString(value.size() + 1)) {};
  explicit String(ASTContext &ctx, const String &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        value(other.value),
        string_type(other.string_type) {};

  const SizedType &type() const
  {
    return string_type;
  }

  const std::string value;
  SizedType string_type;
};

class Identifier : public Node {
public:
  explicit Identifier(ASTContext &ctx, std::string ident, Location &&loc)
      : Node(ctx, std::move(loc)), ident(std::move(ident)) {};
  explicit Identifier(ASTContext &ctx,
                      const Identifier &other,
                      const Location &loc)
      : Node(ctx, loc + other.loc),
        ident(other.ident),
        ident_type(other.ident_type) {};

  const SizedType &type() const
  {
    return ident_type;
  }

  std::string ident;
  SizedType ident_type;
};

class Builtin : public Node {
public:
  explicit Builtin(ASTContext &ctx, std::string ident, Location &&loc)
      : Node(ctx, std::move(loc)), ident(std::move(ident)) {};
  explicit Builtin(ASTContext &ctx, const Builtin &other, const Location &loc)
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

  std::string ident;
  int probe_id;
  SizedType builtin_type;
};

class Call : public Node {
public:
  explicit Call(ASTContext &ctx, std::string func, Location &&loc)
      : Node(ctx, std::move(loc)), func(std::move(func)) {};
  explicit Call(ASTContext &ctx,
                std::string func,
                ExpressionList &&vargs,
                Location &&loc)
      : Node(ctx, std::move(loc)),
        func(std::move(func)),
        vargs(std::move(vargs)) {};
  explicit Call(ASTContext &ctx, const Call &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        func(other.func),
        vargs(clone(ctx, other.vargs, loc)),
        return_type(other.return_type),
        injected_args(other.injected_args) {};

  const SizedType &type() const
  {
    return return_type;
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
  bool ret_val_discarded = false;
};

class Sizeof : public Node {
public:
  explicit Sizeof(ASTContext &ctx, SizedType type, Location &&loc)
      : Node(ctx, std::move(loc)), record(type) {};
  explicit Sizeof(ASTContext &ctx, Expression expr, Location &&loc)
      : Node(ctx, std::move(loc)), record(expr) {};
  explicit Sizeof(ASTContext &ctx, const Sizeof &other, const Location &loc)
      : Node(ctx, loc + other.loc), record(clone(ctx, other.record, loc)) {};

  const SizedType &type() const
  {
    static SizedType uint64 = CreateUInt64();
    return uint64;
  }

  std::variant<Expression, SizedType> record;
};

class Offsetof : public Node {
public:
  explicit Offsetof(ASTContext &ctx,
                    SizedType record,
                    std::vector<std::string> &field,
                    Location &&loc)
      : Node(ctx, std::move(loc)), record(record), field(field) {};
  explicit Offsetof(ASTContext &ctx,
                    Expression expr,
                    std::vector<std::string> &field,
                    Location &&loc)
      : Node(ctx, std::move(loc)), record(expr), field(field) {};
  explicit Offsetof(ASTContext &ctx, const Offsetof &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        record(clone(ctx, other.record, loc + other.loc)),
        field(other.field) {};

  const SizedType &type() const
  {
    static SizedType uint64 = CreateUInt64();
    return uint64;
  }

  std::variant<Expression, SizedType> record;
  std::vector<std::string> field;
};

class MapDeclStatement : public Node {
public:
  explicit MapDeclStatement(ASTContext &ctx,
                            std::string ident,
                            std::string bpf_type,
                            int max_entries,
                            Location &&loc)
      : Node(ctx, std::move(loc)),
        ident(std::move(ident)),
        bpf_type(std::move(bpf_type)),
        max_entries(max_entries) {};
  explicit MapDeclStatement(ASTContext &ctx,
                            const MapDeclStatement &other,
                            const Location &loc)
      : Node(ctx, loc + other.loc),
        ident(other.ident),
        bpf_type(other.bpf_type),
        max_entries(other.max_entries) {};

  const std::string ident;
  const std::string bpf_type;
  const int max_entries;
};
using MapDeclList = std::vector<MapDeclStatement *>;

class Map : public Node {
public:
  explicit Map(ASTContext &ctx, std::string ident, Location &&loc)
      : Node(ctx, std::move(loc)), ident(std::move(ident)) {};
  explicit Map(ASTContext &ctx, const Map &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        ident(other.ident),
        key_type(other.key_type),
        value_type(other.value_type) {};

  const SizedType &type() const
  {
    return value_type;
  }

  std::string ident;
  SizedType key_type;
  SizedType value_type;
};

class Variable : public Node {
public:
  explicit Variable(ASTContext &ctx, std::string ident, Location &&loc)
      : Node(ctx, std::move(loc)), ident(std::move(ident)) {};
  explicit Variable(ASTContext &ctx, const Variable &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        ident(other.ident),
        var_type(other.var_type) {};

  const SizedType &type() const
  {
    return var_type;
  }

  std::string ident;
  SizedType var_type;
};

class VariableAddr : public Node {
public:
  explicit VariableAddr(ASTContext &ctx, Variable *var, Location &&loc)
      : Node(ctx, std::move(loc)),
        var(var),
        var_addr_type(CreatePointer(CreateNone())) {};
  explicit VariableAddr(ASTContext &ctx,
                        const VariableAddr &other,
                        const Location &loc)
      : Node(ctx, loc + other.loc),
        var(other.var),
        var_addr_type(other.var_addr_type) {};

  const SizedType &type() const
  {
    assert(var_addr_type.IsPtrTy());
    return var_addr_type;
  }

  Variable *var = nullptr;
  // This should always be a pointer type
  SizedType var_addr_type;
};

class Binop : public Node {
public:
  explicit Binop(ASTContext &ctx,
                 Expression left,
                 Operator op,
                 Expression right,
                 Location &&loc)
      : Node(ctx, std::move(loc)),
        left(std::move(left)),
        right(std::move(right)),
        op(op) {};
  explicit Binop(ASTContext &ctx, const Binop &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        left(clone(ctx, other.left, loc)),
        right(clone(ctx, other.right, loc)),
        op(other.op),
        result_type(other.result_type) {};

  const SizedType &type() const
  {
    return result_type;
  }

  Expression left;
  Expression right;
  Operator op;
  SizedType result_type;
};

class Unop : public Node {
public:
  explicit Unop(ASTContext &ctx,
                Expression expr,
                Operator op,
                bool is_post_op,
                Location &&loc)
      : Node(ctx, std::move(loc)),
        expr(std::move(expr)),
        op(op),
        is_post_op(is_post_op) {};
  explicit Unop(ASTContext &ctx, const Unop &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        expr(clone(ctx, other.expr, loc)),
        op(other.op),
        is_post_op(other.is_post_op) {};

  const SizedType &type() const
  {
    return result_type;
  }

  Expression expr;
  Operator op;
  bool is_post_op;
  SizedType result_type;
};

class FieldAccess : public Node {
public:
  explicit FieldAccess(ASTContext &ctx,
                       Expression expr,
                       std::string field,
                       Location &&loc)
      : Node(ctx, std::move(loc)),
        expr(std::move(expr)),
        field(std::move(field)) {};
  explicit FieldAccess(ASTContext &ctx,
                       const FieldAccess &other,
                       const Location &loc)
      : Node(ctx, loc + other.loc),
        expr(clone(ctx, other.expr, loc)),
        field(other.field),
        field_type(other.field_type) {};

  const SizedType &type() const
  {
    return field_type;
  }

  Expression expr;
  std::string field;
  SizedType field_type;
};

class ArrayAccess : public Node {
public:
  explicit ArrayAccess(ASTContext &ctx,
                       Expression expr,
                       Expression indexpr,
                       Location &&loc)
      : Node(ctx, std::move(loc)),
        expr(std::move(expr)),
        indexpr(std::move(indexpr)) {};
  explicit ArrayAccess(ASTContext &ctx,
                       const ArrayAccess &other,
                       const Location &loc)
      : Node(ctx, loc + other.loc),
        expr(clone(ctx, other.expr, loc)),
        indexpr(clone(ctx, other.indexpr, loc)) {};

  const SizedType &type() const
  {
    return element_type;
  }

  Expression expr;
  Expression indexpr;
  SizedType element_type;
};

class TupleAccess : public Node {
public:
  explicit TupleAccess(ASTContext &ctx,
                       Expression expr,
                       ssize_t index,
                       Location &&loc)
      : Node(ctx, std::move(loc)), expr(std::move(expr)), index(index) {};
  explicit TupleAccess(ASTContext &ctx,
                       const TupleAccess &other,
                       const Location &loc)
      : Node(ctx, loc + other.loc),
        expr(clone(ctx, other.expr, loc)),
        index(other.index),
        element_type(other.element_type) {};

  const SizedType &type() const
  {
    return element_type;
  }

  Expression expr;
  size_t index;
  SizedType element_type;
};

class MapAccess : public Node {
public:
  explicit MapAccess(ASTContext &ctx, Map *map, Expression key, Location &&loc)
      : Node(ctx, std::move(loc)), map(map), key(std::move(key)) {};
  explicit MapAccess(ASTContext &ctx,
                     const MapAccess &other,
                     const Location &loc)
      : Node(ctx, loc + other.loc),
        map(clone(ctx, other.map, loc)),
        key(clone(ctx, other.key, loc)) {};

  const SizedType &type() const
  {
    return map->type();
  }

  Map *map = nullptr;
  Expression key;
};

class Cast : public Node {
public:
  explicit Cast(ASTContext &ctx,
                SizedType type,
                Expression expr,
                Location &&loc)
      : Node(ctx, std::move(loc)),
        cast_type(std::move(type)),
        expr(std::move(expr)) {};
  explicit Cast(ASTContext &ctx, const Cast &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        cast_type(other.cast_type),
        expr(clone(ctx, other.expr, loc)) {};

  const SizedType &type() const
  {
    return cast_type;
  }

  SizedType cast_type;
  Expression expr;
};

class Tuple : public Node {
public:
  explicit Tuple(ASTContext &ctx, ExpressionList &&elems, Location &&loc)
      : Node(ctx, std::move(loc)), elems(std::move(elems)) {};
  explicit Tuple(ASTContext &ctx, const Tuple &other, const Location &loc)
      : Node(ctx, loc + other.loc), elems(clone(ctx, other.elems, loc)) {};

  const SizedType &type() const
  {
    return tuple_type;
  }

  ExpressionList elems;
  SizedType tuple_type;
};

class ExprStatement : public Node {
public:
  explicit ExprStatement(ASTContext &ctx, Expression expr, Location &&loc)
      : Node(ctx, std::move(loc)), expr(expr) {};
  explicit ExprStatement(ASTContext &ctx,
                         const ExprStatement &other,
                         const Location &loc)
      : Node(ctx, loc + other.loc), expr(clone(ctx, other.expr, loc)) {};

  Expression expr;
};

class VarDeclStatement : public Node {
public:
  explicit VarDeclStatement(ASTContext &ctx,
                            Variable *var,
                            SizedType type,
                            Location &&loc)
      : Node(ctx, std::move(loc)), var(var), type(type) {};
  explicit VarDeclStatement(ASTContext &ctx, Variable *var, Location &&loc)
      : Node(ctx, std::move(loc)), var(var) {};
  explicit VarDeclStatement(ASTContext &ctx,
                            const VarDeclStatement &other,
                            const Location &loc)
      : Node(ctx, loc + other.loc),
        var(clone(ctx, other.var, loc)),
        type(other.type) {};

  Variable *var = nullptr;
  std::optional<SizedType> type;
};

// Scalar map assignment is purely syntactic sugar that is removed by the pass
// returned by`CreateMapSugarPass`. This is replaced by the expansion of
// default keys, so that later steps (semantic analysis, code generation),
// don't need to worry about this. Maps whose accesses are bound to a single
// key will be automatically collapsed into scalar values on the output side.
class AssignScalarMapStatement : public Node {
public:
  explicit AssignScalarMapStatement(ASTContext &ctx,
                                    Map *map,
                                    Expression expr,
                                    Location &&loc)
      : Node(ctx, std::move(loc)), map(map), expr(std::move(expr)) {};
  explicit AssignScalarMapStatement(ASTContext &ctx,
                                    const AssignScalarMapStatement &other,
                                    const Location &loc)
      : Node(ctx, loc + other.loc),
        map(clone(ctx, other.map, loc)),
        expr(clone(ctx, other.expr, loc)) {};

  Map *map = nullptr;
  Expression expr;
};

class AssignMapStatement : public Node {
public:
  explicit AssignMapStatement(ASTContext &ctx,
                              Map *map,
                              Expression key,
                              Expression expr,
                              Location &&loc)
      : Node(ctx, std::move(loc)),
        map(map),
        key(std::move(key)),
        expr(std::move(expr)) {};
  explicit AssignMapStatement(ASTContext &ctx,
                              const AssignMapStatement &other,
                              const Location &loc)
      : Node(ctx, loc + other.loc),
        map(clone(ctx, other.map, loc)),
        key(clone(ctx, other.key, loc)),
        expr(clone(ctx, other.expr, loc)) {};

  Map *map = nullptr;
  Expression key;
  Expression expr;
};

class AssignVarStatement : public Node {
public:
  explicit AssignVarStatement(ASTContext &ctx,
                              Variable *var,
                              Expression expr,
                              Location &&loc)
      : Node(ctx, std::move(loc)), var_decl(var), expr(std::move(expr)) {};
  explicit AssignVarStatement(ASTContext &ctx,
                              VarDeclStatement *var_decl_stmt,
                              Expression expr,
                              Location &&loc)
      : Node(ctx, std::move(loc)),
        var_decl(var_decl_stmt),
        expr(std::move(expr)) {};
  explicit AssignVarStatement(ASTContext &ctx,
                              const AssignVarStatement &other,
                              const Location &loc)
      : Node(ctx, loc + other.loc),
        var_decl(clone(ctx, other.var_decl, loc)),
        expr(clone(ctx, other.expr, loc)) {};

  Variable *var()
  {
    if (std::holds_alternative<VarDeclStatement *>(var_decl)) {
      return std::get<VarDeclStatement *>(var_decl)->var;
    } else {
      return std::get<Variable *>(var_decl);
    }
  }

  std::variant<VarDeclStatement *, Variable *> var_decl;
  Expression expr;
};

class AssignConfigVarStatement : public Node {
public:
  explicit AssignConfigVarStatement(ASTContext &ctx,
                                    std::string var,
                                    uint64_t value,
                                    Location &&loc)
      : Node(ctx, std::move(loc)), var(std::move(var)), value(value) {};
  explicit AssignConfigVarStatement(ASTContext &ctx,
                                    std::string var,
                                    std::string value,
                                    Location &&loc)
      : Node(ctx, std::move(loc)),
        var(std::move(var)),
        value(std::move(value)) {};
  explicit AssignConfigVarStatement(ASTContext &ctx,
                                    std::string var,
                                    bool value,
                                    Location &&loc)
      : Node(ctx, std::move(loc)), var(std::move(var)), value(value) {};
  explicit AssignConfigVarStatement(ASTContext &ctx,
                                    const AssignConfigVarStatement &other,
                                    const Location &loc)
      : Node(ctx, loc + other.loc), var(other.var), value(other.value) {};

  std::string var;
  std::variant<uint64_t, std::string, bool> value;
};
using ConfigStatementList = std::vector<AssignConfigVarStatement *>;

class Block : public Node {
public:
  explicit Block(ASTContext &ctx, StatementList &&stmts, Location &&loc)
      : Node(ctx, std::move(loc)), stmts(std::move(stmts)) {};
  explicit Block(ASTContext &ctx, const Block &other, const Location &loc)
      : Node(ctx, loc + other.loc), stmts(clone(ctx, other.stmts, loc)) {};

  const SizedType &type() const
  {
    static SizedType none = CreateNone();
    return none;
  }

  StatementList stmts;
};

class BlockExpr : public Node {
public:
  explicit BlockExpr(ASTContext &ctx,
                     StatementList &&stmts,
                     Expression expr,
                     Location &&loc)
      : Node(ctx, std::move(loc)),
        stmts(std::move(stmts)),
        expr(std::move(expr)) {};
  explicit BlockExpr(ASTContext &ctx,
                     const BlockExpr &other,
                     const Location &loc)
      : Node(ctx, loc + other.loc),
        stmts(clone(ctx, other.stmts, loc)),
        expr(clone(ctx, other.expr, loc)) {};

  const SizedType &type() const
  {
    return expr.type();
  }

  StatementList stmts;
  Expression expr;
};

class If : public Node {
public:
  explicit If(ASTContext &ctx,
              Expression cond,
              Block *if_block,
              Block *else_block,
              Location &&loc)
      : Node(ctx, std::move(loc)),
        cond(std::move(cond)),
        if_block(if_block),
        else_block(else_block) {};
  explicit If(ASTContext &ctx, const If &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        cond(clone(ctx, other.cond, loc)),
        if_block(clone(ctx, other.if_block, loc)),
        else_block(clone(ctx, other.else_block, loc)) {};

  Expression cond;
  Block *if_block = nullptr;
  Block *else_block = nullptr;
};

class Unroll : public Node {
public:
  explicit Unroll(ASTContext &ctx,
                  Expression expr,
                  Block *block,
                  Location &&loc)
      : Node(ctx, std::move(loc)), expr(std::move(expr)), block(block) {};
  explicit Unroll(ASTContext &ctx, const Unroll &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        expr(clone(ctx, other.expr, loc)),
        block(clone(ctx, other.block, loc)) {};

  Expression expr;
  Block *block = nullptr;
};

class Jump : public Node {
public:
  explicit Jump(ASTContext &ctx,
                JumpType ident,
                Expression return_value,
                Location &&loc)
      : Node(ctx, std::move(loc)),
        ident(ident),
        return_value(std::move(return_value)) {};
  explicit Jump(ASTContext &ctx, JumpType ident, Location &&loc)
      : Node(ctx, std::move(loc)), ident(ident) {};
  explicit Jump(ASTContext &ctx, const Jump &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        ident(other.ident),
        return_value(clone(ctx, other.return_value, loc)) {};

  JumpType ident = JumpType::INVALID;
  std::optional<Expression> return_value;
};

class Predicate : public Node {
public:
  explicit Predicate(ASTContext &ctx, Expression expr, Location &&loc)
      : Node(ctx, std::move(loc)), expr(std::move(expr)) {};
  explicit Predicate(ASTContext &ctx,
                     const Predicate &other,
                     const Location &loc)
      : Node(ctx, loc + other.loc), expr(clone(ctx, other.expr, loc)) {};

  Expression expr;
};

class Ternary : public Node {
public:
  explicit Ternary(ASTContext &ctx,
                   Expression cond,
                   Expression left,
                   Expression right,
                   Location &&loc)
      : Node(ctx, std::move(loc)),
        cond(std::move(cond)),
        left(std::move(left)),
        right(std::move(right)) {};
  explicit Ternary(ASTContext &ctx, const Ternary &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        cond(clone(ctx, other.cond, loc)),
        left(clone(ctx, other.left, loc)),
        right(clone(ctx, other.right, loc)),
        result_type(other.result_type) {};

  const SizedType &type() const
  {
    return result_type;
  }

  Expression cond;
  Expression left;
  Expression right;
  SizedType result_type;
};

class While : public Node {
public:
  explicit While(ASTContext &ctx, Expression cond, Block *block, Location &&loc)
      : Node(ctx, std::move(loc)), cond(cond), block(block) {};
  explicit While(ASTContext &ctx, const While &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        cond(clone(ctx, other.cond, loc)),
        block(clone(ctx, other.block, loc)) {};

  Expression cond;
  Block *block = nullptr;
};

class Range : public Node {
public:
  explicit Range(ASTContext &ctx,
                 Expression start,
                 Expression end,
                 Location &&loc)
      : Node(ctx, std::move(loc)), start(start), end(end) {};
  explicit Range(ASTContext &ctx, const Range &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        start(clone(ctx, other.start, loc)),
        end(clone(ctx, other.end, loc)) {};

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
               Variable *decl,
               Map *map,
               StatementList &&stmts,
               Location &&loc)
      : Node(ctx, std::move(loc)),
        decl(decl),
        iterable(map),
        stmts(std::move(stmts)) {};
  explicit For(ASTContext &ctx,
               Variable *decl,
               Range *range,
               StatementList &&stmts,
               Location &&loc)
      : Node(ctx, std::move(loc)),
        decl(decl),
        iterable(range),
        stmts(std::move(stmts)) {};
  explicit For(ASTContext &ctx, const For &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        decl(clone(ctx, other.decl, loc)),
        iterable(clone(ctx, other.iterable, loc)),
        stmts(clone(ctx, other.stmts, loc)) {};

  Variable *decl = nullptr;
  Iterable iterable;
  StatementList stmts;
  SizedType ctx_type;
};

class Config : public Node {
public:
  explicit Config(ASTContext &ctx, ConfigStatementList &&stmts, Location &&loc)
      : Node(ctx, std::move(loc)), stmts(std::move(stmts)) {};
  explicit Config(ASTContext &ctx, const Config &other, const Location &loc)
      : Node(ctx, loc + other.loc), stmts(clone(ctx, other.stmts, loc)) {};

  ConfigStatementList stmts;
};

class Probe;
class AttachPoint : public Node {
public:
  explicit AttachPoint(ASTContext &ctx,
                       std::string raw_input,
                       bool ignore_invalid,
                       Location &&loc)
      : Node(ctx, std::move(loc)),
        raw_input(std::move(raw_input)),
        ignore_invalid(ignore_invalid) {};
  explicit AttachPoint(ASTContext &ctx,
                       const AttachPoint &other,
                       const Location &loc)
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
        ignore_invalid(other.ignore_invalid),
        index_(other.index_) {};

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

  std::string provider;
  std::string target;
  std::string lang; // for userspace probes, enable language-specific features
  std::string ns;
  std::string func;
  std::string pin;
  usdt_probe_entry usdt; // resolved USDT entry, used to support arguments with
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

  int index() const;
  void set_index(int index);

  bool check_available(const std::string &identifier) const;

private:
  int index_ = 0;
};
using AttachPointList = std::vector<AttachPoint *>;

inline std::string probe_orig_name(AttachPointList &aps)
{
  std::vector<std::string> ap_names;
  std::ranges::transform(aps,
                         std::back_inserter(ap_names),
                         [](const AttachPoint *ap) { return ap->raw_input; });
  return util::str_join(ap_names, ",");
}

class Probe : public Node {
public:
  explicit Probe(ASTContext &ctx,
                 AttachPointList &&attach_points,
                 Predicate *pred,
                 Block *block,
                 Location &&loc)
      : Node(ctx, std::move(loc)),
        attach_points(std::move(attach_points)),
        pred(pred),
        block(block),
        orig_name(probe_orig_name(this->attach_points)) {};
  explicit Probe(ASTContext &ctx, const Probe &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        attach_points(clone(ctx, other.attach_points, loc)),
        pred(clone(ctx, other.pred, loc)),
        block(clone(ctx, other.block, loc)),
        orig_name(other.orig_name),
        index_(other.index_) {};

  AttachPointList attach_points;
  Predicate *pred = nullptr;
  Block *block = nullptr;
  std::string orig_name;

  std::string args_typename() const;

  int index() const;
  void set_index(int index);

  bool has_ap_of_probetype(ProbeType probe_type);

private:
  int index_ = 0;
};
using ProbeList = std::vector<Probe *>;

class SubprogArg : public Node {
public:
  explicit SubprogArg(ASTContext &ctx,
                      std::string name,
                      SizedType type,
                      Location &&loc)
      : Node(ctx, std::move(loc)),
        name(std::move(name)),
        type(std::move(type)) {};
  explicit SubprogArg(ASTContext &ctx,
                      const SubprogArg &other,
                      const Location &loc)
      : Node(ctx, loc + other.loc), name(other.name), type(other.type) {};

  const std::string name;
  SizedType type;
};
using SubprogArgList = std::vector<SubprogArg *>;

class Subprog : public Node {
public:
  explicit Subprog(ASTContext &ctx,
                   std::string name,
                   SizedType return_type,
                   SubprogArgList &&args,
                   StatementList &&stmts,
                   Location &&loc)
      : Node(ctx, std::move(loc)),
        name(std::move(name)),
        return_type(std::move(return_type)),
        args(std::move(args)),
        stmts(std::move(stmts)) {};
  explicit Subprog(ASTContext &ctx, const Subprog &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        name(other.name),
        return_type(other.return_type),
        args(clone(ctx, other.args, loc)),
        stmts(clone(ctx, other.stmts, loc)) {};

  const std::string name;
  SizedType return_type;
  SubprogArgList args;
  StatementList stmts;
};
using SubprogList = std::vector<Subprog *>;

class Import : public Node {
public:
  explicit Import(ASTContext &ctx, std::string name, Location &&loc)
      : Node(ctx, std::move(loc)), name(std::move(name)) {};
  explicit Import(ASTContext &ctx, const Import &other, const Location &loc)
      : Node(ctx, loc + other.loc), name(other.name) {};

  const std::string name;
};
using ImportList = std::vector<Import *>;

class Macro : public Node {
public:
  Macro(ASTContext &ctx,
        std::string name,
        ExpressionList &&vargs,
        BlockExpr *block_expr,
        Location &&loc)
      : Node(ctx, std::move(loc)),
        name(std::move(name)),
        vargs(std::move(vargs)),
        block(block_expr) {};
  Macro(ASTContext &ctx,
        std::string name,
        ExpressionList &&vargs,
        Block *block,
        Location &&loc)
      : Node(ctx, std::move(loc)),
        name(std::move(name)),
        vargs(std::move(vargs)),
        block(block) {};
  explicit Macro(ASTContext &ctx, const Macro &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        name(other.name),
        vargs(clone(ctx, other.vargs, loc)),
        block(clone(ctx, other.block, loc)) {};

  std::string name;
  ExpressionList vargs;
  std::variant<BlockExpr *, Block *> block;
};
using MacroList = std::vector<Macro *>;

class Program : public Node {
public:
  explicit Program(ASTContext &ctx,
                   std::string c_definitions,
                   Config *config,
                   ImportList &&imports,
                   RootStatements &&root_statements,
                   Location &&loc)
      : Node(ctx, std::move(loc)),
        c_definitions(std::move(c_definitions)),
        config(config),
        imports(std::move(imports))
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
  explicit Program(ASTContext &ctx, const Program &other, const Location &loc)
      : Node(ctx, loc + other.loc),
        c_definitions(other.c_definitions),
        config(clone(ctx, other.config, loc)),
        imports(clone(ctx, other.imports, loc)),
        map_decls(clone(ctx, other.map_decls, loc)),
        macros(clone(ctx, other.macros, loc)),
        functions(clone(ctx, other.functions, loc)),
        probes(clone(ctx, other.probes, loc)) {};

  std::string c_definitions;
  Config *config = nullptr;
  ImportList imports;
  MapDeclList map_decls;
  MacroList macros;
  SubprogList functions;
  ProbeList probes;

  void clear_empty_probes();
};

std::string opstr(const Binop &binop);
std::string opstr(const Unop &unop);
std::string opstr(const Jump &jump);
bool is_comparison_op(Operator op);

SizedType ident_to_record(const std::string &ident, int pointer_level = 0);
SizedType ident_to_sized_type(const std::string &ident);

} // namespace bpftrace::ast
