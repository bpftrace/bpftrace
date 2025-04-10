#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "diagnostic.h"
#include "types.h"
#include "usdt.h"

namespace bpftrace::ast {

class ASTContext;

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

// There are 2 kinds of attach point expansion:
// - full expansion  - separate LLVM function is generated for each match
// - multi expansion - one LLVM function and BPF program is generated for all
//                     matches, the list of expanded functions is attached to
//                     the BPF program using the k(u)probe.multi mechanism
// - session expansion - extension of the multi expansion when a single BPF
//                       program is shared for both the entry and the exit probe
//                       (when they are both attached to the same attach points)
//                       using the kprobe.session mechanism
enum class ExpansionType {
  NONE,
  FULL,
  MULTI,
  SESSION,
};

class Node {
public:
  Node(ASTContext &ctx, Location &&loc) : ctx_(ctx), loc(loc) {};
  virtual ~Node() = default;

  Node(const Node &) = delete;
  Node &operator=(const Node &) = delete;
  Node(Node &&) = delete;
  Node &operator=(Node &&) = delete;

  Diagnostic &addError() const;
  Diagnostic &addWarning() const;

private:
  ASTContext &ctx_;

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

  const Location &loc() const
  {
    return std::visit([](const auto *v) -> const Location & { return v->loc; },
                      value);
  }

  std::variant<Ts *...> value;
};

class Integer;
class NegativeInteger;
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
class Binop;
class Unop;
class FieldAccess;
class ArrayAccess;
class TupleAccess;
class MapAccess;
class Cast;
class Tuple;
class Ternary;
class Block;

class Expression : public VariantNode<Integer,
                                      NegativeInteger,
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
                                      Binop,
                                      Unop,
                                      FieldAccess,
                                      ArrayAccess,
                                      TupleAccess,
                                      MapAccess,
                                      Cast,
                                      Tuple,
                                      Ternary,
                                      Block> {
public:
  using VariantNode::VariantNode;
  Expression() : Expression(static_cast<Block *>(nullptr)) {};

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

class Statement : public VariantNode<ExprStatement,
                                     VarDeclStatement,
                                     AssignScalarMapStatement,
                                     AssignMapStatement,
                                     AssignVarStatement,
                                     If,
                                     Unroll,
                                     Jump,
                                     While,
                                     For> {
public:
  using VariantNode::VariantNode;
  Statement() : Statement(static_cast<ExprStatement *>(nullptr)) {};
};
using StatementList = std::vector<Statement>;

class Integer : public Node {
public:
  explicit Integer(ASTContext &ctx, int64_t n, Location &&loc)
      : Node(ctx, std::move(loc)), value(n) {};

  const SizedType &type() const
  {
    static SizedType uint64 = CreateUInt64();
    return uint64;
  }

  const uint64_t value;
};

class NegativeInteger : public Node {
public:
  explicit NegativeInteger(ASTContext &ctx, int64_t n, Location &&loc)
      : Node(ctx, std::move(loc)), value(n) {};

  const SizedType &type() const
  {
    static SizedType int64 = CreateInt64();
    return int64;
  }

  const int64_t value;
};

class PositionalParameter : public Node {
public:
  explicit PositionalParameter(ASTContext &ctx, long n, Location &&loc)
      : Node(ctx, std::move(loc)), n(n) {};

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
        string_type(CreateString(str.size() + 1)) {};

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

  const SizedType &type() const
  {
    return builtin_type;
  }

  // Check if the builtin is 'arg0' - 'arg9'
  bool is_argx() const
  {
    return !ident.compare(0, 3, "arg") && ident.size() == 4 &&
           ident.at(3) >= '0' && ident.at(3) <= '9';
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
};

class Sizeof : public Node {
public:
  explicit Sizeof(ASTContext &ctx, SizedType type, Location &&loc)
      : Node(ctx, std::move(loc)), record(type) {};
  explicit Sizeof(ASTContext &ctx, Expression expr, Location &&loc)
      : Node(ctx, std::move(loc)), record(expr) {};

  const SizedType &type() const
  {
    if (std::holds_alternative<Expression>(record)) {
      return std::get<Expression>(record).type();
    } else {
      return std::get<SizedType>(record);
    }
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

  const SizedType &type() const
  {
    if (std::holds_alternative<Expression>(record)) {
      return std::get<Expression>(record).type();
    } else {
      return std::get<SizedType>(record);
    }
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

  const std::string ident;
  const std::string bpf_type;
  const int max_entries;
};
using MapDeclList = std::vector<MapDeclStatement *>;

class Map : public Node {
public:
  explicit Map(ASTContext &ctx, std::string ident, Location &&loc)
      : Node(ctx, std::move(loc)), ident(std::move(ident)) {};

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

  const SizedType &type() const
  {
    return var_type;
  }

  std::string ident;
  SizedType var_type;
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

  const SizedType &type() const
  {
    return element_type;
  }

  Expression expr;
  ssize_t index;
  SizedType element_type;
};

class MapAccess : public Node {
public:
  explicit MapAccess(ASTContext &ctx, Map *map, Expression key, Location &&loc)
      : Node(ctx, std::move(loc)), map(map), key(std::move(key)) {};

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

  Variable *var = nullptr;
  std::optional<SizedType> type;
};

// Scalar map assignment is purely a syntax sugar that is removed by the pass
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

  std::string var;
  std::variant<uint64_t, std::string> value;
};
using ConfigStatementList = std::vector<AssignConfigVarStatement *>;

class Block : public Node {
public:
  explicit Block(ASTContext &ctx, StatementList &&stmts, Location &&loc)
      : Node(ctx, std::move(loc)), stmts(std::move(stmts)) {};
  explicit Block(ASTContext &ctx,
                 StatementList &&stmts,
                 Expression expr,
                 Location &&loc)
      : Node(ctx, std::move(loc)),
        stmts(std::move(stmts)),
        expr(std::move(expr)) {};

  static const SizedType &none_type()
  {
    static SizedType none = CreateNone();
    return none;
  }
  const SizedType &type() const
  {
    return expr.has_value() ? expr->type() : none_type();
  }

  StatementList stmts;
  // Depending on how it is parsed, a block can also be evaluated as an
  // expression. This follows all other statements in the block.
  std::optional<Expression> expr;
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

  JumpType ident = JumpType::INVALID;
  std::optional<Expression> return_value;
};

class Predicate : public Node {
public:
  explicit Predicate(ASTContext &ctx, Expression expr, Location &&loc)
      : Node(ctx, std::move(loc)), expr(std::move(expr)) {};

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

  Expression cond;
  Block *block = nullptr;
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
        map(map),
        stmts(std::move(stmts)) {};

  Variable *decl = nullptr;
  Map *map = nullptr;
  StatementList stmts;
  SizedType ctx_type;
};

class Config : public Node {
public:
  explicit Config(ASTContext &ctx, ConfigStatementList &&stmts, Location &&loc)
      : Node(ctx, std::move(loc)), stmts(std::move(stmts)) {};

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

  // Currently, the AST node itself is used to store metadata related to probe
  // expansion and attachment. This is done through `create_expansion_copy`
  // below.  Since the nodes are not currently copyable by default (this is
  // currently fraught, as nodes may have backreferences that are not updated
  // in these cases), these fields are copied manually. *Until this is fixed,
  // if you are adding new fields, be sure to update `create_expansion_copy`.

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

  ExpansionType expansion = ExpansionType::NONE;
  Probe *ret_probe = nullptr; // for session probes

  uint64_t address = 0;
  uint64_t func_offset = 0;
  bool ignore_invalid = false;

  std::string name() const;

  AttachPoint &create_expansion_copy(ASTContext &ctx,
                                     const std::string &match) const;

  int index() const;
  void set_index(int index);

private:
  int index_ = 0;
};
using AttachPointList = std::vector<AttachPoint *>;

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
        block(block) {};

  AttachPointList attach_points;
  Predicate *pred = nullptr;
  Block *block = nullptr;

  std::string name() const;
  std::string args_typename() const;
  bool need_expansion = false;    // must build a BPF program per wildcard match
  int tp_args_structs_level = -1; // number of levels of structs that must
                                  // be imported/resolved for tracepoints

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

  const std::string name;
};
using ImportList = std::vector<Import *>;

class Program : public Node {
public:
  explicit Program(ASTContext &ctx,
                   std::string c_definitions,
                   Config *config,
                   ImportList &&imports,
                   MapDeclList &&map_decls,
                   SubprogList &&functions,
                   ProbeList &&probes,
                   Location &&loc)
      : Node(ctx, std::move(loc)),
        c_definitions(std::move(c_definitions)),
        config(config),
        imports(std::move(imports)),
        map_decls(std::move(map_decls)),
        functions(std::move(functions)),
        probes(std::move(probes)) {};

  std::string c_definitions;
  Config *config = nullptr;
  ImportList imports;
  MapDeclList map_decls;
  SubprogList functions;
  ProbeList probes;
};

std::string opstr(const Binop &binop);
std::string opstr(const Unop &unop);
std::string opstr(const Jump &jump);

SizedType ident_to_record(const std::string &ident, int pointer_level = 0);
SizedType ident_to_sized_type(const std::string &ident);

} // namespace bpftrace::ast
