#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "diagnostic.h"
#include "types.h"
#include "usdt.h"
#include "utils.h"

namespace bpftrace {
namespace ast {

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
enum class ExpansionType {
  NONE,
  FULL,
  MULTI,
};

class Node {
public:
  Node(Diagnostics &d, location &&loc)
      : diagnostics_(d), loc_(std::move(loc)) {};
  Node(const Node &) = delete;
  Node &operator=(const Node &) = delete;
  Node(Node &&) = delete;
  Node &operator=(Node &&) = delete;

  template <typename... Args>
  Diagnostic &addError(Args &...args) const
  {
    if constexpr (sizeof...(Args) == 0) {
      return diagnostics_.addError(loc_);
    } else {
      return diagnostics_.addError(loc_ + (args.loc_ + ...));
    }
  }
  template <typename... Args>
  Diagnostic &addWarning(Args &...args) const
  {
    if constexpr (sizeof...(Args) == 0) {
      return diagnostics_.addWarning(loc_);
    } else {
      return diagnostics_.addWarning(loc_ + (args.loc_ + ...));
    }
  }

  const location& loc() const { return loc_; };
private:
  Diagnostics &diagnostics_;
  const location loc_;
};

template <typename... Ts>
class VirtualNode {
public:
  // For simplicity, allow virtual nodes to be default constructible and
  // effectively hold no specific type.
  using variant_t = std::variant<std::monostate, std::reference_wrapper<Ts>...>;
  VirtualNode(variant_t value) : value_(std::move(value)) {};
  VirtualNode() = default;

  template <typename T>
  bool is() const
  {
    return std::holds_alternative<std::reference_wrapper<T>>(value_);
  }

  template <typename T>
  T &as() const
  {
    return std::get<std::reference_wrapper<T>>(value_);
  }

  // Returns the type erased reference, which can be used to extract the
  // location, add diagnostics, etc.
  Node &node() const
  {
    return std::apply([](auto &v) -> Node & { return v; });
  }

  // Returns the type-rich variant, which is used to walk, etc.
  variant_t &value()
  {
    return value_;
  }

private:
  variant_t value_;
};

class Integer;
class PositionalParameter;
class String;
class StackMode;
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
class Cast;
class Tuple;
class Ternary;

class Expression : public VirtualNode<Integer,
                                      PositionalParameter,
                                      String,
                                      StackMode,
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
                                      Cast,
                                      Tuple,
                                      Ternary> {
public:
  Expression() = default;
  Expression(variant_t &&value) : VirtualNode(std::move(value))
  {
    is_literal = is<Integer>() || is<String>() || is<StackMode>();
  }

  // Record whether this is literal is not. In the future this could be
  // statically determined, but for now this is set based on certain positional
  // parameter configurations.
  bool is_literal;

  // All expressions have a type associated with them. This type may be
  // determined by the expression directly. If it is not known, then this will
  // be `NoneType`. In the future, this could be determined dynamically by the
  // underlying objects, but for now this preserve existing behavior.
  SizedType type;
};
using ExpressionList = std::vector<Expression>;

class Integer : public Node {
public:
  explicit Integer(Diagnostics &d,
                   int64_t n,
                   location loc,
                   bool is_negative = true)
      : Node(d, std::move(loc)), n(n), is_negative(is_negative) {};
  operator Expression()
  {
    return Expression(*this);
  };

  int64_t n;
  bool is_negative;
};

class PositionalParameter : public Node {
public:
  explicit PositionalParameter(Diagnostics &d,
                               PositionalParameterType ptype,
                               long n,
                               location loc)
      : Node(d, std::move(loc)), ptype(ptype), n(n) {};
  operator Expression()
  {
    return Expression(*this);
  };

  PositionalParameterType ptype;
  long n;
  bool is_in_str = false;
};

class String : public Node {
public:
  explicit String(Diagnostics &d, const std::string &str, location loc)
      : Node(d, std::move(loc)), str(str) {};
  operator Expression()
  {
    return Expression(*this);
  };

  std::string str;
};

class StackMode : public Node {
public:
  explicit StackMode(Diagnostics &d, const std::string &mode, location loc)
      : Node(d, std::move(loc)), mode(mode) {};
  operator Expression()
  {
    return Expression(*this);
  };

  std::string mode;
};

class Identifier : public Node {
public:
  explicit Identifier(Diagnostics &d, const std::string &ident, location loc)
      : Node(d, std::move(loc)), ident(ident) {};
  operator Expression()
  {
    return Expression(*this);
  };

  std::string ident;
};

class Builtin : public Node {
public:
  explicit Builtin(Diagnostics &d, const std::string &ident, location loc)
      : Node(d, std::move(loc)), ident(is_deprecated(ident)) {};
  operator Expression()
  {
    return Expression(*this);
  };

  std::string ident;
  int probe_id;

  // Check if the builtin is 'arg0' - 'arg9'
  bool is_argx() const
  {
    return !ident.compare(0, 3, "arg") && ident.size() == 4 &&
           ident.at(3) >= '0' && ident.at(3) <= '9';
  }
};

class Call : public Node {
public:
  explicit Call(Diagnostics &d, const std::string &func, location loc)
      : Node(d, std::move(loc)), func(is_deprecated(func)) {};
  explicit Call(Diagnostics &d,
                const std::string &func,
                ExpressionList &&vargs,
                location loc)
      : Node(d, std::move(loc)),
        func(is_deprecated(func)),
        vargs(std::move(vargs)) {};
  operator Expression()
  {
    return Expression(*this);
  };

  std::string func;
  ExpressionList vargs;
};

class Sizeof : public Node {
public:
  explicit Sizeof(Diagnostics &d, SizedType type, location loc)
      : Node(d, std::move(loc)),
        expr(std::in_place_index<0>, std::move(type)) {};
  explicit Sizeof(Diagnostics &d, Expression expr, location loc)
      : Node(d, std::move(loc)),
        expr(std::in_place_index<1>, std::move(expr)) {};
  operator Expression()
  {
    return Expression(*this);
  };

  std::variant<SizedType, Expression> expr;
};

class Offsetof : public Node {
public:
  explicit Offsetof(Diagnostics &d,
                    SizedType record,
                    std::vector<std::string> &&field,
                    location loc)
      : Node(d, std::move(loc)), record(record), field(std::move(field)) {};
  explicit Offsetof(Diagnostics &d,
                    Expression expr,
                    std::vector<std::string> &&field,
                    location loc)
      : Node(d, std::move(loc)), expr(std::move(expr)), field(std::move(field)) {};
  operator Expression()
  {
    return Expression(*this);
  };

  std::optional<SizedType> record;
  std::optional<Expression> expr;
  std::vector<std::string> field;
};

class Map : public Node {
public:
  explicit Map(Diagnostics &d, const std::string &ident, location loc)
      : Node(d, std::move(loc)), ident(ident) {};
  explicit Map(Diagnostics &d,
               const std::string &ident,
               Expression key_expr,
               location loc)
      : Node(d, std::move(loc)), ident(ident), key_expr(std::move(key_expr)) {};
  operator Expression()
  {
    return Expression(*this);
  };

  std::string ident;
  std::optional<Expression> key_expr;
  SizedType key_type;
  bool skip_key_validation = false;
  // This is for a feature check on reading per-cpu maps
  // which involve calling map_lookup_percpu_elem
  // https://github.com/bpftrace/bpftrace/issues/3755
  bool is_read = true;
};

class Variable : public Node {
public:
  explicit Variable(Diagnostics &d, const std::string &ident, location loc)
      : Node(d, std::move(loc)), ident(ident) {};
  operator Expression()
  {
    return Expression(*this);
  };

  std::string ident;
};

class Binop : public Node {
public:
  explicit Binop(Diagnostics &d,
                 Expression left,
                 Operator op,
                 Expression right,
                 location loc)
      : Node(d, std::move(loc)),
        left(std::move(left)),
        right(std::move(right)),
        op(op) {};
  operator Expression()
  {
    return Expression(*this);
  };

  Expression left;
  Expression right;
  Operator op;
};

class Unop : public Node {
public:
  explicit Unop(Diagnostics &d,
                Operator op,
                Expression expr,
                bool is_post_op,
                location loc)
      : Node(d, std::move(loc)),
        expr(std::move(expr)),
        op(op),
        is_post_op(is_post_op) {};
  operator Expression()
  {
    return Expression(*this);
  };

  Expression expr;
  Operator op;
  bool is_post_op;
};

class FieldAccess : public Node {
public:
  explicit FieldAccess(Diagnostics &d,
                       Expression expr,
                       const std::string &field,
                       location loc)
      : Node(d, std::move(loc)), expr(std::move(expr)), field(field)
  {
  }
  explicit FieldAccess(Diagnostics &d,
                       Expression expr,
                       ssize_t index,
                       location loc)
      : Node(d, std::move(loc)), expr(std::move(expr)), index(index)
  {
  }
  operator Expression()
  {
    return Expression(*this);
  };

  Expression expr;
  std::optional<std::string> field;
  std::optional<ssize_t> index;
};

class ArrayAccess : public Node {
public:
  explicit ArrayAccess(Diagnostics &d,
                       Expression expr,
                       Expression indexpr,
                       location loc)
      : Node(d, std::move(loc)),
        expr(std::move(expr)),
        indexpr(std::move(indexpr)) {};
  operator Expression()
  {
    return Expression(*this);
  };

  Expression expr;
  Expression indexpr;
};

class Cast : public Node {
public:
  explicit Cast(Diagnostics &d, SizedType type, Expression expr, location loc)
      : Node(d, std::move(loc)), type(type), expr(std::move(expr)) {};
  operator Expression()
  {
    return Expression(*this);
  };

  SizedType type;
  Expression expr;
};

class Tuple : public Node {
public:
  explicit Tuple(Diagnostics &d, ExpressionList &&elems, location loc)
      : Node(d, std::move(loc)), elems(std::move(elems)) {};
  operator Expression()
  {
    return Expression(*this);
  };

  ExpressionList elems;
};

class ExprStatement;
class VarDeclStatement;
class AssignMapStatement;
class AssignVarStatement;
class AssignConfigVarStatement;
class Block;
class If;
class Unroll;
class Jump;
class While;
class For;
class Config;

class Statement : public VirtualNode<ExprStatement,
                                     VarDeclStatement,
                                     AssignMapStatement,
                                     AssignVarStatement,
                                     AssignConfigVarStatement,
                                     Block,
                                     If,
                                     Unroll,
                                     Jump,
                                     While,
                                     For,
                                     Config> {
public:
  Statement() = default;
  Statement(variant_t &&value) : VirtualNode(std::move(value)) {};
};
using StatementList = std::vector<Statement>;

class ExprStatement : public Node {
public:
  explicit ExprStatement(Diagnostics &d, Expression expr, location loc)
      : Node(d, std::move(loc)), expr(std::move(expr)) {};
  operator Statement()
  {
    return Statement(*this);
  };

  Expression expr;
};

class VarDeclStatement : public Node {
public:
  explicit VarDeclStatement(Diagnostics &d,
                            Variable &var,
                            SizedType type,
                            location loc)
      : Node(d, std::move(loc)), var(var), type(std::move(type)) {};
  explicit VarDeclStatement(Diagnostics &d, Variable &var, location loc)
      : Node(d, std::move(loc)), var(var) {};
  operator Statement()
  {
    return Statement(*this);
  };

  Variable &var;
  std::optional<SizedType> type;
};

class AssignMapStatement : public Node {
public:
  explicit AssignMapStatement(Diagnostics &d,
                              Map &map,
                              Expression expr,
                              location loc)
      : Node(d, std::move(loc)), map(map), expr(std::move(expr)) {};
  operator Statement()
  {
    return Statement(*this);
  };

  Map &map;
  Expression expr;
};

class AssignVarStatement : public Node {
public:
  explicit AssignVarStatement(Diagnostics &d,
                              Variable &var,
                              Expression expr,
                              location loc)
      : Node(d, std::move(loc)), var(var), expr(std::move(expr)) {};
  explicit AssignVarStatement(Diagnostics &d,
                              VarDeclStatement &var_decl_stmt,
                              Expression expr,
                              location loc)
      : Node(d, std::move(loc)),
        var_decl_stmt(var_decl_stmt),
        var(var_decl_stmt.var),
        expr(std::move(expr)) {};
  operator Statement()
  {
    return Statement(*this);
  };

  std::optional<std::reference_wrapper<VarDeclStatement>> var_decl_stmt;
  std::reference_wrapper<Variable> var;
  Expression expr;
};

class AssignConfigVarStatement : public Node {
public:
  explicit AssignConfigVarStatement(Diagnostics &d,
                                    const std::string &config_var,
                                    Expression expr,
                                    location loc)
      : Node(d, std::move(loc)),
        config_var(config_var),
        expr(std::move(expr)) {};
  operator Statement()
  {
    return Statement(*this);
  };

  std::string config_var;
  Expression expr;
};

class Block : public Node {
public:
  explicit Block(Diagnostics &d, StatementList &&stmts, location loc)
      : Node(d, std::move(loc)), stmts(std::move(stmts)) {};

  StatementList stmts;
};

class If : public Node {
public:
  explicit If(Diagnostics &d,
              Expression cond,
              Block &if_block,
              Block &else_block,
              location loc)
      : Node(d, std::move(loc)),
        cond(cond),
        if_block(if_block),
        else_block(std::ref(else_block)) {};
  explicit If(Diagnostics &d, Expression cond, Block &if_block, location loc)
      : Node(d, std::move(loc)), cond(cond), if_block(if_block) {};
  operator Statement()
  {
    return Statement(*this);
  };

  Expression cond;
  Block &if_block;
  std::optional<std::reference_wrapper<Block>> else_block;
};

class Unroll : public Node {
public:
  explicit Unroll(Diagnostics &d, Expression expr, Block &block, location loc)
      : Node(d, std::move(loc)), expr(std::move(expr)), block(block) {};
  operator Statement()
  {
    return Statement(*this);
  };

  long int var = 0;
  Expression expr;
  Block &block;
};

class Jump : public Node {
public:
  explicit Jump(Diagnostics &d,
                JumpType ident,
                Expression return_value,
                location loc)
      : Node(d, std::move(loc)),
        ident(ident),
        return_value(std::move(return_value)) {};
  explicit Jump(Diagnostics &d, JumpType ident, location loc)
      : Node(d, std::move(loc)), ident(ident) {};
  operator Statement()
  {
    return Statement(*this);
  };

  JumpType ident;
  std::optional<Expression> return_value;
};

class Predicate : public Node {
public:
  explicit Predicate(Diagnostics &d, Expression expr, location loc)
      : Node(d, std::move(loc)), expr(std::move(expr)) {};

  Expression expr;
};

class Ternary : public Node {
public:
  explicit Ternary(Diagnostics &d,
                   Expression cond,
                   Expression left,
                   Expression right,
                   location loc)
      : Node(d, std::move(loc)),
        cond(std::move(cond)),
        left(std::move(left)),
        right(std::move(right)) {};
  operator Expression()
  {
    return Expression(*this);
  };

  Expression cond;
  Expression left;
  Expression right;
};

class While : public Node {
public:
  explicit While(Diagnostics &d, Expression cond, Block &block, location loc)
      : Node(d, std::move(loc)), cond(std::move(cond)), block(block) {};
  operator Statement()
  {
    return Statement(*this);
  };

  Expression cond;
  Block &block;
};

class For : public Node {
public:
  explicit For(Diagnostics &d,
               Variable &decl,
               Expression expr,
               StatementList &&stmts,
               location loc)
      : Node(d, std::move(loc)),
        decl(decl),
        expr(expr),
        stmts(std::move(stmts)) {};
  operator Statement()
  {
    return Statement(*this);
  };

  Variable &decl;
  Expression expr;
  StatementList stmts;
  SizedType ctx_type;
};

class Config : public Node {
public:
  explicit Config(Diagnostics &d, StatementList &&stmts, location loc)
      : Node(d, std::move(loc)), stmts(std::move(stmts)) {};

  StatementList stmts;
};

class AttachPoint : public Node {
public:
  explicit AttachPoint(Diagnostics &d,
                       const std::string &raw_input,
                       bool ignore_invalid,
                       location loc)
      : Node(d, std::move(loc)),
        raw_input(raw_input),
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
using AttachPointList = std::vector<std::reference_wrapper<AttachPoint>>;

class Probe : public Node {
public:
  explicit Probe(Diagnostics &d,
                 AttachPointList &&attach_points,
                 std::optional<std::reference_wrapper<Predicate>> pred,
                 std::optional<std::reference_wrapper<Block>> block,
                 location loc)
      : Node(d, std::move(loc)),
        attach_points(std::move(attach_points)),
        pred(pred),
        block(block) {};

  AttachPointList attach_points;
  std::optional<std::reference_wrapper<Predicate>> pred;
  std::optional<std::reference_wrapper<Block>> block;

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
using ProbeList = std::vector<std::reference_wrapper<Probe>>;

class SubprogArg : public Node {
public:
  explicit SubprogArg(Diagnostics &d,
                      const std::string &name,
                      SizedType type,
                      location loc)
      : Node(d, std::move(loc)), name(name), type(std::move(type)) {};

  const std::string name;
  SizedType type;
};
using SubprogArgList = std::vector<std::reference_wrapper<SubprogArg>>;

class Subprog : public Node {
public:
  Subprog(Diagnostics &d,
          const std::string &name,
          SubprogArgList &&args,
          SizedType return_type,
          StatementList &&stmts,
          location loc)
      : Node(d, std::move(loc)),
        name(name),
        args(std::move(args)),
        return_type(std::move(return_type)),
        stmts(std::move(stmts)) {};

  const std::string name;
  SubprogArgList args;
  SizedType return_type;
  StatementList stmts;
};
using SubprogList = std::vector<std::reference_wrapper<Subprog>>;

class Program : public Node {
public:
  explicit Program(Diagnostics &d,
                   const std::string &c_definitions,
                   std::optional<std::reference_wrapper<Config>> config,
                   SubprogList &&functions,
                   ProbeList &&probes,
                   location loc)
      : Node(d, std::move(loc)),
        c_definitions(c_definitions),
        config(config),
        functions(std::move(functions)),
        probes(std::move(probes)) {};

  std::string c_definitions;
  std::optional<std::reference_wrapper<Config>> config;
  SubprogList functions;
  ProbeList probes;
};

std::string opstr(const Binop &binop);
std::string opstr(const Unop &unop);
std::string opstr(const Jump &jump);

SizedType ident_to_record(const std::string &ident, int pointer_level = 0);
SizedType ident_to_sized_type(const std::string &ident);

} // namespace ast
} // namespace bpftrace
