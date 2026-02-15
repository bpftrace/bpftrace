#include "ast/passes/type_graph.h"
#include "ast/ast.h"
#include "ast/async_event_types.h"
#include "ast/passes/cast_creator.h"
#include "ast/passes/clang_parser.h"
#include "ast/passes/fold_literals.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/type_system.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "btf/compat.h"
#include "collect_nodes.h"
#include "config.h"
#include "config_parser.h"
#include "log.h"
#include "probe_types.h"
#include "struct.h"
#include "types.h"

#include <algorithm>
#include <arpa/inet.h>
#include <functional>
#include <queue>

// Notes:
// begin { $a = 0; $a = (uint64)1; }
// 0 is resolved
// assignment assigns uint8 to the scoped var
// two $a Variable nodes are subscribed to this scoped var
// they both update their nodes to uint8
// uint64 is resolved
// 2nd assignment assigns uint64 to the scoped var
// both subscribed $a nodes update to uint64

namespace bpftrace::ast {

namespace {

static std::unordered_set<std::string> VOID_RETURNING_FUNCS = {
  "join", "printf", "errorf", "warnf", "system", "cat",     "debugf",
  "exit", "print",  "clear",  "zero",  "time",   "unwatch", "fail"
};

static std::unordered_map<std::string, SizedType (*)()> SIMPLE_BUILTIN_TYPES = {
  { "pid", CreateUInt32 },
  { "tid", CreateUInt32 },
  { "nsecs", CreateUInt64 },
  { "__builtin_elapsed", CreateUInt64 },
  { "__builtin_cgroup", CreateUInt64 },
  { "__builtin_uid", CreateUInt64 },
  { "__builtin_gid", CreateUInt64 },
  { "__builtin_cpu", CreateUInt64 },
  { "__builtin_rand", CreateUInt64 },
  { "__builtin_jiffies", CreateUInt64 },
  { "__builtin_ncpus", CreateUInt64 },
  { "__builtin_username", CreateUsername },
  { "__builtin_usermode", CreateUInt8 },
  { "__builtin_cpid", CreateUInt64 },
};

static std::unordered_map<std::string, SizedType (*)()> SIMPLE_CALL_TYPES = {
  { "ksym", CreateKSym },          { "usym", CreateUSym },
  { "cgroupid", CreateUInt64 },    { "cgroup_path", CreateCgroupPath },
  { "stack_len", CreateInt64 },    { "strftime", CreateTimestamp },
  { "macaddr", CreateMacAddress }, { "skboutput", CreateUInt32 },
  { "strncmp", CreateUInt64 },     { "socket_cookie", CreateUInt64 },
};

static const std::unordered_map<Type, std::string_view> AGGREGATE_HINTS{
  { Type::count_t, "count()" },
  { Type::sum_t, "sum(retval)" },
  { Type::min_t, "min(retval)" },
  { Type::max_t, "max(retval)" },
  { Type::avg_t, "avg(retval)" },
  { Type::hist_t, "hist(retval)" },
  { Type::lhist_t, "lhist(rand %10, 0, 10, 1)" },
  { Type::tseries_t, "tseries(rand %10, 10s, 1)" },
  { Type::stats_t, "stats(arg2)" },
};

AddrSpace find_addrspace(ProbeType pt)
{
  switch (pt) {
    case ProbeType::kprobe:
    case ProbeType::kretprobe:
    case ProbeType::fentry:
    case ProbeType::fexit:
    case ProbeType::tracepoint:
    case ProbeType::iter:
    case ProbeType::rawtracepoint:
      return AddrSpace::kernel;
    case ProbeType::uprobe:
    case ProbeType::uretprobe:
    case ProbeType::usdt:
      return AddrSpace::user;
    case ProbeType::invalid:
    case ProbeType::special:
    case ProbeType::test:
    case ProbeType::benchmark:
    case ProbeType::profile:
    case ProbeType::interval:
    case ProbeType::software:
    case ProbeType::hardware:
    case ProbeType::watchpoint:
      return AddrSpace::none;
  }
  return {}; // unreached
}

template <class... Ts>
struct overloaded : Ts... {
  using Ts::operator()...;
};

using ScopedVariable = std::pair<Node *, std::string>;
using GraphNode = std::variant<Node *, Typeof *, ScopedVariable, std::string>;

struct MapType {
  SizedType key_type;
  SizedType value_type;
};

struct Consumer {
  GraphNode node;
  std::function<std::optional<SizedType>(SizedType)> callback;
  std::optional<SizedType> last_propagated;

  Consumer(GraphNode node,
           std::function<std::optional<SizedType>(SizedType)> callback)
      : node(std::move(node)), callback(std::move(callback))
  {
  }
};

struct ScopedVariableHash {
  std::size_t operator()(const ScopedVariable &sv) const
  {
    auto h1 = std::hash<Node *>{}(sv.first);
    auto h2 = std::hash<std::string>{}(sv.second);
    return h1 ^ (h2 << 1);
  }
};

struct GraphNodeHash {
  std::size_t operator()(const GraphNode &gn) const
  {
    return std::visit(
        [](const auto &val) -> std::size_t {
          using T = std::decay_t<decltype(val)>;
          if constexpr (std::is_same_v<T, Node *>) {
            return std::hash<Node *>{}(val);
          } else if constexpr (std::is_same_v<T, Typeof *>) {
            return std::hash<Typeof *>{}(val);
          } else if constexpr (std::is_same_v<T, std::string>) {
            return std::hash<std::string>{}(val);
          } else {
            return ScopedVariableHash{}(val);
          }
        },
        gn);
  }
};

using LockedNodes = std::unordered_map<GraphNode, SizedType, GraphNodeHash>;

std::string get_map_value_name(const std::string &ident)
{
  return ident + "__val";
}

std::string get_map_key_name(const std::string &ident)
{
  return ident + "__key";
}

class TypeGraph : public Visitor<TypeGraph> {
public:
  explicit TypeGraph(ASTContext &ast,
                     BPFtrace &bpftrace,
                     MapMetadata &map_metadata,
                     CDefinitions &c_definitions,
                     TypeMetadata &type_metadata,
                     const MacroRegistry &macro_registry,
                     LockedNodes locked_nodes = {})
      : ast_(ast),
        bpftrace_(bpftrace),
        map_metadata_(map_metadata),
        c_definitions_(c_definitions),
        type_metadata_(type_metadata),
        macro_registry_(macro_registry),
        locked_nodes_(std::move(locked_nodes))
  {
  }

  using Visitor<TypeGraph>::visit;
  void visit(ArrayAccess &arr);
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(Binop &binop);
  void visit(BlockExpr &block);
  void visit(Boolean &boolean);
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(Cast &cast);
  void visit(Comptime &comptime);
  void visit(ExprStatement &expr);
  void visit(FieldAccess &acc);
  void visit(For &f);
  void visit(Identifier &identifier);
  void visit(IfExpr &if_expr);
  void visit(Integer &integer);
  void visit(Jump &jump);
  void visit(Map &map);
  void visit(MapAccess &acc);
  void visit(MapAddr &map_addr);
  void visit(NegativeInteger &integer);
  void visit(Offsetof &offof);
  void visit(Probe &probe);
  void visit(Record &record);
  void visit(Sizeof &szof);
  void visit(String &str);
  void visit(Subprog &subprog);
  void visit(Tuple &tuple);
  void visit(TupleAccess &acc);
  void visit(Typeof &typeof);
  void visit(Typeinfo &typeinfo);
  void visit(Unop &unop);
  void visit(VarDeclStatement &decl);
  void visit(Variable &var);
  void visit(VariableAddr &var_addr);

  bool resolve();
  LockedNodes get_locked_nodes();

  const auto &get_resolved_types() const
  {
    return resolved_types_;
  }

  const std::vector<Comptime *> &get_unresolved_comptimes() const
  {
    return unresolved_comptimes_;
  }

  bool needs_rerun() const
  {
    return needs_rerun_;
  }

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
  MapMetadata &map_metadata_;
  CDefinitions &c_definitions_;
  TypeMetadata &type_metadata_;
  const MacroRegistry &macro_registry_;
  const LockedNodes locked_nodes_;
  bool needs_rerun_ = false;
  std::queue<std::pair<GraphNode, SizedType>> queue_;
  std::unordered_map<GraphNode, std::vector<Consumer>, GraphNodeHash> graph_;
  std::unordered_map<Node *, std::unordered_map<std::string, SizedType>>
      variables_;
  std::map<Node *, CollectNodes<Variable>> for_vars_referenced_;
  // These are variables that have a declaration with a type with a SIZE
  // let $a: uint16; // type with a size
  // let $a; // no type no size
  // let $a: string // type but no size
  std::unordered_set<ScopedVariable, ScopedVariableHash> decl_variables_;
  std::unordered_map<std::string, MapType> maps_;
  // At the moment we iterate over the stack from top to
  // bottom as variable shadowing is not supported.
  std::vector<Node *> scope_stack_;
  Node *top_level_node_ = nullptr;
  std::string func_; // tracks Call context for Identifier resolution
  int introspection_level_ = 0;
  std::unordered_set<GraphNode, GraphNodeHash> introspected_nodes_;

  std::vector<Comptime *> unresolved_comptimes_;
  // Tracks the "source" of pointer types (the variable/map being addressed).
  // Key: the ScopedVariable or map value/key holding the pointer Value (the
  // variable/map being addressed - the source).
  std::unordered_map<GraphNode, GraphNode, GraphNodeHash> pointer_sources_;

  std::unordered_map<GraphNode, SizedType, GraphNodeHash> resolved_types_;

  bool resolve_struct_type(SizedType &type, Node &node);
  bool check_offsetof_type(Offsetof &offof, SizedType cstruct);

  SizedType get_resolved_type(const GraphNode &node) const
  {
    auto it = resolved_types_.find(node);
    return it != resolved_types_.end() ? it->second : CreateNone();
  }
  std::optional<SizedType> get_variable_type(
      const ScopedVariable &scoped_var,
      const SizedType &type,
      Node &error_node,
      std::optional<GraphNode> ptr_source = std::nullopt);
  std::optional<SizedType> get_map_value(
      const std::string map_name,
      const SizedType &type,
      Node &error_node,
      std::optional<GraphNode> ptr_source = std::nullopt);
  std::optional<SizedType> get_agg_map_value(const std::string map_name,
                                             const SizedType &type,
                                             Call &call);
  std::optional<SizedType> get_map_key(
      const std::string map_name,
      const SizedType &type,
      Node &error_node,
      std::optional<GraphNode> ptr_source = std::nullopt);
  void propagate_resolved_types();
  void add_resolved_type(const GraphNode &node, const SizedType &type);
  Node *find_variable_scope(const std::string &var_ident, bool safe = true);
  void add_consumer(const GraphNode &source, const GraphNode &consumer);
  std::optional<SizedType> get_locked_node(const GraphNode &node,
                                           const SizedType &type,
                                           Node &error_node,
                                           const std::string &name);
  GraphNode get_pointer_source(Expression &expr);
  bool is_same_pointer_source(const GraphNode &node_key,
                              const GraphNode &ptr_source,
                              const SizedType &incoming_type,
                              const SizedType &current_type);
  Probe *get_probe();
  Probe *get_probe(Node &node, std::string name = "");
  void check_stack_call(Call &call, bool kernel);
};

class IntrospectionFolder
    : public Visitor<IntrospectionFolder, std::optional<Expression>> {
public:
  IntrospectionFolder(ASTContext &ast, const MacroRegistry &macro_registry)
      : ast_(ast), macro_registry_(macro_registry) {};

  using Visitor<IntrospectionFolder, std::optional<Expression>>::visit;

  std::optional<Expression> visit(Expression &expr);
  std::optional<Expression> visit(Binop &binop);
  std::optional<Expression> visit(Offsetof &offof);
  std::optional<Expression> visit(Sizeof &szof);
  std::optional<Expression> visit(Typeinfo &typeinfo);
  std::optional<Expression> visit(FieldAccess &acc);

  bool had_transforms() const
  {
    return had_transforms_;
  }

private:
  ASTContext &ast_;
  const MacroRegistry &macro_registry_;
  bool had_transforms_ = false;
};

using ResolvedTypes = std::unordered_map<GraphNode, SizedType, GraphNodeHash>;

class TypeApplicator : public Visitor<TypeApplicator> {
public:
  explicit TypeApplicator(const ResolvedTypes &resolved_types)
      : resolved_types_(resolved_types) {};

  using Visitor<TypeApplicator>::visit;

  void visit(ArrayAccess &arr);
  void visit(Binop &binop);
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(FieldAccess &acc);
  void visit(Identifier &identifier);
  void visit(IfExpr &if_expr);
  void visit(Map &map);
  void visit(MapAddr &map_addr);
  void visit(Record &record);
  void visit(Tuple &tuple);
  void visit(TupleAccess &acc);
  void visit(Unop &unop);
  void visit(Variable &var);
  void visit(VariableAddr &var_addr);

private:
  const ResolvedTypes &resolved_types_;

  void apply(Node &node, SizedType &target)
  {
    auto it = resolved_types_.find(&node);
    if (it != resolved_types_.end()) {
      target = it->second;
    }
  }
};

std::optional<SizedType> binop_ptr(Binop &binop,
                                   const SizedType &lht,
                                   const SizedType &rht)
{
  bool left_is_ptr = lht.IsPtrTy();
  const auto &ptr = left_is_ptr ? lht : rht;
  const auto &other = left_is_ptr ? rht : lht;

  bool compare = is_comparison_op(binop.op);
  bool logical = binop.op == Operator::LAND || binop.op == Operator::LOR;

  auto invalid_op = [&binop, &lht, &rht]() -> std::optional<SizedType> {
    binop.addError() << "The " << opstr(binop)
                     << " operator can not be used on expressions of types "
                     << lht << ", " << rht;
    return std::nullopt;
  };

  // Binop on two pointers
  if (other.IsPtrTy()) {
    if (compare) {
      const auto le = lht.GetPointeeTy();
      const auto re = rht.GetPointeeTy();
      if (le != re) {
        auto &warn = binop.addWarning();
        warn << "comparison of distinct pointer types: " << le << ", " << re;
        warn.addContext(binop.left.loc()) << "left (" << le << ")";
        warn.addContext(binop.right.loc()) << "right (" << re << ")";
      }
      return CreateBool();
    } else if (!logical) {
      return invalid_op();
    } else {
      return CreateBool();
    }
  }
  // Binop on a pointer and (int or bool)
  else if (other.IsIntTy() || other.IsBoolTy()) {
    // sum is associative but minus only works with pointer on the left hand
    // side
    if (binop.op == Operator::MINUS && !left_is_ptr)
      return invalid_op();
    else if (binop.op == Operator::PLUS || binop.op == Operator::MINUS)
      return CreatePointer(ptr.GetPointeeTy(), ptr.GetAS());
    else if (!compare && !logical)
      return invalid_op();

    if (compare) {
      return CreateBool();
    } else {
      return invalid_op();
    }
  }
  // Binop on a pointer and something else
  else {
    return invalid_op();
  }
}

SizedType binop_int(Binop &binop, const SizedType &lht, const SizedType &rht)
{
  auto is_comparison = is_comparison_op(binop.op);
  if (lht == rht) {
    if (is_comparison) {
      return CreateBool();
    } else {
      if (lht.IsSigned() || binop.op == Operator::MINUS) {
        return CreateInt64();
      }
      return CreateUInt64();
    }
  }

  bool show_warning = false;
  bool mismatched_sign = rht.IsSigned() != lht.IsSigned();
  // N.B. all castable map values are 64 bits
  if (lht.IsCastableMapTy()) {
    if (rht.IsCastableMapTy()) {
      show_warning = mismatched_sign;
    } else {
      if (!get_promoted_type(rht, CreateInteger(64, lht.IsSigned()))) {
        show_warning = true;
      }
    }
  } else if (rht.IsCastableMapTy()) {
    if (!get_promoted_type(lht, CreateInteger(64, rht.IsSigned()))) {
      show_warning = true;
    }
  } else if (!get_promoted_type(lht, rht)) {
    show_warning = true;
  }

  if (show_warning) {
    switch (binop.op) {
      case Operator::EQ:
      case Operator::NE:
      case Operator::LE:
      case Operator::GE:
      case Operator::LT:
      case Operator::GT:
        binop.addWarning() << "comparison of integers of different signs: '"
                           << lht << "' and '" << rht << "'"
                           << " can lead to undefined behavior";
        break;
      case Operator::PLUS:
      case Operator::MINUS:
      case Operator::MUL:
      case Operator::DIV:
      case Operator::MOD:
        binop.addWarning() << "arithmetic on integers of different signs: '"
                           << lht << "' and '" << rht << "'"
                           << " can lead to undefined behavior";
        break;
      default:
        break;
    }
  }

  if (is_comparison) {
    return CreateBool();
  }

  // Next, warn on any operations that require signed division.
  //
  // SDIV is not implemented for bpf. See Documentation/bpf/bpf_design_QA
  // in kernel sources
  if (binop.op == Operator::DIV || binop.op == Operator::MOD) {
    // If they're still signed, we have to warn
    if (lht.IsSigned() || rht.IsSigned()) {
      binop.addWarning() << "signed operands for '" << opstr(binop)
                         << "' can lead to undefined behavior "
                         << "(cast to unsigned to silence warning)";
    }
  }
  if (binop.op == Operator::MINUS || lht.IsSigned() || rht.IsSigned()) {
    return CreateInt64();
  }

  return CreateUInt64();
}

std::optional<SizedType> get_binop_type(Binop &binop,
                                        const SizedType &lht,
                                        const SizedType &rht)
{
  bool is_comparison = is_comparison_op(binop.op);

  if (lht.IsNoneTy() || rht.IsNoneTy()) {
    if (is_comparison) {
      return CreateBool();
    }

    if (lht.IsNoneTy() && rht.IsNoneTy()) {
      return std::nullopt;
    }

    if (rht.IsNoneTy()) {
      // Might have a script like: `@a[0] = @a[0] << 1;` or `$a = $a + 1`;
      if (binop.right.is<MapAccess>()) {
        if (lht.IsIntegerTy()) {
          return CreateInteger(64,
                               (lht.IsSigned() || binop.op == Operator::MINUS));
        }
      }
      return std::nullopt;
    } else {
      if (binop.left.is<MapAccess>()) {
        if (rht.IsIntegerTy()) {
          return CreateInteger(64,
                               (rht.IsSigned() || binop.op == Operator::MINUS));
        }
      }
      return std::nullopt;
    }
  }

  if (lht.IsBoolTy() && rht.IsBoolTy()) {
    return CreateBool();
  }

  bool lsign = lht.IsSigned();
  bool rsign = rht.IsSigned();
  bool is_int_binop = (lht.IsCastableMapTy() || lht.IsIntTy() ||
                       lht.IsBoolTy()) &&
                      (rht.IsCastableMapTy() || rht.IsIntTy() ||
                       rht.IsBoolTy());

  bool is_signed = lsign || rsign;
  switch (binop.op) {
    case Operator::LEFT:
    case Operator::RIGHT:
      is_signed = lsign;
      break;
    default:
      break;
  }

  if (lht.IsPtrTy() || rht.IsPtrTy()) {
    return binop_ptr(binop, lht, rht);
  }

  auto result_type = is_comparison ? CreateBool()
                                   : CreateInteger(64, is_signed);
  auto addr_lhs = lht.GetAS();
  auto addr_rhs = rht.GetAS();

  // if lhs or rhs has different addrspace (not none), then set the
  // addrspace to none. This preserves the behaviour for x86.
  if (addr_lhs != addr_rhs && addr_lhs != AddrSpace::none &&
      addr_rhs != AddrSpace::none) {
    binop.addWarning() << "Addrspace mismatch";
    result_type.SetAS(AddrSpace::none);
  }
  // Associativity from left to right for binary operator
  else if (addr_lhs != AddrSpace::none) {
    result_type.SetAS(addr_lhs);
  } else {
    // In case rhs is none, then this triggers warning in
    // selectProbeReadHelper.
    result_type.SetAS(addr_rhs);
  }

  if (is_int_binop) {
    return binop_int(binop, lht, rht);
  }

  return result_type;
}

bool TypeGraph::check_offsetof_type(Offsetof &offof, SizedType cstruct)
{
  // Check if all sub-fields are present.
  for (const auto &field : offof.field) {
    if (!cstruct.IsCStructTy()) {
      offof.addError() << "'" << cstruct << "' " << "is not a c_struct type.";
      return false;
    } else if (!bpftrace_.structs.Has(cstruct.GetName())) {
      offof.addError() << "'" << cstruct.GetName() << "' does not exist.";
      return false;
    } else if (!cstruct.HasField(field)) {
      offof.addError() << "'" << cstruct.GetName() << "' "
                       << "has no field named " << "'" << field << "'";
      return false;
    } else {
      // Get next sub-field
      const auto &f = cstruct.GetField(field);
      cstruct = f.type;
    }
  }
  return true;
}

// These are special map aggregation types that cannot be assigned
// to scratch variables and map values/keys:
// @a = count();                  // OK
// @a = 1; @b = count(); @a = @b; // OK
// @a = 1; @b = hist(); @a = @b;  // NOK
// @b = count(); @a = @b;         // NOK
// @a = 1; @a = count();          // NOK
// @a = count(); @a = 1;          // NOK
// @a = count(); @a = sum(5);     // NOK
bool is_valid_assignment(const SizedType &type,
                         const SizedType &current_type,
                         bool is_map_assignment = false)
{
  if (type.IsNoneTy() || type.IsVoidTy()) {
    return false;
  } else if (type.NeedsPercpuMap() && !type.IsCastableMapTy()) {
    return false;
  } else if (!current_type.IsIntegerTy() && type.IsCastableMapTy()) {
    // Assigning to maps with no value type yet is not allowed (mostly to
    // prevent user confusion)
    // @b = count(); @a = @b;
    // But assigning to scratch variables or map keys is OK
    if (is_map_assignment) {
      return false;
    } else if (!current_type.IsNoneTy()) {
      return false;
    }
  }
  return true;
}

} // namespace

void TypeGraph::visit(ArrayAccess &arr)
{
  visit(arr.expr);
  visit(arr.indexpr);

  graph_[&arr.expr.node()].emplace_back(
      &arr, [&arr](SizedType type) -> std::optional<SizedType> {
        SizedType elem;
        if (type.IsArrayTy()) {
          elem = type.GetElementTy();
        } else if (type.IsPtrTy()) {
          elem = type.GetPointeeTy();
        } else if (type.IsStringTy()) {
          elem = CreateInt8();
        } else {
          arr.addError() << "The array index operator [] can only be "
                            "used on arrays and pointers, found "
                         << type << ".";
        }

        elem.SetAS(type.GetAS());

        // BPF verifier cannot track BTF information for double pointers so we
        // cannot propagate is_internal for arrays of pointers and we need to
        // reset it on the array type as well. Indexing a pointer as an array
        // also can't be verified, so the same applies there.
        if (elem.IsPtrTy() || type.IsPtrTy()) {
          elem.is_internal = false;
        } else {
          elem.is_internal = type.is_internal;
        }

        return elem;
      });
}

void TypeGraph::visit(AssignMapStatement &assignment)
{
  visit(assignment.map_access);
  visit(assignment.expr);

  auto map_name = assignment.map_access->map->ident;
  auto value_name = get_map_value_name(map_name);
  auto ptr_source = get_pointer_source(assignment.expr);

  graph_[&assignment.expr.node()].emplace_back(
      value_name,
      [this, &assignment, map_name, ptr_source](
          SizedType type) -> std::optional<SizedType> {
        auto value_name = get_map_value_name(map_name);
        auto current_type = get_resolved_type(value_name);

        if (!is_valid_assignment(type, current_type, true)) {
          auto &err = assignment.addError();
          auto hint = AGGREGATE_HINTS.find(type.GetTy());
          if (hint != AGGREGATE_HINTS.end()) {
            err << "Map value '" << type
                << "' cannot be assigned from one map to another. "
                   "The function that returns this type must be called "
                   "directly "
                   "e.g. "
                   "`"
                << assignment.map_access->map->ident << " = " << hint->second
                << ";`.";
            if (const auto *acc = assignment.expr.as<MapAccess>()) {
              if (type.IsCastableMapTy()) {
                err.addHint()
                    << "Add a cast to integer if you want the value of the "
                       "aggregate, "
                    << "e.g. `" << assignment.map_access->map->ident
                    << " = (int64)" << acc->map->ident << ";`.";
              }
            }
          } else {
            err << "Value '" << type << "' cannot be assigned to a map.";
          }

          return std::nullopt;
        }

        return get_map_value(map_name, type, assignment, ptr_source);
      });
}

void TypeGraph::visit(AssignVarStatement &assignment)
{
  visit(assignment.expr);
  visit(assignment.var_decl);

  Node *var_scope = find_variable_scope(assignment.var()->ident);
  ScopedVariable scoped_var = std::make_pair(var_scope,
                                             assignment.var()->ident);

  if (decl_variables_.contains(scoped_var)) {
    return;
  }

  auto ptr_source = get_pointer_source(assignment.expr);

  graph_[&assignment.expr.node()].emplace_back(
      scoped_var,
      [this, &assignment, scoped_var, ptr_source](
          SizedType type) -> std::optional<SizedType> {
        if (!is_valid_assignment(type, get_resolved_type(scoped_var))) {
          assignment.addError()
              << "Value '" << type
              << "' cannot be assigned to a scratch variable.";
          return std::nullopt;
        }

        return get_variable_type(scoped_var, type, assignment, ptr_source);
      });
}

void TypeGraph::visit(Builtin &builtin)
{
  SizedType builtin_type = CreateNone();
  auto simple_it = SIMPLE_BUILTIN_TYPES.find(builtin.ident);
  if (simple_it != SIMPLE_BUILTIN_TYPES.end()) {
    builtin_type = simple_it->second();
  } else if (builtin.ident == "ctx") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType pt = probetype(probe->attach_points[0]->provider);
    bpf_prog_type bt = progtype(pt);
    std::string func = probe->attach_points[0]->func;
    builtin_type = CreatePointer(CreateNone());
    switch (bt) {
      case BPF_PROG_TYPE_KPROBE: {
        auto record = bpftrace_.structs.Lookup("struct pt_regs");
        if (!record.expired()) {
          builtin_type = CreatePointer(CreateCStruct("struct pt_regs", record),
                                       AddrSpace::kernel);
          builtin_type.MarkCtxAccess();
        }
        break;
      }
      case BPF_PROG_TYPE_PERF_EVENT:
        builtin_type = CreatePointer(
            CreateCStruct("struct bpf_perf_event_data",
                          bpftrace_.structs.Lookup(
                              "struct bpf_perf_event_data")),
            AddrSpace::kernel);
        builtin_type.MarkCtxAccess();
        break;
      case BPF_PROG_TYPE_TRACING:
        if (pt == ProbeType::iter) {
          std::string type = "struct bpf_iter__" + func;
          builtin_type = CreatePointer(
              CreateCStruct(type, bpftrace_.structs.Lookup(type)),
              AddrSpace::kernel);
          builtin_type.MarkCtxAccess();
        }
        break;
      default:
        break;
    }
  } else if (builtin.ident == "__builtin_curtask") {
    builtin_type = CreatePointer(CreateCStruct("struct task_struct",
                                               bpftrace_.structs.Lookup(
                                                   "struct task_struct")),
                                 AddrSpace::kernel);
  } else if (builtin.ident == "__builtin_retval") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType type = probe->get_probetype();
    if (type == ProbeType::fentry || type == ProbeType::fexit) {
      const auto *arg = bpftrace_.structs.GetProbeArg(*probe,
                                                      RETVAL_FIELD_NAME);
      if (arg) {
        builtin_type = arg->type;
      } else
        builtin.addError() << "Can't find a field " << RETVAL_FIELD_NAME;
    } else {
      builtin_type = CreateUInt64();
    }
    builtin_type.SetAS(find_addrspace(type));
  } else if (builtin.ident == "kstack") {
    if (bpftrace_.config_->stack_mode == StackMode::build_id) {
      builtin.addWarning() << "'build_id' stack mode can only be used for "
                              "ustack. Falling back to 'raw' mode.";
      builtin_type = CreateStack(true, StackType{ .mode = StackMode::raw });
    } else {
      builtin_type = CreateStack(
          true, StackType{ .mode = bpftrace_.config_->stack_mode });
    }
  } else if (builtin.ident == "ustack") {
    builtin_type = CreateStack(
        false, StackType{ .mode = bpftrace_.config_->stack_mode });
  } else if (builtin.ident == "__builtin_comm") {
    constexpr int COMM_SIZE = 16;
    builtin_type = CreateString(COMM_SIZE);
    builtin_type.SetAS(AddrSpace::kernel);
  } else if (builtin.ident == "__builtin_func") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    ProbeType type = probe->get_probetype();
    if (type == ProbeType::uprobe || type == ProbeType::uretprobe) {
      builtin_type = CreateUSym();
    } else {
      builtin_type = CreateKSym();
    }
  } else if (builtin.is_argx()) {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;
    builtin_type = CreateUInt64();
    builtin_type.SetAS(
        find_addrspace(probetype(probe->attach_points[0]->provider)));
  } else if (builtin.ident == "args") {
    auto *probe = get_probe(builtin, builtin.ident);
    if (probe == nullptr)
      return;

    ProbeType type = probe->get_probetype();
    auto type_name = probe->args_typename();
    if (!type_name) {
      builtin.addError() << "Unable to resolve unique type name.";
      return;
    }

    if (type == ProbeType::fentry || type == ProbeType::fexit ||
        type == ProbeType::uprobe || type == ProbeType::rawtracepoint) {
      builtin_type = CreateCStruct(*type_name,
                                   bpftrace_.structs.Lookup(*type_name));
      if (builtin_type.GetFieldCount() == 0)
        builtin.addError() << "Cannot read function parameters";

      builtin_type.MarkCtxAccess();
      builtin_type.is_funcarg = true;
      builtin_type.SetAS(type == ProbeType::uprobe ? AddrSpace::user
                                                   : AddrSpace::kernel);
      if (type == ProbeType::uprobe)
        builtin_type.is_internal = true;
    } else if (type == ProbeType::tracepoint) {
      builtin_type = CreateCStruct(*type_name,
                                   bpftrace_.structs.Lookup(*type_name));
      builtin_type.SetAS(probe->attach_points.front()->target == "syscalls"
                             ? AddrSpace::user
                             : AddrSpace::kernel);
      builtin_type.MarkCtxAccess();
    }
  } else {
    LOG(BUG) << "Unknown builtin variable: '" << builtin.ident << "'";
  }
  add_resolved_type(&builtin, builtin_type);
}

void TypeGraph::visit(Call &call)
{
  // RAII setter for func_ context (used by Identifier resolution)
  struct func_setter {
    func_setter(TypeGraph &pass, const std::string &s)
        : pass_(pass), old_func_(pass_.func_)
    {
      pass_.func_ = s;
    }

    ~func_setter()
    {
      pass_.func_ = old_func_;
    }

  private:
    TypeGraph &pass_;
    std::string old_func_;
  };

  func_setter scope_bound_func_setter{ *this, call.func };

  // Visit children to wire up graph edges for arguments
  for (auto &varg : call.vargs) {
    visit(varg);
  }

  // These map aggregate functions are the only ones that can set the map value
  // types to the corresponding aggregate types. For example `@a = count();`
  // gets desuggared to `count(@a, 0)` However some of these aggregation types
  // are castable to ints so this is ok:
  // `@a = count(); @b = 1; @b = @a;` but the value type of `@b` remains an
  // integer not `count_t`.
  if (getAssignRewriteFuncs().contains(call.func)) {
    if (auto *map = call.vargs.at(0).as<Map>()) {
      auto map_name = map->ident;

      if (call.func == "count" || call.func == "hist" || call.func == "lhist" ||
          call.func == "tseries") {
        graph_[&call].emplace_back(
            get_map_value_name(map_name),
            [this, &call, map_name](SizedType) -> std::optional<SizedType> {
              SizedType agg_type;
              if (call.func == "count") {
                agg_type = CreateCount();
              } else if (call.func == "hist") {
                agg_type = CreateHist();
              } else if (call.func == "lhist") {
                agg_type = CreateLhist();
              } else if (call.func == "tseries") {
                agg_type = CreateTSeries();
              }

              return get_agg_map_value(map_name, agg_type, call);
            });
      } else {
        // N.B. @a = sum(5); gets desugared to _ = sum(@x, 0, 5); so we have to
        // set the consumer of this map aggregate function to be the map value
        // name directly and also add the resolved call type in the callback
        graph_[&call.vargs.at(2).node()].emplace_back(
            get_map_value_name(map_name),
            [this, &call, map_name](
                SizedType type) -> std::optional<SizedType> {
              if (!type.IsIntegerTy()) {
                call.addError()
                    << call.func << "() only supports integer arguments ("
                    << type << " provided)";
                return std::nullopt;
              }

              SizedType agg_type;
              if (call.func == "avg") {
                agg_type = CreateAvg(type.IsSigned());
              } else if (call.func == "max") {
                agg_type = CreateMax(type.IsSigned());
              } else if (call.func == "min") {
                agg_type = CreateMin(type.IsSigned());
              } else if (call.func == "stats") {
                agg_type = CreateStats(type.IsSigned());
              } else if (call.func == "sum") {
                agg_type = CreateSum(type.IsSigned());
              }
              agg_type.SetSize(type.GetSize());

              return get_agg_map_value(map_name, agg_type, call);
            });
      }

      // 2nd arg is the key
      graph_[&call.vargs.at(1).node()].emplace_back(
          get_map_key_name(map_name),
          [this, &call, map_name](SizedType type) -> std::optional<SizedType> {
            return get_map_key(map_name, type, call);
          });

      add_resolved_type(&call, CreateVoid());
    } else {
      call.vargs.at(0).node().addError()
          << call.func << "() expects a map argument";
    }
  } else {
    // Compute intrinsic return type
    SizedType return_type = CreateNone();
    if (VOID_RETURNING_FUNCS.contains(call.func)) {
      return_type = CreateVoid();
    } else if (auto it = SIMPLE_CALL_TYPES.find(call.func);
               it != SIMPLE_CALL_TYPES.end()) {
      return_type = it->second();
    } else if (call.func == "str") {
      auto strlen = bpftrace_.config_->max_strlen;
      if (call.vargs.size() == 2) {
        if (auto *integer = call.vargs.at(1).as<Integer>()) {
          if (integer->value + 1 > strlen) {
            call.addWarning() << "length param (" << integer->value
                              << ") is too long and will be shortened to "
                              << strlen << " bytes (see BPFTRACE_MAX_STRLEN)";
          } else {
            strlen = integer->value + 1;
          }
        }

        if (auto *integer = dynamic_cast<NegativeInteger *>(
                call.vargs.at(1).as<NegativeInteger>())) {
          call.addError() << call.func << "cannot use negative length ("
                          << integer->value << ")";
        }
      }
      return_type = CreateString(strlen);
      return_type.SetAS(AddrSpace::kernel);
    } else if (call.func == "buf") {
      const uint64_t max_strlen = bpftrace_.config_->max_strlen;
      uint32_t max_buffer_size = max_strlen - sizeof(AsyncEvent::Buf);
      uint32_t buffer_size = max_buffer_size;

      if (call.vargs.size() == 1) {
        auto &arg = call.vargs.at(0);
        if (arg.type().IsArrayTy()) {
          buffer_size = arg.type().GetNumElements() *
                        arg.type().GetElementTy().GetSize();
        }
      } else if (call.vargs.size() == 2) {
        if (auto *integer = call.vargs.at(1).as<Integer>()) {
          buffer_size = integer->value;
        }
      }

      if (buffer_size > max_buffer_size) {
        buffer_size = max_buffer_size;
      }

      return_type = CreateBuffer(buffer_size);
      return_type.SetAS(AddrSpace::kernel);
    } else if (call.func == "ntop") {
      int buffer_size = 24;
      return_type = CreateInet(buffer_size);
    } else if (call.func == "pton") {
      int af_type = 0, addr_size = 0;
      std::string addr;
      if (call.vargs.size() == 1) {
        if (auto *str = call.vargs.at(0).as<String>()) {
          addr = str->value;
          if (addr.find(".") != std::string::npos) {
            af_type = AF_INET;
            addr_size = 4;
          } else if (addr.find(":") != std::string::npos) {
            af_type = AF_INET6;
            addr_size = 16;
          } else {
            call.addError()
                << call.func
                << "() expects an string argument of an IPv4/IPv6 address, got "
                << addr;
            return;
          }
        } else {
          call.addError() << call.func << "() expects an string literal, got "
                          << call.vargs.at(0).type();
          return;
        }
      }

      std::vector<char> dst(addr_size);
      auto ret = inet_pton(af_type, addr.c_str(), dst.data());
      if (ret != 1) {
        call.addError() << call.func
                        << "() expects a valid IPv4/IPv6 address, got " << addr;
        return;
      }

      return_type = CreateArray(addr_size, CreateUInt8());
      return_type.SetAS(AddrSpace::kernel);
      return_type.is_internal = true;
    } else if (call.func == "reg") {
      return_type = CreateUInt64();
      if (auto *probe = dynamic_cast<Probe *>(top_level_node_)) {
        ProbeType pt = probe->get_probetype();
        return_type.SetAS(find_addrspace(pt));
      } else {
        return_type.SetAS(AddrSpace::kernel);
      }
    } else if (call.func == "kaddr") {
      return_type = CreateUInt64();
      return_type.SetAS(AddrSpace::kernel);
    } else if (call.func == "percpu_kaddr") {
      return_type = CreateUInt64();
      return_type.SetAS(AddrSpace::kernel);
    } else if (call.func == "__builtin_uaddr") {
      auto *probe = get_probe(call, call.func);
      if (probe == nullptr)
        return;

      struct symbol sym = {};

      if (!call.vargs.empty() && call.vargs.at(0).is<String>()) {
        auto name = call.vargs.at(0).as<String>()->value;
        const auto &target = probe->attach_points[0]->target;

        int err = bpftrace_.resolve_uname(name, &sym, target);
        if (err < 0 || sym.address == 0) {
          call.addError() << "Could not resolve symbol: " << target << ":"
                          << name;
        }
      }

      size_t pointee_size = 0;
      switch (sym.size) {
        case 1:
        case 2:
        case 4:
          pointee_size = sym.size * 8;
          break;
        default:
          pointee_size = 64;
      }

      return_type = CreatePointer(CreateInt(pointee_size), AddrSpace::user);
    } else if (call.func == "kstack") {
      check_stack_call(call, true);
      return_type = call.return_type;
    } else if (call.func == "ustack") {
      check_stack_call(call, false);
      return_type = call.return_type;
    } else if (call.func == "path") {
      auto call_type_size = bpftrace_.config_->max_strlen;
      if (call.vargs.size() == 2) {
        if (auto *size = call.vargs.at(1).as<Integer>()) {
          call_type_size = size->value;
        }
      }
      return_type = SizedType(Type::string, call_type_size);
    } else if (call.func == "kptr" || call.func == "uptr") {
      graph_[&call.vargs.at(0).node()].emplace_back(
          &call, [this, &call](SizedType type) -> std::optional<SizedType> {
            type.SetAS(call.func == "kptr" ? AddrSpace::kernel
                                           : AddrSpace::user);
            return type;
          });
      return;
    } else if (call.func == "bswap") {
      graph_[&call.vargs.at(0).node()].emplace_back(
          &call, [this, &call](SizedType type) -> std::optional<SizedType> {
            auto int_bit_width = 1;
            if (!type.IsIntTy()) {
              call.addError()
                  << call.func << "() only supports integer arguments ("
                  << type.GetTy() << " provided)";
              return std::nullopt;
            }
            int_bit_width = type.GetIntBitWidth();
            return CreateUInt(int_bit_width);
          });
      return;
    } else if (call.func == "nsecs") {
      if (call.vargs.size() == 1) {
        graph_[&call.vargs.at(0).node()].emplace_back(
            &call, [this, &call](SizedType type) -> std::optional<SizedType> {
              auto ret_type = CreateUInt64();
              ret_type.ts_mode = type.ts_mode;
              return ret_type;
            });
        return;
      } else {
        return_type = CreateUInt64();
        return_type.ts_mode = TimestampMode::boot;
      }
    } else if (auto bit = SIMPLE_BUILTIN_TYPES.find(call.func);
               bit != SIMPLE_BUILTIN_TYPES.end()) {
      return_type = bit->second();
    }

    if (!return_type.IsNoneTy()) {
      add_resolved_type(&call, return_type);
    } else {
      // BTF function lookup
      auto maybe_func = type_metadata_.global.lookup<btf::Function>(call.func);
      if (!maybe_func) {
        call.addError() << "Unknown function: '" << call.func << "'";
        return;
      }

      const auto &func = *maybe_func;

      if (func.linkage() != btf::Function::Linkage::Global &&
          func.linkage() != btf::Function::Linkage::Extern) {
        call.addError() << "Unsupported function linkage: '" << call.func
                        << "'";
        return;
      }

      auto proto = func.type();
      if (!proto) {
        call.addError() << "Unable to find function proto: "
                        << proto.takeError();
        return;
      }
      // Extract our return type.
      auto btf_return_type = proto->return_type();
      if (!btf_return_type) {
        call.addError() << "Unable to read return type: "
                        << btf_return_type.takeError();
        return;
      }
      auto compat_return_type = getCompatType(*btf_return_type);
      if (!compat_return_type) {
        call.addError() << "Unable to convert return type: "
                        << compat_return_type.takeError();
        return;
      }
      add_resolved_type(&call, *compat_return_type);
    }
  }
}

void TypeGraph::visit(Binop &op)
{
  visit(op.left);
  visit(op.right);

  graph_[&op.left.node()].emplace_back(
      &op, [&op, this](SizedType lht) -> std::optional<SizedType> {
        auto rht = get_resolved_type(&op.right.node());
        return get_binop_type(op, lht, rht);
      });

  graph_[&op.right.node()].emplace_back(
      &op, [&op, this](SizedType rht) -> std::optional<SizedType> {
        auto lht = get_resolved_type(&op.left.node());
        return get_binop_type(op, lht, rht);
      });
}

void TypeGraph::visit(BlockExpr &block)
{
  scope_stack_.push_back(&block);
  visit(block.stmts);
  visit(block.expr);

  add_consumer(&block.expr.node(), &block);
  scope_stack_.pop_back();
}

void TypeGraph::visit(Boolean &boolean)
{
  add_resolved_type(&boolean, boolean.type());
}

void TypeGraph::visit(Cast &cast)
{
  visit(cast.expr);

  if (std::holds_alternative<SizedType>(cast.typeof->record)) {
    auto &ty = std::get<SizedType>(cast.typeof->record);
    if (!resolve_struct_type(ty, *cast.typeof)) {
      return;
    }
    add_resolved_type(&cast, ty);
  } else {
    visit(cast.typeof);
    add_consumer(cast.typeof, &cast);
  }
}

void TypeGraph::visit(Comptime &comptime)
{
  visit(comptime.expr);
  unresolved_comptimes_.emplace_back(&comptime);
}

void TypeGraph::visit(ExprStatement &expr)
{
  visit(expr.expr);
}

void TypeGraph::visit(FieldAccess &acc)
{
  visit(acc.expr);

  graph_[&acc.expr.node()].emplace_back(
      &acc, [this, &acc](SizedType expr_type) -> std::optional<SizedType> {
        // FieldAccesses will automatically resolve through any number of
        // pointer dereferences. For now, we inject the `Unop` operator
        // directly, as codegen stores the underlying structs as pointers
        // anyways. In the future, we will likely want to do this in a different
        // way if we are tracking l-values.
        while (expr_type.IsPtrTy()) {
          expr_type = expr_type.GetPointeeTy();
        }

        SizedType result_type = CreateNone();

        if (!expr_type.IsCStructTy() && !expr_type.IsRecordTy()) {
          acc.addError() << "Can not access field '" << acc.field
                         << "' on expression of type '" << expr_type << "'";
          return std::nullopt;
        }

        if (expr_type.is_funcarg) {
          auto *probe = get_probe();
          if (probe == nullptr) {
            return std::nullopt;
          }
          const auto *arg = bpftrace_.structs.GetProbeArg(*probe, acc.field);
          if (arg) {
            result_type = arg->type;
            result_type.SetAS(expr_type.GetAS());

            if (result_type.IsNoneTy()) {
              acc.addError() << acc.field << " has unsupported type";
            }
          } else {
            acc.addError() << "Can't find function parameter " << acc.field;
          }
          return result_type;
        }

        if (!expr_type.IsRecordTy() &&
            !bpftrace_.structs.Has(expr_type.GetName())) {
          acc.addError() << "Unknown struct/union: '" << expr_type.GetName()
                         << "'";
          return std::nullopt;
        }

        const auto &record = expr_type.GetStruct();

        if (!record->HasField(acc.field)) {
          if (expr_type.IsRecordTy()) {
            acc.addError() << "Record does not contain " << "a field named '"
                           << acc.field << "'";
          } else {
            acc.addError() << "Struct/union of type '" << expr_type.GetName()
                           << "' does not contain " << "a field named '"
                           << acc.field << "'";
          }
          return std::nullopt;
        } else {
          const auto &field = record->GetField(acc.field);

          if (field.type.IsPtrTy()) {
            const auto &tags = field.type.GetBtfTypeTags();
            // Currently only "rcu" is safe. "percpu", for example, requires
            // special unwrapping with `bpf_per_cpu_ptr` which is not yet
            // supported.
            static const std::string_view allowed_tag = "rcu";
            for (const auto &tag : tags) {
              if (tag != allowed_tag) {
                acc.addError()
                    << "Attempting to access pointer field '" << acc.field
                    << "' with unsupported tag attribute: " << tag;
              }
            }
          }

          result_type = field.type;
          if (result_type.IsCtxAccess() &&
              (result_type.IsArrayTy() || result_type.IsCStructTy())) {
            // e.g., ((struct bpf_perf_event_data*)ctx)->regs.ax
            result_type.MarkCtxAccess();
          }
          result_type.is_internal = expr_type.is_internal;
          result_type.SetAS(expr_type.GetAS());

          return result_type;
        }
      });
}

void TypeGraph::visit(For &f)
{
  if (auto *map = f.iterable.as<Map>()) {
    if (map_metadata_.bad_iterator.contains(map)) {
      map->addError() << map->ident
                      << " has no explicit keys (scalar map), and "
                         "cannot be used for iteration";
    }
  }

  const auto &decl_name = f.decl->ident;

  // Collect a list of unique variables which are referenced in the loop's
  // body and declared before the loop. These will be passed into the loop
  // callback function as the context parameter.
  std::unordered_set<std::string> found_vars;
  auto [iter, _] = for_vars_referenced_.try_emplace(&f);
  auto &collector = iter->second;
  collector.visit(f.block, [this, &found_vars, &decl_name](const auto &var) {
    if (found_vars.contains(var.ident) || var.ident == decl_name)
      return false;

    Node *scope = find_variable_scope(var.ident, false);
    if (scope && variables_[scope].contains(var.ident)) {
      found_vars.insert(var.ident);
      return true;
    }

    return false;
  });

  visit(f.decl);

  ScopedVariable scoped_var = std::make_pair(scope_stack_.back(), decl_name);

  if (auto *map = f.iterable.as<Map>()) {
    visit(map);
    auto key_name = get_map_key_name(map->ident);
    auto value_name = get_map_value_name(map->ident);
    graph_[map].emplace_back(
        scoped_var,
        [&f, map, key_name, value_name, scoped_var, this](
            SizedType) -> std::optional<SizedType> {
          auto key_type = get_resolved_type(key_name);
          auto value_type = get_resolved_type(value_name);
          if (key_type.IsNoneTy() || value_type.IsNoneTy()) {
            return std::nullopt;
          }
          if (!value_type.IsMapIterableTy()) {
            map->addError()
                << "Loop expression does not support type: " << value_type;
          }
          auto tuple_type = CreateTuple(
              Struct::CreateTuple({ key_type, value_type }));

          auto current_var_type = get_resolved_type(scoped_var);
          if (tuple_type == current_var_type) {
            // This prevents an infinite loop - example:
            // @map[1, 2] = 1; for ($kv : @map) { @map[$kv.0] = 2; }
            return std::nullopt;
          }

          return tuple_type;
        });

  } else if (auto *range = f.iterable.as<Range>()) {
    visit(range->start);
    visit(range->end);
    add_consumer(&range->start.node(), scoped_var);
    graph_[&range->end.node()].emplace_back(
        scoped_var, [range, this](SizedType) -> std::optional<SizedType> {
          auto start_type = get_resolved_type(&range->start.node());
          auto end_type = get_resolved_type(&range->end.node());

          if (!start_type.IsIntTy()) {
            range->addError()
                << "Loop range requires an integer for the start value";
          }
          if (!end_type.IsIntTy()) {
            range->addError()
                << "Loop range requires an integer for the end value";
          }

          if (start_type.IsNoneTy() || end_type.IsNoneTy()) {
            return std::nullopt;
          }

          auto current_type = start_type;
          if (start_type.IsIntTy() && end_type.IsIntTy()) {
            if (start_type.GetSize() > end_type.GetSize() ||
                start_type.GetSize() < end_type.GetSize()) {
              auto promoted = get_promoted_type(start_type, end_type);
              if (promoted) {
                current_type = *promoted;
              }
            }
          }

          return current_type;
        });
  }

  scope_stack_.push_back(&f);

  visit(f.block);

  scope_stack_.pop_back();

  for (Variable &var : collector.nodes()) {
    graph_[&var].emplace_back(
        &f, [this, &f](SizedType type) -> std::optional<SizedType> {
          if (type.IsNoneTy()) {
            return std::nullopt;
          }
          // Finally, create the context tuple now that all variables
          // inside the loop have been resolved.
          std::vector<SizedType> ctx_types;
          std::vector<std::string_view> ctx_idents;
          auto [iter, _] = for_vars_referenced_.try_emplace(&f);
          auto &collector = iter->second;
          for (const Variable &var : collector.nodes()) {
            auto var_type = get_resolved_type(
                const_cast<Node *>(static_cast<const Node *>(&var)));
            ctx_types.push_back(CreatePointer(var_type, AddrSpace::none));
            ctx_idents.push_back(var.ident);
          }

          f.ctx_type = CreateCStruct(
              Struct::CreateRecord(ctx_types, ctx_idents));
          // Nothing should be dependent upon this for loop
          return std::nullopt;
        });
  }

  // Create an empty ctx struct in case there are no referenced vars in the loop
  // body
  std::vector<SizedType> ctx_types;
  std::vector<std::string_view> ctx_idents;
  f.ctx_type = CreateCStruct(Struct::CreateRecord(ctx_types, ctx_idents));
}

void TypeGraph::visit(Identifier &identifier)
{
  SizedType ident_type = CreateNone();
  if (c_definitions_.enums.contains(identifier.ident)) {
    const auto &enum_name = std::get<1>(c_definitions_.enums[identifier.ident]);
    ident_type = CreateEnum(64, enum_name);
  } else if (bpftrace_.structs.Has(identifier.ident)) {
    ident_type = CreateCStruct(identifier.ident,
                               bpftrace_.structs.Lookup(identifier.ident));
  } else if (func_ == "nsecs") {
    ident_type = CreateTimestampMode();
    if (identifier.ident == "monotonic") {
      ident_type.ts_mode = TimestampMode::monotonic;
    } else if (identifier.ident == "boot") {
      ident_type.ts_mode = TimestampMode::boot;
    } else if (identifier.ident == "tai") {
      ident_type.ts_mode = TimestampMode::tai;
    } else if (identifier.ident == "sw_tai") {
      ident_type.ts_mode = TimestampMode::sw_tai;
    } else {
      identifier.addError() << "Invalid timestamp mode: " << identifier.ident;
    }
  } else {
    ConfigParser<StackMode> parser;
    StackMode mode;
    auto ok = parser.parse(func_, &mode, identifier.ident);
    if (ok) {
      ident_type = CreateStack(true, StackType{ .mode = mode });
    }
  }

  if (ident_type.IsNoneTy() && introspection_level_ > 0) {
    ident_type = bpftrace_.btf_->get_stype(identifier.ident);
  }

  add_resolved_type(&identifier, ident_type);
}

void TypeGraph::visit(IfExpr &if_expr)
{
  if (auto *comptime = if_expr.cond.as<Comptime>()) {
    visit(comptime->expr);
    unresolved_comptimes_.emplace_back(comptime);
    return; // Skip visiting this `if` for now.
  }

  visit(if_expr.cond);
  visit(if_expr.left);
  visit(if_expr.right);

  graph_[&if_expr.left.node()].emplace_back(
      &if_expr,
      [&if_expr, this](SizedType left_type) -> std::optional<SizedType> {
        auto current = get_resolved_type(&if_expr);
        auto promoted = get_promoted_type(current, left_type);
        if (!promoted) {
          if_expr.addError()
              << "Branches must return the same type or compatible types: "
              << "have '" << left_type << "' and '" << current << "'";
          return std::nullopt;
        }
        return promoted;
      });

  graph_[&if_expr.right.node()].emplace_back(
      &if_expr,
      [&if_expr, this](SizedType right_type) -> std::optional<SizedType> {
        auto current = get_resolved_type(&if_expr);
        auto promoted = get_promoted_type(current, right_type);
        if (!promoted) {
          if_expr.addError()
              << "Branches must return the same type or compatible types: "
              << "have '" << current << "' and '" << right_type << "'";
          return std::nullopt;
        }
        return promoted;
      });
}

void TypeGraph::visit(Integer &integer)
{
  add_resolved_type(&integer, integer.type());
}

void TypeGraph::visit(Jump &jump)
{
  if (jump.ident == JumpType::RETURN) {
    visit(jump.return_value);
  }
}

void TypeGraph::visit(Map &map)
{
  if (map_metadata_.bad_indexed_access.contains(&map)) {
    map.addError()
        << map.ident
        << " used as a map without an explicit key (scalar map), previously "
           "used with an explicit key (non-scalar map)";
    return;
  }

  maps_.insert({ map.ident, MapType{ CreateNone(), CreateNone() } });

  auto key_name = get_map_key_name(map.ident);
  auto value_name = get_map_value_name(map.ident);

  graph_[key_name].emplace_back(
      &map,
      [](SizedType key_type) -> std::optional<SizedType> { return key_type; });

  graph_[value_name].emplace_back(
      &map, [](SizedType value_type) -> std::optional<SizedType> {
        return value_type;
      });

  if (introspection_level_ > 0) {
    introspected_nodes_.insert(map.ident);
  }
}

void TypeGraph::visit(MapAccess &acc)
{
  visit(acc.map);
  visit(acc.key);

  if (map_metadata_.bad_scalar_access.contains(acc.map)) {
    acc.addError() << acc.map->ident
                   << " used as a map with an explicit key (non-scalar map), "
                      "previously used without an explicit key (scalar map)";
    return;
  }

  auto key_name = get_map_key_name(acc.map->ident);
  auto ptr_source = get_pointer_source(acc.key);

  graph_[&acc.key.node()].emplace_back(
      key_name,
      [this, &acc, key_name, ptr_source](
          SizedType type) -> std::optional<SizedType> {
        if (!is_valid_assignment(type, get_resolved_type(key_name))) {
          acc.addError() << "Value '" << type
                         << "' cannot be used as a map key.";
          return std::nullopt;
        }

        return get_map_key(acc.map->ident, type, acc, ptr_source);
      });

  add_consumer(get_map_value_name(acc.map->ident), &acc);
}

void TypeGraph::visit(MapAddr &map_addr)
{
  visit(map_addr.map);

  // This needs to be fixed as neither the map value or map key are the actual
  // map's type
  graph_[get_map_value_name(map_addr.map->ident)].emplace_back(
      &map_addr, [](SizedType type) -> std::optional<SizedType> {
        return CreatePointer(type, type.GetAS());
      });
}

void TypeGraph::visit(NegativeInteger &integer)
{
  add_resolved_type(&integer, integer.type());
}

void TypeGraph::visit(Offsetof &offof)
{
  if (std::holds_alternative<SizedType>(offof.record)) {
    auto &ty = std::get<SizedType>(offof.record);
    resolve_struct_type(ty, offof);
    if (!check_offsetof_type(offof, ty)) {
      return;
    }
    add_resolved_type(&offof, offof.type());
  } else {
    auto &expr = std::get<Expression>(offof.record);
    visit(expr);
    if (auto *ident = expr.as<Identifier>()) {
      if (ident->type().IsNoneTy()) {
        offof.addError() << "'" << ident->ident << "' "
                         << "is not a c_struct type.";
        return;
      }
    }
    graph_[&expr.node()].emplace_back(
        &offof, [this, &offof](SizedType type) -> std::optional<SizedType> {
          resolve_struct_type(type, offof);
          if (!check_offsetof_type(offof, type)) {
            return std::nullopt;
          }
          return offof.type();
        });
  }
}

void TypeGraph::visit(Probe &probe)
{
  top_level_node_ = &probe;
  visit(probe.attach_points);
  visit(probe.block);
}

void TypeGraph::visit(Record &record)
{
  for (auto *named_arg : record.elems) {
    auto &elem = named_arg->expr;
    visit(elem);

    graph_[&elem.node()].emplace_back(
        &record, [&record, this](SizedType) -> std::optional<SizedType> {
          std::vector<SizedType> elements;
          std::vector<std::string_view> names;
          for (auto *named_arg : record.elems) {
            auto &elem = named_arg->expr;
            auto elem_type = get_resolved_type(&elem.node());
            if (elem_type.IsNoneTy()) {
              return std::nullopt;
            }
            elements.emplace_back(elem_type);
            names.emplace_back(named_arg->name);
          }
          return CreateRecord(Struct::CreateRecord(elements, names));
        });
  }
}

void TypeGraph::visit(Sizeof &szof)
{
  if (std::holds_alternative<SizedType>(szof.record)) {
    auto &ty = std::get<SizedType>(szof.record);
    resolve_struct_type(ty, szof);
    add_resolved_type(&szof, ty);
  } else {
    auto &expr = std::get<Expression>(szof.record);
    visit(expr);
    graph_[&expr.node()].emplace_back(
        &szof, [&szof](SizedType) -> std::optional<SizedType> {
          // The type of Sizeof is always the same
          return szof.type();
        });
  }
}

void TypeGraph::visit(String &str)
{
  add_resolved_type(&str, str.type());
}

void TypeGraph::visit(Subprog &subprog)
{
  // Note that we visit the subprogram and process arguments *after*
  // constructing the stack with the variable states. This is because the
  // arguments, etc. may have types defined in terms of the arguments
  // themselves. We already handle detecting circular dependencies.
  scope_stack_.push_back(&subprog);
  top_level_node_ = &subprog;
  // for (SubprogArg *arg : subprog.args) {
  //   const auto &ty = arg->typeof->type();
  //   auto &var = variables_[scope_stack_.back()]
  //                   .emplace(arg->var->ident,
  //                            variable{
  //                                .type = ty,
  //                                .can_resize = true,
  //                            })
  //                   .first->second;
  //   var.type = ty; // Override in case it has changed.
  // }

  // // Validate that arguments are set.
  // visit(subprog.args);
  // for (SubprogArg *arg : subprog.args) {
  //   if (arg->typeof->type().IsNoneTy()) {
  //     pass_tracker_.inc_num_unresolved();
  //   }
  // }

  // // Visit all statements.
  // visit(subprog.block);

  // // Validate that the return type is valid.
  // visit(subprog.return_type);
  // if (subprog.return_type->type().IsNoneTy()) {
  //   pass_tracker_.inc_num_unresolved();
  // }
  scope_stack_.pop_back();
}

void TypeGraph::visit(Typeof &typeof)
{
  if (std::holds_alternative<SizedType>(typeof.record)) {
    auto &ty = std::get<SizedType>(typeof.record);
    resolve_struct_type(ty, typeof);
    add_resolved_type(&typeof, ty);
  } else {
    auto &expr = std::get<Expression>(typeof.record);
    visit(expr);

    if (auto *ident = expr.as<Identifier>()) {
      auto stype = bpftrace_.btf_->get_stype(ident->ident);
      add_resolved_type(&typeof, stype);
    } else if (auto *map = expr.as<Map>()) {
      // Typeof for a raw (scalar) map returns the key type.
      // Subscribe directly to the map's key name to avoid getting the
      // value type (both propagate through the Map node).
      add_consumer(get_map_key_name(map->ident), &typeof);
    } else {
      add_consumer(&expr.node(), &typeof);
    }
  }
}

void TypeGraph::visit(Tuple &tuple)
{
  for (auto &elem : tuple.elems) {
    visit(elem);

    graph_[&elem.node()].emplace_back(
        &tuple, [&tuple, this](SizedType) -> std::optional<SizedType> {
          std::vector<SizedType> elements;
          for (auto &elem : tuple.elems) {
            auto elem_type = get_resolved_type(&elem.node());
            if (elem_type.IsNoneTy()) {
              return std::nullopt;
            }
            elements.emplace_back(elem_type);
          }
          return CreateTuple(Struct::CreateTuple(elements));
        });
  }
}

void TypeGraph::visit(TupleAccess &acc)
{
  visit(acc.expr);

  graph_[&acc.expr.node()].emplace_back(
      &acc, [&acc](SizedType type) -> std::optional<SizedType> {
        if (!type.IsTupleTy()) {
          return std::nullopt;
        }

        if (acc.index >= type.GetFields().size()) {
          return std::nullopt;
        }

        return type.GetField(acc.index).type;
      });
}

void TypeGraph::visit(Typeinfo &typeinfo)
{
  ++introspection_level_;
  visit(typeinfo.typeof);
  --introspection_level_;
  graph_[typeinfo.typeof].emplace_back(
      &typeinfo, [](SizedType type) -> std::optional<SizedType> {
        auto base_ty_str = to_string(type.GetTy());
        auto full_ty_str = typestr(type);
        std::vector<SizedType> elements = {
          CreateUInt64(),
          CreateString(base_ty_str.size() + 1),
          CreateString(full_ty_str.size() + 1)
        };
        std::vector<std::string_view> names = { "btf_id",
                                                "base_type",
                                                "full_type" };
        return CreateRecord(Struct::CreateRecord(elements, names));
      });
}

void TypeGraph::visit(Unop &unop)
{
  visit(unop.expr);

  bool is_inc_dec_op = false;

  switch (unop.op) {
    case Operator::PRE_INCREMENT:
    case Operator::PRE_DECREMENT:
    case Operator::POST_INCREMENT:
    case Operator::POST_DECREMENT:
      is_inc_dec_op = true;
      break;
    default:;
  }

  // Unops are special in that they can be both assignments and expressions. If
  // we're dealing with a map access or variable then treat these like
  // assignments and resolved_types whereby we resolve the type of unop
  // expression and creates a chain that attemps to assign this integer type to
  // the stored map value or variable. This enables us to get error messages on
  // the correct node if we attempt to increment a string or some other invalid
  // type.
  if (is_inc_dec_op) {
    if (auto *acc = unop.expr.as<MapAccess>()) {
      auto map_name = acc->map->ident;
      auto map_value_name = get_map_value_name(map_name);

      add_resolved_type(&unop, CreateInt64());
      graph_[&unop].emplace_back(
          map_value_name,
          [this, &unop, map_name](SizedType type) -> std::optional<SizedType> {
            return get_map_value(map_name, type, unop);
          });

      return;
    } else if (auto *var = unop.expr.as<Variable>()) {
      Node *scope = find_variable_scope(var->ident);
      ScopedVariable scoped_var = std::make_pair(scope, var->ident);

      add_resolved_type(&unop, CreateInt64());
      graph_[&unop].emplace_back(
          scoped_var,
          [this, &unop, scoped_var](
              SizedType type) -> std::optional<SizedType> {
            if (decl_variables_.contains(scoped_var)) {
              return std::nullopt;
            }

            return get_variable_type(scoped_var, type, unop);
          });

      return;
    }

    unop.addError() << "The " << opstr(unop)
                    << " operator must be applied to a map or variable";
    return;
  }

  auto valid_ptr_op = is_inc_dec_op || unop.op == Operator::MUL;

  graph_[&unop.expr.node()].emplace_back(
      &unop, [&unop, valid_ptr_op](SizedType type) -> std::optional<SizedType> {
        bool invalid = false;
        // Unops are only allowed on ints (e.g. ~$x), dereference only on
        // pointers and context (we allow args->field for backwards
        // compatibility)
        if (type.IsBoolTy()) {
          invalid = unop.op != Operator::LNOT;
        } else if (!type.IsIntegerTy() &&
                   !((type.IsPtrTy() || type.IsCtxAccess()) && valid_ptr_op)) {
          invalid = true;
        }
        if (invalid) {
          unop.addError()
              << "The " << opstr(unop)
              << " operator can not be used on expressions of type '" << type
              << "'";
          return std::nullopt;
        }

        SizedType result = CreateNone();
        if (unop.op == Operator::MUL) {
          if (type.IsPtrTy()) {
            result = type.GetPointeeTy();
            if (type.IsCtxAccess())
              result.MarkCtxAccess();
            result.is_internal = type.is_internal;
            result.SetAS(type.GetAS());
          } else if (type.IsCStructTy()) {
            // We allow dereferencing "args" with no effect (for backwards
            // compat)
            if (type.IsCtxAccess())
              result = type;
            else {
              unop.addError() << "Can not dereference struct/union of type '"
                              << type.GetName() << "'. It is not a pointer.";
            }
          } else if (type.IsIntTy()) {
            result = CreateUInt64();
          } else {
            unop.addError() << "Can not dereference type '" << type
                            << "'. It is not a pointer.";
          }
        } else if (unop.op == Operator::LNOT) {
          result = CreateBool();
        } else if (type.IsPtrTy() && valid_ptr_op) {
          result = type;
        } else {
          result = CreateInt64();
        }

        return result;
      });
}

void TypeGraph::visit(VarDeclStatement &decl)
{
  if (find_variable_scope(decl.var->ident, false) != nullptr) {
    LOG(BUG) << "Variable shadowing should have been caught by now";
  }

  if (!decl.typeof) {
    // If the declaration has no type then we can rely on the assignments to
    // this variable to determine the type. Otherwise we exclusively rely on the
    // type specified in the declaration and ignore the right side (issuing
    // errors later).
    visit(decl.var);
    return;
  }

  auto scope = scope_stack_.back();
  ScopedVariable scoped_var = std::make_pair(scope, decl.var->ident);

  if (std::holds_alternative<SizedType>(decl.typeof->record)) {
    auto &ty = std::get<SizedType>(decl.typeof->record);
    if (!resolve_struct_type(ty, *decl.typeof)) {
      return;
    }
    add_resolved_type(scoped_var, ty);
    // Some declared types like 'string' have no size so we can factor in the
    // size of the assignment
    if (ty.GetSize() != 0) {
      decl_variables_.insert(scoped_var);
    }
  } else {
    decl_variables_.insert(scoped_var);
    visit(decl.typeof);
    graph_[decl.typeof].emplace_back(
        scoped_var,
        [](SizedType type) -> std::optional<SizedType> { return type; });
  }

  visit(decl.var);
}

void TypeGraph::visit(Variable &var)
{
  Node *scope = find_variable_scope(var.ident, false);
  if (scope == nullptr) {
    scope = scope_stack_.back();
  }
  variables_[scope].insert({ var.ident, CreateNone() });

  ScopedVariable scoped_var = std::make_pair(scope, var.ident);

  graph_[scoped_var].emplace_back(
      &var, [](SizedType type) -> std::optional<SizedType> { return type; });

  if (introspection_level_ > 0) {
    introspected_nodes_.insert(scoped_var);
  }
}

void TypeGraph::visit(VariableAddr &var_addr)
{
  visit(var_addr.var);
  graph_[var_addr.var].emplace_back(
      &var_addr, [](SizedType type) -> std::optional<SizedType> {
        return CreatePointer(type, type.GetAS());
      });
}

bool TypeGraph::resolve_struct_type(SizedType &type, Node &node)
{
  SizedType inner_type = type;
  int pointer_level = 0;
  while (inner_type.IsPtrTy()) {
    inner_type = inner_type.GetPointeeTy();
    pointer_level++;
  }
  if (inner_type.IsCStructTy() && !inner_type.GetStruct()) {
    auto struct_type = bpftrace_.structs.Lookup(inner_type.GetName()).lock();
    if (!struct_type) {
      // Try to find the type as something other than a struct, e.g. 'char' or
      // 'uint64_t'
      auto stype = bpftrace_.btf_->get_stype(inner_type.GetName());
      if (stype.IsNoneTy()) {
        node.addError() << "Cannot resolve unknown type \""
                        << inner_type.GetName() << "\"\n";
        return false;
      } else {
        type = stype;
        while (pointer_level > 0) {
          type = CreatePointer(type);
          pointer_level--;
        }
      }
    } else {
      type = CreateCStruct(inner_type.GetName(), struct_type);
      while (pointer_level > 0) {
        type = CreatePointer(type);
        pointer_level--;
      }
    }
  }
  return true;
}

std::optional<SizedType> TypeGraph::get_variable_type(
    const ScopedVariable &scoped_var,
    const SizedType &type,
    Node &error_node,
    std::optional<GraphNode> ptr_source)
{
  const auto &var = scoped_var.second;

  auto locked_type = get_locked_node(scoped_var, type, error_node, var);
  if (locked_type) {
    return *locked_type;
  }

  auto current_type = get_resolved_type(scoped_var);
  auto promoted = get_promoted_type(current_type, type);
  if (promoted) {
    if (promoted->IsPtrTy() && ptr_source.has_value()) {
      pointer_sources_[scoped_var] = *ptr_source;
    }

    return *promoted;
  }

  // The types are incompatible, check if it's ok for same-source pointers
  if (ptr_source.has_value() &&
      is_same_pointer_source(scoped_var, *ptr_source, type, current_type)) {
    return type;
  }

  error_node.addError() << "Type mismatch for " << var << ": "
                        << "trying to assign value of type '" << type
                        << "' when variable already has a type '"
                        << current_type << "'";
  return std::nullopt;
}

std::optional<SizedType> TypeGraph::get_map_value(
    const std::string map_name,
    const SizedType &type,
    Node &error_node,
    std::optional<GraphNode> ptr_source)
{
  auto value_name = get_map_value_name(map_name);

  auto locked_type = get_locked_node(value_name, type, error_node, map_name);
  if (locked_type) {
    return *locked_type;
  }

  auto current_type = get_resolved_type(value_name);

  auto add_error = [&]() {
    error_node.addError() << "Type mismatch for " << map_name << ": "
                          << "trying to assign value of type '" << type
                          << "' when map already has a type '" << current_type
                          << "'";
  };

  // @a = count();                  // OK
  // @a = 1; @b = count(); @a = @b; // OK
  // @b = count(); @a = @b;         // NOK
  // @a = 1; @a = count();          // NOK
  // @a = count(); @a = 1;          // NOK
  // @a = count(); @a = sum(5);     // NOK
  if (!current_type.IsIntegerTy() && current_type.IsCastableMapTy()) {
    add_error();
    return std::nullopt;
  }

  auto promoted = get_promoted_type(current_type, type);
  if (promoted) {
    if (promoted->IsPtrTy() && ptr_source.has_value()) {
      pointer_sources_[value_name] = *ptr_source;
    }

    return promoted;
  }

  // The types are incompatible, check if it's ok for same-source pointers
  if (ptr_source.has_value() &&
      is_same_pointer_source(value_name, *ptr_source, type, current_type)) {
    return type;
  }

  add_error();
  return std::nullopt;
}

std::optional<SizedType> TypeGraph::get_agg_map_value(
    const std::string map_name,
    const SizedType &type,
    Call &call)
{
  auto value_name = get_map_value_name(map_name);

  auto locked_type = get_locked_node(value_name, type, call, map_name);
  if (locked_type) {
    return *locked_type;
  }

  auto current_type = get_resolved_type(value_name);
  if (current_type.IsNoneTy()) {
    return type;
  }

  if (current_type.GetTy() == type.GetTy()) {
    auto promoted = get_promoted_type(current_type, type);
    if (promoted) {
      return promoted;
    }
  }

  call.addError() << "Type mismatch for " << map_name << ": "
                  << "trying to assign value of type '" << type
                  << "' when map already has a type '" << current_type << "'";
  return std::nullopt;
}

std::optional<SizedType> TypeGraph::get_map_key(
    const std::string map_name,
    const SizedType &type,
    Node &error_node,
    std::optional<GraphNode> ptr_source)
{
  auto val = map_metadata_.scalar.find(map_name);
  if (val != map_metadata_.scalar.end() && val->second) {
    // N.B. all scalar map keys are int64
    return CreateInt64();
  }

  auto key_name = get_map_key_name(map_name);

  auto locked_type = get_locked_node(key_name, type, error_node, map_name);
  if (locked_type) {
    return *locked_type;
  }

  auto current_type = get_resolved_type(key_name);
  auto promoted = get_promoted_type(current_type, type);
  if (promoted) {
    if (promoted->IsPtrTy() && ptr_source.has_value()) {
      pointer_sources_[key_name] = *ptr_source;
    }

    return promoted;
  }

  // The types are incompatible, check if it's ok for same-source pointers
  if (ptr_source.has_value() &&
      is_same_pointer_source(key_name, *ptr_source, type, current_type)) {
    return type;
  }

  error_node.addError() << "Argument mismatch for " << map_name << ": "
                        << "trying to access with arguments: '" << type
                        << "' when map expects arguments: '" << current_type
                        << "'";
  return std::nullopt;
}

void TypeGraph::add_resolved_type(const GraphNode &node, const SizedType &type)
{
  if (type.IsNoneTy()) {
    return;
  }
  resolved_types_[node] = type;
  queue_.emplace(node, type);
}

void TypeGraph::propagate_resolved_types()
{
  // BFS to avoid stale updates with statements like $a = 0; $a = $a + 1;
  while (!queue_.empty()) {
    auto [current_source, current_type] = std::move(queue_.front());
    queue_.pop();

    auto found = graph_.find(current_source);
    if (found == graph_.end()) {
      continue;
    }

    for (auto &consumer : found->second) {
      auto result_type = consumer.callback(current_type);
      if (result_type && !result_type->IsNoneTy()) {
        if (consumer.last_propagated == *result_type) {
          continue;
        }
        // N.B. this tracks the last edge type. We can't just use the consumer
        // because map nodes have two edges: the key type and the value type
        consumer.last_propagated = *result_type;
        resolved_types_[consumer.node] = *result_type;
        queue_.emplace(consumer.node, *result_type);
      }
    }
  }
}

void TypeGraph::add_consumer(const GraphNode &source, const GraphNode &consumer)
{
  graph_[source].emplace_back(consumer,
                              [](SizedType type) -> std::optional<SizedType> {
                                return type;
                              });
}

std::optional<SizedType> TypeGraph::get_locked_node(const GraphNode &node,
                                                    const SizedType &type,
                                                    Node &error_node,
                                                    const std::string &name)
{
  if (auto found_locked = locked_nodes_.find(node);
      found_locked != locked_nodes_.end()) {
    if (!type.FitsInto(found_locked->second)) {
      error_node.addError()
          << "Type mismatch for " << name << ": "
          << "this type has been locked because it was used "
             "in another part of the type graph that was already "
             "resolved (e.g. `sizeof`, `typeinfo`, etc.). The new type '"
          << type << "' doesn't fit into the locked type '"
          << found_locked->second << "'";
    }
    return found_locked->second;
  }
  return std::nullopt;
}

GraphNode TypeGraph::get_pointer_source(Expression &expr)
{
  if (auto *var_addr = expr.as<VariableAddr>()) {
    Node *addr_scope = find_variable_scope(var_addr->var->ident);
    return ScopedVariable{ addr_scope, var_addr->var->ident };
  } else if (auto *map_addr = expr.as<MapAddr>()) {
    return get_map_value_name(map_addr->map->ident);
  } else {
    return &expr.node();
  }
}

bool TypeGraph::is_same_pointer_source(const GraphNode &node_key,
                                       const GraphNode &ptr_source,
                                       const SizedType &incoming_type,
                                       const SizedType &current_type)
{
  if (!incoming_type.IsPtrTy() || !current_type.IsPtrTy()) {
    return false;
  }
  auto existing_source = pointer_sources_.find(node_key);
  if (existing_source == pointer_sources_.end()) {
    LOG(BUG) << "Original pointer source should exist";
  }
  return existing_source->second == ptr_source;
}

Probe *TypeGraph::get_probe()
{
  auto *probe = dynamic_cast<Probe *>(top_level_node_);
  return probe;
}

Probe *TypeGraph::get_probe(Node &node, std::string name)
{
  auto *probe = dynamic_cast<Probe *>(top_level_node_);
  if (probe == nullptr) {
    if (name.empty()) {
      node.addError() << "Feature not supported outside probe";
    } else {
      node.addError() << "Builtin " << name << " not supported outside probe";
    }
  }
  return probe;
}

void TypeGraph::check_stack_call(Call &call, bool kernel)
{
  call.return_type = CreateStack(kernel);
  StackType stack_type;
  stack_type.mode = bpftrace_.config_->stack_mode;

  switch (call.vargs.size()) {
    case 0:
      break;
    case 1: {
      if (auto *ident = call.vargs.at(0).as<Identifier>()) {
        ConfigParser<StackMode> parser;
        auto ok = parser.parse(call.func, &stack_type.mode, ident->ident);
        if (!ok) {
          ident->addError() << "Error parsing stack mode: " << ok.takeError();
        }
      } else if (auto *limit = call.vargs.at(0).as<Integer>()) {
        stack_type.limit = limit->value;
      } else {
        call.addError() << call.func << ": invalid limit value";
      }
      break;
    }
    case 2: {
      if (auto *ident = call.vargs.at(0).as<Identifier>()) {
        ConfigParser<StackMode> parser;
        auto ok = parser.parse(call.func, &stack_type.mode, ident->ident);
        if (!ok) {
          ident->addError() << "Error parsing stack mode: " << ok.takeError();
        }
      } else {
        call.addError() << "Expected stack mode as first argument";
      }
      if (auto *limit = call.vargs.at(1).as<Integer>()) {
        stack_type.limit = limit->value;
      } else {
        call.addError() << call.func << ": invalid limit value";
      }
      break;
    }
    default:
      call.addError() << "Invalid number of arguments";
      break;
  }
  constexpr int MAX_STACK_SIZE = 1024;
  if (stack_type.limit > MAX_STACK_SIZE) {
    call.addError() << call.func << "([int limit]): limit shouldn't exceed "
                    << MAX_STACK_SIZE << ", " << stack_type.limit << " given";
  }
  if (stack_type.mode == StackMode::build_id && kernel) {
    call.addError() << "'build_id' stack mode can only be used for ustack";
  }
  call.return_type = CreateStack(kernel, stack_type);
}

bool TypeGraph::resolve()
{
  propagate_resolved_types();

  // Apply resolved types to the AST nodes before further processing.
  TypeApplicator(resolved_types_).visit(ast_.root);

  if (!ast_.diagnostics().ok()) {
    return false;
  }

  // Create literals from expressions like `typeinfo`, `offsetof`, etc.
  // Also handles AST transformations like tuple/record comparisons.
  IntrospectionFolder folder(ast_, macro_registry_);
  folder.visit(ast_.root);
  needs_rerun_ = folder.had_transforms();
  // Fold literals like `comptime (typeof($a).base_ty == "int")`
  fold(ast_);

  return ast_.diagnostics().ok();
}

LockedNodes TypeGraph::get_locked_nodes()
{
  LockedNodes locked_nodes;
  for (auto &node : introspected_nodes_) {
    if (auto *scoped_var = std::get_if<ScopedVariable>(&node)) {
      auto type = get_resolved_type(*scoped_var);
      if (!type.IsNoneTy()) {
        locked_nodes.insert({ *scoped_var, type });
      }
    } else if (auto *map_ident = std::get_if<std::string>(&node)) {
      auto key_type = get_resolved_type(get_map_key_name(*map_ident));
      if (!key_type.IsNoneTy()) {
        locked_nodes.insert({ get_map_key_name(*map_ident), key_type });
      }
      auto value_type = get_resolved_type(get_map_value_name(*map_ident));
      if (!value_type.IsNoneTy()) {
        locked_nodes.insert({ get_map_value_name(*map_ident), value_type });
      }
    }
  }
  return locked_nodes;
}

Node *TypeGraph::find_variable_scope(const std::string &var_ident, bool safe)
{
  for (auto *scope : scope_stack_) {
    if (auto search_val = variables_[scope].find(var_ident);
        search_val != variables_[scope].end()) {
      return scope;
    }
  }
  if (safe) {
    LOG(BUG) << "No scope found for variable: " << var_ident;
  }
  return nullptr;
}

std::optional<Expression> IntrospectionFolder::visit(FieldAccess &acc)
{
  visit(acc.expr);

  // FieldAccesses will automatically resolve through any number of pointer
  // dereferences. For now, we inject the `Unop` operator directly, as codegen
  // stores the underlying structs as pointers anyways. In the future, we will
  // likely want to do this in a different way if we are tracking l-values.
  while (acc.expr.type().IsPtrTy()) {
    const auto &type = acc.expr.type();
    auto *unop = ast_.make_node<Unop>(acc.expr.node().loc,
                                      acc.expr,
                                      Operator::MUL);
    unop->result_type = type.GetPointeeTy();
    if (type.IsCtxAccess())
      unop->result_type.MarkCtxAccess();
    unop->result_type.is_internal = type.is_internal;
    unop->result_type.SetAS(type.GetAS());
    acc.expr.value = unop;
  }

  return std::nullopt;
}

std::optional<Expression> IntrospectionFolder::visit(Offsetof &offof)
{
  SizedType cstruct;
  if (std::holds_alternative<SizedType>(offof.record)) {
    cstruct = std::get<SizedType>(offof.record);
  } else {
    cstruct = std::get<Expression>(offof.record).type();
  }

  if (cstruct.IsNoneTy()) {
    return std::nullopt;
  }

  size_t offset = 0;
  for (const auto &field : offof.field) {
    if (!cstruct.IsCStructTy() || !cstruct.HasField(field)) {
      return std::nullopt;
    }
    const auto &f = cstruct.GetField(field);
    offset += f.offset;
    cstruct = f.type;
  }

  return ast_.make_node<Integer>(Location(offof.loc), offset);
}

std::optional<Expression> IntrospectionFolder::visit(Sizeof &szof)
{
  size_t size = 0;
  if (std::holds_alternative<SizedType>(szof.record)) {
    auto &ty = std::get<SizedType>(szof.record);
    if (ty.IsNoneTy()) {
      return std::nullopt;
    }
    size = ty.GetSize();
  } else {
    const auto &ty = std::get<Expression>(szof.record).type();
    if (ty.IsNoneTy()) {
      return std::nullopt;
    }
    size = ty.GetSize();
  }

  return ast_.make_node<Integer>(Location(szof.loc), size);
}

std::optional<Expression> IntrospectionFolder::visit(Typeinfo &typeinfo)
{
  if (typeinfo.typeof->type().IsNoneTy()) {
    return std::nullopt;
  }

  const auto &type = typeinfo.typeof->type();
  // We currently lack a globally-unique enumeration of types. For
  // simplicity, just use the type string with a placeholder identifier.
  auto *id = ast_.make_node<Integer>(typeinfo.loc, 0);
  auto *base_ty = ast_.make_node<String>(typeinfo.loc, to_string(type.GetTy()));
  auto *full_ty = ast_.make_node<String>(typeinfo.loc, typestr(type));

  std::vector<SizedType> elements = { CreateUInt64(),
                                      base_ty->type(),
                                      full_ty->type() };
  std::vector<std::string_view> names = { "btf_id", "base_type", "full_type" };

  auto record_type = CreateRecord(Struct::CreateRecord(elements, names));

  auto record = make_record(
      ast_,
      typeinfo.loc,
      { { "btf_id", id }, { "base_type", base_ty }, { "full_type", full_ty } });

  record->record_type = record_type;

  return record;
}

std::optional<Expression> IntrospectionFolder::visit(Expression &expr)
{
  auto r = Visitor<IntrospectionFolder, std::optional<Expression>>::visit(
      expr.value);
  if (r) {
    expr.value = r->value;
    if (had_transforms_) {
      expand_macro(ast_, expr, macro_registry_);
    }
  }
  return std::nullopt;
}

std::optional<Expression> IntrospectionFolder::visit(Binop &binop)
{
  visit(binop.left);
  visit(binop.right);

  if (binop.op != Operator::EQ && binop.op != Operator::NE)
    return std::nullopt;

  if (!binop.left.type().IsTupleTy() && !binop.left.type().IsRecordTy())
    return std::nullopt;

  if (!binop.left.type().IsCompatible(binop.right.type()))
    return std::nullopt;

  if (binop.left.is_literal() && binop.right.is_literal()) {
    // This will get folded.
    return std::nullopt;
  }

  bool is_tuple = binop.left.type().IsTupleTy();
  const auto &lht = binop.left.type();
  const auto &rht = binop.right.type();
  auto updatedTy = is_tuple ? get_promoted_tuple(lht, rht)
                            : get_promoted_record(lht, rht);
  if (!updatedTy) {
    binop.addError() << "Type mismatch for '" << opstr(binop) << "': comparing "
                     << lht << " with " << rht;
    return std::nullopt;
  }

  if (*updatedTy != lht) {
    if (is_tuple) {
      try_tuple_cast(ast_, binop.left, lht, *updatedTy);
    } else {
      try_record_cast(ast_, binop.left, lht, *updatedTy);
    }
  }
  if (*updatedTy != rht) {
    if (is_tuple) {
      try_tuple_cast(ast_, binop.right, rht, *updatedTy);
    } else {
      try_record_cast(ast_, binop.right, rht, *updatedTy);
    }
  }

  bool types_equal = binop.left.type() == binop.right.type();

  auto *size = ast_.make_node<Integer>(binop.loc,
                                       updatedTy->GetSize(),
                                       CreateUInt64());
  // N.B. if the types aren't equal at this point it means that
  // we're dealing with record types that are same except for
  // their fields are in a different order so we need to use a
  // different memcmp that saves off both the left and right to
  // variables but sets the type of the right variable to the left
  // before assignment (e.g. `let $right: typeof($left) = right;`)
  // as this ensures the temporary `$right` variable has the same
  // field ordering as the `$left`.
  auto *call = ast_.make_node<Call>(binop.loc,
                                    types_equal ? "memcmp" : "memcmp_record",
                                    ExpressionList{
                                        binop.left, binop.right, size });
  auto *typeof_node = ast_.make_node<Typeof>(binop.loc, CreateBool());
  auto *cast = ast_.make_node<Cast>(binop.loc, typeof_node, call);
  had_transforms_ = true;
  if (binop.op == Operator::NE) {
    return cast;
  } else {
    return ast_.make_node<Unop>(binop.loc, cast, Operator::LNOT);
  }
}

void TypeApplicator::visit(ArrayAccess &arr)
{
  Visitor<TypeApplicator>::visit(arr);
  apply(arr, arr.element_type);
}

void TypeApplicator::visit(Binop &binop)
{
  Visitor<TypeApplicator>::visit(binop);
  apply(binop, binop.result_type);
}

void TypeApplicator::visit(Builtin &builtin)
{
  apply(builtin, builtin.builtin_type);
}

void TypeApplicator::visit(Call &call)
{
  Visitor<TypeApplicator>::visit(call);
  apply(call, call.return_type);
}

void TypeApplicator::visit(FieldAccess &acc)
{
  Visitor<TypeApplicator>::visit(acc);
  apply(acc, acc.field_type);
}

void TypeApplicator::visit(IfExpr &if_expr)
{
  Visitor<TypeApplicator>::visit(if_expr);
  apply(if_expr, if_expr.result_type);
}

void TypeApplicator::visit(Identifier &identifier)
{
  apply(identifier, identifier.ident_type);
}

void TypeApplicator::visit(Map &map)
{
  auto key_it = resolved_types_.find(get_map_key_name(map.ident));
  if (key_it != resolved_types_.end()) {
    map.key_type = key_it->second;
  }
  auto val_it = resolved_types_.find(get_map_value_name(map.ident));
  if (val_it != resolved_types_.end()) {
    map.value_type = val_it->second;
  }

  if (map.value_type.IsNoneTy()) {
    map.addError() << "Undefined map: " + map.ident;
  }
}

void TypeApplicator::visit(MapAddr &map_addr)
{
  Visitor<TypeApplicator>::visit(map_addr);
  apply(map_addr, map_addr.map_addr_type);
}

void TypeApplicator::visit(Record &record)
{
  Visitor<TypeApplicator>::visit(record);
  apply(record, record.record_type);
}

void TypeApplicator::visit(Tuple &tuple)
{
  Visitor<TypeApplicator>::visit(tuple);
  apply(tuple, tuple.tuple_type);
}

void TypeApplicator::visit(TupleAccess &acc)
{
  Visitor<TypeApplicator>::visit(acc);
  apply(acc, acc.element_type);
}

void TypeApplicator::visit(Unop &unop)
{
  Visitor<TypeApplicator>::visit(unop);
  apply(unop, unop.result_type);
}

void TypeApplicator::visit(Variable &var)
{
  apply(var, var.var_type);
}

void TypeApplicator::visit(VariableAddr &var_addr)
{
  Visitor<TypeApplicator>::visit(var_addr);
  apply(var_addr, var_addr.var_addr_type);
}

Pass CreateTypeGraphPass()
{
  return Pass::create(
      "TypeGraph",
      [](ASTContext &ast,
         BPFtrace &b,
         MapMetadata &mm,
         CDefinitions &c_definitions,
         TypeMetadata &types,
         MacroRegistry &macro_registry) {
        // Fold up front
        fold(ast);

        auto type_graph = TypeGraph(
            ast, b, mm, c_definitions, types, macro_registry);
        type_graph.visit(ast.root);
        bool resolve_ok = type_graph.resolve();

        auto prev_comptimes = type_graph.get_unresolved_comptimes();
        LockedNodes locked_nodes = type_graph.get_locked_nodes();
        auto resolved_types = type_graph.get_resolved_types();

        bool should_rerun = prev_comptimes.size() > 0 ||
                            type_graph.needs_rerun();
        bool has_comptime_error = false;
        while (should_rerun && resolve_ok) {
          auto next_pass = TypeGraph(
              ast, b, mm, c_definitions, types, macro_registry, locked_nodes);
          next_pass.visit(ast.root);
          resolve_ok = next_pass.resolve();

          auto next_comptimes = next_pass.get_unresolved_comptimes();
          if (prev_comptimes == next_comptimes && !next_pass.needs_rerun()) {
            for (auto *comptime : next_comptimes) {
              comptime->addError() << "Unable to resolve comptime expression";
            }
            has_comptime_error = !next_comptimes.empty();
            break;
          }
          prev_comptimes = next_comptimes;
          locked_nodes = next_pass.get_locked_nodes();
          resolved_types = next_pass.get_resolved_types();
          should_rerun = prev_comptimes.size() > 0 || next_pass.needs_rerun();
        }

        if (has_comptime_error || !resolve_ok) {
          return;
        }

        TypeApplicator(resolved_types).visit(ast.root);
        CastCreator(ast, b).visit(ast.root);
      });
};

} // namespace bpftrace::ast
