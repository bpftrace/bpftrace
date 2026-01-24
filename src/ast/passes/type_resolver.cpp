#include "ast/passes/type_resolver.h"
#include "ast/ast.h"
#include "ast/async_event_types.h"
#include "ast/passes/ast_transformer.h"
#include "ast/passes/cast_creator.h"
#include "ast/passes/clang_parser.h"
#include "ast/passes/fold_literals.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/named_param.h"
#include "ast/passes/type_applicator.h"
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

namespace bpftrace::ast {

namespace {

std::unordered_set<std::string> VOID_RETURNING_FUNCS = {
  "join", "printf", "errorf", "warnf", "system", "cat",     "debugf",
  "exit", "print",  "clear",  "zero",  "time",   "unwatch", "fail"
};

std::unordered_map<std::string, SizedType (*)()> SIMPLE_BUILTIN_TYPES = {
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

std::unordered_map<std::string, SizedType (*)()> SIMPLE_CALL_TYPES = {
  { "ksym", CreateKSym },          { "usym", CreateUSym },
  { "cgroupid", CreateUInt64 },    { "cgroup_path", CreateCgroupPath },
  { "stack_len", CreateInt64 },    { "strftime", CreateTimestamp },
  { "macaddr", CreateMacAddress }, { "skboutput", CreateUInt32 },
  { "strncmp", CreateUInt64 },     { "socket_cookie", CreateUInt64 },
};

const std::unordered_map<Type, std::string_view> AGGREGATE_HINTS{
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

struct TypeRule {
  TypeVariable output;
  std::vector<TypeVariable> inputs;
  std::function<SizedType(const std::vector<SizedType> &)> resolve;
};

class TypeResolver {
public:
  void set_type(const TypeVariable &node, const SizedType &type)
  {
    if (type.IsNoneTy()) {
      return;
    }
    types_[node] = type;
    seeded_nodes_.push_back(node);
  }

  const SizedType &get_type(const TypeVariable &node) const
  {
    static const SizedType none_type = CreateNone();
    auto it = types_.find(node);
    return it != types_.end() ? it->second : none_type;
  }

  void add_type_rule(TypeRule type_rule)
  {
    size_t idx = type_rules_.size();
    for (const auto &input : type_rule.inputs) {
      dependents_[input].push_back(idx);
    }
    type_rules_.push_back(std::move(type_rule));
  }

  void add_pass_through(const TypeVariable &source, const TypeVariable &target)
  {
    add_type_rule({
        .output = target,
        .inputs = { source },
        .resolve = [](const std::vector<SizedType> &inputs) -> SizedType {
          return inputs[0];
        },
    });
  }

  void resolve(const std::unordered_set<std::string> &map_value_names)
  {
    // Seed worklist from nodes that were set during the visit phase,
    // in the order they were set (preserves AST visitation order).
    for (const auto &node : seeded_nodes_) {
      enqueue_dependents(node);
    }

    while (!worklist_.empty()) {
      auto idx = worklist_.front();
      worklist_.pop();
      in_worklist_.erase(idx);

      auto &type_rule = type_rules_[idx];

      // Check all inputs are resolved
      std::vector<SizedType> input_types;
      input_types.reserve(type_rule.inputs.size());
      bool all_resolved = true;
      for (const auto &input : type_rule.inputs) {
        const auto &t = get_type(input);
        if (t.IsNoneTy()) {
          all_resolved = false;
          break;
        }
        input_types.push_back(t);
      }
      if (!all_resolved) {
        continue;
      }

      auto result_type = type_rule.resolve(input_types);
      if (result_type.IsNoneTy()) {
        continue;
      }

      // N.B. this is ok because nothing lists AST Map nodes as a dependent. AST
      // Map nodes have two types (key type and value type) so storing and
      // referencing a single type for an AST Map node is not correct
      const auto &current_type = types_[type_rule.output];

      // TODO: further investigate and fix this weirdness with address space and
      // ctx access
      if (current_type == result_type &&
          current_type.IsCtxAccess() == result_type.IsCtxAccess() &&
          (current_type.GetAS() == result_type.GetAS() ||
           current_type.GetAS() != AddrSpace::none)) {
        continue;
      }

      types_[type_rule.output] = result_type;
      enqueue_dependents(type_rule.output);
    }

    // There are some map expressions that self initialize, e.g. `@a++` or `@a
    // +=1` and there are no other assignments to them. Treat these as holding
    // an int64 value type and try again to resolve them
    bool had_unresolved_map_values = false;
    for (const auto &name : map_value_names) {
      const auto &current_type = get_type(name);
      if (current_type.IsNoneTy()) {
        had_unresolved_map_values = true;
        set_type(name, CreateInt64());
      }
    }
    if (had_unresolved_map_values) {
      // Re-run the solve
      resolve(map_value_names);
    }
  }

  const ResolvedTypes &get_resolved_types() const
  {
    return types_;
  }

private:
  ResolvedTypes types_;
  std::vector<TypeVariable> seeded_nodes_;
  std::vector<TypeRule> type_rules_;
  std::unordered_map<TypeVariable, std::vector<size_t>, TypeVariableHash>
      dependents_;
  std::queue<size_t> worklist_;
  std::unordered_set<size_t> in_worklist_;

  void enqueue_dependents(const TypeVariable &node)
  {
    auto it = dependents_.find(node);
    if (it == dependents_.end())
      return;
    for (auto idx : it->second) {
      if (in_worklist_.insert(idx).second) {
        worklist_.push(idx);
      }
    }
  }
};

using LockedNodes =
    std::unordered_map<TypeVariable, SizedType, TypeVariableHash>;

class TypeRuleCollector : public Visitor<TypeRuleCollector> {
public:
  explicit TypeRuleCollector(ASTContext &ast,
                             BPFtrace &bpftrace,
                             MapMetadata &map_metadata,
                             CDefinitions &c_definitions,
                             NamedParamDefaults &named_param_defaults,
                             TypeMetadata &type_metadata,
                             const MacroRegistry &macro_registry,
                             TypeResolver &resolver,
                             LockedNodes locked_nodes = {})
      : ast_(ast),
        bpftrace_(bpftrace),
        map_metadata_(map_metadata),
        c_definitions_(c_definitions),
        named_param_defaults_(named_param_defaults),
        type_metadata_(type_metadata),
        macro_registry_(macro_registry),
        resolver_(resolver),
        locked_nodes_(std::move(locked_nodes))
  {
  }

  using Visitor<TypeRuleCollector>::visit;
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
  void visit(PositionalParameter &param);
  void visit(PositionalParameterCount &param);
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

  LockedNodes get_locked_nodes();

  const std::vector<Comptime *> &get_unresolved_comptimes() const
  {
    return unresolved_comptimes_;
  }

  const std::unordered_set<std::string> &get_map_value_names() const
  {
    return map_value_names_;
  }

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
  MapMetadata &map_metadata_;
  CDefinitions &c_definitions_;
  NamedParamDefaults &named_param_defaults_;
  TypeMetadata &type_metadata_;
  const MacroRegistry &macro_registry_;
  TypeResolver &resolver_;
  const LockedNodes locked_nodes_;
  std::unordered_map<Node *, std::unordered_map<std::string, SizedType>>
      variables_;
  std::unordered_set<std::string> map_value_names_;
  std::map<Node *, CollectNodes<Variable>> for_vars_referenced_;
  // These are variables that have a declaration with a type with a SIZE
  // let $a: uint16; // type with a size
  // let $a; // no type no size
  // let $a: string // type but no size
  std::unordered_set<ScopedVariable, ScopedVariableHash> sized_decl_vars_;
  std::vector<Node *> scope_stack_;
  Probe *probe_ = nullptr;
  std::string func_; // tracks Call context for Identifier resolution
  int introspection_level_ = 0;
  // Only includes ScopedVariables and map keys/value strings
  std::unordered_set<TypeVariable, TypeVariableHash> introspected_nodes_;

  std::vector<Comptime *> unresolved_comptimes_;

  // This is for tracking type compatibilty for the arguments passed to map
  // aggregate functions, e.g. `sum`, `avg`, etc.
  // `sum((uint64)1)` is not compatible with `sum((int64)-1)`
  std::unordered_map<std::string, SizedType> agg_map_args_;

  // Cached map name strings to avoid repeated allocations
  std::unordered_map<std::string, std::string> map_key_name_cache_;
  std::unordered_map<std::string, std::string> map_value_name_cache_;

  const std::string &map_key_name(const std::string &ident)
  {
    auto [it, inserted] = map_key_name_cache_.try_emplace(ident);
    if (inserted) {
      it->second = get_map_key_name(ident);
    }
    return it->second;
  }

  const std::string &map_value_name(const std::string &ident)
  {
    auto [it, inserted] = map_value_name_cache_.try_emplace(ident);
    if (inserted) {
      it->second = get_map_value_name(ident);
    }
    return it->second;
  }

  bool resolve_struct_type(SizedType &type, Node &node);
  bool check_offsetof_type(Offsetof &offof, SizedType cstruct);

  SizedType get_var_type(const ScopedVariable &scoped_var,
                         const SizedType &type,
                         Node &error_node);
  SizedType get_map_value_type(const std::string &map_name,
                               const SizedType &type,
                               Node &error_node);
  SizedType get_agg_map_type(const std::string &map_name,
                             const SizedType &type,
                             Call &call);
  SizedType get_map_key_type(const std::string &map_name,
                             const SizedType &type,
                             Node &error_node);
  void check_unresolved_maps();
  Node *find_variable_scope(const std::string &var_ident, bool safe = true);
  SizedType get_locked_node(const TypeVariable &node,
                            const SizedType &type,
                            Node &error_node,
                            const std::string &name);
  Probe *get_probe();
  Probe *get_probe(Node &node, std::string name = "");
  void check_stack_call(Call &call, bool kernel);
};

SizedType binop_ptr(Binop &binop, const SizedType &lht, const SizedType &rht)
{
  bool left_is_ptr = lht.IsPtrTy();
  const auto &ptr = left_is_ptr ? lht : rht;
  const auto &other = left_is_ptr ? rht : lht;

  bool compare = is_comparison_op(binop.op);
  bool logical = binop.op == Operator::LAND || binop.op == Operator::LOR;

  auto invalid_op = [&binop, &lht, &rht]() -> SizedType {
    binop.addError() << "The " << opstr(binop)
                     << " operator can not be used on expressions of types "
                     << lht << ", " << rht;
    return CreateNone();
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
      if (lht.IsSigned()) {
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
  if (lht.IsSigned() || rht.IsSigned()) {
    return CreateInt64();
  }

  return CreateUInt64();
}

SizedType get_binop_type(Binop &binop,
                         const SizedType &lht,
                         const SizedType &rht)
{
  bool is_comparison = is_comparison_op(binop.op);

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
    auto int_type = binop_int(binop, lht, rht);
    int_type.SetAS(result_type.GetAS());
    return int_type;
  }

  return result_type;
}

bool TypeRuleCollector::check_offsetof_type(Offsetof &offof, SizedType cstruct)
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
  if (type.IsVoidTy()) {
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

void TypeRuleCollector::visit(ArrayAccess &arr)
{
  visit(arr.expr);
  visit(arr.indexpr);

  resolver_.add_type_rule({
      .output = &arr,
      .inputs = { &arr.expr.node() },
      .resolve = [&arr](const std::vector<SizedType> &inputs) -> SizedType {
        const auto &type = inputs[0];
        SizedType elem;
        if (type.IsArrayTy()) {
          elem = type.GetElementTy();
        } else if (type.IsPtrTy()) {
          elem = type.GetPointeeTy();
        } else if (type.IsStringTy()) {
          elem = CreateInt8();
        } else if (type.IsTupleTy()) {
          if (auto *integer = arr.indexpr.as<Integer>()) {
            if (static_cast<ssize_t>(integer->value) >= type.GetFieldCount()) {
              arr.addError()
                  << "Invalid tuple index: " << integer->value << ". Found "
                  << type.GetFields().size() << " elements in tuple.";
            } else {
              elem = type.GetField(integer->value).type;
            }
          }
        } else {
          arr.addError() << "The array index operator [] can only be "
                            "used on arrays, pointers, and tuples, found "
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
      },
  });
}

void TypeRuleCollector::visit(AssignMapStatement &assignment)
{
  visit(assignment.map_access);
  visit(assignment.expr);

  auto map_name = assignment.map_access->map->ident;
  const auto &value_name = map_value_name(map_name);

  resolver_.add_type_rule({
      .output = value_name,
      .inputs = { &assignment.expr.node() },
      .resolve = [this, &assignment, map_name](
                     const std::vector<SizedType> &inputs) -> SizedType {
        const auto &type = inputs[0];
        const auto &value_name = map_value_name(map_name);
        const auto &current_type = resolver_.get_type(value_name);

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

          return CreateNone();
        }

        return get_map_value_type(map_name, type, assignment);
      },
  });
}

void TypeRuleCollector::visit(AssignVarStatement &assignment)
{
  visit(assignment.expr);
  visit(assignment.var_decl);

  Node *var_scope = find_variable_scope(assignment.var()->ident);
  ScopedVariable scoped_var = std::make_pair(var_scope,
                                             assignment.var()->ident);

  // Ignore the RHS to determine the type of this variable and issue errors
  // later if the RHS type is not compatible or doesn't fit into this sized
  // declaration type
  if (sized_decl_vars_.contains(scoped_var)) {
    return;
  }

  resolver_.add_type_rule({
      .output = scoped_var,
      .inputs = { &assignment.expr.node() },
      .resolve = [this, &assignment, scoped_var](
                     const std::vector<SizedType> &inputs) -> SizedType {
        const auto &type = inputs[0];
        if (!is_valid_assignment(type, resolver_.get_type(scoped_var))) {
          assignment.addError()
              << "Value '" << type
              << "' cannot be assigned to a scratch variable.";
          return CreateNone();
        }

        return get_var_type(scoped_var, type, assignment);
      },
  });
}

void TypeRuleCollector::visit(Builtin &builtin)
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
  resolver_.set_type(&builtin, builtin_type);
}

void TypeRuleCollector::visit(Call &call)
{
  // RAII setter for func_ context (used by Identifier resolution)
  struct func_setter {
    func_setter(TypeRuleCollector &pass, const std::string &s)
        : pass_(pass), old_func_(pass_.func_)
    {
      pass_.func_ = s;
    }

    ~func_setter()
    {
      pass_.func_ = old_func_;
    }

  private:
    TypeRuleCollector &pass_;
    std::string old_func_;
  };

  func_setter scope_bound_func_setter{ *this, call.func };

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
        resolver_.add_type_rule({
            .output = map_value_name(map_name),
            .inputs = { &call },
            .resolve = [this, &call, map_name](
                           const std::vector<SizedType> &) -> SizedType {
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

              return get_agg_map_type(map_name, agg_type, call);
            },
        });
      } else {
        // N.B. @a = sum(5); gets desugared to _ = sum(@x, 0, 5); so we have to
        // set the consumer of this map aggregate function to be the map value
        // name directly and also add the resolved call type in the callback
        resolver_.add_type_rule({
            .output = map_value_name(map_name),
            .inputs = { &call.vargs.at(2).node() },
            .resolve = [this, &call, map_name](
                           const std::vector<SizedType> &inputs) -> SizedType {
              const auto &type = inputs[0];
              if (!type.IsIntegerTy()) {
                call.addError()
                    << call.func << "() only supports integer arguments ("
                    << type << " provided)";
                return CreateNone();
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

              // Check if the arguments passed are compatible with each other
              auto found = agg_map_args_.find(map_name);
              if (found == agg_map_args_.end()) {
                agg_map_args_[map_name] = type;
              } else {
                auto promoted = get_promoted_type(found->second, type);
                if (!promoted) {
                  call.addError() << "Type mismatch for " << call.func << ": "
                                  << "trying to call function with type '"
                                  << type << "' when it already has a type '"
                                  << found->second << "'";
                  return CreateNone();
                } else {
                  found->second = *promoted;
                }
              }

              return get_agg_map_type(map_name, agg_type, call);
            },
        });
      }

      // 2nd arg is the key
      resolver_.add_type_rule({
          .output = map_key_name(map_name),
          .inputs = { &call.vargs.at(1).node() },
          .resolve = [this, &call, map_name](
                         const std::vector<SizedType> &inputs) -> SizedType {
            return get_map_key_type(map_name, inputs[0], call);
          },
      });

      resolver_.set_type(&call, CreateVoid());
    } else {
      call.vargs.at(0).node().addError()
          << call.func << "() expects a map argument";
    }
  } else {
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
        resolver_.add_type_rule({
            .output = &call,
            .inputs = { &call.vargs.at(0).node() },
            .resolve = [this, &call, max_buffer_size](
                           const std::vector<SizedType> &inputs) -> SizedType {
              const auto &type = inputs[0];
              uint32_t buffer_size = max_buffer_size;
              if (type.IsArrayTy()) {
                buffer_size = type.GetNumElements() *
                              type.GetElementTy().GetSize();
              }
              buffer_size = std::min(buffer_size, max_buffer_size);

              auto return_type = CreateBuffer(buffer_size);
              return_type.SetAS(AddrSpace::kernel);
              return return_type;
            },
        });
        return;
      } else if (call.vargs.size() == 2) {
        if (auto *integer = call.vargs.at(1).as<Integer>()) {
          buffer_size = integer->value;
        }
      }

      buffer_size = std::min(buffer_size, max_buffer_size);

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
          call.addError()
              << call.func
              << "() expects an string literal at the first argument";
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
      if (probe_) {
        ProbeType pt = probe_->get_probetype();
        return_type.SetAS(find_addrspace(pt));
      } else {
        return_type.SetAS(AddrSpace::kernel);
      }
    } else if (call.func == "kaddr" || call.func == "percpu_kaddr") {
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
      resolver_.add_type_rule({
          .output = &call,
          .inputs = { &call.vargs.at(0).node() },
          .resolve =
              [this, &call](const std::vector<SizedType> &inputs) -> SizedType {
            auto result = inputs[0];
            result.SetAS(call.func == "kptr" ? AddrSpace::kernel
                                             : AddrSpace::user);
            return result;
          },
      });
      return;
    } else if (call.func == "bswap") {
      resolver_.add_type_rule({
          .output = &call,
          .inputs = { &call.vargs.at(0).node() },
          .resolve =
              [this, &call](const std::vector<SizedType> &inputs) -> SizedType {
            const auto &type = inputs[0];
            auto int_bit_width = 1;
            if (!type.IsIntTy()) {
              call.addError()
                  << call.func << "() only supports integer arguments ("
                  << type.GetTy() << " provided)";
              return CreateNone();
            }
            int_bit_width = type.GetIntBitWidth();
            return CreateUInt(int_bit_width);
          },
      });
      return;
    } else if (call.func == "nsecs") {
      if (call.vargs.size() == 1) {
        resolver_.add_type_rule({
            .output = &call,
            .inputs = { &call.vargs.at(0).node() },
            .resolve = [this, &call](
                           const std::vector<SizedType> &inputs) -> SizedType {
              auto ret_type = CreateUInt64();
              ret_type.ts_mode = inputs[0].ts_mode;
              return ret_type;
            },
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
      resolver_.set_type(&call, return_type);
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
      resolver_.set_type(&call, *compat_return_type);
    }
  }
}

void TypeRuleCollector::visit(Binop &op)
{
  visit(op.left);
  visit(op.right);

  resolver_.add_type_rule({
      .output = &op,
      .inputs = { &op.left.node(), &op.right.node() },
      .resolve = [&op](const std::vector<SizedType> &inputs) -> SizedType {
        return get_binop_type(op, inputs[0], inputs[1]);
      },
  });
}

void TypeRuleCollector::visit(BlockExpr &block)
{
  scope_stack_.push_back(&block);
  visit(block.stmts);
  visit(block.expr);

  resolver_.add_pass_through(&block.expr.node(), &block);
  scope_stack_.pop_back();
}

void TypeRuleCollector::visit(Boolean &boolean)
{
  resolver_.set_type(&boolean, boolean.type());
}

SizedType update_cast_expr(const SizedType &cast_ty,
                           const SizedType &expr_ty,
                           Probe *probe)
{
  auto updated_ty = cast_ty;
  if (updated_ty.IsArrayTy()) {
    if (updated_ty.GetNumElements() == 0) {
      if (updated_ty.GetElementTy().GetSize() != 0) {
        if (expr_ty.GetSize() % updated_ty.GetElementTy().GetSize() == 0) {
          // casts to unsized arrays (e.g. int8[]) need to determine size from
          // RHS
          auto num_elems = expr_ty.GetSize() /
                           updated_ty.GetElementTy().GetSize();
          updated_ty = CreateArray(num_elems, updated_ty.GetElementTy());
        }
      }
    }

    if (expr_ty.IsIntTy() || expr_ty.IsBoolTy())
      updated_ty.is_internal = true;
  }

  if (expr_ty.IsCtxAccess() && !updated_ty.IsIntTy()) {
    updated_ty.MarkCtxAccess();
  }
  updated_ty.SetAS(expr_ty.GetAS());
  // case : begin { @foo = (struct Foo)0; }
  // case : profile:hz:99 $task = (struct task_struct *)curtask.
  if (updated_ty.GetAS() == AddrSpace::none) {
    if (probe) {
      ProbeType type = probe->get_probetype();
      updated_ty.SetAS(find_addrspace(type));
    } else {
      // Assume kernel space for data in subprogs.
      updated_ty.SetAS(AddrSpace::kernel);
    }
  }
  return updated_ty;
}

void TypeRuleCollector::visit(Cast &cast)
{
  visit(cast.expr);

  // Account for the race condition whereby the expression type may resolve
  // before the cast type even though they both need resolution to determine the
  // final cast type, e.g. `@ = (int8[])"hello"`
  resolver_.add_type_rule({
      .output = &cast,
      .inputs = { &cast.expr.node() },
      .resolve = [this,
                  &cast](const std::vector<SizedType> &inputs) -> SizedType {
        const auto &expr_ty = inputs[0];
        const auto &cast_ty = resolver_.get_type(&cast);
        return update_cast_expr(cast_ty, expr_ty, probe_);
      },
  });

  if (std::holds_alternative<SizedType>(cast.typeof->record)) {
    auto &ty = std::get<SizedType>(cast.typeof->record);
    if (!resolve_struct_type(ty, *cast.typeof)) {
      return;
    }
    const auto &expr_ty = resolver_.get_type(&cast.expr.node());
    if (!expr_ty.IsNoneTy()) {
      ty = update_cast_expr(ty, expr_ty, probe_);
    }
    resolver_.set_type(&cast, ty);
  } else {
    visit(cast.typeof);
    resolver_.add_type_rule({
        .output = &cast,
        .inputs = { cast.typeof },
        .resolve = [this,
                    &cast](const std::vector<SizedType> &inputs) -> SizedType {
          const auto &cast_ty = inputs[0];
          const auto &expr_ty = resolver_.get_type(&cast.expr.node());

          if (!expr_ty.IsNoneTy()) {
            return update_cast_expr(cast_ty, expr_ty, probe_);
          }
          return cast_ty;
        },
    });
  }
}

void TypeRuleCollector::visit(Comptime &comptime)
{
  visit(comptime.expr);
  unresolved_comptimes_.emplace_back(&comptime);
}

void TypeRuleCollector::visit(ExprStatement &expr)
{
  visit(expr.expr);
}

void TypeRuleCollector::visit(FieldAccess &acc)
{
  visit(acc.expr);

  resolver_.add_type_rule({
      .output = &acc,
      .inputs = { &acc.expr.node() },
      .resolve = [this,
                  &acc](const std::vector<SizedType> &inputs) -> SizedType {
        const auto &expr_type_in = inputs[0];
        // FieldAccesses will automatically resolve through any number of
        // pointer dereferences. For now, we inject the `Unop` operator
        // in AstTransformer, as codegen stores the underlying structs as
        // pointers anyways. In the future, we will likely want to do this in a
        // different way if we are tracking l-values.
        bool is_ctx = expr_type_in.IsCtxAccess();
        bool is_internal = expr_type_in.is_internal;
        auto expr_type = expr_type_in;
        while (expr_type.IsPtrTy()) {
          expr_type = expr_type.GetPointeeTy();
        }

        SizedType result_type = CreateNone();

        if (!expr_type.IsCStructTy() && !expr_type.IsRecordTy()) {
          acc.addError() << "Can not access field '" << acc.field
                         << "' on expression of type '" << expr_type << "'";
          return CreateNone();
        }

        if (expr_type.is_funcarg) {
          auto *probe = get_probe();
          if (probe == nullptr) {
            return CreateNone();
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
          return CreateNone();
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
          return CreateNone();
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
          if (is_ctx &&
              (result_type.IsArrayTy() || result_type.IsCStructTy())) {
            // e.g., ((struct bpf_perf_event_data*)ctx)->regs.ax
            result_type.MarkCtxAccess();
          }
          result_type.is_internal = is_internal;
          result_type.SetAS(expr_type.GetAS());

          return result_type;
        }
      },
  });
}

SizedType get_range_type(const SizedType &start_type,
                         const SizedType &end_type,
                         Range *range)
{
  if (!start_type.IsIntTy()) {
    range->addError() << "Loop range requires an integer for the start value";
  }
  if (!end_type.IsIntTy()) {
    range->addError() << "Loop range requires an integer for the end value";
  }

  auto range_type = start_type;
  if (start_type.IsIntTy() && end_type.IsIntTy()) {
    if (start_type.GetSize() > end_type.GetSize() ||
        start_type.GetSize() < end_type.GetSize()) {
      auto promoted = get_promoted_type(start_type, end_type);
      if (promoted) {
        range_type = *promoted;
      }
    }
  }

  return range_type;
}

void TypeRuleCollector::visit(For &f)
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
    const auto &key_name = map_key_name(map->ident);
    const auto &value_name = map_value_name(map->ident);
    resolver_.add_type_rule({
        .output = scoped_var,
        .inputs = { key_name, value_name },
        .resolve = [map](const std::vector<SizedType> &inputs) -> SizedType {
          const auto &key_type = inputs[0];
          const auto &value_type = inputs[1];
          if (!value_type.IsMapIterableTy()) {
            map->addError()
                << "Loop expression does not support type: " << value_type;
          }
          return CreateTuple(Struct::CreateTuple({ key_type, value_type }));
        },
    });

  } else if (auto *range = f.iterable.as<Range>()) {
    visit(range->start);
    visit(range->end);
    resolver_.add_type_rule({
        .output = scoped_var,
        .inputs = { &range->start.node(), &range->end.node() },
        .resolve = [range](const std::vector<SizedType> &inputs) -> SizedType {
          return get_range_type(inputs[0], inputs[1], range);
        },
    });
  }

  scope_stack_.push_back(&f);

  visit(f.block);

  scope_stack_.pop_back();

  {
    std::vector<TypeVariable> ctx_inputs;
    for (Variable &var : collector.nodes()) {
      ctx_inputs.emplace_back(&var);
    }
    if (!ctx_inputs.empty()) {
      resolver_.add_type_rule({
          .output = &f,
          .inputs = std::move(ctx_inputs),
          .resolve = [this, &f](const std::vector<SizedType> &) -> SizedType {
            // Finally, create the context tuple now that all variables
            // inside the loop have been resolved.
            std::vector<SizedType> ctx_types;
            std::vector<std::string_view> ctx_idents;
            auto [iter, _] = for_vars_referenced_.try_emplace(&f);
            auto &collector = iter->second;
            for (const Variable &var : collector.nodes()) {
              const auto &var_type = resolver_.get_type(
                  const_cast<Node *>(static_cast<const Node *>(&var)));
              ctx_types.push_back(CreatePointer(var_type, AddrSpace::none));
              ctx_idents.push_back(var.ident);
            }

            f.ctx_type = CreateCStruct(
                Struct::CreateRecord(ctx_types, ctx_idents));
            // Nothing should be dependent upon this for loop
            return CreateNone();
          },
      });
    }
  }

  // Create an empty ctx struct in case there are no referenced vars in the loop
  // body
  std::vector<SizedType> ctx_types;
  std::vector<std::string_view> ctx_idents;
  f.ctx_type = CreateCStruct(Struct::CreateRecord(ctx_types, ctx_idents));
}

void TypeRuleCollector::visit(Identifier &identifier)
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

  resolver_.set_type(&identifier, ident_type);
}

void TypeRuleCollector::visit(IfExpr &if_expr)
{
  if (auto *comptime = if_expr.cond.as<Comptime>()) {
    visit(comptime->expr);
    unresolved_comptimes_.emplace_back(comptime);
    return; // Skip visiting this `if` for now.
  }

  visit(if_expr.cond);
  visit(if_expr.left);
  visit(if_expr.right);

  resolver_.add_type_rule({
      .output = &if_expr,
      .inputs = { &if_expr.left.node() },
      .resolve = [&if_expr,
                  this](const std::vector<SizedType> &inputs) -> SizedType {
        const auto &left_type = inputs[0];
        const auto &current = resolver_.get_type(&if_expr);
        auto promoted = get_promoted_type(current, left_type);
        if (!promoted) {
          if_expr.addError()
              << "Branches must return the same type or compatible types: "
              << "have '" << left_type << "' and '" << current << "'";
          return CreateNone();
        }
        return *promoted;
      },
  });

  resolver_.add_type_rule({
      .output = &if_expr,
      .inputs = { &if_expr.right.node() },
      .resolve = [&if_expr,
                  this](const std::vector<SizedType> &inputs) -> SizedType {
        const auto &right_type = inputs[0];
        const auto &current = resolver_.get_type(&if_expr);
        auto promoted = get_promoted_type(current, right_type);
        if (!promoted) {
          if_expr.addError()
              << "Branches must return the same type or compatible types: "
              << "have '" << current << "' and '" << right_type << "'";
          return CreateNone();
        }
        return *promoted;
      },
  });
}

void TypeRuleCollector::visit(Integer &integer)
{
  resolver_.set_type(&integer, integer.type());
}

void TypeRuleCollector::visit(Jump &jump)
{
  if (jump.ident == JumpType::RETURN) {
    visit(jump.return_value);
  }
}

void TypeRuleCollector::visit(Map &map)
{
  if (map_metadata_.bad_indexed_access.contains(&map)) {
    map.addError()
        << map.ident
        << " used as a map without an explicit key (scalar map), previously "
           "used with an explicit key (non-scalar map)";
    return;
  }

  const auto &key_name = map_key_name(map.ident);
  const auto &value_name = map_value_name(map.ident);

  // N.B. No pass throughs or TypeRules are added for AST map nodes. This is
  // because consumers should only ever depend on the map key name or the map
  // value name. Functions like `print` and `clear` that use AST Map nodes
  // (instead of map access) don't actually require the value or key types.

  map_value_names_.insert(value_name);

  // Named param maps (from getopt()) are read-only and have their types pre-set
  // by the NamedParamsPass.
  // TODO: consider passing these values in NamedParamDefaults instead of
  // setting them on the AST
  if (named_param_defaults_.defaults.contains(map.ident) &&
      !map.value_type.IsNoneTy()) {
    resolver_.set_type(value_name, map.value_type);
    resolver_.set_type(key_name, map.key_type);
  }

  if (introspection_level_ > 0) {
    introspected_nodes_.insert(map.ident);
  }
}

void TypeRuleCollector::visit(MapAccess &acc)
{
  visit(acc.map);
  visit(acc.key);

  if (map_metadata_.bad_scalar_access.contains(acc.map)) {
    acc.addError() << acc.map->ident
                   << " used as a map with an explicit key (non-scalar map), "
                      "previously used without an explicit key (scalar map)";
    return;
  }

  const auto &key_name = map_key_name(acc.map->ident);

  resolver_.add_type_rule({
      .output = key_name,
      .inputs = { &acc.key.node() },
      .resolve = [this, &acc, key_name](
                     const std::vector<SizedType> &inputs) -> SizedType {
        const auto &type = inputs[0];
        if (!is_valid_assignment(type, resolver_.get_type(key_name))) {
          acc.addError() << "Value '" << type
                         << "' cannot be used as a map key.";
          return CreateNone();
        }

        return get_map_key_type(acc.map->ident, type, acc);
      },
  });

  resolver_.add_pass_through(map_value_name(acc.map->ident), &acc);
}

void TypeRuleCollector::visit(MapAddr &map_addr)
{
  visit(map_addr.map);

  // This needs to be fixed as neither the map value or map key are the actual
  // map's type
  resolver_.add_type_rule({
      .output = &map_addr,
      .inputs = { map_value_name(map_addr.map->ident) },
      .resolve = [](const std::vector<SizedType> &inputs) -> SizedType {
        const auto &type = inputs[0];
        return CreatePointer(type, type.GetAS());
      },
  });
}

void TypeRuleCollector::visit(NegativeInteger &integer)
{
  resolver_.set_type(&integer, integer.type());
}

void TypeRuleCollector::visit(PositionalParameter &param)
{
  resolver_.set_type(&param, CreateInt64());
}

void TypeRuleCollector::visit(PositionalParameterCount &param)
{
  resolver_.set_type(&param, CreateUInt64());
}

void TypeRuleCollector::visit(Offsetof &offof)
{
  // This type will change later depending on what integer literal it resolves
  // to in AstTransformer but for now set it to the smallest uint
  if (std::holds_alternative<SizedType>(offof.record)) {
    auto &ty = std::get<SizedType>(offof.record);
    resolve_struct_type(ty, offof);
    if (!check_offsetof_type(offof, ty)) {
      return;
    }
    resolver_.set_type(&offof, CreateUInt8());
  } else {
    auto &expr = std::get<Expression>(offof.record);
    ++introspection_level_;
    visit(expr);
    --introspection_level_;
    resolver_.add_type_rule({
        .output = &offof,
        .inputs = { &expr.node() },
        .resolve = [this,
                    &offof](const std::vector<SizedType> &inputs) -> SizedType {
          auto local_type = inputs[0];
          resolve_struct_type(local_type, offof);
          if (!check_offsetof_type(offof, local_type)) {
            return CreateNone();
          }
          return CreateUInt8();
        },
    });
  }
}

void TypeRuleCollector::visit(Probe &probe)
{
  probe_ = &probe;
  visit(probe.attach_points);
  visit(probe.block);
}

void TypeRuleCollector::visit(Record &record)
{
  std::vector<TypeVariable> inputs;
  for (auto *named_arg : record.elems) {
    visit(named_arg->expr);
    inputs.emplace_back(&named_arg->expr.node());
  }

  resolver_.add_type_rule({
      .output = &record,
      .inputs = std::move(inputs),
      .resolve = [&record](const std::vector<SizedType> &inputs) -> SizedType {
        std::vector<SizedType> elements;
        std::vector<std::string_view> names;
        for (size_t i = 0; i < record.elems.size(); ++i) {
          elements.emplace_back(inputs[i]);
          names.emplace_back(record.elems[i]->name);
        }
        return CreateRecord(Struct::CreateRecord(elements, names));
      },
  });
}

void TypeRuleCollector::visit(Sizeof &szof)
{
  if (std::holds_alternative<SizedType>(szof.record)) {
    auto &ty = std::get<SizedType>(szof.record);
    resolve_struct_type(ty, szof);
    resolver_.set_type(&szof, ty);
  } else {
    auto &expr = std::get<Expression>(szof.record);
    ++introspection_level_;
    visit(expr);
    --introspection_level_;
    resolver_.add_type_rule({
        .output = &szof,
        .inputs = { &expr.node() },
        .resolve = [&szof](const std::vector<SizedType> &) -> SizedType {
          // This will change later depending on
          // what integer literal it resolves to
          // for now set it to the smallest uint
          return CreateUInt8();
        },
    });
  }
}

void TypeRuleCollector::visit(String &str)
{
  auto type = str.type();
  type.SetAS(AddrSpace::kernel);
  resolver_.set_type(&str, type);
}

void TypeRuleCollector::visit(Subprog &subprog)
{
  // Note that we visit the subprogram and process arguments *after*
  // constructing the stack with the variable states. This is because the
  // arguments, etc. may have types defined in terms of the arguments
  // themselves. We already handle detecting circular dependencies.
  scope_stack_.push_back(&subprog);
  probe_ = nullptr;

  for (SubprogArg *arg : subprog.args) {
    ScopedVariable scoped_var = std::make_pair(&subprog, arg->var->ident);

    if (std::holds_alternative<SizedType>(arg->typeof->record)) {
      auto &ty = std::get<SizedType>(arg->typeof->record);
      if (resolve_struct_type(ty, *arg->typeof)) {
        resolver_.set_type(scoped_var, ty);
        if (ty.GetSize() != 0) {
          sized_decl_vars_.insert(scoped_var);
        }
      }
    } else {
      sized_decl_vars_.insert(scoped_var);
      visit(arg->typeof);
      resolver_.add_pass_through(arg->typeof, scoped_var);
    }

    visit(arg->var);
  }

  visit(subprog.block);
  visit(subprog.return_type);

  scope_stack_.pop_back();
}

void TypeRuleCollector::visit(Typeof &typeof)
{
  if (std::holds_alternative<SizedType>(typeof.record)) {
    auto &ty = std::get<SizedType>(typeof.record);
    resolve_struct_type(ty, typeof);
    resolver_.set_type(&typeof, ty);
  } else {
    auto &expr = std::get<Expression>(typeof.record);
    ++introspection_level_;
    visit(expr);
    --introspection_level_;

    if (auto *map = expr.as<Map>()) {
      // Typeof for a raw (scalar) map returns the key type.
      // Subscribe directly to the map's key name to avoid getting the
      // value type (both propagate through the Map node).
      resolver_.add_pass_through(map_key_name(map->ident), &typeof);
    } else {
      resolver_.add_pass_through(&expr.node(), &typeof);
    }
  }
}

void TypeRuleCollector::visit(Tuple &tuple)
{
  std::vector<TypeVariable> inputs;
  for (auto &elem : tuple.elems) {
    visit(elem);
    inputs.emplace_back(&elem.node());
  }

  resolver_.add_type_rule({
      .output = &tuple,
      .inputs = std::move(inputs),
      .resolve = [&tuple](const std::vector<SizedType> &inputs) -> SizedType {
        return CreateTuple(Struct::CreateTuple(
            std::vector<SizedType>(inputs.begin(), inputs.end())));
      },
  });
}

void TypeRuleCollector::visit(TupleAccess &acc)
{
  visit(acc.expr);

  resolver_.add_type_rule({
      .output = &acc,
      .inputs = { &acc.expr.node() },
      .resolve = [&acc](const std::vector<SizedType> &inputs) -> SizedType {
        const auto &type = inputs[0];
        if (!type.IsTupleTy()) {
          return CreateNone();
        }

        if (acc.index >= type.GetFields().size()) {
          return CreateNone();
        }

        return type.GetField(acc.index).type;
      },
  });
}

void TypeRuleCollector::visit(Typeinfo &typeinfo)
{
  ++introspection_level_;
  visit(typeinfo.typeof);
  --introspection_level_;
  resolver_.add_type_rule({
      .output = &typeinfo,
      .inputs = { typeinfo.typeof },
      .resolve = [](const std::vector<SizedType> &inputs) -> SizedType {
        const auto &type = inputs[0];
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
      },
  });
}

void TypeRuleCollector::visit(Unop &unop)
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
  // assignments whereby we set the type of the unop expression and create a
  // chain that attemps to assign this integer type to the stored map value or
  // variable. This enables us to get error messages on the correct node if we
  // attempt to increment a string or some other invalid type.
  if (is_inc_dec_op) {
    if (auto *acc = unop.expr.as<MapAccess>()) {
      auto map_name = acc->map->ident;

      resolver_.add_type_rule({
          .output = map_value_name(map_name),
          .inputs = { &unop },
          .resolve = [this, &unop, map_name](
                         const std::vector<SizedType> &inputs) -> SizedType {
            const auto &type = inputs[0];
            const auto &current_type = resolver_.get_type(
                map_value_name(map_name));
            if (current_type.IsPtrTy()) {
              return current_type;
            }
            return get_map_value_type(map_name, type, unop);
          },
      });

      resolver_.add_type_rule({
          .output = &unop,
          .inputs = { &unop.expr.node() },
          .resolve =
              [&unop](const std::vector<SizedType> &inputs) -> SizedType {
            return inputs[0].IsSigned() ? CreateInt64() : CreateUInt64();
          },
      });

      return;
    } else if (auto *var = unop.expr.as<Variable>()) {
      Node *scope = find_variable_scope(var->ident);
      ScopedVariable scoped_var = std::make_pair(scope, var->ident);

      resolver_.add_type_rule({
          .output = scoped_var,
          .inputs = { &unop },
          .resolve = [this, &unop, scoped_var](
                         const std::vector<SizedType> &inputs) -> SizedType {
            const auto &type = inputs[0];
            if (sized_decl_vars_.contains(scoped_var)) {
              return CreateNone();
            }

            const auto &current_type = resolver_.get_type(scoped_var);
            if (current_type.IsPtrTy()) {
              return current_type;
            }

            return get_var_type(scoped_var, type, unop);
          },
      });

      resolver_.add_type_rule({
          .output = &unop,
          .inputs = { &unop.expr.node() },
          .resolve = [this, &unop, scoped_var](
                         const std::vector<SizedType> &inputs) -> SizedType {
            const auto &type = inputs[0];
            const auto &current_type = resolver_.get_type(scoped_var);
            if (sized_decl_vars_.contains(scoped_var) ||
                current_type.IsPtrTy()) {
              return current_type;
            }

            return type.IsSigned() ? CreateInt64() : CreateUInt64();
          },
      });

      return;
    } else {
      unop.addError() << "The " << opstr(unop)
                      << " operator must be applied to a map or variable";
    }
  }

  auto valid_ptr_op = unop.op == Operator::MUL;

  resolver_.add_type_rule({
      .output = &unop,
      .inputs = { &unop.expr.node() },
      .resolve = [&unop, valid_ptr_op](
                     const std::vector<SizedType> &inputs) -> SizedType {
        const auto &type = inputs[0];
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
          return CreateNone();
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
          result = type.IsSigned() ? CreateInt64() : CreateUInt64();
        }

        return result;
      },
  });
}

void TypeRuleCollector::visit(VarDeclStatement &decl)
{
  if (find_variable_scope(decl.var->ident, false) != nullptr) {
    LOG(BUG) << "Variable shadowing should have been caught by now";
  }

  if (!decl.typeof) {
    // If the declaration has no type then we can rely on the assignments to
    // this variable to determine the type.
    visit(decl.var);
    return;
  }

  auto *scope = scope_stack_.back();
  ScopedVariable scoped_var = std::make_pair(scope, decl.var->ident);

  if (std::holds_alternative<SizedType>(decl.typeof->record)) {
    auto &ty = std::get<SizedType>(decl.typeof->record);
    if (!resolve_struct_type(ty, *decl.typeof)) {
      return;
    }
    resolver_.set_type(scoped_var, ty);
    // Some declared types like 'string' have no size so we can factor in the
    // size of the assignment
    if (ty.GetSize() != 0) {
      sized_decl_vars_.insert(scoped_var);
    }
  } else {
    sized_decl_vars_.insert(scoped_var);
    visit(decl.typeof);
    resolver_.add_pass_through(decl.typeof, scoped_var);
  }

  visit(decl.var);
}

void TypeRuleCollector::visit(Variable &var)
{
  Node *scope = find_variable_scope(var.ident, false);
  if (scope == nullptr) {
    scope = scope_stack_.back();
  }
  variables_[scope].insert({ var.ident, CreateNone() });

  ScopedVariable scoped_var = std::make_pair(scope, var.ident);

  resolver_.add_pass_through(scoped_var, &var);

  if (introspection_level_ > 0) {
    introspected_nodes_.insert(scoped_var);
  }
}

void TypeRuleCollector::visit(VariableAddr &var_addr)
{
  visit(var_addr.var);
  resolver_.add_type_rule({
      .output = &var_addr,
      .inputs = { var_addr.var },
      .resolve = [](const std::vector<SizedType> &inputs) -> SizedType {
        const auto &type = inputs[0];
        return CreatePointer(type, type.GetAS());
      },
  });
}

bool TypeRuleCollector::resolve_struct_type(SizedType &type, Node &node)
{
  SizedType inner_type = type;
  int pointer_level = 0;
  while (inner_type.IsPtrTy()) {
    inner_type = inner_type.GetPointeeTy();
    pointer_level++;
  }

  bool is_array = false;
  size_t num_elements = 0;
  if (inner_type.IsArrayTy()) {
    num_elements = inner_type.GetNumElements();
    inner_type = inner_type.GetElementTy();
    is_array = true;
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
      }
    } else {
      type = CreateCStruct(inner_type.GetName(), struct_type);
    }
    if (is_array) {
      type = CreateArray(num_elements, type);
    }
    while (pointer_level > 0) {
      type = CreatePointer(type);
      pointer_level--;
    }
  }
  return true;
}

SizedType TypeRuleCollector::get_var_type(const ScopedVariable &scoped_var,
                                          const SizedType &type,
                                          Node &error_node)
{
  const auto &var = scoped_var.second;

  auto locked_type = get_locked_node(scoped_var, type, error_node, var);
  if (!locked_type.IsNoneTy()) {
    return locked_type;
  }

  const auto &current_type = resolver_.get_type(scoped_var);
  auto promoted = get_promoted_type(current_type, type);
  if (promoted) {
    return *promoted;
  }

  error_node.addError() << "Type mismatch for " << var << ": "
                        << "trying to assign value of type '" << type
                        << "' when variable already has a type '"
                        << current_type << "'";
  return CreateNone();
}

SizedType TypeRuleCollector::get_map_value_type(const std::string &map_name,
                                                const SizedType &type,
                                                Node &error_node)
{
  const auto &value_name = map_value_name(map_name);

  auto locked_type = get_locked_node(value_name, type, error_node, map_name);
  if (!locked_type.IsNoneTy()) {
    return locked_type;
  }

  const auto &current_type = resolver_.get_type(value_name);

  auto add_error = [&]() {
    error_node.addError() << "Type mismatch for " << map_name << ": "
                          << "trying to assign value of type '" << type
                          << "' when map already has a type '" << current_type
                          << "'";
  };

  if (current_type.IsCastableMapTy()) {
    add_error();
    return CreateNone();
  }

  auto promoted = get_promoted_type(current_type, type);
  if (promoted) {
    // Data stored in a BPF map is internal (managed by BPF runtime), so
    // structs and arrays should be marked as such.
    if (promoted->IsCStructTy() || promoted->IsArrayTy()) {
      promoted->is_internal = true;
    }

    return *promoted;
  }

  add_error();
  return CreateNone();
}

SizedType TypeRuleCollector::get_agg_map_type(const std::string &map_name,
                                              const SizedType &type,
                                              Call &call)
{
  const auto &value_name = map_value_name(map_name);

  auto locked_type = get_locked_node(value_name, type, call, map_name);
  if (!locked_type.IsNoneTy()) {
    return locked_type;
  }

  const auto &current_type = resolver_.get_type(value_name);
  if (current_type.IsNoneTy()) {
    return type;
  }

  if (current_type.GetTy() == type.GetTy()) {
    auto promoted = get_promoted_type(current_type, type);
    if (promoted) {
      return *promoted;
    }
  }

  call.addError() << "Type mismatch for " << map_name << ": "
                  << "trying to assign value of type '" << type
                  << "' when map already has a type '" << current_type << "'";
  return CreateNone();
}

SizedType TypeRuleCollector::get_map_key_type(const std::string &map_name,
                                              const SizedType &type,
                                              Node &error_node)
{
  auto val = map_metadata_.scalar.find(map_name);
  if (val != map_metadata_.scalar.end() && val->second) {
    // N.B. all scalar map keys are int64
    return CreateInt64();
  }

  const auto &key_name = map_key_name(map_name);

  auto locked_type = get_locked_node(key_name, type, error_node, map_name);
  if (!locked_type.IsNoneTy()) {
    return locked_type;
  }

  const auto &current_type = resolver_.get_type(key_name);
  auto promoted = get_promoted_type(current_type, type);
  if (promoted) {
    return *promoted;
  }

  error_node.addError() << "Argument mismatch for " << map_name << ": "
                        << "trying to access with arguments: '" << type
                        << "' when map expects arguments: '" << current_type
                        << "'";
  return CreateNone();
}

SizedType TypeRuleCollector::get_locked_node(const TypeVariable &node,
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
  return CreateNone();
}

Probe *TypeRuleCollector::get_probe()
{
  return probe_;
}

Probe *TypeRuleCollector::get_probe(Node &node, std::string name)
{
  if (probe_ == nullptr) {
    if (name.empty()) {
      node.addError() << "Feature not supported outside probe";
    } else {
      node.addError() << "Builtin " << name << " not supported outside probe";
    }
  }
  return probe_;
}

void TypeRuleCollector::check_stack_call(Call &call, bool kernel)
{
  call.return_type = CreateStack(kernel);
  StackType stack_type;
  stack_type.mode = bpftrace_.config_->stack_mode;

  auto nargs = call.vargs.size();
  if (nargs > 2) {
    call.addError() << "Invalid number of arguments";
  } else {
    // First arg can be a stack mode identifier or an integer limit
    size_t limit_arg = 0;
    if (nargs >= 1) {
      if (auto *ident = call.vargs.at(0).as<Identifier>()) {
        ConfigParser<StackMode> parser;
        auto ok = parser.parse(call.func, &stack_type.mode, ident->ident);
        if (!ok) {
          ident->addError() << "Error parsing stack mode: " << ok.takeError();
        }
        limit_arg = 1;
      } else if (nargs == 2) {
        call.addError() << "Expected stack mode as first argument";
        limit_arg = 1;
      }
    }
    // Parse the limit from whichever arg position it's at
    if (limit_arg < nargs) {
      if (auto *limit = call.vargs.at(limit_arg).as<Integer>()) {
        stack_type.limit = limit->value;
      } else {
        call.addError() << call.func << ": invalid limit value";
      }
    }
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

LockedNodes TypeRuleCollector::get_locked_nodes()
{
  LockedNodes locked_nodes = locked_nodes_;
  for (const auto &node : introspected_nodes_) {
    if (const auto *scoped_var = std::get_if<ScopedVariable>(&node)) {
      const auto &type = resolver_.get_type(*scoped_var);
      if (!type.IsNoneTy()) {
        locked_nodes.insert({ *scoped_var, type });
      }
    } else if (const auto *map_ident = std::get_if<std::string>(&node)) {
      const auto &key_type = resolver_.get_type(map_key_name(*map_ident));
      if (!key_type.IsNoneTy()) {
        locked_nodes.insert({ map_key_name(*map_ident), key_type });
      }
      const auto &value_type = resolver_.get_type(map_value_name(*map_ident));
      if (!value_type.IsNoneTy()) {
        locked_nodes.insert({ map_value_name(*map_ident), value_type });
      }
    }
  }
  return locked_nodes;
}

Node *TypeRuleCollector::find_variable_scope(const std::string &var_ident,
                                             bool safe)
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

// This pass consists of 4 visitors:
// - TypeRuleCollector
// - AstTransformer
// - TypeApplicator
// - CastCreator
// Read more about how all this works in type_resolution.md
Pass CreateTypeResolverPass()
{
  return Pass::create(
      "TypeResolver",
      [](ASTContext &ast,
         BPFtrace &b,
         MapMetadata &mm,
         CDefinitions &c_definitions,
         NamedParamDefaults &named_param_defaults,
         TypeMetadata &types,
         MacroRegistry &macro_registry) {
        // Fold up front
        fold(ast);

        // Passed to TypeApplicator when all runs are complete
        ResolvedTypes resolved_types;

        std::vector<Comptime *> prev_comptimes;
        LockedNodes locked_nodes;

        bool should_rerun = true; // First run
        // This is just a safety mechanism so we don't spin forever
        constexpr int MAX_ITERATIONS = 50;
        int iteration = 0;

        while (should_rerun) {
          if (++iteration > MAX_ITERATIONS) {
            ast.diagnostics().addError(ast.root->loc)
                << "Type resolution exceeded maximum iterations ("
                << MAX_ITERATIONS
                << "); possible infinite loop in comptime expressions";
            return;
          }

          TypeResolver resolver;
          auto tr_collector = TypeRuleCollector(ast,
                                                b,
                                                mm,
                                                c_definitions,
                                                named_param_defaults,
                                                types,
                                                macro_registry,
                                                resolver,
                                                locked_nodes);
          // Collect the TypeRules (TypeVariable → TypeRules)
          tr_collector.visit(ast.root);

          // Resolve the TypeRules collected by the TypeRuleCollector
          // and generate a set of types for our TypeVariables
          resolver.resolve(tr_collector.get_map_value_names());

          if (!ast.diagnostics().ok()) {
            return;
          }

          resolved_types = resolver.get_resolved_types();

          // Create literals from expressions like `typeinfo`, `offsetof`, etc.
          // Also handles AST transformations like tuple/record comparisons.
          AstTransformer transformer(ast, macro_registry, resolved_types);
          transformer.visit(ast.root);

          // Fold literals like `comptime (typeof($a).base_ty == "int")` that
          // relied on type information to resolve
          fold(ast);

          if (!ast.diagnostics().ok()) {
            return;
          }

          // Check if we haven't made progress resolving comptime expressions
          auto next_comptimes = tr_collector.get_unresolved_comptimes();
          if (!next_comptimes.empty() && prev_comptimes == next_comptimes &&
              !transformer.had_transforms()) {
            for (auto *comptime : next_comptimes) {
              comptime->addError() << "Unable to resolve comptime expression";
            }
            return;
          }

          prev_comptimes = next_comptimes;
          locked_nodes = tr_collector.get_locked_nodes();

          // Check if there are unresolved comptime expressions or there were
          // AST transformations, if so we need to re-run everything above
          should_rerun = !prev_comptimes.empty() ||
                         transformer.had_transforms();
        }

        // Add the types to the AST nodes themselves
        TypeApplicator(resolved_types).visit(ast.root);

        // Apply casts in parts of the AST where we want the left and right
        // sides to have the same type
        CastCreator(ast, b).visit(ast.root);
      });
};

} // namespace bpftrace::ast
