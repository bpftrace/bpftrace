
#include <algorithm>

#include "ast/async_event_types.h"
#include "ast/codegen_helper.h"
#include "ast/passes/resource_analyser.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"
#include "required_resources.h"
#include "struct.h"

namespace libbpf {
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace::ast {

namespace {

// Determines if all map accesses are well bounded. If the map is accessed
// exactly as key zero, then this makes `@` and `@[0]` equivalent.
//
// In the future, this could be used to scale maps that are accessed within
// fixed ranges, for now this is used to determine if the map is a scalar.
class MapBounds : public Visitor<MapBounds> {
public:
  using Visitor<MapBounds>::visit;
  void visit(MapAccess &map)
  {
    if (auto *integer = map.key.as<Integer>()) {
      max[map.map->ident] = std::max(max[map.map->ident], integer->value);
    } else {
      max[map.map->ident] = std::numeric_limits<uint64_t>::max();
    }
  }
  bool is_scalar(const std::string &name)
  {
    return max[name] == 0;
  }

private:
  std::unordered_map<std::string, uint64_t> max;
};

// Resource analysis pass on AST
//
// This pass collects information on what runtime resources a script needs.
// For example, how many maps to create, what sizes the keys and values are,
// all the async printf argument types, etc.
//
// TODO(danobi): Note that while complete resource collection in this pass is
// the goal, there are still places where the goal is not yet realized. For
// example the helper error metadata is still being collected during codegen.
class ResourceAnalyser : public Visitor<ResourceAnalyser> {
public:
  ResourceAnalyser(BPFtrace &bpftrace);

  using Visitor<ResourceAnalyser>::visit;
  void visit(Probe &probe);
  void visit(Subprog &subprog);
  void visit(Builtin &builtin);
  void visit(Call &call);
  void visit(Map &map);
  void visit(MapAccess &acc);
  void visit(MapDeclStatement &decl);
  void visit(Tuple &tuple);
  void visit(For &f);
  void visit(Ternary &ternary);
  void visit(AssignMapStatement &assignment);
  void visit(AssignVarStatement &assignment);
  void visit(VarDeclStatement &decl);
  void visit(Program &prog);

  // This will move the compute resources value, it should be called only
  // after the top-level visit.
  RequiredResources resources();

private:
  MapBounds map_bounds_;

  // Determines whether the given function uses userspace symbol resolution.
  // This is used later for loading the symbol table into memory.
  bool uses_usym_table(const std::string &fun);

  bool exceeds_stack_limit(size_t size);

  void maybe_allocate_map_key_buffer(const Map &map,
                                     const Expression &key_expr);

  void update_map_info(Map &map);
  void update_variable_info(Variable &var);

  RequiredResources resources_;
  BPFtrace &bpftrace_;
  // Current probe we're analysing
  Probe *probe_{ nullptr };
  std::unordered_map<std::string, std::pair<libbpf::bpf_map_type, int>>
      map_decls_;

  int next_map_id_ = 0;
};

} // namespace

// This helper differs from SemanticAnalyser::single_provider_type() in that
// for situations where a single probetype is required we assume the AST is
// well formed.
static ProbeType single_provider_type_postsema(Probe *probe)
{
  if (!probe->attach_points.empty()) {
    return probetype(probe->attach_points.at(0)->provider);
  }

  return ProbeType::invalid;
}

ResourceAnalyser::ResourceAnalyser(BPFtrace &bpftrace) : bpftrace_(bpftrace)
{
}

RequiredResources ResourceAnalyser::resources()
{
  if (resources_.max_fmtstring_args_size > 0) {
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::FMT_STRINGS_BUFFER);
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::MAX_CPU_ID);
  }

  if (resources_.max_tuple_size > 0) {
    assert(resources_.tuple_buffers > 0);
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::TUPLE_BUFFER);
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::MAX_CPU_ID);
  }

  if (resources_.str_buffers > 0) {
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::GET_STR_BUFFER);
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::MAX_CPU_ID);
  }

  if (resources_.max_read_map_value_size > 0) {
    assert(resources_.read_map_value_buffers > 0);
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::READ_MAP_VALUE_BUFFER);
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::MAX_CPU_ID);
  }

  if (resources_.max_write_map_value_size > 0) {
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::WRITE_MAP_VALUE_BUFFER);
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::MAX_CPU_ID);
  }

  if (resources_.max_variable_size > 0) {
    assert(resources_.variable_buffers > 0);
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::VARIABLE_BUFFER);
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::MAX_CPU_ID);
  }

  if (resources_.max_map_key_size > 0) {
    assert(resources_.map_key_buffers > 0);
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::MAP_KEY_BUFFER);
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::MAX_CPU_ID);
  }

  return std::move(resources_);
}

void ResourceAnalyser::visit(Probe &probe)
{
  probe_ = &probe;
  Visitor<ResourceAnalyser>::visit(probe);
}

void ResourceAnalyser::visit(Subprog &subprog)
{
  probe_ = nullptr;
  Visitor<ResourceAnalyser>::visit(subprog);
}

void ResourceAnalyser::visit(Builtin &builtin)
{
  if (uses_usym_table(builtin.ident)) {
    // mark probe as using usym, so that the symbol table can be pre-loaded
    // and symbols resolved even when unavailable at resolution time
    resources_.probes_using_usym.insert(probe_);
  }
}

void ResourceAnalyser::visit(Call &call)
{
  Visitor<ResourceAnalyser>::visit(call);

  if (call.func == "printf" || call.func == "system" || call.func == "cat" ||
      call.func == "debugf") {
    // Implicit first field is the 64bit printf ID.
    //
    // Put it in initially so that offset and alignment calculation is
    // accurate. We'll take it out before saving into resources.
    std::vector<SizedType> args = { CreateInt64() };

    // NOTE: the same logic can be found in the semantic_analyser pass
    for (auto it = call.vargs.begin() + 1; it != call.vargs.end(); it++) {
      // Promote to 64-bit if it's not an aggregate type
      SizedType ty = it->type(); // copy
      if (!ty.IsAggregate() && !ty.IsTimestampTy())
        ty.SetSize(8);

      args.push_back(ty);
    }

    // It may seem odd that we're creating a tuple as part of format
    // string analysis, but it kinda makes sense. When we transmit
    // the format string from kernelspace to userspace, we are basically
    // creating a tuple. Namely: a bunch of values without names, back to
    // back, and with struct alignment rules.
    //
    // Thus, we are good to reuse the padding logic present in tuple
    // creation to generate offsets for each argument in the args "tuple".
    auto tuple = Struct::CreateTuple(args);

    // Remove implicit printf ID field. Downstream consumers do not
    // expect it nor do they care about it.
    tuple->fields.erase(tuple->fields.begin());

    // Keep track of max "tuple" size needed for fmt string args. Codegen
    // will use this information to create a percpu array map of large
    // enough size for all fmt string calls to use.
    const auto tuple_size = static_cast<uint64_t>(tuple->size);
    if (exceeds_stack_limit(tuple_size)) {
      resources_.max_fmtstring_args_size = std::max(
          resources_.max_fmtstring_args_size,
          static_cast<uint64_t>(tuple_size));
    }

    auto fmtstr = call.vargs.at(0).as<String>()->value;
    if (call.func == "printf") {
      if (probe_ != nullptr &&
          single_provider_type_postsema(probe_) == ProbeType::iter) {
        resources_.bpf_print_fmts.emplace_back(fmtstr);
      } else {
        resources_.printf_args.emplace_back(fmtstr, tuple->fields);
      }
    } else if (call.func == "debugf") {
      resources_.bpf_print_fmts.emplace_back(fmtstr);
    } else if (call.func == "system") {
      resources_.system_args.emplace_back(fmtstr, tuple->fields);
    } else {
      resources_.cat_args.emplace_back(fmtstr, tuple->fields);
    }
  } else if (call.func == "join") {
    auto delim = call.vargs.size() > 1 ? call.vargs.at(1).as<String>()->value
                                       : " ";
    resources_.join_args.push_back(delim);
  } else if (call.func == "count" || call.func == "sum" || call.func == "min" ||
             call.func == "max" || call.func == "avg") {
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::NUM_CPUS);
  } else if (call.func == "hist") {
    Map *map = call.vargs.at(0).as<Map>();
    uint64_t bits = call.vargs.at(1).as<Integer>()->value;
    auto args = HistogramArgs{
      .bits = static_cast<long>(bits),
    };

    auto &map_info = resources_.maps_info[map->ident];
    if (!std::holds_alternative<std::monostate>(map_info.detail) &&
        (!std::holds_alternative<HistogramArgs>(map_info.detail) ||
         std::get<HistogramArgs>(map_info.detail) != args)) {
      call.addError() << "Different bits in a single hist unsupported";
    } else {
      map_info.detail.emplace<HistogramArgs>(args);
    }
  } else if (call.func == "lhist") {
    Map *map = call.vargs.at(0).as<Map>();
    Expression &min_arg = call.vargs.at(1);
    Expression &max_arg = call.vargs.at(2);
    Expression &step_arg = call.vargs.at(3);
    auto &min = *min_arg.as<Integer>();
    auto &max = *max_arg.as<Integer>();
    auto &step = *step_arg.as<Integer>();
    auto args = LinearHistogramArgs{
      .min = static_cast<long>(min.value),
      .max = static_cast<long>(max.value),
      .step = static_cast<long>(step.value),
    };

    auto &map_info = resources_.maps_info[map->ident];
    if (!std::holds_alternative<std::monostate>(map_info.detail) &&
        (!std::holds_alternative<LinearHistogramArgs>(map_info.detail) ||
         std::get<LinearHistogramArgs>(map_info.detail) != args)) {
      call.addError() << "Different lhist bounds in a single map unsupported";
    } else {
      map_info.detail.emplace<LinearHistogramArgs>(args);
    }
  } else if (call.func == "time") {
    if (!call.vargs.empty())
      resources_.time_args.push_back(call.vargs.at(0).as<String>()->value);
    else
      resources_.time_args.emplace_back("%H:%M:%S\n");
  } else if (call.func == "strftime") {
    resources_.strftime_args.push_back(call.vargs.at(0).as<String>()->value);
  } else if (call.func == "print") {
    constexpr auto nonmap_headroom = sizeof(AsyncEvent::PrintNonMap);
    auto &arg = call.vargs.at(0);
    if (arg.is<Map>()) {
      resources_.non_map_print_args.push_back(arg.type());
      const size_t fmtstring_args_size = nonmap_headroom + arg.type().GetSize();
      if (exceeds_stack_limit(fmtstring_args_size)) {
        resources_.max_fmtstring_args_size = std::max<uint64_t>(
            resources_.max_fmtstring_args_size, fmtstring_args_size);
      }
    }
  } else if (call.func == "cgroup_path") {
    if (call.vargs.size() > 1)
      resources_.cgroup_path_args.push_back(
          call.vargs.at(1).as<String>()->value);
    else
      resources_.cgroup_path_args.emplace_back("*");
  } else if (call.func == "skboutput") {
    const auto &file = call.vargs.at(0).as<String>()->value;
    const auto &offset = call.vargs.at(3).as<Integer>()->value;

    resources_.skboutput_args_.emplace_back(file, offset);
    resources_.needs_perf_event_map = true;
  } else if (call.func == "delete") {
    auto &arg0 = call.vargs.at(0);
    auto &map = *arg0.as<Map>();
    if (exceeds_stack_limit(map.value_type.GetSize())) {
      resources_.max_write_map_value_size = std::max(
          resources_.max_write_map_value_size, map.value_type.GetSize());
    }
  } else if (call.func == "print" || call.func == "clear" ||
             call.func == "zero") {
    if (auto *map = call.vargs.at(0).as<Map>()) {
      auto &name = map->ident;
      auto &map_info = resources_.maps_info[name];
      if (map_info.id == -1)
        map_info.id = next_map_id_++;
    }
  } else if (call.func == "str" || call.func == "buf" || call.func == "path") {
    const auto max_strlen = bpftrace_.config_->max_strlen;
    if (exceeds_stack_limit(max_strlen))
      resources_.str_buffers++;

    // Aggregation functions like count/sum/max are always called like:
    //   @ = count()
    // Thus, we visit AssignMapStatement AST node which visits the map and
    // assigns a map key buffer. Thus, there is no need to assign another
    // buffer here.
    //
    // The exceptions are:
    // 1. lhist/hist because the map key buffer includes both the key itself
    //    and the bucket ID from a call to linear/log2 functions.
    // 2. has_key/delete because the map key buffer allocation depends on
    //    arguments to the function e.g.
    //      delete(@, 2)
    //    requires a map key buffer to hold arg1 = 2 but map.key_expr is null
    //    so the map key buffer check in visit(Map &map) doesn't work as is.
  } else if (call.func == "lhist" || call.func == "hist") {
    auto &map = *call.vargs.at(0).as<Map>();
    // Allocation is always needed for lhist/hist. But we need to allocate
    // space for both map key and the bucket ID from a call to linear/log2
    // functions.
    const auto map_key_size = map.key_type.GetSize() + CreateUInt64().GetSize();
    if (exceeds_stack_limit(map_key_size)) {
      resources_.map_key_buffers++;
      resources_.max_map_key_size = std::max(resources_.max_map_key_size,
                                             map_key_size);
    }
  } else if (call.func == "has_key") {
    auto &map = *call.vargs.at(0).as<Map>();
    auto &key_expr = call.vargs.at(1);
    // has_key does not work on scalar maps (e.g. @a = 1), so we
    // don't need to check if map.key_expr is set
    if (needMapKeyAllocation(map, key_expr) &&
        exceeds_stack_limit(map.key_type.GetSize())) {
      resources_.map_key_buffers++;
      resources_.max_map_key_size = std::max(resources_.max_map_key_size,
                                             map.key_type.GetSize());
    }
  } else if (call.func == "delete") {
    auto &map = *call.vargs.at(0).as<Map>();
    auto &key_expr = call.vargs.at(1);
    const auto deleteNeedMapKeyAllocation = needMapKeyAllocation(map, key_expr);
    // delete always expects a map and key, so we don't need to check if
    // map.key_expr is set
    if (deleteNeedMapKeyAllocation &&
        exceeds_stack_limit(map.key_type.GetSize())) {
      resources_.map_key_buffers++;
      resources_.max_map_key_size = std::max(resources_.max_map_key_size,
                                             map.key_type.GetSize());
    }
  }

  if (uses_usym_table(call.func)) {
    // mark probe as using usym, so that the symbol table can be pre-loaded
    // and symbols resolved even when unavailable at resolution time
    resources_.probes_using_usym.insert(probe_);
  }
}

void ResourceAnalyser::visit(MapDeclStatement &decl)
{
  Visitor<ResourceAnalyser>::visit(decl);

  auto bpf_type = get_bpf_map_type(decl.bpf_type);
  if (!bpf_type) {
    LOG(BUG) << "No bpf type from string: " << decl.bpf_type;
    return;
  }
  map_decls_.insert({ decl.ident, { *bpf_type, decl.max_entries } });
}

void ResourceAnalyser::visit(Map &map)
{
  Visitor<ResourceAnalyser>::visit(map);

  update_map_info(map);
}

void ResourceAnalyser::visit(MapAccess &acc)
{
  visit(acc.map);
  visit(acc.key);

  if (exceeds_stack_limit(acc.type().GetSize())) {
    resources_.read_map_value_buffers++;
    resources_.max_read_map_value_size = std::max(
        resources_.max_read_map_value_size, acc.type().GetSize());
  }
  maybe_allocate_map_key_buffer(*acc.map, acc.key);
}

void ResourceAnalyser::visit(Tuple &tuple)
{
  Visitor<ResourceAnalyser>::visit(tuple);

  if (exceeds_stack_limit(tuple.tuple_type.GetSize())) {
    resources_.tuple_buffers++;
    resources_.max_tuple_size = std::max(resources_.max_tuple_size,
                                         tuple.tuple_type.GetSize());
  }
}

void ResourceAnalyser::visit(For &f)
{
  Visitor<ResourceAnalyser>::visit(f);

  // Need tuple per for loop to store key and value
  if (exceeds_stack_limit(f.decl->type().GetSize())) {
    resources_.tuple_buffers++;
    resources_.max_tuple_size = std::max(resources_.max_tuple_size,
                                         f.decl->type().GetSize());
  }
}

void ResourceAnalyser::visit(AssignMapStatement &assignment)
{
  // CodegenLLVM traverses the AST like:
  //      AssignmentMapStatement a
  //        |                    |
  //    visit(a.expr)        visit(a.map.key_expr)
  //
  // CodegenLLVM avoid traversing into the map node via visit(a.map)
  // to avoid triggering a map lookup.
  //
  // However, ResourceAnalyser traverses the AST differently:
  //      AssignmentMapStatement a
  //        |                    |
  //    visit(a.expr)        visit(a.map)
  //                               |
  //                           visit(a.map.key_expr)
  //
  // Unfortunately, calling ResourceAnalser::visit(a.map) will trigger
  // an additional read map buffer. Thus to mimic CodegenLLVM, we
  // skip calling ResourceAnalser::visit(a.map) and do the AST traversal
  // ourselves.
  visit(assignment.map);
  visit(assignment.key);
  visit(assignment.expr);

  // The `MapAccess` validated the read limit, we know this to be
  // a write, so we validate the write limit.
  if (needAssignMapStatementAllocation(assignment)) {
    if (exceeds_stack_limit(assignment.map->value_type.GetSize())) {
      resources_.max_write_map_value_size = std::max(
          resources_.max_write_map_value_size,
          assignment.map->value_type.GetSize());
    }
  }
  maybe_allocate_map_key_buffer(*assignment.map, assignment.key);
}

void ResourceAnalyser::visit(Ternary &ternary)
{
  Visitor<ResourceAnalyser>::visit(ternary);

  // Codegen cannot use a phi node for ternary string b/c strings can be of
  // differing lengths and phi node wants identical types. So we have to
  // allocate a result temporary, but not on the stack b/c a big string would
  // blow it up. So we need a scratch buffer for it.

  if (ternary.result_type.IsStringTy()) {
    const auto max_strlen = bpftrace_.config_->max_strlen;
    if (exceeds_stack_limit(max_strlen))
      resources_.str_buffers++;
  }
}

void ResourceAnalyser::visit(Program &prog)
{
  map_bounds_.visit(prog);
  Visitor<ResourceAnalyser>::visit(prog);
}

void ResourceAnalyser::update_variable_info(Variable &var)
{
  // Note we don't check if a variable has been declared/assigned before.
  // We do this to simplify the code and make it more robust to changes
  // in other modules at the expense of memory over-allocation. Otherwise,
  // we would need to track scopes like SemanticAnalyser and CodegenLLVM
  // and duplicate scope tracking in a third module.
  if (exceeds_stack_limit(var.var_type.GetSize())) {
    resources_.variable_buffers++;
    resources_.max_variable_size = std::max(resources_.max_variable_size,
                                            var.var_type.GetSize());
  }
}

void ResourceAnalyser::visit(AssignVarStatement &assignment)
{
  Visitor<ResourceAnalyser>::visit(assignment);

  update_variable_info(*assignment.var());
}

void ResourceAnalyser::visit(VarDeclStatement &decl)
{
  Visitor<ResourceAnalyser>::visit(decl);

  update_variable_info(*decl.var);
}

bool ResourceAnalyser::exceeds_stack_limit(size_t size)
{
  return size > bpftrace_.config_->on_stack_limit;
}

bool ResourceAnalyser::uses_usym_table(const std::string &fun)
{
  return fun == "usym" || fun == "func" || fun == "ustack";
}

void ResourceAnalyser::update_map_info(Map &map)
{
  auto &map_info = resources_.maps_info[map.ident];
  map_info.value_type = map.value_type;
  map_info.key_type = map.key_type;
  map_info.is_scalar = map_bounds_.is_scalar(map.ident);

  auto decl = map_decls_.find(map.ident);
  if (decl != map_decls_.end()) {
    map_info.bpf_type = decl->second.first;
    map_info.max_entries = decl->second.second;
  } else {
    map_info.bpf_type = get_bpf_map_type(map_info.value_type,
                                         map_info.key_type);
    // hist() and lhist() transparently create additional elements in whatever
    // map they are assigned to. So even if the map looks like it has no keys,
    // multiple keys are necessary.
    if (!map.type().IsMultiKeyMapTy() &&
        (map_info.key_type.IsNoneTy() || map_info.is_scalar)) {
      map_info.max_entries = 1;
    } else {
      map_info.max_entries = bpftrace_.config_->max_map_keys;
    }
  }
}

void ResourceAnalyser::maybe_allocate_map_key_buffer(const Map &map,
                                                     const Expression &key_expr)
{
  const auto map_key_size = map.key_type.GetSize();
  if (needMapKeyAllocation(map, key_expr) &&
      exceeds_stack_limit(map_key_size)) {
    resources_.map_key_buffers++;
    resources_.max_map_key_size = std::max(resources_.max_map_key_size,
                                           map_key_size);
  }
}

Pass CreateResourcePass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) {
    ResourceAnalyser analyser(b);
    analyser.visit(ast.root);
    b.resources = analyser.resources();
  };

  return Pass::create("ResourceAnalyser", fn);
}

} // namespace bpftrace::ast
