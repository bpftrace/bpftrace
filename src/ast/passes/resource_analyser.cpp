
#include <algorithm>

#include "ast/async_event_types.h"
#include "ast/codegen_helper.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/named_param.h"
#include "ast/passes/resource_analyser.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"
#include "required_resources.h"
#include "struct.h"
#include "types.h"

namespace libbpf {
#include "libbpf/bpf.h"
} // namespace libbpf

namespace bpftrace::ast {

namespace {

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
  ResourceAnalyser(BPFtrace &bpftrace,
                   MapMetadata &mm,
                   NamedParamDefaults &named_param_defaults);

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

  // This will move the compute resources value, it should be called only
  // after the top-level visit.
  RequiredResources resources();

private:
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
  MapMetadata map_metadata_;
  NamedParamDefaults &named_param_defaults_;

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

ResourceAnalyser::ResourceAnalyser(BPFtrace &bpftrace,
                                   MapMetadata &mm,
                                   NamedParamDefaults &named_param_defaults)
    : bpftrace_(bpftrace),
      map_metadata_(mm),
      named_param_defaults_(named_param_defaults)
{
}

RequiredResources ResourceAnalyser::resources()
{
  if (resources_.max_fmtstring_args_size > 0) {
    resources_.global_vars.add_known(bpftrace::globalvars::FMT_STRINGS_BUFFER);
  }

  if (resources_.max_tuple_size > 0) {
    assert(resources_.tuple_buffers > 0);
    resources_.global_vars.add_known(bpftrace::globalvars::TUPLE_BUFFER);
  }

  if (resources_.str_buffers > 0) {
    resources_.global_vars.add_known(bpftrace::globalvars::GET_STR_BUFFER);
  }

  if (resources_.max_read_map_value_size > 0) {
    assert(resources_.read_map_value_buffers > 0);
    resources_.global_vars.add_known(
        bpftrace::globalvars::READ_MAP_VALUE_BUFFER);
  }

  if (resources_.max_write_map_value_size > 0) {
    resources_.global_vars.add_known(
        bpftrace::globalvars::WRITE_MAP_VALUE_BUFFER);
  }

  if (resources_.max_variable_size > 0) {
    assert(resources_.variable_buffers > 0);
    resources_.global_vars.add_known(bpftrace::globalvars::VARIABLE_BUFFER);
  }

  if (resources_.max_map_key_size > 0) {
    assert(resources_.map_key_buffers > 0);
    resources_.global_vars.add_known(bpftrace::globalvars::MAP_KEY_BUFFER);
  }

  resources_.global_vars.add_known(bpftrace::globalvars::MAX_CPU_ID);
  resources_.global_vars.add_known(bpftrace::globalvars::EVENT_LOSS_COUNTER);

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
  } else if (builtin.ident == "__builtin_ncpus") {
    resources_.global_vars.add_known(bpftrace::globalvars::NUM_CPUS);
  }
}

void ResourceAnalyser::visit(Call &call)
{
  Visitor<ResourceAnalyser>::visit(call);

  if (call.func == "printf" || call.func == "errorf" || call.func == "system" ||
      call.func == "cat" || call.func == "debugf") {
    std::vector<SizedType> args;

    for (auto it = call.vargs.begin() + 1; it != call.vargs.end(); it++) {
      args.push_back(it->type());
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

    // Keep track of max "tuple" size needed for fmt string args. Codegen
    // will use this information to create a percpu array map of large
    // enough size for all fmt string calls to use. Note that since this
    // will end up being aligned differently than the arguments themselves,
    // we need to ensure that it is aligned to the size of the largest type.
    uint64_t args_size = sizeof(uint64_t) + static_cast<uint64_t>(tuple->size);
    if (args_size % sizeof(uint64_t) != 0) {
      args_size += sizeof(uint64_t) - (args_size % sizeof(uint64_t));
    }
    if (exceeds_stack_limit(args_size)) {
      resources_.max_fmtstring_args_size = std::max(
          resources_.max_fmtstring_args_size, args_size);
    }

    auto fmtstr = call.vargs.at(0).as<String>()->value;
    if (call.func == "printf") {
      if (probe_ != nullptr &&
          single_provider_type_postsema(probe_) == ProbeType::iter) {
        resources_.bpf_print_fmts_id_map[&call] =
            resources_.bpf_print_fmts.size();
        resources_.bpf_print_fmts.emplace_back(fmtstr);
      } else {
        resources_.printf_args_id_map[&call] = resources_.printf_args.size();
        resources_.printf_args.emplace_back(
            fmtstr, tuple->fields, PrintfSeverity::NONE, SourceInfo(call.loc));
      }
    } else if (call.func == "errorf") {
      resources_.printf_args_id_map[&call] = resources_.printf_args.size();
      resources_.printf_args.emplace_back(
          fmtstr, tuple->fields, PrintfSeverity::ERROR, SourceInfo(call.loc));
    } else if (call.func == "debugf") {
      resources_.bpf_print_fmts_id_map[&call] =
          resources_.bpf_print_fmts.size();
      resources_.bpf_print_fmts.emplace_back(fmtstr);
    } else if (call.func == "system") {
      resources_.system_args_id_map[&call] = resources_.system_args.size();
      resources_.system_args.emplace_back(fmtstr, tuple->fields);
    } else {
      resources_.cat_args_id_map[&call] = resources_.cat_args.size();
      resources_.cat_args.emplace_back(fmtstr, tuple->fields);
    }
  } else if (call.func == "join") {
    auto delim = call.vargs.size() > 1 ? call.vargs.at(1).as<String>()->value
                                       : " ";
    resources_.join_args_id_map[&call] = resources_.join_args.size();
    resources_.join_args.push_back(delim);
  } else if (call.func == "count" || call.func == "sum" || call.func == "min" ||
             call.func == "max" || call.func == "avg") {
    resources_.global_vars.add_known(bpftrace::globalvars::NUM_CPUS);
  } else if (call.func == "hist") {
    Map *map = call.vargs.at(0).as<Map>();
    uint64_t bits = call.vargs.at(3).as<Integer>()->value;
    auto args = HistogramArgs{
      .bits = static_cast<long>(bits),
    };

    auto &map_info = resources_.maps_info[map->ident];
    if (std::holds_alternative<std::monostate>(map_info.detail)) {
      map_info.detail.emplace<HistogramArgs>(args);
    } else if (std::holds_alternative<HistogramArgs>(map_info.detail) &&
               std::get<HistogramArgs>(map_info.detail) == args) {
      // Same arguments.
    } else {
      call.addError() << "Different bits in a single hist unsupported";
    }
  } else if (call.func == "lhist") {
    Map *map = call.vargs.at(0).as<Map>();
    Expression &min_arg = call.vargs.at(3);
    Expression &max_arg = call.vargs.at(4);
    Expression &step_arg = call.vargs.at(5);
    auto &min = *min_arg.as<Integer>();
    auto &max = *max_arg.as<Integer>();
    auto &step = *step_arg.as<Integer>();
    auto args = LinearHistogramArgs{
      .min = static_cast<long>(min.value),
      .max = static_cast<long>(max.value),
      .step = static_cast<long>(step.value),
    };

    auto &map_info = resources_.maps_info[map->ident];
    if (std::holds_alternative<std::monostate>(map_info.detail)) {
      map_info.detail.emplace<LinearHistogramArgs>(args);
    } else if (std::holds_alternative<LinearHistogramArgs>(map_info.detail) &&
               std::get<LinearHistogramArgs>(map_info.detail) == args) {
      // Same arguments.
    } else {
      call.addError() << "Different lhist bounds in a single map unsupported";
    }
  } else if (call.func == "tseries") {
    Map *map = call.vargs.at(0).as<Map>();

    Expression &n_arg = call.vargs.at(2);
    Expression &interval_ns_arg = call.vargs.at(3);
    Expression &num_intervals_arg = call.vargs.at(4);
    auto &interval_ns = *interval_ns_arg.as<Integer>();
    auto &num_intervals = *num_intervals_arg.as<Integer>();

    auto args = TSeriesArgs{
      .interval_ns = static_cast<long>(interval_ns.value),
      .num_intervals = static_cast<long>(num_intervals.value),
      .value_type = n_arg.type(),
      .agg = TSeriesAggFunc::none,
    };

    if (call.vargs.size() == 6) {
      auto &agg_func = *call.vargs.at(5).as<String>();

      if (agg_func.value == "avg") {
        args.agg = TSeriesAggFunc::avg;
      } else if (agg_func.value == "max") {
        args.agg = TSeriesAggFunc::max;
      } else if (agg_func.value == "min") {
        args.agg = TSeriesAggFunc::min;
      } else if (agg_func.value == "sum") {
        args.agg = TSeriesAggFunc::sum;
      }
    }

    auto &map_info = resources_.maps_info[map->ident];
    if (std::holds_alternative<std::monostate>(map_info.detail)) {
      map_info.detail.emplace<TSeriesArgs>(args);
    } else if (std::holds_alternative<TSeriesArgs>(map_info.detail) &&
               std::get<TSeriesArgs>(map_info.detail) == args) {
      // Same arguments.
    } else {
      call.addError() << "Different tseries bounds in a single map unsupported";
    }
  } else if (call.func == "time") {
    resources_.time_args_id_map[&call] = resources_.time_args.size();
    if (!call.vargs.empty())
      resources_.time_args.push_back(call.vargs.at(0).as<String>()->value);
    else
      resources_.time_args.emplace_back("%H:%M:%S\n");
  } else if (call.func == "strftime") {
    resources_.strftime_args_id_map[&call] = resources_.strftime_args.size();
    resources_.strftime_args.push_back(call.vargs.at(0).as<String>()->value);
  } else if (call.func == "print") {
    constexpr auto nonmap_headroom = sizeof(AsyncEvent::PrintNonMap);
    auto &arg = call.vargs.at(0);
    if (!arg.is<Map>()) {
      resources_.non_map_print_args_id_map[&call] =
          resources_.non_map_print_args.size();
      resources_.non_map_print_args.push_back(arg.type());
      const size_t fmtstring_args_size = nonmap_headroom + arg.type().GetSize();
      if (exceeds_stack_limit(fmtstring_args_size)) {
        resources_.max_fmtstring_args_size = std::max<uint64_t>(
            resources_.max_fmtstring_args_size, fmtstring_args_size);
      }
    }
  } else if (call.func == "cgroup_path") {
    resources_.cgroup_path_args_id_map[&call] =
        resources_.cgroup_path_args.size();
    if (call.vargs.size() > 1)
      resources_.cgroup_path_args.push_back(
          call.vargs.at(1).as<String>()->value);
    else
      resources_.cgroup_path_args.emplace_back("*");
  } else if (call.func == "skboutput") {
    resources_.skboutput_args_id_map[&call] = resources_.skboutput_args_.size();
    const auto &file = call.vargs.at(0).as<String>()->value;
    const auto &offset = call.vargs.at(3).as<Integer>()->value;

    resources_.skboutput_args_.emplace_back(file, offset);
    resources_.using_skboutput = true;
  } else if (call.func == "delete") {
    auto &arg0 = call.vargs.at(0);
    auto &map = *arg0.as<Map>();
    if (exceeds_stack_limit(map.value_type.GetSize())) {
      resources_.max_write_map_value_size = std::max(
          resources_.max_write_map_value_size, map.value_type.GetSize());
    }
  }

  if (call.func == "print" || call.func == "clear" || call.func == "zero") {
    if (auto *map = call.vargs.at(0).as<Map>()) {
      auto &name = map->ident;
      auto &map_info = resources_.maps_info[name];
      if (map_info.id == -1)
        map_info.id = next_map_id_++;
    }
  }

  if (call.func == "str" || call.func == "buf" || call.func == "path") {
    const auto max_strlen = bpftrace_.config_->max_strlen;
    if (exceeds_stack_limit(max_strlen))
      resources_.str_buffers++;
  }

  // These functions, some of which are desugared AssignMapStatements (e.g.,
  // `@a[1, 2, 3] = count(); -> count(@a, (1, 2, 3));`) might require
  // additional map key scratch buffers because the map key type might be
  // a slightly different type due to type promotion in an earlier pass.
  // This requires us to allocate a new map key (or create a scratch buffer)
  // and copy individual elements of the tuple instead of the whole thing.
  if (getAssignRewriteFuncs().contains(call.func) || call.func == "delete" ||
      call.func == "has_key") {
    if (call.func == "lhist" || call.func == "hist" || call.func == "tseries") {
      auto &map = *call.vargs.at(0).as<Map>();
      // Allocation is always needed for lhist/hist/tseries but we need to
      // allocate space for both map key and the bucket ID from a call to
      // linear/log2/tseries functions.
      const auto map_key_size = map.key_type.GetSize() +
                                CreateUInt64().GetSize();
      if (exceeds_stack_limit(map_key_size)) {
        resources_.map_key_buffers++;
        resources_.max_map_key_size = std::max(resources_.max_map_key_size,
                                               map_key_size);
      }
    } else {
      maybe_allocate_map_key_buffer(*call.vargs.at(0).as<Map>(),
                                    call.vargs.at(1));
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

  auto it = named_param_defaults_.defaults.find(map.ident);
  if (it != named_param_defaults_.defaults.end()) {
    resources_.global_vars.add_named_param(map.ident, it->second);
    if (std::holds_alternative<std::string>(it->second)) {
      const auto max_strlen = bpftrace_.config_->max_strlen;
      if (exceeds_stack_limit(max_strlen))
        resources_.str_buffers++;
    }
    return;
  }

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
  return fun == "usym" || fun == "__builtin_func" || fun == "ustack";
}

void ResourceAnalyser::update_map_info(Map &map)
{
  auto &map_info = resources_.maps_info[map.ident];
  map_info.value_type = map.value_type;
  map_info.key_type = map.key_type;
  map_info.is_scalar = map_metadata_.scalar[map.ident];

  auto decl = map_decls_.find(map.ident);
  if (decl != map_decls_.end()) {
    map_info.bpf_type = decl->second.first;
    map_info.max_entries = decl->second.second;
  } else {
    map_info.bpf_type = get_bpf_map_type(map_info.value_type,
                                         map_info.is_scalar);
    // hist() and lhist() transparently create additional elements in whatever
    // map they are assigned to. So even if the map looks like it has no keys,
    // multiple keys are necessary.
    if (!map.type().IsMultiKeyMapTy() && map_info.is_scalar) {
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
  auto fn = [](ASTContext &ast,
               BPFtrace &b,
               MapMetadata &mm,
               NamedParamDefaults &named_param_defaults) {
    ResourceAnalyser analyser(b, mm, named_param_defaults);
    analyser.visit(ast.root);
    b.resources = analyser.resources();
  };

  return Pass::create("ResourceAnalyser", fn);
}

} // namespace bpftrace::ast
