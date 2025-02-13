#include "resource_analyser.h"

#include <algorithm>

#include "ast/async_event_types.h"
#include "ast/codegen_helper.h"
#include "bpftrace.h"
#include "globalvars.h"
#include "log.h"
#include "struct.h"

namespace bpftrace::ast {

namespace {

// This helper differs from SemanticAnalyser::single_provider_type() in that
// for situations where a single probetype is required we assume the AST is
// well formed.
ProbeType single_provider_type_postsema(Probe *probe)
{
  if (!probe->attach_points.empty()) {
    return probetype(probe->attach_points.at(0)->provider);
  }

  return ProbeType::invalid;
}

std::string get_literal_string(Expression &expr)
{
  String &str = static_cast<String &>(expr);
  return str.str;
}

} // namespace

ResourceAnalyser::ResourceAnalyser(ASTContext &ctx,
                                   BPFtrace &bpftrace,
                                   std::ostream &out)
    : Visitor<ResourceAnalyser>(ctx),
      bpftrace_(bpftrace),
      out_(out),
      probe_(nullptr)
{
}

std::optional<RequiredResources> ResourceAnalyser::analyse()
{
  visit(ctx_.root);

  if (!err_.str().empty()) {
    out_ << err_.str();
    return std::nullopt;
  }

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

  return std::optional{ std::move(resources_) };
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
      SizedType ty = (*it)->type; // copy
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

    auto fmtstr = get_literal_string(*call.vargs.at(0));
    if (call.func == "printf") {
      if (probe_ != nullptr &&
          single_provider_type_postsema(probe_) == ProbeType::iter) {
        resources_.bpf_print_fmts.push_back(fmtstr);
      } else {
        resources_.printf_args.emplace_back(fmtstr, tuple->fields);
      }
    } else if (call.func == "debugf") {
      resources_.bpf_print_fmts.push_back(fmtstr);
    } else if (call.func == "system") {
      resources_.system_args.emplace_back(fmtstr, tuple->fields);
    } else {
      resources_.cat_args.emplace_back(fmtstr, tuple->fields);
    }
  } else if (call.func == "join") {
    auto delim = call.vargs.size() > 1 ? get_literal_string(*call.vargs.at(1))
                                       : " ";
    resources_.join_args.push_back(delim);
  } else if (call.func == "count" || call.func == "sum" || call.func == "min" ||
             call.func == "max" || call.func == "avg") {
    resources_.needed_global_vars.insert(
        bpftrace::globalvars::GlobalVar::NUM_CPUS);
  } else if (call.func == "hist") {
    auto &map_info = resources_.maps_info[call.map->ident];
    int bits = static_cast<Integer *>(call.vargs.at(1))->n;

    if (map_info.hist_bits_arg.has_value() && *map_info.hist_bits_arg != bits) {
      LOG(ERROR, call.loc, err_) << "Different bits in a single hist, had "
                                 << *map_info.hist_bits_arg << " now " << bits;
    } else {
      map_info.hist_bits_arg = bits;
    }
  } else if (call.func == "lhist") {
    Expression &min_arg = *call.vargs.at(1);
    Expression &max_arg = *call.vargs.at(2);
    Expression &step_arg = *call.vargs.at(3);
    Integer &min = static_cast<Integer &>(min_arg);
    Integer &max = static_cast<Integer &>(max_arg);
    Integer &step = static_cast<Integer &>(step_arg);

    auto args = LinearHistogramArgs{
      .min = min.n,
      .max = max.n,
      .step = step.n,
    };

    auto &map_info = resources_.maps_info[call.map->ident];

    if (map_info.lhist_args.has_value() && *map_info.lhist_args != args) {
      LOG(ERROR, call.loc, err_)
          << "Different lhist bounds in a single map unsupported";
    } else {
      map_info.lhist_args = args;
    }
  } else if (call.func == "time") {
    if (call.vargs.size() > 0)
      resources_.time_args.push_back(get_literal_string(*call.vargs.at(0)));
    else
      resources_.time_args.push_back("%H:%M:%S\n");
  } else if (call.func == "strftime") {
    resources_.strftime_args.push_back(get_literal_string(*call.vargs.at(0)));
  } else if (call.func == "print") {
    constexpr auto nonmap_headroom = sizeof(AsyncEvent::PrintNonMap);
    auto &arg = *call.vargs.at(0);
    if (!arg.is_map) {
      resources_.non_map_print_args.push_back(arg.type);

      const size_t fmtstring_args_size = nonmap_headroom + arg.type.GetSize();
      if (exceeds_stack_limit(fmtstring_args_size)) {
        resources_.max_fmtstring_args_size = std::max<uint64_t>(
            resources_.max_fmtstring_args_size, fmtstring_args_size);
      }
    } else {
      auto &map = static_cast<Map &>(arg);
      if (map.key_expr) {
        resources_.non_map_print_args.push_back(map.type);

        const size_t fmtstring_args_size = nonmap_headroom + map.type.GetSize();
        if (exceeds_stack_limit(fmtstring_args_size)) {
          resources_.max_fmtstring_args_size = std::max<uint64_t>(
              resources_.max_fmtstring_args_size, fmtstring_args_size);
        }
      }
    }
  } else if (call.func == "cgroup_path") {
    if (call.vargs.size() > 1)
      resources_.cgroup_path_args.push_back(
          get_literal_string(*call.vargs.at(1)));
    else
      resources_.cgroup_path_args.push_back("*");
  } else if (call.func == "skboutput") {
    auto &file_arg = *call.vargs.at(0);
    String &file = static_cast<String &>(file_arg);

    auto &offset_arg = *call.vargs.at(3);
    Integer &offset = static_cast<Integer &>(offset_arg);

    resources_.skboutput_args_.emplace_back(file.str, offset.n);
    resources_.needs_perf_event_map = true;
  } else if (call.func == "delete") {
    auto &arg0 = *call.vargs.at(0);
    auto &map = static_cast<Map &>(arg0);
    if (exceeds_stack_limit(map.type.GetSize())) {
      resources_.max_write_map_value_size = std::max(
          resources_.max_write_map_value_size, map.type.GetSize());
    }
  }

  if (call.func == "print" || call.func == "clear" || call.func == "zero") {
    auto &arg = *call.vargs.at(0);
    if (arg.is_map) {
      auto &name = static_cast<Map &>(arg).ident;
      auto &map_info = resources_.maps_info[name];
      if (map_info.id == -1)
        map_info.id = next_map_id_++;
    }
  }

  if (call.func == "str" || call.func == "buf" || call.func == "path") {
    const auto max_strlen = bpftrace_.config_.get(ConfigKeyInt::max_strlen);
    if (exceeds_stack_limit(max_strlen))
      resources_.str_buffers++;
  }

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
  if (call.func == "lhist" || call.func == "hist") {
    Map &map = *call.map;
    // Allocation is always needed for lhist/hist. But we need to allocate
    // space for both map key and the bucket ID from a call to linear/log2
    // functions.
    const auto map_key_size = map.key_expr ? map.key_type.GetSize() +
                                                 CreateUInt64().GetSize()
                                           : CreateUInt64().GetSize();
    if (exceeds_stack_limit(map_key_size)) {
      resources_.map_key_buffers++;
      resources_.max_map_key_size = std::max(resources_.max_map_key_size,
                                             map_key_size);
    }
  } else if (call.func == "has_key") {
    auto &arg0 = *call.vargs.at(0);
    auto &map = static_cast<Map &>(arg0);
    // has_key does not work on scalar maps (e.g. @a = 1), so we
    // don't need to check if map.key_expr is set
    if (needMapKeyAllocation(map, call.vargs.at(1)) &&
        exceeds_stack_limit(map.key_type.GetSize())) {
      resources_.map_key_buffers++;
      resources_.max_map_key_size = std::max(resources_.max_map_key_size,
                                             map.key_type.GetSize());
    }
  } else if (call.func == "delete") {
    auto &arg0 = *call.vargs.at(0);
    auto &map = static_cast<Map &>(arg0);
    const auto deleteNeedMapKeyAllocation =
        call.vargs.size() > 1 ? needMapKeyAllocation(map, call.vargs.at(1))
                              : needMapKeyAllocation(map);
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

void ResourceAnalyser::visit(Map &map)
{
  Visitor<ResourceAnalyser>::visit(map);

  update_map_info(map);

  if (exceeds_stack_limit(map.type.GetSize())) {
    resources_.read_map_value_buffers++;
    resources_.max_read_map_value_size = std::max(
        resources_.max_read_map_value_size, map.type.GetSize());
  }
  maybe_allocate_map_key_buffer(map);
}

void ResourceAnalyser::visit(Tuple &tuple)
{
  Visitor<ResourceAnalyser>::visit(tuple);

  if (exceeds_stack_limit(tuple.type.GetSize())) {
    resources_.tuple_buffers++;
    resources_.max_tuple_size = std::max(resources_.max_tuple_size,
                                         tuple.type.GetSize());
  }
}

void ResourceAnalyser::visit(For &f)
{
  Visitor<ResourceAnalyser>::visit(f);

  // Need tuple per for loop to store key and value
  if (exceeds_stack_limit(f.decl->type.GetSize())) {
    resources_.tuple_buffers++;
    resources_.max_tuple_size = std::max(resources_.max_tuple_size,
                                         f.decl->type.GetSize());
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
  visit(assignment.expr);
  visit(assignment.map->key_expr);

  update_map_info(*assignment.map);

  if (needAssignMapStatementAllocation(assignment)) {
    if (exceeds_stack_limit(assignment.map->type.GetSize())) {
      resources_.max_write_map_value_size = std::max(
          resources_.max_write_map_value_size, assignment.map->type.GetSize());
    }
  }
  maybe_allocate_map_key_buffer(*assignment.map);
}

void ResourceAnalyser::visit(Ternary &ternary)
{
  Visitor<ResourceAnalyser>::visit(ternary);

  // Codegen cannot use a phi node for ternary string b/c strings can be of
  // differing lengths and phi node wants identical types. So we have to
  // allocate a result temporary, but not on the stack b/c a big string would
  // blow it up. So we need a scratch buffer for it.

  if (ternary.type.IsStringTy()) {
    const auto max_strlen = bpftrace_.config_.get(ConfigKeyInt::max_strlen);
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
  if (exceeds_stack_limit(var.type.GetSize())) {
    resources_.variable_buffers++;
    resources_.max_variable_size = std::max(resources_.max_variable_size,
                                            var.type.GetSize());
  }
}

void ResourceAnalyser::visit(AssignVarStatement &assignment)
{
  Visitor<ResourceAnalyser>::visit(assignment);

  update_variable_info(*assignment.var);
}

void ResourceAnalyser::visit(VarDeclStatement &decl)
{
  Visitor<ResourceAnalyser>::visit(decl);

  update_variable_info(*decl.var);
}

bool ResourceAnalyser::exceeds_stack_limit(size_t size)
{
  return size > bpftrace_.config_.get(ConfigKeyInt::on_stack_limit);
}

bool ResourceAnalyser::uses_usym_table(const std::string &fun)
{
  return fun == "usym" || fun == "func" || fun == "ustack";
}

void ResourceAnalyser::update_map_info(Map &map)
{
  auto &map_info = resources_.maps_info[map.ident];
  map_info.value_type = map.type;
  map_info.key_type = map.key_type;
}

void ResourceAnalyser::maybe_allocate_map_key_buffer(const Map &map)
{
  const auto map_key_size = map.key_expr ? map.key_type.GetSize()
                                         : CreateUInt64().GetSize();
  if (needMapKeyAllocation(map) && exceeds_stack_limit(map_key_size)) {
    resources_.map_key_buffers++;
    resources_.max_map_key_size = std::max(resources_.max_map_key_size,
                                           map_key_size);
  }
}

Pass CreateResourcePass()
{
  auto fn = [](PassContext &ctx) {
    ResourceAnalyser analyser(ctx.ast_ctx, ctx.b);
    auto pass_result = analyser.analyse();

    if (!pass_result.has_value())
      return PassResult::Error("Resource", 1);
    ctx.b.resources = pass_result.value();

    return PassResult::Success();
  };

  return Pass("ResourceAnalyser", fn);
}

} // namespace bpftrace::ast
