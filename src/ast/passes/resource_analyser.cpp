#include "resource_analyser.h"

#include "bpftrace.h"
#include "globalvars.h"
#include "log.h"
#include "struct.h"

namespace bpftrace {
namespace ast {

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

ResourceAnalyser::ResourceAnalyser(Node *root,
                                   BPFtrace &bpftrace,
                                   std::ostream &out)
    : root_(root), bpftrace_(bpftrace), out_(out), probe_(nullptr)
{
}

std::optional<RequiredResources> ResourceAnalyser::analyse()
{
  Visit(*root_);

  if (!err_.str().empty()) {
    out_ << err_.str();
    return std::nullopt;
  }

  return std::optional{ std::move(resources_) };
}

void ResourceAnalyser::visit(Probe &probe)
{
  probe_ = &probe;
  Visitor::visit(probe);
}

void ResourceAnalyser::visit(Subprog &subprog)
{
  probe_ = nullptr;
  Visitor::visit(subprog);
}

void ResourceAnalyser::visit(Builtin &builtin)
{
  if (builtin.ident == "elapsed") {
    resources_.needs_elapsed_map = true;
  } else if (builtin.ident == "kstack" || builtin.ident == "ustack") {
    resources_.stackid_maps.insert(StackType{
        .mode = bpftrace_.config_.get(ConfigKeyStackMode::default_) });
  }

  if (uses_usym_table(builtin.ident)) {
    // mark probe as using usym, so that the symbol table can be pre-loaded
    // and symbols resolved even when unavailable at resolution time
    resources_.probes_using_usym.insert(probe_);
  }
}

void ResourceAnalyser::visit(Call &call)
{
  Visitor::visit(call);

  if (call.func == "printf" || call.func == "system" || call.func == "cat" ||
      call.func == "debugf") {
    std::vector<Field> args;
    // NOTE: the same logic can be found in the semantic_analyser pass
    for (auto it = call.vargs.begin() + 1; it != call.vargs.end(); it++) {
      // Promote to 64-bit if it's not an aggregate type
      SizedType ty = (*it)->type; // copy
      if (!ty.IsAggregate() && !ty.IsTimestampTy())
        ty.SetSize(8);

      args.push_back(Field{
          .name = "",
          .type = ty,
          .offset = 0,
          .bitfield = std::nullopt,
      });
    }

    auto fmtstr = get_literal_string(*call.vargs.at(0));
    if (call.func == "printf") {
      if (probe_ != nullptr &&
          single_provider_type_postsema(probe_) == ProbeType::iter) {
        resources_.bpf_print_fmts.push_back(fmtstr);
      } else {
        resources_.printf_args.emplace_back(fmtstr, args);
      }
    } else if (call.func == "debugf") {
      resources_.bpf_print_fmts.push_back(fmtstr);
    } else if (call.func == "system") {
      resources_.system_args.emplace_back(fmtstr, args);
    } else {
      resources_.cat_args.emplace_back(fmtstr, args);
    }
  } else if (call.func == "join") {
    auto delim = call.vargs.size() > 1 ? get_literal_string(*call.vargs.at(1))
                                       : " ";
    resources_.join_args.push_back(delim);
    resources_.needs_join_map = true;
  } else if (call.func == "count" || call.func == "sum" || call.func == "min" ||
             call.func == "max" || call.func == "avg") {
    resources_.needed_global_vars.insert(bpftrace::globalvars::NUM_CPUS);
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
  } else if (call.func == "str" || call.func == "buf" || call.func == "path") {
    resources_.str_buffers++;
  } else if (call.func == "strftime") {
    resources_.strftime_args.push_back(get_literal_string(*call.vargs.at(0)));
  } else if (call.func == "print") {
    auto &arg = *call.vargs.at(0);
    if (!arg.is_map)
      resources_.non_map_print_args.push_back(arg.type);
    else {
      auto &map = static_cast<Map &>(arg);
      if (map.vargs.size() > 0)
        resources_.non_map_print_args.push_back(map.type);
    }
  } else if (call.func == "kstack" || call.func == "ustack") {
    resources_.stackid_maps.insert(call.type.stack_type);
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

  if (uses_usym_table(call.func)) {
    // mark probe as using usym, so that the symbol table can be pre-loaded
    // and symbols resolved even when unavailable at resolution time
    resources_.probes_using_usym.insert(probe_);
  }
}

void ResourceAnalyser::visit(Map &map)
{
  Visitor::visit(map);

  auto &map_info = resources_.maps_info[map.ident];
  map_info.value_type = map.type;
  map_info.key = map.key_type;
}

bool ResourceAnalyser::uses_usym_table(const std::string &fun)
{
  return fun == "usym" || fun == "func" || fun == "ustack";
}

Pass CreateResourcePass()
{
  auto fn = [](Node &n, PassContext &ctx) {
    ResourceAnalyser analyser{ &n, ctx.b };
    auto pass_result = analyser.analyse();

    if (!pass_result.has_value())
      return PassResult::Error("Resource", 1);
    ctx.b.resources = pass_result.value();

    return PassResult::Success();
  };

  return Pass("ResourceAnalyser", fn);
}

} // namespace ast
} // namespace bpftrace
