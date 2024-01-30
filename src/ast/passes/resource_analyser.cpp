#include "resource_analyser.h"

#include "bpftrace.h"
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
  if (!probe->attach_points->empty()) {
    return probetype(probe->attach_points->at(0)->provider);
  }

  return ProbeType::invalid;
}

std::string get_literal_string(Expression &expr)
{
  String &str = static_cast<String &>(expr);
  return str.str;
}

} // namespace

ResourceAnalyser::ResourceAnalyser(Node *root, std::ostream &out)
    : root_(root), out_(out), probe_(nullptr)
{
}

std::optional<RequiredResources> ResourceAnalyser::analyse()
{
  Visit(*root_);
  prepare_mapped_printf_ids();

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

void ResourceAnalyser::visit(Builtin &builtin)
{
  if (builtin.ident == "elapsed") {
    resources_.needs_elapsed_map = true;
  } else if (builtin.ident == "kstack" || builtin.ident == "ustack") {
    resources_.stackid_maps.insert(StackType{});
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
    for (auto it = call.vargs->begin() + 1; it != call.vargs->end(); it++) {
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

    auto fmtstr = get_literal_string(*call.vargs->at(0));
    if (call.func == "printf") {
      if (single_provider_type_postsema(probe_) == ProbeType::iter) {
        resources_.mapped_printf_args.emplace_back(fmtstr, args);
        resources_.needs_data_map = true;
      } else {
        resources_.printf_args.emplace_back(fmtstr, args);
      }
    } else if (call.func == "debugf") {
      resources_.mapped_printf_args.emplace_back(fmtstr, args);
      resources_.needs_data_map = true;
    } else if (call.func == "system") {
      resources_.system_args.emplace_back(fmtstr, args);
    } else {
      resources_.cat_args.emplace_back(fmtstr, args);
    }
  } else if (call.func == "join") {
    auto delim = call.vargs->size() > 1 ? get_literal_string(*call.vargs->at(1))
                                        : " ";
    resources_.join_args.push_back(delim);
    resources_.needs_join_map = true;
  } else if (call.func == "hist") {
    auto &r = resources_.hist_bits_arg;

    int bits = static_cast<Integer *>(call.vargs->at(1))->n;
    if (r.find(call.map->ident) != r.end() && (r[call.map->ident]) != bits) {
      LOG(ERROR, call.loc, err_) << "Different bits in a single hist, had "
                                 << r[call.map->ident] << " now " << bits;
    } else {
      r[call.map->ident] = bits;
    }
  } else if (call.func == "lhist") {
    Expression &min_arg = *call.vargs->at(1);
    Expression &max_arg = *call.vargs->at(2);
    Expression &step_arg = *call.vargs->at(3);
    Integer &min = static_cast<Integer &>(min_arg);
    Integer &max = static_cast<Integer &>(max_arg);
    Integer &step = static_cast<Integer &>(step_arg);

    auto args = LinearHistogramArgs{
      .min = min.n,
      .max = max.n,
      .step = step.n,
    };

    if (resources_.lhist_args.find(call.map->ident) !=
            resources_.lhist_args.end() &&
        (resources_.lhist_args[call.map->ident].min != args.min ||
         resources_.lhist_args[call.map->ident].max != args.max ||
         resources_.lhist_args[call.map->ident].step != args.step)) {
      LOG(ERROR, call.loc, err_)
          << "Different lhist bounds in a single map unsupported";
    } else {
      resources_.lhist_args[call.map->ident] = args;
    }
  } else if (call.func == "time") {
    if (call.vargs && call.vargs->size() > 0)
      resources_.time_args.push_back(get_literal_string(*call.vargs->at(0)));
    else
      resources_.time_args.push_back("%H:%M:%S\n");
  } else if (call.func == "strftime") {
    resources_.strftime_args.push_back(get_literal_string(*call.vargs->at(0)));
  } else if (call.func == "print") {
    auto &arg = *call.vargs->at(0);
    if (!arg.is_map)
      resources_.non_map_print_args.push_back(arg.type);
  } else if (call.func == "kstack" || call.func == "ustack") {
    resources_.stackid_maps.insert(call.type.stack_type);
  } else if (call.func == "cgroup_path") {
    if (call.vargs->size() > 1)
      resources_.cgroup_path_args.push_back(
          get_literal_string(*call.vargs->at(1)));
    else
      resources_.cgroup_path_args.push_back("*");
  } else if (call.func == "skboutput") {
    auto &file_arg = *call.vargs->at(0);
    String &file = static_cast<String &>(file_arg);

    auto &offset_arg = *call.vargs->at(3);
    Integer &offset = static_cast<Integer &>(offset_arg);

    resources_.skboutput_args_.emplace_back(file.str, offset.n);
    resources_.needs_perf_event_map = true;
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

  resources_.map_vals[map.ident] = map.type;
  resources_.map_keys[map.ident] = map.key_type;
}

void ResourceAnalyser::prepare_mapped_printf_ids()
{
  int idx = 0;

  for (auto &arg : resources_.mapped_printf_args) {
    assert(resources_.needs_data_map);
    auto len = std::get<0>(arg).size();
    resources_.mapped_printf_ids.push_back({ idx, len + 1 });
    idx += len + 1;
  }
}

bool ResourceAnalyser::uses_usym_table(const std::string &fun)
{
  return fun == "usym" || fun == "func" || fun == "ustack";
}

Pass CreateResourcePass()
{
  auto fn = [](Node &n, PassContext &ctx) {
    ResourceAnalyser analyser{ &n };
    auto pass_result = analyser.analyse();

    if (!pass_result.has_value())
      return PassResult::Error("Resource", 1);
    ctx.b.resources = pass_result.value();

    // Create fake maps so that codegen has access to map IDs
    //
    // At runtime we will replace the fake maps with real maps
    ctx.b.resources.create_maps(ctx.b, true);

    return PassResult::Success();
  };

  return Pass("ResourceAnalyser", fn);
}

} // namespace ast
} // namespace bpftrace
