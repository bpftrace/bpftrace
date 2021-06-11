#include "resource_analyser.h"

#include "bpftrace.h"
#include "struct.h"

namespace bpftrace {
namespace ast {

namespace {

// This helper differs from SemanticAnalyser::single_provider_type() in that
// for situations where a single probetype is required we assume the AST is
// well formed.
ProbeType single_provider_type_postsema(Probe *probe)
{
  for (auto &attach_point : *probe->attach_points)
    return probetype(attach_point->provider);

  return ProbeType::invalid;
}

std::string get_literal_string(Expression &expr)
{
  String &str = static_cast<String &>(expr);
  return str.str;
}

} // namespace

ResourceAnalyser::ResourceAnalyser(Node *root) : root_(root), probe_(nullptr)
{
}

RequiredResources ResourceAnalyser::analyse()
{
  Visit(*root_);
  prepare_seq_printf_ids();

  return resources_;
}

void ResourceAnalyser::visit(Probe &probe)
{
  probe_ = &probe;
  Visitor::visit(probe);
}

void ResourceAnalyser::visit(Builtin &builtin)
{
  if (builtin.ident == "elapsed")
  {
    resources_.needs_elapsed_map = true;
  }
  else if (builtin.ident == "kstack" || builtin.ident == "ustack")
  {
    resources_.stackid_maps.insert(StackType{});
  }
}

void ResourceAnalyser::visit(Call &call)
{
  Visitor::visit(call);

  if (call.func == "printf" || call.func == "system" || call.func == "cat")
  {
    std::string fmt = get_literal_string(*call.vargs->at(0));
    std::vector<Field> args;
    for (auto it = call.vargs->begin() + 1; it != call.vargs->end(); it++)
    {
      // Promote to 64-bit if it's not an aggregate type
      SizedType ty = (*it)->type; // copy
      if (!ty.IsAggregate() && !ty.IsTimestampTy())
        ty.SetSize(8);

      args.push_back(Field{
          .name = "",
          .type = ty,
          .offset = 0,
          .is_bitfield = false,
          .bitfield =
              Bitfield{
                  .read_bytes = 0,
                  .access_rshift = 0,
                  .mask = 0,
              },
      });
    }

    if (call.func == "printf")
    {
      if (single_provider_type_postsema(probe_) == ProbeType::iter)
      {
        resources_.seq_printf_args.emplace_back(fmt, args);
        resources_.needs_data_map = true;
      }
      else
      {
        resources_.printf_args.emplace_back(fmt, args);
      }
    }
    else if (call.func == "system")
    {
      resources_.system_args.emplace_back(fmt, args);
    }
    else
    {
      resources_.cat_args.emplace_back(fmt, args);
    }
  }
  else if (call.func == "join")
  {
    auto delim = call.vargs->size() > 1 ? get_literal_string(*call.vargs->at(1))
                                        : " ";
    resources_.join_args.push_back(delim);
    resources_.needs_join_map = true;
  }
  else if (call.func == "lhist")
  {
    Expression &min_arg = *call.vargs->at(1);
    Expression &max_arg = *call.vargs->at(2);
    Expression &step_arg = *call.vargs->at(3);
    Integer &min = static_cast<Integer &>(min_arg);
    Integer &max = static_cast<Integer &>(max_arg);
    Integer &step = static_cast<Integer &>(step_arg);

    resources_.lhist_args[call.map->ident] = LinearHistogramArgs{
      .min = min.n,
      .max = max.n,
      .step = step.n,
    };
  }
  else if (call.func == "time")
  {
    if (call.vargs && call.vargs->size() > 0)
      resources_.time_args.push_back(get_literal_string(*call.vargs->at(0)));
    else
      resources_.time_args.push_back("%H:%M:%S\n");
  }
  else if (call.func == "strftime")
  {
    resources_.strftime_args.push_back(get_literal_string(*call.vargs->at(0)));
  }
  else if (call.func == "print")
  {
    auto &arg = *call.vargs->at(0);
    if (!arg.is_map)
      resources_.non_map_print_args.push_back(arg.type);
  }
  else if (call.func == "kstack" || call.func == "ustack")
  {
    resources_.stackid_maps.insert(call.type.stack_type);
  }
}

void ResourceAnalyser::visit(Map &map)
{
  Visitor::visit(map);

  resources_.map_vals[map.ident] = map.type;
  resources_.map_keys[map.ident] = map.key_type;
}

void ResourceAnalyser::prepare_seq_printf_ids()
{
  int idx = 0;

  for (auto &arg : resources_.seq_printf_args)
  {
    assert(resources_.needs_data_map);
    auto len = std::get<0>(arg).size();
    resources_.seq_printf_ids.push_back({ idx, len + 1 });
    idx += len + 1;
  }
}

Pass CreateResourcePass()
{
  auto fn = [](Node &n, PassContext &ctx) {
    ResourceAnalyser analyser{ &n };
    auto resources = analyser.analyse();
    ctx.b.resources = resources;

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
