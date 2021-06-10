#include "resource_analyser.h"

#include "bpftrace.h"

namespace bpftrace {
namespace ast {

ResourceAnalyser::ResourceAnalyser(Node *root) : root_(root)
{
}

RequiredResources ResourceAnalyser::analyse()
{
  Visit(*root_);
  return resources_;
}

Pass CreateResourcePass()
{
  auto fn = [](Node &n, PassContext &ctx) {
    ResourceAnalyser analyser{ &n };
    auto resources = analyser.analyse();
    ctx.b.resources = resources;

    return PassResult::Success();
  };

  return Pass("ResourceAnalyser", fn);
}

} // namespace ast
} // namespace bpftrace
