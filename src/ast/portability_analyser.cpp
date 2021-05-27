#include "portability_analyser.h"

#include "log.h"

namespace bpftrace {
namespace ast {

PortabilityAnalyser::PortabilityAnalyser(Node *root, std::ostream &out)
    : root_(root), out_(out)
{
}

int PortabilityAnalyser::analyse()
{
  return 0;
}

Pass CreatePortabilityPass()
{
  auto fn = [](Node &n, PassContext &__attribute__((unused))) {
    PortabilityAnalyser analyser{ &n };
    if (analyser.analyse())
      return PassResult::Error("");

    return PassResult::Success();
  };

  return Pass("PortabilityAnalyser", fn);
}

} // namespace ast
} // namespace bpftrace
