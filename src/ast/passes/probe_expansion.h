#pragma once

#include <set>

#include "ast/ast.h"
#include "ast/pass_manager.h"

namespace bpftrace::ast {

// There are 3 kinds of attach point expansion:
// - full expansion  - separate LLVM function is generated for each match
// - multi expansion - one LLVM function and BPF program is generated for all
//                     matches, the list of expanded functions is attached to
//                     the BPF program using the k(u)probe.multi mechanism
// - session expansion - extension of the multi expansion when a single BPF
//                       program is shared for both the entry and the exit probe
//                       (when they are both attached to the same attach points)
//                       using the kprobe.session mechanism
enum class ExpansionType {
  NONE,
  FULL,
  MULTI,
  SESSION,
};

class ExpansionResult : public State<"expansions"> {
public:
  ExpansionResult() = default;
  ExpansionResult(const ExpansionResult &) = delete;
  ExpansionResult &operator=(const ExpansionResult &) = delete;
  ExpansionResult(ExpansionResult &&) = default;
  ExpansionResult &operator=(ExpansionResult &&) = default;

  void set_ap_expansion(AttachPoint &ap, ExpansionType type)
  {
    ap_expansions[&ap] = type;
  }
  ExpansionType get_ap_expansion(AttachPoint &ap)
  {
    auto exp = ap_expansions.find(&ap);
    if (exp == ap_expansions.end())
      return ExpansionType::NONE;
    return exp->second;
  }

  void set_expanded_funcs(AttachPoint &ap, std::set<std::string> funcs)
  {
    expanded_funcs.emplace(&ap, std::move(funcs));
  }
  void add_expanded_func(AttachPoint &ap, const std::string &func)
  {
    auto funcs = expanded_funcs.emplace(&ap, std::set<std::string>());
    funcs.first->second.insert(func);
  }
  std::set<std::string> get_expanded_funcs(AttachPoint &ap)
  {
    auto funcs = expanded_funcs.find(&ap);
    if (funcs == expanded_funcs.end())
      return {};

    return funcs->second;
  }

  void add_probe(Probe * probe) {
    probe_expansions.insert(probe);
  }

  bool has_probe(Probe* probe) {
    return probe_expansions.contains(probe);
  }

private:
  std::unordered_map<AttachPoint *, ExpansionType> ap_expansions;
  std::unordered_map<AttachPoint *, std::set<std::string>> expanded_funcs;
  std::unordered_set<Probe *> probe_expansions;
};

Pass CreateProbeExpansionPass();

} // namespace bpftrace::ast
