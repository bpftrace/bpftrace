#include "functions.h"

#include "log.h"

namespace bpftrace {

Function &FunctionRegistry::add(Function::Origin origin,
                                std::string_view name,
                                const SizedType &returnType,
                                std::vector<Param> params)
{
  all_funcs_.push_back(std::make_unique<Function>(
      origin, std::string{ name }, returnType, params));
  Function &newFunc = *all_funcs_.back().get();
  funcs_by_fq_name_[newFunc.name()].push_back(newFunc);
  return newFunc;
}

Function &FunctionRegistry::add(Function::Origin origin,
                                std::string_view ns,
                                std::string_view name,
                                const SizedType &returnType,
                                std::vector<Param> params)
{
  all_funcs_.push_back(std::make_unique<Function>(
      origin, std::string{ name }, returnType, params));
  Function &newFunc = *all_funcs_.back().get();
  // TODO use proper namespacing syntax instead of underscore:
  funcs_by_fq_name_[std::string{ ns } + "_" + newFunc.name()].push_back(
      newFunc);
  return newFunc;
}

namespace {
bool can_implicit_cast(const SizedType &from, const SizedType &to)
{
  if (from.FitsInto(to))
    return true;

  // TODO Native BpfScript functions should ignore string sizes
  if (from.IsStringTy() && to.IsPtrTy() && to.GetPointeeTy()->IsIntTy() &&
      to.GetPointeeTy()->GetSize() == 1) {
    // Allow casting from string to int8* or uint8*
    return true;
  }

  return false;
}
} // namespace

const Function *FunctionRegistry::get(const std::string &name,
                                      const std::vector<SizedType> &arg_types,
                                      std::optional<location> loc) const
{
  auto it = funcs_by_fq_name_.find(name);
  if (it == funcs_by_fq_name_.end()) {
    return nullptr;
  }

  const auto &candidates = it->second;

  for (const Function &candidate : candidates) {
    if (candidate.params().size() != arg_types.size())
      continue;

    bool match = true;
    for (size_t i = 0; i < arg_types.size(); i++) {
      if (!can_implicit_cast(arg_types[i], candidate.params()[i].type())) {
        match = false;
        break;
      }
    }

    if (match)
      return &candidate;
  }

  std::string error = "No match for function: " + name + "(";
  bool first = true;
  for (const SizedType &arg_type : arg_types) {
    if (!first)
      error += ", ";
    error += typestr(arg_type);
    first = false;
  }
  error += ")";
  // TODO add runtime tests checking error messages
  LOG(ERROR, loc) << error;

  std::string hint = "Candidates:\n";
  for (const Function &candidate : candidates) {
    hint += "        " + candidate.name() + "(";
    bool first = true;
    for (const Param &param : candidate.params()) {
      if (!first)
        hint += ", ";
      hint += typestr(param.type());
      first = false;
    }
    hint += ")";
  }
  LOG(HINT) << hint;

  return nullptr;
}

} // namespace bpftrace
