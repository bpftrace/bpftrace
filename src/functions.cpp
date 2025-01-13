#include "functions.h"

#include "log.h"

namespace bpftrace {

namespace {
std::string arg_types_str(const std::vector<SizedType> &arg_types)
{
  std::string str = "(";
  bool first = true;
  for (const SizedType &arg_type : arg_types) {
    if (!first)
      str += ", ";
    str += typestr(arg_type);
    first = false;
  }
  str += ")";
  return str;
}

std::string param_types_str(const std::vector<Param> &params)
{
  std::string str = "(";
  bool first = true;
  for (const Param &param : params) {
    if (!first)
      str += ", ";
    str += typestr(param.type());
    first = false;
  }
  str += ")";
  return str;
}
} // namespace

FunctionRegistry::FunctionRegistry(std::ostream &out) : out_(out)
{
}

Function &FunctionRegistry::add(Function::Origin origin,
                                std::string_view name,
                                const SizedType &returnType,
                                std::vector<Param> params)
{
  return add(origin, {}, name, returnType, params);
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
  std::string fq_name;
  if (ns.empty())
    fq_name = name;
  else
    fq_name = std::string{ ns } + "::" + newFunc.name();

  // Check for duplicate function definitions
  // The assumption is that builtin functions are all added to the registry
  // before any user-defined functions.
  for (const Function &func : funcs_by_fq_name_[fq_name]) {
    if (func.origin() == Function::Origin::Builtin)
      continue; // Allow duplicates of builtins
    if (func.params().size() != params.size())
      continue;
    bool is_dup = true;
    for (size_t i = 0; i < func.params().size(); i++) {
      if (func.params()[i].type() != params[i].type()) {
        is_dup = false;
        break;
      }
    }
    if (is_dup) {
      throw std::runtime_error("Cannot redefine existing function: " + fq_name +
                               param_types_str(params));
    }
  }

  funcs_by_fq_name_[fq_name].push_back(newFunc);
  return newFunc;
}

namespace {
bool can_implicit_cast(const SizedType &from, const SizedType &to)
{
  if (from.FitsInto(to))
    return true;

  if (from.IsStringTy() && to.IsPtrTy() && to.GetPointeeTy()->IsIntTy() &&
      to.GetPointeeTy()->GetSize() == 1) {
    // Allow casting from string to int8* or uint8*
    return true;
  }

  // Builtin and script functions do not care about string sizes. External
  // functions cannot be defined to accept string types (they'd take char*)
  if (from.IsStringTy() && to.IsStringTy())
    return true;

  return false;
}
} // namespace

/*
 * Find the best function called 'name' for the given argument types.
 *
 * Returns either a single function or nullptr, when no such function exists or
 * a single best match can not be found.
 *
 * Summary of overload resolution rules:
 * 1. If a single valid candidate function exists, pick that
 * 2. If one of the candidates is an exact type match, pick that
 * 3. If multiple candidates are exact type matches, prefer script/external
 *    functions over builtin functions
 * 4. If there are multiple, non-exact matches, return no-match
 *
 * Valid functions have the correct name and all arguments can be implicitly
 * casted into all parameter types.
 */
const Function *FunctionRegistry::get(const std::string &name,
                                      const std::vector<SizedType> &arg_types,
                                      std::optional<location> loc) const
{
  auto it = funcs_by_fq_name_.find(name);
  if (it == funcs_by_fq_name_.end()) {
    LOG(ERROR, out_) << "Function not found: '" << name << "'";
    return nullptr;
  }

  const auto &candidates = it->second;
  std::vector<std::reference_wrapper<const Function>> exact_matches,
      valid_matches;

  for (const Function &candidate : candidates) {
    if (candidate.params().size() != arg_types.size())
      continue;

    bool valid = true;
    bool exact = true;
    for (size_t i = 0; i < arg_types.size(); i++) {
      if (arg_types[i] != candidate.params()[i].type())
        exact = false;
      if (!can_implicit_cast(arg_types[i], candidate.params()[i].type())) {
        valid = false;
        break;
      }
    }

    if (exact)
      exact_matches.push_back(candidate);
    if (valid)
      valid_matches.push_back(candidate);
  }

  // 1. If a single valid candidate function exists, pick that
  if (valid_matches.size() == 1)
    return &valid_matches[0].get();

  // 2. If one of the candidates is an exact type match, pick that
  if (exact_matches.size() == 1)
    return &exact_matches[0].get();

  // 3. If multiple candidates are exact type matches, prefer script/external
  // functions over builtin functions
  if (exact_matches.size() == 2) {
    if (exact_matches[0].get().origin() == Function::Origin::Builtin)
      return &exact_matches[1].get();
    return &exact_matches[0].get();
  }

  // We disallow duplicate functions other than for builtins, so expect at most
  // two exact matches.
  if (exact_matches.size() > 2)
    LOG(BUG) << "Duplicate functions in registry";

  auto *hint_candidates = &candidates;
  std::string error;
  if (valid_matches.size() == 0) {
    error = "Cannot call function '" + name +
            "' using argument types: " + arg_types_str(arg_types);
  } else {
    error = "Could not pick between multiple candidate functions in call to: " +
            name + arg_types_str(arg_types);
    hint_candidates = &valid_matches;
  }

  LOG(ERROR, loc, out_) << error;

  std::string hint = "Candidate functions:";
  for (const Function &candidate : *hint_candidates) {
    hint += "\n  " + candidate.name() + param_types_str(candidate.params());
  }
  LOG(HINT, out_) << hint;

  return nullptr;
}

} // namespace bpftrace
