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

const Function *FunctionRegistry::add(Function::Origin origin,
                                      std::string_view name,
                                      const SizedType &return_type,
                                      const std::vector<Param> &params)
{
  return add(origin, {}, name, return_type, params);
}

const Function *FunctionRegistry::add(Function::Origin origin,
                                      std::string_view ns,
                                      std::string_view name,
                                      const SizedType &return_type,
                                      const std::vector<Param> &params)
{
  FqName fq_name{
    .ns = std::string{ ns },
    .name = std::string{ name },
  };

  // Check for duplicate function definitions
  // The assumption is that builtin functions are all added to the registry
  // before any user-defined functions.
  // Builtin functions can be duplicated. Other functions can not.
  for (const Function &func : funcs_by_fq_name_[fq_name]) {
    if (func.origin() != Function::Origin::Builtin) {
      return nullptr;
    }
  }

  all_funcs_.push_back(std::make_unique<Function>(
      origin, std::string{ name }, return_type, params));
  Function &new_func = *all_funcs_.back().get();

  funcs_by_fq_name_[fq_name].push_back(new_func);
  return &new_func;
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

// Find the best function by name for the given argument types.
//
// Returns either a single function or nullptr, when no such function exists.
//
// When there are multiple candidate functions with the same name, prefer the
// non-builtin over the builtin function.
//
// Valid functions have the correct name and all arguments can be implicitly
// casted into all parameter types.
const Function *FunctionRegistry::get(std::string_view ns,
                                      std::string_view name,
                                      const std::vector<SizedType> &arg_types,
                                      std::ostream &out,
                                      std::optional<location> loc) const
{
  FqName fq_name = {
    .ns = std::string{ ns },
    .name = std::string{ name },
  };
  auto it = funcs_by_fq_name_.find(fq_name);
  if (it == funcs_by_fq_name_.end()) {
    LOG(ERROR, loc, out) << "Function not found: '" << name << "'";
    return nullptr;
  }

  const auto &candidates = it->second;

  // We disallow duplicate functions other than for builtins, so expect at most
  // two exact matches.
  assert(candidates.size() <= 2);

  // No candidates => no match
  // 1 candidate   => use it
  // 2 candidates  => use non-builtin candidate
  const Function *candidate = nullptr;
  for (const Function &func : candidates) {
    candidate = &func;
    if (candidate->origin() != Function::Origin::Builtin)
      break;
  }

  // Validate that the candidate's parameters can take our arguments
  if (candidate) {
    bool valid = true;
    if (candidate->params().size() != arg_types.size()) {
      valid = false;
    } else {
      for (size_t i = 0; i < arg_types.size(); i++) {
        if (!can_implicit_cast(arg_types[i], candidate->params()[i].type())) {
          valid = false;
          break;
        }
      }
    }

    if (valid)
      return candidate;
  }

  LOG(ERROR, loc, out) << "Cannot call function '" << name
                       << "' using argument types: "
                       << arg_types_str(arg_types);
  LOG(HINT, out) << "Candidate function:\n  " << candidate->name()
                 << param_types_str(candidate->params());

  return nullptr;
}

} // namespace bpftrace
