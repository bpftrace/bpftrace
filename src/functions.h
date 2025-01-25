#pragma once

#include <optional>
#include <ostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "location.hh"
#include "types.h"

namespace bpftrace {

// A parameter for a BpfScript function
class Param {
public:
  Param(std::string name, const SizedType &type)
      : name_(std::move(name)), type_(type)
  {
  }

  const std::string &name() const
  {
    return name_;
  }
  const SizedType &type() const
  {
    return type_;
  }

private:
  std::string name_;
  SizedType type_;
};

// Represents the type of a function which is callable in a BpfScript program.
//
// The function's implementation is not contained here.
class Function {
public:
  // "Builtin" functions are hardcoded into bpftrace.
  // "Script" functions are user-defined in BpfScript.
  // "External" functions are imported from pre-compiled BPF programs.
  enum class Origin {
    Builtin,
    Script,
    External,
  };

  Function(Origin origin,
           std::string name,
           const SizedType &return_type,
           const std::vector<Param> &params)
      : name_(std::move(name)),
        return_type_(return_type),
        params_(params),
        origin_(origin)
  {
  }

  const std::string &name() const
  {
    return name_;
  }
  const SizedType &return_type() const
  {
    return return_type_;
  }
  const std::vector<Param> &params() const
  {
    return params_;
  }
  Origin origin() const
  {
    return origin_;
  }

private:
  std::string name_;
  SizedType return_type_;
  std::vector<Param> params_;
  Origin origin_;
};

// Registry of callable functions
//
// Non-builtin functions are not allowed to share the same name. When a builtin
// and a non-builtin function share a name, the non-builtin is preferred.
class FunctionRegistry {
public:
  const Function *add(Function::Origin origin,
                      std::string_view name,
                      const SizedType &return_type,
                      const std::vector<Param> &params);
  const Function *add(Function::Origin origin,
                      std::string_view ns,
                      std::string_view name,
                      const SizedType &return_type,
                      const std::vector<Param> &params);

  // Returns the best match for the given function name and arguments
  const Function *get(std::string_view ns,
                      std::string_view name,
                      const std::vector<SizedType> &arg_types,
                      std::ostream &out = std::cerr,
                      std::optional<location> loc = {}) const;

private:
  struct FqName {
    std::string ns;
    std::string name;

    std::string str() const
    {
      if (ns.empty())
        return name;
      return ns + "::" + name;
    }

    bool operator==(const FqName &other) const
    {
      return ns == other.ns && name == other.name;
    }
  };

  class HashFqName {
  public:
    size_t operator()(const FqName &fq_name) const
    {
      return std::hash<std::string>()(fq_name.ns) ^
             std::hash<std::string>()(fq_name.name);
    }
  };

  std::unordered_map<FqName,
                     std::vector<std::reference_wrapper<const Function>>,
                     HashFqName>
      funcs_by_fq_name_;
  std::vector<std::unique_ptr<Function>> all_funcs_;
};

} // namespace bpftrace
