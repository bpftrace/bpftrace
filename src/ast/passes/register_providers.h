#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include "ast/pass_manager.h"
#include "btf/btf.h"
#include "providers/provider.h"
#include "util/result.h"

namespace bpftrace::ast {

// Registry for all available providers.
//
// This provides a convenient way to register a set of providers.
class ProviderRegistry : public State<"providers"> {
public:
  using Provider = providers::Provider;
  using AttachPointList = providers::AttachPointList;

  // Register a providers, returning an error if there are
  // any conflicts or errors.
  Result<> add(std::unique_ptr<Provider> &&provider);

  // Looks up a provider by name.
  const Provider *lookup(const std::string &name);

  // Looks up a provider by type.
  template <typename T>
  const Provider *lookup()
  {
    return lookup(T().name());
  }

  // Return matching attachpoints, given a glob.
  //
  // Note that these attach points could belong to different providers, and
  // need to be grouped appropriately in order to use multiple attachpoints.
  // This is left as the responsibility of the caller.
  Result<std::vector<std::pair<const Provider *, AttachPointList>>> get_all_matching(
      const std::string &provider_glob,
      const std::string &target_glob,
      providers::BtfLookup &btf) const;

private:
  std::unordered_map<std::string, std::unique_ptr<Provider>> providers_by_name_;
  std::unordered_map<std::string, Provider *> aliases_to_provider_;
};

// Returns a registry will all known providers.
Result<ProviderRegistry> DefaultProviderRegistry();

// Registers known providers.
Pass CreateRegisterProvidersPass();

} // namespace bpftrace::ast
