#include <optional>
#include <string>

#include "providers/provider.h"

namespace bpftrace {

// Default system BTF implementation.
class KernelTypes : public providers::BtfLookup {
public:
  Result<btf::Types> get_kernel_btf(const std::optional<std::string> &module = std::nullopt) override;
  Result<std::vector<std::string>> list_modules() override;
  Result<btf::Types> get_user_btf(const std::string &binary_path) override;

private:
  std::optional<btf::Types> vmlinux_;
  std::unordered_map<std::string, btf::Types> modules_;
  std::unordered_map<std::string, btf::Types> binaries_;
};

} // namespace bpftrace
