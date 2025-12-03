#include "kernel_types.h"

namespace bpftrace {

Result<btf::Types> KernelTypes::get_kernel_btf(
    const std::optional<std::string> &module)
{
  if (!vmlinux_) {
    auto *btf = btf__load_vmlinux_btf();
    if (!btf) {
      return make_error<SystemError>("failed to load vmlinux BTF");
    }
    vmlinux_.emplace(btf::Types::create(btf));
  }
  if (!module) {
    return *vmlinux_;
  }
  auto it = modules_.find(*module);
  if (it != modules_.end()) {
    return it->second;
  }
  auto *btf = btf__load_module_btf(module->c_str(), vmlinux_->btf_library());
  if (!btf) {
    return make_error<SystemError>("failed to load module BTF");
  }
  return modules_.emplace(*module, btf::Types::create(btf)).first->second;
}

Result<std::vector<std::string>> KernelTypes::list_modules()
{
  return std::vector<std::string>();
}

Result<btf::Types> KernelTypes::get_user_btf(
    [[maybe_unused]] const std::string &binary_path)
{
  return make_error<SystemError>("unable to load user types");
}

} // namespace bpftrace
