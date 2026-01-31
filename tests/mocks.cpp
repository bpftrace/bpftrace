#include "mocks.h"
#include "tracefs/tracefs.h"
#include "util/elf_parser.h"
#include "gmock/gmock-nice-strict.h"

namespace bpftrace::test {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

bool MockKernelFunctionInfo::is_traceable(
    [[maybe_unused]] const std::string &func_name) const
{
  return true;
}

std::unordered_set<std::string> MockKernelFunctionInfo::get_modules(
    const std::string &func) const
{
  const auto &funcs = get_traceable_funcs();
  auto mod = funcs.find(func);
  return mod != funcs.end() ? mod->second : std::unordered_set<std::string>();
}

bool MockKernelFunctionInfo::is_module_loaded(const std::string &module) const
{
  return (module == "vmlinux" || module == "mock_vmlinux" ||
          module == "kernel_mod_1" || module == "kernel_mod_2");
}

const util::ModulesFuncsMap &MockKernelFunctionInfo::get_traceable_funcs() const
{
  static const util::ModulesFuncsMap funcs_map = {
    { "f", { "vmlinux" } },
    { "func_1", { "vmlinux" } },
    { "func_2", { "vmlinux" } },
    { "func_3", { "vmlinux" } },
    { "func_anon_struct", { "vmlinux" } },
    { "func_array_with_compound_data", { "vmlinux" } },
    { "func_arrays", { "vmlinux" } },
    { "main", { "vmlinux" } },
    { "mod_func_1", { "kernel_mod_1", "kernel_mod_2" } },
    { "mod_func_2", { "kernel_mod_1" } },
    { "sys_read", { "vmlinux" } },
    { "sys_write", { "vmlinux" } },
    { "tcp_shutdown", { "vmlinux" } },
    { "queued_spin_lock_slowpath", { "vmlinux" } },
    { "bpf_map_sum_elem_count", { "vmlinux" } },
    { "bpf_iter_task", { "vmlinux" } },
    { "bpf_iter_task_file", { "vmlinux" } },
    { "bpf_iter_task_vma", { "vmlinux" } },
  };
  return funcs_map;
}

const util::ModulesFuncsMap &MockKernelFunctionInfo::get_raw_tracepoints() const
{
  static const util::ModulesFuncsMap raw_tracepoints_map = {
    { "event", { "module" } },
    { "event_rt", { "vmlinux" } },
    { "sched_switch", { "vmlinux" } },
  };
  return raw_tracepoints_map;
}

std::vector<std::pair<__u32, std::string>> MockKernelFunctionInfo::
    get_bpf_progs() const
{
  // Mock data for testing: return func_1 with IDs 123 and 456, and func_2
  // with ID 123.
  return {
    { 123, "func_1" },
    { 123, "func_2" },
    { 456, "func_1" },
  };
}

Result<std::unique_ptr<std::istream>> MockUserFunctionInfo::
    get_symbols_from_file(const std::string &path) const
{
  if (path == tracefs::available_events()) {
    return std::make_unique<std::istringstream>(
        "category:event\n"
        "sched:sched_one\nsched:sched_two\nsched:foo\nsched_extra:sched_extra\n"
        "notsched:bar\nfile:filename\ntcp:some_tcp_tp\nbtf:tag\nvmlinux:event_"
        "rt\n");
  }
  return std::make_unique<std::istringstream>("");
}

Result<std::unique_ptr<std::istream>> MockUserFunctionInfo::
    get_func_symbols_from_file([[maybe_unused]] std::optional<int> pid,
                               const std::string &path) const
{
  static const std::string sh_usyms =
      "/bin/sh:f\n/bin/sh:first_open\n/bin/sh:main\n/bin/sh:readline\n"
      "/bin/sh:second_open\n/bin/sh:cpp_mangled\n/bin/sh:_Z11cpp_mangledi\n"
      "/bin/sh:_Z11cpp_mangledv\n/bin/sh:_Z18cpp_mangled_suffixv\n";

  if (path == "/bin/sh") {
    return std::make_unique<std::istringstream>(sh_usyms);
  } else if (path == "/bin/*sh") {
    return std::make_unique<std::istringstream>(sh_usyms +
                                                "/bin/bash:first_open\n");
  }
  return std::make_unique<std::istringstream>("");
}

Result<std::unique_ptr<std::istream>> MockUserFunctionInfo::
    get_symbols_from_usdt([[maybe_unused]] std::optional<int> pid,
                          const std::string &target) const
{
  static const std::string sh_usdts =
      "/bin/sh:prov1:tp1\n/bin/sh:prov1:tp2\n/bin/sh:prov2:tp\n"
      "/bin/sh:prov2:notatp\n/bin/sh:nahprov:tp\n";

  if (target == "/bin/sh") {
    return std::make_unique<std::istringstream>(sh_usdts);
  } else if (target == "/bin/*sh") {
    return std::make_unique<std::istringstream>(sh_usdts +
                                                "/bin/bash:prov1:tp3\n");
  }
  return std::make_unique<std::istringstream>("");
}

Result<util::usdt_probe_entry> MockUserFunctionInfo::find_usdt(
    [[maybe_unused]] std::optional<int> pid,
    [[maybe_unused]] const std::string &target,
    [[maybe_unused]] const std::string &provider,
    [[maybe_unused]] const std::string &name) const
{
  return util::usdt_probe_entry{ "", "", "", 0, 0 };
}

Result<util::usdt_probe_list> MockUserFunctionInfo::usdt_probes_for_pid(
    [[maybe_unused]] int pid) const
{
  return util::usdt_probe_list();
}

Result<util::usdt_probe_list> MockUserFunctionInfo::usdt_probes_for_all_pids()
    const
{
  return util::usdt_probe_list();
}

Result<util::usdt_probe_list> MockUserFunctionInfo::usdt_probes_for_path(
    [[maybe_unused]] const std::string &path) const
{
  return util::usdt_probe_list();
}

// MockBtfKernelFunctionInfo implementations
bool MockBtfKernelFunctionInfo::is_traceable(const std::string &func_name) const
{
  const auto &funcs = get_traceable_funcs();
  return funcs.contains(func_name);
}

std::unordered_set<std::string> MockBtfKernelFunctionInfo::get_modules(
    const std::string &func) const
{
  const auto &funcs = get_traceable_funcs();
  auto mod = funcs.find(func);
  return mod != funcs.end() ? mod->second : std::unordered_set<std::string>();
}

bool MockBtfKernelFunctionInfo::is_module_loaded(
    const std::string &module) const
{
  return (module == "vmlinux" || module == "mock_vmlinux" ||
          module == "kernel_mod_1" || module == "kernel_mod_2");
}

const util::ModulesFuncsMap &MockBtfKernelFunctionInfo::get_traceable_funcs()
    const
{
  // Functions from the test BTF data (data_source.c).
  static const util::ModulesFuncsMap funcs_map = {
    { "f", { "vmlinux" } },
    { "func_1", { "vmlinux" } },
    { "func_2", { "vmlinux" } },
    { "func_3", { "vmlinux" } },
    { "func_anon_struct", { "vmlinux" } },
    { "func_array_with_compound_data", { "vmlinux" } },
    { "func_arrays", { "vmlinux" } },
    { "main", { "vmlinux" } },
    { "tcp_shutdown", { "vmlinux" } },
    { "bpf_map_sum_elem_count", { "vmlinux" } },
    { "bpf_iter_task", { "vmlinux" } },
    { "bpf_iter_task_file", { "vmlinux" } },
    { "bpf_iter_task_vma", { "vmlinux" } },
  };
  return funcs_map;
}

const util::ModulesFuncsMap &MockBtfKernelFunctionInfo::get_raw_tracepoints()
    const
{
  // Raw tracepoints from the test BTF data.
  static const util::ModulesFuncsMap raw_tracepoints_map = {
    { "event", { "module" } },
    { "event_rt", { "vmlinux" } },
  };
  return raw_tracepoints_map;
}

std::vector<std::pair<__u32, std::string>> MockBtfKernelFunctionInfo::
    get_bpf_progs() const
{
  // Mock data for testing: return func_1 with IDs 123 and 456, and func_2
  // with ID 123.
  return {
    { 123, "func_1" },
    { 123, "func_2" },
    { 456, "func_1" },
  };
}

ast::FunctionInfo &get_mock_function_info()
{
  static MockKernelFunctionInfo kernel_func_info;
  static MockUserFunctionInfo user_func_info;
  static ast::FunctionInfo func_info_state(kernel_func_info, user_func_info);
  return func_info_state;
}

std::unique_ptr<ast::FunctionInfo> get_real_user_function_info()
{
  // Use a static mock kernel function info (same as mock function info)
  // but with a real user function info that can read actual binaries.
  static MockKernelFunctionInfo kernel_func_info;
  static util::UserFunctionInfoImpl user_func_info;
  return std::make_unique<ast::FunctionInfo>(kernel_func_info, user_func_info);
}

std::unique_ptr<BPFtrace> create_bpftrace()
{
  return std::make_unique<BPFtrace>();
}

void setup_mock_bpftrace(MockBPFtrace &bpftrace)
{
  bpftrace.delta_taitime_ = timespec{};
  // Fill in a tracepoint struct definition so that we don't need to mock the
  // tracepoint format files.
  bpftrace.structs.Add("struct tracepoint:sched:sched_one_args", 8);
  bpftrace.structs.Lookup("struct tracepoint:sched:sched_one_args")
      .lock()
      ->AddField("common_field", CreateUInt64(), 8);
}

std::unique_ptr<MockBPFtrace> get_mock_bpftrace()
{
  auto bpftrace = std::make_unique<NiceMock<MockBPFtrace>>();
  setup_mock_bpftrace(*bpftrace);

  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);

  return bpftrace;
}

std::unique_ptr<MockBPFtrace> get_strict_mock_bpftrace()
{
  auto bpftrace = std::make_unique<StrictMock<MockBPFtrace>>();
  setup_mock_bpftrace(*bpftrace);

  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);

  return bpftrace;
}

} // namespace bpftrace::test
