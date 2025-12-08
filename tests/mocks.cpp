#include "mocks.h"
#include "tracefs/tracefs.h"
#include "util/elf_parser.h"
#include "gmock/gmock-nice-strict.h"

namespace bpftrace::test {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

// MockKernelFunctionInfo implementations
bool MockKernelFunctionInfo::is_traceable(
    [[maybe_unused]] const std::string &func_name) const
{
  return true;
}

std::unordered_set<std::string> MockKernelFunctionInfo::get_modules(
    const std::string &func) const
{
  if (func == "func_in_mod" || func == "other_func_in_mod")
    return { "kernel_mod", "other_kernel_mod" };
  if (func == "queued_spin_lock_slowpath")
    return { "vmlinux" };
  return { "mock_vmlinux" };
}

const util::FuncsModulesMap &MockKernelFunctionInfo::get_traceable_funcs() const
{
  static const util::FuncsModulesMap funcs_map = {
    { "SyS_read", { "vmlinux" } },
    { "sys_read", { "vmlinux" } },
    { "sys_write", { "vmlinux" } },
    { "my_one", { "vmlinux" } },
    { "my_two", { "vmlinux" } },
    { "func_in_mod", { "kernel_mod", "other_kernel_mod" } },
    { "other_func_in_mod", { "kernel_mod" } },
    { "queued_spin_lock_slowpath", { "vmlinux" } },
    { "func_1", { "vmlinux" } },
    { "func_2", { "vmlinux" } },
    { "func_3", { "vmlinux" } },
  };
  return funcs_map;
}

const util::FuncsModulesMap &MockKernelFunctionInfo::get_raw_tracepoints() const
{
  static const util::FuncsModulesMap raw_tracepoints_map = {
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

// MockUserFunctionInfo implementations
Result<std::unique_ptr<std::istream>> MockUserFunctionInfo::
    get_symbols_from_file(const std::string &path) const
{
  if (path == tracefs::available_events()) {
    return std::make_unique<std::istringstream>(
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
      "/bin/sh:first_open\n/bin/sh:second_open\n/bin/sh:open_as_well\n"
      "/bin/sh:something_else\n/bin/sh:cpp_mangled\n/bin/sh:_Z11cpp_mangledi\n"
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

const util::FuncsModulesMap &MockBtfKernelFunctionInfo::get_traceable_funcs()
    const
{
  // Functions from the test BTF data (data_source.c).
  static const util::FuncsModulesMap funcs_map = {
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

const util::FuncsModulesMap &MockBtfKernelFunctionInfo::get_raw_tracepoints()
    const
{
  // Raw tracepoints from the test BTF data.
  static const util::FuncsModulesMap raw_tracepoints_map = {
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

// MockBPFtrace member function implementations
util::KernelFunctionInfo *MockBPFtrace::get_mock_kernel_func_info()
{
  // Return pointer to the static mock kernel function info
  static MockKernelFunctionInfo kernel_func_info;
  return &kernel_func_info;
}

util::UserFunctionInfo *MockBPFtrace::get_mock_user_func_info()
{
  // Return pointer to the static mock user function info
  static MockUserFunctionInfo user_func_info;
  return &user_func_info;
}

// Helper function implementations
ast::FunctionInfo &get_mock_function_info()
{
  static MockKernelFunctionInfo kernel_func_info;
  static MockUserFunctionInfo user_func_info;
  static ast::FunctionInfo func_info_state(kernel_func_info, user_func_info);
  return func_info_state;
}

std::unique_ptr<BPFtrace> create_bpftrace()
{
  auto result = BPFtrace::create();
  if (!result) {
    throw std::runtime_error("Failed to create BPFtrace for test");
  }

  return std::move(*result);
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

  bpftrace->feature_ = std::make_unique<MockBPFfeature>(*bpftrace->btf_, true);

  return bpftrace;
}

std::unique_ptr<MockBPFtrace> get_strict_mock_bpftrace()
{
  auto bpftrace = std::make_unique<StrictMock<MockBPFtrace>>();
  setup_mock_bpftrace(*bpftrace);

  bpftrace->feature_ = std::make_unique<MockBPFfeature>(*bpftrace->btf_, true);

  return bpftrace;
}

} // namespace bpftrace::test
