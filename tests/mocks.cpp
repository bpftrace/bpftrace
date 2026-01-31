#include "mocks.h"
#include "util/elf_parser.h"
#include "util/kernel.h"
#include "gmock/gmock-nice-strict.h"

namespace bpftrace::test {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

util::ModuleSet MockKernelFunctionInfo::get_modules(
    [[maybe_unused]] const std::optional<std::string> &mod_name) const
{
  static const util::ModuleSet modules = {
    "vmlinux", "mock_vmlinux", "kernel_mod_1", "kernel_mod_2"
  };
  return modules;
}

static util::ModulesFuncsMap make_mock_functions()
{
  util::ModulesFuncsMap result;
  result.emplace("vmlinux",
                 std::make_shared<util::FunctionSet>(
                     std::set<std::string>({ "f",
                                             "func_1",
                                             "func_2",
                                             "func_3",
                                             "func_anon_struct",
                                             "func_array_with_compound_data",
                                             "func_arrays",
                                             "main",
                                             "sys_read",
                                             "sys_write",
                                             "tcp_shutdown",
                                             "queued_spin_lock_slowpath",
                                             "bpf_map_sum_elem_count",
                                             "bpf_iter_task",
                                             "bpf_iter_task_file",
                                             "bpf_iter_task_vma",
                                             "__probestub_event_rt" })));
  result.emplace("kernel_mod_1",
                 std::make_shared<util::FunctionSet>(
                     std::set<std::string>({ "mod_func_1", "mod_func_2" })));
  result.emplace("kernel_mod_2",
                 std::make_shared<util::FunctionSet>(
                     std::set<std::string>({ "mod_func_1" })));
  return result;
}

static util::ModulesFuncsMap make_mock_raw_tracepoints()
{
  util::ModulesFuncsMap result;
  result.emplace("vmlinux",
                 std::make_shared<util::FunctionSet>(
                     std::set<std::string>({ "event_rt", "sched_switch" })));
  result.emplace("module",
                 std::make_shared<util::FunctionSet>(
                     std::set<std::string>({ "event" })));
  return result;
}

static util::ModulesFuncsMap make_mock_tracepoints()
{
  util::ModulesFuncsMap result;
  result.emplace("vmlinux",
                 std::make_shared<util::FunctionSet>(
                     std::set<std::string>({ "event_rt" })));
  result.emplace("category",
                 std::make_shared<util::FunctionSet>(
                     std::set<std::string>({ "event" })));
  result.emplace("sched",
                 std::make_shared<util::FunctionSet>(
                     std::set<std::string>({ "sched_one", "sched_two" })));
  result.emplace("sched_extra",
                 std::make_shared<util::FunctionSet>(
                     std::set<std::string>({ "sched_extra" })));
  result.emplace("notsched",
                 std::make_shared<util::FunctionSet>(
                     std::set<std::string>({ "bar" })));
  result.emplace("file",
                 std::make_shared<util::FunctionSet>(
                     std::set<std::string>({ "filename" })));
  result.emplace("tcp",
                 std::make_shared<util::FunctionSet>(
                     std::set<std::string>({ "some_tcp_tp" })));
  result.emplace("btf",
                 std::make_shared<util::FunctionSet>(
                     std::set<std::string>({ "tag" })));
  return result;
}

util::ModulesFuncsMap MockKernelFunctionInfo::get_traceable_funcs(
    const std::optional<std::string> &mod_name) const
{
  static const util::ModulesFuncsMap funcs_map = make_mock_functions();
  return filter(funcs_map, mod_name);
}

util::ModulesFuncsMap MockKernelFunctionInfo::get_raw_tracepoints(
    const std::optional<std::string> &mod_name) const
{
  static const util::ModulesFuncsMap raw_tracepoints_map =
      make_mock_raw_tracepoints();
  return filter(raw_tracepoints_map, mod_name);
}

util::ModulesFuncsMap MockKernelFunctionInfo::get_tracepoints(
    const std::optional<std::string> &category_name) const
{
  static const util::ModulesFuncsMap tracepoints_map = make_mock_tracepoints();
  return filter(tracepoints_map, category_name);
}

std::vector<std::pair<__u32, std::string>> MockKernelFunctionInfo::
    get_bpf_progs() const
{
  return {
    { 123, "func_1" },
    { 123, "func_2" },
    { 456, "func_1" },
  };
}

Result<util::FunctionSet> MockUserFunctionInfo::func_symbols_for_path(
    const std::string &path) const
{
  if (path == "/bin/sh") {
    return util::FunctionSet({ "f",
                               "first_open",
                               "main",
                               "readline",
                               "second_open",
                               "cpp_mangled",
                               "_Z11cpp_mangledi",
                               "_Z11cpp_mangledv",
                               "_Z18cpp_mangled_suffixv" });
  } else if (path == "/bin/bash") {
    return util::FunctionSet({ "f",
                               "first_open",
                               "main",
                               "readline",
                               "cpp_mangled",
                               "_Z11cpp_mangledi",
                               "_Z11cpp_mangledv",
                               "_Z18cpp_mangled_suffixv" });
  }
  return util::FunctionSet();
}

Result<util::BinaryFuncMap> MockUserFunctionInfo::func_symbols_for_pid(
    [[maybe_unused]] int pid) const
{
  return util::BinaryFuncMap();
}

Result<util::BinaryUSDTMap> MockUserFunctionInfo::usdt_probes_for_pid(
    [[maybe_unused]] int pid) const
{
  return util::BinaryUSDTMap();
}

Result<util::BinaryUSDTMap> MockUserFunctionInfo::usdt_probes_for_all_pids()
    const
{
  return util::BinaryUSDTMap();
}

Result<util::USDTSet> MockUserFunctionInfo::usdt_probes_for_path(
    const std::string &path) const
{
  if (path == "/bin/sh") {
    return util::USDTSet({ util::usdt_probe_entry("prov1", "tp1"),
                           util::usdt_probe_entry("prov1", "tp2"),
                           util::usdt_probe_entry("prov2", "tp"),
                           util::usdt_probe_entry("prov2", "notatp"),
                           util::usdt_probe_entry("nahprov", "tp") });
  } else if (path == "/bin/bash") {
    return util::USDTSet({ util::usdt_probe_entry("prov1", "tp3") });
  }
  return util::USDTSet();
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
