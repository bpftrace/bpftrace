#include "mocks.h"
#include "data/data_source_btf.h"
#include "symbols/elf_parser.h"
#include "symbols/kernel.h"
#include "gmock/gmock-nice-strict.h"

namespace bpftrace::test {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

symbols::ModuleSet MockKernelInfo::get_modules(
    [[maybe_unused]] const std::optional<std::string> &mod_name) const
{
  static const symbols::ModuleSet modules = {
    "vmlinux", "mock_vmlinux", "kernel_mod_1", "kernel_mod_2"
  };
  return modules;
}

static symbols::ModulesFuncsMap make_mock_functions()
{
  symbols::ModulesFuncsMap result;
  result.emplace("vmlinux",
                 std::make_shared<symbols::FunctionSet>(
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
                 std::make_shared<symbols::FunctionSet>(
                     std::set<std::string>({ "mod_func_1", "mod_func_2" })));
  result.emplace("kernel_mod_2",
                 std::make_shared<symbols::FunctionSet>(
                     std::set<std::string>({ "mod_func_1" })));
  return result;
}

static symbols::ModulesFuncsMap make_mock_raw_tracepoints()
{
  symbols::ModulesFuncsMap result;
  result.emplace("vmlinux",
                 std::make_shared<symbols::FunctionSet>(
                     std::set<std::string>({ "event_rt", "sched_switch" })));
  result.emplace("module",
                 std::make_shared<symbols::FunctionSet>(
                     std::set<std::string>({ "event" })));
  return result;
}

static symbols::ModulesFuncsMap make_mock_tracepoints()
{
  symbols::ModulesFuncsMap result;
  result.emplace("vmlinux",
                 std::make_shared<symbols::FunctionSet>(
                     std::set<std::string>({ "event_rt" })));
  result.emplace("category",
                 std::make_shared<symbols::FunctionSet>(
                     std::set<std::string>({ "event" })));
  result.emplace("sched",
                 std::make_shared<symbols::FunctionSet>(
                     std::set<std::string>({ "sched_one", "sched_two" })));
  result.emplace("sched_extra",
                 std::make_shared<symbols::FunctionSet>(
                     std::set<std::string>({ "sched_extra" })));
  result.emplace("notsched",
                 std::make_shared<symbols::FunctionSet>(
                     std::set<std::string>({ "bar" })));
  result.emplace("file",
                 std::make_shared<symbols::FunctionSet>(
                     std::set<std::string>({ "filename" })));
  result.emplace("tcp",
                 std::make_shared<symbols::FunctionSet>(
                     std::set<std::string>({ "some_tcp_tp" })));
  result.emplace("btf",
                 std::make_shared<symbols::FunctionSet>(
                     std::set<std::string>({ "tag" })));
  return result;
}

symbols::ModulesFuncsMap MockKernelInfo::get_traceable_funcs(
    const std::optional<std::string> &mod_name) const
{
  static const symbols::ModulesFuncsMap funcs_map = make_mock_functions();
  return filter(funcs_map, mod_name);
}

symbols::ModulesFuncsMap MockKernelInfo::get_raw_tracepoints(
    const std::optional<std::string> &mod_name) const
{
  static const symbols::ModulesFuncsMap raw_tracepoints_map =
      make_mock_raw_tracepoints();
  return filter(raw_tracepoints_map, mod_name);
}

symbols::ModulesFuncsMap MockKernelInfo::get_tracepoints(
    const std::optional<std::string> &category_name) const
{
  static const symbols::ModulesFuncsMap tracepoints_map =
      make_mock_tracepoints();
  return filter(tracepoints_map, category_name);
}

Result<btf::Types> MockKernelInfo::load_btf(const std::string &mod_name) const
{
  if (mod_name == "vmlinux") {
    return btf::Types::parse(reinterpret_cast<const char *>(btf_data),
                             sizeof(btf_data));
  }
  return btf::Types();
}

std::vector<std::pair<__u32, std::string>> MockKernelInfo::get_bpf_progs() const
{
  return {
    { 123, "func_1" },
    { 123, "func_2" },
    { 456, "func_1" },
  };
}

Result<symbols::FunctionSet> MockUserInfo::func_symbols_for_path(
    const std::string &path) const
{
  if (path == "/bin/sh") {
    return symbols::FunctionSet({ "f",
                                  "first_open",
                                  "main",
                                  "readline",
                                  "second_open",
                                  "cpp_mangled",
                                  "_Z11cpp_mangledi",
                                  "_Z11cpp_mangledv",
                                  "_Z18cpp_mangled_suffixv" });
  } else if (path == "/bin/bash") {
    return symbols::FunctionSet({ "f",
                                  "first_open",
                                  "main",
                                  "readline",
                                  "cpp_mangled",
                                  "_Z11cpp_mangledi",
                                  "_Z11cpp_mangledv",
                                  "_Z18cpp_mangled_suffixv" });
  }
  return symbols::FunctionSet();
}

Result<symbols::BinaryFuncMap> MockUserInfo::func_symbols_for_pid(
    [[maybe_unused]] int pid) const
{
  return symbols::BinaryFuncMap();
}

Result<symbols::BinaryUSDTMap> MockUserInfo::usdt_probes_for_pid(
    [[maybe_unused]] int pid) const
{
  return symbols::BinaryUSDTMap();
}

Result<symbols::BinaryUSDTMap> MockUserInfo::usdt_probes_for_all_pids() const
{
  return symbols::BinaryUSDTMap();
}

Result<symbols::USDTSet> MockUserInfo::usdt_probes_for_path(
    const std::string &path) const
{
  if (path == "/bin/sh") {
    return symbols::USDTSet({ symbols::usdt_probe_entry("prov1", "tp1"),
                              symbols::usdt_probe_entry("prov1", "tp2"),
                              symbols::usdt_probe_entry("prov2", "tp"),
                              symbols::usdt_probe_entry("prov2", "notatp"),
                              symbols::usdt_probe_entry("nahprov", "tp") });
  } else if (path == "/bin/bash") {
    return symbols::USDTSet({ symbols::usdt_probe_entry("prov1", "tp3") });
  }
  return symbols::USDTSet();
}

ast::FunctionInfo &get_mock_function_info()
{
  static MockKernelInfo kernel_func_info;
  static MockUserInfo user_func_info;
  static ast::FunctionInfo func_info_state(kernel_func_info, user_func_info);
  return func_info_state;
}

std::unique_ptr<ast::FunctionInfo> get_real_user_info()
{
  // Use a static mock kernel function info (same as mock function info)
  // but with a real user function info that can read actual binaries.
  static MockKernelInfo kernel_func_info;
  static symbols::UserInfoImpl user_func_info;
  return std::make_unique<ast::FunctionInfo>(kernel_func_info, user_func_info);
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
