#pragma once

#include "ast/passes/attachpoint_passes.h"
#include "attached_probe.h"
#include "bpffeature.h"
#include "bpfmap.h"
#include "bpftrace.h"
#include "child.h"
#include "probe_matcher.h"
#include "procmon.h"
#include "tracefs/tracefs.h"
#include "util/elf_parser.h"
#include "util/kernel.h"
#include "util/result.h"
#include "util/strings.h"
#include "util/user.h"
#include "gmock/gmock-function-mocker.h"

namespace bpftrace::test {

// Mock KernelFunctionInfo for testing.
class MockKernelFunctionInfo : public util::KernelFunctionInfo {
public:
  bool is_traceable(const std::string &func_name) const override;
  std::unordered_set<std::string> get_modules(const std::string &func) const override;
  const util::FuncsModulesMap& get_traceable_funcs() const override;
  const util::FuncsModulesMap& get_raw_tracepoints() const override;
  std::vector<std::pair<__u32, std::string>> get_bpf_progs() const override;
};

// Mock UserFunctionInfo for testing.
class MockUserFunctionInfo : public util::UserFunctionInfo {
public:
  Result<std::unique_ptr<std::istream>> get_symbols_from_file(const std::string &path) const override;
  Result<std::unique_ptr<std::istream>> get_func_symbols_from_file(std::optional<int> pid, const std::string &path) const override;
  Result<std::unique_ptr<std::istream>> get_symbols_from_usdt(std::optional<int> pid, const std::string &target) const override;
  Result<util::usdt_probe_entry> find_usdt(std::optional<int> pid, const std::string &target, const std::string &provider, const std::string &name) const override;
  Result<util::usdt_probe_list> usdt_probes_for_pid(int pid) const override;
  Result<util::usdt_probe_list> usdt_probes_for_all_pids() const override;
  Result<util::usdt_probe_list> usdt_probes_for_path(const std::string & path) const override;
};

// Mock KernelFunctionInfo for BTF tests that returns functions from test data.
class MockBtfKernelFunctionInfo : public util::KernelFunctionInfo {
public:
  bool is_traceable(const std::string &func_name) const override;
  std::unordered_set<std::string> get_modules(const std::string &func) const override;
  const util::FuncsModulesMap &get_traceable_funcs() const override;
  const util::FuncsModulesMap &get_raw_tracepoints() const override;
  std::vector<std::pair<__u32, std::string>> get_bpf_progs() const override;
};

class MockBpfMap : public BpfMap {
public:
  MockBpfMap(bpf_map_type type = BPF_MAP_TYPE_HASH,
             std::string name = "mock_map",
             uint32_t key_size = sizeof(uint64_t),
             uint32_t value_size = sizeof(uint64_t),
             uint32_t max_entries = 10)
      : BpfMap(type, name, key_size, value_size, max_entries)
  {
  }
  MOCK_CONST_METHOD1(collect_elements, Result<MapElements>(int nvalues));
  MOCK_CONST_METHOD2(collect_histogram_data,
                     Result<HistogramMap>(const MapInfo &map_info,
                                          int nvalues));
  MOCK_CONST_METHOD2(collect_tseries_data,
                     Result<TSeriesMap>(const MapInfo &map_info, int nvalues));
};

class MockBPFtrace : public BPFtrace {
public:
  MockBPFtrace() : BPFtrace(std::make_unique<bpftrace::Config>())
  {
    // Load BTF with reference to our StructManager.
    auto btf_result = BTF::load(structs);
    if (!btf_result) {
      throw std::runtime_error("BTF loading failed in MockBPFtrace");
    }
    btf_ = std::move(*btf_result);
  }

  MOCK_METHOD2(
      attach_probe,
      Result<std::unique_ptr<AttachedProbe>>(::bpftrace::Probe &probe,
                                             const BpfBytecode &bytecode));

  MOCK_METHOD1(resume_tracee, int(pid_t tracee_pid));
  std::vector<::bpftrace::Probe> get_probes()
  {
    return resources.probes;
  }
  std::vector<::bpftrace::Probe> get_begin_probes()
  {
    return resources.begin_probes;
  }
  std::vector<::bpftrace::Probe> get_end_probes()
  {
    return resources.end_probes;
  }
  std::vector<::bpftrace::Probe> get_test_probes()
  {
    return resources.test_probes;
  }
  std::vector<::bpftrace::Probe> get_benchmark_probes()
  {
    return resources.benchmark_probes;
  }

  int resolve_uname(const std::string &name,
                    struct symbol *sym,
                    const std::string &path) const override
  {
    (void)path;
    sym->name = name;
    if (name == "cpp_mangled(int)") {
      return -1;
    } else if (name[0] >= 'A' && name[0] <= 'z') {
      sym->address = 12345;
      sym->size = 4;
    } else {
      auto fields = util::split_string(name, '_');
      sym->address = std::stoull(fields.at(0));
      sym->size = std::stoull(fields.at(1));
    }
    return 0;
  }

  Result<uint64_t> get_buffer_pages(
      bool __attribute__((unused)) /*per_cpu*/) const override
  {
    return 64;
  }

  const std::optional<struct stat> &get_pidns_self_stat() const override
  {
    static const std::optional<struct stat> init_pid_namespace = []() {
      struct stat s {};
      s.st_ino = 0xeffffffc; // PROC_PID_INIT_INO
      return std::optional{ s };
    }();
    static const std::optional<struct stat> child_pid_namespace = []() {
      struct stat s {};
      s.st_ino = 0xf0000011; // Arbitrary user namespace
      return std::optional{ s };
    }();

    if (mock_in_init_pid_ns)
      return init_pid_namespace;
    return child_pid_namespace;
  }

  util::KernelFunctionInfo* get_mock_kernel_func_info();
  util::UserFunctionInfo* get_mock_user_func_info();

  bool mock_in_init_pid_ns = true;
};

std::unique_ptr<MockBPFtrace> get_mock_bpftrace();
std::unique_ptr<MockBPFtrace> get_strict_mock_bpftrace();

// Helper to get FunctionInfo for tests.
//
// Returns a reference to a static instance that can be used with PassManager.
ast::FunctionInfo& get_mock_function_info();

// Helper to create a real BPFtrace for tests.
//
// Throws if BTF loading fails.
std::unique_ptr<BPFtrace> create_bpftrace();

static auto bpf_nofeature = BPFnofeature();

class MockBPFfeature : public BPFfeature {
public:
  MockBPFfeature(BTF& btf, bool has_features = true)
      : BPFfeature(bpf_nofeature, btf)
  {
    has_prog_fentry_ = std::make_optional<bool>(has_features);
    has_features_ = has_features;
    has_d_path_ = std::make_optional<bool>(has_features);
    has_kprobe_multi_ = std::make_optional<bool>(has_features);
    has_kprobe_session_ = std::make_optional<bool>(has_features);
    has_uprobe_multi_ = std::make_optional<bool>(has_features);
    has_ktime_get_tai_ns_ = std::make_optional<bool>(has_features);
    has_map_lookup_percpu_elem_ = std::make_optional<bool>(has_features);
    has_loop_ = std::make_optional<bool>(has_features);
  };

private:
  bool has_iter(std::string name __attribute__((unused))) override
  {
    return has_features_;
  }

  bool has_features_;
};

class MockChildProc : public ChildProcBase {
public:
  MockChildProc(std::string cmd __attribute__((unused)))
  {
    child_pid_ = 1337;
  };
  ~MockChildProc() override = default;

  void terminate(bool force __attribute__((unused)) = false) override {};
  bool is_alive() override
  {
    return true;
  };
  void resume() override {};

  void run(bool pause = false) override
  {
    (void)pause;
  };
};

class MockProcMon : public ProcMonBase {
public:
  MockProcMon(pid_t pid)
  {
    pid_ = pid;
  }

  ~MockProcMon() override = default;

  bool is_alive() override
  {
    return pid_ > 0;
  }
};

} // namespace bpftrace::test
