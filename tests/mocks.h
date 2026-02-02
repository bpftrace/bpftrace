#pragma once

#include "ast/passes/attachpoint_passes.h"
#include "attached_probe.h"
#include "bpffeature.h"
#include "bpfmap.h"
#include "bpftrace.h"
#include "probe_matcher.h"
#include "util/kernel.h"
#include "util/proc.h"
#include "util/result.h"
#include "util/strings.h"
#include "util/user.h"
#include "gmock/gmock-function-mocker.h"

namespace bpftrace::test {

class MockKernelFunctionInfo : public util::KernelFunctionInfoBase<MockKernelFunctionInfo> {
public:
  util::ModuleSet get_modules(const std::optional<std::string> &mod_name = std::nullopt) const override;
  util::ModulesFuncsMap get_traceable_funcs(const std::optional<std::string> &mod_name = std::nullopt) const override;
  util::ModulesFuncsMap get_raw_tracepoints(const std::optional<std::string> &mod_name = std::nullopt) const override;
  util::ModulesFuncsMap get_tracepoints(const std::optional<std::string> &category_name = std::nullopt) const override;
  std::vector<std::pair<__u32, std::string>> get_bpf_progs() const override;
};

class MockUserFunctionInfo : public util::UserFunctionInfo {
public:
 Result<util::BinaryFuncMap> func_symbols_for_pid(int pid) const override;
 Result<util::FunctionSet> func_symbols_for_path(
    const std::string &path) const override;
  Result<util::BinaryUSDTMap> usdt_probes_for_pid(int pid) const override;
  Result<util::BinaryUSDTMap> usdt_probes_for_all_pids() const override;
  Result<util::USDTSet> usdt_probes_for_path(
      const std::string &path) const override;
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

  bool mock_in_init_pid_ns = true;
};

std::unique_ptr<MockBPFtrace> get_mock_bpftrace();
std::unique_ptr<MockBPFtrace> get_strict_mock_bpftrace();

// Helpers to get FunctionInfo for tests.
//
// Returns a reference to a static instance that can be used with PassManager.
ast::FunctionInfo& get_mock_function_info();

// Returns a FunctionInfo with mock kernel info but real user function info.
// This is useful for tests that need to read actual binaries (e.g., DWARF tests).
std::unique_ptr<ast::FunctionInfo> get_real_user_function_info();

// Helper to create a real BPFtrace for tests.
//
// In general, this should be avoided and instead more precise mocks or
// individual state objects used instead. As we remove functionality from the
// mega-BPFtrace object, this should be deleted in its entirely. At a minimum,
// tests should be able to use `MockBPFtrace` instead of the actual structure.
[[deprecated("will be removed in the future")]]
std::unique_ptr<BPFtrace> create_bpftrace();

static auto bpf_nofeature = BPFnofeature();
static auto btf_obj = BTF(nullptr);

class MockBPFfeature : public BPFfeature {
public:
  MockBPFfeature(bool has_features = true) : BPFfeature(bpf_nofeature, btf_obj)
  {
    has_prog_fentry_ = std::make_optional<bool>(has_features);
    has_features_ = has_features;
    has_d_path_ = std::make_optional<bool>(has_features);
    has_kprobe_multi_ = std::make_optional<bool>(has_features);
    has_kprobe_session_ = std::make_optional<bool>(has_features);
    has_uprobe_multi_ = std::make_optional<bool>(has_features);
    has_ktime_get_tai_ns_ = std::make_optional<bool>(has_features);
    has_get_func_ip_ = std::make_optional<bool>(has_features);
    has_map_lookup_percpu_elem_ = std::make_optional<bool>(has_features);
    has_loop_ = std::make_optional<bool>(has_features);
  };

  bool has_iter(std::string name __attribute__((unused))) override
  {
    return has_features_;
  }

  bool has_features_;
};

class MockChildProc : public util::ChildProc {
public:
  MockChildProc([[maybe_unused]] std::string cmd) : pid_(1337) {};
  ~MockChildProc() override = default;

  Result<> terminate([[maybe_unused]] bool force = false) override
  {
    return OK();
  };
  bool is_alive() override
  {
    return true;
  };
  pid_t pid() override
  {
    return pid_;
  }
  Result<int> pidfd() override
  {
    return make_error<SystemError>("MockChildProc does not support pidfd");
  }
  Result<> resume() override
  {
    return OK();
  };
  Result<> run([[maybe_unused]] bool pause = false) override
  {
    return OK();
  };
  Result<bool> wait([[maybe_unused]] std::optional<int> timeout_ms = std::nullopt) override
  {
    return false;
  }

private:
  pid_t pid_ = 0;
};

class MockProcMon : public util::Proc {
public:
  MockProcMon(pid_t pid) : pid_(pid) {}
  ~MockProcMon() override = default;

  bool is_alive() override
  {
    return pid_ > 0;
  }
  pid_t pid() override
  {
    return pid_;
  }
  Result<int> pidfd() override
  {
    return make_error<SystemError>("MockProcMon does not support pidfd");
  }

private:
  pid_t pid_ = 0;
};

} // namespace bpftrace::test
