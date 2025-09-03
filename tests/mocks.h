#pragma once

#include "bpffeature.h"
#include "bpfmap.h"
#include "bpftrace.h"
#include "child.h"
#include "probe_matcher.h"
#include "procmon.h"
#include "util/result.h"
#include "util/strings.h"
#include "gmock/gmock-function-mocker.h"

namespace bpftrace::test {

class MockProbeMatcher : public ProbeMatcher {
public:
  MockProbeMatcher(BPFtrace *bpftrace) : ProbeMatcher(bpftrace)
  {
  }
#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Winconsistent-missing-override"
#endif
  MOCK_CONST_METHOD1(get_symbols_from_file,
                     std::unique_ptr<std::istream>(const std::string &path));
  MOCK_CONST_METHOD1(get_symbols_from_traceable_funcs,
                     std::unique_ptr<std::istream>(bool with_modules));
  MOCK_CONST_METHOD2(get_symbols_from_usdt,
                     std::unique_ptr<std::istream>(std::optional<int> pid,
                                                   const std::string &target));
  MOCK_CONST_METHOD2(get_func_symbols_from_file,
                     std::unique_ptr<std::istream>(std::optional<int> pid,
                                                   const std::string &path));
  MOCK_CONST_METHOD0(get_raw_tracepoint_symbols,
                     std::unique_ptr<std::istream>());

  MOCK_CONST_METHOD0(get_fentry_symbols, std::unique_ptr<std::istream>());

  MOCK_CONST_METHOD0(get_running_bpf_programs, std::unique_ptr<std::istream>());

#pragma GCC diagnostic pop
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
      Result<std::unique_ptr<AttachedProbe>>(Probe &probe,
                                             const BpfBytecode &bytecode));

  MOCK_METHOD1(resume_tracee, int(pid_t tracee_pid));
  std::vector<Probe> get_probes()
  {
    return resources.probes;
  }
  std::unordered_map<std::string, Probe> get_special_probes()
  {
    return resources.special_probes;
  }
  std::vector<Probe> get_benchmark_probes()
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

  bool is_traceable_func(
      const std::string &__attribute__((unused)) /*func_name*/) const override
  {
    return true;
  }

  Result<uint64_t> get_buffer_pages(bool __attribute__((unused)) /*per_cpu*/) const override
  {
    return 64;
  }

  std::unordered_set<std::string> get_func_modules(
      const std::string &__attribute__((unused)) /*func_name*/) const override
  {
    return { "mock_vmlinux" };
  }

  const std::optional<struct stat> &get_pidns_self_stat() const override
  {
    static const std::optional<struct stat> init_pid_namespace = []() {
      struct stat s{};
      s.st_ino = 0xeffffffc; // PROC_PID_INIT_INO
      return std::optional{ s };
    }();
    static const std::optional<struct stat> child_pid_namespace = []() {
      struct stat s{};
      s.st_ino = 0xf0000011; // Arbitrary user namespace
      return std::optional{ s };
    }();

    if (mock_in_init_pid_ns)
      return init_pid_namespace;
    return child_pid_namespace;
  }

  void set_mock_probe_matcher(std::unique_ptr<MockProbeMatcher> probe_matcher)
  {
    probe_matcher_ = std::move(probe_matcher);
    mock_probe_matcher = dynamic_cast<MockProbeMatcher *>(probe_matcher_.get());
  }

  MockProbeMatcher *mock_probe_matcher;
  bool mock_in_init_pid_ns = true;
};

std::unique_ptr<MockBPFtrace> get_mock_bpftrace();
std::unique_ptr<MockBPFtrace> get_strict_mock_bpftrace();

static auto bpf_nofeature = BPFnofeature();
static auto btf_obj = BTF(nullptr);

class MockBPFfeature : public BPFfeature {
public:
  MockBPFfeature(bool has_features = true) : BPFfeature(bpf_nofeature, btf_obj)
  {
    has_send_signal_ = std::make_optional<bool>(has_features);
    has_get_current_cgroup_id_ = std::make_optional<bool>(has_features);
    has_override_return_ = std::make_optional<bool>(has_features);
    has_prog_fentry_ = std::make_optional<bool>(has_features);
    has_probe_read_kernel_ = std::make_optional<bool>(has_features);
    has_features_ = has_features;
    has_d_path_ = std::make_optional<bool>(has_features);
    has_ktime_get_boot_ns_ = std::make_optional<bool>(has_features);
    has_kprobe_multi_ = std::make_optional<bool>(has_features);
    has_kprobe_session_ = std::make_optional<bool>(has_features);
    has_uprobe_multi_ = std::make_optional<bool>(has_features);
    has_skb_output_ = std::make_optional<bool>(has_features);
    map_ringbuf_ = std::make_optional<bool>(has_features);
    has_ktime_get_tai_ns_ = std::make_optional<bool>(has_features);
    has_get_func_ip_ = std::make_optional<bool>(has_features);
    has_jiffies64_ = std::make_optional<bool>(has_features);
    has_for_each_map_elem_ = std::make_optional<bool>(has_features);
    has_get_ns_current_pid_tgid_ = std::make_optional<bool>(has_features);
    has_map_lookup_percpu_elem_ = std::make_optional<bool>(has_features);
    has_loop_ = std::make_optional<bool>(has_features);
  };

  bool has_fentry() override
  {
    return has_features_;
  }

  void add_to_available_kernel_funcs(Kfunc kfunc, bool available)
  {
    available_kernel_funcs_.emplace(kfunc, available);
  }

  bool has_kernel_func(Kfunc kfunc) override
  {
    auto find_kfunc = available_kernel_funcs_.find(kfunc);
    if (find_kfunc != available_kernel_funcs_.end())
      return find_kfunc->second;

    return false;
  }

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

class MockUSDTHelper : public USDTHelper {
public:
  MockUSDTHelper()
  {
  }
#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Winconsistent-missing-override"
#endif
  MOCK_METHOD4(find,
               std::optional<usdt_probe_entry>(std::optional<int> pid,
                                               const std::string &target,
                                               const std::string &provider,
                                               const std::string &name));
#pragma GCC diagnostic pop
};

std::unique_ptr<MockUSDTHelper> get_mock_usdt_helper(int num_locations);

} // namespace bpftrace::test
