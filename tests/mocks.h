#pragma once

#include "gmock/gmock.h"

#include "bpffeature.h"
#include "bpftrace.h"
#include "child.h"
#include "probe_matcher.h"
#include "procmon.h"

namespace bpftrace {
namespace test {

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
                     std::unique_ptr<std::istream>(int pid,
                                                   const std::string &target));
  MOCK_CONST_METHOD2(get_func_symbols_from_file,
                     std::unique_ptr<std::istream>(int pid,
                                                   const std::string &path));
#pragma GCC diagnostic pop
};

class MockBPFtrace : public BPFtrace {
public:
  std::vector<Probe> get_probes()
  {
    return resources.probes;
  }
  std::vector<Probe> get_special_probes()
  {
    return resources.special_probes;
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
      auto fields = split_string(name, '_');
      sym->address = std::stoull(fields.at(0));
      sym->size = std::stoull(fields.at(1));
    }
    return 0;
  }

  bool is_traceable_func(
      const std::string &__attribute__((unused))) const override
  {
    return true;
  }

  std::unordered_set<std::string> get_func_modules(
      const std::string &__attribute__((unused))) const override
  {
    return { "mock_vmlinux" };
  }

  void set_mock_probe_matcher(std::unique_ptr<MockProbeMatcher> probe_matcher)
  {
    probe_matcher_ = std::move(probe_matcher);
    mock_probe_matcher = dynamic_cast<MockProbeMatcher *>(probe_matcher_.get());
  }

  MockProbeMatcher *mock_probe_matcher;
};

std::unique_ptr<MockBPFtrace> get_mock_bpftrace();
std::unique_ptr<MockBPFtrace> get_strict_mock_bpftrace();

class MockBPFfeature : public BPFfeature {
public:
  MockBPFfeature(bool has_features = true)
  {
    has_send_signal_ = std::make_optional<bool>(has_features);
    has_get_current_cgroup_id_ = std::make_optional<bool>(has_features);
    has_override_return_ = std::make_optional<bool>(has_features);
    has_prog_kfunc_ = std::make_optional<bool>(has_features);
    has_loop_ = std::make_optional<bool>(has_features);
    has_probe_read_kernel_ = std::make_optional<bool>(has_features);
    has_features_ = has_features;
    has_d_path_ = std::make_optional<bool>(has_features);
    has_ktime_get_boot_ns_ = std::make_optional<bool>(has_features);
    has_kprobe_multi_ = std::make_optional<bool>(has_features);
    has_uprobe_multi_ = std::make_optional<bool>(has_features);
    has_skb_output_ = std::make_optional<bool>(has_features);
    map_ringbuf_ = std::make_optional<bool>(has_features);
    map_percpu_hash_ = std::make_optional<bool>(has_features);
    has_ktime_get_tai_ns_ = std::make_optional<bool>(has_features);
    has_get_func_ip_ = std::make_optional<bool>(has_features);
    has_jiffies64_ = std::make_optional<bool>(has_features);
    has_for_each_map_elem_ = std::make_optional<bool>(has_features);
  };

  void has_loop(bool has)
  {
    has_loop_ = std::make_optional<bool>(has);
  }

  bool has_features_;
};

class MockChildProc : public ChildProcBase {
public:
  MockChildProc(std::string cmd __attribute__((unused)))
  {
    child_pid_ = 1337;
  };
  ~MockChildProc(){};

  void terminate(bool force __attribute__((unused)) = false) override{};
  bool is_alive() override
  {
    return true;
  };
  void resume(void) override{};

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

  bool is_alive(void) override
  {
    if (pid_ > 0)
      return true;
    else
      return false;
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
               std::optional<usdt_probe_entry>(int pid,
                                               const std::string &target,
                                               const std::string &provider,
                                               const std::string &name));
#pragma GCC diagnostic pop
};

std::unique_ptr<MockUSDTHelper> get_mock_usdt_helper(int num_locations);

} // namespace test
} // namespace bpftrace
