#include "mocks.h"
#include "tracefs/tracefs.h"
#include "util/elf_parser.h"
#include "gmock/gmock-nice-strict.h"

namespace bpftrace::test {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

void setup_mock_probe_matcher(MockProbeMatcher &matcher)
{
  // This must return all functions used throughout the unit tests, otherwise
  // attach points will be skipped in `ProbeAndApExpander` which calls
  // `get_symbols_from_traceable_funcs(false)`.
  ON_CALL(matcher, get_symbols_from_traceable_funcs(false)).WillByDefault([]() {
    std::string ksyms = "f\n"
                        "func_1\n"
                        "func_2\n"
                        "mod_func_1\n"
                        "mod_func_2\n"
                        "sys_read\n"
                        "sys_write\n"
                        "tcp_shutdown\n"
                        "queued_spin_lock_slowpath\n";
    auto myval = std::unique_ptr<std::istream>(new std::istringstream(ksyms));
    return myval;
  });

  ON_CALL(matcher, get_symbols_from_traceable_funcs(true)).WillByDefault([]() {
    std::string ksyms = "kernel_mod_1:mod_func_1\n"
                        "kernel_mod_1:mod_func_2\n"
                        "kernel_mod_2:mod_func_1\n"
                        "mock_vmlinux:func_1\n"
                        "vmlinux:queued_spin_lock_slowpath\n";
    auto myval = std::unique_ptr<std::istream>(new std::istringstream(ksyms));
    return myval;
  });

  ON_CALL(matcher, get_module_symbols_from_traceable_funcs(_))
      .WillByDefault([]() {
        std::string ksyms = "kernel_mod_1:mod_func_1\n"
                            "kernel_mod_1:mod_func_2\n"
                            "kernel_mod_2:mod_func_1\n"
                            "mock_vmlinux:func_1\n"
                            "mock_vmlinux:func_anon_struct\n"
                            "vmlinux:func_1\n"
                            "vmlinux:queued_spin_lock_slowpath\n";
        auto myval = std::unique_ptr<std::istream>(
            new std::istringstream(ksyms));
        return myval;
      });

  ON_CALL(matcher, get_symbols_from_file(tracefs::available_events()))
      .WillByDefault([](const std::string &) {
        std::string tracepoints = "category:event\n"
                                  "sched:sched_one\n"
                                  "sched:sched_two\n"
                                  "sched_extra:sched_extra\n"
                                  "vmlinux:event_rt\n";
        return std::unique_ptr<std::istream>(
            new std::istringstream(tracepoints));
      });

  ON_CALL(matcher, get_raw_tracepoint_symbols()).WillByDefault([]() {
    std::string rawtracepoints = "module:event\n"
                                 "vmlinux:event_rt\n"
                                 "vmlinux:sched_switch\n";
    return std::unique_ptr<std::istream>(
        new std::istringstream(rawtracepoints));
  });

  ON_CALL(matcher, get_fentry_symbols(_)).WillByDefault([]() {
    std::string funcs = "mock_vmlinux:f\n"
                        "mock_vmlinux:func_1\n"
                        "mock_vmlinux:func_2\n"
                        "mock_vmlinux:func_3\n"
                        "mock_vmlinux:func_anon_struct\n"
                        "mock_vmlinux:func_arrays\n"
                        "mock_vmlinux:tcp_shutdown\n"
                        "vmlinux:func_1\n"
                        "vmlinux:func_2\n"
                        "vmlinux:func_3\n"
                        "vmlinux:queued_spin_lock_slowpath\n";
    return std::unique_ptr<std::istream>(new std::istringstream(funcs));
  });

  std::string sh_usyms = "/bin/sh:f\n"
                         "/bin/sh:first_open\n"
                         "/bin/sh:main\n"
                         "/bin/sh:readline\n"
                         "/bin/sh:second_open\n"
                         "/bin/sh:cpp_mangled\n"
                         "/bin/sh:_Z11cpp_mangledi\n"
                         "/bin/sh:_Z11cpp_mangledv\n"
                         "/bin/sh:_Z18cpp_mangled_suffixv\n";
  std::string bash_usyms = "/bin/bash:first_open\n";
  ON_CALL(matcher, get_func_symbols_from_file(_, "/bin/sh"))
      .WillByDefault([sh_usyms](std::optional<int>, const std::string &) {
        return std::unique_ptr<std::istream>(new std::istringstream(sh_usyms));
      });

  ON_CALL(matcher, get_func_symbols_from_file(_, "/bin/*sh"))
      .WillByDefault(
          [sh_usyms, bash_usyms](std::optional<int>, const std::string &) {
            return std::unique_ptr<std::istream>(
                new std::istringstream(sh_usyms + bash_usyms));
          });

  std::string sh_usdts = "/bin/sh:probe\n"
                         "/bin/sh:prov1:tp1\n"
                         "/bin/sh:prov1:tp2\n"
                         "/bin/sh:prov2:tp\n"
                         "/bin/sh:nahprov:tp\n";
  std::string bash_usdts = "/bin/bash:prov1:tp3\n";
  ON_CALL(matcher, get_symbols_from_usdt(_, "/bin/sh"))
      .WillByDefault([sh_usdts](std::optional<int>, const std::string &) {
        return std::unique_ptr<std::istream>(new std::istringstream(sh_usdts));
      });
  ON_CALL(matcher, get_symbols_from_usdt(_, "/bin/*sh"))
      .WillByDefault(
          [sh_usdts, bash_usdts](std::optional<int>, const std::string &) {
            return std::unique_ptr<std::istream>(
                new std::istringstream(sh_usdts + bash_usdts));
          });

  ON_CALL(matcher, get_running_bpf_programs()).WillByDefault([]() {
    std::string bpf_progs = "bpf:123:func_1\n"
                            "bpf:123:func_2\n"
                            "bpf:456:func_1\n";
    return std::unique_ptr<std::istream>(new std::istringstream(bpf_progs));
  });
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

  auto probe_matcher = std::make_unique<NiceMock<MockProbeMatcher>>(
      bpftrace.get());
  setup_mock_probe_matcher(*probe_matcher);
  bpftrace->set_mock_probe_matcher(std::move(probe_matcher));

  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);

  return bpftrace;
}

std::unique_ptr<MockBPFtrace> get_strict_mock_bpftrace()
{
  auto bpftrace = std::make_unique<StrictMock<MockBPFtrace>>();
  setup_mock_bpftrace(*bpftrace);

  auto probe_matcher = std::make_unique<StrictMock<MockProbeMatcher>>(
      bpftrace.get());
  setup_mock_probe_matcher(*probe_matcher);
  bpftrace->set_mock_probe_matcher(std::move(probe_matcher));

  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);

  return bpftrace;
}

std::unique_ptr<MockUSDTHelper> get_mock_usdt_helper()
{
  auto usdt_helper = std::make_unique<NiceMock<MockUSDTHelper>>();

  ON_CALL(*usdt_helper, find(_, _, _, _, _))
      .WillByDefault(
          [](std::optional<int>,
             const std::string &,
             const std::string &,
             const std::string &,
             bool) { return util::usdt_probe_entry{ "", "", "", 0, 0 }; });

  return usdt_helper;
}

} // namespace bpftrace::test
