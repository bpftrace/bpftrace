#include "mocks.h"

namespace bpftrace {
namespace test {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

void setup_mock_probe_matcher(MockProbeMatcher &matcher)
{
  ON_CALL(matcher,
          get_symbols_from_file(
              "/sys/kernel/debug/tracing/available_filter_functions"))
      .WillByDefault([](const std::string &) {
        std::string ksyms = "SyS_read\n"
                            "sys_read\n"
                            "sys_write\n"
                            "my_one\n"
                            "my_two\n"
                            "func_in_mod [kernel_mod]\n";
        auto myval = std::unique_ptr<std::istream>(new std::istringstream(ksyms));
        return myval;
      });

  ON_CALL(matcher,
          get_symbols_from_file("/sys/kernel/debug/tracing/available_events"))
      .WillByDefault([](const std::string &) {
        std::string tracepoints = "sched:sched_one\n"
                                  "sched:sched_two\n"
                                  "sched:foo\n"
                                  "sched_extra:sched_extra\n"
                                  "notsched:bar\n"
                                  "file:filename\n"
                                  "tcp:some_tcp_tp\n";
        return std::unique_ptr<std::istream>(new std::istringstream(tracepoints));
      });

  std::string sh_usyms = "/bin/sh:first_open\n"
                         "/bin/sh:second_open\n"
                         "/bin/sh:open_as_well\n"
                         "/bin/sh:something_else\n"
                         "/bin/sh:_Z11cpp_mangledi\n"
                         "/bin/sh:_Z11cpp_mangledv\n";
  std::string bash_usyms = "/bin/bash:first_open\n";
  ON_CALL(matcher, get_func_symbols_from_file("/bin/sh"))
      .WillByDefault([sh_usyms](const std::string &) {
        return std::unique_ptr<std::istream>(new std::istringstream(sh_usyms));
      });

  ON_CALL(matcher, get_func_symbols_from_file("/bin/*sh"))
      .WillByDefault([sh_usyms, bash_usyms](const std::string &) {
        return std::unique_ptr<std::istream>(
            new std::istringstream(sh_usyms + bash_usyms));
      });

  std::string sh_usdts = "/bin/sh:prov1:tp1\n"
                         "/bin/sh:prov1:tp2\n"
                         "/bin/sh:prov2:tp\n"
                         "/bin/sh:prov2:notatp\n"
                         "/bin/sh:nahprov:tp\n";
  std::string bash_usdts = "/bin/bash:prov1:tp3";
  ON_CALL(matcher, get_symbols_from_usdt(_, "/bin/sh"))
      .WillByDefault([sh_usdts](int, const std::string &) {
        return std::unique_ptr<std::istream>(new std::istringstream(sh_usdts));
      });
  ON_CALL(matcher, get_symbols_from_usdt(_, "/bin/*sh"))
      .WillByDefault([sh_usdts, bash_usdts](int, const std::string &) {
        return std::unique_ptr<std::istream>(
            new std::istringstream(sh_usdts + bash_usdts));
      });
}

void setup_mock_bpftrace(MockBPFtrace &bpftrace)
{
  // Fill in some default tracepoint struct definitions
  bpftrace.structs_["struct _tracepoint_sched_sched_one"] = Struct{
    .size = 8,
    .fields = { { "common_field",
                  Field{
                      .type = CreateUInt64(),
                      .offset = 8,
                      .is_bitfield = false,
                      .bitfield = {},
                  } } },
  };
  bpftrace.structs_["struct _tracepoint_sched_sched_two"] = Struct{
    .size = 8,
    .fields = { { "common_field",
                  Field{
                      .type = CreateUInt64(),
                      .offset = 16, // different offset than
                                    // sched_one.common_field
                      .is_bitfield = false,
                      .bitfield = {},
                  } } },
  };
  bpftrace.structs_["struct _tracepoint_sched_extra_sched_extra"] = Struct{
    .size = 8,
    .fields = { { "common_field",
                  Field{
                      .type = CreateUInt64(),
                      .offset = 24, // different offset than
                                    // sched_(one|two).common_field
                      .is_bitfield = false,
                      .bitfield = {},
                  } } },
  };
  bpftrace.structs_["struct _tracepoint_tcp_some_tcp_tp"] = Struct{
    .size = 16,
    .fields = { { "saddr_v6",
                  Field{
                      .type = CreateArray(16, CreateUInt(8)),
                      .offset = 0,
                      .is_bitfield = false,
                      .bitfield = {},
                  } } },
  };

  auto ptr_type = CreatePointer(CreateInt8());
  bpftrace.structs_["struct _tracepoint_file_filename"] = Struct{
    .size = 8,
    .fields = { { "filename",
                  Field{
                      .type = ptr_type,
                      .offset = 8,
                      .is_bitfield = false,
                      .bitfield = {},
                  } } },
  };
}

std::unique_ptr<MockBPFtrace> get_mock_bpftrace()
{
  auto bpftrace = std::make_unique<NiceMock<MockBPFtrace>>();
  setup_mock_bpftrace(*bpftrace);

  auto probe_matcher = std::make_unique<NiceMock<MockProbeMatcher>>(
      bpftrace.get());
  setup_mock_probe_matcher(*probe_matcher);
  bpftrace->set_mock_probe_matcher(std::move(probe_matcher));

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

  return bpftrace;
}

} // namespace test
} // namespace bpftrace
