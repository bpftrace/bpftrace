#include "mocks.h"

namespace bpftrace {
namespace test {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::StrictMock;

void setup_mock_bpftrace(MockBPFtrace &bpftrace)
{
  ON_CALL(bpftrace,
          get_symbols_from_file("/sys/kernel/debug/tracing/available_filter_functions"))
      .WillByDefault([](const std::string &)
      {
        std::string ksyms = "SyS_read\n"
                            "sys_read\n"
                            "sys_write\n"
                            "my_one\n"
                            "my_two\n";
        auto myval = std::unique_ptr<std::istream>(new std::istringstream(ksyms));
        return myval;
      });

  ON_CALL(bpftrace,
          get_symbols_from_file("/sys/kernel/debug/tracing/available_events"))
      .WillByDefault([](const std::string &) {
        std::string tracepoints = "sched:sched_one\n"
                                  "sched:sched_two\n"
                                  "sched:foo\n"
                                  "notsched:bar\n"
                                  "file:filename\n";
        return std::unique_ptr<std::istream>(new std::istringstream(tracepoints));
      });

  std::string usyms = "first_open\n"
                      "second_open\n"
                      "open_as_well\n"
                      "something_else\n"
                      "_Z11cpp_mangledi\n"
                      "_Z11cpp_mangledv\n";
  ON_CALL(bpftrace, extract_func_symbols_from_path(_))
      .WillByDefault(Return(usyms));

  ON_CALL(bpftrace, get_symbols_from_usdt(_, _))
      .WillByDefault([](int, const std::string &)
      {
        std::string usdt_syms = "prov1:tp1\n"
                                "prov1:tp2\n"
                                "prov2:tp\n"
                                "prov2:notatp\n"
                                "nahprov:tp\n";
        return std::unique_ptr<std::istream>(new std::istringstream(usdt_syms));
      });

  // Fill in some default tracepoint struct definitions
  bpftrace.structs_["struct _tracepoint_sched_sched_one"] = Struct
  {
    .size = 8,
    .fields = {{"common_field", Field
      {
        .type = SizedType(Type::integer, 8, false),
        .offset = 8,
        .is_bitfield = false,
        .bitfield = {},
      }}},
  };
  bpftrace.structs_["struct _tracepoint_sched_sched_two"] = Struct
  {
    .size = 8,
    .fields = {{"common_field", Field
      {
        .type = SizedType(Type::integer, 8, false),
        .offset = 16, // different offset than sched_one.common_field
        .is_bitfield = false,
        .bitfield = {},
      }}},
  };

  auto ptr_type = SizedType(Type::integer, 8, false);
  ptr_type.is_pointer = true;
  ptr_type.pointee_size = 1;
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
  return bpftrace;
}

std::unique_ptr<MockBPFtrace> get_strict_mock_bpftrace()
{
  auto bpftrace = std::make_unique<StrictMock<MockBPFtrace>>();
  setup_mock_bpftrace(*bpftrace);
  return bpftrace;
}

} // namespace test
} // namespace bpftrace
