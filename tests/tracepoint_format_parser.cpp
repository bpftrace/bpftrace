#include "gtest/gtest.h"
#include "tracepoint_format_parser.h"

namespace bpftrace {
namespace test {
namespace tracepoint_format_parser {

class MockTracepointFormatParser : public TracepointFormatParser
{
public:
  static std::string get_tracepoint_struct_public(std::istream &format_file, const std::string &category, const std::string &event_name)
  {
    return get_tracepoint_struct(format_file, category, event_name);
  }
};

TEST(tracepoint_format_parser, tracepoint_struct)
{
  std::string input =
    "name: sys_enter_read\n"
    "ID: 650\n"
    "format:\n"
    "	field:unsigned short common_type;	offset:0;	size:2;	signed:0;\n"
    "	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;\n"
    "	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;\n"
    "	field:int common_pid;	offset:4;	size:4;	signed:1;\n"
    "\n"
    "	field:int __syscall_nr;	offset:8;	size:4;	signed:1;\n"
    "	field:unsigned int fd;	offset:16;	size:8;	signed:0;\n"
    "	field:char * buf;	offset:24;	size:8;	signed:0;\n"
    "	field:size_t count;	offset:32;	size:8;	signed:0;\n"
    "\n"
    "print fmt: \"fd: 0x%08lx, buf: 0x%08lx, count: 0x%08lx\", ((unsigned long)(REC->fd)), ((unsigned long)(REC->buf)), ((unsigned long)(REC->count))\n";

  std::string expected =
    "struct _tracepoint_syscalls_sys_enter_read\n"
    "{\n"
    "  unsigned short common_type;\n"
    "  unsigned char common_flags;\n"
    "  unsigned char common_preempt_count;\n"
    "  int common_pid;\n"
    "  int __syscall_nr;\n"
    "  u64 fd;\n"
    "  char * buf;\n"
    "  size_t count;\n"
    "};\n";

  std::istringstream format_file(input);

  std::string result = MockTracepointFormatParser::get_tracepoint_struct_public(format_file, "syscalls", "sys_enter_read");

  EXPECT_EQ(expected, result);
}

TEST(tracepoint_format_parser, array)
{
  std::string input =
    "	field:char char_array[8];	offset:0;	size:8;	signed:1;\n"
    "	field:int int_array[2];	offset:8;	size:8;	signed:1;\n";

  std::string expected =
    "struct _tracepoint_syscalls_sys_enter_read\n"
    "{\n"
    "  char char_array[8];\n"
    "  int int_array[2];\n"
    "};\n";

  std::istringstream format_file(input);

  std::string result = MockTracepointFormatParser::get_tracepoint_struct_public(format_file, "syscalls", "sys_enter_read");

  EXPECT_EQ(expected, result);
}

TEST(tracepoint_format_parser, data_loc)
{
  std::string input = "	field:__data_loc char[] msg;	offset:8;	size:4;	signed:1;";

  std::string expected =
    "struct _tracepoint_syscalls_sys_enter_read\n"
    "{\n"
    "  int data_loc_msg;\n"
    "};\n";

  std::istringstream format_file(input);

  std::string result = MockTracepointFormatParser::get_tracepoint_struct_public(format_file, "syscalls", "sys_enter_read");

  EXPECT_EQ(expected, result);
}

} // namespace tracepoint_format_parser
} // namespace test
} // namespace bpftrace
