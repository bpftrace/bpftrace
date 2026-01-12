#include "ast/passes/tracepoint_format_parser.h"
#include "btf_common.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

using namespace testing;

namespace bpftrace::test::tracepoint_format_parser {

class MockTracepointFormatParser : public ast::TracepointFormatParser {
public:
  MockTracepointFormatParser(std::string category,
                             std::string event,
                             BPFtrace &bpftrace)
      : ast::TracepointFormatParser(std::move(category),
                                    std::move(event),
                                    bpftrace) {};

  Result<std::shared_ptr<Struct>> get_tracepoint_struct_public(
      std::istream &format_file)
  {
    return get_tracepoint_struct(format_file);
  }
};

class tracepoint_format_parser : public test_btf {};

TEST_F(tracepoint_format_parser, tracepoint_struct)
{
  std::string input =
      "name: sys_enter_read\n"
      "ID: 650\n"
      "format:\n"
      "	field:unsigned short common_type;	offset:0;	size:2;	"
      "signed:0;\n"
      "	field:unsigned char common_flags;	offset:2;	size:1;	"
      "signed:0;\n"
      "	field:unsigned char common_preempt_count;	offset:3;	"
      "size:1;	signed:0;\n"
      "	field:int common_pid;	offset:4;	size:4;	signed:1;\n"
      "\n"
      "	field:int __syscall_nr;	offset:8;	size:4;	signed:1;\n"
      "	field:unsigned int fd;	offset:16;	size:8;	signed:0;\n"
      "	field:char * buf;	offset:24;	size:8;	signed:0;\n"
      "	field:size_t count;	offset:32;	size:8;	signed:0;\n"
      "\n"
      "print fmt: \"fd: 0x%08lx, buf: 0x%08lx, count: 0x%08lx\", ((unsigned "
      "long)(REC->fd)), ((unsigned long)(REC->buf)), ((unsigned "
      "long)(REC->count))\n";

  std::istringstream format_file(input);

  auto bpftrace = get_mock_bpftrace();
  MockTracepointFormatParser parser("syscalls", "sys_enter_read", *bpftrace);
  auto result = parser.get_tracepoint_struct_public(format_file);

  EXPECT_TRUE(bool(result));

  Struct *type = result->get();
  EXPECT_EQ(type->size, 40);

  EXPECT_TRUE(type->HasField("common_type"));
  auto common_type = type->GetField("common_type");
  EXPECT_TRUE(common_type.type.IsIntTy());
  EXPECT_EQ(common_type.type.GetSize(), 2);
  EXPECT_FALSE(common_type.type.IsSigned());
  EXPECT_EQ(common_type.offset, 0);

  EXPECT_TRUE(type->HasField("common_flags"));
  auto common_flags = type->GetField("common_flags");
  EXPECT_TRUE(common_flags.type.IsIntTy());
  EXPECT_EQ(common_flags.type.GetSize(), 1);
  EXPECT_FALSE(common_flags.type.IsSigned());
  EXPECT_EQ(common_flags.offset, 2);

  EXPECT_TRUE(type->HasField("common_preempt_count"));
  auto common_preempt_count = type->GetField("common_preempt_count");
  EXPECT_TRUE(common_preempt_count.type.IsIntTy());
  EXPECT_EQ(common_preempt_count.type.GetSize(), 1);
  EXPECT_FALSE(common_preempt_count.type.IsSigned());
  EXPECT_EQ(common_preempt_count.offset, 3);

  EXPECT_TRUE(type->HasField("common_pid"));
  auto common_pid = type->GetField("common_pid");
  EXPECT_TRUE(common_pid.type.IsIntTy());
  EXPECT_EQ(common_pid.type.GetSize(), 4);
  EXPECT_TRUE(common_pid.type.IsSigned());
  EXPECT_EQ(common_pid.offset, 4);

  EXPECT_TRUE(type->HasField("__syscall_nr"));
  auto __syscall_nr = type->GetField("__syscall_nr");
  EXPECT_TRUE(__syscall_nr.type.IsIntTy());
  EXPECT_EQ(__syscall_nr.type.GetSize(), 4);
  EXPECT_TRUE(__syscall_nr.type.IsSigned());
  EXPECT_EQ(__syscall_nr.offset, 8);

  EXPECT_TRUE(type->HasField("fd"));
  auto fd = type->GetField("fd");
  EXPECT_TRUE(fd.type.IsIntTy());
  EXPECT_EQ(fd.type.GetSize(), 8);
  EXPECT_FALSE(fd.type.IsSigned());
  EXPECT_EQ(fd.offset, 16);

  EXPECT_TRUE(type->HasField("buf"));
  auto buf = type->GetField("buf");
  EXPECT_TRUE(buf.type.IsPtrTy());
  EXPECT_TRUE(buf.type.GetPointeeTy()->IsIntTy());
  EXPECT_EQ(buf.type.GetPointeeTy()->GetSize(), 1);
  EXPECT_EQ(buf.offset, 24);

  EXPECT_TRUE(type->HasField("count"));
  auto count = type->GetField("count");
  EXPECT_TRUE(count.type.IsIntTy());
  EXPECT_EQ(count.type.GetSize(), 8);
  EXPECT_FALSE(count.type.IsSigned());
  EXPECT_EQ(count.offset, 32);
}

TEST_F(tracepoint_format_parser, array)
{
  std::string input =
      "	field:char char_array[8];	offset:0;	size:8;	signed:1;\n"
      "	field:char uchar_array[8];	offset:8;	size:8;	signed:0;\n"
      "	field:int int_array[2];	offset:16;	size:8;	signed:1;\n";

  std::istringstream format_file(input);

  auto bpftrace = get_mock_bpftrace();
  MockTracepointFormatParser parser("syscalls", "sys_enter_read", *bpftrace);
  auto result = parser.get_tracepoint_struct_public(format_file);

  EXPECT_TRUE(bool(result));

  Struct *type = result->get();
  EXPECT_EQ(type->size, 24);

  EXPECT_TRUE(type->HasField("char_array"));
  auto char_array = type->GetField("char_array");
  EXPECT_TRUE(char_array.type.IsStringTy());
  EXPECT_EQ(char_array.offset, 0);

  EXPECT_TRUE(type->HasField("uchar_array"));
  auto uchar_array = type->GetField("uchar_array");
  EXPECT_TRUE(uchar_array.type.IsStringTy());
  EXPECT_EQ(uchar_array.offset, 8);

  EXPECT_TRUE(type->HasField("int_array"));
  auto int_array = type->GetField("int_array");
  EXPECT_TRUE(int_array.type.IsArrayTy());
  EXPECT_EQ(int_array.type.GetNumElements(), 2);
  EXPECT_EQ(int_array.offset, 16);
  const auto *int_array_elem = int_array.type.GetElementTy();
  EXPECT_TRUE(int_array_elem->IsIntTy());
  EXPECT_EQ(int_array_elem->GetSize(), 4);
  EXPECT_TRUE(int_array_elem->IsSigned());
}

TEST_F(tracepoint_format_parser, data_loc)
{
  std::string input =
      "	field:__data_loc char[] msg;	offset:0;	size:4;	signed:1;";

  std::istringstream format_file(input);

  auto bpftrace = get_mock_bpftrace();
  MockTracepointFormatParser parser("syscalls", "sys_enter_read", *bpftrace);
  auto result = parser.get_tracepoint_struct_public(format_file);

  EXPECT_TRUE(bool(result));

  Struct *type = result->get();
  EXPECT_EQ(type->size, 8);

  EXPECT_TRUE(type->HasField("msg"));
  auto msg = type->GetField("msg");
  EXPECT_TRUE(msg.type.IsIntTy());
  EXPECT_EQ(msg.type.GetSize(), 8);
  EXPECT_TRUE(msg.type.IsSigned());
  EXPECT_EQ(msg.offset, 0);
  EXPECT_TRUE(msg.is_data_loc);
}

TEST_F(tracepoint_format_parser, integer_types)
{
  // Check that we can handle several situations wrt. integer types:
  // - the size: or the signed: field has different value from what is standard
  //   for that type
  // - the types are named differently from what is in BTF
  std::string input =
      "  field:int int_field;  offset:0;  size:8;  signed:0;\n"
      "  field:unsigned int uint_field;  offset:8;  size:8;  signed:0;\n"
      "  field:unsigned unsigned_field;  offset:16;  size:4;  signed:0;\n"
      "  field:short short_field;  offset:20;  size:2;  signed:1;\n"
      "  field:unsigned short ushort_field;  offset:22;  size:2;  signed:0;\n"
      "  field:long long_field;  offset:24;  size:8;  signed:1;\n"
      "  field:unsigned long ulong_field;  offset:32;  size:8;  signed:0;\n"
      "  field:long long llong_field;  offset:40;  size:8;  signed:1;\n"
      "  field:unsigned long long ullong_field; offset:48; size:8; signed:0;\n";

  std::istringstream format_file(input);

  auto bpftrace = get_mock_bpftrace();
  MockTracepointFormatParser parser("syscalls", "sys_enter_read", *bpftrace);
  auto result = parser.get_tracepoint_struct_public(format_file);

  EXPECT_TRUE(bool(result));
  Struct *type = result->get();
  EXPECT_EQ(type->size, 56);

  EXPECT_TRUE(type->HasField("int_field"));
  auto int_field = type->GetField("int_field");
  EXPECT_TRUE(int_field.type.IsIntTy());
  EXPECT_EQ(int_field.type.GetSize(), 8);
  EXPECT_FALSE(int_field.type.IsSigned());
  EXPECT_EQ(int_field.offset, 0);

  EXPECT_TRUE(type->HasField("uint_field"));
  auto uint_field = type->GetField("uint_field");
  EXPECT_TRUE(uint_field.type.IsIntTy());
  EXPECT_EQ(uint_field.type.GetSize(), 8);
  EXPECT_FALSE(uint_field.type.IsSigned());
  EXPECT_EQ(uint_field.offset, 8);

  EXPECT_TRUE(type->HasField("unsigned_field"));
  auto unsigned_field = type->GetField("unsigned_field");
  EXPECT_TRUE(unsigned_field.type.IsIntTy());
  EXPECT_EQ(unsigned_field.type.GetSize(), 4);
  EXPECT_FALSE(unsigned_field.type.IsSigned());
  EXPECT_EQ(unsigned_field.offset, 16);

  EXPECT_TRUE(type->HasField("short_field"));
  auto short_field = type->GetField("short_field");
  EXPECT_TRUE(short_field.type.IsIntTy());
  EXPECT_EQ(short_field.type.GetSize(), 2);
  EXPECT_TRUE(short_field.type.IsSigned());
  EXPECT_EQ(short_field.offset, 20);

  EXPECT_TRUE(type->HasField("ushort_field"));
  auto ushort_field = type->GetField("ushort_field");
  EXPECT_TRUE(ushort_field.type.IsIntTy());
  EXPECT_EQ(ushort_field.type.GetSize(), 2);
  EXPECT_FALSE(ushort_field.type.IsSigned());
  EXPECT_EQ(ushort_field.offset, 22);

  EXPECT_TRUE(type->HasField("long_field"));
  auto long_field = type->GetField("long_field");
  EXPECT_TRUE(long_field.type.IsIntTy());
  EXPECT_EQ(long_field.type.GetSize(), 8);
  EXPECT_TRUE(long_field.type.IsSigned());
  EXPECT_EQ(long_field.offset, 24);

  EXPECT_TRUE(type->HasField("ulong_field"));
  auto ulong_field = type->GetField("ulong_field");
  EXPECT_TRUE(ulong_field.type.IsIntTy());
  EXPECT_EQ(ulong_field.type.GetSize(), 8);
  EXPECT_FALSE(ulong_field.type.IsSigned());
  EXPECT_EQ(ulong_field.offset, 32);

  EXPECT_TRUE(type->HasField("llong_field"));
  auto llong_field = type->GetField("llong_field");
  EXPECT_TRUE(llong_field.type.IsIntTy());
  EXPECT_EQ(llong_field.type.GetSize(), 8);
  EXPECT_TRUE(llong_field.type.IsSigned());
  EXPECT_EQ(llong_field.offset, 40);

  EXPECT_TRUE(type->HasField("ullong_field"));
  auto ullong_field = type->GetField("ullong_field");
  EXPECT_TRUE(ullong_field.type.IsIntTy());
  EXPECT_EQ(ullong_field.type.GetSize(), 8);
  EXPECT_FALSE(ullong_field.type.IsSigned());
  EXPECT_EQ(ullong_field.offset, 48);
}

TEST_F(tracepoint_format_parser, pointer_types)
{
  // Check that we can handle several various pointer types that appear in
  // tracepoint format files.
  std::string input =
      " field:int * ptr;	offset:0;	size:8;	signed:0;\n"
      " field:const int * const_ptr;	offset:8;	size:8;	signed:0;\n"
      " field:int ** double_ptr;	offset:16;	size:8;	signed:0;\n"
      " field:int * * double_ptr_space;	offset:24;	size:8;	signed:0;\n"
      " field:const int *const * dbl_const_ptr; offset:32; size:8; signed:0;\n";

  std::istringstream format_file(input);

  auto bpftrace = get_mock_bpftrace();
  MockTracepointFormatParser parser("syscalls", "sys_enter_read", *bpftrace);
  auto result = parser.get_tracepoint_struct_public(format_file);

  EXPECT_TRUE(bool(result));

  Struct *type = result->get();
  EXPECT_EQ(type->size, 40);

  EXPECT_TRUE(type->HasField("ptr"));
  auto ptr = type->GetField("ptr");
  EXPECT_TRUE(ptr.type.IsPtrTy());
  EXPECT_TRUE(ptr.type.GetPointeeTy()->IsIntTy());
  EXPECT_EQ(ptr.type.GetPointeeTy()->GetSize(), 4);
  EXPECT_EQ(ptr.offset, 0);

  EXPECT_TRUE(type->HasField("const_ptr"));
  auto const_ptr = type->GetField("const_ptr");
  EXPECT_TRUE(const_ptr.type.IsPtrTy());
  EXPECT_TRUE(const_ptr.type.GetPointeeTy()->IsIntTy());
  EXPECT_EQ(const_ptr.type.GetPointeeTy()->GetSize(), 4);
  EXPECT_EQ(const_ptr.offset, 8);

  EXPECT_TRUE(type->HasField("double_ptr"));
  auto double_ptr = type->GetField("double_ptr");
  EXPECT_TRUE(double_ptr.type.IsPtrTy());
  EXPECT_TRUE(double_ptr.type.GetPointeeTy()->IsPtrTy());
  EXPECT_TRUE(double_ptr.type.GetPointeeTy()->GetPointeeTy()->IsIntTy());
  EXPECT_EQ(double_ptr.type.GetPointeeTy()->GetPointeeTy()->GetSize(), 4);
  EXPECT_EQ(double_ptr.offset, 16);

  EXPECT_TRUE(type->HasField("double_ptr_space"));
  auto double_ptr_space = type->GetField("double_ptr_space");
  EXPECT_TRUE(double_ptr_space.type.IsPtrTy());
  EXPECT_TRUE(double_ptr_space.type.GetPointeeTy()->IsPtrTy());
  EXPECT_TRUE(double_ptr_space.type.GetPointeeTy()->GetPointeeTy()->IsIntTy());
  EXPECT_EQ(double_ptr_space.type.GetPointeeTy()->GetPointeeTy()->GetSize(), 4);
  EXPECT_EQ(double_ptr_space.offset, 24);

  EXPECT_TRUE(type->HasField("dbl_const_ptr"));
  auto dbl_const_ptr = type->GetField("dbl_const_ptr");
  EXPECT_TRUE(dbl_const_ptr.type.IsPtrTy());
  EXPECT_TRUE(dbl_const_ptr.type.GetPointeeTy()->IsPtrTy());
  EXPECT_TRUE(dbl_const_ptr.type.GetPointeeTy()->GetPointeeTy()->IsIntTy());
  EXPECT_EQ(dbl_const_ptr.type.GetPointeeTy()->GetPointeeTy()->GetSize(), 4);
  EXPECT_EQ(dbl_const_ptr.offset, 32);
}

TEST_F(tracepoint_format_parser, user_pointer)
{
  // Check that we can handle user-space pointer types marked with
  // btf_type_tag("user")
  std::string input =
      " field:char __attribute__((btf_type_tag(\"user\"))) * user_buf; "
      "offset:0; size:8; signed:0;\n"
      " field:char * kernel_buf; offset:8; size:8; signed:0;\n";

  std::istringstream format_file(input);

  auto bpftrace = get_mock_bpftrace();
  MockTracepointFormatParser parser("syscalls", "sys_enter_read", *bpftrace);
  auto result = parser.get_tracepoint_struct_public(format_file);

  EXPECT_TRUE(bool(result));

  Struct *type = result->get();
  EXPECT_EQ(type->size, 16);

  EXPECT_TRUE(type->HasField("user_buf"));
  auto user_buf = type->GetField("user_buf");
  EXPECT_TRUE(user_buf.type.IsPtrTy());
  EXPECT_EQ(user_buf.type.GetAS(), AddrSpace::user);
  EXPECT_TRUE(user_buf.type.GetPointeeTy()->IsIntTy());
  EXPECT_EQ(user_buf.offset, 0);

  EXPECT_TRUE(type->HasField("kernel_buf"));
  auto kernel_buf = type->GetField("kernel_buf");
  EXPECT_TRUE(kernel_buf.type.IsPtrTy());
  EXPECT_EQ(kernel_buf.type.GetAS(), AddrSpace::kernel);
  EXPECT_TRUE(kernel_buf.type.GetPointeeTy()->IsIntTy());
  EXPECT_EQ(kernel_buf.offset, 8);
}

} // namespace bpftrace::test::tracepoint_format_parser
