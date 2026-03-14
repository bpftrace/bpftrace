#include "struct.h"
#include "util/opaque.h"
#include "gtest/gtest.h"
#include <unistd.h>

namespace bpftrace::test::bitfield {

TEST(bitfield, to_opaque)
{
  auto data = bpftrace::util::OpaqueValue::from<uint8_t>(0xff);
  auto bf = bpftrace::Bitfield{ 1, 0, 0x1 };
  EXPECT_EQ(bf.to_opaque<uint8_t>(data),
            bpftrace::util::OpaqueValue::from<uint8_t>(0x1));

  bf = bpftrace::Bitfield{ 1, 0, 0x3 };
  EXPECT_EQ(bf.to_opaque<uint8_t>(data),
            bpftrace::util::OpaqueValue::from<uint8_t>(0x3));

  // test other data types
  data = bpftrace::util::OpaqueValue::from<uint16_t>(0x0304);
  bf = bpftrace::Bitfield{ 2, 8, 0xf };
  EXPECT_EQ(bf.to_opaque<uint16_t>(data),
            bpftrace::util::OpaqueValue::from<uint16_t>(0x3));

  data = bpftrace::util::OpaqueValue::from<uint32_t>(0x01020304);
  bf = bpftrace::Bitfield{ 4, 8, 0xf };
  EXPECT_EQ(bf.to_opaque<uint32_t>(data),
            bpftrace::util::OpaqueValue::from<uint32_t>(0x3));

  data = bpftrace::util::OpaqueValue::from<uint64_t>(0x0102030405060708);
  bf = bpftrace::Bitfield{ 8, 40, 0xf };
  EXPECT_EQ(bf.to_opaque<uint64_t>(data),
            bpftrace::util::OpaqueValue::from<uint64_t>(0x3));
}

TEST(bitfield, to_opaque_boundary)
{
  // test crossing the byte boundary
  auto data = bpftrace::util::OpaqueValue::from<uint32_t>(0x01020304);
  auto bf = bpftrace::Bitfield{ 4, 6, 0xf };
  EXPECT_EQ(bf.to_opaque<uint32_t>(data),
            bpftrace::util::OpaqueValue::from<uint32_t>(0xc));
}

} // namespace bpftrace::test::bitfield
