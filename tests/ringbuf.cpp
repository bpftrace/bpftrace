#include "bpfmap.h"
#include "gtest/gtest.h"

namespace bpftrace::test::ringbuf {

TEST(ringbuf, name)
{
  auto s1 = get_bpf_ringbuf_map_str(RingbufMap::Normal);
  EXPECT_EQ(s1, "ringbuf");
  auto s2 = get_bpf_ringbuf_map_str(RingbufMap::Urgent);
  EXPECT_EQ(s2, "ringbuf_urg");
}

} // namespace bpftrace::test::ringbuf
