#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, map_hash)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, R"(let @a = hash(10); begin { @a[1] = 1; })", NAME);
}

TEST(codegen, map_lruhash)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, R"(let @a = lruhash(10); begin { @a[1] = 1; })", NAME);
}

TEST(codegen, map_percpuhash)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace,
       R"(let @a = percpuhash(10); begin { @a[1] = count(); })",
       NAME);
}

TEST(codegen, map_percpulruhash)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace,
       R"(let @a = percpulruhash(10); begin { @a[1] = count(); })",
       NAME);
}

TEST(codegen, map_percpuarray)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, R"(let @a = percpuarray(1); begin { @a = count(); })", NAME);
}

// Make sure it doesn't make it to codegen
TEST(codegen, map_unused)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, R"(let @a = hash(1); begin { 1 })", NAME);
}

} // namespace bpftrace::test::codegen
