#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

namespace call_len {
constexpr auto PROG = "BEGIN { @x[1] = 1; } kprobe:f { $s = len(@x); }";

TEST_F(codegen_btf, call_len_for_each_map_elem)
{
  auto bpftrace = get_mock_bpftrace();
  auto feature = std::make_unique<MockBPFfeature>();
  feature->mock_missing_kernel_func(Kfunc::bpf_map_sum_elem_count);
  bpftrace->feature_ = std::move(feature);

  test(*bpftrace, PROG, NAME);
}

TEST_F(codegen_btf, call_len_map_sum_elem_count)
{
  test(PROG, NAME);
}

TEST_F(codegen_btf, call_len_ustack_kstack)
{
  test("kprobe:f { @x = len(ustack); @y = len(kstack); }", NAME);
}

} // namespace call_len

} // namespace codegen
} // namespace test
} // namespace bpftrace
