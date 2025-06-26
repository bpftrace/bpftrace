#include "common.h"
#include "config.h"

namespace bpftrace::test::codegen {

TEST(codegen, call_join)
{
  test("struct arg { char **argv } kprobe:f { $x = (struct arg *) 0; "
       "join($x->argv); }",
       NAME);
}

TEST(codegen, call_join_with_debug)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->debug_output_ = true;
  test(*bpftrace,
       "struct arg { char **argv } kprobe:f { $x = (struct arg *) 0; "
       "join($x->argv); }",
       NAME);
}

} // namespace bpftrace::test::codegen
