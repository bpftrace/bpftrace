#include "common.h"
#include "config.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, call_join)
{
  test("struct arg { char **argv } kprobe:f { $x = (struct arg *) 0; "
       "join($x->argv); }",
       NAME);
}

TEST(codegen, call_join_with_debug)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->feature_ = std::make_unique<MockBPFfeature>(true);
  auto config_setter = ConfigSetter(bpftrace->config_, ConfigSource::env_var);
  config_setter.set(ConfigKeyBool::debug_output, true);
  test(*bpftrace,
       "struct arg { char **argv } kprobe:f { $x = (struct arg *) 0; "
       "join($x->argv); }",
       NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace
