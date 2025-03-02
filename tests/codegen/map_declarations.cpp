#include "common.h"

namespace bpftrace::test::codegen {

TEST(codegen, map_hash)
{
  auto bpftrace = get_mock_bpftrace();
  auto configs = ConfigSetter(*bpftrace->config_, ConfigSource::script);
  configs.set(ConfigKeyBool::unstable_map_decl, true);

  test(*bpftrace, R"(let @a = hash(10); BEGIN { @a[1] = 1; })", NAME);
}

TEST(codegen, map_lruhash)
{
  auto bpftrace = get_mock_bpftrace();
  auto configs = ConfigSetter(*bpftrace->config_, ConfigSource::script);
  configs.set(ConfigKeyBool::unstable_map_decl, true);

  test(*bpftrace, R"(let @a = lruhash(10); BEGIN { @a[1] = 1; })", NAME);
}

TEST(codegen, map_percpuhash)
{
  auto bpftrace = get_mock_bpftrace();
  auto configs = ConfigSetter(*bpftrace->config_, ConfigSource::script);
  configs.set(ConfigKeyBool::unstable_map_decl, true);

  test(*bpftrace,
       R"(let @a = percpuhash(10); BEGIN { @a[1] = count(); })",
       NAME);
}

TEST(codegen, map_percpulruhash)
{
  auto bpftrace = get_mock_bpftrace();
  auto configs = ConfigSetter(*bpftrace->config_, ConfigSource::script);
  configs.set(ConfigKeyBool::unstable_map_decl, true);

  test(*bpftrace,
       R"(let @a = percpulruhash(10); BEGIN { @a[1] = count(); })",
       NAME);
}

TEST(codegen, map_percpuarray)
{
  auto bpftrace = get_mock_bpftrace();
  auto configs = ConfigSetter(*bpftrace->config_, ConfigSource::script);
  configs.set(ConfigKeyBool::unstable_map_decl, true);

  test(*bpftrace, R"(let @a = percpuarray(1); BEGIN { @a = count(); })", NAME);
}

// Make sure it doesn't make it to codegen
TEST(codegen, map_unused)
{
  auto bpftrace = get_mock_bpftrace();
  auto configs = ConfigSetter(*bpftrace->config_, ConfigSource::script);
  configs.set(ConfigKeyBool::unstable_map_decl, true);

  test(*bpftrace, R"(let @a = hash(1); BEGIN { 1 })", NAME);
}

} // namespace bpftrace::test::codegen
