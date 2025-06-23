#include <sstream>

#include "bpfmap.h"
#include "mocks.h"
#include "output/text.h"
#include "types_format.h"
#include "gtest/gtest.h"

namespace bpftrace::test::output {

static ast::CDefinitions no_c_defs; // Used for format below.

TEST(TextOutput, lhist_no_suffix)
{
  std::stringstream out;
  ::bpftrace::output::TextOutput output(out);

  auto bpftrace = get_mock_bpftrace();
  bpftrace->resources.maps_info["@mymap"] = MapInfo{
    .key_type = CreateInt64(),
    .value_type = SizedType{ Type::lhist_t, 8 },
    .detail = LinearHistogramArgs{ .min = 610000,
                                   .max = 670000,
                                   .step = 10000 },
    .id = {},
    .is_scalar = true,
  };
  std::map<std::vector<uint8_t>, std::vector<uint64_t>> values_by_key = {
    {
        { 0 },
        { 0, 1, 1, 1, 1, 1, 1, 0 },
    },
  };
  auto mock_map = std::make_unique<MockBpfMap>(libbpf::BPF_MAP_TYPE_HASH,
                                               "@mymap");
  EXPECT_CALL(*mock_map, collect_histogram_data(testing::_, testing::_))
      .WillOnce(testing::Return(
          testing::ByMove(Result<HistogramMap>(values_by_key))));

  auto hist = format(*bpftrace, no_c_defs, *mock_map);
  ASSERT_TRUE(bool(hist));
  output.map(mock_map->name(), *hist);

  // The buckets for this test case have been specifically chosen: 640000 can
  // also be written as 625K, while the other bucket boundaries can not be
  // expressed with a suffix. We should only use the suffix representation for a
  // bucket if all buckets can be expressed with one.
  EXPECT_EQ(R"(@mymap:
[610000, 620000)       1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[620000, 630000)       1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[630000, 640000)       1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[640000, 650000)       1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[650000, 660000)       1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[660000, 670000)       1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

)",
            out.str());
}

TEST(TextOutput, lhist_suffix)
{
  std::stringstream out;
  ::bpftrace::output::TextOutput output(out);

  auto bpftrace = get_mock_bpftrace();
  bpftrace->resources.maps_info["@mymap"] = MapInfo{
    .key_type = CreateInt64(),
    .value_type = SizedType{ Type::lhist_t, 8 },
    .detail = LinearHistogramArgs{ .min = 0, .max = 5 * 1024, .step = 1024 },
    .id = {},
    .is_scalar = true,
  };
  std::map<std::vector<uint8_t>, std::vector<uint64_t>> values_by_key = {
    {
        { 0 },
        { 0, 1, 1, 1, 1, 1, 0 },
    },
  };
  auto mock_map = std::make_unique<MockBpfMap>(libbpf::BPF_MAP_TYPE_HASH,
                                               "@mymap");
  EXPECT_CALL(*mock_map, collect_histogram_data(testing::_, testing::_))
      .WillOnce(testing::Return(
          testing::ByMove(Result<HistogramMap>(values_by_key))));

  auto hist = format(*bpftrace, no_c_defs, *mock_map);
  ASSERT_TRUE(bool(hist));
  output.map(mock_map->name(), *hist);

  EXPECT_EQ(R"(@mymap:
[0, 1K)                1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1K, 2K)               1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[2K, 3K)               1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[3K, 4K)               1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[4K, 5K)               1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

)",
            out.str());
}

} // namespace bpftrace::test::output
