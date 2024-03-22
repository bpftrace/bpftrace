#include "output.h"

#include <gtest/gtest.h>
#include <sstream>

#include "bpfmap.h"
#include "bpftrace.h"
#include "mocks.h"

namespace bpftrace::test::output {

TEST(TextOutput, lhist_no_suffix)
{
  std::stringstream out;
  std::stringstream err;
  TextOutput output{ out, err };

  MockBPFtrace bpftrace;
  bpftrace.resources.maps_info["@mymap"] = MapInfo{ MapKey{},
                                                    SizedType{ Type::lhist, 8 },
                                                    LinearHistogramArgs{
                                                        610000, 670000, 10000 },
                                                    {},
                                                    {} };
  BpfMap map{ libbpf::BPF_MAP_TYPE_HASH, "@mymap", 8, 8, 1000 };

  std::map<std::vector<uint8_t>, std::vector<uint64_t>> values_by_key = {
    {
        { 0 },
        { 0, 1, 1, 1, 1, 1, 1, 0 },
    },
  };

  std::vector<std::pair<std::vector<uint8_t>, uint64_t>> total_counts_by_key = {
    { { 0 }, 6 }
  };

  output.map_hist(bpftrace, map, 0, 0, values_by_key, total_counts_by_key);

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
  EXPECT_TRUE(err.str().empty());
}

TEST(TextOutput, lhist_suffix)
{
  std::stringstream out;
  std::stringstream err;
  TextOutput output{ out, err };

  MockBPFtrace bpftrace;
  bpftrace.resources.maps_info["@mymap"] = MapInfo{ MapKey{},
                                                    SizedType{ Type::lhist, 8 },
                                                    LinearHistogramArgs{
                                                        0, 5 * 1024, 1024 },
                                                    {},
                                                    {} };
  BpfMap map{ libbpf::BPF_MAP_TYPE_HASH, "@mymap", 8, 8, 1000 };

  std::map<std::vector<uint8_t>, std::vector<uint64_t>> values_by_key = {
    {
        { 0 },
        { 0, 1, 1, 1, 1, 1, 0 },
    },
  };

  std::vector<std::pair<std::vector<uint8_t>, uint64_t>> total_counts_by_key = {
    { { 0 }, 5 }
  };

  output.map_hist(bpftrace, map, 0, 0, values_by_key, total_counts_by_key);

  EXPECT_EQ(R"(@mymap: 
[0, 1K)                1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[1K, 2K)               1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[2K, 3K)               1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[3K, 4K)               1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[4K, 5K)               1 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|

)",
            out.str());
  EXPECT_TRUE(err.str().empty());
}

} // namespace bpftrace::test::output
