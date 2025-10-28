#include <iostream>
#include <sstream>

#include "format_string.h"
#include "required_resources.h"
#include "struct.h"
#include "types.h"
#include "gtest/gtest.h"

namespace bpftrace::test {

// ========================================================================
// It's a bit overkill to completely test every field in `RequiredResources`
// so for these tests we opt to get coverage on every type we serialize.
// ========================================================================

TEST(required_resources, round_trip_simple)
{
  std::ostringstream serialized(std::ios::binary);
  {
    RequiredResources r;
    r.probe_ids.emplace_back("itsastring");
    r.save_state(serialized);
  }

  std::istringstream input(serialized.str());
  {
    RequiredResources r;
    r.load_state(input);
    ASSERT_EQ(r.probe_ids.size(), 1UL);
    EXPECT_EQ(r.probe_ids[0], "itsastring");
  }
}

TEST(required_resources, round_trip_field_sized_type)
{
  std::ostringstream serialized(std::ios::binary);
  {
    RequiredResources r;
    r.system_args.emplace_back(FormatString("field0"),
                               std::vector{ Field{
                                   .name = "myfield",
                                   .type = CreateInt32(),
                                   .offset = 123,
                                   .bitfield = Bitfield(1, 2, 0xFF),
                               } });
    r.save_state(serialized);
  }

  std::istringstream input(serialized.str());
  {
    RequiredResources r;
    r.load_state(input);

    ASSERT_EQ(r.system_args.size(), 1UL);
    EXPECT_EQ(std::get<0>(r.system_args[0]).str(), "field0");

    auto &fields = std::get<1>(r.system_args[0]);
    ASSERT_EQ(fields.size(), 1UL);
    auto &field = fields[0];
    EXPECT_EQ(field.name, "myfield");
    EXPECT_TRUE(field.type.IsIntTy());
    EXPECT_EQ(field.type.GetSize(), 4UL);
    EXPECT_EQ(field.offset, 123);
    // clang-tidy does not recognize ASSERT_*() terminates testcase
    // NOLINTBEGIN(bugprone-unchecked-optional-access)
    ASSERT_TRUE(field.bitfield.has_value());
    EXPECT_EQ(field.bitfield->read_bytes, 1UL);
    EXPECT_EQ(field.bitfield->access_rshift, 2UL);
    EXPECT_EQ(field.bitfield->mask, 0xFFUL);
    // NOLINTEND(bugprone-unchecked-optional-access)
  }
}

TEST(required_resources, round_trip_map_info)
{
  std::ostringstream serialized(std::ios::binary);
  {
    MapInfo info{
      .key_type = CreateNone(),
      .value_type = CreateInet(3),
      .detail =
          LinearHistogramArgs{
              .min = 99,
              .max = 123,
              .step = 33,
          },
    };
    info.key_type = CreateInt32();
    RequiredResources r;
    r.maps_info.insert({ "mymap", info });
    r.save_state(serialized);
  }

  std::istringstream input(serialized.str());
  {
    RequiredResources r;
    r.load_state(input);

    ASSERT_EQ(r.maps_info.count("mymap"), 1UL);
    const auto &map_info = r.maps_info["mymap"];

    EXPECT_TRUE(map_info.value_type.IsInetTy());
    EXPECT_EQ(map_info.value_type.GetSize(), 3UL);

    EXPECT_TRUE(map_info.key_type.IsIntegerTy());
    EXPECT_EQ(map_info.key_type.GetSize(), 4);

    const auto &lhist_args = std::get<LinearHistogramArgs>(map_info.detail);
    EXPECT_EQ(lhist_args.min, 99);
    EXPECT_EQ(lhist_args.max, 123);
    EXPECT_EQ(lhist_args.step, 33);
  }
}

TEST(required_resources, round_trip_probes)
{
  std::ostringstream serialized(std::ios::binary);
  {
    RequiredResources r;

    Probe p;
    p.type = ProbeType::hardware;
    p.path = "mypath";
    p.index = 3;
    r.begin_probes.emplace_back(std::move(p));

    r.save_state(serialized);
  }

  std::istringstream input(serialized.str());
  {
    RequiredResources r;
    r.load_state(input);

    ASSERT_EQ(r.begin_probes.size(), 1UL);
    auto &probe = r.begin_probes.front();
    EXPECT_EQ(probe.type, ProbeType::hardware);
    EXPECT_EQ(probe.path, "mypath");
    EXPECT_EQ(probe.index, 3);
  }
}

TEST(required_resources, round_trip_multiple_members)
{
  std::ostringstream serialized(std::ios::binary);
  {
    RequiredResources r;
    r.join_args.emplace_back("joinarg0");
    r.time_args.emplace_back("timearg0");
    r.save_state(serialized);
  }

  std::istringstream input(serialized.str());
  {
    RequiredResources r;
    r.load_state(input);

    ASSERT_EQ(r.join_args.size(), 1UL);
    EXPECT_EQ(r.join_args[0], "joinarg0");
    ASSERT_EQ(r.time_args.size(), 1UL);
    EXPECT_EQ(r.time_args[0], "timearg0");
  }
}

} // namespace bpftrace::test
