#include "required_resources.h"

#include <iostream>
#include <sstream>

#include <gtest/gtest.h>

#include "struct.h"
#include "types.h"

namespace bpftrace {
namespace test {

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
    ASSERT_EQ(r.probe_ids.size(), 1);
    EXPECT_EQ(r.probe_ids[0], "itsastring");
  }
}

TEST(required_resources, round_trip_field_sized_type)
{
  std::ostringstream serialized(std::ios::binary);
  {
    RequiredResources r;
    r.system_args.emplace_back("field0",
                               std::vector{ Field{
                                   .name = "myfield",
                                   .type = CreateInt32(),
                                   .offset = 123,
                                   .is_bitfield = false,
                                   .bitfield =
                                       Bitfield{
                                           .read_bytes = 1,
                                           .access_rshift = 2,
                                           .mask = 0xFF,
                                       },
                               } });
    r.save_state(serialized);
  }

  std::istringstream input(serialized.str());
  {
    RequiredResources r;
    r.load_state(input);

    ASSERT_EQ(r.system_args.size(), 1);
    EXPECT_EQ(std::get<0>(r.system_args[0]), "field0");

    auto &fields = std::get<1>(r.system_args[0]);
    ASSERT_EQ(fields.size(), 1);
    auto &field = fields[0];
    EXPECT_EQ(field.name, "myfield");
    EXPECT_TRUE(field.type.IsIntTy());
    EXPECT_EQ(field.type.GetSize(), 4);
    EXPECT_EQ(field.offset, 123);
    EXPECT_EQ(field.is_bitfield, false);
    EXPECT_EQ(field.bitfield.read_bytes, 1);
    EXPECT_EQ(field.bitfield.access_rshift, 2);
    EXPECT_EQ(field.bitfield.mask, 0xFF);
  }
}

TEST(required_resources, round_trip_map_sized_type)
{
  std::ostringstream serialized(std::ios::binary);
  {
    RequiredResources r;
    r.map_vals.insert({ "mymap", CreateInet(3) });
    r.save_state(serialized);
  }

  std::istringstream input(serialized.str());
  {
    RequiredResources r;
    r.load_state(input);

    ASSERT_EQ(r.map_vals.count("mymap"), 1);
    auto &type = r.map_vals["mymap"];
    EXPECT_TRUE(type.IsInetTy());
    EXPECT_EQ(type.GetSize(), 3);
  }
}

TEST(required_resources, round_trip_map_lhist_args)
{
  std::ostringstream serialized(std::ios::binary);
  {
    RequiredResources r;
    r.lhist_args.insert({ "mymap",
                          LinearHistogramArgs{
                              .min = 99,
                              .max = 123,
                              .step = 33,
                          } });
    r.save_state(serialized);
  }

  std::istringstream input(serialized.str());
  {
    RequiredResources r;
    r.load_state(input);

    ASSERT_EQ(r.lhist_args.count("mymap"), 1);
    auto &args = r.lhist_args["mymap"];
    EXPECT_EQ(args.min, 99);
    EXPECT_EQ(args.max, 123);
    EXPECT_EQ(args.step, 33);
  }
}

TEST(required_resources, round_trip_set_stack_type)
{
  std::ostringstream serialized(std::ios::binary);
  {
    RequiredResources r;
    r.stackid_maps.insert(StackType{
        .limit = 33,
        .mode = StackMode::perf,
    });
    r.save_state(serialized);
  }

  std::istringstream input(serialized.str());
  {
    RequiredResources r;
    r.load_state(input);

    ASSERT_EQ(r.stackid_maps.size(), 1);
    for (const auto &st : r.stackid_maps)
    {
      EXPECT_EQ(st.limit, 33);
      EXPECT_EQ(st.mode, StackMode::perf);
    }
  }
}

TEST(required_resources, round_trip_multiple_members)
{
  std::ostringstream serialized(std::ios::binary);
  {
    RequiredResources r;
    r.join_args.emplace_back("joinarg0");
    r.stackid_maps.insert(StackType{
        .limit = 33,
        .mode = StackMode::perf,
    });
    r.needs_elapsed_map = true;
    r.save_state(serialized);
  }

  std::istringstream input(serialized.str());
  {
    RequiredResources r;
    r.load_state(input);

    ASSERT_EQ(r.join_args.size(), 1);
    EXPECT_EQ(r.join_args[0], "joinarg0");
    ASSERT_EQ(r.stackid_maps.size(), 1);
    for (const auto &st : r.stackid_maps)
    {
      EXPECT_EQ(st.limit, 33);
      EXPECT_EQ(st.mode, StackMode::perf);
    }
    EXPECT_TRUE(r.needs_elapsed_map);
  }
}

} // namespace test
} // namespace bpftrace
