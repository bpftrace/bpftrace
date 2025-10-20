#include "types.h"
#include "struct.h"
#include "gtest/gtest.h"

namespace bpftrace::test::types {

static std::string to_str(SizedType type)
{
  std::stringstream out;
  out << type;
  return out.str();
}

TEST(types, to_str)
{
  EXPECT_EQ(to_str(CreateInt8()), "int8");
  EXPECT_EQ(to_str(CreateInt16()), "int16");
  EXPECT_EQ(to_str(CreateInt32()), "int32");
  EXPECT_EQ(to_str(CreateInt64()), "int64");
  EXPECT_EQ(to_str(CreateUInt8()), "uint8");
  EXPECT_EQ(to_str(CreateUInt16()), "uint16");
  EXPECT_EQ(to_str(CreateUInt32()), "uint32");
  EXPECT_EQ(to_str(CreateUInt64()), "uint64");

  EXPECT_EQ(to_str(CreateString(10)), "string[10]");

  EXPECT_EQ(to_str(CreateInet(10)), "inet[10]");
  EXPECT_EQ(to_str(CreateBuffer(10)), "buffer[14]"); // metadata headroom

  EXPECT_EQ(to_str(CreatePointer(CreateInt8(), AddrSpace::kernel)), "int8 *");

  auto ptr_ctx = CreatePointer(CreateInt8(), AddrSpace::kernel);
  EXPECT_EQ(to_str(ptr_ctx), "int8 *");

  EXPECT_EQ(to_str(CreateArray(2, CreateInt8())), "int8[2]");

  EXPECT_EQ(to_str(CreateCStruct("hello")), "hello");

  std::shared_ptr<Struct> tuple = Struct::CreateTuple(
      { CreateInt8(), CreateString(10) });
  EXPECT_EQ(to_str(CreateTuple(std::move(tuple))), "(int8,string[10])");

  EXPECT_EQ(to_str(CreateSum(true)), "sum_t");
  EXPECT_EQ(to_str(CreateSum(false)), "usum_t");

  EXPECT_EQ(to_str(CreateMin(true)), "min_t");
  EXPECT_EQ(to_str(CreateMin(false)), "umin_t");

  EXPECT_EQ(to_str(CreateMax(true)), "max_t");
  EXPECT_EQ(to_str(CreateMax(false)), "umax_t");

  EXPECT_EQ(to_str(CreateAvg(true)), "avg_t");
  EXPECT_EQ(to_str(CreateAvg(false)), "uavg_t");

  EXPECT_EQ(to_str(CreateStats(true)), "stats_t");
  EXPECT_EQ(to_str(CreateStats(false)), "ustats_t");

  EXPECT_EQ(to_str(CreateCount()), "count_t");

  EXPECT_EQ(to_str(CreateMacAddress()), "mac_address");

  EXPECT_EQ(to_str(CreateStack(true)), "kstack_bpftrace_127");
  EXPECT_EQ(to_str(CreateStack(false)), "ustack_bpftrace_127");

  StackType stack_type = StackType();
  stack_type.limit = 10;
  stack_type.mode = StackMode::raw;
  EXPECT_EQ(to_str(CreateStack(true, stack_type)), "kstack_raw_10");

  StackType stack_type2 = StackType();
  stack_type2.limit = 20;
  stack_type2.mode = StackMode::build_id;
  EXPECT_EQ(to_str(CreateStack(false, stack_type2)), "ustack_build_id_20");

  EXPECT_EQ(to_str(CreateTimestamp()), "timestamp");
  EXPECT_EQ(to_str(CreateKSym()), "ksym_t");
  EXPECT_EQ(to_str(CreateUSym()), "usym_t");
  EXPECT_EQ(to_str(CreateUsername()), "username");
  EXPECT_EQ(to_str(CreateTimestampMode()), "timestamp_mode");
  EXPECT_EQ(to_str(CreateCgroupPath()), "cgroup_path_t");
  EXPECT_EQ(to_str(CreateHist()), "hist_t");
  EXPECT_EQ(to_str(CreateLhist()), "lhist_t");
  EXPECT_EQ(to_str(CreateTSeries()), "tseries_t");
  EXPECT_EQ(to_str(CreateNone()), "none");
  EXPECT_EQ(to_str(CreateVoid()), "void");
}

} // namespace bpftrace::test::types
