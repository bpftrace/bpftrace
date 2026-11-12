#include <cerrno>
#include <cstring>
#include <set>

#include "bpfmap.h"
#include "gtest/gtest.h"

namespace bpftrace::test::bpfmap {

// The kernel returns ENOTSUPP for map types without batch operations.
constexpr int KERNEL_ENOTSUPP = 524;

// Behaves like the kernel's BPF_MAP_LOOKUP_BATCH on a hash map: elements live
// in buckets, a whole bucket is returned or none of it, and the batch position
// is the index of the next bucket to read.
class FakeHashMap {
public:
  FakeHashMap(std::vector<std::vector<uint64_t>> buckets)
      : buckets_(std::move(buckets))
  {
  }

  MapBatchOp op()
  {
    return [this](void *in_batch,
                  void *out_batch,
                  void *keys,
                  void *values,
                  uint32_t *count) {
      return lookup_batch(in_batch, out_batch, keys, values, count);
    };
  }

  std::vector<uint32_t> requested_counts;

private:
  int lookup_batch(void *in_batch,
                   void *out_batch,
                   void *keys,
                   void *values,
                   uint32_t *count)
  {
    requested_counts.push_back(*count);
    uint32_t bucket = 0;
    if (in_batch) {
      std::memcpy(&bucket, in_batch, sizeof(bucket));
    }

    int ret = 0;
    uint32_t total = 0;
    for (; bucket < buckets_.size(); bucket++) {
      const auto &elems = buckets_.at(bucket);
      if (elems.size() > *count - total) {
        if (total == 0) {
          ret = -ENOSPC;
        }
        break;
      }
      for (uint64_t key : elems) {
        uint64_t value = key * 10;
        std::memcpy(static_cast<char *>(keys) + (total * sizeof(key)),
                    &key,
                    sizeof(key));
        std::memcpy(static_cast<char *>(values) + (total * sizeof(value)),
                    &value,
                    sizeof(value));
        total++;
      }
    }
    if (bucket >= buckets_.size()) {
      ret = -ENOENT;
    }

    std::memcpy(out_batch, &bucket, sizeof(bucket));
    *count = total;
    return ret;
  }

  std::vector<std::vector<uint64_t>> buckets_;
};

static Result<bool> walk(const MapBatchOp &op, std::vector<uint64_t> &keys)
{
  return batch_walk_map("AT_x",
                        "lookup",
                        sizeof(uint64_t),
                        sizeof(uint64_t),
                        op,
                        [&](OpaqueValue key, OpaqueValue value) {
                          EXPECT_EQ(value.bitcast<uint64_t>(),
                                    key.bitcast<uint64_t>() * 10);
                          keys.push_back(key.bitcast<uint64_t>());
                        });
}

TEST(BatchWalkMap, empty_map)
{
  FakeHashMap map({ {}, {}, {} });
  std::vector<uint64_t> keys;
  auto ok = walk(map.op(), keys);
  ASSERT_TRUE(bool(ok));
  EXPECT_TRUE(*ok);
  EXPECT_TRUE(keys.empty());
  EXPECT_EQ(map.requested_counts.size(), 1);
}

TEST(BatchWalkMap, many_batches)
{
  // 3000 elements, two per bucket, need three batches of 1024.
  std::vector<std::vector<uint64_t>> buckets;
  for (uint64_t i = 0; i < 3000; i += 2) {
    buckets.push_back({ i, i + 1 });
  }
  FakeHashMap map(std::move(buckets));
  std::vector<uint64_t> keys;
  auto ok = walk(map.op(), keys);
  ASSERT_TRUE(bool(ok));
  EXPECT_TRUE(*ok);
  EXPECT_EQ(map.requested_counts.size(), 3);

  // Every element is visited exactly once.
  ASSERT_EQ(keys.size(), 3000);
  std::set<uint64_t> unique(keys.begin(), keys.end());
  EXPECT_EQ(unique.size(), 3000);
  EXPECT_EQ(*unique.begin(), 0);
  EXPECT_EQ(*unique.rbegin(), 2999);
}

TEST(BatchWalkMap, bucket_larger_than_batch)
{
  // The middle bucket does not fit into the initial buffer, so the kernel
  // returns ENOSPC and the buffer has to grow.
  std::vector<uint64_t> big;
  for (uint64_t i = 1; i <= 3000; i++) {
    big.push_back(i);
  }
  FakeHashMap map({ { 0 }, big, { 3001 } });
  std::vector<uint64_t> keys;
  auto ok = walk(map.op(), keys);
  ASSERT_TRUE(bool(ok));
  EXPECT_TRUE(*ok);
  EXPECT_EQ(map.requested_counts,
            std::vector<uint32_t>({ 1024, 1024, 2048, 4096 }));
  ASSERT_EQ(keys.size(), 3002);
  std::set<uint64_t> unique(keys.begin(), keys.end());
  EXPECT_EQ(unique.size(), 3002);
}

TEST(BatchWalkMap, without_callback)
{
  FakeHashMap map({ { 1, 2 }, { 3 } });
  auto ok = batch_walk_map(
      "AT_x", "clear", sizeof(uint64_t), sizeof(uint64_t), map.op(), nullptr);
  ASSERT_TRUE(bool(ok));
  EXPECT_TRUE(*ok);
  EXPECT_EQ(map.requested_counts.size(), 1);
}

TEST(BatchWalkMap, unsupported)
{
  for (int err : { -KERNEL_ENOTSUPP, -EOPNOTSUPP, -EINVAL }) {
    int calls = 0;
    std::vector<uint64_t> keys;
    auto ok = walk(
        [&](void *, void *, void *, void *, uint32_t *) {
          calls++;
          return err;
        },
        keys);
    ASSERT_TRUE(bool(ok));
    EXPECT_FALSE(*ok);
    EXPECT_EQ(calls, 1);
    EXPECT_TRUE(keys.empty());
  }
}

TEST(BatchWalkMap, error)
{
  std::vector<uint64_t> keys;
  auto ok = walk(
      [](void *, void *, void *, void *, uint32_t *) { return -EPERM; }, keys);
  ASSERT_FALSE(bool(ok));
  EXPECT_EQ(llvm::toString(ok.takeError()),
            "BPF map operation lookup failed: Operation not permitted [map = "
            "AT_x]");
}

TEST(BatchWalkMap, error_after_first_batch)
{
  // Once elements have been visited, falling back to per-key lookups would
  // visit them twice, so even EINVAL is an error.
  FakeHashMap map({ { 1 }, { 2 } });
  auto op = map.op();
  int calls = 0;
  std::vector<uint64_t> keys;
  auto ok = walk(
      [&](void *in_batch, void *out_batch, void *k, void *v, uint32_t *count) {
        if (calls++ > 0) {
          return -EINVAL;
        }
        *count = 1;
        return op(in_batch, out_batch, k, v, count);
      },
      keys);
  ASSERT_FALSE(bool(ok));
  EXPECT_EQ(llvm::toString(ok.takeError()),
            "BPF map operation lookup failed: Invalid argument [map = AT_x]");
  EXPECT_EQ(keys, std::vector<uint64_t>({ 1 }));
}

} // namespace bpftrace::test::bpfmap
