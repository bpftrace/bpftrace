#include "util/opaque.h"
#include "gtest/gtest.h"
#include <cstring>
#include <numbers> // for std::numbers
#include <string>
#include <vector>

namespace bpftrace::util::test::opaque {

TEST(OpaqueValueTest, BasicAllocation)
{
  auto value = OpaqueValue::alloc(10, [](char* data) {
    for (int i = 0; i < 10; ++i) {
      data[i] = static_cast<char>(i);
    }
  });

  EXPECT_EQ(value.size(), 10);
  const char* data = value.data();
  for (int i = 0; i < 10; ++i) {
    EXPECT_EQ(data[i], static_cast<char>(i));
  }
}

TEST(OpaqueValueTest, ZeroSizeAllocation)
{
  auto value = OpaqueValue::alloc(0);
  EXPECT_EQ(value.size(), 0);
}

TEST(OpaqueValueTest, StringCreation)
{
  std::string test_str = "hello";
  auto value = OpaqueValue::string(test_str, 10);

  EXPECT_EQ(value.size(), 10);
  const char* data = value.data();
  EXPECT_STREQ(data, "hello");

  for (size_t i = test_str.size() + 1; i < 10; ++i) {
    EXPECT_EQ(data[i], 0);
  }
}

TEST(OpaqueValueTest, StringCreationExactSize)
{
  std::string test_str = "hello";
  auto value = OpaqueValue::string(test_str, test_str.size() + 1);

  EXPECT_EQ(value.size(), 6);
  EXPECT_STREQ(value.data(), "hello");
}

TEST(OpaqueValueTest, StringCreationTruncated)
{
  std::string test_str = "hello world";
  auto value = OpaqueValue::string(test_str, 5);

  EXPECT_EQ(value.size(), 5);
  const char* data = value.data();
  EXPECT_EQ(std::string(data, 5), "hello");
}

TEST(OpaqueValueTest, FromTrivialTypes)
{
  int test_int = 42;
  auto int_value = OpaqueValue::from(test_int);

  EXPECT_EQ(int_value.size(), sizeof(int));
  EXPECT_EQ(int_value.bitcast<int>(), 42);

  double test_double = std::numbers::pi;
  auto double_value = OpaqueValue::from(test_double);

  EXPECT_EQ(double_value.size(), sizeof(double));
  EXPECT_DOUBLE_EQ(double_value.bitcast<double>(), std::numbers::pi);
}

TEST(OpaqueValueTest, FromPointerAndLength)
{
  int test_array[] = { 1, 2, 3, 4, 5 };
  auto value = OpaqueValue::from(test_array, 5);

  EXPECT_EQ(value.size(), sizeof(int) * 5);
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(value.bitcast<int>(i), i + 1);
  }
}

TEST(OpaqueValueTest, FromVector)
{
  std::vector<int> test_vec = { 10, 20, 30 };
  auto value = OpaqueValue::from(test_vec);

  EXPECT_EQ(value.size(), sizeof(int) * 3);
  for (size_t i = 0; i < 3; ++i) {
    EXPECT_EQ(value.bitcast<int>(i), test_vec[i]);
  }
}

TEST(OpaqueValueTest, FromStringRange)
{
  std::string test_str = "abc";
  auto value = OpaqueValue::from(test_str);

  // Should include null terminator.
  EXPECT_EQ(value.size(), 4);
  EXPECT_STREQ(value.data(), "abc");
}

TEST(OpaqueValueTest, Concatenation)
{
  auto value1 = OpaqueValue::from<int>(42);
  auto value2 = OpaqueValue::from<double>(std::numbers::pi);

  auto combined = value1 + value2;

  EXPECT_EQ(combined.size(), sizeof(int) + sizeof(double));
  EXPECT_EQ(combined.bitcast<int>(0), 42);
  EXPECT_DOUBLE_EQ(combined.slice(sizeof(int)).bitcast<double>(0),
                   std::numbers::pi);
}

TEST(OpaqueValueTest, MultipleConcatenations)
{
  auto value1 = OpaqueValue::from(1);
  auto value2 = OpaqueValue::from(2);
  auto value3 = OpaqueValue::from(3);

  auto combined = value1 + value2 + value3;

  EXPECT_EQ(combined.size(), sizeof(int) * 3);
  EXPECT_EQ(combined.bitcast<int>(0), 1);
  EXPECT_EQ(combined.bitcast<int>(1), 2);
  EXPECT_EQ(combined.bitcast<int>(2), 3);
}

TEST(OpaqueValueTest, BasicSlicing)
{
  auto value = OpaqueValue::alloc(10, [](char* data) {
    for (int i = 0; i < 10; ++i) {
      data[i] = static_cast<char>(i);
    }
  });

  auto slice = value.slice(2, 5);

  EXPECT_EQ(slice.size(), 5);
  const char* data = slice.data();
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(data[i], static_cast<char>(i + 2));
  }
}

TEST(OpaqueValueTest, SlicingToEnd)
{
  auto value = OpaqueValue::alloc(10, [](char* data) {
    for (int i = 0; i < 10; ++i) {
      data[i] = static_cast<char>(i);
    }
  });

  auto slice = value.slice(3);

  EXPECT_EQ(slice.size(), 7);
  const char* data = slice.data();
  for (int i = 0; i < 7; ++i) {
    EXPECT_EQ(data[i], static_cast<char>(i + 3));
  }
}

TEST(OpaqueValueTest, NestedSlicing)
{
  auto value = OpaqueValue::alloc(10, [](char* data) {
    for (int i = 0; i < 10; ++i) {
      data[i] = static_cast<char>(i);
    }
  });

  auto slice1 = value.slice(2, 6);
  auto slice2 = slice1.slice(1, 3);

  EXPECT_EQ(slice2.size(), 3);
  const char* data = slice2.data();
  for (int i = 0; i < 3; ++i) {
    EXPECT_EQ(data[i], static_cast<char>(i + 3));
  }
}

TEST(OpaqueValueTest, CountMethod)
{
  constexpr size_t kSize = 20;
  auto value = OpaqueValue::alloc(kSize,
                                  [](char* data) { memset(data, 0, kSize); });

  EXPECT_EQ(value.count<int>(), kSize / sizeof(int));
  EXPECT_EQ(value.count<char>(), kSize / sizeof(char));
  EXPECT_EQ(value.count<double>(), kSize / sizeof(double));
}

TEST(OpaqueValueTest, BitcastWithIndex)
{
  int test_array[] = { 10, 20, 30, 40 };
  auto value = OpaqueValue::from(test_array, 4);

  EXPECT_EQ(value.bitcast<int>(0), 10);
  EXPECT_EQ(value.bitcast<int>(1), 20);
  EXPECT_EQ(value.bitcast<int>(2), 30);
  EXPECT_EQ(value.bitcast<int>(3), 40);
}

TEST(OpaqueValueTest, EqualityOperator)
{
  auto value1 = OpaqueValue::from(42);
  auto value2 = OpaqueValue::from(42);
  auto value3 = OpaqueValue::from(43);

  EXPECT_TRUE(value1 == value2);
  EXPECT_FALSE(value1 == value3);
  EXPECT_FALSE(value1 != value2);
  EXPECT_TRUE(value1 != value3);
}

TEST(OpaqueValueTest, EqualityDifferentSizes)
{
  auto value1 = OpaqueValue::from(42);
  auto value2 = OpaqueValue::from(42.0);

  EXPECT_FALSE(value1 == value2);
  EXPECT_TRUE(value1 != value2);
}

TEST(OpaqueValueTest, EqualityWithSlices)
{
  auto value1 = OpaqueValue::alloc(8, [](char* data) {
    memcpy(data, "abcdefgh", 8);
  });

  auto value2 = OpaqueValue::alloc(4,
                                   [](char* data) { memcpy(data, "cdef", 4); });

  auto slice = value1.slice(2, 4);

  EXPECT_TRUE(slice == value2);
  EXPECT_FALSE(slice != value2);
}

TEST(OpaqueValueTest, LessThanOperator)
{
  auto value1 = OpaqueValue::alloc(4,
                                   [](char* data) { memcpy(data, "aaaa", 4); });

  auto value2 = OpaqueValue::alloc(4,
                                   [](char* data) { memcpy(data, "aaab", 4); });

  auto value3 = OpaqueValue::alloc(3,
                                   [](char* data) { memcpy(data, "aaa", 3); });

  EXPECT_TRUE(value1 < value2);
  EXPECT_FALSE(value2 < value1);
  EXPECT_TRUE(value3 < value1); // Shorter length should be less.
}

TEST(OpaqueValueTest, HashFunctionality)
{
  auto value1 = OpaqueValue::from(42);
  auto value2 = OpaqueValue::from(42);
  auto value3 = OpaqueValue::from(43);

  EXPECT_EQ(value1.hash(), value2.hash());
  EXPECT_NE(value1.hash(), value3.hash());

  std::hash<OpaqueValue> hasher;
  EXPECT_EQ(hasher(value1), hasher(value2));
  EXPECT_NE(hasher(value1), hasher(value3));
}

TEST(OpaqueValueTest, SliceOutOfBounds)
{
  auto value = OpaqueValue::alloc(10, [](char* data) { memset(data, 0, 10); });

  EXPECT_THROW(value.slice(15), std::bad_alloc);
  EXPECT_THROW(value.slice(5, 10), std::bad_alloc);
  EXPECT_THROW(value.slice(0, 15), std::bad_alloc);
}

TEST(OpaqueValueTest, BitcastOutOfBounds)
{
  auto value = OpaqueValue::from<int>(42);

  EXPECT_THROW(value.bitcast<int>(1), std::bad_alloc);
  EXPECT_THROW(value.bitcast<double>(0), std::bad_alloc);
}

TEST(OpaqueValueTest, LargeAllocation)
{
  size_t large_size = 1024;
  auto value = OpaqueValue::alloc(large_size, [large_size](char* data) {
    for (size_t i = 0; i < large_size; ++i) {
      data[i] = static_cast<char>(i % 256);
    }
  });

  EXPECT_EQ(value.size(), large_size);
  const char* data = value.data();
  for (size_t i = 0; i < large_size; ++i) {
    EXPECT_EQ(data[i], static_cast<char>(i % 256));
  }
}

TEST(OpaqueValueTest, SmallAllocation)
{
  size_t small_size = sizeof(uintptr_t);
  auto value = OpaqueValue::alloc(small_size, [small_size](char* data) {
    for (size_t i = 0; i < small_size; ++i) {
      data[i] = static_cast<char>(i);
    }
  });

  EXPECT_EQ(value.size(), small_size);
  const char* data = value.data();
  for (size_t i = 0; i < small_size; ++i) {
    EXPECT_EQ(data[i], static_cast<char>(i));
  }
}

TEST(OpaqueValueTest, CopySemanticsSmall)
{
  auto original = OpaqueValue::alloc(1);
  auto copy = OpaqueValue(original);

  // These should always be stored inline.
  EXPECT_NE(original.data(), copy.data());
  EXPECT_TRUE(original == copy);
}

TEST(OpaqueValueTest, CopySemanticsLarge)
{
  auto original = OpaqueValue::alloc(10, [](char* data) {
    for (int i = 0; i < 10; ++i) {
      data[i] = static_cast<char>(i);
    }
  });
  auto copy = OpaqueValue(original);
  EXPECT_EQ(original.data(), copy.data());
  EXPECT_TRUE(original == copy);

  auto slice1 = copy.slice(2, 4);
  auto slice2 = copy.slice(2, 4);

  // Both slices should reference the same underlying data.
  EXPECT_EQ(slice1.data(), slice2.data());
  EXPECT_TRUE(slice1 == slice2);
}

TEST(OpaqueValueTest, ConcatenationWithEmpty)
{
  auto empty = OpaqueValue::alloc(0);
  auto value = OpaqueValue::from(42);

  auto result1 = empty + value;
  auto result2 = value + empty;

  EXPECT_EQ(result1.size(), sizeof(int));
  EXPECT_EQ(result2.size(), sizeof(int));
  EXPECT_EQ(result1.bitcast<int>(), 42);
  EXPECT_EQ(result2.bitcast<int>(), 42);
}

TEST(OpaqueValueTest, ComplexTypeCombinations)
{
  auto int_val = OpaqueValue::from(42);
  auto double_val = OpaqueValue::from(std::numbers::pi);
  auto string_val = OpaqueValue::string("test", 8);

  auto combined = int_val + double_val + string_val;

  EXPECT_EQ(combined.size(), sizeof(int) + sizeof(double) + 8);
  EXPECT_EQ(combined.bitcast<int>(0), 42);

  auto double_slice = combined.slice(sizeof(int), sizeof(double));
  EXPECT_DOUBLE_EQ(double_slice.bitcast<double>(), std::numbers::pi);

  auto string_slice = combined.slice(sizeof(int) + sizeof(double), 8);
  EXPECT_STREQ(string_slice.data(), "test");
}

} // namespace bpftrace::util::test::opaque
