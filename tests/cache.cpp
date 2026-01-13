#include <filesystem>
#include <gtest/gtest.h>
#include <string>

#include "util/cache.h"
#include "util/temp.h"

namespace bpftrace::util::test {

static size_t count_files_in_dir(const std::filesystem::path &dir)
{
  size_t count = 0;
  for (const auto &entry : std::filesystem::directory_iterator(dir)) {
    if (std::filesystem::is_regular_file(entry))
      count++;
  }
  return count;
}

TEST(CacheTest, cache_hit_string_input)
{
  auto cache_dir = TempDir::create();
  ASSERT_TRUE(bool(cache_dir));
  auto cache = CacheManager(cache_dir->path());

  std::vector<std::string> keys = { "key1", "key2" };
  std::vector<CacheObject> inputs = { CacheObject("input1"),
                                      CacheObject("input2") };
  int generator_calls = 0;

  auto generator = [&]() -> Result<CacheObject> {
    generator_calls++;
    return CacheObject("generated_output");
  };

  // First call: cache miss.
  auto result1 = cache.lookup(keys, inputs, "dat", generator);
  ASSERT_TRUE(bool(result1));
  ASSERT_EQ(generator_calls, 1);
  ASSERT_EQ(count_files_in_dir(cache_dir->path()), 1);

  ASSERT_EQ(result1->data(), "generated_output");

  // Second call: cache hit.
  auto result2 = cache.lookup(keys, inputs, "dat", generator);
  ASSERT_TRUE(bool(result2));
  ASSERT_EQ(generator_calls, 1); // Generator should not be called again.

  ASSERT_EQ(result2->data(), "generated_output");
}

TEST(CacheTest, cache_hit_file_input)
{
  auto cache_dir = TempDir::create();
  ASSERT_TRUE(bool(cache_dir));
  auto cache = CacheManager(cache_dir->path());

  auto input_file = cache_dir->create_file();
  ASSERT_TRUE(bool(input_file));
  ASSERT_TRUE(bool(input_file->write_all(std::string("file_contents"))));

  std::vector<std::string> keys = { "mykey" };
  std::vector<CacheObject> inputs = { CacheObject(input_file->path()) };
  int generator_calls = 0;

  auto generator = [&]() -> Result<CacheObject> {
    generator_calls++;
    return CacheObject("result_data");
  };

  // First call: cache miss.
  auto result1 = cache.lookup(keys, inputs, "o", generator);
  ASSERT_TRUE(bool(result1));
  ASSERT_EQ(generator_calls, 1);
  ASSERT_EQ(result1->data(), "result_data");

  // Second call: cache hit.
  auto result2 = cache.lookup(keys, inputs, "o", generator);
  ASSERT_TRUE(bool(result2));
  ASSERT_EQ(generator_calls, 1);
}

TEST(CacheTest, different_keys_different_cache)
{
  auto cache_dir = TempDir::create();
  ASSERT_TRUE(bool(cache_dir));
  auto cache = CacheManager(cache_dir->path());

  std::vector<CacheObject> inputs = { CacheObject("same_input") };
  int generator_calls = 0;

  auto generator = [&]() -> Result<CacheObject> {
    generator_calls++;
    return CacheObject("output");
  };

  auto result1 = cache.lookup({ "key1" }, inputs, "dat", generator);
  ASSERT_TRUE(bool(result1));
  ASSERT_EQ(generator_calls, 1);
  ASSERT_EQ(count_files_in_dir(cache_dir->path()), 1);

  auto result2 = cache.lookup({ "key2" }, inputs, "dat", generator);
  ASSERT_TRUE(bool(result2));
  ASSERT_EQ(generator_calls, 2);
  ASSERT_EQ(count_files_in_dir(cache_dir->path()), 2);
}

TEST(CacheTest, different_input_content_different_cache)
{
  auto cache_dir = TempDir::create();
  ASSERT_TRUE(bool(cache_dir));
  auto cache = CacheManager(cache_dir->path());

  auto obj1 = CacheObject("version1");
  std::vector<CacheObject> inputs1 = { std::move(obj1) };
  int generator_calls = 0;

  auto generator = [&]() -> Result<CacheObject> {
    generator_calls++;
    return CacheObject("output");
  };

  auto result1 = cache.lookup({}, inputs1, "o", generator);
  ASSERT_TRUE(bool(result1));
  ASSERT_EQ(generator_calls, 1);

  // Modify the input file.
  auto obj2 = CacheObject("version2");
  std::vector<CacheObject> inputs2 = { std::move(obj2) };

  auto result2 = cache.lookup({}, inputs2, "o", generator);
  ASSERT_TRUE(bool(result2));
  ASSERT_EQ(generator_calls, 2);
  ASSERT_EQ(count_files_in_dir(cache_dir->path()), 2);
}

TEST(CacheTest, generator_returns_file)
{
  auto cache_dir = TempDir::create();
  ASSERT_TRUE(bool(cache_dir));
  auto cache = CacheManager(cache_dir->path());

  auto output_file = cache_dir->create_file();
  ASSERT_TRUE(bool(output_file));
  ASSERT_TRUE(bool(output_file->write_all(std::string("file_output"))));

  int generator_calls = 0;
  auto generator = [&]() -> Result<CacheObject> {
    generator_calls++;
    return CacheObject::from(output_file->path());
  };

  auto result = cache.lookup({}, {}, "bin", generator);
  ASSERT_TRUE(bool(result));
  ASSERT_EQ(generator_calls, 1);
  ASSERT_EQ(result->data(), "file_output");
}

TEST(CacheTest, generator_failure)
{
  auto cache_dir = TempDir::create();
  ASSERT_TRUE(bool(cache_dir));
  auto cache = CacheManager(cache_dir->path());

  bool generator_called = false;
  auto generator = [&]() -> Result<CacheObject> {
    generator_called = true;
    return make_error<SystemError>("failed");
  };

  auto result = cache.lookup({}, {}, "dat", generator);
  ASSERT_FALSE(bool(result));
  ASSERT_TRUE(generator_called);
  ASSERT_EQ(count_files_in_dir(cache_dir->path()), 0);
}

TEST(CacheTest, multiple_inputs_hashed_correctly)
{
  auto cache_dir = TempDir::create();
  ASSERT_TRUE(bool(cache_dir));
  auto cache = CacheManager(cache_dir->path());

  auto file1 = cache_dir->create_file();
  auto file2 = cache_dir->create_file();
  ASSERT_TRUE(bool(file1));
  ASSERT_TRUE(bool(file2));
  ASSERT_TRUE(bool(file1->write_all(std::string("content1"))));
  ASSERT_TRUE(bool(file2->write_all(std::string("content2"))));

  auto obj1 = CacheObject::from(file1->path());
  auto obj2 = CacheObject::from(file2->path());
  ASSERT_TRUE(bool(obj1));
  ASSERT_TRUE(bool(obj2));
  std::vector<CacheObject> inputs = { std::move(*obj1),
                                      std::move(*obj2),
                                      CacheObject("string_input") };
  int generator_calls = 0;

  auto generator = [&]() -> Result<CacheObject> {
    generator_calls++;
    return CacheObject("combined_output");
  };

  auto result1 = cache.lookup({ "key" }, inputs, "dat", generator);
  ASSERT_TRUE(bool(result1));
  ASSERT_EQ(generator_calls, 1);

  auto result2 = cache.lookup({ "key" }, inputs, "dat", generator);
  ASSERT_TRUE(bool(result2));
  ASSERT_EQ(generator_calls, 1); // Should hit cache.
}

TEST(CacheTest, extension_is_appended)
{
  auto cache_dir = TempDir::create();
  ASSERT_TRUE(bool(cache_dir));
  auto cache = CacheManager(cache_dir->path());

  auto generator = []() -> Result<CacheObject> { return CacheObject("data"); };

  auto result = cache.lookup({}, {}, "custom", generator);
  ASSERT_TRUE(bool(result));

  // Verify that a file with .custom extension exists in cache.
  bool found_custom_ext = false;
  for (const auto &entry :
       std::filesystem::directory_iterator(cache_dir->path())) {
    if (entry.path().extension() == ".custom") {
      found_custom_ext = true;
      break;
    }
  }
  ASSERT_TRUE(found_custom_ext);
}

} // namespace bpftrace::util::test
