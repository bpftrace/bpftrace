#include <functional>
#include <map>
#include <span>
#include <string>
#include <vector>

#include "async/functions.h"
#include "data/data_source_native_object.h"
#include "gtest/gtest.h"

namespace bpftrace::test::async_functions {

using async::Functions;

static std::vector<int> callback_values;
extern "C" void callback(int value)
{
  callback_values.push_back(value);
}

class AsyncFunctionsTest : public ::testing::Test {
protected:
  AsyncFunctionsTest()
      : object_data(reinterpret_cast<const char *>(native_object),
                    sizeof(native_object)),
        external_functions(
            { { "callback", reinterpret_cast<void *>(callback) } }){};

  void SetUp() override
  {
    callback_values.clear();
  }

  std::span<const char> object_data;
  std::map<std::string, void *> external_functions;
};

TEST_F(AsyncFunctionsTest, LoadNativeObject)
{
  auto functions = Functions::load(object_data, external_functions);
  ASSERT_TRUE(bool(functions)) << functions.takeError();

  // Should not fail something that isn't there.
  using callback_func = void (*)(int);
  auto func_result = functions->function<callback_func>(
      "non_existent_function");
  EXPECT_FALSE(bool(func_result)) << "Should fail to get non-existent function";

  // Should be able to load the callback.
  func_result = functions->function<callback_func>("call_callback");
  ASSERT_TRUE(bool(func_result)) << func_result.takeError();

  // Call with zero.
  auto call_callback = *func_result;
  call_callback(0);
  EXPECT_TRUE(callback_values.empty())
      << "No callback values should be recorded";

  // Call with one.
  call_callback(1);
  ASSERT_EQ(callback_values.size(), 1) << "Should have one callback value";
  EXPECT_EQ(callback_values[0], 0) << "First callback value should be 0";

  // Call with three.
  call_callback(3);
  ASSERT_EQ(callback_values.size(), 4) << "Should have one callback value";
  EXPECT_EQ(callback_values[0], 0) << "First callback value should be 0";
  EXPECT_EQ(callback_values[1], 0) << "Second callback value should be 0";
  EXPECT_EQ(callback_values[2], 1) << "Third callback value should be 1";
  EXPECT_EQ(callback_values[3], 2) << "Fourth callback value should be 2";
}

TEST_F(AsyncFunctionsTest, LoadWithUnresolvedFunctions)
{
  auto functions_result = Functions::load(object_data, {});
  EXPECT_FALSE(bool(functions_result))
      << "Load should fail with unresolved functions";
}

TEST_F(AsyncFunctionsTest, LoadWithInvalidObjectData)
{
  std::vector<char> invalid_data = { 'i', 'n', 'v', 'a', 'l', 'i', 'd' };
  std::span<const char> object_data(invalid_data.data(), invalid_data.size());
  auto functions_result = Functions::load(invalid_data, external_functions);
  EXPECT_FALSE(bool(functions_result))
      << "Load should fail with invalid object data";
}

} // namespace bpftrace::test::async_functions
