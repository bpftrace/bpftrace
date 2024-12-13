#include "functions.h"

#include <sstream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "struct.h"

namespace bpftrace::test::function_registry {

using ::testing::Property;
using ::testing::StrEq;
using ::testing::Throws;

class TestFunctionRegistryPopulated : public ::testing::Test {
protected:
  TestFunctionRegistryPopulated()
  {
    unique_no_args_ = reg_.add(
        Function::Origin::Builtin, "unique_no_args", CreateNone(), {});
    unique_int8_ = reg_.add(Function::Origin::Builtin,
                            "unique_int8",
                            CreateNone(),
                            {
                                Param{ "a", CreateInt8() },
                            });
    unique_int16_ = reg_.add(Function::Origin::Builtin,
                             "unique_int16",
                             CreateNone(),
                             {
                                 Param{ "a", CreateInt16() },
                             });
    unique_int32_ = reg_.add(Function::Origin::Builtin,
                             "unique_int32",
                             CreateNone(),
                             {
                                 Param{ "a", CreateInt32() },
                             });
    unique_int64_ = reg_.add(Function::Origin::Builtin,
                             "unique_int64",
                             CreateNone(),
                             {
                                 Param{ "a", CreateInt64() },
                             });
    unique_uint8_ = reg_.add(Function::Origin::Builtin,
                             "unique_uint8",
                             CreateNone(),
                             {
                                 Param{ "a", CreateUInt8() },
                             });
    unique_uint16_ = reg_.add(Function::Origin::Builtin,
                              "unique_uint16",
                              CreateNone(),
                              {
                                  Param{ "a", CreateUInt16() },
                              });
    unique_uint32_ = reg_.add(Function::Origin::Builtin,
                              "unique_uint32",
                              CreateNone(),
                              {
                                  Param{ "a", CreateUInt32() },
                              });
    unique_uint64_ = reg_.add(Function::Origin::Builtin,
                              "unique_uint64",
                              CreateNone(),
                              {
                                  Param{ "a", CreateUInt64() },
                              });
    unique_string_ = reg_.add(Function::Origin::Builtin,
                              "unique_string",
                              CreateNone(),
                              {
                                  Param{ "a", CreateString(32) },
                              });
    unique_tuple_ = reg_.add(
        Function::Origin::Builtin,
        "unique_tuple",
        CreateNone(),
        {
            Param{ "a",
                   CreateTuple(structs_.AddTuple(
                       { CreateInt32(), CreateString(64) })) },
        });

    auto unique_struct_arg = structs_.Add("unique_struct_arg", 8).lock();
    unique_struct_arg->AddField("x", CreateInt64(), 0);
    unique_struct_ = reg_.add(
        Function::Origin::Builtin,
        "unique_struct",
        CreateNone(),
        {
            Param{ "a", CreateRecord("unique_struct_arg", unique_struct_arg) },
        });

    takes_c_string_ = reg_.add(Function::Origin::Builtin,
                               "takes_c_string",
                               CreateNone(),
                               {
                                   Param{ "a", CreatePointer(CreateInt8()) },
                               });

    overloaded_origin_b_s_builtin_ = reg_.add(
        Function::Origin::Builtin, "overloaded_origin_b_s", CreateNone(), {});
    overloaded_origin_b_s_script_ = reg_.add(
        Function::Origin::Script, "overloaded_origin_b_s", CreateNone(), {});

    overloaded_origin_b_e_builtin_ = reg_.add(
        Function::Origin::Builtin, "overloaded_origin_b_e", CreateNone(), {});
    overloaded_origin_b_e_external_ = reg_.add(
        Function::Origin::External, "overloaded_origin_b_e", CreateNone(), {});
  }

  FunctionRegistry reg_;
  StructManager structs_;
  const Function *unique_no_args_ = nullptr;
  const Function *unique_int8_ = nullptr;
  const Function *unique_int16_ = nullptr;
  const Function *unique_int32_ = nullptr;
  const Function *unique_int64_ = nullptr;
  const Function *unique_uint8_ = nullptr;
  const Function *unique_uint16_ = nullptr;
  const Function *unique_uint32_ = nullptr;
  const Function *unique_uint64_ = nullptr;
  const Function *unique_string_ = nullptr;
  const Function *unique_tuple_ = nullptr;
  const Function *unique_struct_ = nullptr;
  const Function *takes_c_string_ = nullptr;
  const Function *overloaded_origin_b_s_builtin_ = nullptr;
  const Function *overloaded_origin_b_s_script_ = nullptr;
  const Function *overloaded_origin_b_e_builtin_ = nullptr;
  const Function *overloaded_origin_b_e_external_ = nullptr;

  void test(const std::string &func_name,
            const std::vector<SizedType> &arg_types,
            const Function *expected_result);
  void test(const std::string &func_name,
            const std::vector<SizedType> &arg_types,
            std::string_view expected_error);
};

void TestFunctionRegistryPopulated::test(
    const std::string &func_name,
    const std::vector<SizedType> &arg_types,
    const Function *expected_result)
{
  std::stringstream out;
  EXPECT_EQ(expected_result, reg_.get("", func_name, arg_types, out));
  EXPECT_EQ("", out.str());
}

void TestFunctionRegistryPopulated::test(
    const std::string &func_name,
    const std::vector<SizedType> &arg_types,
    std::string_view expected_error)
{
  std::stringstream out;
  EXPECT_EQ(nullptr, reg_.get("", func_name, arg_types, out));

  if (expected_error[0] == '\n')
    expected_error.remove_prefix(1);
  EXPECT_EQ(expected_error, out.str());
}

TEST_F(TestFunctionRegistryPopulated, does_not_exist)
{
  test("does_not_exist", {}, R"(
ERROR: Function not found: 'does_not_exist'
)");
}

TEST_F(TestFunctionRegistryPopulated, unique_wrong_args)
{
  test("unique_int32", { CreateString(32) }, R"(
ERROR: Cannot call function 'unique_int32' using argument types: (string[32])
HINT: Candidate function:
  unique_int32(int32)
)");
  test("unique_int32", { CreateInt32(), CreateInt32() }, R"(
ERROR: Cannot call function 'unique_int32' using argument types: (int32, int32)
HINT: Candidate function:
  unique_int32(int32)
)");
}

TEST_F(TestFunctionRegistryPopulated, unique_exact_args)
{
  test("unique_no_args", {}, unique_no_args_);
}

TEST_F(TestFunctionRegistryPopulated, unique_integers)
{
  // This test goes through every combination of [u]intX -> [u]intY

  // Include one hardcoded test so we can see clearly what the full error
  // messages look like. This acts as a sanity-check for the generated error
  // messages below.
  test("unique_int8", { CreateInt16() }, R"(
ERROR: Cannot call function 'unique_int8' using argument types: (int16)
HINT: Candidate function:
  unique_int8(int8)
)");

  // columns represent the type of the parameter being passed in, in order:
  // int8, int16, int32, int64,    uint8, uint16, uint32, uint64
  // clang-format off
  const std::vector<std::vector<int>> expected = {
    { 1, 0, 0, 0,    0, 0, 0, 0 }, // to int8
    { 1, 1, 0, 0,    1, 0, 0, 0 }, // to int16
    { 1, 1, 1, 0,    1, 1, 0, 0 }, // to int32
    { 1, 1, 1, 1,    1, 1, 1, 0 }, // to int64

    { 0, 0, 0, 0,    1, 0, 0, 0 }, // to uint8
    { 0, 0, 0, 0,    1, 1, 0, 0 }, // to uint16
    { 0, 0, 0, 0,    1, 1, 1, 0 }, // to uint32
    { 0, 0, 0, 0,    1, 1, 1, 1 }, // to uint64
  };
  // clang-format on
  const std::vector<std::pair<std::string, const Function *>> to = {
    { "int8", unique_int8_ },     { "int16", unique_int16_ },
    { "int32", unique_int32_ },   { "int64", unique_int64_ },
    { "uint8", unique_uint8_ },   { "uint16", unique_uint16_ },
    { "uint32", unique_uint32_ }, { "uint64", unique_uint64_ },
  };
  const std::vector<std::pair<std::string, SizedType>> from = {
    { "int8", CreateInt8() },     { "int16", CreateInt16() },
    { "int32", CreateInt32() },   { "int64", CreateInt64() },
    { "uint8", CreateUInt8() },   { "uint16", CreateUInt16() },
    { "uint32", CreateUInt32() }, { "uint64", CreateUInt64() },
  };

  for (size_t i = 0; i < to.size(); i++) {
    for (size_t j = 0; j < from.size(); j++) {
      std::string func_name = "unique_" + to[i].first;

      if (expected[i][j]) {
        // valid
        test(func_name, { from[j].second }, to[i].second);
      } else {
        // invalid
        std::string expected_error = R"(
ERROR: Cannot call function ')" + func_name +
                                     "' using argument types: (" +
                                     from[j].first + R"()
HINT: Candidate function:
  )" + func_name + "(" + to[i].first +
                                     R"()
)";
        test(func_name, { from[j].second }, expected_error);
      }
    }
  }
}

TEST_F(TestFunctionRegistryPopulated, unique_string)
{
  test("unique_string", { CreateString(10) }, unique_string_);
  test("unique_string", { CreateString(32) }, unique_string_);
  test("unique_string", { CreateString(64) }, unique_string_);
}

TEST_F(TestFunctionRegistryPopulated, unique_tuple)
{
  auto tuple1 = CreateTuple(
      structs_.AddTuple({ CreateInt16(), CreateString(64) }));
  auto tuple2 = CreateTuple(
      structs_.AddTuple({ CreateInt32(), CreateString(64) }));
  auto tuple3 = CreateTuple(
      structs_.AddTuple({ CreateInt64(), CreateString(64) }));

  test("unique_tuple", { tuple1 }, unique_tuple_);
  test("unique_tuple", { tuple2 }, unique_tuple_);

  test("unique_tuple", { tuple3 }, R"(
ERROR: Cannot call function 'unique_tuple' using argument types: ((int64,string[64]))
HINT: Candidate function:
  unique_tuple((int32,string[64]))
)");

  // Can't pass deconstructed tuple fields as multiple arguments
  test("unique_tuple", { CreateInt32(), CreateString(64) }, R"(
ERROR: Cannot call function 'unique_tuple' using argument types: (int32, string[64])
HINT: Candidate function:
  unique_tuple((int32,string[64]))
)");
}

TEST_F(TestFunctionRegistryPopulated, unique_struct)
{
  auto exact_struct = structs_.Lookup("unique_struct_arg");

  auto compatible_struct =
      structs_.Add("same_layout_as_unique_struct_arg", 8).lock();
  compatible_struct->AddField("x", CreateInt64(), 0);

  auto different_struct =
      structs_.Add("different_layout_to_unique_struct_arg", 2).lock();
  different_struct->AddField("a", CreateInt8(), 0);
  different_struct->AddField("b", CreateInt8(), 0);

  test("unique_struct",
       { CreateRecord("unique_struct_arg", exact_struct) },
       unique_struct_);

  test("unique_struct",
       { CreateRecord("same_layout_as_unique_struct_arg", compatible_struct) },
       R"(
ERROR: Cannot call function 'unique_struct' using argument types: (same_layout_as_unique_struct_arg)
HINT: Candidate function:
  unique_struct(unique_struct_arg)
)");

  test("unique_struct",
       { CreateRecord("different_layout_to_unique_struct_arg",
                      different_struct) },
       R"(
ERROR: Cannot call function 'unique_struct' using argument types: (different_layout_to_unique_struct_arg)
HINT: Candidate function:
  unique_struct(unique_struct_arg)
)");
}

TEST_F(TestFunctionRegistryPopulated, string_to_pointer)
{
  test("takes_c_string", { CreateString(64) }, takes_c_string_);
}

TEST_F(TestFunctionRegistryPopulated, overloaded_origin)
{
  test("overloaded_origin_b_s", {}, overloaded_origin_b_s_script_);
  test("overloaded_origin_b_e", {}, overloaded_origin_b_e_external_);
}

TEST(TestFunctionRegistry, add_namespaced)
{
  std::stringstream out; // To suppress (expected) errors from unit test output
  FunctionRegistry reg;
  auto *foo = reg.add(Function::Origin::Script, "ns", "foo", CreateNone(), {});
  EXPECT_EQ(nullptr, reg.get("", "foo", {}, out));
  EXPECT_EQ(foo, reg.get("ns", "foo", {}, out));
}

TEST(TestFunctionRegistry, add_duplicate_of_builtin)
{
  FunctionRegistry reg;
  EXPECT_NE(nullptr,
            reg.add(Function::Origin::Builtin, "foo", CreateNone(), {}));
  EXPECT_NE(nullptr,
            reg.add(Function::Origin::Script, "foo", CreateNone(), {}));
}

TEST(TestFunctionRegistry, add_duplicate)
{
  FunctionRegistry reg;
  EXPECT_NE(nullptr,
            reg.add(Function::Origin::Script, "foo", CreateNone(), {}));
  EXPECT_EQ(nullptr,
            reg.add(Function::Origin::Script, "foo", CreateNone(), {}));
}

} // namespace bpftrace::test::function_registry
