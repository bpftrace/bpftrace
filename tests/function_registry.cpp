#include "functions.h"

#include "gtest/gtest.h"

#include "struct.h"

namespace bpftrace::test::function_registry {

class TestFunctionRegistry : public ::testing::Test {
protected:
  TestFunctionRegistry()
  {
    unique_void_ = &reg_.add(Function::Origin::Builtin,
                             "unique_void",
                             CreateVoid(),
                             {
                                 Param{ "a", CreateVoid() },
                             });
    unique_int8_ = &reg_.add(Function::Origin::Builtin,
                             "unique_int8",
                             CreateVoid(),
                             {
                                 Param{ "a", CreateInt8() },
                             });
    unique_int16_ = &reg_.add(Function::Origin::Builtin,
                              "unique_int16",
                              CreateVoid(),
                              {
                                  Param{ "a", CreateInt16() },
                              });
    unique_int32_ = &reg_.add(Function::Origin::Builtin,
                              "unique_int32",
                              CreateVoid(),
                              {
                                  Param{ "a", CreateInt32() },
                              });
    unique_int64_ = &reg_.add(Function::Origin::Builtin,
                              "unique_int64",
                              CreateVoid(),
                              {
                                  Param{ "a", CreateInt64() },
                              });
    unique_uint8_ = &reg_.add(Function::Origin::Builtin,
                              "unique_uint8",
                              CreateVoid(),
                              {
                                  Param{ "a", CreateUInt8() },
                              });
    unique_uint16_ = &reg_.add(Function::Origin::Builtin,
                               "unique_uint16",
                               CreateVoid(),
                               {
                                   Param{ "a", CreateUInt16() },
                               });
    unique_uint32_ = &reg_.add(Function::Origin::Builtin,
                               "unique_uint32",
                               CreateVoid(),
                               {
                                   Param{ "a", CreateUInt32() },
                               });
    unique_uint64_ = &reg_.add(Function::Origin::Builtin,
                               "unique_uint64",
                               CreateVoid(),
                               {
                                   Param{ "a", CreateUInt64() },
                               });
    unique_string_ = &reg_.add(Function::Origin::Builtin,
                               "unique_string",
                               CreateVoid(),
                               {
                                   Param{ "a", CreateString(64) }, // TODO max
                                                                   // strlen
                               });
    unique_tuple_ = &reg_.add(
        Function::Origin::Builtin,
        "unique_tuple",
        CreateVoid(),
        {
            Param{ "a",
                   CreateTuple(structs_.AddTuple(
                       { CreateInt32(), CreateString(64) })) },
        });

    auto unique_struct_arg = structs_.Add("unique_struct_arg", 8).lock();
    unique_struct_arg->AddField("x", CreateInt64(), 0);
    unique_struct_ = &reg_.add(
        Function::Origin::Builtin,
        "unique_struct",
        CreateVoid(),
        {
            Param{ "a", CreateRecord("unique_struct_arg", unique_struct_arg) },
        });

    overloaded_int_int16_ = &reg_.add(Function::Origin::Builtin,
                                      "overloaded_int",
                                      CreateVoid(),
                                      {
                                          Param{ "a", CreateInt16() },
                                      });
    overloaded_int_int32_ = &reg_.add(Function::Origin::Builtin,
                                      "overloaded_int",
                                      CreateVoid(),
                                      {
                                          Param{ "a", CreateInt32() },
                                      });
    overloaded_int_int64_ = &reg_.add(Function::Origin::Builtin,
                                      "overloaded_int",
                                      CreateVoid(),
                                      {
                                          Param{ "a", CreateInt64() },
                                      });
    overloaded_different_types_int32_ = &reg_.add(Function::Origin::Builtin,
                                                  "overloaded_different_types",
                                                  CreateVoid(),
                                                  {
                                                      Param{ "a",
                                                             CreateInt32() },
                                                  });
    overloaded_different_types_string_ = &reg_.add(
        Function::Origin::Builtin,
        "overloaded_different_types",
        CreateVoid(),
        {
            Param{ "a", CreateString(64) },
        });

    overloaded_multiple_args_64_64_ = &reg_.add(Function::Origin::Builtin,
                                                "overloaded_multiple_args",
                                                CreateVoid(),
                                                {
                                                    Param{ "a", CreateInt64() },
                                                    Param{ "b", CreateInt64() },
                                                });
    overloaded_multiple_args_64_32_ = &reg_.add(Function::Origin::Builtin,
                                                "overloaded_multiple_args",
                                                CreateVoid(),
                                                {
                                                    Param{ "a", CreateInt64() },
                                                    Param{ "b", CreateInt32() },
                                                });
    overloaded_multiple_args_32_64_ = &reg_.add(Function::Origin::Builtin,
                                                "overloaded_multiple_args",
                                                CreateVoid(),
                                                {
                                                    Param{ "a", CreateInt32() },
                                                    Param{ "b", CreateInt64() },
                                                });
    takes_c_string_ = &reg_.add(Function::Origin::Builtin,
                                "takes_c_string",
                                CreateVoid(),
                                {
                                    Param{ "a", CreatePointer(CreateInt8()) },
                                });

    // TODO multiple arguments, exact, wrong, implicit casting
  }

  FunctionRegistry reg_;
  StructManager structs_;
  Function *unique_void_ = nullptr;
  Function *unique_int8_ = nullptr;
  Function *unique_int16_ = nullptr;
  Function *unique_int32_ = nullptr;
  Function *unique_int64_ = nullptr;
  Function *unique_uint8_ = nullptr;
  Function *unique_uint16_ = nullptr;
  Function *unique_uint32_ = nullptr;
  Function *unique_uint64_ = nullptr;
  Function *unique_string_ = nullptr;
  Function *unique_tuple_ = nullptr;
  Function *unique_struct_ = nullptr;
  Function *overloaded_int_int16_ = nullptr;
  Function *overloaded_int_int32_ = nullptr;
  Function *overloaded_int_int64_ = nullptr;
  Function *overloaded_different_types_int32_ = nullptr;
  Function *overloaded_different_types_string_ = nullptr;
  Function *overloaded_multiple_args_64_64_ = nullptr;
  Function *overloaded_multiple_args_64_32_ = nullptr;
  Function *overloaded_multiple_args_32_64_ = nullptr;
  Function *takes_c_string_ = nullptr;
};

TEST_F(TestFunctionRegistry, does_not_exist)
{
  EXPECT_EQ(reg_.get("does_not_exist", { CreateVoid() }), nullptr);
}

TEST_F(TestFunctionRegistry, unique_wrong_args)
{
  EXPECT_EQ(reg_.get("unique_int32", { CreateString(32) }), nullptr);
  EXPECT_EQ(reg_.get("unique_int32", { CreateInt32(), CreateInt32() }),
            nullptr);
}

TEST_F(TestFunctionRegistry, unique_exact_args)
{
  EXPECT_EQ(reg_.get("unique_void", { CreateVoid() }), unique_void_);
}

TEST_F(TestFunctionRegistry, unique_int8)
{
  EXPECT_EQ(reg_.get("unique_int8", { CreateInt8() }), unique_int8_);
  EXPECT_EQ(reg_.get("unique_int8", { CreateInt16() }), nullptr);
  EXPECT_EQ(reg_.get("unique_int8", { CreateInt32() }), nullptr);
  EXPECT_EQ(reg_.get("unique_int8", { CreateInt64() }), nullptr);

  EXPECT_EQ(reg_.get("unique_int8", { CreateUInt8() }), nullptr);
  EXPECT_EQ(reg_.get("unique_int8", { CreateUInt16() }), nullptr);
  EXPECT_EQ(reg_.get("unique_int8", { CreateUInt32() }), nullptr);
  EXPECT_EQ(reg_.get("unique_int8", { CreateUInt64() }), nullptr);
}

TEST_F(TestFunctionRegistry, unique_int16)
{
  EXPECT_EQ(reg_.get("unique_int16", { CreateInt8() }), unique_int16_);
  EXPECT_EQ(reg_.get("unique_int16", { CreateInt16() }), unique_int16_);
  EXPECT_EQ(reg_.get("unique_int16", { CreateInt32() }), nullptr);
  EXPECT_EQ(reg_.get("unique_int16", { CreateInt64() }), nullptr);

  EXPECT_EQ(reg_.get("unique_int16", { CreateUInt8() }), unique_int16_);
  EXPECT_EQ(reg_.get("unique_int16", { CreateUInt16() }), nullptr);
  EXPECT_EQ(reg_.get("unique_int16", { CreateUInt32() }), nullptr);
  EXPECT_EQ(reg_.get("unique_int16", { CreateUInt64() }), nullptr);
}

TEST_F(TestFunctionRegistry, unique_int32)
{
  EXPECT_EQ(reg_.get("unique_int32", { CreateInt8() }), unique_int32_);
  EXPECT_EQ(reg_.get("unique_int32", { CreateInt16() }), unique_int32_);
  EXPECT_EQ(reg_.get("unique_int32", { CreateInt32() }), unique_int32_);
  EXPECT_EQ(reg_.get("unique_int32", { CreateInt64() }), nullptr);

  EXPECT_EQ(reg_.get("unique_int32", { CreateUInt8() }), unique_int32_);
  EXPECT_EQ(reg_.get("unique_int32", { CreateUInt16() }), unique_int32_);
  EXPECT_EQ(reg_.get("unique_int32", { CreateUInt32() }), nullptr);
  EXPECT_EQ(reg_.get("unique_int32", { CreateUInt64() }), nullptr);
}

TEST_F(TestFunctionRegistry, unique_int64)
{
  EXPECT_EQ(reg_.get("unique_int64", { CreateInt8() }), unique_int64_);
  EXPECT_EQ(reg_.get("unique_int64", { CreateInt16() }), unique_int64_);
  EXPECT_EQ(reg_.get("unique_int64", { CreateInt32() }), unique_int64_);
  EXPECT_EQ(reg_.get("unique_int64", { CreateInt64() }), unique_int64_);

  EXPECT_EQ(reg_.get("unique_int64", { CreateUInt8() }), unique_int64_);
  EXPECT_EQ(reg_.get("unique_int64", { CreateUInt16() }), unique_int64_);
  EXPECT_EQ(reg_.get("unique_int64", { CreateUInt32() }), unique_int64_);
  EXPECT_EQ(reg_.get("unique_int64", { CreateUInt64() }), nullptr);
}

TEST_F(TestFunctionRegistry, unique_uint8)
{
  EXPECT_EQ(reg_.get("unique_uint8", { CreateUInt8() }), unique_uint8_);
  EXPECT_EQ(reg_.get("unique_uint8", { CreateUInt16() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint8", { CreateUInt32() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint8", { CreateUInt64() }), nullptr);

  EXPECT_EQ(reg_.get("unique_uint8", { CreateInt8() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint8", { CreateInt16() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint8", { CreateInt32() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint8", { CreateInt64() }), nullptr);
}

TEST_F(TestFunctionRegistry, unique_uint16)
{
  EXPECT_EQ(reg_.get("unique_uint16", { CreateUInt8() }), unique_uint16_);
  EXPECT_EQ(reg_.get("unique_uint16", { CreateUInt16() }), unique_uint16_);
  EXPECT_EQ(reg_.get("unique_uint16", { CreateUInt32() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint16", { CreateUInt64() }), nullptr);

  EXPECT_EQ(reg_.get("unique_uint16", { CreateInt8() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint16", { CreateInt16() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint16", { CreateInt32() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint16", { CreateInt64() }), nullptr);
}

TEST_F(TestFunctionRegistry, unique_uint32)
{
  EXPECT_EQ(reg_.get("unique_uint32", { CreateUInt8() }), unique_uint32_);
  EXPECT_EQ(reg_.get("unique_uint32", { CreateUInt16() }), unique_uint32_);
  EXPECT_EQ(reg_.get("unique_uint32", { CreateUInt32() }), unique_uint32_);
  EXPECT_EQ(reg_.get("unique_uint32", { CreateUInt64() }), nullptr);

  EXPECT_EQ(reg_.get("unique_uint32", { CreateInt8() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint32", { CreateInt16() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint32", { CreateInt32() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint32", { CreateInt64() }), nullptr);
}

TEST_F(TestFunctionRegistry, unique_uint64)
{
  EXPECT_EQ(reg_.get("unique_uint64", { CreateUInt8() }), unique_uint64_);
  EXPECT_EQ(reg_.get("unique_uint64", { CreateUInt16() }), unique_uint64_);
  EXPECT_EQ(reg_.get("unique_uint64", { CreateUInt32() }), unique_uint64_);
  EXPECT_EQ(reg_.get("unique_uint64", { CreateUInt64() }), unique_uint64_);

  EXPECT_EQ(reg_.get("unique_uint64", { CreateInt8() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint64", { CreateInt16() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint64", { CreateInt32() }), nullptr);
  EXPECT_EQ(reg_.get("unique_uint64", { CreateInt64() }), nullptr);
}

TEST_F(TestFunctionRegistry, unique_string)
{
  EXPECT_EQ(reg_.get("unique_string", { CreateString(10) }), unique_string_);
  EXPECT_EQ(reg_.get("unique_string", { CreateString(32) }), unique_string_);
  EXPECT_EQ(reg_.get("unique_string", { CreateString(64) }), unique_string_);
}

TEST_F(TestFunctionRegistry, unique_tuple)
{
  auto tuple1 = CreateTuple(
      structs_.AddTuple({ CreateInt16(), CreateString(64) }));
  auto tuple2 = CreateTuple(
      structs_.AddTuple({ CreateInt32(), CreateString(64) }));
  auto tuple3 = CreateTuple(
      structs_.AddTuple({ CreateInt64(), CreateString(64) }));
  EXPECT_EQ(reg_.get("unique_tuple", { tuple1 }), unique_tuple_);
  EXPECT_EQ(reg_.get("unique_tuple", { tuple2 }), unique_tuple_);
  EXPECT_EQ(reg_.get("unique_tuple", { tuple3 }), nullptr);
}

TEST_F(TestFunctionRegistry, unique_struct)
{
  auto exact_struct = structs_.Lookup("unique_struct_arg");

  auto compatible_struct =
      structs_.Add("same_layout_as_unique_struct_arg", 8).lock();
  compatible_struct->AddField("x", CreateInt64(), 0);

  auto different_struct =
      structs_.Add("different_layout_to_unique_struct_arg", 2).lock();
  different_struct->AddField("a", CreateInt8(), 0);
  different_struct->AddField("b", CreateInt8(), 0);

  EXPECT_EQ(reg_.get("unique_struct",
                     { CreateRecord("unique_struct_arg", exact_struct) }),
            unique_struct_);
  EXPECT_EQ(reg_.get("unique_struct",
                     { CreateRecord("same_layout_as_unique_struct_arg",
                                    compatible_struct) }),
            nullptr);
  EXPECT_EQ(reg_.get("unique_struct",
                     { CreateRecord("different_layout_to_unique_struct_arg",
                                    different_struct) }),
            nullptr);
}

TEST_F(TestFunctionRegistry, overloaded_int)
{
  // TODO: This first case is only working due to a coincidence. We aren't doing
  // any kind of overload rankings. It will break with user-defined functions.
  EXPECT_EQ(reg_.get("overloaded_int", { CreateInt8() }),
            overloaded_int_int16_);
  EXPECT_EQ(reg_.get("overloaded_int", { CreateInt16() }),
            overloaded_int_int16_);
  EXPECT_EQ(reg_.get("overloaded_int", { CreateInt32() }),
            overloaded_int_int32_);
  EXPECT_EQ(reg_.get("overloaded_int", { CreateInt64() }),
            overloaded_int_int64_);

  EXPECT_EQ(reg_.get("overloaded_int", { CreateUInt8() }),
            overloaded_int_int16_);
  EXPECT_EQ(reg_.get("overloaded_int", { CreateUInt16() }),
            overloaded_int_int32_);
  EXPECT_EQ(reg_.get("overloaded_int", { CreateUInt32() }),
            overloaded_int_int64_);
  EXPECT_EQ(reg_.get("overloaded_int", { CreateUInt64() }), nullptr);
}

TEST_F(TestFunctionRegistry, overloaded_different_types)
{
  EXPECT_EQ(reg_.get("overloaded_different_types", { CreateInt16() }),
            overloaded_different_types_int32_);
  EXPECT_EQ(reg_.get("overloaded_different_types", { CreateInt32() }),
            overloaded_different_types_int32_);
  EXPECT_EQ(reg_.get("overloaded_different_types", { CreateInt64() }), nullptr);

  EXPECT_EQ(reg_.get("overloaded_different_types", { CreateString(10) }),
            overloaded_different_types_string_);
  EXPECT_EQ(reg_.get("overloaded_different_types", { CreateString(64) }),
            overloaded_different_types_string_);

  EXPECT_EQ(reg_.get("overloaded_different_types", { CreateVoid() }), nullptr);
}

TEST_F(TestFunctionRegistry, overloaded_multiple_args)
{
  GTEST_SKIP() << "Overload resolution is incomplete";

  // Exact matches
  EXPECT_EQ(reg_.get("overloaded_multiple_args",
                     { CreateInt64(), CreateInt64() }),
            overloaded_multiple_args_64_64_);
  EXPECT_EQ(reg_.get("overloaded_multiple_args",
                     { CreateInt64(), CreateInt32() }),
            overloaded_multiple_args_64_32_);
  EXPECT_EQ(reg_.get("overloaded_multiple_args",
                     { CreateInt32(), CreateInt64() }),
            overloaded_multiple_args_32_64_);

  // Minimal casting
  EXPECT_EQ(reg_.get("overloaded_multiple_args",
                     { CreateInt16(), CreateInt64() }),
            overloaded_multiple_args_32_64_);
  EXPECT_EQ(reg_.get("overloaded_multiple_args",
                     { CreateInt64(), CreateInt16() }),
            overloaded_multiple_args_64_32_);
  EXPECT_EQ(reg_.get("overloaded_multiple_args",
                     { CreateInt16(), CreateInt32() }),
            overloaded_multiple_args_64_32_);
  EXPECT_EQ(reg_.get("overloaded_multiple_args",
                     { CreateInt32(), CreateInt16() }),
            overloaded_multiple_args_32_64_);

  // No best unique candidate
  EXPECT_EQ(reg_.get("overloaded_multiple_args",
                     { CreateInt32(), CreateInt32() }),
            nullptr);
  EXPECT_EQ(reg_.get("overloaded_multiple_args",
                     { CreateInt16(), CreateInt16() }),
            nullptr);
}

TEST_F(TestFunctionRegistry, string_to_pointer)
{
  EXPECT_EQ(reg_.get("takes_c_string", { CreateString(64) }), takes_c_string_);
}

} // namespace bpftrace::test::function_registry
