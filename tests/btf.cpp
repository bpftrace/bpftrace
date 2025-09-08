#include <string>
#include <unordered_set>

#include "btf/btf.h"
#include "btf/helpers.h"
#include "data/data_source_btf.h"
#include "gtest/gtest.h"

namespace bpftrace::test::btf {

using namespace bpftrace::btf;

static std::string to_str(const AnyType &type)
{
  std::stringstream out;
  out << type;
  return out.str();
}

TEST(btf, to_str)
{
  Types btf;
  auto int8 = btf.add<Integer>("int8", 1, 1);
  ASSERT_TRUE(bool(int8));
  EXPECT_EQ(to_str(AnyType(*int8)), "int8");
}

TEST(btf, kernel_types)
{
  auto btf = Types::parse(reinterpret_cast<const char *>(btf_data),
                          sizeof(btf_data));
  ASSERT_TRUE(bool(btf));

  // Want to see all the functions available?
  std::unordered_set<std::string> funcs;
  for (const auto &type : *btf) {
    if (!type.is<btf::Function>()) {
      continue;
    }
    const auto &func = type.as<btf::Function>();
    EXPECT_FALSE(funcs.contains(func.name()));
    funcs.insert(func.name());
  }
  EXPECT_TRUE(!funcs.empty());

  // Let's just look at the variables.
  std::unordered_set<std::string> vars;
  for (const auto &type : *btf) {
    if (!type.is<btf::Var>()) {
      continue;
    }
    const auto &var = type.as<btf::Var>();
    EXPECT_FALSE(vars.contains(var.name()));
    vars.insert(var.name());
  }
  EXPECT_TRUE(!vars.empty());
}

TEST(btf, map_types)
{
  Types btf;
  auto int8 = btf.add<Integer>("int8", 1, 1);
  ASSERT_TRUE(bool(int8));

  auto m = createMap(btf,
                     MapInfo{
                         .map_type = BPF_MAP_TYPE_HASH,
                         .key = *int8,
                         .value = *int8,
                         .nr_elements = 1,
                     });
  ASSERT_TRUE(bool(m));
  EXPECT_EQ(to_str(AnyType(*m)),
            "map{type=1, key_type=int8, value_type=int8, nr_elements=1}");
}

TEST(btf, integer_types)
{
  Types btf;

  auto int8 = btf.add<Integer>("int8", 1, 1);
  auto uint8 = btf.add<Integer>("uint8", 1, 0);
  auto int16 = btf.add<Integer>("int16", 2, 1);
  auto int32 = btf.add<Integer>("int32", 4, 1);
  auto int64 = btf.add<Integer>("int64", 8, 1);
  auto boolean = btf.add<Integer>("int8", 1, 4);

  ASSERT_TRUE(bool(int8));
  ASSERT_TRUE(bool(uint8));
  ASSERT_TRUE(bool(int16));
  ASSERT_TRUE(bool(int32));
  ASSERT_TRUE(bool(int64));
  ASSERT_TRUE(bool(boolean));

  EXPECT_EQ(int8->bytes(), 1);
  EXPECT_EQ(uint8->bytes(), 1);
  EXPECT_EQ(int16->bytes(), 2);
  EXPECT_EQ(int32->bytes(), 4);
  EXPECT_EQ(int64->bytes(), 8);
  EXPECT_EQ(boolean->bytes(), 1);

  EXPECT_FALSE(int8->is_bool());
  EXPECT_TRUE(boolean->is_bool());

  EXPECT_EQ(to_str(AnyType(*int8)), "int8");
  EXPECT_EQ(to_str(AnyType(*uint8)), "uint8");
  EXPECT_EQ(to_str(AnyType(*int16)), "int16");
  EXPECT_EQ(to_str(AnyType(*int32)), "int32");
  EXPECT_EQ(to_str(AnyType(*int64)), "int64");
  EXPECT_EQ(to_str(AnyType(*boolean)), "int8");
}

TEST(btf, pointer_types)
{
  Types btf;
  auto int32 = btf.add<Integer>("int32", 4, 1);
  ASSERT_TRUE(bool(int32));

  auto ptr_int32 = btf.add<Pointer>(AnyType(*int32));
  ASSERT_TRUE(bool(ptr_int32));

  auto element = ptr_int32->element_type();
  ASSERT_TRUE(bool(element));
  EXPECT_TRUE(element->is<Integer>());
  EXPECT_EQ(to_str(*element), "int32");

  auto ptr_ptr_int32 = btf.add<Pointer>(AnyType(*ptr_int32));
  ASSERT_TRUE(bool(ptr_ptr_int32));
}

TEST(btf, array_types)
{
  Types btf;
  auto int32 = btf.add<Integer>("int32", 4, 1);
  auto size_t_type = btf.add<Integer>("size_t", 8, 0);
  ASSERT_TRUE(bool(int32));
  ASSERT_TRUE(bool(size_t_type));

  auto array_int32 = btf.add<Array>(*size_t_type, ValueType(*int32), 10);
  ASSERT_TRUE(bool(array_int32));

  EXPECT_EQ(array_int32->element_count(), 10);

  auto element_type = array_int32->element_type();
  ASSERT_TRUE(bool(element_type));
  EXPECT_TRUE(element_type->is<Integer>());

  auto index_type = array_int32->index_type();
  ASSERT_TRUE(bool(index_type));
  EXPECT_TRUE(index_type->is<Integer>());
}

TEST(btf, struct_types)
{
  Types btf;
  auto int32 = btf.add<Integer>("int32", 4, 1);
  auto int64 = btf.add<Integer>("int64", 8, 1);
  ASSERT_TRUE(bool(int32));
  ASSERT_TRUE(bool(int64));

  std::vector<std::pair<std::string, ValueType>> fields = {
    { "x", ValueType(*int32) },
    { "y", ValueType(*int32) },
    { "z", ValueType(*int64) }
  };

  auto point_struct = btf.add<Struct>("Point", fields);
  ASSERT_TRUE(bool(point_struct));

  EXPECT_EQ(point_struct->name(), "Point");

  auto all_fields = point_struct->fields();
  ASSERT_TRUE(bool(all_fields));
  EXPECT_EQ(all_fields->size(), 3);
  EXPECT_EQ(all_fields->at(0).first, "x");
  EXPECT_EQ(all_fields->at(1).first, "y");
  EXPECT_EQ(all_fields->at(2).first, "z");

  auto x_field = point_struct->field("x");
  ASSERT_TRUE(bool(x_field));
  EXPECT_TRUE(x_field->type.is<Integer>());
}

TEST(btf, union_types)
{
  Types btf;
  auto int32 = btf.add<Integer>("int32", 4, 1);
  auto other_type = btf.add<Integer>("foo", 4, 0);
  ASSERT_TRUE(bool(int32));
  ASSERT_TRUE(bool(other_type));

  std::vector<std::pair<std::string, ValueType>> fields = {
    { "as_int", ValueType(*int32) }, { "as_float", ValueType(*other_type) }
  };

  auto value_union = btf.add<Union>("Value", fields);
  ASSERT_TRUE(bool(value_union));

  EXPECT_EQ(value_union->name(), "Value");

  auto all_fields = value_union->fields();
  ASSERT_TRUE(bool(all_fields));
  EXPECT_EQ(all_fields->size(), 2);
  EXPECT_EQ(all_fields->at(0).first, "as_int");
  EXPECT_EQ(all_fields->at(1).first, "as_float");
}

TEST(btf, enum_types)
{
  Types btf;

  std::map<std::string, int32_t> values = { { "RED", 0 },
                                            { "GREEN", 1 },
                                            { "BLUE", 2 } };

  auto color_enum = btf.add<Enum>("Color", values);
  ASSERT_TRUE(bool(color_enum));

  EXPECT_EQ(color_enum->name(), "Color");

  auto enum_values = color_enum->values();
  EXPECT_EQ(enum_values.size(), 3);
  EXPECT_EQ(enum_values["RED"], 0);
  EXPECT_EQ(enum_values["GREEN"], 1);
  EXPECT_EQ(enum_values["BLUE"], 2);
}

TEST(btf, enum64_types)
{
  Types btf;

  std::map<std::string, int64_t> values = { { "SMALL", 1LL },
                                            { "MEDIUM", 1000000LL },
                                            { "LARGE", 1000000000000LL } };

  auto size_enum = btf.add<Enum64>("Size", values);
  ASSERT_TRUE(bool(size_enum));

  EXPECT_EQ(size_enum->name(), "Size");

  auto enum_values = size_enum->values();
  EXPECT_EQ(enum_values.size(), 3);
  EXPECT_EQ(enum_values["SMALL"], 1LL);
  EXPECT_EQ(enum_values["MEDIUM"], 1000000LL);
  EXPECT_EQ(enum_values["LARGE"], 1000000000000LL);
}

TEST(btf, typedef_types)
{
  Types btf;
  auto int32 = btf.add<Integer>("int32", 4, 1);
  ASSERT_TRUE(bool(int32));

  auto my_int = btf.add<Typedef>("MyInt", AnyType(*int32));
  ASSERT_TRUE(bool(my_int));

  EXPECT_EQ(my_int->name(), "MyInt");

  auto underlying_type = my_int->type();
  ASSERT_TRUE(bool(underlying_type));
  EXPECT_TRUE(underlying_type->is<Integer>());
  EXPECT_EQ(to_str(*underlying_type), "int32");
}

TEST(btf, qualifier_types)
{
  Types btf;
  auto int32 = btf.add<Integer>("int32", 4, 1);
  ASSERT_TRUE(bool(int32));

  auto const_int32 = btf.add<Const>(ValueType(*int32));
  ASSERT_TRUE(bool(const_int32));

  auto const_type = const_int32->type();
  ASSERT_TRUE(bool(const_type));
  EXPECT_TRUE(const_type->is<Integer>());

  auto volatile_int32 = btf.add<Volatile>(ValueType(*int32));
  ASSERT_TRUE(bool(volatile_int32));

  auto volatile_type = volatile_int32->type();
  ASSERT_TRUE(bool(volatile_type));
  EXPECT_TRUE(volatile_type->is<Integer>());

  auto restrict_int32 = btf.add<Restrict>(ValueType(*int32));
  ASSERT_TRUE(bool(restrict_int32));

  auto restrict_type = restrict_int32->type();
  ASSERT_TRUE(bool(restrict_type));
  EXPECT_TRUE(restrict_type->is<Integer>());
}

TEST(btf, function_types)
{
  Types btf;
  auto int32 = btf.add<Integer>("int32", 4, 1);
  ASSERT_TRUE(bool(int32));

  std::vector<std::pair<std::string, ValueType>> args = {
    { "a", ValueType(*int32) }, { "b", ValueType(*int32) }
  };

  auto add_proto = btf.add<FunctionProto>(ValueType(*int32), args);
  ASSERT_TRUE(bool(add_proto));

  auto return_type = add_proto->return_type();
  ASSERT_TRUE(bool(return_type));
  EXPECT_TRUE(return_type->is<Integer>());

  auto arg_types = add_proto->argument_types();
  ASSERT_TRUE(bool(arg_types));
  EXPECT_EQ(arg_types->size(), 2);

  auto add_func = btf.add<Function>("add",
                                    Function::Linkage::Global,
                                    *add_proto);
  ASSERT_TRUE(bool(add_func));

  EXPECT_EQ(add_func->name(), "add");
  EXPECT_EQ(add_func->linkage(), Function::Linkage::Global);

  auto func_type = add_func->type();
  ASSERT_TRUE(bool(func_type));
}

TEST(btf, variable_types)
{
  Types btf;
  auto int32 = btf.add<Integer>("int32", 4, 1);
  ASSERT_TRUE(bool(int32));

  auto global_var = btf.add<Var>("global_counter",
                                 Var::Linkage::Global,
                                 ValueType(*int32));
  ASSERT_TRUE(bool(global_var));

  EXPECT_EQ(global_var->name(), "global_counter");
  EXPECT_EQ(global_var->linkage(), Var::Linkage::Global);

  auto var_type = global_var->type();
  ASSERT_TRUE(bool(var_type));
  EXPECT_TRUE(var_type->is<Integer>());

  auto static_var = btf.add<Var>("static_counter",
                                 Var::Linkage::Static,
                                 ValueType(*int32));
  ASSERT_TRUE(bool(static_var));
  EXPECT_EQ(static_var->linkage(), Var::Linkage::Static);
}

TEST(btf, complex_nested_types)
{
  Types btf;
  auto int32 = btf.add<Integer>("int32", 4, 1);
  auto size_t_type = btf.add<Integer>("size_t", 8, 0);
  ASSERT_TRUE(bool(int32));
  ASSERT_TRUE(bool(size_t_type));

  auto int_array = btf.add<Array>(*size_t_type, ValueType(*int32), 10);
  ASSERT_TRUE(bool(int_array));

  auto ptr_to_array = btf.add<Pointer>(AnyType(*int_array));
  ASSERT_TRUE(bool(ptr_to_array));

  std::vector<std::pair<std::string, ValueType>> fields = {
    { "data", ValueType(*ptr_to_array) }, { "size", ValueType(*int32) }
  };

  auto container_struct = btf.add<Struct>("Container", fields);
  ASSERT_TRUE(bool(container_struct));

  auto ptr_to_struct = btf.add<Pointer>(AnyType(*container_struct));
  ASSERT_TRUE(bool(ptr_to_struct));

  auto const_ptr_to_struct = btf.add<Const>(ValueType(*ptr_to_struct));
  ASSERT_TRUE(bool(const_ptr_to_struct));

  auto final_type = const_ptr_to_struct->type();
  ASSERT_TRUE(bool(final_type));
  EXPECT_TRUE(final_type->is<Pointer>());
}

TEST(btf, type_lookup)
{
  Types btf;
  auto int32 = btf.add<Integer>("int32", 4, 1);
  ASSERT_TRUE(bool(int32));

  auto looked_up = btf.lookup<Integer>("int32");
  ASSERT_TRUE(bool(looked_up));
  EXPECT_EQ(looked_up->type_id(), int32->type_id());

  auto looked_up_by_id = btf.lookup<Integer>(int32->type_id());
  ASSERT_TRUE(bool(looked_up_by_id));
  EXPECT_EQ(looked_up_by_id->type_id(), int32->type_id());

  auto any_looked_up = btf.lookup("int32");
  ASSERT_TRUE(bool(any_looked_up));
  EXPECT_TRUE(any_looked_up->is<Integer>());
  EXPECT_EQ(any_looked_up->type_id(), int32->type_id());
}

TEST(btf, type_iteration)
{
  Types btf;
  auto int32 = btf.add<Integer>("int32", 4, 1);
  auto int64 = btf.add<Integer>("int64", 8, 1);
  auto ptr_int32 = btf.add<Pointer>(AnyType(*int32));

  ASSERT_TRUE(bool(int32));
  ASSERT_TRUE(bool(int64));
  ASSERT_TRUE(bool(ptr_int32));

  size_t integer_count = 0;
  size_t pointer_count = 0;

  for (const auto &type : btf) {
    if (type.is<Integer>()) {
      integer_count++;
    } else if (type.is<Pointer>()) {
      pointer_count++;
    }
  }

  EXPECT_EQ(integer_count, 2);
  EXPECT_EQ(pointer_count, 1);
}

TEST(btf, filtered_iteration)
{
  Types btf;
  auto int32 = btf.add<Integer>("int32", 4, 1);
  auto int64 = btf.add<Integer>("int64", 8, 1);
  auto ptr_int32 = btf.add<Pointer>(AnyType(*int32));

  ASSERT_TRUE(bool(int32));
  ASSERT_TRUE(bool(int64));
  ASSERT_TRUE(bool(ptr_int32));

  std::vector<std::string> integer_names;
  for (const auto &type : btf) {
    if (!type.is<btf::Integer>()) {
      continue;
    }
    const auto &integer = type.as<btf::Integer>();
    EXPECT_TRUE(integer.bytes() == 4 || integer.bytes() == 8);
  }

  size_t pointer_count = 0;
  for (const auto &type : btf) {
    if (!type.is<btf::Pointer>()) {
      continue;
    }
    const auto &pointer = type.as<btf::Pointer>();
    pointer_count++;
    auto element = pointer.element_type();
    ASSERT_TRUE(bool(element));
  }
  EXPECT_EQ(pointer_count, 1);
}

TEST(btf, size_and_alignment)
{
  Types btf;
  auto int8 = btf.add<Integer>("int8", 1, 1);
  auto int32 = btf.add<Integer>("int32", 4, 1);
  auto int64 = btf.add<Integer>("int64", 8, 1);

  ASSERT_TRUE(bool(int8));
  ASSERT_TRUE(bool(int32));
  ASSERT_TRUE(bool(int64));

  auto size8 = int8->size();
  auto size32 = int32->size();
  auto size64 = int64->size();

  ASSERT_TRUE(bool(size8));
  ASSERT_TRUE(bool(size32));
  ASSERT_TRUE(bool(size64));

  EXPECT_EQ(*size8, 1);
  EXPECT_EQ(*size32, 4);
  EXPECT_EQ(*size64, 8);

  auto align8 = int8->alignment();
  auto align32 = int32->alignment();
  auto align64 = int64->alignment();

  ASSERT_TRUE(bool(align8));
  ASSERT_TRUE(bool(align32));
  ASSERT_TRUE(bool(align64));

  EXPECT_EQ(*align8, 1);
  EXPECT_EQ(*align32, 4);
  EXPECT_EQ(*align64, 8);
}

TEST(btf, error_handling)
{
  Types btf;

  auto missing_type = btf.lookup<Integer>("nonexistent");
  EXPECT_FALSE(bool(missing_type));

  auto missing_by_id = btf.lookup<Integer>(9999);
  EXPECT_FALSE(bool(missing_by_id));

  auto int32 = btf.add<Integer>("int32", 4, 1);
  auto ptr_int32 = btf.add<Pointer>(AnyType(*int32));
  ASSERT_TRUE(bool(ptr_int32));

  auto wrong_kind = btf.lookup<Integer>(ptr_int32->type_id());
  EXPECT_FALSE(bool(wrong_kind));
}

TEST(btf, helper_functions)
{
  Types btf;
  auto int32 = btf.add<Integer>("int32", 4, 1);
  auto int64 = btf.add<Integer>("int64", 8, 1);
  ASSERT_TRUE(bool(int32));
  ASSERT_TRUE(bool(int64));

  std::vector<ValueType> tuple_types = { ValueType(*int32),
                                         ValueType(*int64),
                                         ValueType(*int32) };

  auto tuple = createTuple(btf, tuple_types);
  ASSERT_TRUE(bool(tuple));

  auto tuple_fields = tuple->fields();
  ASSERT_TRUE(bool(tuple_fields));
  EXPECT_EQ(tuple_fields->size(), 3);

  MapInfo map_info = { .map_type = BPF_MAP_TYPE_HASH,
                       .key = ValueType(*int32),
                       .value = ValueType(*int64),
                       .nr_elements = 100 };

  auto map_struct = createMap(btf, map_info);
  ASSERT_TRUE(bool(map_struct));

  auto retrieved_info = getMapInfo(AnyType(*map_struct));
  ASSERT_TRUE(bool(retrieved_info));

  EXPECT_EQ(retrieved_info->map_type, BPF_MAP_TYPE_HASH);
  EXPECT_EQ(retrieved_info->nr_elements, 100);
  EXPECT_TRUE(retrieved_info->key.is<Integer>());
  EXPECT_TRUE(retrieved_info->value.is<Integer>());
}

} // namespace bpftrace::test::btf
