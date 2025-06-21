#include "globalvars.h"
#include "types.h"
#include "gmock/gmock-matchers.h"
#include "gtest/gtest.h"

namespace bpftrace::test {

using ::testing::HasSubstr;

TEST(GlobalVars, get_named_param_vals)
{
  auto global_vars = globalvars::GlobalVars();
  global_vars.add_named_param("hello", Type::string, false, "bye");
  global_vars.add_named_param("is_true", Type::integer, true, "");
  global_vars.add_named_param("number", Type::integer, false, "5");

  auto global_var_values = global_vars.get_named_param_vals(
      { { "hello", "low" }, { "number", "10" } });
  auto hello_val = global_var_values->at("hello");
  EXPECT_EQ("low", std::get<std::string>(hello_val));

  auto is_true_val = global_var_values->at("is_true");
  EXPECT_EQ(1, std::get<int64_t>(is_true_val));

  auto number_val = global_var_values->at("number");
  EXPECT_EQ(10, std::get<int64_t>(number_val));

  auto global_var_values2 = global_vars.get_named_param_vals(
      { { "random", "low" } });
  EXPECT_FALSE(global_var_values2);
  bool has_unknown_opts_error = false;
  auto ok2 = handleErrors(
      std::move(global_var_values2), [&](const UnknownParamError& uo_err) {
        EXPECT_THAT(uo_err.err(),
                    HasSubstr("Unexpected command line options: --random"));
        has_unknown_opts_error = true;
      });
  EXPECT_TRUE(has_unknown_opts_error);

  auto global_var_values3 = global_vars.get_named_param_vals(
      { { "number", "tomato" } });
  EXPECT_FALSE(global_var_values3);
  bool has_named_param_error = false;
  auto ok3 = handleErrors(
      std::move(global_var_values3), [&](const NamedParamError& uo_err) {
        EXPECT_THAT(uo_err.err(),
                    HasSubstr("Command line option --number is expecting an "
                              "integer. Got: tomato"));
        has_named_param_error = true;
      });
  EXPECT_TRUE(has_named_param_error);

  auto global_var_values4 = global_vars.get_named_param_vals(
      { { "is_true", "5" } });
  EXPECT_FALSE(global_var_values4);
  has_named_param_error = false;
  auto ok4 = handleErrors(
      std::move(global_var_values4), [&](const NamedParamError& uo_err) {
        EXPECT_THAT(uo_err.err(),
                    HasSubstr("Command line option --is_true is expecting a "
                              "boolean (e.g. 'true'). Got: 5"));
        has_named_param_error = true;
      });
  EXPECT_TRUE(has_named_param_error);

  auto global_var_values5 = global_vars.get_named_param_vals(
      { { "hello", "" } });
  EXPECT_FALSE(global_var_values5);
  has_named_param_error = false;
  auto ok5 = handleErrors(
      std::move(global_var_values5), [&](const NamedParamError& uo_err) {
        EXPECT_THAT(uo_err.err(),
                    HasSubstr("Command line option --hello is expecting a "
                              "string. Got a boolean flag."));
        has_named_param_error = true;
      });
  EXPECT_TRUE(has_named_param_error);
}

} // namespace bpftrace::test
