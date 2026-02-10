#include "globalvars.h"
#include "types.h"
#include "gmock/gmock-matchers.h"
#include "gtest/gtest.h"

namespace bpftrace::globalvars::test {

using ::testing::HasSubstr;

void test_named_param_error(globalvars::GlobalVars& global_vars,
                            const std::vector<std::string>& params,
                            const std::string& expected_error_substr)
{
  auto bad_values = global_vars.get_named_param_vals(params);
  EXPECT_FALSE(bad_values);
  bool has_named_param_error = false;
  auto ok = handleErrors(std::move(bad_values),
                         [&](const NamedParamError& uo_err) {
                           EXPECT_THAT(uo_err.err(),
                                       HasSubstr(expected_error_substr));
                           has_named_param_error = true;
                         });
  EXPECT_TRUE(has_named_param_error);
}

TEST(GlobalVars, get_named_param_vals)
{
  auto global_vars = globalvars::GlobalVars();
  global_vars.add_named_param("hello", "bye", "Bye");
  global_vars.add_named_param("is_true", true, "Flag");
  global_vars.add_named_param("will_be_true", false, "Will");
  global_vars.add_named_param("number", 5, "Number of values");

  auto good_values1 = global_vars.get_named_param_vals(
      { "hello=low", "number=10", "will_be_true" });
  auto hello_val = good_values1->at("hello");
  EXPECT_EQ("low", std::get<std::string>(hello_val));

  auto is_true_val = good_values1->at("is_true");
  EXPECT_EQ(true, std::get<bool>(is_true_val));

  auto is_also_true_val = good_values1->at("will_be_true");
  EXPECT_EQ(true, std::get<bool>(is_also_true_val));

  auto number_val = good_values1->at("number");
  EXPECT_EQ(10, std::get<int64_t>(number_val));

  auto good_values2 = global_vars.get_named_param_vals(
      { "number=-10", "is_true=false" });

  number_val = good_values2->at("number");
  EXPECT_EQ(-10, std::get<int64_t>(number_val));

  auto is_false_val = good_values2->at("is_true");
  EXPECT_EQ(false, std::get<bool>(is_false_val));

  auto good_values3 = global_vars.get_named_param_vals({ "number=1m" });

  number_val = good_values3->at("number");
  EXPECT_EQ(60000000000, std::get<int64_t>(number_val));

  // Test errors

  auto bad_values1 = global_vars.get_named_param_vals({ "random=low" });
  EXPECT_FALSE(bad_values1);
  bool has_unknown_opts_error = false;
  auto ok2 = handleErrors(
      std::move(bad_values1), [&](const UnknownParamError& uo_err) {
        EXPECT_THAT(uo_err.err(),
                    HasSubstr(
                        "unexpected program command line options: --random"));
        has_unknown_opts_error = true;
      });
  EXPECT_TRUE(has_unknown_opts_error);

  test_named_param_error(global_vars, { "number=tomato" }, "invalid integer");
  test_named_param_error(global_vars,
                         { "is_true=5" },
                         "expects a boolean (e.g. 'true')");
  test_named_param_error(global_vars, { "hello" }, "expects a string");
  test_named_param_error(global_vars,
                         { "number=1000000000000000000000000000000000000" },
                         "value is out of range");
}

} // namespace bpftrace::globalvars::test
