#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "bpftrace.h"
#include "driver.h"
#include "semantic_analyser.h"

namespace bpftrace {
namespace test {
namespace semantic_analyser {

class MockBPFtrace : public BPFtrace {
public:
  MOCK_METHOD1(add_probe, int(ast::Probe &p));
};

using ::testing::_;

void test(BPFtrace &bpftrace, Driver &driver, const std::string &input, int expected_result=0)
{
  ASSERT_EQ(driver.parse_str(input), 0);

  std::stringstream out;
  ast::SemanticAnalyser semantics(driver.root_, bpftrace, out);
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";
  EXPECT_EQ(expected_result, semantics.analyse()) << msg.str() + out.str();
}

void test(BPFtrace &bpftrace, const std::string &input, int expected_result=0)
{
  Driver driver;
  test(bpftrace, driver, input, expected_result);
}

void test(Driver &driver, const std::string &input, int expected_result=0)
{
  BPFtrace bpftrace;
  test(bpftrace, driver, input, expected_result);
}

void test(const std::string &input, int expected_result=0)
{
  Field field = { SizedType(Type::integer, 8), 0 };
  Field mystr = { SizedType(Type::string, 8), 8 };
  Field type2_field_ptr = { SizedType(Type::cast, 8, "type2*"), 16 };
  Field type2_field = { SizedType(Type::cast, 8, "type2"), 24 };

  Struct type1 = { 16, {{"field", field},
                        {"mystr", mystr},
                        {"type2ptr", type2_field_ptr},
                        {"type2", type2_field}} };
  Struct type2 = { 8, {{"field", field}} };

  BPFtrace bpftrace;
  bpftrace.structs_["type1"] = type1;
  bpftrace.structs_["type2"] = type2;

  Driver driver;
  test(bpftrace, driver, input, expected_result);
}

TEST(semantic_analyser, builtin_variables)
{
  test("kprobe:f { pid }", 0);
  test("kprobe:f { tid }", 0);
  test("kprobe:f { uid }", 0);
  test("kprobe:f { gid }", 0);
  test("kprobe:f { nsecs }", 0);
  test("kprobe:f { cpu }", 0);
  test("kprobe:f { curtask }", 0);
  test("kprobe:f { rand }", 0);
  test("kprobe:f { comm }", 0);
  test("kprobe:f { stack }", 0);
  test("kprobe:f { ustack }", 0);
  test("kprobe:f { arg0 }", 0);
  test("kprobe:f { retval }", 0);
  test("kprobe:f { func }", 0);
  test("kprobe:f { name }", 0);
//  test("kprobe:f { fake }", 1);
}

TEST(semantic_analyser, builtin_functions)
{
  test("kprobe:f { @x = hist(123) }", 0);
  test("kprobe:f { @x = count() }", 0);
  test("kprobe:f { @x = sum(pid) }", 0);
  test("kprobe:f { @x = min(pid) }", 0);
  test("kprobe:f { @x = max(pid) }", 0);
  test("kprobe:f { @x = avg(pid) }", 0);
  test("kprobe:f { @x = stats(pid) }", 0);
  test("kprobe:f { @x = 1; delete(@x) }", 0);
  test("kprobe:f { @x = 1; print(@x) }", 0);
  test("kprobe:f { @x = 1; clear(@x) }", 0);
  test("kprobe:f { @x = 1; zero(@x) }", 0);
  test("kprobe:f { time() }", 0);
  test("kprobe:f { exit() }", 0);
  test("kprobe:f { str(0xffff) }", 0);
  test("kprobe:f { printf(\"hello\\n\") }", 0);
  test("kprobe:f { join(0) }", 0);
  test("kprobe:f { sym(0xffff) }", 0);
  test("kprobe:f { usym(0xffff) }", 0);
  test("kprobe:f { reg(\"ip\") }", 0);
  test("kprobe:f { @x = count(pid) }", 1);
  test("kprobe:f { @x = sum(pid, 123) }", 1);
  test("kprobe:f { fake() }", 1);
}

TEST(semantic_analyser, probe_count)
{
  MockBPFtrace bpftrace;
  EXPECT_CALL(bpftrace, add_probe(_)).Times(2);

  test(bpftrace, "kprobe:f { 1; } kprobe:d { 1; }");
}

TEST(semantic_analyser, undefined_map)
{
  test("kprobe:f / @mymap == 123 / { @mymap = 0 }", 0);
  test("kprobe:f / @mymap == 123 / { 456; }", 10);
  test("kprobe:f / @mymap1 == 1234 / { 1234; @mymap1 = @mymap2; }", 10);
}

TEST(semantic_analyser, predicate_expressions)
{
  test("kprobe:f / 999 / { 123 }", 0);
  test("kprobe:f / \"str\" / { 123 }", 10);
  test("kprobe:f / stack / { 123 }", 10);
  test("kprobe:f / @mymap / { @mymap = \"str\" }", 10);
}

TEST(semantic_analyser, ternary_experssions)
{
  test("kprobe:f { @x = pid < 10000 ? 1 : 2 }", 0);
  test("kprobe:f { @x = pid < 10000 ? \"lo\" : \"high\" }", 0);
  test("kprobe:f { @x = pid < 10000 ? 1 : \"high\" }", 10);
  test("kprobe:f { @x = pid < 10000 ? \"lo\" : 2 }", 10);
}

TEST(semantic_analyser, mismatched_call_types)
{
  test("kprobe:f { @x = 1; @x = count(); }", 1);
  test("kprobe:f { @x = count(); @x = sum(pid); }", 1);
  test("kprobe:f { @x = 1; @x = hist(0); }", 1);
}

TEST(semantic_analyser, call_hist)
{
  test("kprobe:f { @x = hist(1); }", 0);
  test("kprobe:f { @x = hist(); }", 1);
  test("kprobe:f { hist(); }", 1);
}

TEST(semantic_analyser, call_count)
{
  test("kprobe:f { @x = count(); }", 0);
  test("kprobe:f { @x = count(1); }", 1);
  test("kprobe:f { count(); }", 1);
}

TEST(semantic_analyser, call_sum)
{
  test("kprobe:f { @x = sum(); }", 1);
  test("kprobe:f { @x = sum(123); }", 0);
  test("kprobe:f { sum(); }", 1);
}

TEST(semantic_analyser, call_min)
{
  test("kprobe:f { @x = min(); }", 1);
  test("kprobe:f { @x = min(123); }", 0);
  test("kprobe:f { min(); }", 1);
}

TEST(semantic_analyser, call_max)
{
  test("kprobe:f { @x = max(); }", 1);
  test("kprobe:f { @x = max(123); }", 0);
  test("kprobe:f { max(); }", 1);
}

TEST(semantic_analyser, call_avg)
{
  test("kprobe:f { @x = avg(); }", 1);
  test("kprobe:f { @x = avg(123); }", 0);
  test("kprobe:f { avg(); }", 1);
}

TEST(semantic_analyser, call_stats)
{
  test("kprobe:f { @x = stats(); }", 1);
  test("kprobe:f { @x = stats(123); }", 0);
  test("kprobe:f { stats(); }", 1);
}

TEST(semantic_analyser, call_delete)
{
  test("kprobe:f { @x = 1; delete(@x); }", 0);
  test("kprobe:f { delete(1); }", 1);
  test("kprobe:f { delete(); }", 1);
  test("kprobe:f { @y = delete(@x); }", 1);
  test("kprobe:f { $y = delete(@x); }", 1);
}

TEST(semantic_analyser, call_exit)
{
  test("kprobe:f { exit(); }", 0);
  test("kprobe:f { exit(1); }", 1);
}

TEST(semantic_analyser, call_print)
{
  test("kprobe:f { @x = count(); print(@x); }", 0);
  test("kprobe:f { @x = count(); print(@x, 5); }", 0);
  test("kprobe:f { @x = count(); print(@x, 5, 10); }", 0);
  test("kprobe:f { @x = count(); print(@x, 5, 10, 1); }", 1);
  test("kprobe:f { @x = count(); @x = print(); }", 1);
}

TEST(semantic_analyser, call_clear)
{
  test("kprobe:f { @x = count(); clear(@x); }", 0);
  test("kprobe:f { @x = count(); clear(@x, 1); }", 1);
  test("kprobe:f { @x = count(); @x = clear(); }", 1);
}

TEST(semantic_analyser, call_zero)
{
  test("kprobe:f { @x = count(); zero(@x); }", 0);
  test("kprobe:f { @x = count(); zero(@x, 1); }", 1);
  test("kprobe:f { @x = count(); @x = zero(); }", 1);
}

TEST(semantic_analyser, call_time)
{
  test("kprobe:f { time(); }", 0);
  test("kprobe:f { time(\"%M:%S\"); }", 0);
  test("kprobe:f { time(\"%M:%S\", 1); }", 1);
  test("kprobe:f { @x = time(); }", 1);
}

TEST(semantic_analyser, call_str)
{
  test("kprobe:f { str(arg0); }", 0);
  test("kprobe:f { @x = str(arg0); }", 0);
  test("kprobe:f { str(); }", 1);
  test("kprobe:f { str(\"hello\"); }", 10);
}

TEST(semantic_analyser, call_sym)
{
  test("kprobe:f { sym(arg0); }", 0);
  test("kprobe:f { @x = sym(arg0); }", 0);
  test("kprobe:f { sym(); }", 1);
  test("kprobe:f { sym(\"hello\"); }", 10);
}

TEST(semantic_analyser, call_usym)
{
  test("kprobe:f { usym(arg0); }", 0);
  test("kprobe:f { @x = usym(arg0); }", 0);
  test("kprobe:f { usym(); }", 1);
  test("kprobe:f { usym(\"hello\"); }", 10);
}

TEST(semantic_analyser, call_reg)
{
  test("kprobe:f { reg(\"ip\"); }", 0);
  test("kprobe:f { @x = reg(\"ip\"); }", 0);
  test("kprobe:f { reg(\"blah\"); }", 1);
  test("kprobe:f { reg(); }", 1);
  test("kprobe:f { reg(123); }", 1);
}

TEST(semantic_analyser, call_func)
{
  test("kprobe:f { @[func] = count(); }", 0);
  test("kprobe:f { printf(\"%s\", func);  }", 0);
  test("kprobe:f { func(\"blah\"); }", 1);
  test("kprobe:f { func(); }", 1);
  test("kprobe:f { func(123); }", 1);
}

TEST(semantic_analyser, call_name)
{
  test("kprobe:f { @[name] = count(); }", 0);
  test("kprobe:f { printf(\"%s\", name);  }", 0);
  test("kprobe:f { name(\"blah\"); }", 1);
  test("kprobe:f { name(); }", 1);
  test("kprobe:f { name(123); }", 1);
}

TEST(semantic_analyser, map_reassignment)
{
  test("kprobe:f { @x = 1; @x = 2; }", 0);
  test("kprobe:f { @x = 1; @x = \"foo\"; }", 1);
}

TEST(semantic_analyser, variable_reassignment)
{
  test("kprobe:f { $x = 1; $x = 2; }", 0);
  test("kprobe:f { $x = 1; $x = \"foo\"; }", 1);
}

TEST(semantic_analyser, map_use_before_assign)
{
  test("kprobe:f { @x = @y; @y = 2; }", 0);
}

TEST(semantic_analyser, variable_use_before_assign)
{
  test("kprobe:f { @x = $y; $y = 2; }", 1);
}

TEST(semantic_analyser, maps_are_global)
{
  test("kprobe:f { @x = 1 } kprobe:g { @y = @x }", 0);
  test("kprobe:f { @x = 1 } kprobe:g { @x = \"abc\" }", 1);
}

TEST(semantic_analyser, variables_are_local)
{
  test("kprobe:f { $x = 1 } kprobe:g { $x = \"abc\"; }", 0);
  test("kprobe:f { $x = 1 } kprobe:g { @y = $x }", 1);
}

TEST(semantic_analyser, variable_type)
{
  Driver driver;
  test(driver, "kprobe:f { $x = 1 }", 0);
  SizedType st(Type::integer, 8);
  auto assignment = static_cast<ast::AssignVarStatement*>(driver.root_->probes->at(0)->stmts->at(0));
  EXPECT_EQ(st, assignment->var->type);
}

TEST(semantic_analyser, printf)
{
  test("kprobe:f { printf(\"hi\") }", 0);
  test("kprobe:f { printf(1234) }", 1);
  test("kprobe:f { printf() }", 1);
  test("kprobe:f { $fmt = \"mystring\"; printf($fmt) }", 1);
  test("kprobe:f { @x = printf(\"hi\") }", 1);
  test("kprobe:f { $x = printf(\"hi\") }", 1);
}

TEST(semantic_analyser, printf_format_int)
{
  test("kprobe:f { printf(\"int: %d\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %d\", pid) }", 0);
  test("kprobe:f { @x = 123; printf(\"int: %d\", @x) }", 0);
  test("kprobe:f { $x = 123; printf(\"int: %d\", $x) }", 0);

  test("kprobe:f { printf(\"int: %u\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %x\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %X\", 1234) }", 0);
}

TEST(semantic_analyser, printf_format_int_with_length)
{
  test("kprobe:f { printf(\"int: %d\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %u\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %x\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %X\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %p\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %hhd\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hhu\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hhx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hhX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hhp\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %hd\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hu\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %hp\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %ld\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %lu\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %lx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %lX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %lp\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %lld\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %llu\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %llx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %llX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %llp\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %jd\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %ju\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %jx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %jX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %jp\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %zd\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %zu\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %zx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %zX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %zp\", 1234) }", 0);

  test("kprobe:f { printf(\"int: %td\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %tu\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %tx\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %tX\", 1234) }", 0);
  test("kprobe:f { printf(\"int: %tp\", 1234) }", 0);
}

TEST(semantic_analyser, printf_format_string)
{
  test("kprobe:f { printf(\"str: %s\", \"mystr\") }", 0);
  test("kprobe:f { printf(\"str: %s\", comm) }", 0);
  test("kprobe:f { printf(\"str: %s\", str(arg0)) }", 0);
  test("kprobe:f { @x = \"hi\"; printf(\"str: %s\", @x) }", 0);
  test("kprobe:f { $x = \"hi\"; printf(\"str: %s\", $x) }", 0);
}

TEST(semantic_analyser, printf_bad_format_string)
{
  test("kprobe:f { printf(\"%d\", \"mystr\") }", 10);
  test("kprobe:f { printf(\"%d\", str(arg0)) }", 10);

  test("kprobe:f { printf(\"%s\", 1234) }", 10);
  test("kprobe:f { printf(\"%s\", arg0) }", 10);
}

TEST(semantic_analyser, printf_format_multi)
{
  test("kprobe:f { printf(\"%d %d %s\", 1, 2, \"mystr\") }", 0);
  test("kprobe:f { printf(\"%d %s %d\", 1, 2, \"mystr\") }", 10);
}

TEST(semantic_analyser, join)
{
  test("kprobe:f { join(arg0) }", 0);
  test("kprobe:f { printf(\"%s\", join(arg0)) }", 10);
  test("kprobe:f { join() }", 1);
  test("kprobe:f { $fmt = \"mystring\"; join($fmt) }", 10);
  test("kprobe:f { @x = join(arg0) }", 1);
  test("kprobe:f { $x = join(arg0) }", 1);
}

TEST(semantic_analyser, kprobe)
{
  test("kprobe:f { 1 }", 0);
  test("kprobe:path:f { 1 }", 1);
  test("kprobe { 1 }", 1);

  test("kretprobe:f { 1 }", 0);
  test("kretprobe:path:f { 1 }", 1);
  test("kretprobe { 1 }", 1);
}

TEST(semantic_analyser, uprobe)
{
  test("uprobe:path:f { 1 }", 0);
  test("uprobe:f { 1 }", 1);
  test("uprobe { 1 }", 1);

  test("uretprobe:path:f { 1 }", 0);
  test("uretprobe:f { 1 }", 1);
  test("uretprobe { 1 }", 1);
}

TEST(semantic_analyser, usdt)
{
  test("usdt:/bin/sh:probe { 1 }", 0);
  test("usdt:/notexistfile:probe { 1 }", 1);
  test("usdt { 1 }", 1);
}

TEST(semantic_analyser, begin_end_probes)
{
  test("BEGIN { 1 }", 0);
  test("BEGIN:f { 1 }", 1);
  test("BEGIN:path:f { 1 }", 1);
  test("BEGIN { 1 } BEGIN { 2 }", 10);

  test("END { 1 }", 0);
  test("END:f { 1 }", 1);
  test("END:path:f { 1 }", 1);
  test("END { 1 } END { 2 }", 10);
}

TEST(semantic_analyser, tracepoint)
{
  test("tracepoint:category:event { 1 }", 0);
  test("tracepoint:f { 1 }", 1);
  test("tracepoint { 1 }", 1);
}

TEST(semantic_analyser, profile)
{
  test("profile:hz:997 { 1 }", 0);
  test("profile:s:10 { 1 }", 0);
  test("profile:ms:100 { 1 }", 0);
  test("profile:us:100 { 1 }", 0);
  test("profile:ms:nan { 1 }", 1);
  test("profile:unit:100 { 1 }", 1);
  test("profile:f { 1 }", 1);
  test("profile { 1 }", 1);
}

TEST(semantic_analyser, variable_cast_types)
{
  test("kprobe:f { $x = (type1)cpu; $x = (type1)cpu; }", 0);
  test("kprobe:f { $x = (type1)cpu; $x = (type2)cpu; }", 1);
}

TEST(semantic_analyser, map_cast_types)
{
  test("kprobe:f { @x = (type1)cpu; @x = (type1)cpu; }", 0);
  test("kprobe:f { @x = (type1)cpu; @x = (type2)cpu; }", 1);
}

TEST(semantic_analyser, variable_casts_are_local)
{
  test("kprobe:f { $x = (type1)cpu } kprobe:g { $x = (type2)cpu; }", 0);
}

TEST(semantic_analyser, map_casts_are_global)
{
  test("kprobe:f { @x = (type1)cpu } kprobe:g { @x = (type2)cpu; }", 1);
}

TEST(semantic_analyser, cast_unknown_type)
{
  test("kprobe:f { (faketype)cpu }", 1);
}

TEST(semantic_analyser, field_access)
{
  test("kprobe:f { ((type1)cpu).field }", 0);
  test("kprobe:f { $x = (type1)cpu; $x.field }", 0);
  test("kprobe:f { @x = (type1)cpu; @x.field }", 0);
}

TEST(semantic_analyser, field_access_wrong_field)
{
  test("kprobe:f { ((type1)cpu).blah }", 1);
  test("kprobe:f { $x = (type1)cpu; $x.blah }", 1);
  test("kprobe:f { @x = (type1)cpu; @x.blah }", 1);
}

TEST(semantic_analyser, field_access_wrong_expr)
{
  test("kprobe:f { 1234->field }", 10);
}

TEST(semantic_analyser, field_access_types)
{
  test("kprobe:f { ((type1)0).field == 123 }", 0);
  test("kprobe:f { ((type1)0).field == \"abc\" }", 10);

  test("kprobe:f { ((type1)0).mystr == \"abc\" }", 0);
  test("kprobe:f { ((type1)0).mystr == 123 }", 10);

  test("kprobe:f { ((type1)0).field == ((type2)0).field }", 0);
  test("kprobe:f { ((type1)0).mystr == ((type2)0).field }", 10);
}

TEST(semantic_analyser, field_access_pointer)
{
  test("kprobe:f { ((type1*)0)->field }", 0);
  test("kprobe:f { ((type1*)0).field }", 1);
  test("kprobe:f { *((type1*)0) }", 0);
}

TEST(semantic_analyser, field_access_sub_struct)
{
  test("kprobe:f { ((type1)0).type2ptr->field }", 0);
  test("kprobe:f { ((type1)0).type2.field }", 0);
  test("kprobe:f { $x = (type2)0; $x = ((type1)0).type2 }", 0);
  test("kprobe:f { $x = (type2*)0; $x = ((type1)0).type2ptr }", 0);
  test("kprobe:f { $x = (type1)0; $x = ((type1)0).type2 }", 1);
  test("kprobe:f { $x = (type1*)0; $x = ((type1)0).type2ptr }", 1);
}

} // namespace semantic_analyser
} // namespace test
} // namespace bpftrace
