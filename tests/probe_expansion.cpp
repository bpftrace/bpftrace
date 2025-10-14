#include "ast/passes/probe_expansion.h"
#include "ast/passes/ap_expansion.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/clang_parser.h"
#include "ast/passes/printer.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

#include "btf_common.h"
#ifdef HAVE_LIBDW
#include "dwarf_common.h"
#endif // HAVE_LIBDW

namespace bpftrace::test::probe_expansion {

using ::testing::_;

void test(BPFtrace &bpftrace,
          const std::string &input,
          std::string_view expected_ast)
{
  std::stringstream msg;
  msg << "\nInput:\n" << input << "\n\nOutput:\n";

  ast::ASTContext ast("stdin", input);
  auto result = ast::PassManager()
                    .put(ast)
                    .put(bpftrace)
                    .add(CreateParsePass())
                    .add(ast::CreateParseAttachpointsPass())
                    .add(ast::CreateApExpansionPass())
                    .add(ast::CreateProbeExpansionPass())
                    .add(ast::CreateClangParsePass())
                    .add(ast::CreateProbeExpansionPass(
                        { ProbeType::tracepoint }))
                    .run();
  ASSERT_TRUE(bool(result)) << msg.str();

  if (expected_ast.empty()) {
    EXPECT_EQ(ast.diagnostics().ok(), false);
  } else {
    EXPECT_EQ(ast.diagnostics().ok(), true);
    if (expected_ast[0] == '\n')
      expected_ast.remove_prefix(1);

    std::stringstream out;
    ast::Printer printer(out);
    printer.visit(ast.root);
    EXPECT_EQ(out.str(), expected_ast);
  }
}

void test(const std::string &input, std::string_view expected_ast)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, input, expected_ast);
}

void test_error(const std::string &input)
{
  auto bpftrace = get_mock_bpftrace();
  test(*bpftrace, input, "");
}

class probe_expansion_btf : public test_btf {};

TEST_F(probe_expansion_btf, fentry_args)
{
  test("fentry:func_1, fentry:func_2 { args }", R"(
Program
 fentry:mock_vmlinux:func_1
  builtin: args
 fentry:mock_vmlinux:func_2
  builtin: args
)");

  test("fentry:func_2, fentry:func_3 { args }", R"(
Program
 fentry:mock_vmlinux:func_2
 fentry:mock_vmlinux:func_3
  builtin: args
)");

  test("fentry:func_* { args }", R"(
Program
 fentry:vmlinux:func_1
  builtin: args
 fentry:vmlinux:func_2
  builtin: args
 fentry:vmlinux:func_3
  builtin: args
)");

  test("fentry:func_* { 1 }", R"(
Program
 fentry:vmlinux:func_1
 fentry:vmlinux:func_2
 fentry:vmlinux:func_3
  int: 1 :: [int64]
)");

  test_error("fentry:func_2, fentry:aaa { args }");
}

TEST_F(probe_expansion_btf, fentry_retval)
{
  test("fexit:func_1, fexit:func_2 { __builtin_retval }", R"(
Program
 fexit:mock_vmlinux:func_1
  builtin: __builtin_retval
 fexit:mock_vmlinux:func_2
  builtin: __builtin_retval
)");

  test("fexit:func_2, fexit:func_3 { __builtin_retval }", R"(
Program
 fexit:mock_vmlinux:func_2
 fexit:mock_vmlinux:func_3
  builtin: __builtin_retval
)");

  test("fexit:func_* { __builtin_retval }", R"(
Program
 fexit:vmlinux:func_1
  builtin: __builtin_retval
 fexit:vmlinux:func_2
  builtin: __builtin_retval
 fexit:vmlinux:func_3
  builtin: __builtin_retval
)");

  test_error("fentry:func_2, fentry:aaa { __builtin_retval }");
}

TEST_F(probe_expansion_btf, mixed_providers)
{
  test("fentry:func_2, fexit:func_3 { args }", R"(
Program
 fentry:mock_vmlinux:func_2
  builtin: args
 fexit:mock_vmlinux:func_3
  builtin: args
)");

  test_error("tracepoint:sched:sched_one, fexit:aaa { args }");
}

TEST_F(probe_expansion_btf, tracepoint_args)
{
  test("tracepoint:sched:sched_one, tracepoint:sched:sched_two { args }", R"(
Program
 tracepoint:sched:sched_one
  builtin: args
 tracepoint:sched:sched_two
  builtin: args
)");

  test("tracepoint:sched:sched_one, tracepoint:sched:sched_two { 1 }", R"(
Program
 tracepoint:sched:sched_one
 tracepoint:sched:sched_two
  int: 1 :: [int64]
)");

  test("tracepoint:sched:sched_* { args }", R"(
Program
 tracepoint:sched:sched_one
  builtin: args
 tracepoint:sched:sched_two
  builtin: args
)");
}

TEST_F(probe_expansion_btf, builtin_probe)
{
  test("fentry:vmlinux:func_1, fentry:vmlinux:func_2 { __builtin_probe }", R"(
Program
 fentry:vmlinux:func_1
  builtin: __builtin_probe
 fentry:vmlinux:func_2
  builtin: __builtin_probe
)");

  test("fentry:vmlinux:func_* { __builtin_probe }", R"(
Program
 fentry:vmlinux:func_1
  builtin: __builtin_probe
 fentry:vmlinux:func_2
  builtin: __builtin_probe
 fentry:vmlinux:func_3
  builtin: __builtin_probe
)");
}

TEST_F(probe_expansion_btf, builtin_probetype)
{
  test("fentry:vmlinux:func_1, fentry:vmlinux:func_2 { __builtin_probetype }",
       R"(
Program
 fentry:vmlinux:func_1
 fentry:vmlinux:func_2
  identifier: __builtin_probetype
)");

  test("fentry:vmlinux:func_* { __builtin_probetype }", R"(
Program
 fentry:vmlinux:func_1
 fentry:vmlinux:func_2
 fentry:vmlinux:func_3
  identifier: __builtin_probetype
)");

  test("fentry:vmlinux:func_1, tracepoint:sched:sched_one { "
       "__builtin_probetype }",
       R"(
Program
 fentry:vmlinux:func_1
  identifier: __builtin_probetype
 tracepoint:sched:sched_one
  identifier: __builtin_probetype
)");

  test("begin, end { __builtin_probetype }", R"(
Program
 begin
 end
  identifier: __builtin_probetype
)");

  test("begin, end, interval:1s { __builtin_probetype }", R"(
Program
 begin
  identifier: __builtin_probetype
 end
  identifier: __builtin_probetype
 interval:us:1000000
  identifier: __builtin_probetype
)");
}

#ifdef HAVE_LIBDW

class probe_expansion_dwarf : public test_dwarf {};

TEST_F(probe_expansion_dwarf, uprobe_args)
{
  std::string uprobe = "uprobe:" + std::string(bin_);
  test(uprobe + ":func_1," + uprobe + ":func_2 { args }", R"(
Program
 uprobe:/tmp/bpftrace-test-dwarf-data:func_1
  builtin: args
 uprobe:/tmp/bpftrace-test-dwarf-data:func_2
  builtin: args
)");

  test(uprobe + ":func_2," + uprobe + ":func_3 { args }", R"(
Program
 uprobe:/tmp/bpftrace-test-dwarf-data:func_2
 uprobe:/tmp/bpftrace-test-dwarf-data:func_3
  builtin: args
)");
}

TEST_F(probe_expansion_dwarf, uretprobe_retval)
{
  // all uretprobes have the same return value so no need to expand
  std::string uretprobe = "uretprobe:" + std::string(bin_);
  test(uretprobe + ":func_1," + uretprobe + ":func_2 { __builtin_retval }", R"(
Program
 uretprobe:/tmp/bpftrace-test-dwarf-data:func_1
 uretprobe:/tmp/bpftrace-test-dwarf-data:func_2
  builtin: __builtin_retval
)");
}

#endif // HAVE_LIBDW

} // namespace bpftrace::test::probe_expansion
