#include "ast/passes/probe_expansion.h"
#include "ast/attachpoint_parser.h"
#include "ast/passes/printer.h"
#include "btf_common.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::probe_expansion {

static void test(const std::string &prog,
                 const std::vector<std::string> &expected_aps,
                 const std::vector<std::set<std::string>> &expected_funcs,
                 std::string_view expected_ast,
                 bool features)
{
  auto mock_bpftrace = get_mock_bpftrace();
  mock_bpftrace->feature_ = std::make_unique<MockBPFfeature>(features);

  BPFtrace &bpftrace = *mock_bpftrace;
  ast::ASTContext ast("stdin", prog);

  ast::PassManager pm;
  pm.put(ast)
      .put(bpftrace)
      .add(CreateParsePass())
      .add(ast::CreateParseAttachpointsPass())
      .add(ast::CreateProbeExpansionPass());
  auto result = pm.run();
  ASSERT_TRUE(result && ast.diagnostics().ok());

  if (!expected_aps.empty()) {
    auto &probe = ast.root->probes.at(0);
    ASSERT_EQ(probe->attach_points.size(), expected_aps.size());
    for (size_t i = 0; i < expected_aps.size(); i++) {
      ASSERT_EQ(probe->attach_points.at(i)->name(), expected_aps.at(i));
    }
  }

  if (!expected_funcs.empty()) {
    auto &probe = ast.root->probes.at(0);
    auto &expansions = result->get<ast::ExpansionResult>();

    ASSERT_EQ(probe->attach_points.size(), expected_funcs.size());
    for (size_t i = 0; i < expected_funcs.size(); i++) {
      auto *ap = probe->attach_points.at(i);
      ASSERT_EQ(expansions.get_expanded_funcs(*ap), expected_funcs.at(i));
    }
  }

  if (!expected_ast.empty()) {
    if (expected_ast[0] == '\n')
      expected_ast.remove_prefix(1);

    std::stringstream out;
    ast::Printer printer(out);
    printer.visit(ast.root);
    EXPECT_EQ(out.str(), expected_ast);
  }
}

static void test_attach_points(const std::string &input,
                               const std::vector<std::string> &expected_aps,
                               bool features = true)
{
  test(input, expected_aps, {}, "", features);
}

static void test_multi_attach_points(
    const std::string &input,
    const std::vector<std::string> &expected_aps,
    const std::vector<std::set<std::string>> &expected_funcs)
{
  test(input, expected_aps, expected_funcs, "", true);
}

static void test_ast(const std::string &input, std::string_view expected_ast)
{
  test(input, {}, {}, expected_ast, true);
}

TEST(probe_expansion, session_ast)
{
  test_ast("kprobe:sys_* { @entry = 1 } kretprobe:sys_* { @exit = 1 }", R"(
Program
 kprobe:sys_*
  if
   builtin: __builtin_session_is_return
   then
    =
     map: @exit
     int: 1 :: [int64]
   else
    =
     map: @entry
     int: 1 :: [int64]
)");
}

TEST(probe_expansion, kprobe_wildcard)
{
  // Disabled kprobe_multi - should get full expansion
  test_attach_points("kprobe:sys_read,kprobe:my_*,kprobe:sys_write {}",
                     { "kprobe:sys_read",
                       "kprobe:my_one",
                       "kprobe:my_two",
                       "kprobe:sys_write" },
                     false);
}

TEST(probe_expansion, kprobe_multi_wildcard)
{
  test_multi_attach_points(
      "kprobe:sys_read,kprobe:my_*,kprobe:sys_write {}",
      { "kprobe:sys_read", "kprobe:my_*", "kprobe:sys_write" },
      { {}, { "my_one", "my_two" }, {} });
}

TEST(probe_expansion, probe_builtin)
{
  // Even though kprobe_multi is enabled (by default), we should get full
  // expansion due to using the "probe" builtin.
  test_attach_points(
      "kprobe:sys_read,kprobe:my_*,kprobe:sys_write { __builtin_probe }",
      { "kprobe:sys_read",
        "kprobe:my_one",
        "kprobe:my_two",
        "kprobe:sys_write" });
}

TEST(probe_expansion, kprobe_wildcard_no_matches)
{
  test_attach_points("kprobe:sys_read,kprobe:not_here_*,kprobe:sys_write {}",
                     { "kprobe:sys_read", "kprobe:sys_write" },
                     false);
}

TEST(probe_expansion, krpobe_multi_wildcard_no_matches)
{
  test_attach_points("kprobe:sys_read,kprobe:not_here_*,kprobe:sys_write {}",
                     { "kprobe:sys_read", "kprobe:sys_write" });
}

TEST(probe_expansion, kprobe_module_wildcard)
{
  // We leave kprobe_multi enabled here but it doesn't support the
  // module:function syntax so full expansion should be done anyways.
  test_attach_points("kprobe:*kernel_mod:* {}",
                     { "kprobe:kernel_mod:func_in_mod",
                       "kprobe:kernel_mod:other_func_in_mod",
                       "kprobe:other_kernel_mod:func_in_mod" });
}

TEST(probe_expansion, kprobe_module_function_wildcard)
{
  // We leave kprobe_multi enabled here but it doesn't support the
  // module:function syntax so full expansion should be done anyways.
  test_attach_points("kprobe:kernel_mod:*func_in_mod {}",
                     { "kprobe:kernel_mod:func_in_mod",
                       "kprobe:kernel_mod:other_func_in_mod" });
}

TEST(probe_expansion, uprobe_wildcard)
{
  // Disabled uprobe_multi - should get full expansion
  test_attach_points("uprobe:/bin/sh:*open {}",
                     { "uprobe:/bin/sh:first_open",
                       "uprobe:/bin/sh:second_open" },
                     false);
}

TEST(probe_expansion, uprobe_multi_wildcard)
{
  test_multi_attach_points("uprobe:/bin/sh:*open {}",
                           { "uprobe:/bin/sh:*open" },
                           { { "/bin/sh:first_open", "/bin/sh:second_open" } });
}

TEST(probe_expansion, uprobe_wildcard_file)
{
  // Disabled uprobe_multi - should get full expansion
  test_attach_points("uprobe:/bin/*sh:*open {}",
                     { "uprobe:/bin/bash:first_open",
                       "uprobe:/bin/sh:first_open",
                       "uprobe:/bin/sh:second_open" },
                     false);
}

TEST(probe_expansion, uprobe_multi_wildcard_file)
{
  // Enabled uprobe_multi - targets should be expanded, functions shouldn't
  test_multi_attach_points("uprobe:/bin/*sh:*open {}",
                           { "uprobe:/bin/sh:*open", "uprobe:/bin/bash:*open" },
                           { { "/bin/sh:first_open", "/bin/sh:second_open" },
                             { "/bin/bash:first_open" } });
}

TEST(probe_expansion, uprobe_wildcard_no_matches)
{
  test_attach_points("uprobe:/bin/sh:foo*,uprobe:/bin/sh:first_open {}",
                     { "uprobe:/bin/sh:first_open" },
                     false);
}

TEST(probe_expansion, uprobe_wildcard_multi_no_matches)
{
  test_attach_points("uprobe:/bin/sh:foo*,uprobe:/bin/sh:first_open {}",
                     { "uprobe:/bin/sh:first_open" });
}

TEST(probe_expansion, uprobe_cpp_symbol)
{
  test_attach_points("uprobe:/bin/sh:cpp:cpp_mangled {}",
                     { "uprobe:/bin/sh:cpp:_Z11cpp_mangledi",
                       "uprobe:/bin/sh:cpp:_Z11cpp_mangledv",
                       "uprobe:/bin/sh:cpp:cpp_mangled" },
                     false);
}

TEST(probe_expansion, uprobe_cpp_symbol_full)
{
  test_attach_points("uprobe:/bin/sh:cpp:\"cpp_mangled(int)\" {}",
                     { "uprobe:/bin/sh:cpp:_Z11cpp_mangledi" },
                     false);
}

TEST(probe_expansion, uprobe_cpp_symbol_wildcard)
{
  test_attach_points("uprobe:/bin/sh:cpp:cpp_mangled* {}",
                     { "uprobe:/bin/sh:cpp:_Z11cpp_mangledi",
                       "uprobe:/bin/sh:cpp:_Z11cpp_mangledv",
                       "uprobe:/bin/sh:cpp:_Z18cpp_mangled_suffixv",
                       "uprobe:/bin/sh:cpp:cpp_mangled" },
                     false);
}

TEST(probe_expansion, uprobe_no_demangling)
{
  // Without the :cpp prefix, only look for non-mangled "cpp_mangled" symbol
  test_attach_points("uprobe:/bin/sh:cpp_mangled* {}",
                     { "uprobe:/bin/sh:cpp_mangled" },
                     false);
}

TEST(probe_expansion, usdt_wildcard)
{
  test_attach_points("usdt:/bin/*sh:prov*:tp* {}",
                     { "usdt:/bin/bash:prov1:tp3",
                       "usdt:/bin/sh:prov1:tp1",
                       "usdt:/bin/sh:prov1:tp2",
                       "usdt:/bin/sh:prov2:tp" });
}

TEST(probe_expansion, usdt_empty_namespace)
{
  test_attach_points("usdt:/bin/sh:tp1 {}", { "usdt:/bin/sh:prov1:tp1" });
}

TEST(probe_expansion, tracepoint_wildcard)
{
  test_attach_points("tracepoint:sched:sched_* {}",
                     { "tracepoint:sched:sched_one",
                       "tracepoint:sched:sched_two" });
}

TEST(probe_expansion, tracepoint_category_wildcard)
{
  test_attach_points("tracepoint:sched*:sched_* {}",
                     { "tracepoint:sched:sched_one",
                       "tracepoint:sched:sched_two",
                       "tracepoint:sched_extra:sched_extra" });
}

TEST(probe_expansion, tracepoint_wildcard_no_matches)
{
  test_attach_points("tracepoint:type:typo_*,tracepoint:sched:sched_one {}",
                     { "tracepoint:sched:sched_one" });
}

class probe_expansion_btf : public test_btf {};

TEST(probe_expansion_btf, fentry_wildcard)
{
  test_attach_points("fentry:func_* {}",
                     { "fentry:vmlinux:func_1",
                       "fentry:vmlinux:func_2",
                       "fentry:vmlinux:func_3" });
}

TEST(probe_expansion_btf, fentry_wildcard_no_matches)
{
  test_attach_points("fentry:foo*,fentry:vmlinux:func_1 {}",
                     { "fentry:vmlinux:func_1" });
}

TEST(probe_expansion_btf, fentry_module_wildcard)
{
  test_attach_points("fentry:*:func_1 {}", { "fentry:vmlinux:func_1" });
}

TEST(probe_expansion_btf, fentry_bpf_id_wildcard)
{
  test_attach_points("fentry:bpf:123:func_* {}",
                     { "fentry:bpf:123:func_1", "fentry:bpf:123:func_2" });
}

TEST(probe_expansion_btf, rawtracepoint_wildcard)
{
  test_attach_points("rawtracepoint:event* {}",
                     { "rawtracepoint:vmlinux:event_rt" });
}

TEST(probe_expansion_btf, rawtracepoint_wildcard_no_matches)
{
  test_attach_points("rawtracepoint:foo*,rawtracepoint:event_rt {}",
                     { "rawtracepoint:vmlinux:event_rt" });
}

TEST(probe_expansion_btf, kprobe_session)
{
  test_multi_attach_points("kprobe:my_* {} kretprobe:my_* {}",
                           { "kprobe:my_*" },
                           { { "my_one", "my_two" } });
}

} // namespace bpftrace::test::probe_expansion
