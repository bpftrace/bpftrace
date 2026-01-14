#include "ast/passes/ap_probe_expansion.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast_matchers.h"
#include "btf_common.h"
#include "driver.h"
#include "mocks.h"
#include "gtest/gtest.h"

namespace bpftrace::test::ap_probe_expansion {

using bpftrace::test::AssignScalarMapStatement;
using bpftrace::test::Block;
using bpftrace::test::Builtin;
using bpftrace::test::ExprStatement;
using bpftrace::test::If;
using bpftrace::test::Integer;
using bpftrace::test::Map;
using bpftrace::test::Probe;
using bpftrace::test::Program;

template <typename MatcherT>
static void test(const std::string &prog,
                 const std::vector<std::string> &expected_aps,
                 const std::vector<std::set<std::string>> &expected_funcs,
                 const MatcherT &matcher,
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
      .add(ast::CreateProbeAndApExpansionPass());
  auto result = pm.run();
  ASSERT_TRUE(result && ast.diagnostics().ok());

  if (!expected_aps.empty()) {
    ASSERT_EQ(ast.root->probes.size(), expected_aps.size());
    for (size_t i = 0; i < expected_aps.size(); i++) {
      ASSERT_EQ(ast.root->probes.at(i)->attach_points.at(0)->name(),
                expected_aps.at(i));
    }
  }

  if (!expected_funcs.empty()) {
    auto &expansions = result->get<ast::ExpansionResult>();
    ASSERT_EQ(ast.root->probes.size(), expected_funcs.size());
    for (size_t i = 0; i < expected_funcs.size(); i++) {
      auto *ap = ast.root->probes.at(i)->attach_points.at(0);
      ASSERT_EQ(expansions.get_expanded_funcs(*ap), expected_funcs.at(i));
    }
  }

  EXPECT_THAT(ast, matcher);
}

static void test_attach_points(const std::string &input,
                               const std::vector<std::string> &expected_aps,
                               bool features = true)
{
  test(input, expected_aps, {}, _, features);
}

static void test_multi_attach_points(
    const std::string &input,
    const std::vector<std::string> &expected_aps,
    const std::vector<std::set<std::string>> &expected_funcs)
{
  test(input, expected_aps, expected_funcs, _, true);
}

template <typename MatcherT>
static void test_ast(const std::string &input, const MatcherT matcher)
{
  test(input, {}, {}, matcher, true);
}

TEST(ap_probe_expansion, session_ast)
{
  test_ast(
      "kprobe:sys_* { @entry = 1 } kretprobe:sys_* { @exit = 1 }",
      Program().WithProbe(Probe(
          { "kprobe:sys_*" },
          { ExprStatement(
              If(Call("__session_is_return", {}),
                 Block({ AssignScalarMapStatement(Map("@exit"), Integer(1)) },
                       None()),
                 Block({ AssignScalarMapStatement(Map("@entry"), Integer(1)) },
                       None()))) })));
}

TEST(ap_probe_expansion, kprobe_wildcard)
{
  // Disabled kprobe_multi - should get full expansion
  test_attach_points("kprobe:sys_read,kprobe:func_*,kprobe:sys_write {}",
                     { "kprobe:sys_read",
                       "kprobe:func_1",
                       "kprobe:func_2",
                       "kprobe:sys_write" },
                     false);
}

TEST(ap_probe_expansion, kprobe_multi_wildcard)
{
  test_multi_attach_points(
      "kprobe:sys_read,kprobe:func_*,kprobe:sys_write {}",
      { "kprobe:sys_read", "kprobe:func_*", "kprobe:sys_write" },
      { {}, { "func_1", "func_2" }, {} });
}

TEST(ap_probe_expansion, probe_builtin)
{
  // Even though kprobe_multi is enabled (by default), we should get full
  // expansion due to using the "probe" builtin.
  test_attach_points(
      "kprobe:sys_read,kprobe:func_*,kprobe:sys_write { __builtin_probe }",
      { "kprobe:sys_read",
        "kprobe:func_1",
        "kprobe:func_2",
        "kprobe:sys_write" });
}

TEST(ap_probe_expansion, kprobe_wildcard_no_matches)
{
  test_attach_points("kprobe:sys_read,kprobe:not_here_*,kprobe:sys_write {}",
                     { "kprobe:sys_read", "kprobe:sys_write" },
                     false);
}

TEST(ap_probe_expansion, krpobe_multi_wildcard_no_matches)
{
  test_attach_points("kprobe:sys_read,kprobe:not_here_*,kprobe:sys_write {}",
                     { "kprobe:sys_read", "kprobe:sys_write" });
}

TEST(ap_probe_expansion, kprobe_module_wildcard)
{
  // We leave kprobe_multi enabled here but it doesn't support the
  // module:function syntax so full expansion should be done anyways.
  test_attach_points("kprobe:kernel_mod_*:* {}",
                     { "kprobe:kernel_mod_1:mod_func_1",
                       "kprobe:kernel_mod_1:mod_func_2",
                       "kprobe:kernel_mod_2:mod_func_1" });
}

TEST(ap_probe_expansion, kprobe_module_function_wildcard)
{
  // We leave kprobe_multi enabled here but it doesn't support the
  // module:function syntax so full expansion should be done anyways.
  test_attach_points("kprobe:kernel_mod_1:mod_func_* {}",
                     { "kprobe:kernel_mod_1:mod_func_1",
                       "kprobe:kernel_mod_1:mod_func_2" });
}

TEST(ap_probe_expansion, uprobe_wildcard)
{
  // Disabled uprobe_multi - should get full expansion
  test_attach_points("uprobe:/bin/sh:*open {}",
                     { "uprobe:/bin/sh:first_open",
                       "uprobe:/bin/sh:second_open" },
                     false);
}

TEST(ap_probe_expansion, uprobe_multi_wildcard)
{
  test_multi_attach_points("uprobe:/bin/sh:*open {}",
                           { "uprobe:/bin/sh:*open" },
                           { { "/bin/sh:first_open", "/bin/sh:second_open" } });
}

TEST(ap_probe_expansion, uprobe_wildcard_file)
{
  // Disabled uprobe_multi - should get full expansion
  test_attach_points("uprobe:/bin/*sh:*open {}",
                     { "uprobe:/bin/bash:first_open",
                       "uprobe:/bin/sh:first_open",
                       "uprobe:/bin/sh:second_open" },
                     false);
}

TEST(ap_probe_expansion, uprobe_multi_wildcard_file)
{
  // Enabled uprobe_multi - targets should be expanded, functions shouldn't
  test_multi_attach_points("uprobe:/bin/*sh:*open {}",
                           { "uprobe:/bin/sh:*open", "uprobe:/bin/bash:*open" },
                           { { "/bin/sh:first_open", "/bin/sh:second_open" },
                             { "/bin/bash:first_open" } });
}

TEST(ap_probe_expansion, uprobe_wildcard_no_matches)
{
  test_attach_points("uprobe:/bin/sh:nonsense*,uprobe:/bin/sh:first_open {}",
                     { "uprobe:/bin/sh:first_open" },
                     false);
}

TEST(ap_probe_expansion, uprobe_wildcard_multi_no_matches)
{
  test_attach_points("uprobe:/bin/sh:nonsense*,uprobe:/bin/sh:first_open {}",
                     { "uprobe:/bin/sh:first_open" });
}

TEST(ap_probe_expansion, uprobe_cpp_symbol)
{
  test_attach_points("uprobe:/bin/sh:cpp:cpp_mangled {}",
                     { "uprobe:/bin/sh:cpp:_Z11cpp_mangledi",
                       "uprobe:/bin/sh:cpp:_Z11cpp_mangledv",
                       "uprobe:/bin/sh:cpp:cpp_mangled" },
                     false);
}

TEST(ap_probe_expansion, uprobe_cpp_symbol_full)
{
  test_attach_points("uprobe:/bin/sh:cpp:\"cpp_mangled(int)\" {}",
                     { "uprobe:/bin/sh:cpp:_Z11cpp_mangledi" },
                     false);
}

TEST(ap_probe_expansion, uprobe_cpp_symbol_wildcard)
{
  test_attach_points("uprobe:/bin/sh:cpp:cpp_mangled* {}",
                     { "uprobe:/bin/sh:cpp:_Z11cpp_mangledi",
                       "uprobe:/bin/sh:cpp:_Z11cpp_mangledv",
                       "uprobe:/bin/sh:cpp:_Z18cpp_mangled_suffixv",
                       "uprobe:/bin/sh:cpp:cpp_mangled" },
                     false);
}

TEST(ap_probe_expansion, uprobe_no_demangling)
{
  // Without the :cpp prefix, only look for non-mangled "cpp_mangled" symbol
  test_attach_points("uprobe:/bin/sh:cpp_mangled* {}",
                     { "uprobe:/bin/sh:cpp_mangled" },
                     false);
}

TEST(ap_probe_expansion, usdt_wildcard)
{
  test_attach_points("usdt:/bin/*sh:prov*:tp* {}",
                     { "usdt:/bin/bash:prov1:tp3",
                       "usdt:/bin/sh:prov1:tp1",
                       "usdt:/bin/sh:prov1:tp2",
                       "usdt:/bin/sh:prov2:tp" });
}

TEST(ap_probe_expansion, usdt_empty_namespace)
{
  test_attach_points("usdt:/bin/sh:tp1 {}", { "usdt:/bin/sh:prov1:tp1" });
}

TEST(ap_probe_expansion, tracepoint_wildcard)
{
  test_attach_points("tracepoint:sched:sched_* {}",
                     { "tracepoint:sched:sched_one",
                       "tracepoint:sched:sched_two" });
}

TEST(ap_probe_expansion, tracepoint_category_wildcard)
{
  test_attach_points("tracepoint:sched*:sched_* {}",
                     { "tracepoint:sched:sched_one",
                       "tracepoint:sched:sched_two",
                       "tracepoint:sched_extra:sched_extra" });
}

TEST(ap_probe_expansion, tracepoint_wildcard_no_matches)
{
  test_attach_points("tracepoint:type:typo_*,tracepoint:sched:sched_one {}",
                     { "tracepoint:sched:sched_one" });
}

class ap_probe_expansion_btf : public test_btf {};

TEST(ap_probe_expansion_btf, fentry_wildcard)
{
  test_attach_points("fentry:func_* {}",
                     { "fentry:mock_vmlinux:func_1",
                       "fentry:mock_vmlinux:func_2",
                       "fentry:mock_vmlinux:func_3",
                       "fentry:mock_vmlinux:func_anon_struct",
                       "fentry:mock_vmlinux:func_arrays",
                       "fentry:vmlinux:func_1",
                       "fentry:vmlinux:func_2",
                       "fentry:vmlinux:func_3" });
}

TEST(ap_probe_expansion_btf, fentry_wildcard_no_matches)
{
  test_attach_points("fentry:foo*,fentry:vmlinux:func_1 {}",
                     { "fentry:vmlinux:func_1" });
}

TEST(ap_probe_expansion_btf, fentry_module_wildcard)
{
  test_attach_points("fentry:*:func_1 {}",
                     { "fentry:mock_vmlinux:func_1", "fentry:vmlinux:func_1" });
}

TEST(ap_probe_expansion_btf, fentry_bpf_id_wildcard)
{
  test_attach_points("fentry:bpf:123:func_* {}",
                     { "fentry:bpf:123:func_1", "fentry:bpf:123:func_2" });
}

TEST(ap_probe_expansion_btf, rawtracepoint_wildcard)
{
  test_attach_points("rawtracepoint:event* {}",
                     { "rawtracepoint:module:event",
                       "rawtracepoint:vmlinux:event_rt" });
}

TEST(ap_probe_expansion_btf, rawtracepoint_wildcard_no_matches)
{
  test_attach_points("rawtracepoint:foo*,rawtracepoint:event_rt {}",
                     { "rawtracepoint:vmlinux:event_rt" });
}

TEST(ap_probe_expansion_btf, kprobe_session)
{
  test_multi_attach_points("kprobe:func_* {} kretprobe:func_* {}",
                           { "kprobe:func_*" },
                           { { "func_1", "func_2" } });
}

} // namespace bpftrace::test::ap_probe_expansion
