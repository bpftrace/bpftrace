#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>

#include "arch/arch.h"
#include "ast/ast.h"
#include "ast/passes/ap_probe_expansion.h"
#include "ast/passes/args_resolver.h"
#include "ast/passes/attachpoint_passes.h"
#include "ast/passes/builtins.h"
#include "ast/passes/c_macro_expansion.h"
#include "ast/passes/clang_parser.h"
#include "ast/passes/control_flow_analyser.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/fold_literals.h"
#include "ast/passes/import_scripts.h"
#include "ast/passes/loop_return.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/named_param.h"
#include "ast/passes/resolve_imports.h"
#include "ast/passes/type_checker.h"
#include "ast/passes/type_resolver.h"
#include "ast/passes/type_system.h"
#include "ast_matchers.h"
#include "bpftrace.h"
#include "btf_common.h"
#include "driver.h"
#include "mocks.h"
#include "struct.h"

namespace bpftrace::test::type_checker {

using bpftrace::test::AssignMapStatement;
using bpftrace::test::AssignVarStatement;
using bpftrace::test::Binop;
using bpftrace::test::Builtin;
using bpftrace::test::Cast;
using bpftrace::test::ExprStatement;
using bpftrace::test::FieldAccess;
using bpftrace::test::For;
using bpftrace::test::If;
using bpftrace::test::Integer;
using bpftrace::test::Map;
using bpftrace::test::MapAccess;
using bpftrace::test::NamedArgument;
using bpftrace::test::Probe;
using bpftrace::test::Program;
using bpftrace::test::Record;
using bpftrace::test::String;
using bpftrace::test::Tuple;
using bpftrace::test::Typeof;
using bpftrace::test::Variable;
using ::testing::_;
using ::testing::HasSubstr;

struct Mock {
  BPFtrace &bpftrace;
};
enum class UnsafeMode {
  Enable = 0, // Default is safe.
};
enum class NoFeatures {
  Enable = 0, // Default is full features.
};
struct Warning {
  std::string_view str;
};
struct NoWarning {
  std::string_view str;
};
struct Error {
  std::string_view str;
};
struct Types {
  ast::TypeMetadata &types;
};
struct ExpectedAST {
  ProgramMatcher matcher;
};

template <typename T, typename First, typename... Ts>
std::optional<T> extract(First &&arg, Ts &&...rest)
{
  if constexpr (std::is_same_v<std::decay_t<First>, T>) {
    // Assert that nothing in the rest matches T.
    static_assert(!(std::is_same_v<std::decay_t<Ts>, T> || ...),
                  "Only one argument of each type is allowed");
    return arg;
  }
  if constexpr (sizeof...(Ts) != 0) {
    return extract<T, Ts...>(std::forward<Ts>(rest)...);
  }
  return std::nullopt;
}

template <typename T>
std::optional<T> extract()
{
  return std::nullopt;
}

std::string_view clean_prefix(std::string_view view)
{
  while (!view.empty() && view[0] == '\n')
    view.remove_prefix(1); // Remove initial '\n'
  return view;
}

// This exists as a test fixture because the types may refer to `bpftrace`, so
// this objects lifetime must exceed the tests lifetime. This is easier with a
// fixture, and allows us to have a single harness.
class TypeCheckerHarness {
public:
  template <typename... Ts>
    requires((std::is_same_v<std::decay_t<Ts>, Mock> ||
              std::is_same_v<std::decay_t<Ts>, UnsafeMode> ||
              std::is_same_v<std::decay_t<Ts>, NoFeatures> ||
              std::is_same_v<std::decay_t<Ts>, Warning> ||
              std::is_same_v<std::decay_t<Ts>, NoWarning> ||
              std::is_same_v<std::decay_t<Ts>, Error> ||
              std::is_same_v<std::decay_t<Ts>, ExpectedAST> ||
              std::is_same_v<std::decay_t<Ts>, Types>) &&
             ...)
  ast::ASTContext test(std::string_view input, Ts &&...args)
  {
    ast::ASTContext ast("stdin", std::string(clean_prefix(input)));

    // Reset for each iteration. We only guarantee that the types remain
    // valid after the ASTContext has been returned.
    bpftrace_.reset();
    types_.reset();

    // Extract all extra arguments.
    auto mock = extract<Mock>(args...);
    auto unsafe_mode = extract<UnsafeMode>(args...);
    auto no_features = extract<NoFeatures>(args...);
    auto warning = extract<Warning>(args...);
    auto nowarning = extract<NoWarning>(args...);
    auto error = extract<Error>(args...);
    auto types = extract<Types>(args...);
    auto expected_ast = extract<ExpectedAST>(args...);

    if (!mock) {
      // Create a fresh instance.
      bpftrace_ = get_mock_bpftrace();
      mock.emplace(*bpftrace_);
    }
    mock->bpftrace.safe_mode_ = !unsafe_mode.has_value();
    mock->bpftrace.feature_ = std::make_unique<MockBPFfeature>(
        !no_features.has_value());
    if (!types) {
      types_.emplace();
      types.emplace(*types_);
    }

    auto ok = ast::PassManager()
                  .put(ast)
                  .put(mock->bpftrace)
                  .put(get_mock_function_info())
                  .put(types->types)
                  .add(CreateParsePass())
                  .add(ast::CreateResolveRootImportsPass())
                  .add(ast::CreateLoopReturnPass())
                  .add(ast::CreateControlFlowPass())
                  .add(ast::CreateImportInternalScriptsPass())
                  .add(ast::CreateMacroExpansionPass())
                  .add(ast::CreateParseAttachpointsPass())
                  .add(ast::CreateProbeAndApExpansionPass())
                  .add(ast::CreateArgsResolverPass())
                  .add(ast::CreateFieldAnalyserPass())
                  .add(ast::CreateClangParsePass())
                  .add(ast::CreateFoldLiteralsPass())
                  .add(ast::CreateBuiltinsPass())
                  .add(ast::CreateCMacroExpansionPass())
                  .add(ast::CreateMapSugarPass())
                  .add(ast::CreateNamedParamsPass())
                  .add(ast::CreateTypeResolverPass())
                  .add(ast::CreateTypeCheckerPass())
                  .run();
    EXPECT_TRUE(bool(ok));

    std::stringstream out;
    ast.diagnostics().emit(out, ast::Diagnostics::Severity::Warning);
    if (warning) {
      EXPECT_TRUE(!warning->str.empty());
      EXPECT_THAT(out.str(), HasSubstr(clean_prefix(warning->str)))
          << out.str();
    }
    if (nowarning) {
      EXPECT_TRUE(!nowarning->str.empty());
      EXPECT_THAT(out.str(), Not(HasSubstr(clean_prefix(nowarning->str))))
          << out.str();
    }
    out.str("");
    ast.diagnostics().emit(out, ast::Diagnostics::Severity::Error);
    const auto errstr = out.str();
    if (error) {
      if (!error->str.empty()) {
        EXPECT_THAT(errstr, HasSubstr(clean_prefix(error->str))) << errstr;
      } else {
        EXPECT_TRUE(!errstr.empty()) << errstr;
      }
    } else {
      EXPECT_EQ(errstr, "") << errstr;
    }
    out.str("");
    if (expected_ast) {
      EXPECT_THAT(ast, expected_ast->matcher);
    }

    return ast;
  }

private:
  std::unique_ptr<MockBPFtrace> bpftrace_;
  std::optional<ast::TypeMetadata> types_;
};

class TypeCheckerTest : public TypeCheckerHarness, public testing::Test {};

TEST_F(TypeCheckerTest, builtin_variables)
{
  // Just check that each one exists as a builtin or macro
  test("kprobe:f { pid }");
  test("kprobe:f { tid }");
  test("kprobe:f { cgroup }");
  test("kprobe:f { uid }");
  test("kprobe:f { username }");
  test("kprobe:f { gid }");
  test("kprobe:f { nsecs }");
  test("kprobe:f { elapsed }");
  test("kprobe:f { cpu }");
  test("kprobe:f { ncpus }");
  test("kprobe:f { rand }");
  test("kprobe:f { ctx }");
  test("kprobe:f { comm }");
  test("kprobe:f { kstack }");
  test("kprobe:f { ustack }");
  test("kprobe:f { arg0 }");
  test("kretprobe:f { retval }");
  test("kprobe:f { func }");
  test("uprobe:/bin/sh:f { func }");
  test("kprobe:f { probe }");
  test("kprobe:f { jiffies }");
  test("kprobe:f { cpid }");

  test("kprobe:f { fake }", Error{ R"(
stdin:1:12-16: ERROR: Unknown identifier: 'fake'
kprobe:f { fake }
           ~~~~
)" });

  test("fentry:f { func }", NoFeatures::Enable, Error{});
}

TEST_F(TypeCheckerTest, builtin_functions)
{
  // Just check that each function exists.
  // Each function should also get its own test case for more thorough testing
  test("kprobe:f { @x = hist(123) }");
  test("kprobe:f { @x = lhist(123, 0, 123, 1) }");
  test("kprobe:f { @x = tseries(3, 1s, 1) }");
  test("kprobe:f { @x = count() }");
  test("kprobe:f { @x = sum(pid) }");
  test("kprobe:f { @x = min(pid) }");
  test("kprobe:f { @x = max(pid) }");
  test("kprobe:f { @x = avg(pid) }");
  test("kprobe:f { @x = stats(pid) }");
  test("kprobe:f { @x = 1; print(@x) }");
  test("kprobe:f { @x = 1; clear(@x) }");
  test("kprobe:f { @x = 1; zero(@x) }");
  test("kprobe:f { @x = 1; @y[1] = 1; $a = is_scalar(@x); $b = is_scalar(@y); "
       "}");
  test("kprobe:f { time() }");
  test("kprobe:f { exit() }");
  test("kprobe:f { str(0xffff) }");
  test("kprobe:f { buf(0xffff, 1) }");
  test(R"(kprobe:f { printf("hello\n") })");
  test(R"(kprobe:f { system("ls\n") })", UnsafeMode::Enable);
  test("kprobe:f { join(0) }");
  test("kprobe:f { ksym(0xffff) }");
  test("kprobe:f { usym(0xffff) }");
  test("kprobe:f { kaddr(\"sym\") }");
  test("kprobe:f { ntop(0xffff) }");
  test("kprobe:f { ntop(2, 0xffff) }");
  test("kprobe:f { pton(\"127.0.0.1\") }");
  test("kprobe:f { pton(\"::1\") }");
  test("kprobe:f { pton(\"0000:0000:0000:0000:0000:0000:0000:0001\") }");
  test("kprobe:f { kstack(1) }");
  test("kprobe:f { ustack(1) }");
  test("kprobe:f { cat(\"/proc/uptime\") }");
  test("uprobe:/bin/sh:main { __builtin_uaddr(\"glob_asciirange\") }");
  test("kprobe:f { cgroupid(\"/sys/fs/cgroup/unified/mycg\"); }");
  test("kprobe:f { macaddr(0xffff) }");
  test("kprobe:f { nsecs() }");
  test("kprobe:f { pid() }");
  test("kprobe:f { tid() }");
}

TEST_F(TypeCheckerTest, undefined_map)
{
  test("kprobe:f / @mymap == 123 / { @mymap = 0 }");
  test("kprobe:f / @mymap == 123 / { 456; }", Error{ R"(
stdin:1:12-18: ERROR: Undefined map: @mymap
kprobe:f / @mymap == 123 / { 456; }
           ~~~~~~
)" });
  test("kprobe:f / @mymap1 == 1234 / { 1234; @mymap1 = @mymap2; }", Error{ R"(
stdin:1:48-55: ERROR: Undefined map: @mymap2
kprobe:f / @mymap1 == 1234 / { 1234; @mymap1 = @mymap2; }
                                               ~~~~~~~
)" });
  test("kprobe:f { print(@x); }", Error{ R"(
stdin:1:18-20: ERROR: Undefined map: @x
kprobe:f { print(@x); }
                 ~~
)" });
  test("kprobe:f { zero(@x); }", Error{ R"(
stdin:1:17-19: ERROR: Undefined map: @x
kprobe:f { zero(@x); }
                ~~
)" });
}

TEST_F(TypeCheckerTest, consistent_map_values)
{
  test("kprobe:f { @x = 0; @x = 1; }");
  test(
      R"(begin { $a = (3, "hello"); @m[1] = $a; $a = (1,"aaaaaaaaaa"); @m[2] = $a; })");
  test("kprobe:f { @x = 0; @x = \"a\"; }", Error{ R"(
stdin:1:20-28: ERROR: Type mismatch for @x: trying to assign value of type 'string[2]' when map already has a type 'uint8'
kprobe:f { @x = 0; @x = "a"; }
                   ~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, consistent_map_keys)
{
  test("begin { @x = 0; @x; }");
  test("begin { @x[1] = 0; @x[2]; }");
  test("begin { @x[@y] = 5; @y = 1;}");
  test("begin { @x[@y[@z]] = 5; @y[2] = 1; @z = @x[0]; }");
  test("begin { @y[1] = 0; @y[@x] = 2; @x = 1; }");

  test("begin { @x = 0; @x[1]; }", Error{ R"(
stdin:1:17-22: ERROR: @x used as a map with an explicit key (non-scalar map), previously used without an explicit key (scalar map)
begin { @x = 0; @x[1]; }
                ~~~~~
)" });
  test("begin { @x[1] = 0; @x; }", Error{ R"(
stdin:1:20-22: ERROR: @x used as a map without an explicit key (scalar map), previously used with an explicit key (non-scalar map)
begin { @x[1] = 0; @x; }
                   ~~
)" });

  test("begin { @x[1,2] = 0; @x[3,4]; }");
  test("begin { @x[1, 1] = 0; @x[(3, 4)]; }");
  test("begin { @x[1, ((int8)2, ((int16)3, 4))] = 0; @x[5, (6, (7, 8))]; }");

  test("begin { @x[1,2] = 0; @x[3]; }", Error{ R"(
stdin:1:25-26: ERROR: Argument mismatch for @x: trying to access with arguments: 'uint8' when map expects arguments: '(uint8,uint8)'
begin { @x[1,2] = 0; @x[3]; }
                        ~
)" });
  test("begin { @x[1] = 0; @x[2,3]; }", Error{ R"(
stdin:1:20-27: ERROR: Argument mismatch for @x: trying to access with arguments: '(uint8,uint8)' when map expects arguments: 'uint8'
begin { @x[1] = 0; @x[2,3]; }
                   ~~~~~~~
)" });

  test(R"(begin { @x[1,"a",kstack] = 0; @x[2,"b", kstack]; })");

  test(R"(
    begin {
      @x[1,"a",kstack] = 0;
      @x["b", 2, kstack];
    })",
       Error{ R"(
stdin:3:7-25: ERROR: Argument mismatch for @x: trying to access with arguments: '(string[2],uint8,kstack_bpftrace_127)' when map expects arguments: '(uint8,string[2],kstack_bpftrace_127)'
      @x["b", 2, kstack];
      ~~~~~~~~~~~~~~~~~~
)" });

  test("begin { @map[1, 2] = 1; for ($kv : @map) { @map[$kv.0] = 2; } }");

  test(R"(begin { @map[1, 2] = 1; for ($kv : @map) { @map[$kv.0.0] = 2; } })",
       Error{ R"(
stdin:1:55-56: ERROR: Argument mismatch for @map: trying to access with arguments: 'uint8' when map expects arguments: '(uint8,uint8)'
begin { @map[1, 2] = 1; for ($kv : @map) { @map[$kv.0.0] = 2; } }
                                                      ~
)" });

  test(R"(begin { $a = (3, "hi"); @map[1, "by"] = 1; @map[$a] = 2; })");
  test(R"(begin { @map[1, "hellohello"] = 1; @map[(3, "hi")] = 2; })");
  test(R"(begin { $a = (3, "hi"); @map[1, "hellohello"] = 1; @map[$a] = 2; })");
  test(
      R"(begin { $a = (3, "hello"); @m[$a] = 1; $a = (1,"aaaaaaaaaa"); @m[$a] = 2; })");
  test(
      R"(begin { $a = (3, "hi", 50); $b = "goodbye"; $c = (4, $b, 60); @map[$a] = 1; @map[$c] = 2; })");
  test(
      R"(begin { @["hi", ("hellolongstr", 2)] = 1; @["hellolongstr", ("hi", 5)] = 2; })");
  test(
      R"(begin { $a = (3, (uint64)1234); $b = (4, (uint8)5); @map[$a] = 1; @map[$b] = 2; })");
  test(
      R"(begin { $a = (3, (uint8)5); $b = (4, (uint64)1234); @map[$a] = 1; @map[$b] = 2; })");
}

TEST_F(TypeCheckerTest, if_statements)
{
  test("kprobe:f { if(true) { 123 } }");
  test("kprobe:f { if(false) { 123 } }");
  test("kprobe:f { if(1) { 123 } }");
  test("kprobe:f { if(1) { 123 } else { 456 } }");
  test("kprobe:f { if(0) { 123 } else if(1) { 456 } else { 789 } }");
  test("kprobe:f { if((int32)pid) { 123 } }");
}

TEST_F(TypeCheckerTest, predicate_expressions)
{
  test("kprobe:f / 999 / { 123 }");
  test("kprobe:f / true / { 123 }");
  test("kprobe:f / \"str\" / { 123 }");
  test("kprobe:f / kstack / { 123 }", Error{ R"(
stdin:1:10-20: ERROR: Invalid condition: kstack
kprobe:f / kstack / { 123 }
         ~~~~~~~~~~
)" });
  test("kprobe:f / @mymap / { @mymap = \"str\" }", Error{ R"(
stdin:1:10-20: ERROR: Invalid condition: string
kprobe:f / @mymap / { @mymap = "str" }
         ~~~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, ternary_expressions)
{
  // There are some supported types left out of this list
  // as they don't make sense or cause other errors e.g.
  // map aggregate functions and builtins
  std::unordered_map<std::string, std::string> supported_types = {
    { "1", "2" },
    { "true", "false" },
    { "\"lo\"", "\"high\"" },
    { "(\"hi\", 1)", "(\"bye\", 2)" },
    { "printf(\"lo\")", "exit()" },
    { "buf(\"mystr\", 5)", "buf(\"mystr\", 4)" },
    { "macaddr(arg0)", "macaddr(arg1)" },
    { "kstack(3)", "kstack(3)" },
    { "ustack(3)", "ustack(3)" },
    { "ustack(build_id, 3)", "ustack(build_id, 3)" },
    { "ntop(arg0)", "ntop(arg1)" },
    { "nsecs(boot)", "nsecs(monotonic)" },
    { "ksym(arg0)", "ksym(arg1)" },
    { "usym(arg0)", "usym(arg1)" },
    { "cgroup_path(1)", "cgroup_path(2)" },
    { "pid(curr_ns)", "pid(init)" },
    { "tid(curr_ns)", "tid(init)" },
  };

  for (const auto &[left, right] : supported_types) {
    test("kprobe:f { true ? " + left + " : " + right + " }");
  }

  test("kprobe:f { pid < 10000 ? printf(\"lo\") : exit() }");
  test(R"(kprobe:f { @x = pid < 10000 ? printf("lo") : cat("/proc/uptime") })",
       Error{});
  test("struct Foo { int x; } kprobe:f { true ? (struct Foo)*arg0 : "
       "(struct "
       "Foo)*arg1 }",
       Error{});
  test("struct Foo { int x; } kprobe:f { true ? (struct Foo*)arg0 : "
       "(struct "
       "Foo*)arg1 }");
  test(
      R"(kprobe:f { pid < 10000 ? ("a", "hellolongstr") : ("hellolongstr", "b") })",
      ExpectedAST{ Program().WithProbe(
          Probe({ "kprobe:f" },
                { ExprStatement(
                    If(Binop(Operator::LT, Builtin("pid"), Integer(10000)),
                       Block({ ExprStatement(Tuple(
                                   { String("a"), String("hellolongstr") })),
                               Jump(ast::JumpType::RETURN) }),
                       Block({ ExprStatement(Tuple(
                                   { String("hellolongstr"), String("b") })),
                               Jump(ast::JumpType::RETURN) }))) })) });

  // Error location is incorrect: #3063
  test("kprobe:f { $x = pid < 10000 ? 3 : cat(\"/proc/uptime\"); exit(); }",
       Error{ R"(
stdin:1:17-54: ERROR: Branches must return the same type: have 'uint8' and 'void'
kprobe:f { $x = pid < 10000 ? 3 : cat("/proc/uptime"); exit(); }
                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Error location is incorrect: #3063
  test("kprobe:f { @x = pid < 10000 ? 1 : \"high\" }", Error{ R"(
stdin:1:17-41: ERROR: Branches must return the same type: have 'uint8' and 'string[5]'
kprobe:f { @x = pid < 10000 ? 1 : "high" }
                ~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Error location is incorrect: #3063
  test("kprobe:f { @x = pid < 10000 ? \"lo\" : 2 }", Error{ R"(
stdin:1:17-39: ERROR: Branches must return the same type: have 'string[3]' and 'uint8'
kprobe:f { @x = pid < 10000 ? "lo" : 2 }
                ~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Error location is incorrect: #3063
  test("kprobe:f { @x = pid < 10000 ? (1, 2) : (\"a\", 4) }", Error{ R"(
stdin:1:17-48: ERROR: Branches must return the same type: have '(uint8,uint8)' and '(string[2],uint8)'
kprobe:f { @x = pid < 10000 ? (1, 2) : ("a", 4) }
                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Error location is incorrect: #3063
  test("kprobe:f { @x = pid < 10000 ? ustack(1) : ustack(2) }", Error{ R"(
stdin:1:17-52: ERROR: Branches must return the same type: have 'ustack_bpftrace_1' and 'ustack_bpftrace_2'
kprobe:f { @x = pid < 10000 ? ustack(1) : ustack(2) }
                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Error location is incorrect: #3063
  test("kprobe:f { @x = pid < 10000 ? kstack(raw) : kstack(perf) }", Error{ R"(
stdin:1:17-57: ERROR: Branches must return the same type: have 'kstack_raw_127' and 'kstack_perf_127'
kprobe:f { @x = pid < 10000 ? kstack(raw) : kstack(perf) }
                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, mismatched_call_types)
{
  test("kprobe:f { @x = 1; @x = count(); }", Error{ R"(
stdin:1:25-32: ERROR: Type mismatch for @x: trying to assign value of type 'count_t' when map already has a type 'uint8'
kprobe:f { @x = 1; @x = count(); }
                        ~~~~~~~
)" });
  test("kprobe:f { @x = count(); @x "
       "= sum(pid); }",
       Error{ R"(
stdin:1:31-39: ERROR: Type mismatch for @x: trying to assign value of type 'usum_t' when map already has a type 'count_t'
kprobe:f { @x = count(); @x = sum(pid); }
                              ~~~~~~~~
)" });
  test("kprobe:f { @x = 1; @x = hist(0); }", Error{ R"(
stdin:1:25-32: ERROR: Type mismatch for @x: trying to assign value of type 'hist_t' when map already has a type 'uint8'
kprobe:f { @x = 1; @x = hist(0); }
                        ~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, compound_left)
{
  test("kprobe:f { $a = 0; $a <<= 1 }");
  test("kprobe:f { @a <<= 1 }");
}

TEST_F(TypeCheckerTest, compound_right)
{
  test("kprobe:f { $a = 0; $a >>= 1 }");
  test("kprobe:f { @a >>= 1 }");
}

TEST_F(TypeCheckerTest, compound_plus)
{
  test("kprobe:f { $a = 0; $a += 1 }");
  test("kprobe:f { @a += 1 }");
}

TEST_F(TypeCheckerTest, compound_minus)
{
  test("kprobe:f { $a = 0; $a -= 1 }");
  test("kprobe:f { @a -= 1 }");
}

TEST_F(TypeCheckerTest, compound_mul)
{
  test("kprobe:f { $a = 0; $a *= 1 }");
  test("kprobe:f { @a *= 1 }");
}

TEST_F(TypeCheckerTest, compound_div)
{
  test("kprobe:f { $a = 0; $a /= 1 }");
  test("kprobe:f { @a /= 1 }");
}

TEST_F(TypeCheckerTest, compound_mod)
{
  test("kprobe:f { $a = 0; $a %= 1 }");
  test("kprobe:f { @a %= 1 }");
}

TEST_F(TypeCheckerTest, compound_band)
{
  test("kprobe:f { $a = 0; $a &= 1 }");
  test("kprobe:f { @a &= 1 }");
}

TEST_F(TypeCheckerTest, compound_bor)
{
  test("kprobe:f { $a = 0; $a |= 1 }");
  test("kprobe:f { @a |= 1 }");
}

TEST_F(TypeCheckerTest, compound_bxor)
{
  test("kprobe:f { $a = 0; $a ^= 1 }");
  test("kprobe:f { @a ^= 1 }");
}

TEST_F(TypeCheckerTest, call_hist)
{
  test("kprobe:f { @x = hist(1); }");
  test("kprobe:f { @x = hist(1, 0); }");
  test("kprobe:f { @x = hist(1, 5); }");
  test("kprobe:f { $n = 3; @x = hist(1, $n); }", Error{ R"(
stdin:1:25-36: ERROR: hist() expects a int literal (int provided)
kprobe:f { $n = 3; @x = hist(1, $n); }
                        ~~~~~~~~~~~
)" });
  test("kprobe:f { hist(1); }", Error{ R"(
stdin:1:12-19: ERROR: hist() must be assigned directly to a map
kprobe:f { hist(1); }
           ~~~~~~~
)" });
  test("kprobe:f { $x = hist(1); }", Error{ R"(
stdin:1:17-24: ERROR: hist() must be assigned directly to a map
kprobe:f { $x = hist(1); }
                ~~~~~~~
)" });
  test("kprobe:f { @x[hist(1)] = 1; }", Error{ R"(
stdin:1:15-22: ERROR: hist() must be assigned directly to a map
kprobe:f { @x[hist(1)] = 1; }
              ~~~~~~~
)" });
  test("kprobe:f { if(hist()) { 123 } }", Error{ R"(
stdin:1:15-21: ERROR: hist() must be assigned directly to a map
kprobe:f { if(hist()) { 123 } }
              ~~~~~~
)" });
  test("kprobe:f { hist() ? 0 : 1; }", Error{ R"(
stdin:1:12-18: ERROR: hist() must be assigned directly to a map
kprobe:f { hist() ? 0 : 1; }
           ~~~~~~
)" });
}

TEST_F(TypeCheckerTest, call_lhist)
{
  test("kprobe:f { @ = lhist(5, 0, 10, 1); "
       "}");
  test("kprobe:f { lhist(-10, -10, 10, 1); }", Error{ R"(
stdin:1:12-34: ERROR: lhist() must be assigned directly to a map
kprobe:f { lhist(-10, -10, 10, 1); }
           ~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { $x = lhist(); }", Error{ R"(
stdin:1:17-24: ERROR: lhist() must be assigned directly to a map
kprobe:f { $x = lhist(); }
                ~~~~~~~
)" });
  test("kprobe:f { @[lhist()] = 1; }", Error{ R"(
stdin:1:14-21: ERROR: lhist() must be assigned directly to a map
kprobe:f { @[lhist()] = 1; }
             ~~~~~~~
)" });
  test("kprobe:f { if(lhist()) { 123 } }", Error{ R"(
stdin:1:15-22: ERROR: lhist() must be assigned directly to a map
kprobe:f { if(lhist()) { 123 } }
              ~~~~~~~
)" });
  test("kprobe:f { lhist() ? 0 : 1; }", Error{ R"(
stdin:1:12-19: ERROR: lhist() must be assigned directly to a map
kprobe:f { lhist() ? 0 : 1; }
           ~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, call_tseries)
{
  test("kprobe:f { @ = tseries(5, 10s, 1); }");
  test("kprobe:f { @ = tseries(-5, 10s, 1); }");
  test("kprobe:f { tseries(5, 10s, 1); }", Error{ R"(
stdin:1:12-30: ERROR: tseries() must be assigned directly to a map
kprobe:f { tseries(5, 10s, 1); }
           ~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { $x = tseries(); }", Error{ R"(
stdin:1:17-26: ERROR: tseries() must be assigned directly to a map
kprobe:f { $x = tseries(); }
                ~~~~~~~~~
)" });
  test("kprobe:f { @[tseries()] = 1; }", Error{ R"(
stdin:1:14-23: ERROR: tseries() must be assigned directly to a map
kprobe:f { @[tseries()] = 1; }
             ~~~~~~~~~
)" });
  test("kprobe:f { if(tseries()) { 123 } }", Error{ R"(
stdin:1:15-24: ERROR: tseries() must be assigned directly to a map
kprobe:f { if(tseries()) { 123 } }
              ~~~~~~~~~
)" });
  test("kprobe:f { tseries() ? 0 : 1; }", Error{ R"(
stdin:1:12-21: ERROR: tseries() must be assigned directly to a map
kprobe:f { tseries() ? 0 : 1; }
           ~~~~~~~~~
)" });
  test("kprobe:f { @ = tseries(-1, 10s, 5); }");
  // Good duration strings.
  test("kprobe:f { @ = tseries(1, 10ns, 5); }");
  test("kprobe:f { @ = tseries(1, 10us, 5); }");
  test("kprobe:f { @ = tseries(1, 10ms, 5); }");
  test("kprobe:f { @ = tseries(1, 10s, 5); }");
}

TEST_F(TypeCheckerTest, call_count)
{
  test("kprobe:f { @x = count(); }");
  test("kprobe:f { count(); }", Error{});
  test("kprobe:f { $x = count(); }", Error{});
  test("kprobe:f { @[count()] = 1; }", Error{});
  test("kprobe:f { if(count()) { 123 } }", Error{});
  test("kprobe:f { count() ? 0 : 1; }", Error{});
}

TEST_F(TypeCheckerTest, call_sum)
{
  test("kprobe:f { @x = sum(123); }");
  test("kprobe:f { sum(123); }", Error{});
  test("kprobe:f { $x = sum(123); }", Error{});
  test("kprobe:f { @[sum(123)] = 1; }", Error{});
  test("kprobe:f { if(sum(1)) { 123 } }", Error{});
  test("kprobe:f { sum(1) ? 0 : 1; }", Error{});
}

TEST_F(TypeCheckerTest, call_min)
{
  test("kprobe:f { @x = min(123); }");
  test("kprobe:f { min(123); }", Error{});
  test("kprobe:f { $x = min(123); }", Error{});
  test("kprobe:f { @[min(123)] = 1; }", Error{});
  test("kprobe:f { if(min(1)) { 123 } }", Error{});
  test("kprobe:f { min(1) ? 0 : 1; }", Error{});
}

TEST_F(TypeCheckerTest, call_max)
{
  test("kprobe:f { @x = max(123); }");
  test("kprobe:f { max(123); }", Error{});
  test("kprobe:f { $x = max(123); }", Error{});
  test("kprobe:f { @[max(123)] = 1; }", Error{});
  test("kprobe:f { if(max(1)) { 123 } }", Error{});
  test("kprobe:f { max(1) ? 0 : 1; }", Error{});
}

TEST_F(TypeCheckerTest, call_avg)
{
  test("kprobe:f { @x = avg(123); }");
  test("kprobe:f { avg(123); }", Error{});
  test("kprobe:f { $x = avg(123); }", Error{});
  test("kprobe:f { @[avg(123)] = 1; }", Error{});
  test("kprobe:f { if(avg(1)) { 123 } }", Error{});
  test("kprobe:f { avg(1) ? 0 : 1; }", Error{});
}

TEST_F(TypeCheckerTest, call_stats)
{
  test("kprobe:f { @x = stats(123); }");
  test("kprobe:f { stats(123); }", Error{});
  test("kprobe:f { $x = stats(123); }", Error{});
  test("kprobe:f { @[stats(123)] = 1; }", Error{});
  test("kprobe:f { if(stats(1)) { 123 } }", Error{});
  test("kprobe:f { stats(1) ? 0 : 1; }", Error{});
}

TEST_F(TypeCheckerTest, call_delete)
{
  ast::TypeMetadata types;

  auto vd_ty = types.global.lookup<btf::Void>("void");
  ASSERT_TRUE(bool(vd_ty));
  auto vd_ptr = types.global.add<btf::Pointer>(*vd_ty);
  ASSERT_TRUE(bool(vd_ptr));

  auto long_ty = types.global.add<btf::Integer>("long", 4, 0);
  ASSERT_TRUE(bool(long_ty));

  std::vector<std::pair<std::string, btf::ValueType>> args = {
    { "map", btf::ValueType(*vd_ptr) }, { "key", btf::ValueType(*vd_ptr) }
  };

  auto delete_proto = types.global.add<btf::FunctionProto>(
      btf::ValueType(*long_ty), args);
  ASSERT_TRUE(bool(delete_proto));

  auto delete_func = types.global.add<btf::Function>(
      "__delete", btf::Function::Linkage::Global, *delete_proto);
  ASSERT_TRUE(bool(delete_func));

  test("kprobe:f { @x = 1; delete(@x); }", Types{ types });
  test("kprobe:f { @y[5] = 5; delete(@y, "
       "5); }",
       Types{ types });
  test("kprobe:f { @a[1] = 1; delete(@a, "
       "@a[1]); }",
       Types{ types });
  test("kprobe:f { @a = 1; @b[2] = 2; "
       "delete(@b, @a); }",
       Types{ types });
  test("kprobe:f { @a[1] = 1; $x = 1; "
       "delete(@a, $x); }",
       Types{ types });
  test(R"(kprobe:f { @y["hi"] = 5; delete(@y, "longerstr"); })",
       Types{ types });
  test(R"(kprobe:f { @y["hi", 5] = 5; delete(@y, ("hi", 5)); })",
       Types{ types });
  test(R"(kprobe:f { @y["longerstr", 5] = 5; delete(@y, ("hi", 5)); })",
       Types{ types });
  test(R"(kprobe:f { @y["hi", 5] = 5; delete(@y, ("longerstr", 5)); })",
       Types{ types });
  test("kprobe:f { @y[(3, 4, 5)] = 5; "
       "delete(@y, (1, 2, 3)); }",
       Types{ types });
  test("kprobe:f { @y[((int8)3, 4, 5)] = "
       "5; delete(@y, (1, 2, 3)); }",
       Types{ types });
  test("kprobe:f { @y[(3, 4, 5)] = 5; "
       "delete(@y, ((int8)1, 2, 3)); }",
       Types{ types });
  test("kprobe:f { @x = 1; @y = "
       "delete(@x); }",
       Types{ types });
  test("kprobe:f { @x = 1; $y = "
       "delete(@x); }",
       Types{ types });
  test("kprobe:f { @x = 1; @[delete(@x)] = "
       "1; }",
       Types{ types });
  test("kprobe:f { @x = 1; if(delete(@x)) "
       "{ 123 } }",
       Types{ types });
  test("kprobe:f { @x = 1; delete(@x) ? 0 "
       ": 1; }",
       Types{ types });
  // The second arg gets treated like a map
  // key, in terms of int type adjustment
  test("kprobe:f { @y[5] = 5; delete(@y, "
       "(int8)5); }",
       Types{ types });
  test("kprobe:f { @y[5, 4] = 5; delete(@y, "
       "((int8)5, (int32)4)); }",
       Types{ types });

  test("kprobe:f { delete(1); }", Error{}, Types{ types });
  test("kprobe:f { delete(1, 1); }", Error{}, Types{ types });

  test("kprobe:f { @y[(3, 4, 5)] = "
       "5; delete(@y, (1, 2)); }",
       Error{ R"(
ERROR: Type mismatch for $$delete_$key: trying to assign value of type '(uint8,uint8)' when variable already has a type '(uint8,uint8,uint8)'
)" },
       Types{ types });

  test("kprobe:f { @y[1] = 2; delete(@y); }", Error{}, Types{ types });
  test("kprobe:f { @a[1] = 1; "
       "delete(@a, @a); }",
       Error{ R"(
ERROR: @a used as a map without an explicit key (scalar map), previously used with an explicit key (non-scalar map)
)" },
       Types{ types });

  // Deprecated API
  test("kprobe:f { @x = 1; delete(@x); }", Types{ types });
  test("kprobe:f { @y[5] = 5; "
       "delete(@y[5]); }",
       Types{ types });
  test(R"(kprobe:f { @y[1, "hi"] = 5; delete(@y[1, "longerstr"]); })",
       Types{ types });
  test(R"(kprobe:f { @y[1, "longerstr"] = 5; delete(@y[1, "hi"]); })",
       Types{ types });

  test("kprobe:f { @x = 1; @y = 5; "
       "delete(@x, @y); }",
       Error{ R"(
ERROR: call to delete() with two arguments expects a map with explicit keys (non-scalar map)
)" },
       Types{ types });

  test(R"(kprobe:f { @x[1, "hi"] = 1; delete(@x["hi", 1]); })",
       Error{ R"(
ERROR: Type mismatch for $$delete_$key: trying to assign value of type '(string[3],uint8)' when variable already has a type '(uint8,string[3])'
)" },
       Types{ types });

  test("kprobe:f { @x[0] = 1; @y[5] = 5; "
       "delete(@x, @y[5], @y[6]); }",
       Error{},
       Types{ types });

  test("kprobe:f { @x = 1; delete(@x[1]); }", Error{}, Types{ types });
}

TEST_F(TypeCheckerTest, call_exit)
{
  test("kprobe:f { exit(); }");
  test("kprobe:f { exit(1); }");
  test("kprobe:f { $a = 1; exit($a); }");
  test("kprobe:f { @a = exit(); }", Error{});
  test("kprobe:f { @a = exit(1); }", Error{});
  test("kprobe:f { $a = exit(1); }", Error{});
  test("kprobe:f { @[exit(1)] = 1; }", Error{});
  test("kprobe:f { if(exit()) { 123 } }", Error{});
  test("kprobe:f { exit() ? 0 : 1; }", Error{});

  test("kprobe:f { $a = \"1\"; exit($a); }", Error{ R"(
stdin:1:22-30: ERROR: exit() only supports int arguments (string provided)
kprobe:f { $a = "1"; exit($a); }
                     ~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, call_print)
{
  test("kprobe:f { @x = count(); print(@x); }");
  test("kprobe:f { @x = count(); print(@x, 5); }");
  test("kprobe:f { @x = count(); print(@x, 5, 10); }");
  test("kprobe:f { @x = count(); @x = print(1); }", Error{});

  test("kprobe:f { print(@x); @x[1,2] = count(); }");
  test("kprobe:f { @x[1,2] = count(); print(@x); }");

  test("kprobe:f { @x = count(); @ = print(@x); }", Error{});
  test("kprobe:f { @x = count(); $y = print(@x); }", Error{});
  test("kprobe:f { @x = count(); @[print(@x)] = 1; }", Error{});
  test("kprobe:f { @x = count(); if(print(@x)) { 123 } }", Error{});
  test("kprobe:f { @x = count(); print(@x) ? 0 : 1; }", Error{});

  test("kprobe:f { @x = stats(10); print(@x, 2); }",
       Warning{ "top and div arguments are ignored" });
  test("kprobe:f { @x = stats(10); print(@x, 2, 3); }",
       Warning{ "top and div arguments are ignored" });
}

TEST_F(TypeCheckerTest, call_print_map_item)
{
  test(R"_(begin { @x[1] = 1; print(@x[1]); })_");
  test(R"_(begin { @x[1] = 1; @x[2] = 2; print(@x[2]); })_");
  test(R"_(begin { @x[1] = 1; print(@x[2]); })_");
  test(R"_(begin { @x[3, 5] = 1; print(@x[3, 5]); })_");
  test(R"_(begin { @x[1,2] = "asdf"; print((1, 2, @x[1,2])); })_");

  test("begin { @x[1] = 1; print(@x[\"asdf\"]); }", Error{ R"(
stdin:1:34-35: ERROR: Argument mismatch for @x: trying to access with arguments: 'string[5]' when map expects arguments: 'uint8'
begin { @x[1] = 1; print(@x["asdf"]); }
                                 ~
)" });
  test("begin { print(@x[2]); }", Error{ R"(
stdin:1:15-20: ERROR: Undefined map: @x
begin { print(@x[2]); }
              ~~~~~
)" });
  test("begin { @x[1] = 1; print(@x[1], 3, 5); }", Error{ R"(
stdin:1:20-38: ERROR: Non-map print() only takes 1 argument, 3 found
begin { @x[1] = 1; print(@x[1], 3, 5); }
                   ~~~~~~~~~~~~~~~~~~
)" });
  test("begin { @x[1] = hist(10); print(@x[1]); }", Error{ R"(
stdin:1:27-39: ERROR: Map type hist_t cannot print the value of individual keys. You must print the whole map.
begin { @x[1] = hist(10); print(@x[1]); }
                          ~~~~~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, call_print_non_map)
{
  test(R"(begin { print(1) })");
  test(R"(begin { print(comm) })");
  test(R"(begin { print(nsecs) })");
  test(R"(begin { print("string") })");
  test(R"(begin { print((1, 2, "tuple")) })");
  test(R"(begin { $x = 1; print($x) })");
  test(R"(begin { $x = 1; $y = $x + 3; print($y) })");
  test(R"(begin { print((int8 *)0) })");

  test(R"(begin { print(3, 5) })", Error{});
  test(R"(begin { print(3, 5, 2) })", Error{});

  test(R"(begin { print(exit()) })", Error{});
  test(R"(begin { print(count()) })", Error{});
  test(R"(begin { print(ctx) })", Error{});
}

TEST_F(TypeCheckerTest, call_clear)
{
  test("kprobe:f { @x = count(); clear(@x); }");
  test("kprobe:f { @x = count(); @x = clear(); }", Error{});

  test("kprobe:f { clear(@x); @x[1,2] = count(); }");
  test("kprobe:f { @x[1,2] = count(); clear(@x); }");
  test("kprobe:f { @x[1,2] = count(); clear(@x[3,4]); }", Error{});

  test("kprobe:f { @x = count(); @ = clear(@x); }", Error{});
  test("kprobe:f { @x = count(); $y = clear(@x); }", Error{});
  test("kprobe:f { @x = count(); @[clear(@x)] = 1; }", Error{});
  test("kprobe:f { @x = count(); if(clear(@x)) { 123 } }", Error{});
  test("kprobe:f { @x = count(); clear(@x) ? 0 : 1; }", Error{});
}

TEST_F(TypeCheckerTest, call_zero)
{
  test("kprobe:f { @x = count(); zero(@x); }");
  test("kprobe:f { @x = count(); @x = zero(); }", Error{});

  test("kprobe:f { zero(@x); @x[1,2] = count(); }");
  test("kprobe:f { @x[1,2] = count(); zero(@x); }");
  test("kprobe:f { @x[1,2] = count(); zero(@x[3,4]); }", Error{});

  test("kprobe:f { @x = count(); @ = zero(@x); }", Error{});
  test("kprobe:f { @x = count(); $y = zero(@x); }", Error{});
  test("kprobe:f { @x = count(); @[zero(@x)] = 1; }", Error{});
  test("kprobe:f { @x = count(); if(zero(@x)) { 123 } }", Error{});
  test("kprobe:f { @x = count(); zero(@x) ? 0 : 1; }", Error{});
}

TEST_F(TypeCheckerTest, call_has_key)
{
  ast::TypeMetadata types;

  auto vd_ty = types.global.lookup<btf::Void>("void");
  ASSERT_TRUE(bool(vd_ty));
  auto vd_ptr = types.global.add<btf::Pointer>(*vd_ty);
  ASSERT_TRUE(bool(vd_ptr));

  std::vector<std::pair<std::string, btf::ValueType>> args = {
    { "map", btf::ValueType(*vd_ptr) }, { "key", btf::ValueType(*vd_ptr) }
  };

  auto lookup_elem_proto = types.global.add<btf::FunctionProto>(
      btf::ValueType(*vd_ptr), args);
  ASSERT_TRUE(bool(lookup_elem_proto));

  auto lookup_elem_func = types.global.add<btf::Function>(
      "__lookup_elem", btf::Function::Linkage::Global, *lookup_elem_proto);
  ASSERT_TRUE(bool(lookup_elem_func));

  test("kprobe:f { @x[1] = 0; if "
       "(has_key(@x, 1)) {} }",
       Types{ types });
  test("kprobe:f { @x[1, 2] = 0; if "
       "(has_key(@x, (3, 4))) {} }",
       Types{ types });
  test("kprobe:f { @x[1, (int8)2] = 0; if "
       "(has_key(@x, (3, 4))) {} }",
       Types{ types });
  test(R"(kprobe:f { @x[1, "hi"] = 0; if (has_key(@x, (2, "bye"))) {} })",
       Types{ types });
  test(R"(kprobe:f { @x[1, "hi"] = 0; if (has_key(@x, (2, "longerstr"))) {} })",
       Types{ types });
  test(R"(kprobe:f { @x[1, "longerstr"] = 0; if (has_key(@x, (2, "hi"))) {} })",
       Types{ types });
  test("kprobe:f { @x[1, 2] = 0; $a = (3, "
       "4); if (has_key(@x, $a)) {} }",
       Types{ types });
  test("kprobe:f { @x[1, 2] = 0; @a = (3, "
       "4); if (has_key(@x, @a)) {} }",
       Types{ types });
  test("kprobe:f { @x[1, 2] = 0; @a[1] = "
       "(3, 4); if (has_key(@x, @a[1])) {} "
       "}",
       Types{ types });
  test("kprobe:f { @x[1] = 0; @a = "
       "has_key(@x, 1); }",
       Types{ types });
  test("kprobe:f { @x[1] = 0; $a = "
       "has_key(@x, 1); }",
       Types{ types });
  test("kprobe:f { @x[1] = 0; "
       "@a[has_key(@x, 1)] = 1; }",
       Types{ types });

  test("kprobe:f { @x[1] = 1;  if (has_key(@x)) {} }", Error{}, Types{ types });
  test("kprobe:f { @x[1] = 1;  if (has_key(@x[1], 1)) {} }",
       Error{},
       Types{ types });
  test("kprobe:f { @x = 1;  if (has_key(@x, 1)) {} }", Error{}, Types{ types });
  test("kprobe:f { @x[1] = 1; $a = 1; if (has_key($a, 1)) {} }",
       Error{},
       Types{ types });

  test(
      "kprobe:f { @x[1, 2] = 1;  if (has_key(@x, 1)) {} }",
      Error{
          R"(ERROR: Type mismatch for $$has_key_$key: trying to assign value of type 'uint8' when variable already has a type '(uint8,uint8)')" },
      Types{ types });

  test(
      R"(kprobe:f { @x[1, "hi"] = 0; if (has_key(@x, (2, 1))) {} })",
      Error{
          R"(ERROR: Type mismatch for $$has_key_$key: trying to assign value of type '(uint8,uint8)' when variable already has a type '(uint8,string[3])')" },
      Types{ types });

  test("kprobe:f { @a[1] = 1; has_key(@a, @a); }",
       Error{ R"(
stdin:1:35-37: ERROR: @a used as a map without an explicit key (scalar map), previously used with an explicit key (non-scalar map)
kprobe:f { @a[1] = 1; has_key(@a, @a); }
                                  ~~
)" },
       Types{ types });
}

// N.B. find uses mostly the same implementation as has_key
TEST_F(TypeCheckerTest, call_find)
{
  ast::TypeMetadata types;

  auto vd_ty = types.global.lookup<btf::Void>("void");
  ASSERT_TRUE(bool(vd_ty));
  auto vd_ptr = types.global.add<btf::Pointer>(*vd_ty);
  ASSERT_TRUE(bool(vd_ptr));

  std::vector<std::pair<std::string, btf::ValueType>> args = {
    { "map", btf::ValueType(*vd_ptr) }, { "key", btf::ValueType(*vd_ptr) }
  };

  auto lookup_elem_proto = types.global.add<btf::FunctionProto>(
      btf::ValueType(*vd_ptr), args);
  ASSERT_TRUE(bool(lookup_elem_proto));

  auto lookup_elem_func = types.global.add<btf::Function>(
      "__lookup_elem", btf::Function::Linkage::Global, *lookup_elem_proto);
  ASSERT_TRUE(bool(lookup_elem_func));

  test("kprobe:f { @x[1] = 0; let $y; if "
       "(find(@x, 1, $y)) {} }",
       Types{ types });
  test("kprobe:f { @x[1, 2] = 0; let $y; if "
       "(find(@x, (3, 4), $y)) {} }",
       Types{ types });
  test("kprobe:f { @x[1, (int8)2] = 0; let $y; if "
       "(find(@x, (3, 4), $y)) {} }",
       Types{ types });
  test("kprobe:f { @x[1] = (uint16)1; $y = (int16)2; if "
       "(find(@x, 1, $y)) {} }",
       Types{ types });
  test(
      R"(kprobe:f { @x[1, "hi"] = 0; let $y; if (find(@x, (2, "bye"), $y)) {} })",
      Types{ types });
  test(
      R"(kprobe:f { @x[1, "hi"] = 0; let $y; if (find(@x, (2, "longerstr"), $y)) {} })",
      Types{ types });
  test(
      R"(kprobe:f { @x[1, "longerstr"] = 0; let $y; if (find(@x, (2, "hi"), $y)) {} })",
      Types{ types });
  test(
      R"(kprobe:f { @x[1, "hi"] = "reallylongstr"; $y = "hi"; if (find(@x, (2, "longerstr"), $y)) {} })",
      Types{ types });
  test("kprobe:f { @x[1, 2] = 0; $a = (3, "
       "4); let $y; if (find(@x, $a, $y)) {} }",
       Types{ types });
  test("kprobe:f { @x[1, 2] = 0; @a = (3, "
       "4); let $y; if (find(@x, @a, $y)) {} }",
       Types{ types });
  test("kprobe:f { @x[1, 2] = 0; @a[1] = "
       "(3, 4); let $y; if (find(@x, @a[1], $y)) {} "
       "}",
       Types{ types });

  test(
      R"(kprobe:f { @x[1, "hi"] = 0; $y = "hello"; if (find(@x, (2, "longerstr"), $y)) {} })",
      Error{},
      Types{ types });
  test("kprobe:f { @x[1] = 1; let $y; if (find(@x)) {} }",
       Error{},
       Types{ types });
  test("kprobe:f { @x[1] = 1; let $y; if (find(@x, 1)) {} }",
       Error{},
       Types{ types });
  test("kprobe:f { @x[1] = 1; let $y; if (find(@x[1], 1, $y)) {} }",
       Error{},
       Types{ types });
  test("kprobe:f { @x = 1; let $y; if (find(@x, 1, $y)) {} }",
       Error{},
       Types{ types });
  test("kprobe:f { @x[1] = 1; $a = 1; let $y; if (find($a, 1, $y)) {} }",
       Error{},
       Types{ types });

  test("kprobe:f { @x[1, 2] = 1; let $y; if (find(@x, 1, $y)) {} }",
       Error{},
       Types{ types });

  test(R"(kprobe:f { @x[1, "hi"] = 0; let $y; if (find(@x, (2, 1), $y)) {} })",
       Error{},
       Types{ types });
}

TEST_F(TypeCheckerTest, call_time)
{
  test("kprobe:f { time(); }");
  test("kprobe:f { time(\"%M:%S\"); }");
  test("kprobe:f { @x = time(); }", Error{});
  test("kprobe:f { $x = time(); }", Error{});
  test("kprobe:f { @[time()] = 1; }", Error{});
  test("kprobe:f { time(1); }", Error{});
  test("kprobe:f { $x = \"str\"; time($x); }", Error{});
  test("kprobe:f { if(time()) { 123 } }", Error{});
  test("kprobe:f { time() ? 0 : 1; }", Error{});
}

TEST_F(TypeCheckerTest, call_strftime)
{
  test("kprobe:f { strftime(\"%M:%S\", 1); }");
  test("kprobe:f { strftime(\"%M:%S\", nsecs); }");
  test(R"(kprobe:f { strftime("%M:%S", ""); })", Error{});
  test("kprobe:f { strftime(1, nsecs); }", Error{});
  test("kprobe:f { $var = \"str\"; strftime($var, nsecs); }", Error{});
  test("kprobe:f { $ts = strftime(\"%M:%S\", 1); }");
  test("kprobe:f { @ts = strftime(\"%M:%S\", nsecs); }");
  test("kprobe:f { @[strftime(\"%M:%S\", nsecs)] = 1; }");
  test(R"(kprobe:f { printf("%s", strftime("%M:%S", nsecs)); })");
  test(R"(kprobe:f { strncmp("str", strftime("%M:%S", nsecs), 10); })",
       Error{});

  test("kprobe:f { strftime(\"%M:%S\", nsecs(monotonic)); }", Error{});
  test("kprobe:f { strftime(\"%M:%S\", nsecs(boot)); }");
  test("kprobe:f { strftime(\"%M:%S\", nsecs(tai)); }");
}

TEST_F(TypeCheckerTest, call_str)
{
  test("kprobe:f { str(arg0); }");
  test("kprobe:f { @x = str(arg0); }");
  test("kprobe:f { str(\"hello\"); }");
}

TEST_F(TypeCheckerTest, call_str_2_lit)
{
  test("kprobe:f { str(arg0, 3); }");
  test("kprobe:f { str(arg0, -3); }", Error{});
  test("kprobe:f { @x = str(arg0, 3); }");
  test("kprobe:f { str(arg0, \"hello\"); }", Error{});

  // Check the string size
  BPFtrace bpftrace;
  auto ast = test("kprobe:f { $x = str(arg0, 3); }");

  auto *x =
      ast.root->probes.at(0)->block->stmts.at(0).as<ast::AssignVarStatement>();

  // N.B. the string buffer is 1 larger than the parameter passed to the `str`
  // function, since it needs to be capable of signalling well-formedness to
  // the runtime while having a string of length 3.
  EXPECT_EQ(CreateString(4), x->var()->var_type);
}

TEST_F(TypeCheckerTest, call_str_2_expr)
{
  test("kprobe:f { str(arg0, arg1); }");
  test("kprobe:f { @x = str(arg0, arg1); }");
}

TEST_F(TypeCheckerTest, call_str_state_leak_regression_test)
{
  // Previously, the semantic analyser would
  // leak state in the first str() call.
  // This would make the semantic analyser
  // think it's still processing a
  // positional parameter in the second
  // str() call causing confusing error
  // messages.
  test(R"PROG(kprobe:f { $x = str($1) == "asdf"; $y = str(arg0, 1) })PROG");
}

TEST_F(TypeCheckerTest, call_buf)
{
  test("kprobe:f { buf(arg0, 1); }");
  test("kprobe:f { buf(arg0, -1); }", Error{});
  test("kprobe:f { @x = buf(arg0, 1); }");
  test("kprobe:f { $x = buf(arg0, 1); }");
  test("kprobe:f { buf(\"hello\"); }", Error{});
  test("struct x { int c[4] }; kprobe:f { "
       "$foo = (struct x*)0; @x = "
       "buf($foo->c); }");
}

TEST_F(TypeCheckerTest, call_buf_lit)
{
  test("kprobe:f { @x = buf(arg0, 3); }");
  test("kprobe:f { buf(arg0, \"hello\"); }", Error{});
}

TEST_F(TypeCheckerTest, call_buf_expr)
{
  test("kprobe:f { buf(arg0, arg1); }");
  test("kprobe:f { @x = buf(arg0, arg1); }");
}

TEST_F(TypeCheckerTest, call_buf_posparam)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("1");
  bpftrace->add_param("hello");
  test("kprobe:f { buf(arg0, $1); }", Mock{ *bpftrace });
  test("kprobe:f { buf(arg0, $2); }", Mock{ *bpftrace }, Error{});
}

TEST_F(TypeCheckerTest, call_ksym)
{
  test("kprobe:f { ksym(arg0); }");
  test("kprobe:f { @x = ksym(arg0); }");
  test("kprobe:f { ksym(\"hello\"); }", Error{});
}

TEST_F(TypeCheckerTest, call_usym)
{
  test("kprobe:f { usym(arg0); }");
  test("kprobe:f { @x = usym(arg0); }");
  test("kprobe:f { usym(\"hello\"); }", Error{});
}

TEST_F(TypeCheckerTest, call_ntop)
{
  std::string structs = "struct inet { unsigned char "
                        "ipv4[4]; unsigned char "
                        "ipv6[16]; unsigned char "
                        "invalid[10]; } ";

  test("kprobe:f { ntop(2, arg0); }");
  test("kprobe:f { ntop(arg0); }");
  test(structs + "kprobe:f { ntop(10, ((struct inet*)0)->ipv4); }");
  test(structs + "kprobe:f { ntop(10, ((struct inet*)0)->ipv6); }");
  test(structs + "kprobe:f { ntop(((struct inet*)0)->ipv4); }");
  test(structs + "kprobe:f { ntop(((struct inet*)0)->ipv6); }");

  test("kprobe:f { @x = ntop(2, arg0); }");
  test("kprobe:f { @x = ntop(arg0); }");
  test("kprobe:f { @x = ntop(2, 0xFFFF); }");
  test("kprobe:f { @x = ntop(0xFFFF); }");
  test(structs + "kprobe:f { @x = ntop(((struct inet*)0)->ipv4); }");
  test(structs + "kprobe:f { @x = ntop(((struct inet*)0)->ipv6); }");

  test("kprobe:f { ntop(2, \"hello\"); }", Error{});
  test("kprobe:f { ntop(\"hello\"); }", Error{});
  test(structs + "kprobe:f { ntop(((struct inet*)0)->invalid); }", Error{});
}

TEST_F(TypeCheckerTest, call_pton)
{
  test("kprobe:f { $addr_v4 = pton(\"127.0.0.1\"); }");
  test("kprobe:f { $addr_v4 = pton(\"127.0.0.1\"); $b1 = $addr_v4[0]; }");
  test("kprobe:f { $addr_v6 = pton(\"::1\"); }");
  test("kprobe:f { $addr_v6 = pton(\"::1\"); $b1 = $addr_v6[0]; }");

  std::string def = "#define AF_INET 2\n "
                    "#define AF_INET6 10\n";
  test("kprobe:f { $addr_v4_text = ntop(pton(\"127.0.0.1\")); }");
  test(def +
       "kprobe:f { $addr_v4_text = ntop(AF_INET, pton(\"127.0.0.1\")); }");
  test(def + "kprobe:f { $addr_v6_text = ntop(AF_INET6, pton(\"::1\")); }");

  test("kprobe:f { $addr_v4 = pton(\"\"); }", Error{});
  test("kprobe:f { $addr_v4 = pton(\"127.0.1\"); }", Error{});
  test("kprobe:f { $addr_v4 = pton(\"127.0.0.0.1\"); }", Error{});
  test("kprobe:f { $addr_v6 = pton(\":\"); }", Error{});
  test("kprobe:f { $addr_v6 = pton(\"1:1:1:1:1:1:1:1:1\"); }", Error{});

  std::string structs = "struct inet { unsigned char non_literal_string[4]; } ";
  test("kprobe:f { $addr_v4 = pton(1); }", Error{});
  test(structs + "kprobe:f { $addr_v4 = pton(((struct "
                 "inet*)0)->non_literal_string); }",
       Error{});
}

TEST_F(TypeCheckerTest, call_kaddr)
{
  test("kprobe:f { kaddr(\"avenrun\"); }");
  test("kprobe:f { @x = kaddr(\"avenrun\"); }");
  test("kprobe:f { kaddr(123); }", Error{});
}

TEST_F(TypeCheckerTest, call_uaddr)
{
  test("u:/bin/sh:main { "
       "__builtin_uaddr(\"github.com/golang/"
       "glog.severityName\"); }");
  test("uprobe:/bin/sh:main { "
       "__builtin_uaddr(\"glob_asciirange\"); }");
  test("u:/bin/sh:main,u:/bin/sh:readline "
       "{ __builtin_uaddr(\"glob_asciirange\"); }");
  test("uprobe:/bin/sh:main { @x = "
       "__builtin_uaddr(\"glob_asciirange\"); }");
  test("uprobe:/bin/sh:main { __builtin_uaddr(123); }", Error{});
  test("uprobe:/bin/sh:main { "
       "__builtin_uaddr(\"?\"); }",
       Error{});
  test("uprobe:/bin/sh:main { $str = "
       "\"glob_asciirange\"; __builtin_uaddr($str); }",
       Error{});
  test("uprobe:/bin/sh:main { @str = "
       "\"glob_asciirange\"; __builtin_uaddr(@str); }",
       Error{});

  // The C struct parser should set the
  // is_signed flag on signed types
  BPFtrace bpftrace;
  std::string prog = "uprobe:/bin/sh:main {"
                     "$a = __builtin_uaddr(\"12345_1\");"
                     "$b = __builtin_uaddr(\"12345_2\");"
                     "$c = __builtin_uaddr(\"12345_4\");"
                     "$d = __builtin_uaddr(\"12345_8\");"
                     "$e = __builtin_uaddr(\"12345_5\");"
                     "$f = __builtin_uaddr(\"12345_33\");"
                     "}";

  auto ast = test(prog);

  std::vector<int> sizes = { 8, 16, 32, 64, 64, 64 };

  for (size_t i = 0; i < sizes.size(); i++) {
    auto *v = ast.root->probes.at(0)
                  ->block->stmts.at(i)
                  .as<ast::AssignVarStatement>();
    EXPECT_TRUE(v->var()->var_type.IsPtrTy());
    EXPECT_TRUE(v->var()->var_type.GetPointeeTy().IsIntTy());
    EXPECT_EQ((unsigned long int)sizes.at(i),
              v->var()->var_type.GetPointeeTy().GetIntBitWidth());
  }
}

TEST_F(TypeCheckerTest, call_cgroupid)
{
  // Handle args above default max-string
  // length (64)
  test("kprobe:f { cgroupid("
       //          1         2         3 4
       //          5         6
       "\"123456789/123456789/123456789/"
       "123456789/123456789/123456789/"
       "12345\""
       "); }");
}

TEST_F(TypeCheckerTest, call_probe)
{
  test("kprobe:f { @[probe] = count(); }");
  test("kprobe:f { printf(\"%s\", probe); }");
}

TEST_F(TypeCheckerTest, call_cat)
{
  test("kprobe:f { cat(\"/proc/loadavg\"); }");
  test("kprobe:f { cat(\"/proc/%d/cmdline\", 1); }");
  test("kprobe:f { cat(123); }", Error{});
  test("kprobe:f { @x = cat(\"/proc/loadavg\"); }", Error{});
  test("kprobe:f { $x = cat(\"/proc/loadavg\"); }", Error{});
  test("kprobe:f { @[cat(\"/proc/loadavg\")] = 1; }", Error{});
  test("kprobe:f { if(cat(\"/proc/loadavg\")) { 123 } }", Error{});
  test("kprobe:f { cat(\"/proc/loadavg\") ? 0 : 1; }", Error{});
}

TEST_F(TypeCheckerTest, call_stack)
{
  test("kprobe:f { kstack() }");
  test("kprobe:f { ustack() }");
  test("kprobe:f { kstack(bpftrace) }");
  test("kprobe:f { ustack(bpftrace) }");
  test("kprobe:f { kstack(perf) }");
  test("kprobe:f { ustack(perf) }");
  test("kprobe:f { kstack(3) }");
  test("kprobe:f { ustack(3) }");
  test("kprobe:f { kstack(perf, 3) }");
  test("kprobe:f { ustack(perf, 3) }");
  test("kprobe:f { kstack(raw, 3) }");
  test("kprobe:f { ustack(raw, 3) }");

  // Wrong arguments
  test("kprobe:f { kstack(3, perf) }", Error{});
  test("kprobe:f { ustack(3, perf) }", Error{});
  test("kprobe:f { kstack(bob) }", Error{});
  test("kprobe:f { ustack(bob) }", Error{});
  test("kprobe:f { kstack(\"str\") }", Error{});
  test("kprobe:f { ustack(\"str\") }", Error{});
  test("kprobe:f { kstack(perf, \"str\") }", Error{});
  test("kprobe:f { ustack(perf, \"str\") }", Error{});
  test("kprobe:f { kstack(\"str\", 3) }", Error{});
  test("kprobe:f { ustack(\"str\", 3) }", Error{});

  // Non-literals
  test("kprobe:f { @x = perf; kstack(@x) }", Error{});
  test("kprobe:f { @x = perf; ustack(@x) }", Error{});
  test("kprobe:f { @x = perf; kstack(@x, 3) }", Error{});
  test("kprobe:f { @x = perf; ustack(@x, 3) }", Error{});
  test("kprobe:f { @x = 3; kstack(@x) }", Error{});
  test("kprobe:f { @x = 3; ustack(@x) }", Error{});
  test("kprobe:f { @x = 3; kstack(perf, @x) }", Error{});
  test("kprobe:f { @x = 3; ustack(perf, @x) }", Error{});

  // Positional params
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("3");
  bpftrace->add_param("hello");
  test("kprobe:f { kstack($1) }", Mock{ *bpftrace });
  test("kprobe:f { ustack($1) }", Mock{ *bpftrace });
  test("kprobe:f { kstack(perf, $1) }", Mock{ *bpftrace });
  test("kprobe:f { ustack(perf, $1) }", Mock{ *bpftrace });
  test("kprobe:f { kstack($2) }", Mock{ *bpftrace }, Error{});
  test("kprobe:f { ustack($2) }", Mock{ *bpftrace }, Error{});
  test("kprobe:f { kstack(perf, $2) }", Mock{ *bpftrace }, Error{});
  test("kprobe:f { ustack(perf, $2) }", Mock{ *bpftrace }, Error{});

  // Type comparisons
  test("kprobe:f { $a = (1, kstack); $a = (2, kstack); }");
  test("kprobe:f { $a = (1, kstack); $a = (2, ustack); }", Error{});
  test("kprobe:f { $a = (1, kstack(10)); $a = (2, kstack(11)); }", Error{});
  test("kprobe:f { $a = (1, kstack(perf)); $a = (2, kstack(bpftrace)); }",
       Error{});
  test("kprobe:f { $a = (1, kstack(perf, 1)); $a = (2, kstack(perf, 2)); }",
       Error{});
}

TEST_F(TypeCheckerTest, call_macaddr)
{
  std::string structs = "struct mac { char addr[6]; }; "
                        "struct invalid { char addr[4]; }; ";

  test("kprobe:f { macaddr(arg0); }");

  test(structs + "kprobe:f { macaddr((struct mac*)arg0); }");

  test(structs + "kprobe:f { @x[macaddr((struct mac*)arg0)] = 1; }");
  test(structs + "kprobe:f { @x = macaddr((struct mac*)arg0); }");

  test(structs + "kprobe:f { printf(\"%s\", macaddr((struct mac*)arg0)); }");

  test(structs + "kprobe:f { macaddr(((struct invalid*)arg0)->addr); }",
       Error{});
  test(structs + "kprobe:f { macaddr(*(struct mac*)arg0); }", Error{});

  test("kprobe:f { macaddr(\"foo\"); }", Error{});
}

TEST_F(TypeCheckerTest, call_bswap)
{
  test("kprobe:f { bswap(arg0); }");

  test("kprobe:f { bswap(0x12); }");
  test("kprobe:f { bswap(0x12 + 0x34); }");

  test("kprobe:f { bswap((int8)0x12); }");
  test("kprobe:f { bswap((int16)0x12); }");
  test("kprobe:f { bswap((int32)0x12); }");
  test("kprobe:f { bswap((int64)0x12); }");

  test("kprobe:f { bswap(\"hello\"); }", Error{});
}

TEST_F(TypeCheckerTest, call_cgroup_path)
{
  test("kprobe:f { cgroup_path(1) }");
  test("kprobe:f { cgroup_path(1, \"hello\") }");

  test("kprobe:f { cgroup_path(1, 2) }", Error{});
  test("kprobe:f { cgroup_path(\"1\") }", Error{});

  test("kprobe:f { printf(\"%s\", cgroup_path(1)) }");
  test("kprobe:f { printf(\"%s %s\", cgroup_path(1), cgroup_path(2)) }");
  test("kprobe:f { $var = cgroup_path(0); printf(\"%s %s\", $var, $var) }");

  test("kprobe:f { printf(\"%d\", cgroup_path(1)) }", Error{});
}

TEST_F(TypeCheckerTest, map_reassignment)
{
  test("kprobe:f { @x = 1; @x = 2; }");
  test("kprobe:f { @x = 1; @x = \"foo\"; }", Error{});
}

TEST_F(TypeCheckerTest, variable_reassignment)
{
  test("kprobe:f { $x = 1; $x = 2; }");
  test("kprobe:f { $x = 1; $x = \"foo\"; }", Error{});
  test(R"(kprobe:f { $b = "hi"; $b = @b; } kprobe:func_1 { @b = "bye"; })");

  test(R"(kprobe:f { $b = "hi"; $b = @b; } kprobe:func_1 { @b = 1; })",
       Error{ R"(
stdin:1:23-30: ERROR: Type mismatch for $b: trying to assign value of type 'uint8' when variable already has a type 'string[3]'
kprobe:f { $b = "hi"; $b = @b; } kprobe:func_1 { @b = 1; }
                      ~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, map_use_before_assign)
{
  test("kprobe:f { @x = @y; @y = 2; }");
  test("kprobe:f { @y = 0; @y = @x; @x = 1; }");
}

TEST_F(TypeCheckerTest, maps_are_global)
{
  test("kprobe:f { @x = 1 } kprobe:func_1 { @y = @x }");
  test("kprobe:f { @x = 1 } kprobe:func_1 { @x = \"abc\" }", Error{});
}

TEST_F(TypeCheckerTest, variables_are_local)
{
  test("kprobe:f { $x = 1 } kprobe:func_1 { $x = \"abc\"; }");
  test("kprobe:f { $x = 1 } kprobe:func_1 { @y = $x }", Error{});
}

TEST_F(TypeCheckerTest, array_access)
{
  test("kprobe:f { $s = arg0; @x = $s->y[0];}", Error{});
  test("kprobe:f { $s = 0; @x = $s->y[0];}", Error{});
  test("struct MyStruct { int y[4]; } "
       "kprobe:f { $s = (struct MyStruct *) "
       "arg0; @x = $s->y[5];}",
       Error{});
  test("struct MyStruct { int y[4]; } "
       "kprobe:f { $s = (struct MyStruct *) "
       "arg0; @x = $s->y[-1];}",
       Error{});
  test("struct MyStruct { int y[4]; } "
       "kprobe:f { $s = (struct MyStruct *) "
       "arg0; @x = $s->y[\"0\"];}",
       Error{});
  test("struct MyStruct { int y[4]; } "
       "kprobe:f { $s = (struct MyStruct *) "
       "arg0; $idx = 0; @x = $s->y[$idx];}");
  test("struct MyStruct { int y[4]; } "
       "kprobe:f { $s = (struct MyStruct *) "
       "arg0; $idx = -1; @x = $s->y[$idx];}",
       Error{});
  test("kprobe:f { $s = arg0; @x = $s[0]; }", Error{});
  test("struct MyStruct { void *y; } "
       "kprobe:f { $s = (struct MyStruct *) "
       "arg0; @x = $s->y[5];}",
       Error{});
  auto ast = test("struct MyStruct { int y[4]; } "
                  "kprobe:f { $s = (struct MyStruct *) "
                  "arg0; @x = $s->y[0];}");
  auto *assignment =
      ast.root->probes.at(0)->block->stmts.at(1).as<ast::AssignMapStatement>();
  EXPECT_EQ(CreateInt32(), assignment->map_access->map->value_type);

  ast = test("struct MyStruct { int y[4]; "
             "} kprobe:f { $s = ((struct "
             "MyStruct *) "
             "arg0)->y; @x = $s[0];}");
  auto *array_var_assignment =
      ast.root->probes.at(0)->block->stmts.at(0).as<ast::AssignVarStatement>();
  EXPECT_EQ(CreateArray(4, CreateInt32()),
            array_var_assignment->var()->var_type);

  ast = test("struct MyStruct { int y[4]; "
             "} kprobe:f { @a[0] = "
             "((struct MyStruct *) "
             "arg0)->y; @x = @a[0][0];}");
  auto *array_map_assignment =
      ast.root->probes.at(0)->block->stmts.at(0).as<ast::AssignMapStatement>();
  EXPECT_EQ(CreateArray(4, CreateInt32()),
            array_map_assignment->map_access->map->value_type);

  ast = test("kprobe:f { $s = (int32 *) "
             "arg0; $x = $s[0]; }");
  auto *var_assignment =
      ast.root->probes.at(0)->block->stmts.at(1).as<ast::AssignVarStatement>();
  EXPECT_EQ(CreateInt32(), var_assignment->var()->var_type);

  // Positional parameter as index
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("0");
  bpftrace->add_param("hello");
  test("struct MyStruct { int y[4]; } "
       "kprobe:f { $s = ((struct MyStruct "
       "*)arg0)->y[$1]; }",
       Mock{ *bpftrace });
  test("struct MyStruct { int y[4]; } "
       "kprobe:f { $s = ((struct MyStruct "
       "*)arg0)->y[$2]; }",
       Mock{ *bpftrace },
       Error{});

  test("struct MyStruct { int x; int y[]; } "
       "kprobe:f { $s = (struct MyStruct *) arg0; @y = $s->y[0];}",
       Mock{ *bpftrace });
}

TEST_F(TypeCheckerTest, array_in_map)
{
  test("struct MyStruct { int x[2]; int y[4]; } "
       "kprobe:f { @ = ((struct MyStruct *)arg0)->x; }");
  test("struct MyStruct { int x[2]; int y[4]; } "
       "kprobe:f { @a[0] = ((struct MyStruct *)arg0)->x; }");
  // Mismatched map value types
  test("struct MyStruct { int x[2]; int y[4]; } "
       "kprobe:f { "
       "    @a[0] = ((struct MyStruct *)arg0)->x; "
       "    @a[1] = ((struct MyStruct *)arg0)->y; }",
       Error{});
  test("#include <stdint.h>\n"
       "struct MyStruct { uint8_t x[8]; uint32_t y[2]; }"
       "kprobe:f { "
       "    @a[0] = ((struct MyStruct *)arg0)->x; "
       "    @a[1] = ((struct MyStruct *)arg0)->y; }",
       Error{});
}

TEST_F(TypeCheckerTest, array_as_map_key)
{
  test("struct MyStruct { int x[2]; int y[4]; }"
       "kprobe:f { @x[((struct MyStruct *)arg0)->x] = 0; }");

  test("struct MyStruct { int x[2]; int y[4]; }"
       "kprobe:f { @x[((struct MyStruct *)arg0)->x, "
       "              ((struct MyStruct *)arg0)->y] = 0; }");
  test(R"(
    struct MyStruct { int x[2]; int y[4]; }
    begin {
      @x[((struct MyStruct *)0)->x] = 0;
      @x[((struct MyStruct *)0)->y] = 1;
    })");
}

TEST_F(TypeCheckerTest, array_compare)
{
  test("#include <stdint.h>\n"
       "struct MyStruct { uint8_t x[4]; }"
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x == $s->x); }");
  test("#include <stdint.h>\n"
       "struct MyStruct { uint64_t x[4]; } "
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x == $s->x); }");
  test("struct MyStruct { int x[4]; } "
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x != $s->x); }");

  // unsupported operators
  test("struct MyStruct { int x[4]; } "
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x > $s->x); }",
       Error{});

  // different length
  test("struct MyStruct { int x[4]; int y[8]; }"
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x == $s->y); }",
       Error{});

  // different element type
  test("#include <stdint.h>\n"
       "struct MyStruct { uint8_t x[4]; uint16_t y[4]; } "
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x == $s->y); }",
       Error{});

  // compare with other type
  test("struct MyStruct { int x[4]; int y; } "
       "kprobe:f { $s = (struct MyStruct *) arg0; @ = ($s->x == $s->y); }",
       Error{});
}

TEST_F(TypeCheckerTest, variable_type)
{
  auto ast = test("kprobe:f { $x = 1 }");
  auto st = CreateUInt8();
  auto *assignment =
      ast.root->probes.at(0)->block->stmts.at(0).as<ast::AssignVarStatement>();
  EXPECT_EQ(st, assignment->var()->var_type);
}

TEST_F(TypeCheckerTest, unroll)
{
  test(R"(kprobe:f { $i = 0; unroll(5) { printf("%d", $i); $i = $i + 1; } })");
}

TEST_F(TypeCheckerTest, map_integer_sizes)
{
  auto ast = test("kprobe:f { $x = (int32) -1; @x = $x; }");

  auto *var_assignment =
      ast.root->probes.at(0)->block->stmts.at(0).as<ast::AssignVarStatement>();
  auto *map_assignment =
      ast.root->probes.at(0)->block->stmts.at(1).as<ast::AssignMapStatement>();
  EXPECT_EQ(CreateInt32(), var_assignment->var()->var_type);
  EXPECT_EQ(CreateInt32(), map_assignment->map_access->map->value_type);
}

TEST_F(TypeCheckerTest, binop_tuple)
{
  ast::TypeMetadata types;

  // See the actual function prototype in src/stdlib/base/base.bpf.c.
  //
  // If we wind up with many required extern types, we could consider
  // either automatically imported for semantic analyser tests or having
  // a single point where we define these required external functions.
  auto vd_ty = types.global.add<btf::Integer>("char", 1, 1);
  ASSERT_TRUE(bool(vd_ty));
  auto vd_ptr = types.global.add<btf::Pointer>(*vd_ty);
  ASSERT_TRUE(bool(vd_ptr));
  auto uint64 = types.global.add<btf::Integer>("uint64", 8, 0);
  ASSERT_TRUE(bool(uint64));
  auto int32 = types.global.add<btf::Integer>("int", 4, 1);
  ASSERT_TRUE(bool(int32));

  std::vector<std::pair<std::string, btf::ValueType>> args = {
    { "mem_left", btf::ValueType(*vd_ptr) },
    { "mem_right", btf::ValueType(*vd_ptr) },
    { "count", btf::ValueType(*uint64) }
  };
  auto memcmp_proto = types.global.add<btf::FunctionProto>(
      btf::ValueType(*int32), args);
  ASSERT_TRUE(bool(memcmp_proto));

  auto memcmp_func = types.global.add<btf::Function>(
      "__memcmp", btf::Function::Linkage::Global, *memcmp_proto);
  ASSERT_TRUE(bool(memcmp_func));

  // These are all variables so they don't get folded
  test(
      R"(kprobe:f { $a = (2, (int8[2])(int16)1); $b = (2, (int8[2])(int16)2); $a == $b })",
      Types{ types });
  test(R"(kprobe:f { $a = ((int16)1, 3); $b = ((int64)2, 4); $a == $b })",
       Types{ types });
  test(
      R"(kprobe:f { $a = (1, "reallyreallyreallylongstr", true); $b = (2, "bye", false); $a == $b })",
      Types{ types });
  test(
      R"(kprobe:f { $a = (1, "reallyreallyreallylongstr", ((int8)1, "bye")); $b = (2, "bye", (2, "reallyreallyreallylongstr")); $a == $b })",
      Types{ types });
  test(
      R"(kprobe:f { $a = ((int16)1, (int16)3); $b = ((int64)2, 4); $a == $b })",
      Types{ types });

  test(R"(kprobe:f { $a = (1, true); $b = (2, false, 3); $a == $b })",
       Error{},
       Types{ types });
  test(
      R"(kprobe:f { $a = (1, true, "bye"); $b = (2, "bye", false); $a == $b })",
      Error{},
      Types{ types });
  test(
      R"(kprobe:f { $a = (2, (int8[2])(int16)1); $b = (2, (int8[8])1); $a == $b })",
      Error{},
      Types{ types });
  test(
      R"(kprobe:f { $a = (2, (1, (int8[2])(int16)1)); $b = (2, (1, (int16[2])(int32)1)); $a == $b })",
      Error{},
      Types{ types });
  test(
      R"(kprobe:f { $a = (1, "hello", true); $b = (2, "bye", false); $a < $b })",
      Error{},
      Types{ types });
  test(
      R"(kprobe:f { $a = (1, "hello", true); $b = (2, "bye", false); $a > $b })",
      Error{},
      Types{ types });
}

TEST_F(TypeCheckerTest, binop_array)
{
  // These are variables so they don't get folded
  test(
      R"(kprobe:f { $a = (int8[2])(int16)1; $b = (int8[2])(int16)2; $a == $b })");

  test(
      R"(kprobe:f { $a = (int8[4])(int32)1; $b = (int8[2])(int16)2; $a == $b })",
      Error{});
  test(
      R"(kprobe:f { $a = (int8[4])(int32)1; $b = (int16[2])(int32)2; $a == $b })",
      Error{});
  test(
      R"(kprobe:f { $a = (int8[2])(int16)1; $b = (int8[2])(int16)2; $a < $b })",
      Error{});
  test(
      R"(kprobe:f { $a = (int8[2])(int16)1; $b = (int8[2])(int16)2; $a > $b })",
      Error{});
}

TEST_F(TypeCheckerTest, unop_dereference)
{
  test("kprobe:f { *0; }");
  test("struct X { int n; } kprobe:f { $x = (struct X*)0; *$x; }");
  test("struct X { int n; } kprobe:f { $x = *(struct X*)0; *$x; }", Error{});
  test("kprobe:f { *\"0\"; }", Error{});
  test("kprobe:f { *true; }", Error{});
}

TEST_F(TypeCheckerTest, unop_not)
{
  std::string structs = "struct X { int x; };";
  test("kprobe:f { ~0; }");
  test(structs + "kprobe:f { $x = *(struct X*)0; ~$x; }", Error{});
  test(structs + "kprobe:f { $x = (struct X*)0; ~$x; }", Error{});
  test("kprobe:f { ~\"0\"; }", Error{});
  test("kprobe:f { ~true; }", Error{});
}

TEST_F(TypeCheckerTest, unop_lnot)
{
  test("kprobe:f { !0; }");
  test("kprobe:f { !false; }");
  test("kprobe:f { !(int32)0; }");
  test("struct X { int n; } kprobe:f { $x = (struct X*)0; !$x; }", Error{});
  test("struct X { int n; } kprobe:f { $x = *(struct X*)0; !$x; }", Error{});
  test("kprobe:f { !\"0\"; }", Error{});
}

TEST_F(TypeCheckerTest, unop_increment_decrement)
{
  test("kprobe:f { $x = 0; $x++; }");
  test("kprobe:f { $x = 0; $x--; }");
  test("kprobe:f { $x = 0; ++$x; }");
  test("kprobe:f { $x = 0; --$x; }");

  test("kprobe:f { @x++; }");
  test("kprobe:f { @x--; }");
  test("kprobe:f { ++@x; }");
  test("kprobe:f { --@x; }");

  test("kprobe:f { $x++; }", Error{});
  test("kprobe:f { @x = \"a\"; @x++; }", Error{});
  test("kprobe:f { $x = \"a\"; $x++; }", Error{});
  test("kprobe:f { ++true; }", Error{});
  test("kprobe:f { --true; }", Error{});
}

TEST_F(TypeCheckerTest, printf_errorf_warnf)
{
  std::vector<std::string> funcs = { "printf", "errorf", "warnf" };
  for (const auto &func : funcs) {
    test("kprobe:f { " + func + "(\"hi\") }");
    test("kprobe:f { " + func + "(1234) }", Error{});
    test("kprobe:f { $fmt = \"mystring\"; " + func + "($fmt) }", Error{});
    test("kprobe:f { " + func + "(\"%s\", comm) }");
    test("kprobe:f { " + func + "(\"%-16s\", comm) }");
    test("kprobe:f { " + func + "(\"%-10.10s\", comm) }");
    test("kprobe:f { " + func + "(\"%A\", comm) }", Error{});
    test("kprobe:f { @x = " + func + "(\"hi\") }", Error{});
    test("kprobe:f { $x = " + func + "(\"hi\") }", Error{});
    test("kprobe:f { " + func +
         "(\"%d %d %d %d %d %d %d %d %d\", "
         "1, 2, 3, 4, 5, 6, 7, 8, 9); }");
    test("kprobe:f { " + func + "(\"%dns\", nsecs) }");

    {
      // Long format string should be ok
      std::stringstream prog;

      prog << "i:ms:100 { " + func + "(\"" << std::string(200, 'a')
           << " %d\\n\", 1); }";
      test(prog.str());
    }
  }
}

TEST_F(TypeCheckerTest, debugf)
{
  test("kprobe:f { debugf(\"hi\") }");
  test("kprobe:f { debugf(1234) }", Error{});
  test("kprobe:f { $fmt = \"mystring\"; debugf($fmt) }", Error{});
  test("kprobe:f { debugf(\"%s\", comm) }");
  test("kprobe:f { debugf(\"%-16s\", comm) }");
  test("kprobe:f { debugf(\"%-10.10s\", comm) }");
  test("kprobe:f { debugf(\"%lluns\", nsecs) }");
  test("kprobe:f { debugf(\"%A\", comm) }", Error{});
  test("kprobe:f { @x = debugf(\"hi\") }", Error{});
  test("kprobe:f { $x = debugf(\"hi\") }", Error{});
  test("kprobe:f { debugf(\"%d\", 1) }");
  test("kprobe:f { debugf(\"%d %d\", 1, 1) }");
  test("kprobe:f { debugf(\"%d %d %d\", 1, 1, 1) }");

  {
    // Long format string should be ok
    std::stringstream prog;
    prog << "i:ms:100 { debugf(\"" << std::string(59, 'a')
         << R"(%s\n", "a"); })";
    test(prog.str());
  }
}

TEST_F(TypeCheckerTest, system)
{
  test("kprobe:f { system(\"ls\") }", UnsafeMode::Enable);
  test("kprobe:f { system(1234) }", UnsafeMode::Enable, Error{});
  test("kprobe:f { $fmt = \"mystring\"; system($fmt) }",
       UnsafeMode::Enable,
       Error{});
}

TEST_F(TypeCheckerTest, printf_format_int)
{
  test("kprobe:f { printf(\"int: %d\", 1234) }");
  test("kprobe:f { printf(\"int: %d\", pid) }");
  test("kprobe:f { @x = 123; printf(\"int: %d\", @x) }");
  test("kprobe:f { $x = 123; printf(\"int: %d\", $x) }");

  test("kprobe:f { printf(\"int: %u\", 1234) }");
  test("kprobe:f { printf(\"int: %o\", 1234) }");
  test("kprobe:f { printf(\"int: %x\", 1234) }");
  test("kprobe:f { printf(\"int: %X\", 1234) }");
}

TEST_F(TypeCheckerTest, printf_format_int_with_length)
{
  test("kprobe:f { printf(\"int: %d\", 1234) }");
  test("kprobe:f { printf(\"int: %u\", 1234) }");
  test("kprobe:f { printf(\"int: %o\", 1234) }");
  test("kprobe:f { printf(\"int: %x\", 1234) }");
  test("kprobe:f { printf(\"int: %X\", 1234) }");
  test("kprobe:f { printf(\"int: %p\", 1234) }");

  test("kprobe:f { printf(\"int: %hhd\", 1234) }");
  test("kprobe:f { printf(\"int: %hhu\", 1234) }");
  test("kprobe:f { printf(\"int: %hho\", 1234) }");
  test("kprobe:f { printf(\"int: %hhx\", 1234) }");
  test("kprobe:f { printf(\"int: %hhX\", 1234) }");
  test("kprobe:f { printf(\"int: %hhp\", 1234) }");

  test("kprobe:f { printf(\"int: %hd\", 1234) }");
  test("kprobe:f { printf(\"int: %hu\", 1234) }");
  test("kprobe:f { printf(\"int: %ho\", 1234) }");
  test("kprobe:f { printf(\"int: %hx\", 1234) }");
  test("kprobe:f { printf(\"int: %hX\", 1234) }");
  test("kprobe:f { printf(\"int: %hp\", 1234) }");

  test("kprobe:f { printf(\"int: %ld\", 1234) }");
  test("kprobe:f { printf(\"int: %lu\", 1234) }");
  test("kprobe:f { printf(\"int: %lo\", 1234) }");
  test("kprobe:f { printf(\"int: %lx\", 1234) }");
  test("kprobe:f { printf(\"int: %lX\", 1234) }");
  test("kprobe:f { printf(\"int: %lp\", 1234) }");

  test("kprobe:f { printf(\"int: %lld\", 1234) }");
  test("kprobe:f { printf(\"int: %llu\", 1234) }");
  test("kprobe:f { printf(\"int: %llo\", 1234) }");
  test("kprobe:f { printf(\"int: %llx\", 1234) }");
  test("kprobe:f { printf(\"int: %llX\", 1234) }");
  test("kprobe:f { printf(\"int: %llp\", 1234) }");

  test("kprobe:f { printf(\"int: %jd\", 1234) }");
  test("kprobe:f { printf(\"int: %ju\", 1234) }");
  test("kprobe:f { printf(\"int: %jo\", 1234) }");
  test("kprobe:f { printf(\"int: %jx\", 1234) }");
  test("kprobe:f { printf(\"int: %jX\", 1234) }");
  test("kprobe:f { printf(\"int: %jp\", 1234) }");

  test("kprobe:f { printf(\"int: %zd\", 1234) }");
  test("kprobe:f { printf(\"int: %zu\", 1234) }");
  test("kprobe:f { printf(\"int: %zo\", 1234) }");
  test("kprobe:f { printf(\"int: %zx\", 1234) }");
  test("kprobe:f { printf(\"int: %zX\", 1234) }");
  test("kprobe:f { printf(\"int: %zp\", 1234) }");

  test("kprobe:f { printf(\"int: %td\", 1234) }");
  test("kprobe:f { printf(\"int: %tu\", 1234) }");
  test("kprobe:f { printf(\"int: %to\", 1234) }");
  test("kprobe:f { printf(\"int: %tx\", 1234) }");
  test("kprobe:f { printf(\"int: %tX\", 1234) }");
  test("kprobe:f { printf(\"int: %tp\", 1234) }");
}

TEST_F(TypeCheckerTest, printf_format_string)
{
  test(R"(kprobe:f { printf("str: %s", "mystr") })");
  test("kprobe:f { printf(\"str: %s\", comm) }");
  test("kprobe:f { printf(\"str: %s\", str(arg0)) }");
  test(R"(kprobe:f { @x = "hi"; printf("str: %s", @x) })");
  test(R"(kprobe:f { $x = "hi"; printf("str: %s", $x) })");

  // Most types support automatic string conversion.
  test("kprobe:f { printf(\"%s\", 1234) }");
  test("kprobe:f { printf(\"%s\", arg0) }");
}

TEST_F(TypeCheckerTest, printf_bad_format_string)
{
  test(R"(kprobe:f { printf("%d", "mystr") })", Error{});
  test("kprobe:f { printf(\"%d\", str(arg0)) }", Error{});
}

TEST_F(TypeCheckerTest, printf_format_buf)
{
  test(R"(kprobe:f { printf("%r", buf("mystr", 5)) })");
}

TEST_F(TypeCheckerTest, printf_bad_format_buf)
{
  test(R"(kprobe:f { printf("%r", "mystr") })", Error{});
  test("kprobe:f { printf(\"%r\", arg0) }", Error{});
}

TEST_F(TypeCheckerTest, printf_format_buf_no_ascii)
{
  test(R"(kprobe:f { printf("%rx", buf("mystr", 5)) })");
}

TEST_F(TypeCheckerTest, printf_bad_format_buf_no_ascii)
{
  test(R"(kprobe:f { printf("%rx", "mystr") })", Error{});
  test("kprobe:f { printf(\"%rx\", arg0) }", Error{});
}

TEST_F(TypeCheckerTest, printf_format_buf_nonescaped_hex)
{
  test(R"(kprobe:f { printf("%rh", buf("mystr", 5)) })");
}

TEST_F(TypeCheckerTest, printf_bad_format_buf_nonescaped_hex)
{
  test(R"(kprobe:f { printf("%rh", "mystr") })", Error{});
  test("kprobe:f { printf(\"%rh\", arg0) }", Error{});
}

TEST_F(TypeCheckerTest, printf_format_multi)
{
  test(R"(kprobe:f { printf("%d %d %s", 1, 2, "mystr") })");
  test(R"(kprobe:f { printf("%d %s %d", 1, 2, "mystr") })", Error{});
}

TEST_F(TypeCheckerTest, join)
{
  test("kprobe:f { join(arg0) }");
  test("kprobe:f { printf(\"%s\", join(arg0)) }", Error{});
  test("kprobe:f { $fmt = \"mystring\"; join($fmt) }", Error{});
  test("kprobe:f { @x = join(arg0) }", Error{});
  test("kprobe:f { $x = join(arg0) }", Error{});
}

TEST_F(TypeCheckerTest, join_delimiter)
{
  test("kprobe:f { join(arg0, \",\") }");
  test(R"(kprobe:f { printf("%s", join(arg0, ",")) })", Error{});
  test(R"(kprobe:f { $fmt = "mystring"; join($fmt, ",") })", Error{});
  test("kprobe:f { @x = join(arg0, \",\") }", Error{});
  test("kprobe:f { $x = join(arg0, \",\") }", Error{});
  test("kprobe:f { join(arg0, 3) }", Error{});
}

TEST_F(TypeCheckerTest, variable_cast_types)
{
  std::string structs = "struct type1 { int field; } struct "
                        "type2 { int field; }";
  test(structs +
       "kprobe:f { $x = (struct type1*)cpu; $x = (struct type1*)cpu; }");
  test(structs +
           "kprobe:f { $x = (struct type1*)cpu; $x = (struct type2*)cpu; }",
       Error{});
}

TEST_F(TypeCheckerTest, map_cast_types)
{
  std::string structs = "struct type1 { int field; } struct "
                        "type2 { int field; }";
  test(structs +
       "kprobe:f { @x = *(struct type1*)cpu; @x = *(struct type1*)cpu; }");
  test(structs +
           "kprobe:f { @x = *(struct type1*)cpu; @x = *(struct type2*)cpu; }",
       Error{});
}

TEST_F(TypeCheckerTest, map_aggregations_implicit_cast)
{
  // When assigning an aggregation to a map
  // containing integers, the aggregation is
  // implicitly cast to an integer.
  test("kprobe:f { @x = 1; @y = count(); @x = @y; }",
       ExpectedAST{ Program().WithProbe(
           Probe({ "kprobe:f" },
                 { AssignMapStatement(Map("@x"), Integer(0), Integer(1)),
                   DiscardExpr(Call("count", { Map("@y"), Integer(0) })),
                   AssignMapStatement(
                       Map("@x"),
                       Integer(0),
                       Cast(Typeof(bpftrace::test::SizedType(Type::integer)),
                            MapAccess(Map("@y"), Integer(0)))),
                   Jump(ast::JumpType::RETURN) })) });
  test("kprobe:f { @x = 1; @y = sum(5); @x = @y; }",
       ExpectedAST{ Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignMapStatement(Map("@x"), Integer(0), Integer(1)),
             DiscardExpr(Call("sum", { Map("@y"), Integer(0), Integer(5) })),
             AssignMapStatement(
                 Map("@x"),
                 Integer(0),
                 Cast(Typeof(bpftrace::test::SizedType(Type::integer)),
                      MapAccess(Map("@y"), Integer(0)))),
             Jump(ast::JumpType::RETURN) })) });
  test("kprobe:f { @x = 1; @y = min(5); @x = @y; }",
       ExpectedAST{ Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignMapStatement(Map("@x"), Integer(0), Integer(1)),
             DiscardExpr(Call("min", { Map("@y"), Integer(0), Integer(5) })),
             AssignMapStatement(
                 Map("@x"),
                 Integer(0),
                 Cast(Typeof(bpftrace::test::SizedType(Type::integer)),
                      MapAccess(Map("@y"), Integer(0)))),
             Jump(ast::JumpType::RETURN) })) });
  test("kprobe:f { @x = 1; @y = max(5); @x = @y; }",
       ExpectedAST{ Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignMapStatement(Map("@x"), Integer(0), Integer(1)),
             DiscardExpr(Call("max", { Map("@y"), Integer(0), Integer(5) })),
             AssignMapStatement(
                 Map("@x"),
                 Integer(0),
                 Cast(Typeof(bpftrace::test::SizedType(Type::integer)),
                      MapAccess(Map("@y"), Integer(0)))),
             Jump(ast::JumpType::RETURN) })) });
  test("kprobe:f { @x = 1; @y = avg(5); @x = @y; }",
       ExpectedAST{ Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignMapStatement(Map("@x"), Integer(0), Integer(1)),
             DiscardExpr(Call("avg", { Map("@y"), Integer(0), Integer(5) })),
             AssignMapStatement(
                 Map("@x"),
                 Integer(0),
                 Cast(Typeof(bpftrace::test::SizedType(Type::integer)),
                      MapAccess(Map("@y"), Integer(0)))),
             Jump(ast::JumpType::RETURN) })) });

  // Assigning to a newly declared map
  // requires an explicit cast to get the
  // value of the aggregation.
  test("kprobe:f { @x = count(); @y = (uint64)@x; }");
  test("kprobe:f { @x = sum(5); @y = (uint64)@x; }");
  test("kprobe:f { @x = min(5); @y = (uint64)@x; }");
  test("kprobe:f { @x = max(5); @y = (uint64)@x; }");
  test("kprobe:f { @x = avg(5); @y = (uint64)@x; }");

  // However, if there is no explicit cast,
  // the assignment is rejected and casting
  // is suggested.
  test("kprobe:f { @y = count(); @x = @y; }", Error{ R"(
stdin:1:26-33: ERROR: Map value 'count_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@x = count();`.
kprobe:f { @y = count(); @x = @y; }
                         ~~~~~~~
HINT: Add a cast to integer if you want the value of the aggregate, e.g. `@x = (int64)@y;`.
)" });
  test("kprobe:f { @y = sum(5); @x = @y; }", Error{ R"(
stdin:1:25-32: ERROR: Map value 'usum_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@x = sum(retval);`.
kprobe:f { @y = sum(5); @x = @y; }
                        ~~~~~~~
HINT: Add a cast to integer if you want the value of the aggregate, e.g. `@x = (int64)@y;`.
)" });
  test("kprobe:f { @y = min(5); @x = @y; }", Error{ R"(
stdin:1:25-32: ERROR: Map value 'umin_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@x = min(retval);`.
kprobe:f { @y = min(5); @x = @y; }
                        ~~~~~~~
HINT: Add a cast to integer if you want the value of the aggregate, e.g. `@x = (int64)@y;`.
)" });
  test("kprobe:f { @y = max(5); @x = @y; }", Error{ R"(
stdin:1:25-32: ERROR: Map value 'umax_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@x = max(retval);`.
kprobe:f { @y = max(5); @x = @y; }
                        ~~~~~~~
HINT: Add a cast to integer if you want the value of the aggregate, e.g. `@x = (int64)@y;`.
)" });
  test("kprobe:f { @y = avg(5); @x = @y; }", Error{ R"(
stdin:1:25-32: ERROR: Map value 'uavg_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@x = avg(retval);`.
kprobe:f { @y = avg(5); @x = @y; }
                        ~~~~~~~
HINT: Add a cast to integer if you want the value of the aggregate, e.g. `@x = (int64)@y;`.
)" });
  test("kprobe:f { @y = stats(5); @x = @y; }", Error{ R"(
stdin:1:27-34: ERROR: Map value 'ustats_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@x = stats(arg2);`.
kprobe:f { @y = stats(5); @x = @y; }
                          ~~~~~~~
)" });
  test("kprobe:f { @x = 1; @y = stats(5); @x = @y; }", Error{ R"(
stdin:1:35-42: ERROR: Map value 'ustats_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@x = stats(arg2);`.
kprobe:f { @x = 1; @y = stats(5); @x = @y; }
                                  ~~~~~~~
)" });

  test("kprobe:f { @ = count(); if (@ > 0) { print((1)); } }");
  test("kprobe:f { @ = sum(5); if (@ > 0) { print((1)); } }");
  test("kprobe:f { @ = min(5); if (@ > 0) { print((1)); } }");
  test("kprobe:f { @ = max(5); if (@ > 0) { print((1)); } }");
  test("kprobe:f { @ = avg(5); if (@ > 0) { print((1)); } }");

  test("kprobe:f { @ = hist(5); if (@ > 0) { print((1)); } }", Error{ R"(
stdin:1:31-32: ERROR: Type mismatch for '>': comparing hist_t with uint8
kprobe:f { @ = hist(5); if (@ > 0) { print((1)); } }
                              ~
stdin:1:29-30: ERROR: left (hist_t)
kprobe:f { @ = hist(5); if (@ > 0) { print((1)); } }
                            ~
stdin:1:33-34: ERROR: right (uint8)
kprobe:f { @ = hist(5); if (@ > 0) { print((1)); } }
                                ~
)" });
  test("kprobe:f { @ = count(); @ += 5 }", Error{ R"(
stdin:1:25-31: ERROR: Type mismatch for @: trying to assign value of type 'uint64' when map already has a type 'count_t'
kprobe:f { @ = count(); @ += 5 }
                        ~~~~~~
)" });
}

TEST_F(TypeCheckerTest, map_aggregations_explicit_cast)
{
  test("kprobe:f { @ = count(); print((1, (uint16)@)); }");
  test("kprobe:f { @ = sum(5); print((1, (uint16)@)); }");
  test("kprobe:f { @ = min(5); print((1, (uint16)@)); }");
  test("kprobe:f { @ = max(5); print((1, (uint16)@)); }");
  test("kprobe:f { @ = avg(5); print((1, (uint16)@)); }");

  test("kprobe:f { @ = hist(5); print((1, (uint16)@)); }", Error{ R"(
stdin:1:35-43: ERROR: Cannot cast from "hist_t" to "uint16"
kprobe:f { @ = hist(5); print((1, (uint16)@)); }
                                  ~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, variable_casts_are_local)
{
  std::string structs = "struct type1 { int field; } struct "
                        "type2 { int field; }";
  test(structs + "kprobe:f { $x = *(struct type1 *)cpu } "
                 "kprobe:func_1 { $x = *(struct type2 *)cpu; }");
}

TEST_F(TypeCheckerTest, map_casts_are_global)
{
  std::string structs = "struct type1 { int field; } struct "
                        "type2 { int field; }";
  test(structs + "kprobe:f { @x = *(struct type1 *)cpu }"
                 "kprobe:func_1 { @x = *(struct type2 *)cpu }",
       Error{});
}

TEST_F(TypeCheckerTest, cast_unknown_type)
{
  test("begin { (struct faketype *)cpu }", Error{ R"(
stdin:1:10-27: ERROR: Cannot resolve unknown type "struct faketype"
begin { (struct faketype *)cpu }
         ~~~~~~~~~~~~~~~~~
)" });
  test("begin { (faketype)cpu }", Error{ R"(
stdin:1:10-18: ERROR: Cannot resolve unknown type "faketype"
begin { (faketype)cpu }
         ~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, cast_struct)
{
  // Casting struct by value is forbidden
  test("struct mytype { int field; }\n"
       "begin { $s = (struct mytype *)cpu; (uint32)*$s; }",
       Error{ R"(
stdin:2:36-44: ERROR: Cannot cast from struct type "struct mytype"
begin { $s = (struct mytype *)cpu; (uint32)*$s; }
                                   ~~~~~~~~
)" });
  test("struct mytype { int field; } "
       "begin { (struct mytype)cpu }",
       Error{ R"(
stdin:1:38-53: ERROR: Cannot cast from "uint64" to "struct mytype"
struct mytype { int field; } begin { (struct mytype)cpu }
                                     ~~~~~~~~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, cast_bool)
{
  test("kprobe:f { $a = (bool)1; }");
  test("kprobe:f { $a = (bool)\"str\"; }");
  test("kprobe:f { $a = (bool)comm; }");
  test("kprobe:f { $a = (int64 *)0; $b = (bool)$a; }");
  test("kprobe:f { $a = (int64)true; $b = (int64)false; }");

  test("kprobe:f { $a = (bool)kstack; }", Error{ R"(
stdin:1:17-23: ERROR: Cannot cast from "kstack_bpftrace_127" to "bool"
kprobe:f { $a = (bool)kstack; }
                ~~~~~~
)" });

  test("kprobe:f { $a = (bool)pton(\"127.0.0.1\"); }", Error{ R"(
stdin:1:17-23: ERROR: Cannot cast from "uint8[4]" to "bool"
kprobe:f { $a = (bool)pton("127.0.0.1"); }
                ~~~~~~
)" });
}

TEST_F(TypeCheckerTest, cast_string)
{
  test("kprobe:f { $a = (string[10])\"hello\"; }");

  test("kprobe:f { $a = (string[2])\"hello\"; }", Error{});
  test("kprobe:f { $a = (string[2])5; }", Error{});
  test("kprobe:f { $a = (string)5; }", Error{});
}

TEST_F(TypeCheckerTest, field_access)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { $x = *(struct type1*)cpu; $x.field }");
  test(structs + "kprobe:f { @x = *(struct type1*)cpu; @x.field }");
}

TEST_F(TypeCheckerTest, field_access_wrong_field)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { ((struct type1 *)cpu)->blah }", Error{});
  test(structs + "kprobe:f { $x = (struct type1 *)cpu; $x->blah }", Error{});
  test(structs + "kprobe:f { @x = (struct type1 *)cpu; @x->blah }", Error{});
}

TEST_F(TypeCheckerTest, field_access_wrong_expr)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { 1234->field }", Error{});
}

TEST_F(TypeCheckerTest, field_access_types)
{
  std::string structs = "struct type1 { int field; char mystr[8]; }"
                        "struct type2 { int field; }";

  test(structs + "kprobe:f { (*((struct type1*)0)).field == 123 }");
  test(structs + "kprobe:f { (*((struct type1*)0)).field == \"abc\" }",
       Error{});

  test(structs + "kprobe:f { (*((struct type1*)0)).mystr == \"abc\" }");
  test(structs + "kprobe:f { (*((struct type1*)0)).mystr == 123 }", Error{});

  test(structs + "kprobe:f { (*((struct type1*)0)).field"
                 " == (*((struct type2*)0)).field }");
  test(structs + "kprobe:f { (*((struct type1*)0)).mystr"
                 " == (*((struct type2*)0)).field }",
       Error{});
}

TEST_F(TypeCheckerTest, field_access_pointer)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { ((struct type1*)0)->field }");
  test(structs + "kprobe:f { ((struct type1*)0).field }");
  test(structs + "kprobe:f { *((struct type1*)0) }");
}

TEST_F(TypeCheckerTest, field_access_sub_struct)
{
  std::string structs =
      "struct type2 { int field; } "
      "struct type1 { struct type2 *type2ptr; struct type2 type2; }";

  test(structs + "kprobe:f { (*(struct type1*)0).type2ptr->field }");
  test(structs + "kprobe:f { (*(struct type1*)0).type2.field }");
  test(structs + "kprobe:f { $x = (struct type2*)0; $x = (*(struct "
                 "type1*)0).type2ptr }");
  test(structs + "kprobe:f { $x = *(struct type1*)0; $x = (*(struct "
                 "type1*)0).type2 }",
       Error{});
  test(structs + "kprobe:f { $x = (struct type1*)0; "
                 "$x = (*(struct type1*)0).type2ptr }",
       Error{});
}

TEST_F(TypeCheckerTest, field_access_is_internal)
{
  BPFtrace bpftrace;
  std::string structs = "struct type1 { int x; }";

  {
    auto ast = test(structs + "kprobe:f { $x = (*(struct type1*)0).x }");
    auto &stmts = ast.root->probes.at(0)->block->stmts;
    auto *var_assignment1 = stmts.at(0).as<ast::AssignVarStatement>();
    EXPECT_FALSE(var_assignment1->var()->var_type.is_internal);
  }

  {
    auto ast = test(structs +
                    "kprobe:f { @type1 = *(struct type1*)0; $x = @type1.x }");
    auto &stmts = ast.root->probes.at(0)->block->stmts;
    auto *map_assignment = stmts.at(0).as<ast::AssignMapStatement>();
    auto *var_assignment2 = stmts.at(1).as<ast::AssignVarStatement>();
    EXPECT_TRUE(map_assignment->map_access->map->value_type.is_internal);
    EXPECT_TRUE(var_assignment2->var()->var_type.is_internal);
  }
}

TEST_F(TypeCheckerTest, struct_as_map_key)
{
  test("struct A { int x; } struct B { char x; } "
       "kprobe:f { @x[*((struct A *)arg0)] = 0; }");

  test("struct A { int x; } struct B { char x; } "
       "kprobe:f { @x[*((struct A *)arg0), *((struct B *)arg1)] = 0; }");

  // Mismatched key types
  test(R"(
    struct A { int x; } struct B { char x; }
    begin {
        @x[*((struct A *)0)] = 0;
        @x[*((struct B *)0)] = 1;
    })",
       Error{ R"(
stdin:4:12-13: ERROR: Argument mismatch for @x: trying to access with arguments: 'struct B' when map expects arguments: 'struct A'
        @x[*((struct B *)0)] = 1;
           ~
)" });
}

TEST_F(TypeCheckerTest, per_cpu_map_as_map_key)
{
  test("begin { @x = count(); @y[@x] = 1; }");
  test("begin { @x = sum(10); @y[@x] = 1; }");
  test("begin { @x = min(1); @y[@x] = 1; }");
  test("begin { @x = max(1); @y[@x] = 1; }");
  test("begin { @x = avg(1); @y[@x] = 1; }");

  test("begin { @x = hist(10); @y[@x] = 1; }", Error{ R"(
stdin:1:27-29: ERROR: hist_t cannot be part of a map key
begin { @x = hist(10); @y[@x] = 1; }
                          ~~
)" });

  test("begin { @x = lhist(10, 0, 10, 1); @y[@x] = 1; }", Error{ R"(
stdin:1:38-40: ERROR: lhist_t cannot be part of a map key
begin { @x = lhist(10, 0, 10, 1); @y[@x] = 1; }
                                     ~~
)" });

  test("begin { @x = tseries(10, 1s, 10); @y[@x] = 1; }", Error{ R"(
stdin:1:38-40: ERROR: tseries_t cannot be part of a map key
begin { @x = tseries(10, 1s, 10); @y[@x] = 1; }
                                     ~~
)" });

  test("begin { @x = stats(10); @y[@x] = 1; }", Error{ R"(
stdin:1:28-30: ERROR: ustats_t cannot be part of a map key
begin { @x = stats(10); @y[@x] = 1; }
                           ~~
)" });
}

TEST_F(TypeCheckerTest, probe_short_name)
{
  test("t:sched:sched_one { 1 }");
  test("k:f { pid }");
  test("kr:f { pid }");
  test("u:/bin/sh:f { 1 }");
  test("ur:/bin/sh:f { 1 }");
  test("p:hz:997 { 1 }");
  test("h:cache-references:1000000 { 1 }");
  test("s:faults:1000 { 1 }");
  test("i:s:1 { 1 }");
}

TEST_F(TypeCheckerTest, positional_parameters)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("123");
  bpftrace->add_param("hello");
  bpftrace->add_param("0x123");

  test("kprobe:f { printf(\"%d\", $1); }", Mock{ *bpftrace });
  test("kprobe:f { printf(\"%s\", str($1)); }", Mock{ *bpftrace });

  test("kprobe:f { printf(\"%s\", str($2)); }", Mock{ *bpftrace });
  test("kprobe:f { printf(\"%s\", str($2 + 1)); }", Mock{ *bpftrace });
  test("kprobe:f { printf(\"%d\", $2); }", Mock{ *bpftrace }, Error{});

  test("kprobe:f { printf(\"%d\", $3); }", Mock{ *bpftrace });

  // Pointer arithmetic in str() for parameters
  test("kprobe:f { printf(\"%s\", str($1 + 1)); }", Mock{ *bpftrace });
  test("kprobe:f { printf(\"%s\", str(1 + $1)); }", Mock{ *bpftrace });
  test("kprobe:f { printf(\"%s\", str($1 + 4)); }", Mock{ *bpftrace });
  test("kprobe:f { printf(\"%s\", str($1 * 2)); }", Mock{ *bpftrace });
  test("kprobe:f { printf(\"%s\", str($1 + 1 + 1)); }", Mock{ *bpftrace });

  // Parameters are not required to exist to be used:
  test("kprobe:f { printf(\"%s\", str($4)); }", Mock{ *bpftrace });
  test("kprobe:f { printf(\"%d\", $4); }", Mock{ *bpftrace });

  test("kprobe:f { printf(\"%d\", $#); }", Mock{ *bpftrace });
  test("kprobe:f { printf(\"%s\", str($#)); }", Mock{ *bpftrace });
  test("kprobe:f { printf(\"%s\", str($#+1)); }", Mock{ *bpftrace });

  // Parameters can be used as string literals
  test("kprobe:f { printf(\"%d\", cgroupid(str($2))); }", Mock{ *bpftrace });

  bpftrace->add_param("0999");
  test("kprobe:f { printf(\"%d\", $4); }", Mock{ *bpftrace }, Error{});
}

TEST_F(TypeCheckerTest, c_macros)
{
  test("#define A 1\nkprobe:f { printf(\"%d\", A); }");
  test("#define A A\nkprobe:f { printf(\"%d\", A); }", Error{});
  test("enum { A = 1 }\n#define A A\nkprobe:f { printf(\"%d\", A); }");
}

TEST_F(TypeCheckerTest, enums)
{
  // Anonymous enums have empty string names in libclang <= 15,
  // so this is an important test
  test("enum { a = 1, b } kprobe:f { printf(\"%d\", a); }");
  test("enum { a = 1, b } kprobe:f { printf(\"%s\", a); }");
  test("enum { a = 1, b } kprobe:f { $e = a; printf(\"%s\", $e); }");
  test("enum { a = 1, b } kprobe:f { printf(\"%15s %-15s\", a, a); }");

  test("enum named { a = 1, b } kprobe:f { printf(\"%d\", a); }");
  test("enum named { a = 1, b } kprobe:f { printf(\"%s\", a); }");
  test("enum named { a = 1, b } kprobe:f { $e = a; printf(\"%s\", $e); }");
  test("enum named { a = 1, b } kprobe:f { printf(\"%15s %-15s\", a, a); }");
}

TEST_F(TypeCheckerTest, enum_casts)
{
  test("enum named { a = 1, b } kprobe:f { print((enum named)1); }");
  // We can't detect this issue because the cast expr is not a literal
  test("enum named { a = 1, b } kprobe:f { $x = 3; print((enum named)$x); }");

  test("enum named { a = 1, b } kprobe:f { print((enum named)3); }", Error{ R"(
stdin:1:42-54: ERROR: Enum: named doesn't contain a variant value of 3
enum named { a = 1, b } kprobe:f { print((enum named)3); }
                                         ~~~~~~~~~~~~
)" });

  test("enum Foo { a = 1, b } kprobe:f { print((enum Bar)1); }", Error{ R"(
stdin:1:40-50: ERROR: Unknown enum: Bar
enum Foo { a = 1, b } kprobe:f { print((enum Bar)1); }
                                       ~~~~~~~~~~
)" });

  test("enum named { a = 1, b } kprobe:f { $a = \"str\"; print((enum "
       "named)$a); }",
       Error{ R"(
stdin:1:54-66: ERROR: Cannot cast from "string[4]" to "enum named"
enum named { a = 1, b } kprobe:f { $a = "str"; print((enum named)$a); }
                                                     ~~~~~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, signed_int_comparison_warnings)
{
  std::string cmp_sign = "comparison of integers of different signs";
  test("kretprobe:f /-1 < retval/ {}", Warning{ cmp_sign });
  test("kretprobe:f /-1 > retval/ {}", Warning{ cmp_sign });
  test("kretprobe:f /-1 >= retval/ {}", Warning{ cmp_sign });
  test("kretprobe:f /-1 <= retval/ {}", Warning{ cmp_sign });
  test("kretprobe:f /-1 != retval/ {}", Warning{ cmp_sign });
  test("kretprobe:f /-1 == retval/ {}", Warning{ cmp_sign });
  test("kretprobe:f /retval > -1/ {}", Warning{ cmp_sign });
  test("kretprobe:f /retval < -1/ {}", Warning{ cmp_sign });

  // These should not trigger a warning
  test("kretprobe:f /1 < retval/ {}", NoWarning{ cmp_sign });
  test("kretprobe:f /1 > retval/ {}", NoWarning{ cmp_sign });
  test("kretprobe:f /1 >= retval/ {}", NoWarning{ cmp_sign });
  test("kretprobe:f /1 <= retval/ {}", NoWarning{ cmp_sign });
  test("kretprobe:f /1 != retval/ {}", NoWarning{ cmp_sign });
  test("kretprobe:f /1 == retval/ {}", NoWarning{ cmp_sign });
  test("kretprobe:f /retval > 1/ {}", NoWarning{ cmp_sign });
  test("kretprobe:f /retval < 1/ {}", NoWarning{ cmp_sign });
}

TEST_F(TypeCheckerTest, string_comparison)
{
  test("struct MyStruct {char y[4]; } "
       "kprobe:f { $s = (struct MyStruct*)arg0; $s->y == \"abc\"}");
  test("struct MyStruct {char y[4]; } "
       "kprobe:f { $s = (struct MyStruct*)arg0; \"abc\" != $s->y}");
  test("struct MyStruct {char y[4]; } "
       "kprobe:f { $s = (struct MyStruct*)arg0; \"abc\" == \"abc\"}");

  std::string msg = "the condition is always false";
  test("struct MyStruct {char y[4]; } "
       "kprobe:f { $s = (struct MyStruct*)arg0; $s->y == \"long string\"}",
       NoWarning{ msg });
  test("struct MyStruct {char y[4]; } "
       "kprobe:f { $s = (struct MyStruct*)arg0; \"long string\" != $s->y}",
       NoWarning{ msg });
}

TEST_F(TypeCheckerTest, string_index)
{
  // String indexing produces an 8-bit signed integer.
  test("kprobe:f { $x = \"foo\"; $x[0] == 102; }");

  // Able to index to the null, but not past it.
  test(R"(kprobe:f { $x = "foo"; printf("%c is the fourth letter", $x[3]); })");
  test(R"(kprobe:f { $x = "foo"; printf("%c is the fifth letter", $x[4]); })",
       Error{ R"(
stdin:1:59-62: ERROR: the index 4 is out of bounds for array of size 4
kprobe:f { $x = "foo"; printf("%c is the fifth letter", $x[4]); }
                                                          ~~~
)" });
}

TEST_F(TypeCheckerTest, signed_int_arithmetic_warnings)
{
  // Test type warnings for arithmetic
  std::string msg = "arithmetic on integers of different signs";

  test("kprobe:f { @ = -1 - arg0 }", Warning{ msg });
  test("kprobe:f { @ = -1 + arg0 }", Warning{ msg });
  test("kprobe:f { @ = -1 * arg0 }", Warning{ msg });
  test("kprobe:f { @ = -1 / arg0 }", Warning{ msg });

  test("kprobe:f { @ = arg0 + 1 }", NoWarning{ msg });
  test("kprobe:f { @ = arg0 - 1 }", NoWarning{ msg });
  test("kprobe:f { @ = arg0 * 1 }", NoWarning{ msg });
  test("kprobe:f { @ = arg0 / 1 }", NoWarning{ msg });
}

TEST_F(TypeCheckerTest, signed_int_division_warnings)
{
  std::string msg = "signed operands";
  test("kprobe:f { @x = -1; @y = @x / 1 }", Warning{ msg });
  test("kprobe:f { @x = (uint64)1; @y = @x / -1 }", Warning{ msg });

  // These should not trigger a warning.
  // Note that we need to assign to a map in
  // order to ensure that they are typed.
  // Literals are not yet typed.
  test("kprobe:f { @x = (uint64)1; @y = @x / 1 }", NoWarning{ msg });
  test("kprobe:f { @x = (uint64)1; @y = -(@x / 1) }", NoWarning{ msg });
}

TEST_F(TypeCheckerTest, signed_int_modulo_warnings)
{
  std::string msg = "signed operands";
  test("kprobe:f { @x = -1; @y = @x % 1 }", Warning{ msg });
  test("kprobe:f { @x = (uint64)1; @y = @x % -1 }", Warning{ msg });

  // These should not trigger a warning. See above re: types.
  test("kprobe:f { @x = (uint64)1; @y = @x % 1 }", NoWarning{ msg });
  test("kprobe:f { @x = (uint64)1; @y = -(@x % 1) }", NoWarning{ msg });
}

TEST_F(TypeCheckerTest, map_as_lookup_table)
{
  // Initializing a map should not lead to usage issues
  test("begin { @[0] = \"abc\"; @[1] = \"def\" } "
       "kretprobe:f { printf(\"%s\\n\", @[(int64)retval])}");
}

TEST_F(TypeCheckerTest, cast_sign)
{
  // The C struct parser should set the is_signed flag on signed types
  std::string prog = "struct t { int s; unsigned int us; "
                     "long l; unsigned long ul }; "
                     "kprobe:f { "
                     "  $t = ((struct t *)0xFF);"
                     "  $s = $t->s; $us = $t->us; $l = "
                     "$t->l; $lu = $t->ul; }";
  auto ast = test(prog);

  auto *s =
      ast.root->probes.at(0)->block->stmts.at(1).as<ast::AssignVarStatement>();
  auto *us =
      ast.root->probes.at(0)->block->stmts.at(2).as<ast::AssignVarStatement>();
  auto *l =
      ast.root->probes.at(0)->block->stmts.at(3).as<ast::AssignVarStatement>();
  auto *ul =
      ast.root->probes.at(0)->block->stmts.at(4).as<ast::AssignVarStatement>();
  EXPECT_EQ(CreateInt32(), s->var()->var_type);
  EXPECT_EQ(CreateUInt32(), us->var()->var_type);
  EXPECT_EQ(CreateInt64(), l->var()->var_type);
  EXPECT_EQ(CreateUInt64(), ul->var()->var_type);
}

TEST_F(TypeCheckerTest, binop_bool_and_int)
{
  std::string operators[] = {
    "==", "!=", "<", "<=", ">",  ">=", "&&", "||", "+",
    "-",  "/",  "*", ">>", "<<", "&",  "|",  "^",
  };

  // Making a single variable below so as not to trigger fold_literals code

  // both sides bool
  for (std::string op : operators) {
    test("kretprobe:f { $a = true; $b = $a " + op + " false; }");
  }

  // one side int
  for (std::string op : operators) {
    test("kretprobe:f { $a = true; $b = $a " + op + " 1; }");
  }
}

TEST_F(TypeCheckerTest, binop_arithmetic)
{
  // Make sure types are correct
  std::string prog_pre = "struct t { long l; unsigned long ul }; "
                         "kprobe:f { $t = ((struct t *)0xFF); ";

  std::string arithmetic_operators[] = { "+", "-", "/", "*" };
  for (std::string op : arithmetic_operators) {
    std::string prog = prog_pre + "$varA = $t->l " + op +
                       " $t->l; "
                       "$varB = $t->ul " +
                       op +
                       " $t->l; "
                       "$varC = $t->ul " +
                       op +
                       " $t->ul; "
                       "$varD = $t->ul " +
                       op +
                       " true; "
                       "$bool_t = false; "
                       "$varE = $bool_t " +
                       op +
                       " true; "
                       "}";

    auto ast = test(prog);
    auto *varA = ast.root->probes.at(0)
                     ->block->stmts.at(1)
                     .as<ast::AssignVarStatement>();
    EXPECT_EQ(CreateInt64(), varA->var()->var_type);
    auto *varB = ast.root->probes.at(0)
                     ->block->stmts.at(2)
                     .as<ast::AssignVarStatement>();
    EXPECT_EQ(CreateInt64(), varB->var()->var_type);
    auto *varC = ast.root->probes.at(0)
                     ->block->stmts.at(3)
                     .as<ast::AssignVarStatement>();
    EXPECT_EQ(CreateUInt64(), varC->var()->var_type);
    auto *varD = ast.root->probes.at(0)
                     ->block->stmts.at(4)
                     .as<ast::AssignVarStatement>();
    EXPECT_EQ(CreateUInt64(), varD->var()->var_type);
    // This one is not like the others
    auto *varE = ast.root->probes.at(0)
                     ->block->stmts.at(5)
                     .as<ast::AssignVarStatement>();
    EXPECT_EQ(CreateBool(), varE->var()->var_type);
  }
}

TEST_F(TypeCheckerTest, binop_compare)
{
  std::string prog_pre = "struct t { long l }; "
                         "kprobe:f { $t = ((struct t *)0xFF); ";
  std::string compare_operators[] = { "==", "!=", "<", "<=", ">", ">=" };

  for (std::string op : compare_operators) {
    std::string prog = prog_pre + "$varA = 1 " + op +
                       " 1; "
                       "$varB = $t " +
                       op +
                       " 1; "
                       "$varC = true " +
                       op +
                       " 1; "
                       "$varD = true " +
                       op +
                       " $t; "
                       "}";

    auto ast = test(prog);
    auto *varA = ast.root->probes.at(0)
                     ->block->stmts.at(1)
                     .as<ast::AssignVarStatement>();
    EXPECT_EQ(CreateBool(), varA->var()->var_type);
    auto *varB = ast.root->probes.at(0)
                     ->block->stmts.at(2)
                     .as<ast::AssignVarStatement>();
    EXPECT_EQ(CreateBool(), varB->var()->var_type);
    auto *varC = ast.root->probes.at(0)
                     ->block->stmts.at(3)
                     .as<ast::AssignVarStatement>();
    EXPECT_EQ(CreateBool(), varC->var()->var_type);
    auto *varD = ast.root->probes.at(0)
                     ->block->stmts.at(4)
                     .as<ast::AssignVarStatement>();
    EXPECT_EQ(CreateBool(), varD->var()->var_type);
  }
}

TEST_F(TypeCheckerTest, int_cast_types)
{
  test("kretprobe:f { @ = (int8)retval }");
  test("kretprobe:f { @ = (int16)retval }");
  test("kretprobe:f { @ = (int32)retval }");
  test("kretprobe:f { @ = (int64)retval }");
  test("kretprobe:f { @ = (uint8)retval }");
  test("kretprobe:f { @ = (uint16)retval }");
  test("kretprobe:f { @ = (uint32)retval }");
  test("kretprobe:f { @ = (uint64)retval }");
}

TEST_F(TypeCheckerTest, int_cast_usage)
{
  test("kretprobe:f /(int32) retval < 0/ {}");
  test("kprobe:f /(int32) arg0 < 0/ {}");
  test("kprobe:f { @=sum((int32)arg0) }");
  test("kprobe:f { @=avg((int32)arg0) }");
  test("kprobe:f { @=avg((int32)arg0) }");

  test("kprobe:f { @=avg((int32)\"abc\") }", Error{});
}

TEST_F(TypeCheckerTest, intptr_cast_types)
{
  test("kretprobe:f { @ = *(int8*)retval }");
  test("kretprobe:f { @ = *(int16*)retval }");
  test("kretprobe:f { @ = *(int32*)retval }");
  test("kretprobe:f { @ = *(int64*)retval }");
  test("kretprobe:f { @ = *(uint8*)retval }");
  test("kretprobe:f { @ = *(uint16*)retval }");
  test("kretprobe:f { @ = *(uint32*)retval }");
  test("kretprobe:f { @ = *(uint64*)retval }");
}

TEST_F(TypeCheckerTest, intptr_cast_usage)
{
  test("kretprobe:f /(*(int32*) retval) < 0/ {}");
  test("kprobe:f /(*(int32*) arg0) < 0/ {}");
  test("kprobe:f { @=sum(*(int32*)arg0) }");
  test("kprobe:f { @=avg(*(int32*)arg0) }");
  test("kprobe:f { @=avg(*(int32*)arg0) }");

  // This is OK (@ = 0x636261)
  test("kprobe:f { @=avg(*(int32*)\"abc\") }");
  test("kprobe:f { @=avg(*(int32*)123) }");
}

TEST_F(TypeCheckerTest, intarray_cast_types)
{
  test("kprobe:f { @ = (int8[8])1 }");
  test("kprobe:f { @ = (int8[4])1 }");
  test("kprobe:f { @ = (int8[2])1 }");
  test("kprobe:f { @ = (int16[4])1 }");
  test("kprobe:f { @ = (int32[2])1 }");
  test("kprobe:f { @ = (int64[1])1 }");
  test("kprobe:f { @ = (int8[4])(int32)1 }");
  test("kprobe:f { @ = (int8[2])(int16)1 }");
  test("kprobe:f { @ = (int8[1])(int8)1 }");
  test("kprobe:f { @ = (int8[])1 }");
  test("kprobe:f { @ = (uint8[8])1 }");
  test("kretprobe:f { @ = (int8[8])retval }");
  test("kprobe:f { @ = (int8[6])\"hello\" }");
  test("kprobe:f { @ = (int8[])\"hello\" }");

  test("kprobe:f { @ = (int32[])(int16)1 }", Error{});
  test("kprobe:f { @ = (int8[2])\"hello\" }", Error{});

  test("struct Foo { int x; } kprobe:f { @ = (struct Foo [2])1 }", Error{});
}

TEST_F(TypeCheckerTest, bool_array_cast_types)
{
  test("kprobe:f { @ = (bool[8])1 }");
  test("kprobe:f { @ = (bool[4])1 }");
  test("kprobe:f { @ = (bool[4])(uint32)1 }");
  test("kprobe:f { @ = (bool[2])(uint16)1 }");

  test("kprobe:f { @ = (bool[64])1 }", Error{});
}

TEST_F(TypeCheckerTest, intarray_cast_usage)
{
  test("kprobe:f { $a=(int8[8])1; }");
  test("kprobe:f { @=(int8[8])1; }");
  test("kprobe:f { @[(int8[8])1] = 0; }");
  test("kprobe:f { if (((int8[8])1)[0] == 1) {} }");
}

TEST_F(TypeCheckerTest, intarray_to_int_cast)
{
  test("#include <stdint.h>\n"
       "struct Foo { uint8_t x[8]; } "
       "kprobe:f { @ = (int64)((struct Foo *)arg0)->x; }");
  test("#include <stdint.h>\n"
       "struct Foo { uint32_t x[2]; } "
       "kprobe:f { @ = (int64)((struct Foo *)arg0)->x; }");
  test("#include <stdint.h>\n"
       "struct Foo { uint8_t x[4]; } "
       "kprobe:f { @ = (int32)((struct Foo *)arg0)->x; }");

  test("#include <stdint.h>\n"
       "struct Foo { uint8_t x[8]; } "
       "kprobe:f { @ = (int32)((struct Foo *)arg0)->x; }",
       Error{});
  test("#include <stdint.h>\n"
       "struct Foo { uint8_t x[8]; } "
       "kprobe:f { @ = (int32 *)((struct "
       "Foo *)arg0)->x; }",
       Error{});
}

TEST_F(TypeCheckerTest, mixed_int_var_assignments)
{
  test("kprobe:f { $x = (uint64)0; $x = (uint16)1; }");
  test("kprobe:f { $x = (int8)1; $x = 5; }");
  test("kprobe:f { $x = 1; $x = -1; }");
  test("kprobe:f { $x = (uint8)1; $x = 200; }");
  test("kprobe:f { $x = (int8)1; $x = -2; }");
  test("kprobe:f { $x = (int16)1; $x = 20000; }");
  test("kprobe:f { $x = (uint32)5; $x += 1; }");
  test("kprobe:f { $x = (uint8)1; $x = -1; }");
  test("kprobe:f { $x = (int16)1; $x = 100000; }");
  test("kprobe:f { $a = (uint16)5; $x = (uint8)0; $x = $a; }");
  test("kprobe:f { $a = (int8)-1; $x = (uint8)0; $x = $a; }");

  // Errors
  test("begin { $a = -1; $a = (uint64)2; }", Error{});
  test("begin { $a = (int64)1; $a = (uint64)2; }", Error{});
  test("begin { $a = -1; $a = 9223372036854775808; }", Error{});
  test("begin { $a = 9223372036854775807; $a = -2147483648 }", Error{});
  test("kprobe:f { $x = -1; $x = 10223372036854775807; }", Error{ R"(
stdin:1:21-46: ERROR: Type mismatch for $x: trying to assign value of type 'uint64' when variable already has a type 'int8'
kprobe:f { $x = -1; $x = 10223372036854775807; }
                    ~~~~~~~~~~~~~~~~~~~~~~~~~
)" });

  test("begin { $x = (int8)1; $x = 5; }",
       ExpectedAST{ Program().WithProbe(
           Probe({ "begin" },
                 { AssignVarStatement(Variable("$x"),
                                      Cast(Typeof(SizedType(Type::integer)),
                                           Integer(1))),
                   AssignVarStatement(Variable("$x"), Integer(5)),
                   Jump(ast::JumpType::RETURN) })) });
  test("begin { $x = (int8)1; $x = (uint8)5; }",
       ExpectedAST{ Program().WithProbe(Probe(
           { "begin" },
           { AssignVarStatement(Variable("$x"),
                                Cast(Typeof(SizedType(Type::integer)),
                                     Cast(Typeof(SizedType(Type::integer)),
                                          Integer(1)))),
             AssignVarStatement(Variable("$x"),
                                Cast(Typeof(SizedType(Type::integer)),
                                     Cast(Typeof(SizedType(Type::integer)),
                                          Integer(5)))),
             Jump(ast::JumpType::RETURN) })) });
}

TEST_F(TypeCheckerTest, mixed_int_like_map_assignments)
{
  test("kprobe:f { @x = (uint64)0; @x = (uint16)1; }");
  test("kprobe:f { @x = (int8)1; @x = 5; }");
  test("kprobe:f { @x = 1; @x = -1; }");
  test("kprobe:f { @x = (int8)1; @x = -2; }");
  test("kprobe:f { @x = (int16)1; @x = 20000; }");
  test("kprobe:f { @x = (uint16)1; @x = 200; }");
  test("kprobe:f { @x = (uint16)1; @x = 10223372036854775807; }");
  test("kprobe:f { @x = 1; @x = 9223372036854775807; }");
  test("kprobe:f { @x = 1; @x = -9223372036854775808; }");
  test("kprobe:f { @x = (uint8)1; @x = -1; }");
  test("kprobe:f { @x = 1; @x = 10223372036854775807; }");
  test("kprobe:f { @x = sum(1); @x = sum(-1); }");
  test("kprobe:f { @x = sum((uint32)1); @x = sum(-1); }");
  test("kprobe:f { @x = avg(1); @x = avg(-1); }");
  test("kprobe:f { @x = avg((uint32)1); @x = avg(-1); }");
  test("kprobe:f { @x = min(1); @x = min(-1); }");
  test("kprobe:f { @x = min((uint32)1); @x = min(-1); }");
  test("kprobe:f { @x = max(1); @x = max(-1); }");
  test("kprobe:f { @x = max((uint32)1); @x = max(-1); }");
  test("kprobe:f { @x = stats(1); @x = stats(-1); }");
  test("kprobe:f { @x = stats((uint32)1); @x = stats(-1); }");

  test("kprobe:f { @x = sum((uint64)1); @x = sum(-1); }", Error{ R"(
stdin:1:38-45: ERROR: Type mismatch for @x: trying to assign value of type 'int8' when map already has a type 'uint64'
kprobe:f { @x = sum((uint64)1); @x = sum(-1); }
                                     ~~~~~~~
)" });
  test("kprobe:f { @x = min((uint64)1); @x = min(-1); }", Error{ R"(
stdin:1:38-45: ERROR: Type mismatch for @x: trying to assign value of type 'int8' when map already has a type 'uint64'
kprobe:f { @x = min((uint64)1); @x = min(-1); }
                                     ~~~~~~~
)" });
  test("kprobe:f { @x = max((uint64)1); @x = max(-1); }", Error{ R"(
stdin:1:38-45: ERROR: Type mismatch for @x: trying to assign value of type 'int8' when map already has a type 'uint64'
kprobe:f { @x = max((uint64)1); @x = max(-1); }
                                     ~~~~~~~
)" });
  test("kprobe:f { @x = avg((uint64)1); @x = avg(-1); }", Error{ R"(
stdin:1:38-45: ERROR: Type mismatch for @x: trying to assign value of type 'int8' when map already has a type 'uint64'
kprobe:f { @x = avg((uint64)1); @x = avg(-1); }
                                     ~~~~~~~
)" });
  test("kprobe:f { @x = stats((uint64)1); @x = stats(-1); }", Error{ R"(
stdin:1:40-49: ERROR: Type mismatch for @x: trying to assign value of type 'int8' when map already has a type 'uint64'
kprobe:f { @x = stats((uint64)1); @x = stats(-1); }
                                       ~~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, mixed_int_map_access)
{
  test("kprobe:f { @x[1] = 1; @x[(int16)2] }");
  test("kprobe:f { @x[-1] = 1; @x[1] }");
  test("kprobe:f { @x[(int16)1] = 1; @x[2] }");
  test("kprobe:f { @x[(int16)1] = 1; @x[(int64)2] }");
  test("kprobe:f { @x[(uint16)1] = 1; @x[(uint64)2] }");
  test("kprobe:f { @x[(uint64)1] = 1; @x[(uint16)2] }");
  test("kprobe:f { @x[(uint16)1] = 1; @x[2] }");
  test("kprobe:f { @x[(uint16)1] = 1; @x[10223372036854775807] }");
  test("kprobe:f { @x[1] = 1; @x[9223372036854775807] }");
  test("kprobe:f { @x[1] = 1; @x[-9223372036854775808] }");
  test("kprobe:f { @x[1] = 1; @x[(uint64)1] }");
  test("kprobe:f { @x[(uint32)-1] = 1; @x[1] }");
  test("kprobe:f { @x[-1] = 1; @x[(uint32)1] }");

  test("kprobe:f { @x[-1] = 1; @x[10223372036854775807] }", Error{ R"(
stdin:1:27-47: ERROR: Argument mismatch for @x: trying to access with arguments: 'uint64' when map expects arguments: 'int8'
kprobe:f { @x[-1] = 1; @x[10223372036854775807] }
                          ~~~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { @x[(uint64)1] = 1; @x[-1] }", Error{ R"(
stdin:1:34-35: ERROR: Argument mismatch for @x: trying to access with arguments: 'int8' when map expects arguments: 'uint64'
kprobe:f { @x[(uint64)1] = 1; @x[-1] }
                                 ~
)" });
  test("kretprobe:f { @x[-1] = 1; @x[(uint64)1] }", Error{ R"(
ERROR: Argument mismatch for @x: trying to access with arguments: 'uint64' when map expects arguments: 'int8'
)" });
}

TEST_F(TypeCheckerTest, mixed_int_like_binop)
{
  test("kprobe:f { $a = 1 == -1; }", NoWarning{ "comparison of integers" });
  test("kprobe:f { $a = 1 == (int64)-1; }",
       NoWarning{ "comparison of integers" });
  test("kprobe:f { $a = (uint32)1 == (int32)-1; }",
       NoWarning{ "comparison of integers" });
  test("kprobe:f { @a = sum(-1); $a = 1 == @a; }",
       NoWarning{ "comparison of integers" });
  test("kprobe:f { @a = sum(-1); $a = @a == 1; }",
       NoWarning{ "comparison of integers" });
  test("kprobe:f { @a = sum(1); $a = @a == (uint16)1; }",
       NoWarning{ "comparison of integers" });
  test("kprobe:f { @a = sum(-1); $a = @a == (uint16)1; }",
       NoWarning{ "comparison of integers" });
  test("kprobe:f { @a = sum(1); @b = count(); $a = @a == @b; }",
       NoWarning{ "comparison of integers" });

  test("kprobe:f { $a = (uint64)1 == (int64)-1; }",
       Warning{ "comparison of integers" });
  test("kprobe:f { @a = sum(-1); $a = (uint64)1 == @a; }",
       Warning{ "comparison of integers" });
  test("kprobe:f { @a = sum(-1); $a = @a == (uint64)1; }",
       Warning{ "comparison of integers" });
  test("kprobe:f { @a = sum(-1); @b = count(); $a = @a == @b; }",
       Warning{ "comparison of integers" });

  test("kprobe:f { $a = 1 + -1; }", NoWarning{ "arithmetic on integers" });
  test("kprobe:f { $a = 1 + (int64)-1; }",
       NoWarning{ "arithmetic on integers" });
  test("kprobe:f { $a = (uint32)1 + (int32)-1; }",
       NoWarning{ "arithmetic on integers" });
  test("kprobe:f { @a = sum(-1); $a = 1 + @a; }",
       NoWarning{ "arithmetic on integers" });
  test("kprobe:f { @a = sum(-1); $a = @a + 1; }",
       NoWarning{ "arithmetic on integers" });
  test("kprobe:f { @a = sum(1); $a = @a + (uint16)1; }",
       NoWarning{ "arithmetic on integers" });
  test("kprobe:f { @a = sum(-1); $a = @a + (uint16)1; }",
       NoWarning{ "arithmetic on integers" });
  test("kprobe:f { @a = sum(1); @b = count(); $a = @a + @b; }",
       NoWarning{ "arithmetic on integers" });

  test("kprobe:f { $a = (uint64)1 + (int64)-1; }",
       Warning{ "arithmetic on integers" });
  test("kprobe:f { @a = sum(-1); $a = (uint64)1 + @a; }",
       Warning{ "arithmetic on integers" });
  test("kprobe:f { @a = sum(-1); $a = @a + (uint64)1; }",
       Warning{ "arithmetic on integers" });
  test("kprobe:f { @a = sum(-1); @b = count(); $a = @a + @b; }",
       Warning{ "arithmetic on integers" });

  // Both are additionally casted to int16
  test("kprobe:f { $a = (uint8)1 == (int8)-1; }",
       ExpectedAST{ Program().WithProbe(Probe(
           { "kprobe:f" },
           { AssignVarStatement(
                 Variable("$a"),
                 Binop(Operator::EQ,
                       Cast(Typeof(SizedType(Type::integer)),
                            Cast(Typeof(SizedType(Type::integer)), Integer(1))),
                       Cast(Typeof(SizedType(Type::integer)),
                            Cast(Typeof(SizedType(Type::integer)),
                                 NegativeInteger(-1))))),
             Jump(ast::JumpType::RETURN) })) });

  // The left has an additional cast to int64
  test("kprobe:f { @a = sum(-1); $a = (uint8)1 == @a; }",
       ExpectedAST{ Program().WithProbe(Probe(
           { "kprobe:f" },
           { DiscardExpr(
                 Call("sum", { Map("@a"), Integer(0), NegativeInteger(-1) })),
             AssignVarStatement(
                 Variable("$a"),
                 Binop(Operator::EQ,
                       Cast(Typeof(SizedType(Type::integer)),
                            Cast(Typeof(SizedType(Type::integer)), Integer(1))),
                       MapAccess(Map("@a"), Integer(0)))),
             Jump(ast::JumpType::RETURN) })) });
}

TEST_F(TypeCheckerTest, signal)
{
  ast::TypeMetadata types;

  auto uint32 = types.global.add<btf::Integer>("uint32", 4, 0);
  ASSERT_TRUE(bool(uint32));
  auto int32 = types.global.add<btf::Integer>("int32", 4, 1);
  ASSERT_TRUE(bool(int32));

  std::vector<std::pair<std::string, btf::ValueType>> args = {
    { "sig", btf::ValueType(*uint32) }
  };
  auto signal_proto = types.global.add<btf::FunctionProto>(
      btf::ValueType(*int32), args);
  ASSERT_TRUE(bool(signal_proto));

  auto signal_process_func = types.global.add<btf::Function>(
      "__signal_process", btf::Function::Linkage::Global, *signal_proto);
  ASSERT_TRUE(bool(signal_process_func));

  auto signal_thread_func = types.global.add<btf::Function>(
      "__signal_thread", btf::Function::Linkage::Global, *signal_proto);
  ASSERT_TRUE(bool(signal_process_func));

  for (const auto &signal :
       std::vector<std::string>{ "signal", "signal_thread" }) {
    // int literals
    test("k:f {" + signal + "(1); }", UnsafeMode::Enable, Types{ types });
    test("k:f {" + signal + "(1); }", UnsafeMode::Enable, Types{ types });
    test("kr:f {" + signal + "(1); }", UnsafeMode::Enable, Types{ types });
    test("u:/bin/sh:f {" + signal + "(11); }",
         UnsafeMode::Enable,
         Types{ types });
    test("ur:/bin/sh:f {" + signal + "(11); }",
         UnsafeMode::Enable,
         Types{ types });
    test("p:hz:1 {" + signal + "(1); }", UnsafeMode::Enable, Types{ types });

    // vars
    test("k:f { @=1;" + signal + "(@); }", UnsafeMode::Enable, Types{ types });
    test("k:f { " + signal + "((uint64)arg0); }",
         UnsafeMode::Enable,
         Types{ types });

    // String
    test("k:f {" + signal + "(\"KILL\"); }",
         UnsafeMode::Enable,
         Types{ types });
    test("k:f {" + signal + "(\"SIGKILL\"); }",
         UnsafeMode::Enable,
         Types{ types });
    test("k:f {" + signal + "({ \"SIGKILL\" }); }",
         UnsafeMode::Enable,
         Types{ types });

    // Not allowed for:
    test("hardware:pcm:1000 {" + signal + "(1); }",
         UnsafeMode::Enable,
         Types{ types },
         Error{});
    test("software:pcm:1000 {" + signal + "(1); }",
         UnsafeMode::Enable,
         Types{ types },
         Error{});
    test("begin {" + signal + "(1); }",
         UnsafeMode::Enable,
         Types{ types },
         Error{});
    test("end {" + signal + "(1); }",
         UnsafeMode::Enable,
         Types{ types },
         Error{});
    test("i:s:1 {" + signal + "(1); }",
         UnsafeMode::Enable,
         Types{ types },
         Error{});

    // invalid signals
    test("k:f {" + signal + "(0); }",
         UnsafeMode::Enable,
         Types{ types },
         Error{});
    test("k:f {" + signal + "(-100); }",
         UnsafeMode::Enable,
         Types{ types },
         Error{});
    test("k:f {" + signal + "(100); }",
         UnsafeMode::Enable,
         Types{ types },
         Error{});
    test("k:f { $a = -1" + signal + "($a); }",
         UnsafeMode::Enable,
         Types{ types },
         Error{});
    test("k:f {" + signal + "(\"SIGABC\"); }",
         UnsafeMode::Enable,
         Types{ types },
         Error{});
    test("k:f {" + signal + "(\"ABC\"); }",
         UnsafeMode::Enable,
         Types{ types },
         Error{});
    test("k:f { $a = \"SIGKILL\"" + signal + "($a); }",
         UnsafeMode::Enable,
         Types{ types },
         Error{});
    test("k:f { $a = \"SIGKILL\"" + signal + "({ $a }); }",
         UnsafeMode::Enable,
         Types{ types },
         Error{});

    // // Positional parameter
    auto bpftrace = get_mock_bpftrace();
    bpftrace->add_param("1");
    test("k:f {" + signal + "($1) }",
         UnsafeMode::Enable,
         Mock{ *bpftrace },
         Types{ types });
  }
}

TEST_F(TypeCheckerTest, strncmp)
{
  // Test strncmp builtin
  test(R"(i:s:1 { $a = "bar"; strncmp("foo", $a, 1) })");
  test(R"(i:s:1 { strncmp("foo", "bar", 1) })");
  test("i:s:1 { strncmp(1,1,1) }", Error{});
  test("i:s:1 { strncmp(\"a\",1,1) }", Error{});
}

TEST_F(TypeCheckerTest, strncmp_posparam)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("1");
  bpftrace->add_param("hello");
  test(R"(i:s:1 { strncmp("foo", "bar", $1) })", Mock{ *bpftrace });
  test(R"(i:s:1 { strncmp("foo", "bar", $2) })", Mock{ *bpftrace }, Error{});
}

TEST_F(TypeCheckerTest, override)
{
  ast::TypeMetadata types;

  auto vd_ty = types.global.lookup<btf::Void>("void");
  ASSERT_TRUE(bool(vd_ty));
  auto vd_ptr = types.global.add<btf::Pointer>(*vd_ty);
  ASSERT_TRUE(bool(vd_ptr));
  auto uint64 = types.global.add<btf::Integer>("uint64", 8, 0);
  ASSERT_TRUE(bool(uint64));

  std::vector<std::pair<std::string, btf::ValueType>> args = {
    { "ctx", btf::ValueType(*vd_ptr) }, { "rc", btf::ValueType(*uint64) }
  };
  auto override_proto = types.global.add<btf::FunctionProto>(
      btf::ValueType(*vd_ty), args);
  ASSERT_TRUE(bool(override_proto));

  auto override_func = types.global.add<btf::Function>(
      "__override", btf::Function::Linkage::Global, *override_proto);
  ASSERT_TRUE(bool(override_func));

  // literals
  test("k:f { override(-1); }", UnsafeMode::Enable, Types{ types });

  // variables
  test("k:f { override(arg0); }", UnsafeMode::Enable, Types{ types });

  // Probe types
  test("kr:f { override(-1); }", UnsafeMode::Enable, Error{}, Types{ types });
  test("u:/bin/sh:f { override(-1); }",
       UnsafeMode::Enable,
       Error{},
       Types{ types });
  test("t:syscalls:sys_enter_openat { override(-1); }",
       UnsafeMode::Enable,
       Error{},
       Types{ types });
  test("i:s:1 { override(-1); }", UnsafeMode::Enable, Error{}, Types{ types });
  test("p:hz:1 { override(-1); }", UnsafeMode::Enable, Error{}, Types{ types });
}

TEST_F(TypeCheckerTest, unwatch)
{
  test("i:s:1 { unwatch(12345) }");
  test("i:s:1 { unwatch(0x1234) }");
  test("i:s:1 { $x = 1; unwatch($x); }");
  test("i:s:1 { @x = 1; @x++; unwatch(@x); }");
  test("k:f { unwatch(arg0); }");
  test("k:f { unwatch((int64)arg0); }");
  test("k:f { unwatch(*(int64*)arg0); }");

  test("i:s:1 { unwatch(\"asdf\") }", Error{});
  test(R"(i:s:1 { @x["hi"] = "world"; unwatch(@x["hi"]) })", Error{});
  test("i:s:1 { printf(\"%d\", unwatch(2)) }", Error{});
}

TEST_F(TypeCheckerTest, struct_member_keywords)
{
  // These are valid builtins / existing keywords in scripts, and we ensure that
  // these are not parsed in that way and are instead treated as fields.
  std::string keywords[] = {
    "arg0",   "args",   "curtask", "func",   "gid",      "rand",
    "uid",    "avg",    "cat",     "exit",   "kaddr",    "min",
    "printf", "usym",   "kstack",  "ustack", "bpftrace", "perf",
    "raw",    "uprobe", "kprobe",  "config", "fn",       "errorf",
  };
  for (auto kw : keywords) {
    test("struct S{ int " + kw + ";}; k:f { ((struct S*)arg0)->" + kw + "}");
    test("struct S{ int " + kw + ";}; k:f { (*(struct S*)arg0)." + kw + "}");
  }
}

TEST_F(TypeCheckerTest, jumps)
{
  test("i:s:1 { return; }");
  // must be used in loops
  test("i:s:1 { break; }", Error{});
  test("i:s:1 { continue; }", Error{});
}

TEST_F(TypeCheckerTest, while_loop)
{
  test("i:s:1 { $a = 1; while ($a < 10) { $a++ }}");
  test("i:s:1 { $a = 1; while (1) { if($a > 50) { break } $a++ }}");
  test("i:s:1 { $a = 1; while ($a < 10) { $a++ }}");
  test("i:s:1 { $a = 1; while (1) { if($a > 50) { break } $a++ }}");
  test(R"(
i:s:1 {
  $a = 1;
  while ($a < 10) {
    $a++; $j=0;
    while ($j < 10) {
      $j++;
    }
  }
})");
  test("i:s:1 { $a = 1; while (1) { if($a > 50) { return } $a++ }}");

  test("i:s:1 { $a = 1; while ($a < 10) { break; $a++ }}",
       Warning{ "Unreachable" });
  test("i:s:1 { $a = 1; while ($a < 10) { continue; $a++ }}",
       Warning{ "Unreachable" });
  test("i:s:1 { $a = 1; while ($a < 10) { @=$a++; print(@); }}",
       Warning{ "'print()' in a loop" });

  test("i:s:1 { $a = 1; while ($a < 10) { return; $a++ }}",
       Warning{ "Unreachable" });
}

TEST_F(TypeCheckerTest, type_ctx)
{
  std::string structs = "struct c {char c} struct x { long a; short b[4]; "
                        "struct c c; struct c *d;}";
  auto ast = test(structs + "kprobe:f { $x = (struct x*)ctx; $a "
                            "= $x->a; $b = $x->b[0]; "
                            "$c = $x->c.c; $d = $x->d->c;}");
  auto &stmts = ast.root->probes.at(0)->block->stmts;

  // $x = (struct x*)ctx;
  auto *assignment = stmts.at(0).as<ast::AssignVarStatement>();
  EXPECT_TRUE(assignment->var()->var_type.IsPtrTy());

  // $a = $x->a;
  assignment = stmts.at(1).as<ast::AssignVarStatement>();
  EXPECT_EQ(CreateInt64(), assignment->var()->var_type);
  auto *fieldaccess = assignment->expr.as<ast::FieldAccess>();
  EXPECT_EQ(CreateInt64(), fieldaccess->field_type);
  auto *unop = fieldaccess->expr.as<ast::Unop>();
  EXPECT_TRUE(unop->result_type.IsCtxAccess());
  auto *var = unop->expr.as<ast::Variable>();
  EXPECT_TRUE(var->var_type.IsPtrTy());

  // $b = $x->b[0];
  assignment = stmts.at(2).as<ast::AssignVarStatement>();
  EXPECT_EQ(CreateInt16(), assignment->var()->var_type);
  auto *arrayaccess = assignment->expr.as<ast::ArrayAccess>();
  EXPECT_EQ(CreateInt16(), arrayaccess->element_type);
  fieldaccess = arrayaccess->expr.as<ast::FieldAccess>();
  EXPECT_TRUE(fieldaccess->field_type.IsCtxAccess());
  unop = fieldaccess->expr.as<ast::Unop>();
  EXPECT_TRUE(unop->result_type.IsCtxAccess());
  var = unop->expr.as<ast::Variable>();
  EXPECT_TRUE(var->var_type.IsPtrTy());

  class SizedType chartype;
  if (arch::Host::Machine == arch::Machine::X86_64) {
    chartype = CreateInt8();
  } else {
    chartype = CreateUInt8();
  }

  // $c = $x->c.c;
  assignment = stmts.at(3).as<ast::AssignVarStatement>();
  EXPECT_EQ(chartype, assignment->var()->var_type);
  fieldaccess = assignment->expr.as<ast::FieldAccess>();
  EXPECT_EQ(chartype, fieldaccess->field_type);
  fieldaccess = fieldaccess->expr.as<ast::FieldAccess>();
  EXPECT_TRUE(fieldaccess->field_type.IsCtxAccess());
  unop = fieldaccess->expr.as<ast::Unop>();
  EXPECT_TRUE(unop->result_type.IsCtxAccess());
  var = unop->expr.as<ast::Variable>();
  EXPECT_TRUE(var->var_type.IsPtrTy());

  // $d = $x->d->c;
  assignment = stmts.at(4).as<ast::AssignVarStatement>();
  EXPECT_EQ(chartype, assignment->var()->var_type);
  fieldaccess = assignment->expr.as<ast::FieldAccess>();
  EXPECT_EQ(chartype, fieldaccess->field_type);
  unop = fieldaccess->expr.as<ast::Unop>();
  EXPECT_TRUE(unop->result_type.IsCStructTy());
  fieldaccess = unop->expr.as<ast::FieldAccess>();
  EXPECT_TRUE(fieldaccess->field_type.IsPtrTy());
  unop = fieldaccess->expr.as<ast::Unop>();
  EXPECT_TRUE(unop->result_type.IsCtxAccess());
  var = unop->expr.as<ast::Variable>();
  EXPECT_TRUE(var->var_type.IsPtrTy());

  test("k:f, kr:f { @ = (uint64)ctx; }");
  test("t:sched:sched_one { @ = (uint64)ctx; }", Error{});
}

TEST_F(TypeCheckerTest, double_pointer_basic)
{
  test(R"_(begin { $pp = (int8 **)0; $p = *$pp; $val = *$p; })_");
  test(R"_(begin { $pp = (int8 **)0; $val = **$pp; })_");

  const std::string structs = "struct Foo { int x; }";
  test(structs + R"_(begin { $pp = (struct Foo **)0; $val = (*$pp)->x; })_");
}

TEST_F(TypeCheckerTest, double_pointer_int)
{
  auto ast = test("kprobe:f { $pp = (int8 **)1; $p = *$pp; $val = *$p; }");
  auto &stmts = ast.root->probes.at(0)->block->stmts;

  // $pp = (int8 **)1;
  auto *assignment = stmts.at(0).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsPtrTy());
  ASSERT_TRUE(assignment->var()->var_type.GetPointeeTy().IsPtrTy());
  ASSERT_TRUE(
      assignment->var()->var_type.GetPointeeTy().GetPointeeTy().IsIntTy());
  EXPECT_EQ(assignment->var()
                ->var_type.GetPointeeTy()
                .GetPointeeTy()
                .GetIntBitWidth(),
            8ULL);

  // $p = *$pp;
  assignment = stmts.at(1).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsPtrTy());
  ASSERT_TRUE(assignment->var()->var_type.GetPointeeTy().IsIntTy());
  EXPECT_EQ(assignment->var()->var_type.GetPointeeTy().GetIntBitWidth(), 8ULL);

  // $val = *$p;
  assignment = stmts.at(2).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsIntTy());
  EXPECT_EQ(assignment->var()->var_type.GetIntBitWidth(), 8ULL);
}

TEST_F(TypeCheckerTest, double_pointer_struct)
{
  auto ast = test(
      "struct Foo { char x; long y; }"
      "kprobe:f { $pp = (struct Foo **)1; $p = *$pp; $val = $p->x; }");
  auto &stmts = ast.root->probes.at(0)->block->stmts;

  // $pp = (struct Foo **)1;
  auto *assignment = stmts.at(0).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsPtrTy());
  ASSERT_TRUE(assignment->var()->var_type.GetPointeeTy().IsPtrTy());
  ASSERT_TRUE(
      assignment->var()->var_type.GetPointeeTy().GetPointeeTy().IsCStructTy());
  EXPECT_EQ(assignment->var()->var_type.GetPointeeTy().GetPointeeTy().GetName(),
            "struct Foo");

  // $p = *$pp;
  assignment = stmts.at(1).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsPtrTy());
  ASSERT_TRUE(assignment->var()->var_type.GetPointeeTy().IsCStructTy());
  EXPECT_EQ(assignment->var()->var_type.GetPointeeTy().GetName(), "struct Foo");

  // $val = $p->x;
  assignment = stmts.at(2).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsIntTy());
  EXPECT_EQ(assignment->var()->var_type.GetIntBitWidth(), 8ULL);
}

TEST_F(TypeCheckerTest, pointer_arith)
{
  test(R"(begin { $t = (int32*) 32; $t = $t + 1 })");
  test(R"(begin { $t = (int32*) 32; $t +=1 })");
  test(R"(begin { $t = (int32*) 32; $t++ })");
  test(R"(begin { $t = (int32*) 32; ++$t })");
  test(R"(begin { $t = (int32*) 32; $t = $t - 1 })");
  test(R"(begin { $t = (int32*) 32; $t -=1 })");
  test(R"(begin { $t = (int32*) 32; $t-- })");
  test(R"(begin { $t = (int32*) 32; --$t })");

  // pointer compare
  test(R"(begin { $t = (int32*) 32; @ = ($t > $t); })");
  test(R"(begin { $t = (int32*) 32; @ = ($t < $t); })");
  test(R"(begin { $t = (int32*) 32; @ = ($t >= $t); })");
  test(R"(begin { $t = (int32*) 32; @ = ($t <= $t); })");
  test(R"(begin { $t = (int32*) 32; @ = ($t == $t); })");

  // map
  test(R"(begin { @ = (int32*) 32; @ = @ + 1 })");
  test(R"(begin { @ = (int32*) 32; @ +=1 })");
  test(R"(begin { @ = (int32*) 32; @++ })");
  test(R"(begin { @ = (int32*) 32; ++@ })");
  test(R"(begin { @ = (int32*) 32; @ = @ - 1 })");
  test(R"(begin { @ = (int32*) 32; @ -=1 })");
  test(R"(begin { @ = (int32*) 32; @-- })");
  test(R"(begin { @ = (int32*) 32; --@ })");

  // associativity
  test(R"(begin { $t = (int32*) 32; $t = $t + 1 })");
  test(R"(begin { $t = (int32*) 32; $t = 1 + $t })");
  test(R"(begin { $t = (int32*) 32; $t = $t - 1 })");
  test(R"(begin { $t = (int32*) 32; $t = 1 - $t })", Error{});

  // invalid ops
  test(R"(begin { $t = (int32*) 32; $t *= 5 })", Error{});
  test(R"(begin { $t = (int32*) 32; $t /= 5 })", Error{});
  test(R"(begin { $t = (int32*) 32; $t %= 5 })", Error{});
  test(R"(begin { $t = (int32*) 32; $t <<= 5 })", Error{});
  test(R"(begin { $t = (int32*) 32; $t >>= 5 })", Error{});

  test(R"(begin { $t = (int32*) 32; $t -= $t })", Error{});
  test(R"(begin { $t = (int32*) 32; $t += $t })", Error{});

  // invalid types
  test(R"(begin { $t = (int32*) 32; $t += "abc" })", Error{});
  test(R"(begin { $t = (int32*) 32; $t += comm })", Error{});
  test(
      R"(struct A {}; begin { $t = (int32*) 32; $s = *(struct A*) 0; $t += $s })",
      Error{});
}

TEST_F(TypeCheckerTest, pointer_compare)
{
  test(R"(begin { $t = (int32*) 32; $c = $t < 1 })");
  test(R"(begin { $t = (int32*) 32; $c = $t > 1 })");
  test(R"(begin { $t = (int32*) 32; $c = $t <= 1 })");
  test(R"(begin { $t = (int32*) 32; $c = $t >= 1 })");
  test(R"(begin { $t = (int32*) 32; $c = $t != 1 })");

  test(R"(begin { $t = (int32*) 32; $c = $t < $t })");
  test(R"(begin { $t = (int32*) 32; $c = $t > $t })");
  test(R"(begin { $t = (int32*) 32; $c = $t <= $t })");
  test(R"(begin { $t = (int32*) 32; $c = $t >= $t })");
  test(R"(begin { $t = (int32*) 32; $c = $t != $t })");

  // pointer compare diff types
  test(R"(begin { $t = (int32*) 32; $y = (int64*) 1024; @ = ($t > $y); })");
  test(R"(begin { $t = (int32*) 32; $y = (int64*) 1024; @ = ($t < $y); })");
  test(R"(begin { $t = (int32*) 32; $y = (int64*) 1024; @ = ($t >= $y); })");
  test(R"(begin { $t = (int32*) 32; $y = (int64*) 1024; @ = ($t <= $y); })");
  test(R"(begin { $t = (int32*) 32; $y = (int64*) 1024; @ = ($t == $y); })");

  test("k:f { $a = (int8*) 1; $b = (int16*) 2; $c = ($a == $b) }",
       Warning{ "comparison of distinct pointer types: int8, int16" });
}

// Basic functionality test
TEST_F(TypeCheckerTest, tuple)
{
  test(R"(begin { $t = (1)})");
  test(R"(begin { $t = (1, 2); $v = $t;})");
  test(R"(begin { $t = (1, 2, "string")})");
  test(R"(begin { $t = (1, 2, "string"); $t = (3, 4, "other"); })");
  test(R"(begin { $t = (1, kstack()) })");
  test(R"(begin { $t = (1, (2,3)) })");

  test(R"(begin { @t = (1)})");
  test(R"(begin { @t = (1, 2); @v = @t;})");
  test(R"(begin { @t = (1, 2, "string")})");
  test(R"(begin { @t = (1, 2, "string"); @t = (3, 4, "other"); })");
  test(R"(begin { @t = (1, kstack()) })");
  test(R"(begin { @t = (1, (2,3)) })");
  test(R"(begin { $t = (1, (int64)2); $t = (2, (int32)3); })");
  test(R"(begin { $t = (1, (int32)2); $t = (2, (int64)3); })");

  test(R"(begin { $t = (1, 2); $t = (4, "other"); })", Error{});
  test(R"(begin { $t = (1, 2); $t = 5; })", Error{});
  test(R"(begin { $t = (1, count()) })", Error{});

  test(R"(begin { @t = (1, 2); @t = (4, "other"); })", Error{});
  test(R"(begin { @t = (1, 2); @t = 5; })", Error{});
  test(R"(begin { @t = (1, count()) })", Error{});
  test(R"(begin { $t = (1, (2, 3)); $t = (4, ((uint8)5, 6)); })");

  test(R"(begin { $t = (1, (2, 3)); $t = (4, ((int64)5, 6)); })");

  test(R"(begin { $t = (1, ((int8)2, 3)); $t = (4, ((uint64)5, 6)); })",
       Error{ R"(
stdin:1:33-57: ERROR: Type mismatch for $t: trying to assign value of type '(uint8,(uint64,uint8))' when variable already has a type '(uint8,(int8,uint8))'
begin { $t = (1, ((int8)2, 3)); $t = (4, ((uint64)5, 6)); }
                                ~~~~~~~~~~~~~~~~~~~~~~~~
)" });

  test(R"(begin { $t = ((uint8)1, (2, 3)); $t = (4, (5, 6)); })");
  test(R"(begin { @t = (1, 2, "hi"); @t = (3, 4, "hellolongstr"); })");
  test(R"(begin { $t = (1, ("hi", 2)); $t = (3, ("hellolongstr", 4)); })");

  test("begin { @x[1] = hist(10); $y = (1, @x[1]); }", Error{ R"(
stdin:1:36-41: ERROR: Map type hist_t cannot exist inside a tuple.
begin { @x[1] = hist(10); $y = (1, @x[1]); }
                                   ~~~~~
)" });
}

TEST_F(TypeCheckerTest, tuple_indexing)
{
  test(R"(begin { (1,2).0 })");
  test(R"(begin { (1,2).1 })");
  test(R"(begin { (1,2,3).2 })");
  test(R"(begin { $t = (1,2,3).0 })");
  test(R"(begin { $t = (1,2,3); $v = $t.0; })");

  test(R"(begin { (1,2,3).3 })", Error{});
  test(R"(begin { (1,2,3).9999999999999 })", Error{});
}

// More in depth inspection of AST
TEST_F(TypeCheckerTest, tuple_assign_var)
{
  class SizedType ty = CreateTuple(
      Struct::CreateTuple({ CreateUInt8(), CreateString(6) }));
  auto ast = test(R"(begin { $t = (1, "str"); $t = (4, "other"); })");
  auto &stmts = ast.root->probes.at(0)->block->stmts;

  // $t = (1, "str");
  auto *assignment = stmts.at(0).as<ast::AssignVarStatement>();
  EXPECT_EQ(ty, assignment->var()->var_type);

  // $t = (4, "other");
  assignment = stmts.at(1).as<ast::AssignVarStatement>();
  EXPECT_EQ(ty, assignment->var()->var_type);
}

// More in depth inspection of AST
TEST_F(TypeCheckerTest, tuple_assign_map)
{
  auto ast = test(R"(begin { @ = (1, 3, 3, 7); @ = (0, 0, 0, 0); })");
  auto &stmts = ast.root->probes.at(0)->block->stmts;

  // $t = (1, 3, 3, 7);
  auto *assignment = stmts.at(0).as<ast::AssignMapStatement>();
  class SizedType ty = CreateTuple(Struct::CreateTuple(
      { CreateUInt8(), CreateUInt8(), CreateUInt8(), CreateUInt8() }));
  EXPECT_EQ(ty, assignment->map_access->map->value_type);

  // $t = (0, 0, 0, 0);
  assignment = stmts.at(1).as<ast::AssignMapStatement>();
  ty = CreateTuple(Struct::CreateTuple(
      { CreateUInt8(), CreateUInt8(), CreateUInt8(), CreateUInt8() }));
  EXPECT_EQ(ty, assignment->map_access->map->value_type);
}

// More in depth inspection of AST
TEST_F(TypeCheckerTest, tuple_nested)
{
  class SizedType ty_inner = CreateTuple(
      Struct::CreateTuple({ CreateUInt8(), CreateUInt8() }));
  class SizedType ty = CreateTuple(
      Struct::CreateTuple({ CreateUInt8(), ty_inner }));
  auto ast = test(R"(begin { $t = (1,(1,2)); })");
  auto &stmts = ast.root->probes.at(0)->block->stmts;

  // $t = (1, "str");
  auto *assignment = stmts.at(0).as<ast::AssignVarStatement>();
  EXPECT_EQ(ty, assignment->var()->var_type);
}

TEST_F(TypeCheckerTest, mixed_tuple)
{
  // The same resizing rules should exist for ints and strings inside tuples
  test(R"(begin { $a = ((int16)1, "hi"); $a = ((uint16)2, "hellostr"); })");
  test(
      R"(begin { $a = (((int16)1, (uint32)2), "hi"); $a = (((uint16)2, (int32)3), "hellostr"); })");
  test(R"(begin { @a[(int16)1, "hi"] = 1; @a[(uint16)2, "hellostr"] = 2; })");
  test(
      R"(begin { @a[((int16)1, (uint32)2), "hi"] = 1; @a[((uint16)2, (int32)3), "hellostr"] = 2; })");
  test(R"(begin { @a = ((int16)1, "hi"); @a = ((uint16)2, "hellostr"); })");
  test(
      R"(begin { @a = (((int16)1, (uint32)2), "hi"); @a = (((uint16)2, (int32)3), "hellostr"); })");
  test(
      R"(begin { print(if (pid == 1) { ((int16)1, "hi") } else { ((uint16)2, "hellostr") }); })");

  test(R"(begin { $a = ((int64)1, "hi"); $a = ((uint64)2, "hellostr"); })",
       Error{});
  test(R"(begin { @a[(int64)1, "hi"] = 1; @a[(uint64)2, "hellostr"] = 2; })",
       Error{});
  test(R"(begin { @a = ((int64)1, "hi"); @a = ((uint64)2, "hellostr"); })",
       Error{});
  test(
      R"(begin { print(if (pid == 1) { ((int64)1, "hi") } else { ((uint64)2, "hellostr") }); })",
      Error{});

  // Test inserted casts
  test(R"(begin { $a = ((int16)1, "hi"); $a = ((uint16)2, "hellostr"); })",
       ExpectedAST{ Program().WithProbe(Probe(
           { "begin" },
           { AssignVarStatement(
                 Variable("$a"),
                 Tuple(
                     { Cast(Typeof(SizedType(Type::integer)
                                       .WithSize(4)
                                       .WithSigned(true)),
                            Cast(Typeof(SizedType(Type::integer)), Integer(1))),
                       Cast(Typeof(SizedType(Type::string)), String("hi")) })),
             AssignVarStatement(
                 Variable("$a"),
                 Tuple(
                     { Cast(Typeof(SizedType(Type::integer)
                                       .WithSize(4)
                                       .WithSigned(true)),
                            Cast(Typeof(SizedType(Type::integer)), Integer(2))),
                       String("hellostr") })),
             Jump(ast::JumpType::RETURN) })) });
  test(
      R"(begin { $a = ((int16)1, "hi"); $b = ((uint16)2, "hellostr"); $a = $b })",
      ExpectedAST{ Program().WithProbe(Probe(
          { "begin" },
          { AssignVarStatement(
                Variable("$a"),
                Tuple(
                    { Cast(Typeof(SizedType(Type::integer)
                                      .WithSize(4)
                                      .WithSigned(true)),
                           Cast(Typeof(SizedType(Type::integer)), Integer(1))),
                      Cast(Typeof(SizedType(Type::string).WithSize(9)),
                           String("hi")) })),
            AssignVarStatement(Variable("$b"),
                               Tuple({ Cast(Typeof(SizedType(Type::integer)),
                                            Integer(2)),
                                       String("hellostr") })),
            AssignVarStatement(Variable("$a"),
                               Tuple({ Cast(Typeof(SizedType(Type::integer)),
                                            TupleAccess(Variable("$b"), 0)),
                                       TupleAccess(Variable("$b"), 1) })),
            Jump(ast::JumpType::RETURN) })) });
  test(
      R"(begin { $a = ((int16)1, "hi"); $b = ((uint16)2, "hellostr"); $b = $a })",
      ExpectedAST{ Program().WithProbe(Probe(
          { "begin" },
          { AssignVarStatement(Variable("$a"),
                               Tuple({ Cast(Typeof(SizedType(Type::integer)),
                                            Integer(1)),
                                       String("hi") })),
            AssignVarStatement(
                Variable("$b"),
                Tuple(
                    { Cast(Typeof(SizedType(Type::integer)
                                      .WithSize(4)
                                      .WithSigned(true)),
                           Cast(Typeof(SizedType(Type::integer)), Integer(2))),
                      String("hellostr") })),
            AssignVarStatement(
                Variable("$b"),
                Tuple({ Cast(Typeof(SizedType(Type::integer)
                                        .WithSize(4)
                                        .WithSigned(true)),
                             TupleAccess(Variable("$a"), 0)),
                        Cast(Typeof(SizedType(Type::string).WithSize(9)),
                             TupleAccess(Variable("$a"), 1)) })),
            Jump(ast::JumpType::RETURN) })) });
  test(
      R"(begin { @a = ((int16)1, "hi"); @b = ((uint16)2, "hellostr"); @a = @b })",
      ExpectedAST{ Program().WithProbe(Probe(
          { "begin" },
          { AssignMapStatement(
                Map("@a"),
                Integer(0),
                Tuple(
                    { Cast(Typeof(SizedType(Type::integer)
                                      .WithSize(4)
                                      .WithSigned(true)),
                           Cast(Typeof(SizedType(Type::integer)), Integer(1))),
                      Cast(Typeof(SizedType(Type::string).WithSize(9)),
                           String("hi")) })),
            AssignMapStatement(Map("@b"),
                               Integer(0),
                               Tuple({ Cast(Typeof(SizedType(Type::integer)),
                                            Integer(2)),
                                       String("hellostr") })),
            AssignMapStatement(
                Map("@a"),
                Integer(0),
                Tuple({ Cast(Typeof(SizedType(Type::integer)),
                             TupleAccess(MapAccess(Map("@b"), Integer(0)), 0)),
                        TupleAccess(MapAccess(Map("@b"), Integer(0)), 1) })),
            Jump(ast::JumpType::RETURN) })) });
  test(
      R"(begin { print(if (pid == 1) { ((int16)1, "hi") } else { ((uint16)2, "hellostr") }); })",
      ExpectedAST{ Program().WithProbe(Probe(
          { "begin" },
          { ExprStatement(Block(
              { ExprStatement(Call(
                    "print",
                    { If(Binop(Operator::EQ, Builtin("pid"), Integer(1)),
                         Tuple(
                             { Cast(Typeof(SizedType(Type::integer)
                                               .WithSize(4)
                                               .WithSigned(true)),
                                    Cast(Typeof(SizedType(Type::integer)),
                                         Integer(1))),
                               Cast(Typeof(SizedType(Type::string).WithSize(9)),
                                    String("hi")) }),
                         Tuple({ Cast(Typeof(SizedType(Type::integer)
                                                 .WithSize(4)
                                                 .WithSigned(true)),
                                      Cast(Typeof(SizedType(Type::integer)),
                                           Integer(2))),
                                 String("hellostr") })) })),
                Jump(ast::JumpType::RETURN) })) })) });
}

TEST_F(TypeCheckerTest, multi_pass_type_inference_zero_size_int)
{
  // The first pass on processing the Unop
  // does not have enough information to
  // figure out size of `@i` yet. The
  // analyzer figures out the size after
  // seeing the `@i++`. On the second pass
  // the correct size is determined.
  test("begin { if (!@i) { @i++; } }");
}

TEST_F(TypeCheckerTest, call_kptr_uptr)
{
  test("k:f { @  = kptr((int8*) arg0); }");
  test("k:f { $a = kptr((int8*) arg0); }");

  test("k:f { @ = kptr(arg0); }");
  test("k:f { $a = kptr(arg0); }");

  test("k:f { @  = uptr((int8*) arg0); }");
  test("k:f { $a = uptr((int8*) arg0); }");

  test("k:f { @ = uptr(arg0); }");
  test("k:f { $a = uptr(arg0); }");
}

TEST_F(TypeCheckerTest, call_path)
{
  test("kprobe:f { $k = path( arg0 ) }", Error{});
  test("kretprobe:f { $k = path( arg0 ) }", Error{});
  test("tracepoint:category:event { $k = path( NULL ) }", Error{});
  test("kprobe:f { $k = path( arg0 ) }", Error{});
  test("kretprobe:f{ $k = path( \"abc\" ) }", Error{});
  test("tracepoint:category:event { $k = path( -100 ) }", Error{});
  test("uprobe:/bin/sh:f { $k = path( arg0 ) }", Error{});
  test("begin { $k = path( 1 ) }", Error{});
  test("end { $k = path( 1 ) }", Error{});
}

TEST_F(TypeCheckerTest, call_offsetof)
{
  test("struct Foo { int x; long l; char c; } \
        begin { @x = offsetof(struct Foo, x); }");
  test("struct Foo { int comm; } \
        begin { @x = offsetof(struct Foo, comm); }");
  test("struct Foo { int ctx; } \
        begin { @x = offsetof(struct Foo, ctx); }");
  test("struct Foo { int args; } \
        begin { @x = offsetof(struct Foo, args); }");
  test("struct Foo { int x; long l; char c; } \
        struct Bar { struct Foo foo; int x; } \
        begin { @x = offsetof(struct Bar, x); }");
  test("struct Foo { int x; long l; char c; } \
        union Bar { struct Foo foo; int x; } \
        begin { @x = offsetof(union Bar, x); }");
  test("struct Foo { int x; long l; char c; } \
        struct Fun { struct Foo foo; int (*call)(void); } \
        begin { @x = offsetof(struct Fun, call); }");
  test("struct Foo { int x; long l; char c; } \
        begin { $foo = (struct Foo *)0; @x = offsetof(*$foo, x); }");
  test("struct Foo { int x; long l; char c; } \
        struct Ano { \
          struct { \
            struct Foo foo; \
            int a; \
          }; \
          long l; \
        } \
        begin { @x = offsetof(struct Ano, a); }");
  test("struct Foo { struct Bar { int a; } bar; } \
        begin { @x = offsetof(struct Foo, bar.a); }");
  test("struct Foo { struct Bar { int *a; } bar; } \
        begin { @x = offsetof(struct Foo, bar.a); }");
  test("struct Foo { struct Bar { struct { int a; } anon; } bar; } \
        begin { @x = offsetof(struct Foo, bar.anon.a); }");
  test("struct Foo { struct Bar { struct { int a; }; } bar; } \
        begin { @x = offsetof(struct Foo, bar.a); }");

  // Error tests

  // Bad type
  test("struct Foo { struct Bar { int a; } *bar; } \
              begin { @x = offsetof(struct Foo, bar.a); }",
       Error{ R"(
stdin:1:71-98: ERROR: 'struct Bar *' is not a c_struct type.
struct Foo { struct Bar { int a; } *bar; }               begin { @x = offsetof(struct Foo, bar.a); }
                                                                      ~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Not exist (sub)field
  test("struct Foo { int x; long l; char c; } \
              begin { @x = offsetof(struct Foo, __notexistfield__); }",
       Error{ R"(
stdin:1:66-105: ERROR: 'struct Foo' has no field named '__notexistfield__'
struct Foo { int x; long l; char c; }               begin { @x = offsetof(struct Foo, __notexistfield__); }
                                                                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("struct Foo { struct Bar { int a; } bar; } \
              begin { @x = offsetof(struct Foo, bar.__notexist_subfield__); }",
       Error{ R"(
stdin:1:70-117: ERROR: 'struct Bar' has no field named '__notexist_subfield__'
struct Foo { struct Bar { int a; } bar; }               begin { @x = offsetof(struct Foo, bar.__notexist_subfield__); }
                                                                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Not exist c_struct
  test("begin { @x = offsetof(__passident__, x); }", Error{});
  test("begin { @x = offsetof(__passident__, x.y.z); }", Error{});
  test("begin { @x = offsetof(struct __notexiststruct__, x); }", Error{});
  test("begin { @x = offsetof(struct __notexiststruct__, x.y.z); }", Error{});
}

TEST_F(TypeCheckerTest, int_ident)
{
  test("begin { sizeof(int32) }");
}

TEST_F(TypeCheckerTest, string_size)
{
  // Size of the variable should be the size of the larger string (incl. null)
  auto ast = test(R"(begin { $x = "hi"; $x = "hello"; })");
  auto stmt = ast.root->probes.at(0)->block->stmts.at(0);
  auto *var_assign = stmt.as<ast::AssignVarStatement>();
  ASSERT_TRUE(var_assign->expr.is<ast::Cast>());
  ASSERT_TRUE(var_assign->var()->var_type.IsStringTy());
  ASSERT_EQ(var_assign->var()->var_type.GetSize(), 6UL);

  ast = test(R"(k:func_1 {@ = "hi";} k:func_2 {@ = "hello";})");
  stmt = ast.root->probes.at(0)->block->stmts.at(0);
  auto *map_assign = stmt.as<ast::AssignMapStatement>();
  ASSERT_TRUE(map_assign->expr.is<ast::Cast>());
  ASSERT_TRUE(map_assign->map_access->map->value_type.IsStringTy());
  ASSERT_EQ(map_assign->map_access->map->value_type.GetSize(), 6UL);

  ast = test(R"(k:func_1 {@["hi"] = 0;} k:func_2 {@["hello"] = 1;})");
  stmt = ast.root->probes.at(0)->block->stmts.at(0);
  map_assign = stmt.as<ast::AssignMapStatement>();
  ASSERT_TRUE(map_assign->map_access->key.is<ast::Cast>());
  ASSERT_TRUE(map_assign->map_access->key.type().IsStringTy());
  ASSERT_EQ(map_assign->map_access->key.type().GetSize(), 6UL);
  ASSERT_EQ(map_assign->map_access->map->key_type.GetSize(), 6UL);

  ast = test(R"(k:func_1 {@["hi", 0] = 0;} k:func_2 {@["hello", 1] = 1;})");
  stmt = ast.root->probes.at(0)->block->stmts.at(0);
  map_assign = stmt.as<ast::AssignMapStatement>();
  ASSERT_TRUE(map_assign->map_access->key.as<ast::Tuple>()
                  ->elems.at(0)
                  .is<ast::Cast>());
  ASSERT_TRUE(map_assign->map_access->key.type().IsTupleTy());
  ASSERT_TRUE(map_assign->map_access->key.type().GetField(0).type.IsStringTy());
  ASSERT_EQ(map_assign->map_access->key.type().GetField(0).type.GetSize(), 6UL);
  ASSERT_EQ(map_assign->map_access->map->key_type.GetField(0).type.GetSize(),
            6UL);
  ASSERT_EQ(map_assign->map_access->key.type().GetSize(), 7UL);
  ASSERT_EQ(map_assign->map_access->map->key_type.GetSize(), 7UL);

  ast = test(R"(k:func_1 {$x = ("hello", 0);} k:func_2 {$x = ("hi", 0); })");
  stmt = ast.root->probes.at(0)->block->stmts.at(0);
  var_assign = stmt.as<ast::AssignVarStatement>();
  ASSERT_TRUE(var_assign->var()->var_type.IsTupleTy());
  ASSERT_TRUE(var_assign->var()->var_type.GetField(0).type.IsStringTy());
  ASSERT_EQ(var_assign->var()->var_type.GetSize(),
            7UL); // tuples are not
                  // packed
  ASSERT_EQ(var_assign->var()->var_type.GetField(0).type.GetSize(), 6UL);
}

TEST_F(TypeCheckerTest, call_nsecs)
{
  test("begin { $ns = nsecs(); }");
  test("begin { $ns = nsecs(monotonic); }");
  test("begin { $ns = nsecs(boot); }");
  test("begin { $ns = nsecs(tai); }");
  test("begin { $ns = nsecs(sw_tai); }");
  test("begin { $ns = nsecs(xxx); }", Error{ R"(
stdin:1:21-24: ERROR: Invalid timestamp mode: xxx
begin { $ns = nsecs(xxx); }
                    ~~~
)" });
}

TEST_F(TypeCheckerTest, call_pid_tid)
{
  test("begin { $i = tid(); }");
  test("begin { $i = pid(); }");
  test("begin { $i = tid(curr_ns); }");
  test("begin { $i = pid(curr_ns); }");
  test("begin { $i = tid(init); }");
  test("begin { $i = pid(init); }");
}

TEST_F(TypeCheckerTest, subprog_return)
{
  test("fn f(): void { return; }");
  test("fn f(): uint8 { return 1; }");

  // Error location is incorrect: #3063
  test("fn f(): void { return 1; }", Error{ R"(
stdin:1:16-24: ERROR: Function f is of type void, cannot return uint8
fn f(): void { return 1; }
               ~~~~~~~~
)" });
  // Error location is incorrect: #3063
  test("fn f(): int64 { return; }", Error{ R"(
stdin:1:17-23: ERROR: Function f is of type int64, cannot return void
fn f(): int64 { return; }
                ~~~~~~
)" });
}

TEST_F(TypeCheckerTest, subprog_arguments)
{
  test("fn f($a : int64): int64 { return $a; }");
  // Error location is incorrect: #3063
  test("fn f($a : int64): string { return $a; }", Error{ R"(
stdin:1:28-37: ERROR: Function f is of type string, cannot return int64
fn f($a : int64): string { return $a; }
                           ~~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, subprog_map)
{
  test("fn f(): void { @a = 0; }");
  test("fn f(): uint64 { @a = 0; return @a + 1; }");
  test("fn f(): void { @a[0] = 0; }");
  test("fn f(): uint64 { @a[0] = 0; return @a[0] + 1; }");
}

TEST_F(TypeCheckerTest, subprog_builtin)
{
  test("fn f(): void { print(\"Hello world\"); }");
  test("fn f(): uint8 { return sizeof(int64); }");
  test("fn f(): uint64 { return nsecs; }");
}

TEST_F(TypeCheckerTest, subprog_builtin_disallowed)
{
  // Error location is incorrect: #3063
  test("fn f(): int64 { return func; }", Error{ R"(
ERROR: Builtin __builtin_func not supported outside probe
)" });
}

class TypeCheckerBTFTest : public TypeCheckerHarness, public test_btf {};

TEST_F(TypeCheckerBTFTest, fentry)
{
  test("fentry:func_1 { 1 }");
  test("fexit:func_1 { 1 }");
  test("fentry:func_1 { $x = args.a; $y = args.foo1; $z = args.foo2->f.a; }");
  test("fexit:func_1 { $x = retval; }");
  test("fentry:vmlinux:func_1 { 1 }");
  test("fentry:*:func_1 { 1 }");

  test("fexit:func_1 { $x = args.foo; }", Error{ R"(
stdin:1:25-26: ERROR: Can't find function parameter foo
fexit:func_1 { $x = args.foo; }
                        ~
)" });
  test("fexit:func_1 { $x = args; }");
  test("fentry:func_1 { @ = args; }");
  test("fentry:func_1 { @[args] = 1; }");
  // Backwards compatibility
  test("fentry:func_1 { $x = args->a; }");
}

TEST_F(TypeCheckerBTFTest, short_name)
{
  test("f:func_1 { 1 }");
  test("fr:func_1 { 1 }");
}

TEST_F(TypeCheckerBTFTest, call_path)
{
  test("fentry:func_1 { @k = path( args.foo1 ) }");
  test("fexit:func_1 { @k = path( retval->foo1 ) }");
  test("fentry:func_1 { path(args.foo1, 16); }");
}

TEST_F(TypeCheckerBTFTest, call_skb_output)
{
  test("fentry:func_1 { $ret = skboutput(\"one.pcap\", args.foo1, 1500, 0); "
       "}");
  test("fexit:func_1 { $ret = skboutput(\"one.pcap\", args.foo1, 1500, 0); }");
}

TEST_F(TypeCheckerBTFTest, call_percpu_kaddr)
{
  test("kprobe:f { percpu_kaddr(\"process_counts\"); }");
  test("kprobe:f { percpu_kaddr(\"process_counts\", 0); }");
  test("kprobe:f { @x = percpu_kaddr(\"process_counts\"); }");
  test("kprobe:f { @x = percpu_kaddr(\"process_counts\", 0); }");
  test("kprobe:f { percpu_kaddr(0); }", Error{});

  test("kprobe:f { percpu_kaddr(\"nonsense\"); }",
       UnsafeMode::Enable,
       Error{ R"(
stdin:1:12-36: ERROR: Could not resolve variable "nonsense" from BTF
kprobe:f { percpu_kaddr("nonsense"); }
           ~~~~~~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(TypeCheckerBTFTest, call_socket_cookie)
{
  test("fentry:tcp_shutdown { $ret = socket_cookie(args.sk); }");
  test("fexit:tcp_shutdown { $ret = socket_cookie(args.sk); }");

  test("fentry:tcp_shutdown { $ret = socket_cookie(args.how); }", Error{ R"(
stdin:1:30-53: ERROR: socket_cookie() only supports pointer arguments (int provided)
fentry:tcp_shutdown { $ret = socket_cookie(args.how); }
                             ~~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("fentry:func_1 { $ret = socket_cookie(args.foo1); }", Error{ R"(
stdin:1:24-48: ERROR: socket_cookie() only supports 'struct sock *' as the argument ('struct Foo1 *' provided)
fentry:func_1 { $ret = socket_cookie(args.foo1); }
                       ~~~~~~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(TypeCheckerBTFTest, rawtracepoint)
{
  test("rawtracepoint:event_rt { args.first_real_arg }");

  test("rawtracepoint:event_rt { args.bad_arg }", Error{ R"(
stdin:1:30-31: ERROR: Can't find function parameter bad_arg
rawtracepoint:event_rt { args.bad_arg }
                             ~
)" });
}

// Sanity check for kfunc/kretfunc aliases
TEST_F(TypeCheckerBTFTest, kfunc)
{
  test("kfunc:func_1 { 1 }");
  test("kretfunc:func_1 { 1 }");
  test("kfunc:func_1 { $x = args.a; $y = args.foo1; $z = args.foo2->f.a; }");
  test("kretfunc:func_1 { $x = retval; }");
  test("kfunc:vmlinux:func_1 { 1 }");
  test("kfunc:*:func_1 { 1 }");
  test("kfunc:func_1 { @[func] = 1; }");

  test("kretfunc:func_1 { $x = args.foo; }", Error{ R"(
stdin:1:28-29: ERROR: Can't find function parameter foo
kretfunc:func_1 { $x = args.foo; }
                           ~
)" });
  test("kretfunc:func_1 { $x = args; }");
  test("kfunc:func_1 { @ = args; }");
  test("kfunc:func_1 { @[args] = 1; }");
  // Backwards compatibility
  test("kfunc:func_1 { $x = args->a; }");
}

TEST_F(TypeCheckerBTFTest, ntop)
{
  test(R"(fentry:func_arrays { printf("%s\n", ntop(args.arr.char_arr2)); })");
}

TEST_F(TypeCheckerTest, btf_type_tags)
{
  auto bpftrace = get_mock_bpftrace();
  auto type = bpftrace->structs.Add("struct Foo", 16);

  auto ptr_type_w_tag = CreatePointer(CreateInt8());
  ptr_type_w_tag.SetBtfTypeTags({ "rcu" });
  auto ptr_type_w_bad_tag = CreatePointer(CreateInt8());
  ptr_type_w_bad_tag.SetBtfTypeTags({ "rcu", "percpu" });

  type.lock()->AddField("field_with_tag", ptr_type_w_tag, 8);
  type.lock()->AddField("field_with_bad_tag", ptr_type_w_bad_tag, 16);

  test("kprobe:f { ((struct Foo *)arg0)->field_with_tag }", Mock{ *bpftrace });
  test("kprobe:f { ((struct Foo *)arg0)->field_with_bad_tag }",
       Mock{ *bpftrace },
       Error{ R"(
stdin:1:32-34: ERROR: Attempting to access pointer field 'field_with_bad_tag' with unsupported tag attribute: percpu
kprobe:f { ((struct Foo *)arg0)->field_with_bad_tag }
                               ~~
)" });
}

TEST_F(TypeCheckerTest, for_loop_map_one_key)
{
  test("begin { @map[0] = 1; for ($kv : @map) { print($kv); } }",
       ExpectedAST{ Program().WithProbe(
           Probe({ "begin" },
                 { AssignMapStatement(Map("@map"), Integer(0), Integer(1)),
                   For(Variable("$kv"),
                       Map("@map"),
                       { ExprStatement(Block(
                           { ExprStatement(Call("print", { Variable("$kv") })),
                             Jump(ast::JumpType::CONTINUE) })) }),
                   Jump(ast::JumpType::RETURN) })) });
}

TEST_F(TypeCheckerTest, for_loop_map_two_keys)
{
  test("begin { @map[0,0] = 1; for ($kv : @map) { print($kv); } }",
       ExpectedAST{ Program().WithProbe(Probe(
           { "begin" },
           { AssignMapStatement(
                 Map("@map"), Tuple({ Integer(0), Integer(0) }), Integer(1)),
             For(Variable("$kv"),
                 Map("@map"),
                 { ExprStatement(
                     Block({ ExprStatement(Call("print", { Variable("$kv") })),
                             Jump(ast::JumpType::CONTINUE) })) }),
             Jump(ast::JumpType::RETURN) })) });
}

TEST_F(TypeCheckerTest, for_loop_map)
{
  test("begin { @map[0] = 1; for ($kv : @map) { print($kv); } }");
  test("begin { @map[0] = 1; for ($kv : @map) { print($kv.0); } }");
  test("begin { @map[0] = 1; for ($kv : @map) { print($kv.1); } }");
  test("begin {@map1[@map2] = 1; @map2 = 1; for ($kv : @map1) {print($kv);}}");
}

TEST_F(TypeCheckerTest, for_loop_map_declared_after)
{
  // Regression test: What happens with
  // @map[$kv.0] when @map hasn't been
  // defined yet?
  test("begin { for ($kv : @map) { @map[$kv.0] } @map[0] = 1; }");
}

TEST_F(TypeCheckerTest, for_loop_map_no_key)
{
  // Error location is incorrect: #3063
  test("begin { @map = 1; for ($kv : @map) { } }", Error{ R"(
stdin:1:30-34: ERROR: @map has no explicit keys (scalar map), and cannot be used for iteration
begin { @map = 1; for ($kv : @map) { } }
                             ~~~~
)" });
}

TEST_F(TypeCheckerTest, for_loop_map_undefined)
{
  // Error location is incorrect: #3063
  test("begin { for ($kv : @map) { } }", Error{ R"(
stdin:1:20-24: ERROR: Undefined map: @map
begin { for ($kv : @map) { } }
                   ~~~~
)" });
}

TEST_F(TypeCheckerTest, for_loop_map_undefined2)
{
  // Error location is incorrect: #3063
  test("begin { @map[0] = 1; for ($kv : @undef) { @map[$kv.0]; } }", Error{ R"(
stdin:1:33-39: ERROR: Undefined map: @undef
begin { @map[0] = 1; for ($kv : @undef) { @map[$kv.0]; } }
                                ~~~~~~
)" });
}

TEST_F(TypeCheckerTest, for_loop_map_restricted_types)
{
  test("begin { @map[0] = hist(10); for ($kv : @map) { } }", Error{ R"(
stdin:1:40-44: ERROR: Loop expression does not support type: hist_t
begin { @map[0] = hist(10); for ($kv : @map) { } }
                                       ~~~~
)" });
  test("begin { @map[0] = lhist(10, 0, 10, 1); for ($kv : @map) { } }",
       Error{ R"(
stdin:1:51-55: ERROR: Loop expression does not support type: lhist_t
begin { @map[0] = lhist(10, 0, 10, 1); for ($kv : @map) { } }
                                                  ~~~~
)" });
  test("begin { @map[0] = tseries(10, 10s, 10); for ($kv : @map) { } }",
       Error{ R"(
stdin:1:52-56: ERROR: Loop expression does not support type: tseries_t
begin { @map[0] = tseries(10, 10s, 10); for ($kv : @map) { } }
                                                   ~~~~
)" });
  test("begin { @map[0] = stats(10); for ($kv : @map) { } }", Error{ R"(
stdin:1:41-45: ERROR: Loop expression does not support type: ustats_t
begin { @map[0] = stats(10); for ($kv : @map) { } }
                                        ~~~~
)" });
}

TEST_F(TypeCheckerTest, for_loop_variables_read_only)
{
  test(
      R"(
    begin {
      $var = 0;
      @map[0] = 1;
      for ($kv : @map) {
        print($var);
      }
      print($var);
    })",
      ExpectedAST{ Program().WithProbe(Probe(
          { "begin" },
          {
              AssignVarStatement(Variable("$var"), Integer(0)),
              AssignMapStatement(Map("@map"), Integer(0), Integer(1)),
              For(Variable("$kv"),
                  Map("@map"),
                  { ExprStatement(Block(
                      { ExprStatement(Call("print", { Variable("$var") })),
                        Jump(ast::JumpType::CONTINUE) })) })
                  .WithContext(
                      bpftrace::test::SizedType(Type::c_struct)
                          .WithField("$var",
                                     bpftrace::test::SizedType(Type::pointer)
                                         .WithElement(bpftrace::test::SizedType(
                                             Type::integer)))),
              ExprStatement(
                  Block({ ExprStatement(Call("print", { Variable("$var") })),
                          Jump(ast::JumpType::RETURN) })),
          })) });
}

TEST_F(TypeCheckerTest, for_loop_variables_modified_during_loop)
{
  test(
      R"(
    begin {
      $var = 0;
      @map[0] = 1;
      for ($kv : @map) {
        $var++;
      }
      print($var);
    })",
      ExpectedAST{ Program().WithProbe(Probe(
          { "begin" },
          {
              AssignVarStatement(Variable("$var"), Integer(0)),
              AssignMapStatement(Map("@map"), Integer(0), Integer(1)),
              For(Variable("$kv"),
                  Map("@map"),
                  { ExprStatement(
                      Block({ ExprStatement(Unop(Operator::POST_INCREMENT,
                                                 Variable("$var"))),
                              Jump(ast::JumpType::CONTINUE) })) })
                  .WithContext(
                      bpftrace::test::SizedType(Type::c_struct)
                          .WithField("$var",
                                     bpftrace::test::SizedType(Type::pointer)
                                         .WithElement(bpftrace::test::SizedType(
                                             Type::integer)))),
              ExprStatement(
                  Block({ ExprStatement(Call("print", { Variable("$var") })),
                          Jump(ast::JumpType::RETURN) })),
          })) });
}

TEST_F(TypeCheckerTest, for_loop_variables_created_in_loop)
{
  test(R"(
    begin {
      @map[0] = 1;
      for ($kv : @map) {
        $var = 2;
        print($var);
      }
    })",
       ExpectedAST{ Program().WithProbe(Probe(
           { "begin" },
           { AssignMapStatement(Map("@map"), Integer(0), Integer(1)),
             For(Variable("$kv"),
                 Map("@map"),
                 { AssignVarStatement(Variable("$var"), Integer(2)),
                   ExprStatement(Block(
                       { ExprStatement(Call("print", { Variable("$var") })),
                         Jump(ast::JumpType::CONTINUE) })) })
                 .WithContext(testing::Not(
                     SizedType(Type::c_struct).WithField("$var", _))),
             Jump(ast::JumpType::RETURN) })) });
}

TEST_F(TypeCheckerTest, for_loop_variables_multiple)
{
  test(
      R"(
    begin {
      @map[0] = 1;
      $var1 = 123;
      $var2 = "abc";
      $var3 = "def";
      for ($kv : @map) {
        $var1 = 100;
        print($var3);
      }
    })",
      ExpectedAST{ Program().WithProbe(Probe(
          { "begin" },
          { AssignMapStatement(Map("@map"), Integer(0), Integer(1)),
            AssignVarStatement(Variable("$var1"), Integer(123)),
            AssignVarStatement(Variable("$var2"), String("abc")),
            AssignVarStatement(Variable("$var3"), String("def")),
            For(Variable("$kv"),
                Map("@map"),
                { AssignVarStatement(Variable("$var1"), Integer(100)),
                  ExprStatement(Block(
                      { ExprStatement(Call("print", { Variable("$var3") })),
                        Jump(ast::JumpType::CONTINUE) })) })
                .WithContext(
                    bpftrace::test::SizedType(Type::c_struct)
                        .WithField("$var1",
                                   SizedType(Type::pointer)
                                       .WithElement(bpftrace::test::SizedType(
                                           Type::integer)))
                        .WithField("$var3",
                                   SizedType(Type::pointer)
                                       .WithElement(bpftrace::test::SizedType(
                                           Type::string)))),
            Jump(ast::JumpType::RETURN) })) });
}

TEST_F(TypeCheckerTest, for_loop_invalid_expr)
{
  // Error location is incorrect: #3063
  test("begin { for ($x : $var) { } }", Error{ R"(
stdin:1:23-24: ERROR: syntax error, unexpected ), expecting [ or . or ->
begin { for ($x : $var) { } }
                      ~
)" });
  test("begin { for ($x : 1+2) { } }", Error{ R"(
stdin:1:20-21: ERROR: syntax error, unexpected +, expecting [ or . or ->
begin { for ($x : 1+2) { } }
                   ~
)" });
  test("begin { for ($x : \"abc\") { } }", Error{ R"(
stdin:1:24-25: ERROR: syntax error, unexpected ), expecting [ or . or ->
begin { for ($x : "abc") { } }
                       ~
)" });
}

TEST_F(TypeCheckerTest, for_loop_control_flow)
{
  test("begin { @map[0] = 1; for ($kv : @map) { break; } }");
  test("begin { @map[0] = 1; for ($kv : @map) { continue; } }");
  test("begin { @map[0] = 1; for ($kv : @map) { return; } }");
}

TEST_F(TypeCheckerTest, for_range_loop)
{
  // These are all technically valid,
  // although they may result in zero
  // iterations (for example 5..0 will
  // result in no iterations).
  test(R"(begin { for ($i : 0..5) { printf("%d\n", $i); } })");
  test(R"(begin { for ($i : 5..0) { printf("%d\n", $i); } })");
  test(R"(begin { for ($i : (-10)..10) { printf("%d\n", $i); } })");
  test(R"(begin { $start = 0; for ($i : $start..5) { printf("%d\n", $i); } })");
  test(R"(begin { $end = 5; for ($i : 0..$end) { printf("%d\n", $i); } })");
  test(
      R"(begin { $start = 0; $end = 5; for ($i : $start..$end) { printf("%d\n", $i); } })");
  test(
      R"(begin { for ($i : nsecs()..(nsecs()+100)) { printf("%d\n", $i); } })");
  test(
      R"(begin { for ($i : sizeof(int8)..sizeof(int64)) { printf("%d\n", $i); } })");
  test(R"(begin { for ($i : ((int8)0)..((int8)5)) { printf("%d\n", $i); } })");
}

TEST_F(TypeCheckerTest, for_range_nested)
{
  test("begin { for ($i : 0..5) { "
       "for ($j : 0..$i) { printf(\"%d %d\\n\", $i, $j); } "
       "} }");
}

TEST_F(TypeCheckerTest, for_range_variable_use)
{
  test("begin { for ($i : 0..5) { @[$i] = "
       "$i * 2; } }");
}

TEST_F(TypeCheckerTest, for_range_invalid_types)
{
  test(R"(begin { for ($i : "str"..5) { printf("%d", $i); } })", Error{ R"(
stdin:1:23-27: ERROR: Loop range requires an integer for the start value
begin { for ($i : "str"..5) { printf("%d", $i); } }
                      ~~~~
)" });

  test(R"(begin { for ($i : 0.."str") { printf("%d", $i); } })", Error{ R"(
stdin:1:19-27: ERROR: Loop range requires an integer for the end value
begin { for ($i : 0.."str") { printf("%d", $i); } }
                  ~~~~~~~~
)" });

  test(R"(begin { for ($i : 0.0..5) { printf("%d", $i); } })", Error{ R"(
stdin:1:19-25: ERROR: Loop range requires an integer for the start value
begin { for ($i : 0.0..5) { printf("%d", $i); } }
                  ~~~~~~
)" });
}

TEST_F(TypeCheckerTest, for_range_control_flow)
{
  test("begin { for ($i : 0..5) { break; } }");
  test("begin { for ($i : 0..5) { continue; } }");
  test("begin { for ($i : 0..5) { return; } }");
}

TEST_F(TypeCheckerTest, for_range_context_access)
{
  test("kprobe:f { for ($i : 0..5) { arg0 } }", Error{ R"(
stdin:1:30-34: ERROR: 'arg0' builtin is not allowed in a for-loop
kprobe:f { for ($i : 0..5) { arg0 } }
                             ~~~~
)" });
}

TEST_F(TypeCheckerTest, for_range_nested_range)
{
  test("begin { for ($i : 0..5) { for ($j : 0..$i) { "
       "printf(\"%d %d\\n\", $i, $j); "
       "} } }");
}

TEST_F(TypeCheckerTest, castable_map_missing_feature)
{
  test("k:f {  @a = count(); }", NoFeatures::Enable);
  test("k:f {  @a = count(); print(@a) }", NoFeatures::Enable);
  test("k:f {  @a = count(); clear(@a) }", NoFeatures::Enable);
  test("k:f {  @a = count(); zero(@a) }", NoFeatures::Enable);

  test("begin { @a = count(); print((uint64)@a) }",
       NoFeatures::Enable,
       Error{ R"(
stdin:1:37-39: ERROR: Missing required kernel feature: map_lookup_percpu_elem
begin { @a = count(); print((uint64)@a) }
                                    ~~
)" });

  test("begin { @a = count(); print((@a, 1)) }", NoFeatures::Enable, Error{ R"(
stdin:1:30-32: ERROR: Missing required kernel feature: map_lookup_percpu_elem
begin { @a = count(); print((@a, 1)) }
                             ~~
)" });

  test("begin { @a[1] = count(); print(@a[1]) }", NoFeatures::Enable, Error{ R"(
stdin:1:32-37: ERROR: Missing required kernel feature: map_lookup_percpu_elem
begin { @a[1] = count(); print(@a[1]) }
                               ~~~~~
)" });

  test("begin { @a = count(); $b = @a; }", NoFeatures::Enable, Error{ R"(
stdin:1:28-30: ERROR: Missing required kernel feature: map_lookup_percpu_elem
begin { @a = count(); $b = @a; }
                           ~~
)" });

  test("begin { @a = count(); @b = 1; @b = @a; }",
       NoFeatures::Enable,
       Error{ R"(
stdin:1:36-38: ERROR: Missing required kernel feature: map_lookup_percpu_elem
begin { @a = count(); @b = 1; @b = @a; }
                                   ~~
)" });
}

TEST_F(TypeCheckerTest, for_loop_no_ctx_access)
{
  test("kprobe:f { @map[0] = 1; for ($kv : @map) { ctx } }", Error{ R"(
stdin:1:44-47: ERROR: 'ctx' builtin is not allowed in a for-loop
kprobe:f { @map[0] = 1; for ($kv : @map) { ctx } }
                                           ~~~
)" });
}

TEST_F(TypeCheckerBTFTest, args_builtin_mixed_probes)
{
  test("fentry:func_1,rawtracepoint:event_rt { args }");
}

TEST_F(TypeCheckerBTFTest, binop_late_ptr_resolution)
{
  test(R"(fentry:func_1 { if (@a[1] == args.foo1) { } @a[1] = args.foo1; })");
}

TEST_F(TypeCheckerBTFTest, anon_struct_resolution)
{
  test("fentry:func_anon_struct {\n"
       "  @a1 = args.AnonStruct.AnonTypedefArray[0].a;\n"
       "  @a2 = args.AnonTypedef.a;\n"
       "  @b1 = args.AnonStruct.AnonArray[0].b;\n"
       "  $x = args.AnonStruct.AnonArray[0];\n"
       "  $y = $x.a;\n"
       "  $z = $x.AnonSubArray[0].c;\n"
       "}");
}

TEST_F(TypeCheckerTest, buf_strlen_too_large)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->config_->max_strlen = 9999999999;

  test("uprobe:/bin/sh:f { buf(arg0, 4) }", Mock{ *bpftrace }, Error{ R"(
stdin:1:20-32: ERROR: BPFTRACE_MAX_STRLEN too large to use on buffer (9999999999 > 4294967295)
uprobe:/bin/sh:f { buf(arg0, 4) }
                   ~~~~~~~~~~~~
)" });

  test("uprobe:/bin/sh:f { buf(arg0) }", Mock{ *bpftrace }, Error{ R"(
stdin:1:20-29: ERROR: BPFTRACE_MAX_STRLEN too large to use on buffer (9999999999 > 4294967295)
uprobe:/bin/sh:f { buf(arg0) }
                   ~~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, variable_declarations)
{
  test("begin { let $a; $a = 1; }");
  test("begin { let $a: int16; $a = 1; }");
  test("begin { let $a = 1; }");
  test("begin { let $a: uint16 = 1; }");
  test("begin { let $a: int16 = 1; }");
  test("begin { let $a: uint8 = 1; $a = 100; }");
  test("begin { let $a: int8 = 1; $a = -100; }");
  test(R"(begin { let $a: string; $a = "hiya"; })");
  test("begin { let $a: int16; print($a); }");
  test("begin { let $a; print($a); $a = 1; }");
  test(R"(begin { let $a = "hiya"; $a = "longerstr"; })");
  test("begin { let $a: int16 = 1; $a = (int8)2; }");

  // Test more types
  test("struct x { int a; }; begin { let $a: struct x; }");
  test("struct x { int a; }; begin { let $a: struct x *; }");
  test("struct x { int a; } begin { let $a: struct x[10]; }");
  test("begin { if (pid) { let $x; } $x = 2; }");
  test("begin { if (pid) { let $x; } else { let $x; } let $x; }");

  test("begin { let $a: uint16; $a = -1; }", Error{ R"(
stdin:1:25-32: ERROR: Type mismatch for $a: trying to assign value of type 'int32' when variable already has a type 'uint16'
begin { let $a: uint16; $a = -1; }
                        ~~~~~~~
)" });

  test("begin { let $a: uint8 = 1; $a = 10000; }", Error{ R"(
stdin:1:28-38: ERROR: Type mismatch for $a: trying to assign value of type 'uint16' when variable already has a type 'uint8'
begin { let $a: uint8 = 1; $a = 10000; }
                           ~~~~~~~~~~
)" });

  test("begin { let $a: int8 = 1; $a = -10000; }", Error{ R"(
stdin:1:27-38: ERROR: Type mismatch for $a: trying to assign value of type 'int16' when variable already has a type 'int8'
begin { let $a: int8 = 1; $a = -10000; }
                          ~~~~~~~~~~~
)" });

  test("begin { let $a: int8; $a = 10000; }", Error{ R"(
stdin:1:23-33: ERROR: Type mismatch for $a: trying to assign value of type 'int32' when variable already has a type 'int8'
begin { let $a: int8; $a = 10000; }
                      ~~~~~~~~~~
)" });

  test("begin { $a = -1; let $a; }", Error{ R"(
stdin:1:18-24: ERROR: Variable declarations need to occur before variable usage or assignment. Variable: $a
begin { $a = -1; let $a; }
                 ~~~~~~
)" });

  test("begin { let $a: uint16 = -1; }", Error{ R"(
stdin:1:9-28: ERROR: Type mismatch for $a: trying to assign value of type 'int32' when variable already has a type 'uint16'
begin { let $a: uint16 = -1; }
        ~~~~~~~~~~~~~~~~~~~
)" });

  test(R"(begin { let $a: sum_t; })", Error{ R"(
stdin:1:9-22: ERROR: Invalid variable declaration type: sum_t
begin { let $a: sum_t; }
        ~~~~~~~~~~~~~
)" });

  test(R"(begin { let $a: struct bad_task; print($a); })", Error{ R"(
stdin:1:17-32: ERROR: Cannot resolve unknown type "struct bad_task"
begin { let $a: struct bad_task; print($a); }
                ~~~~~~~~~~~~~~~
)" });

  test(R"(begin { $x = 2; if (pid) { let $x; } })", Error{ R"(
stdin:1:28-34: ERROR: Variable declarations need to occur before variable usage or assignment. Variable: $x
begin { $x = 2; if (pid) { let $x; } }
                           ~~~~~~
)" });
}

TEST_F(TypeCheckerTest, variable_address)
{
  test("begin { $a = 1; $b = &$a; @c = &$a; }");

  auto ast = test("begin { $a = 1; $b = &$a; }");
  auto &stmts = ast.root->probes.at(0)->block->stmts;

  auto *assignment = stmts.at(1).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsPtrTy());
  ASSERT_TRUE(assignment->var()->var_type.GetPointeeTy().IsIntTy());

  test("begin { let $a; $b = &$a; }", Error{ R"(
stdin:1:22-25: ERROR: No type available for variable $a
begin { let $a; $b = &$a; }
                     ~~~
)" });
}

TEST_F(TypeCheckerTest, map_address)
{
  test("begin { @a = 1; @b[1] = 2; $x = &@a; $y = &@b; }");

  test("begin { $x = &@a; }", Error{ R"(
stdin:1:14-17: ERROR: Undefined map: @a
begin { $x = &@a; }
             ~~~
)" });
}

TEST_F(TypeCheckerTest, block_scoping)
{
  // if/else
  test("begin { $a = 1; if (pid) { $b = 2; "
       "print(($a, $b)); } }");
  test(R"(
      begin {
        $a = 1;
        if (pid) {
          print(($a));
          $b = 2;
          if (pid) {
            print(($a, $b));
          } else {
            print(($a, $b));
          }
        }
      })");

  // for loops
  test(R"(
      begin {
        @x[0] = 1;
        $a = 1;
        for ($kv : @x) {
          $b = 2;
          print(($a, $b));
        }
      })");
  test(R"(
    begin {
      @x[0] = 1;
      @y[0] = 2;
      $a = 1;
      for ($kv : @x) {
        $b = 2;
        for ($ap : @y) {
          print(($a, $b));
        }
      }
    })");

  // while loops
  test(R"(
    begin {
      $a = 1;
      while (1) {
        $b = 2;
        print(($a, $b));
      }
    })");
  test(R"(
    begin {
      $a = 1;
      while (1) {
        print(($a));
        $b = 2;
        while (1) {
          print(($a, $b));
        }
      }
    })");

  // unroll
  test("begin { $a = 1; unroll(1) { $b = "
       "2; print(($a, $b)); } }");
  test(R"(
    begin {
      $a = 1;
      unroll(1) {
        $b = 2;
        unroll(2) {
          print(($a, $b));
        }
      }
    })");

  // mixed
  test(R"(
    begin {
      $a = 1;
      @x[0] = 1;
      if (pid) {
        $b = 2;
        for ($kv : @x) {
          $c = 3;
          while (1) {
            $d = 4;
            unroll(1) {
              $e = 5;
              print(($a, $b, $c, $d, $e));
            }
          }
        }
      }
    })");
}

TEST_F(TypeCheckerTest, invalid_assignment)
{
  test("begin { @a = hist(10); let $b = @a; }", Error{ R"(
stdin:1:24-35: ERROR: Value 'hist_t' cannot be assigned to a scratch variable.
begin { @a = hist(10); let $b = @a; }
                       ~~~~~~~~~~~)" });

  test("begin { @a = lhist(123, 0, 123, 1); let $b = @a; }", Error{ R"(
stdin:1:37-48: ERROR: Value 'lhist_t' cannot be assigned to a scratch variable.
begin { @a = lhist(123, 0, 123, 1); let $b = @a; }
                                    ~~~~~~~~~~~
)" });

  test("begin { @a = tseries(10, 10s, 1); let $b = @a; }", Error{ R"(
stdin:1:35-46: ERROR: Value 'tseries_t' cannot be assigned to a scratch variable.
begin { @a = tseries(10, 10s, 1); let $b = @a; }
                                  ~~~~~~~~~~~
)" });

  test("begin { @a = stats(10); let $b = @a; }", Error{ R"(
stdin:1:25-36: ERROR: Value 'ustats_t' cannot be assigned to a scratch variable.
begin { @a = stats(10); let $b = @a; }
                        ~~~~~~~~~~~
)" });

  test("begin { @a = hist(10); @b = @a; }", Error{ R"(
stdin:1:24-31: ERROR: Map value 'hist_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@b = hist(retval);`.
begin { @a = hist(10); @b = @a; }
                       ~~~~~~~
)" });

  test("begin { @a = lhist(123, 0, 123, 1); @b = @a; }", Error{ R"(
stdin:1:37-44: ERROR: Map value 'lhist_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@b = lhist(rand %10, 0, 10, 1);`.
begin { @a = lhist(123, 0, 123, 1); @b = @a; }
                                    ~~~~~~~
)" });

  test("begin { @a = tseries(10, 10s, 1); @b = @a; }", Error{ R"(
stdin:1:35-42: ERROR: Map value 'tseries_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@b = tseries(rand %10, 10s, 1);`.
begin { @a = tseries(10, 10s, 1); @b = @a; }
                                  ~~~~~~~
)" });

  test("begin { @a = stats(10); @b = @a; }", Error{ R"(
stdin:1:25-32: ERROR: Map value 'ustats_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@b = stats(arg2);`.
begin { @a = stats(10); @b = @a; }
                        ~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, no_maximum_passes)
{
  test("interval:s:1 { @j = @i; @i = @h; @h "
       "= @g; @g = @f; @f = @e; @e = @d; "
       "@d = @c; "
       "@c = @b; @b = @a; } interval:s:1 { "
       "@a = 1; }");
}

TEST_F(TypeCheckerTest, block_expressions)
{
  // Good, variable is not shadowed
  test("begin { let $x = { let $x = 1; $x }; print($x) }",
       ExpectedAST{ Program().WithProbe(Probe(
           { "begin" },
           {
               AssignVarStatement(Variable("$x"),
                                  Block({ AssignVarStatement(Variable("$x"),
                                                             Integer(1)) },
                                        Variable("$x"))),
               ExprStatement(
                   Block({ ExprStatement(Call("print", { Variable("$x") })),
                           Jump(ast::JumpType::RETURN) })),
           })) });
}

TEST_F(TypeCheckerTest, map_declarations)
{
  test("let @a = hash(2); begin { @a = 1; }");
  test("let @a = lruhash(2); begin { @a = 1; }");
  test("let @a = percpuhash(2); begin { @a[1] = count(); }");
  test("let @a = percpulruhash(2); begin { @a[1] = count(); }");
  test("let @a = percpulruhash(2); begin { @a[1] = count(); }");

  test("let @a = hash(2); begin { print(1); }",
       Warning{ "WARNING: Unused map: @a" });

  test("let @a = percpuhash(2); begin { @a = 1; }", Error{ R"(
stdin:1:33-35: ERROR: Incompatible map types. Type from declaration: percpuhash. Type from value/key type: hash
let @a = percpuhash(2); begin { @a = 1; }
                                ~~
)" });
  test("let @a = percpulruhash(2); begin { @a = 1; }", Error{ R"(
stdin:1:36-38: ERROR: Incompatible map types. Type from declaration: percpulruhash. Type from value/key type: hash
let @a = percpulruhash(2); begin { @a = 1; }
                                   ~~
)" });
  test("let @a = hash(2); begin { @a = count(); }", Error{ R"(
stdin:1:27-29: ERROR: Incompatible map types. Type from declaration: hash. Type from value/key type: percpuhash
let @a = hash(2); begin { @a = count(); }
                          ~~
)" });
  test("let @a = lruhash(2); begin { @a = count(); }", Error{ R"(
stdin:1:30-32: ERROR: Incompatible map types. Type from declaration: lruhash. Type from value/key type: percpuhash
let @a = lruhash(2); begin { @a = count(); }
                             ~~
)" });
  test("let @a = potato(2); begin { @a[1] = count(); }", Error{ R"(
stdin:1:1-20: ERROR: Invalid bpf map type: potato
let @a = potato(2); begin { @a[1] = count(); }
~~~~~~~~~~~~~~~~~~~
HINT: Valid map types: percpulruhash, percpuhash, lruhash, hash
)" });
}

TEST_F(TypeCheckerTest, macros)
{
  auto bpftrace = get_mock_bpftrace();

  test("macro set($x) { $x = 1; $x } begin { $a = \"string\"; set($a); }",
       Mock{ *bpftrace },
       Error{ R"(
stdin:1:17-23: ERROR: Type mismatch for $a: trying to assign value of type 'uint8' when variable already has a type 'string[7]'
macro set($x) { $x = 1; $x } begin { $a = "string"; set($a); }
                ~~~~~~
stdin:1:53-60: ERROR: expanded from
macro set($x) { $x = 1; $x } begin { $a = "string"; set($a); }
                                                    ~~~~~~~
)" });

  test("macro add2($x) { $x + 1 } "
       "macro add1($x) { add2($x) } "
       "begin { $a = \"string\"; add1($a); }",
       Mock{ *bpftrace },
       Error{ R"(
stdin:1:21-22: ERROR: Type mismatch for '+': comparing string[7] with uint8
macro add2($x) { $x + 1 } macro add1($x) { add2($x) } begin { $a = "string"; add1($a); }
                    ~
stdin:1:18-20: ERROR: left (string[7])
macro add2($x) { $x + 1 } macro add1($x) { add2($x) } begin { $a = "string"; add1($a); }
                 ~~
stdin:1:23-24: ERROR: right (uint8)
macro add2($x) { $x + 1 } macro add1($x) { add2($x) } begin { $a = "string"; add1($a); }
                      ~
stdin:1:44-52: ERROR: expanded from
macro add2($x) { $x + 1 } macro add1($x) { add2($x) } begin { $a = "string"; add1($a); }
                                           ~~~~~~~~
stdin:1:78-86: ERROR: expanded from
macro add2($x) { $x + 1 } macro add1($x) { add2($x) } begin { $a = "string"; add1($a); }
                                                                             ~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, warning_for_empty_positional_parameters)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("1");
  test("begin { print(($1, $2)) }",
       Warning{ "Positional parameter $2 is empty or not provided." },
       Mock{ *bpftrace });
}

TEST_F(TypeCheckerTest, warning_for_discared_expression_statement_value)
{
  // Non exhaustive testing, just a few examples
  test("k:f { bswap(arg0); }", Warning{ "Return value discarded" });
  test("k:f { cgroup_path(1); }", Warning{ "Return value discarded" });
  test("k:f { uptr((int8*) arg0); }", Warning{ "Return value discarded" });
  test("k:f { ustack(raw); }", Warning{ "Return value discarded" });
  test("k:f { { 1 } }", Warning{ "Return value discarded" });

  test("k:f { _ = { 1 } }", NoWarning{ "Return value discarded" });
  test("k:f { print(1); }", NoWarning{ "Return value discarded" });
  test("k:f { $a = 1; }", NoWarning{ "Return value discarded" });
  test("k:f { $a = 1; ++$a }", NoWarning{ "Return value discarded" });
  test("k:f { $a = 1; $a++ }", NoWarning{ "Return value discarded" });
  test("k:f { @a[1] = count(); }", NoWarning{ "Return value discarded" });
}

TEST_F(TypeCheckerTest, external_function)
{
  ast::TypeMetadata types;

  // Build some basic types.
  auto int32 = types.global.add<btf::Integer>("int32", 4, 1);
  ASSERT_TRUE(bool(int32));
  auto int64 = types.global.add<btf::Integer>("int64", 8, 1);
  ASSERT_TRUE(bool(int64));

  // Add a function `foo` that is of the form: `int32 foo(int32, int64)`.
  std::vector<std::pair<std::string, btf::ValueType>> args = {
    { "a", btf::ValueType(*int32) }, { "b", btf::ValueType(*int64) }
  };
  auto add_proto = types.global.add<btf::FunctionProto>(btf::ValueType(*int32),
                                                        args);
  ASSERT_TRUE(bool(add_proto));
  auto add_func = types.global.add<btf::Function>(
      "foo", btf::Function::Linkage::Global, *add_proto);
  ASSERT_TRUE(bool(add_func));

  // Test that calling this function works.
  test("kprobe:f { foo((int32)1, (int64)2); }", Types{ types });
  test("kprobe:f { print(foo((int32)1, (int64)2)); }", Types{ types });

  // Test that calling with the wrong number of arguments fails.
  test("kprobe:f { foo((int32)1); }", Types{ types }, Error{ R"(
stdin:1:12-25: ERROR: Function `foo` requires 2 arguments, got only 1
kprobe:f { foo((int32)1); }
           ~~~~~~~~~~~~~
)" });

  // Test that calling with the wrong types fails.
  test("kprobe:f { foo((int64)1, (int64)2); }", Types{ types }, Error{ R"(
stdin:1:16-23: ERROR: Expected int32 for argument `a` got int64
kprobe:f { foo((int64)1, (int64)2); }
               ~~~~~~~
stdin:1:12-35: ERROR: Function `foo` requires arguments (int32, int64)
kprobe:f { foo((int64)1, (int64)2); }
           ~~~~~~~~~~~~~~~~~~~~~~~
)" });

  // Test that the return type is well-understood.
  test("kprobe:f { $x = (int32*)0; $x = foo((int32)1, (int64)2); }",
       Types{ types },
       Error{ R"(
stdin:1:28-56: ERROR: Type mismatch for $x: trying to assign value of type 'int32' when variable already has a type 'int32 *'
kprobe:f { $x = (int32*)0; $x = foo((int32)1, (int64)2); }
                           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, printf_str_conversion)
{
  // %s just uses the default text output representation, and therefore can
  // print any type that can be serialized.
  test("kprobe:f { $x = (uint8)1; printf(\"%s\", $x) }");
  test("kprobe:f { $x = (uint8*)0; printf(\"%s\", $x) }");
  test("kprobe:f { $x = (1, 1); printf(\"%s\", $x) }");
  test(R"(kprobe:f { $x = "foo"; printf("%s", $x) })");
}

TEST_F(TypeCheckerTest, fail)
{
  test(R"(kprobe:f { fail("always fail"); })", Error{ R"(
stdin:1:12-31: ERROR: always fail
kprobe:f { fail("always fail"); }
           ~~~~~~~~~~~~~~~~~~~
)" });
  test(R"(kprobe:f { fail("always fail %s %d %d %d", "now", 1, -1, false); })",
       Error{ R"(
stdin:1:12-64: ERROR: always fail now 1 -1 0
kprobe:f { fail("always fail %s %d %d %d", "now", 1, -1, false); }
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  test(R"(kprobe:f { if comptime (false) { fail("always false"); } })");

  // Check that non-comptime expressions are not folder.
  test(R"(kprobe:f { if (false) { fail("always false"); } })", Error{ R"(
stdin:1:25-45: ERROR: always false
kprobe:f { if (false) { fail("always false"); } }
                        ~~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, typeof_decls)
{
  test("kprobe:f { $x = (uint8)1; let $y : typeof($x); $y = 2; }");
  test(R"(kprobe:f { $x = "foo"; let $y : typeof($x); $y = "bar"; })");
  test(R"(kprobe:f { let $y : string = "hi"; $y = "muchmuchlongerstr"; })");
  test("begin { let $a: uint32 = 1; }");
  test("begin { let $a: uint32; $a = (uint8)1; }");
  test("begin { let $a: int8; $a = 1; }");
  test("begin { let $a; $a = (int32)1; }");
  test("begin { let $a; $a = (int8)1; }");
  test("begin { let $a; $a = -1; }");
  test("begin { let $a: int32 = 0; }");
  test(
      R"(begin { @a["hi", 2] = 1; let $x: typeof(@a) = ("hello", (int16)1); @a["hello", (int32)2] = 2; })");

  // These types should be enforced.
  test("begin { let $a: int8 = 1; $a = (int32)1; }", Error{});
  test("begin { let $a: uint8; $a = (int8)1; }", Error{});
  test("begin { $y = (int8)1; let $a: uint8; $a = $y; }", Error{});
  test("begin { let $a: uint8; $a = -1; }", Error{});
  test(R"(kprobe:f { let $x: string[3] = "helloooooo"; })", Error{});
  test(R"(kprobe:f { let $x: string[3] = "hi"; $x = "helloooooo"; })", Error{});
  test(
      R"(begin { @a["hi", 2] = 1; let $x: typeof(@a) = ("hello", (uint64)1); @a["hello", (int32)2] = 2; })",
      Error{});

  test(R"(kprobe:f { $a = (1, "hi"); let $x: typeof($a) = (1, "helllooo"); })",
       Error{});
  test(
      R"(kprobe:f { $a = (1, "hi"); let $x: typeof($a) = (2, "by"); $x = (1, "helllooo"); })",
      Error{});
  test(R"(kprobe:f { $x = (uint8)1; let $y : typeof($x); $y = "foo"; })",
       Error{ R"(
stdin:1:48-58: ERROR: Type mismatch for $y: trying to assign value of type 'string[4]' when variable already has a type 'uint8'
kprobe:f { $x = (uint8)1; let $y : typeof($x); $y = "foo"; }
                                               ~~~~~~~~~~
)" });
  test(R"(kprobe:f { $x = "foo"; let $y : typeof($x); $y = 2; })", Error{ R"(
stdin:1:45-51: ERROR: Type mismatch for $y: trying to assign value of type 'uint8' when variable already has a type 'string[4]'
kprobe:f { $x = "foo"; let $y : typeof($x); $y = 2; }
                                            ~~~~~~
)" });

  // But ordering should not matter, as long as the scope is the same.
  test("kprobe:f { let $x; let $y : typeof($x); $y = 2; $x = (uint8)1; }");
  test(R"(kprobe:f { let $x; let $y : typeof($x); $y = "bar"; $x = "foo"; })");
}

TEST_F(TypeCheckerTest, typeof_subprog)
{
  // Basic subprogram arguments can be defined relatively.
  test("fn foo($x : int64, $y : typeof($x)) : int8 { return 0; }");
  test("fn foo($x : typeof($y), $y : int64) : int8 { return 0; }");
  test("fn foo($x : typeof($y), $y : int64) : typeof($x) { return (int64)0; }");
  test("fn foo($x : typeof($y), $y : int64) : typeof($y) { return (int64)0; }");
  test("fn foo($x : typeof($y), $y : int64) : typeof($x) { return 0; }");
}

TEST_F(TypeCheckerTest, typeof_casts)
{
  test(R"(kprobe:f { $x = (uint8)1; $y = (typeof($x))10; })");
  test(R"(kprobe:f { $x = (void*)0; $y = (typeof($x))1; })");

  // Overflow & signed warnings still apply.
  test(R"(kprobe:f { $x = (uint8)1; $y = (typeof($x))256; })");
  test(R"(kprobe:f { $x = (uint8)1; $y = (typeof($x))-1; })");

  // Map keys and values
  test(
      R"(kprobe:f { let $a: int8; $a = (typeof(@x))2; @x[(int8)2] = (uint32)10; })");
  test(R"(kprobe:f { let $a: int8; $a = (typeof(@x))2; @x = (int8)10; })");
  test(
      R"(kprobe:f { let $a: int8; $a = (typeof(@x[1]))2; @x[(int32)2] = (int8)10; })");
  // This is read as a scalar map access which doesn't match the map type
  test(
      R"(kprobe:f { let $a: int8; $a = (typeof({ @x }))2; @x[(int8)2] = (uint32)10; })",
      Error{});

  test(
      R"(struct foo { int x; } kprobe:f { $x = (struct foo*)0; $y = (typeof(*$x))0; })",
      Error{ R"(
stdin:1:60-73: ERROR: Cannot cast from "uint8" to "struct foo"
struct foo { int x; } kprobe:f { $x = (struct foo*)0; $y = (typeof(*$x))0; }
                                                           ~~~~~~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, if_comptime)
{
  test(R"(kprobe:f { @a = 1; if (comptime false) { @a[1] = 1; } })");
  test(R"(kprobe:f { @a[1] = 1; if (comptime false) { @a = 1; } })");
  test(R"(kprobe:f { @a[1] = 1; if (comptime is_scalar(@a)) { @a = 1; } })");
  test(R"(kprobe:f { @a = 1; if (comptime !is_scalar(@a)) { @a[1] = 1; } })");
  test(R"(kprobe:f { @a = 1; if (comptime false) { for ($kv : @a) { } } })");
  test(R"(kprobe:f { @a[1] = 1; if (comptime true) { @a = 1; } })", Error{ R"(
stdin:1:44-46: ERROR: @a used as a map without an explicit key (scalar map), previously used with an explicit key (non-scalar map)
kprobe:f { @a[1] = 1; if (comptime true) { @a = 1; } }
                                           ~~
)" });
  test(R"(kprobe:f { @a = 1; if comptime (@a > 1) { print(1); } })", Error{ R"(
stdin:1:23-40: ERROR: Unable to resolve comptime expression
kprobe:f { @a = 1; if comptime (@a > 1) { print(1); } }
                      ~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, comptime)
{
  test(R"(begin { comptime (1 + 1) })");
  test(R"(begin { $x = 1; comptime (sizeof($x)) })");
  test(R"(begin { $x = 1; comptime (typeinfo($x)) })");
  test(R"(begin { @x = 1; comptime (typeinfo(@x)) })");

  test(R"(begin { $x = 0; comptime ($x + 1) })", Error{ R"(
stdin:1:17-34: ERROR: Unable to resolve comptime expression.
begin { $x = 0; comptime ($x + 1) }
                ~~~~~~~~~~~~~~~~~
)" });
  test(R"(begin { @x = 0; comptime (@x + 1) })", Error{ R"(
stdin:1:17-34: ERROR: Unable to resolve comptime expression.
begin { @x = 0; comptime (@x + 1) }
                ~~~~~~~~~~~~~~~~~
)" });
  test(R"(begin { @x[1] = 1; comptime (@x[1] + 1) })", Error{});
}

TEST_F(TypeCheckerTest, typeinfo_if_comptime)
{
  // We should be able to selectively analyze specific branches. Only the
  // correct type branch will be chosen, and we will not encounted a type
  // error for the other branch.
  test(
      R"(kprobe:f { $x = 1; if comptime (typeinfo($x) == typeinfo("abc")) { $x = "foo"; } else { $x = 2; } })");
  test(
      R"(kprobe:f { $x = "xyz"; if comptime (typeinfo($x) == typeinfo("abc")) { $x = "foo"; } else { $x = 2; } })");
  test(
      R"(kprobe:f { $x = 1; if comptime (typeinfo($x) != typeinfo(1)) { fail("only integers"); } })");
  test(
      R"(kprobe:f { $x = 1; if comptime (typeinfo($x) == typeinfo(1)) { fail("no integers"); } })",
      Error{ R"(
stdin:1:64-83: ERROR: no integers
kprobe:f { $x = 1; if comptime (typeinfo($x) == typeinfo(1)) { fail("no integers"); } }
                                                               ~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(TypeCheckerTest, no_meta_used_warnings)
{
  test("begin { let $a; print(sizeof($a)); $a = 1; }",
       NoWarning{ "Variable used" });
  test("struct Foo { int x; } begin { let $a : struct Foo*; "
       "print(offsetof(*$a, x)); }",
       NoWarning{ "Variable used" });
  test("begin { let $a; let $b : typeof($a) = 0; $a = 1; }",
       NoWarning{ "Variable used" });
  test("begin { let $a; print(typeinfo($a)); $a = 1; }",
       NoWarning{ "Variable used" });
}

TEST_F(TypeCheckerTest, no_meta_map_assignments)
{
  test("begin { let $b : typeof({ @a = 1; 1 }); }", Error{});
  test("begin { $b = typeinfo({ @a = 1; 1 }); }", Error{});
  test("begin { print(sizeof({ @a = 1; 1 })); }", Error{});
  test("struct Foo { int x; }  begin { let $a : struct Foo*; print(offsetof({ "
       "@a =1; *$a}, x)); }",
       Error{});
}

TEST_F(TypeCheckerTest, probe_return)
{
  test("begin { return 1; }");
  test("begin { $a = 1; return $a; }");
  test("begin { $a = 1; return 0 + 1; }");

  test("begin { $a = 1; return $a; }",
       ExpectedAST{ Program().WithProbe(
           Probe({ "begin" },
                 { AssignVarStatement(Variable("$a"), Integer(1)),
                   Jump(ast::JumpType::RETURN)
                       .WithReturnValue(
                           Cast(Typeof(SizedType(Type::integer).WithSize(8)),
                                Variable("$a"))) })) });

  test("begin { return \"tomato\"; }", Error{});
}

TEST_F(TypeCheckerTest, record)
{
  // Variables
  test(R"(begin { $t = (a=1)})");
  test(R"(begin { $t = (a=1, b=2); $v = $t;})");
  test(R"(begin { $t = (a=1, b=2, c="string")})");
  test(R"(begin { $t = (a=1, b=2, c="string"); $t = (a=3, b=4, c="other"); })");
  test(R"(begin { $t = (a=1, b=kstack()) })");
  test(R"(begin { $t = (a=1, b=(x=2,y=3)) })");

  // Map Values
  test(R"(begin { @t = (a=1)})");
  test(R"(begin { @t = (a=1, b=2); @v = @t;})");
  test(R"(begin { @t = (a=1, b=2, c="string")})");
  test(R"(begin { @t = (a=1, b=2, c="string"); @t = (a=3, b=4, c="other"); })");
  test(R"(begin { @t = (a=1, b=kstack()) })");
  test(R"(begin { @t = (a=1, b=(x=2,y=3)) })");

  // Map Keys
  test(R"(begin { @t[(a=1)] = 1; })");
  test(R"(begin { @t[(a=1, b=2, c="string")] = 1; })");
  test(
      R"(begin { @t[(a=1, b=2, c="string")] = 1; @t[(b=4, c="other", a=3)] = 1; })");
  test(R"(begin { @t[(a=1, b=kstack())] = 1; })");
  test(R"(begin { @t[(a=1, b=(x=2,y=3))] = 1; })");

  test(R"(begin { $t = (a=1, b=(int64)2); $t = (a=2, b=(int32)3); })");
  test(R"(begin { $t = (a=1, b=(int32)2); $t = (a=2, b=(int64)3); })");

  test(R"(struct task_struct { int x; } begin { $t = (a=1, b=curtask); })");
  test(
      R"(struct task_struct { int x[4]; } begin { $t = (a=1, b=curtask->x); })");

  // Different field order should be compatible as long as types match
  test(R"(begin { $t = (a=1, b=2); $t = (b=4, a=5); })");
  test(R"(begin { @t = (a=1, b=2); @t = (b=4, a=5); })");

  // Compatible types
  test(
      R"(begin { $t = (a=1, b=(x=2, y=3)); $t = (a=4, b=(x=(uint8)5, y=6)); })");
  test(
      R"(begin { $t = (a=1, b=(x=2, y=3)); $t = (a=4, b=(x=(int64)5, y=6)); })");
  test(
      R"(begin { $t = (a=(uint8)1, b=(x=2, y=3)); $t = (a=4, b=(x=5, y=6)); })");
  test(
      R"(begin { @t = (a=1, b=2, c="hi"); @t = (a=3, b=4, c="hellolongstr"); })");
  test(
      R"(begin { $t = (a=1, b=(x="hi", y=2)); $t = (a=3, b=(x="hellolongstr", y=4)); })");

  // Error cases - type mismatch
  test(R"(begin { $t = (a=1, b=2); $t = (a=4, b="other"); })", Error{});
  test(R"(begin { $t = (a=1, b=2); $t = 5; })", Error{});
  test(R"(begin { $t = (a=1, b=count()) })", Error{});
  test(R"(begin { @t = (a=1, b=2); @t = (a=4, b="other"); })", Error{});
  test(R"(begin { @t = (a=1, b=2); @t = 5; })", Error{});
  test(R"(begin { @t = (a=1, b=count()) })", Error{});
  test(R"(begin { $t = (a=1, b=2); $t = (a=3); })", Error{});

  test(
      R"(begin { $t = (a=1, b=(x=2, y=3)); $t = (a=4, b=(x=(int64)5, y="hi")); })",
      Error{ R"(
stdin:1:35-69: ERROR: Type mismatch for $t: trying to assign value of type 'record { .a = uint8, .b = record { .x = int64, .y = string[3] } }' when variable already has a type 'record { .a = uint8, .b = record { .x = uint8, .y = uint8 } }'
begin { $t = (a=1, b=(x=2, y=3)); $t = (a=4, b=(x=(int64)5, y="hi")); }
                                  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });

  test("begin { @x[1] = hist(10); $y = (a=1, b=@x[1]); }", Error{ R"(
stdin:1:40-45: ERROR: Map type hist_t cannot exist inside a record.
begin { @x[1] = hist(10); $y = (a=1, b=@x[1]); }
                                       ~~~~~
)" });

  // Different field names should cause error
  test(R"(begin { $t = (a=1, b=2); $t = (a=3, c=4); })", Error{});
  test(R"(begin { $t = (a=1, b=2); $t = (x=3, y=4); })", Error{});
}

TEST_F(TypeCheckerTest, record_field_access)
{
  test(R"(begin { (a=1,b=2).a })");
  test(R"(begin { (a=1,b=2).b })");
  test(R"(begin { (a=1,b=2,c=3).c })");
  test(R"(begin { $t = (a=1,b=2,c=3).a })");
  test(R"(begin { $t = (a=1,b=2,c=3); $v = $t.a; })");

  test(R"(begin { (a=1,b=2).c })", Error{});
}

TEST_F(TypeCheckerTest, record_assign_var)
{
  class SizedType ty = CreateRecord(
      Struct::CreateRecord({ CreateUInt8(), CreateString(6) }, { "a", "b" }));
  auto ast = test(R"(begin { $t = (a=1, b="str"); $t = (b="other", a=4); })");
  auto &stmts = ast.root->probes.at(0)->block->stmts;

  // The field order of both assignments are preserved
  auto *assignment = stmts.at(0).as<ast::AssignVarStatement>();
  EXPECT_EQ(ty, assignment->var()->var_type);
  EXPECT_EQ("a", assignment->expr.as<ast::Record>()->elems[0]->name);
  EXPECT_EQ("b", assignment->expr.as<ast::Record>()->elems[1]->name);

  assignment = stmts.at(1).as<ast::AssignVarStatement>();
  EXPECT_EQ(ty, assignment->var()->var_type);
  EXPECT_EQ("b", assignment->expr.as<ast::Record>()->elems[0]->name);
  EXPECT_EQ("a", assignment->expr.as<ast::Record>()->elems[1]->name);
}

TEST_F(TypeCheckerTest, record_mixed_types)
{
  // The same resizing rules should exist for ints, strings, and tuples inside
  // records
  test(
      R"(begin { $a = (x=(int16)1, y="hi"); $a = (x=(uint16)2, y="hellostr"); })");
  test(
      R"(begin { $a = (y="hi", x=(int16)1); $a = (x=(uint16)2, y="hellostr"); })");
  test(
      R"(begin { $a = (x=(1, (uint32)2), y="hi"); $a = (x=((uint16)2, 3), y="hellostr"); })");
  test(
      R"(begin { @a[(x=(int64)1, y="hi")] = 1; @a[(x=(uint16)2, y="hellostr")] = 2; })");
  test(R"(begin { @a = (x=(int64)1, y="hi"); @a = (x=2, y="hellostr"); })");
  test(
      R"(begin { print(if (pid == 1) { (x=(int32)1, y="hi") } else { (x=(uint16)2, y="hellostr") }); })");
  test(
      R"(begin { $a = (y="hi", x=(a=(uint8)1, b=(uint32)2)); $a = (x=(b=(uint8)3, a=(int16)5), y="hellostr"); })");

  test(
      R"(begin { $a = (x=(int64)1, y="hi"); $a = (x=(uint64)2, y="hellostr"); })",
      Error{});
  test(
      R"(begin { @a[(x=(int64)1, y="hi")] = 1; @a[(x=(uint64)2, y="hellostr")] = 2; })",
      Error{});
  test(
      R"(begin { @a = (x=(int64)1, y="hi"); @a = (x=(uint64)2, y="hellostr"); })",
      Error{});
  test(
      R"(begin { print(if (pid == 1) { (x=(int64)1, y="hi") } else { (x=(uint64)2, y="hellostr") }); })",
      Error{});

  // Test inserted casts
  test(
      R"(begin { $a = (a=(int16)1, b="hi"); $a = (b="hellostr", a=(uint16)2); })",
      ExpectedAST{ Program().WithProbe(Probe(
          { "begin" },
          { AssignVarStatement(
                Variable("$a"),
                Record(
                    { NamedArgument("a",
                                    Cast(Typeof(SizedType(Type::integer)
                                                    .WithSize(4)
                                                    .WithSigned(true)),
                                         Cast(Typeof(SizedType(Type::integer)),
                                              Integer(1)))),
                      NamedArgument("b",
                                    Cast(Typeof(SizedType(Type::string)),
                                         String("hi"))) })),
            AssignVarStatement(
                Variable("$a"),
                Record(
                    { NamedArgument("b", String("hellostr")),
                      NamedArgument("a",
                                    Cast(Typeof(SizedType(Type::integer)
                                                    .WithSize(4)
                                                    .WithSigned(true)),
                                         Cast(Typeof(SizedType(Type::integer)),
                                              Integer(2)))) })),
            Jump(ast::JumpType::RETURN) })) });

  // Nested record with casts
  test(
      R"(begin { $a = (x=(a=(int8)1, b=(uint16)2), y="hi"); $a = (y="hello", x=(b=(uint8)4, a=(int16)3)); })",
      ExpectedAST{ Program().WithProbe(Probe(
          { "begin" },
          { AssignVarStatement(
                Variable("$a"),
                Record({ NamedArgument(
                             "x",
                             Record({ NamedArgument(
                                          "a",
                                          Cast(Typeof(SizedType(Type::integer)
                                                          .WithSize(2)
                                                          .WithSigned(true)),
                                               Cast(Typeof(SizedType(
                                                        Type::integer)),
                                                    Integer(1)))),
                                      NamedArgument(
                                          "b",
                                          Cast(Typeof(SizedType(Type::integer)
                                                          .WithSize(2)
                                                          .WithSigned(false)),
                                               Integer(2))) })),
                         NamedArgument("y",
                                       Cast(Typeof(SizedType(Type::string)),
                                            String("hi"))) })),
            AssignVarStatement(
                Variable("$a"),
                Record({
                    NamedArgument("y", String("hello")),
                    NamedArgument(
                        "x",
                        Record({
                            NamedArgument(
                                "b",
                                Cast(Typeof(SizedType(Type::integer)
                                                .WithSize(2)
                                                .WithSigned(false)),
                                     Cast(Typeof(SizedType(Type::integer)),
                                          Integer(4)))),
                            NamedArgument("a",
                                          Cast(Typeof(SizedType(Type::integer)
                                                          .WithSize(2)
                                                          .WithSigned(true)),
                                               Integer(3))),
                        })),
                })),
            Jump(ast::JumpType::RETURN) })) });

  // Tuple inside record with casts
  test(
      R"(begin { $a = (x=((int8)1, (uint16)2), y="hi"); $a = (x=((int16)3, (uint8)4), y="hello"); })",
      ExpectedAST{ Program().WithProbe(Probe(
          { "begin" },
          { AssignVarStatement(
                Variable("$a"),
                Record({ NamedArgument(
                             "x",
                             Tuple({ Cast(Typeof(SizedType(Type::integer)
                                                     .WithSize(2)
                                                     .WithSigned(true)),
                                          Cast(Typeof(SizedType(Type::integer)),
                                               Integer(1))),
                                     Cast(Typeof(SizedType(Type::integer)
                                                     .WithSize(2)
                                                     .WithSigned(false)),
                                          Integer(2)) })),
                         NamedArgument("y",
                                       Cast(Typeof(SizedType(Type::string)),
                                            String("hi"))) })),
            AssignVarStatement(
                Variable("$a"),
                Record({ NamedArgument(
                             "x",
                             Tuple({ Cast(Typeof(SizedType(Type::integer)
                                                     .WithSize(2)
                                                     .WithSigned(true)),
                                          Integer(3)),
                                     Cast(Typeof(SizedType(Type::integer)
                                                     .WithSize(2)
                                                     .WithSigned(false)),
                                          Cast(Typeof(SizedType(Type::integer)),
                                               Integer(4))) })),
                         NamedArgument("y", String("hello")) })),
            Jump(ast::JumpType::RETURN) })) });
}

} // namespace bpftrace::test::type_checker
