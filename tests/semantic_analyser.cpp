#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>

#include "arch/arch.h"
#include "ast/ast.h"
#include "ast/attachpoint_parser.h"
#include "ast/passes/c_macro_expansion.h"
#include "ast/passes/clang_parser.h"
#include "ast/passes/field_analyser.h"
#include "ast/passes/fold_literals.h"
#include "ast/passes/import_scripts.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/named_param.h"
#include "ast/passes/printer.h"
#include "ast/passes/probe_expansion.h"
#include "ast/passes/resolve_imports.h"
#include "ast/passes/semantic_analyser.h"
#include "ast/passes/type_system.h"
#include "bpftrace.h"
#include "btf_common.h"
#include "driver.h"
#include "mocks.h"

namespace bpftrace::test::semantic_analyser {

using ::testing::_;
using ::testing::HasSubstr;

struct Mock {
  BPFtrace &bpftrace;
};
enum class UnsafeMode {
  Enable = 0, // Default is safe.
};
enum class Child {
  Enable = 0, // Default is no child.
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
  std::string_view str;
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
class SemanticAnalyserHarness {
public:
  template <typename... Ts>
    requires((std::is_same_v<std::decay_t<Ts>, Mock> ||
              std::is_same_v<std::decay_t<Ts>, UnsafeMode> ||
              std::is_same_v<std::decay_t<Ts>, Child> ||
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
    auto child = extract<Child>(args...);
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
    if (child.has_value()) {
      mock->bpftrace.cmd_ = "not-empty"; // Used by SemanticAnalyser.
    }
    if (!types) {
      types_.emplace();
      types.emplace(*types_);
    }

    auto ok = ast::PassManager()
                  .put(ast)
                  .put(mock->bpftrace)
                  .put(types->types)
                  .add(CreateParsePass())
                  .add(ast::CreateResolveImportsPass())
                  .add(ast::CreateImportInternalScriptsPass())
                  .add(ast::CreateMacroExpansionPass())
                  .add(ast::CreateParseAttachpointsPass())
                  .add(ast::CreateProbeExpansionPass())
                  .add(ast::CreateFieldAnalyserPass())
                  .add(ast::CreateClangParsePass())
                  .add(ast::CreateCMacroExpansionPass())
                  .add(ast::CreateFoldLiteralsPass())
                  .add(ast::CreateMapSugarPass())
                  .add(ast::CreateNamedParamsPass())
                  .add(ast::CreateSemanticPass())
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
      EXPECT_TRUE(!expected_ast->str.empty());
      ast::Printer printer(out);
      printer.visit(ast.root);
      const auto aststr = out.str();
      EXPECT_THAT(aststr, HasSubstr(clean_prefix(expected_ast->str))) << aststr;
    }

    return ast;
  }

private:
  std::unique_ptr<MockBPFtrace> bpftrace_;
  std::optional<ast::TypeMetadata> types_;
};

class SemanticAnalyserTest : public SemanticAnalyserHarness,
                             public testing::Test {};

TEST_F(SemanticAnalyserTest, builtin_variables)
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
  test("kprobe:f { numaid }");
  test("kprobe:f { cpu }");
  test("kprobe:f { ncpus }");
  test("kprobe:f { curtask }");
  test("kprobe:f { rand }");
  test("kprobe:f { ctx }");
  test("kprobe:f { comm }");
  test("kprobe:f { kstack }");
  test("kprobe:f { ustack }");
  test("kprobe:f { arg0 }");
  test("kprobe:f { sarg0 }");
  test("kretprobe:f { retval }");
  test("kprobe:f { func }");
  test("uprobe:/bin/sh:f { func }");
  test("kprobe:f { probe }");
  test("tracepoint:sched:sched_one { args }");
  test("kprobe:f { jiffies }");

  test("kprobe:f { fake }", Error{ R"(
stdin:1:12-16: ERROR: Unknown identifier: 'fake'
kprobe:f { fake }
           ~~~~
)" });

  test("k:f { jiffies }", NoFeatures::Enable, Error{});
}

TEST_F(SemanticAnalyserTest, builtin_cpid)
{
  test(R"(i:ms:100 { printf("%d\n", cpid); })", Error{});
  test("i:ms:100 { @=cpid }", Error{});
  test("i:ms:100 { $a=cpid }", Error{});

  test(R"(i:ms:100 { printf("%d\n", cpid); })", Child::Enable);
  test("i:ms:100 { @=cpid }", Child::Enable);
  test("i:ms:100 { $a=cpid }", Child::Enable);
}

TEST_F(SemanticAnalyserTest, builtin_functions)
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
  test("kprobe:f { @x = 1; delete(@x) }");
  test("kprobe:f { @x = 1; print(@x) }");
  test("kprobe:f { @x = 1; clear(@x) }");
  test("kprobe:f { @x = 1; zero(@x) }");
  test("kprobe:f { @x[1] = 1; if (has_key(@x, 1)) {} }");
  test("kprobe:f { @x[1] = 1; @s = len(@x) }");
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
#ifdef __x86_64__
  test("kprobe:f { reg(\"ip\") }");
#endif
  test("kprobe:f { kstack(1) }");
  test("kprobe:f { ustack(1) }");
  test("kprobe:f { cat(\"/proc/uptime\") }");
  test("uprobe:/bin/sh:main { uaddr(\"glob_asciirange\") }");
  test("kprobe:f { cgroupid(\"/sys/fs/cgroup/unified/mycg\"); }");
  test("kprobe:f { macaddr(0xffff) }");
  test("kprobe:f { nsecs() }");
  test("kprobe:f { pid() }");
  test("kprobe:f { tid() }");
}

TEST_F(SemanticAnalyserTest, undefined_map)
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
stdin:1:12-20: ERROR: Undefined map: @x
kprobe:f { print(@x); }
           ~~~~~~~~
)" });
  test("kprobe:f { zero(@x); }", Error{ R"(
stdin:1:12-19: ERROR: Undefined map: @x
kprobe:f { zero(@x); }
           ~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, consistent_map_values)
{
  test("kprobe:f { @x = 0; @x = 1; }");
  test(
      R"(begin { $a = (3, "hello"); @m[1] = $a; $a = (1,"aaaaaaaaaa"); @m[2] = $a; })");
  test("kprobe:f { @x = 0; @x = \"a\"; }", Error{ R"(
stdin:1:20-28: ERROR: Type mismatch for @x: trying to assign value of type 'string' when map already contains a value of type 'int64'
kprobe:f { @x = 0; @x = "a"; }
                   ~~~~~~~~
)" });
  test("kprobe:f { @x = 0; @x = *curtask; }", Error{ R"(
stdin:1:20-33: ERROR: Type mismatch for @x: trying to assign value of type 'struct task_struct' when map already contains a value of type 'int64'
kprobe:f { @x = 0; @x = *curtask; }
                   ~~~~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, consistent_map_keys)
{
  test("begin { @x = 0; @x; }");
  test("begin { @x[1] = 0; @x[2]; }");
  test("begin { @x[@y] = 5; @y = 1;}");
  test("begin { @x[@y[@z]] = 5; @y[2] = 1; @z = @x[0]; }");

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
stdin:1:22-26: ERROR: Argument mismatch for @x: trying to access with arguments: 'int64' when map expects arguments: '(int64,int64)'
begin { @x[1,2] = 0; @x[3]; }
                     ~~~~
)" });
  test("begin { @x[1] = 0; @x[2,3]; }", Error{ R"(
stdin:1:20-27: ERROR: Argument mismatch for @x: trying to access with arguments: '(int64,int64)' when map expects arguments: 'int64'
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
stdin:3:7-25: ERROR: Argument mismatch for @x: trying to access with arguments: '(string,int64,kstack)' when map expects arguments: '(int64,string,kstack)'
      @x["b", 2, kstack];
      ~~~~~~~~~~~~~~~~~~
)" });

  test("begin { @map[1, 2] = 1; for ($kv : @map) { @map[$kv.0] = 2; } }");

  test(R"(begin { @map[1, 2] = 1; for ($kv : @map) { @map[$kv.0.0] = 2; } })",
       Error{ R"(
stdin:1:45-57: ERROR: Argument mismatch for @map: trying to access with arguments: 'int64' when map expects arguments: '(int64,int64)'
begin { @map[1, 2] = 1; for ($kv : @map) { @map[$kv.0.0] = 2; } }
                                            ~~~~~~~~~~~~
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

TEST_F(SemanticAnalyserTest, if_statements)
{
  test("kprobe:f { if(true) { 123 } }");
  test("kprobe:f { if(false) { 123 } }");
  test("kprobe:f { if(1) { 123 } }");
  test("kprobe:f { if(1) { 123 } else { 456 } }");
  test("kprobe:f { if(0) { 123 } else if(1) { 456 } else { 789 } }");
  test("kprobe:f { if((int32)pid) { 123 } }");
  test("kprobe:f { if(curtask) { 123 } }");
  test("kprobe:f { if(curtask && (int32)pid) { 123 } }");
}

TEST_F(SemanticAnalyserTest, predicate_expressions)
{
  test("kprobe:f / 999 / { 123 }");
  test("kprobe:f / true / { 123 }");
  test("kprobe:f / \"str\" / { 123 }", Error{ R"(
stdin:1:10-19: ERROR: Invalid type for predicate: string
kprobe:f / "str" / { 123 }
         ~~~~~~~~~
)" });
  test("kprobe:f / kstack / { 123 }", Error{ R"(
stdin:1:10-20: ERROR: Invalid type for predicate: kstack
kprobe:f / kstack / { 123 }
         ~~~~~~~~~~
)" });
  test("kprobe:f / @mymap / { @mymap = \"str\" }", Error{ R"(
stdin:1:10-20: ERROR: Invalid type for predicate: string
kprobe:f / @mymap / { @mymap = "str" }
         ~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, ternary_expressions)
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
    { "ntop(arg0)", "ntop(arg1)" },
    { "nsecs(boot)", "nsecs(monotonic)" },
    { "ksym(arg0)", "ksym(arg1)" },
    { "usym(arg0)", "usym(arg1)" },
    { "cgroup_path(1)", "cgroup_path(2)" },
    { "strerror(1)", "strerror(2)" },
    { "pid(curr_ns)", "pid(init)" },
    { "tid(curr_ns)", "tid(init)" },
  };

  for (const auto &[left, right] : supported_types) {
    test("kprobe:f { curtask ? " + left + " : " + right + " }");
  }

  test("kprobe:f { pid < 10000 ? printf(\"lo\") : exit() }");
  test(R"(kprobe:f { @x = pid < 10000 ? printf("lo") : cat("/proc/uptime") })",
       Error{});
  test("struct Foo { int x; } kprobe:f { curtask ? (struct Foo)*arg0 : "
       "(struct "
       "Foo)*arg1 }",
       Error{});
  test("struct Foo { int x; } kprobe:f { curtask ? (struct Foo*)arg0 : "
       "(struct "
       "Foo*)arg1 }");
  test(
      R"(kprobe:f { pid < 10000 ? ("a", "hellolongstr") : ("hellolongstr", "b") })");

  test(
      R"(kprobe:f { pid < 10000 ? ("a", "hellolongstr") : ("hellolongstr", "b") })",
      ExpectedAST{ R"(
Program
 kprobe:f
  ?: :: [(string[13],string[13])]
   < :: [bool]
    builtin: pid :: [uint32]
    int: 10000 :: [int64]
   tuple: :: [(string[2],string[13])]
    string: a
    string: hellolongstr
   tuple: :: [(string[13],string[2])]
    string: hellolongstr
    string: b
)" });

  // Error location is incorrect: #3063
  test("kprobe:f { pid < 10000 ? 3 : cat(\"/proc/uptime\") }", Error{ R"(
stdin:1:12-50: ERROR: Ternary operator must return the same type: have 'int64' and 'none'
kprobe:f { pid < 10000 ? 3 : cat("/proc/uptime") }
           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Error location is incorrect: #3063
  test("kprobe:f { @x = pid < 10000 ? 1 : \"high\" }", Error{ R"(
stdin:1:17-42: ERROR: Ternary operator must return the same type: have 'int64' and 'string'
kprobe:f { @x = pid < 10000 ? 1 : "high" }
                ~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Error location is incorrect: #3063
  test("kprobe:f { @x = pid < 10000 ? \"lo\" : 2 }", Error{ R"(
stdin:1:17-40: ERROR: Ternary operator must return the same type: have 'string' and 'int64'
kprobe:f { @x = pid < 10000 ? "lo" : 2 }
                ~~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Error location is incorrect: #3063
  test("kprobe:f { @x = pid < 10000 ? (1, 2) : (\"a\", 4) }", Error{ R"(
stdin:1:17-49: ERROR: Ternary operator must return the same type: have '(int64,int64)' and '(string,int64)'
kprobe:f { @x = pid < 10000 ? (1, 2) : ("a", 4) }
                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Error location is incorrect: #3063
  test("kprobe:f { @x = pid < 10000 ? ustack(1) : ustack(2) }", Error{ R"(
stdin:1:17-53: ERROR: Ternary operator must have the same stack type on the right and left sides.
kprobe:f { @x = pid < 10000 ? ustack(1) : ustack(2) }
                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Error location is incorrect: #3063
  test("kprobe:f { @x = pid < 10000 ? kstack(raw) : kstack(perf) }", Error{ R"(
stdin:1:17-58: ERROR: Ternary operator must have the same stack type on the right and left sides.
kprobe:f { @x = pid < 10000 ? kstack(raw) : kstack(perf) }
                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, mismatched_call_types)
{
  test("kprobe:f { @x = 1; @x = count(); }", Error{ R"(
stdin:1:25-32: ERROR: Type mismatch for @x: trying to assign value of type 'count_t' when map already contains a value of type 'int64'
kprobe:f { @x = 1; @x = count(); }
                        ~~~~~~~
)" });
  test("kprobe:f { @x = count(); @x "
       "= sum(pid); }",
       Error{ R"(
stdin:1:31-39: ERROR: Type mismatch for @x: trying to assign value of type 'usum_t' when map already contains a value of type 'count_t'
kprobe:f { @x = count(); @x = sum(pid); }
                              ~~~~~~~~
)" });
  test("kprobe:f { @x = 1; @x = hist(0); }", Error{ R"(
stdin:1:25-32: ERROR: Type mismatch for @x: trying to assign value of type 'hist_t' when map already contains a value of type 'int64'
kprobe:f { @x = 1; @x = hist(0); }
                        ~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, compound_left)
{
  test("kprobe:f { $a <<= 0 }", Error{ R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a <<= 0 }
           ~~
)" });
  test("kprobe:f { $a = 0; $a <<= 1 }");
  test("kprobe:f { @a <<= 1 }");
}

TEST_F(SemanticAnalyserTest, compound_right)
{
  test("kprobe:f { $a >>= 0 }", Error{ R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a >>= 0 }
           ~~
)" });
  test("kprobe:f { $a = 0; $a >>= 1 }");
  test("kprobe:f { @a >>= 1 }");
}

TEST_F(SemanticAnalyserTest, compound_plus)
{
  test("kprobe:f { $a += 0 }", Error{ R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a += 0 }
           ~~
)" });
  test("kprobe:f { $a = 0; $a += 1 }");
  test("kprobe:f { @a += 1 }");
}

TEST_F(SemanticAnalyserTest, compound_minus)
{
  test("kprobe:f { $a -= 0 }", Error{ R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a -= 0 }
           ~~
)" });
  test("kprobe:f { $a = 0; $a -= 1 }");
  test("kprobe:f { @a -= 1 }");
}

TEST_F(SemanticAnalyserTest, compound_mul)
{
  test("kprobe:f { $a *= 0 }", Error{ R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a *= 0 }
           ~~
)" });
  test("kprobe:f { $a = 0; $a *= 1 }");
  test("kprobe:f { @a *= 1 }");
}

TEST_F(SemanticAnalyserTest, compound_div)
{
  test("kprobe:f { $a /= 0 }", Error{ R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a /= 0 }
           ~~
)" });
  test("kprobe:f { $a = 0; $a /= 1 }");
  test("kprobe:f { @a /= 1 }");
}

TEST_F(SemanticAnalyserTest, compound_mod)
{
  test("kprobe:f { $a %= 0 }", Error{ R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a %= 0 }
           ~~
)" });
  test("kprobe:f { $a = 0; $a %= 1 }");
  test("kprobe:f { @a %= 1 }");
}

TEST_F(SemanticAnalyserTest, compound_band)
{
  test("kprobe:f { $a &= 0 }", Error{ R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a &= 0 }
           ~~
)" });
  test("kprobe:f { $a = 0; $a &= 1 }");
  test("kprobe:f { @a &= 1 }");
}

TEST_F(SemanticAnalyserTest, compound_bor)
{
  test("kprobe:f { $a |= 0 }", Error{ R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a |= 0 }
           ~~
)" });
  test("kprobe:f { $a = 0; $a |= 1 }");
  test("kprobe:f { @a |= 1 }");
}

TEST_F(SemanticAnalyserTest, compound_bxor)
{
  test("kprobe:f { $a ^= 0 }", Error{ R"(
stdin:1:12-14: ERROR: Undefined or undeclared variable: $a
kprobe:f { $a ^= 0 }
           ~~
)" });
  test("kprobe:f { $a = 0; $a ^= 1 }");
  test("kprobe:f { @a ^= 1 }");
}

TEST_F(SemanticAnalyserTest, call_hist)
{
  test("kprobe:f { @x = hist(1); }");
  test("kprobe:f { @x = hist(1, 0); }");
  test("kprobe:f { @x = hist(1, 5); }");
  test("kprobe:f { @x = hist(1, 10); }", Error{ R"(
stdin:1:17-28: ERROR: hist: bits 10 must be 0..5
kprobe:f { @x = hist(1, 10); }
                ~~~~~~~~~~~
)" });
  test("kprobe:f { $n = 3; @x = hist(1, $n); }", Error{ R"(
stdin:1:25-36: ERROR: hist() expects a int literal (int provided)
kprobe:f { $n = 3; @x = hist(1, $n); }
                        ~~~~~~~~~~~
)" });
  test("kprobe:f { @x = hist(); }", Error{ R"(
stdin:1:17-23: ERROR: hist() requires at least one argument (0 provided)
kprobe:f { @x = hist(); }
                ~~~~~~
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
stdin:1:12-22: ERROR: hist() must be assigned directly to a map
kprobe:f { @x[hist(1)] = 1; }
           ~~~~~~~~~~
)" });
  test("kprobe:f { if(hist()) { 123 } }", Error{ R"(
stdin:1:12-21: ERROR: hist() must be assigned directly to a map
kprobe:f { if(hist()) { 123 } }
           ~~~~~~~~~
)" });
  test("kprobe:f { hist() ? 0 : 1; }", Error{ R"(
stdin:1:12-18: ERROR: hist() must be assigned directly to a map
kprobe:f { hist() ? 0 : 1; }
           ~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, call_lhist)
{
  test("kprobe:f { @ = lhist(5, 0, 10, 1); "
       "}");
  test("kprobe:f { @ = lhist(5, 0, 10); }", Error{ R"(
stdin:1:16-31: ERROR: lhist() requires 4 arguments (3 provided)
kprobe:f { @ = lhist(5, 0, 10); }
               ~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { @ = lhist(5, 0); }", Error{ R"(
stdin:1:16-27: ERROR: lhist() requires 4 arguments (2 provided)
kprobe:f { @ = lhist(5, 0); }
               ~~~~~~~~~~~
)" });
  test("kprobe:f { @ = lhist(5); }", Error{ R"(
stdin:1:16-24: ERROR: lhist() requires 4 arguments (1 provided)
kprobe:f { @ = lhist(5); }
               ~~~~~~~~
)" });
  test("kprobe:f { @ = lhist(); }", Error{ R"(
stdin:1:16-23: ERROR: lhist() requires 4 arguments (0 provided)
kprobe:f { @ = lhist(); }
               ~~~~~~~
)" });
  test("kprobe:f { @ = lhist(5, 0, 10, 1, 2); }", Error{ R"(
stdin:1:16-37: ERROR: lhist() requires 4 arguments (5 provided)
kprobe:f { @ = lhist(5, 0, 10, 1, 2); }
               ~~~~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { lhist(-10, -10, 10, 1); }", Error{ R"(
stdin:1:12-34: ERROR: lhist() must be assigned directly to a map
kprobe:f { lhist(-10, -10, 10, 1); }
           ~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { @ = lhist(-10, -10, 10, 1); }", Error{ R"(
stdin:1:16-38: ERROR: lhist: invalid min value (must be non-negative literal)
kprobe:f { @ = lhist(-10, -10, 10, 1); }
               ~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { $x = lhist(); }", Error{ R"(
stdin:1:17-24: ERROR: lhist() must be assigned directly to a map
kprobe:f { $x = lhist(); }
                ~~~~~~~
)" });
  test("kprobe:f { @[lhist()] = 1; }", Error{ R"(
stdin:1:12-21: ERROR: lhist() must be assigned directly to a map
kprobe:f { @[lhist()] = 1; }
           ~~~~~~~~~
)" });
  test("kprobe:f { if(lhist()) { 123 } }", Error{ R"(
stdin:1:12-22: ERROR: lhist() must be assigned directly to a map
kprobe:f { if(lhist()) { 123 } }
           ~~~~~~~~~~
)" });
  test("kprobe:f { lhist() ? 0 : 1; }", Error{ R"(
stdin:1:12-19: ERROR: lhist() must be assigned directly to a map
kprobe:f { lhist() ? 0 : 1; }
           ~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, call_lhist_posparam)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("0");
  bpftrace->add_param("10");
  bpftrace->add_param("1");
  bpftrace->add_param("hello");
  test("kprobe:f { @ = lhist(5, $1, $2, $3); }", Mock{ *bpftrace });
  test("kprobe:f { @ = lhist(5, $1, $2, $4); }", Mock{ *bpftrace }, Error{});
}

TEST_F(SemanticAnalyserTest, call_tseries)
{
  test("kprobe:f { @ = tseries(5, 10s, 1); }");
  test("kprobe:f { @ = tseries(-5, 10s, 1); }");
  test("kprobe:f { @ = tseries(5, 10s); }", Error{ R"(
stdin:1:16-31: ERROR: tseries() requires at least 3 arguments (2 provided)
kprobe:f { @ = tseries(5, 10s); }
               ~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { @ = tseries(5); }", Error{ R"(
stdin:1:16-26: ERROR: tseries() requires at least 3 arguments (1 provided)
kprobe:f { @ = tseries(5); }
               ~~~~~~~~~~
)" });
  test("kprobe:f { @ = tseries(); }", Error{ R"(
stdin:1:16-25: ERROR: tseries() requires at least 3 arguments (0 provided)
kprobe:f { @ = tseries(); }
               ~~~~~~~~~
)" });
  test("kprobe:f { @ = tseries(5, 10s, 1, 10, 10); }", Error{ R"(
stdin:1:16-42: ERROR: tseries() takes up to 4 arguments (5 provided)
kprobe:f { @ = tseries(5, 10s, 1, 10, 10); }
               ~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
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
stdin:1:12-23: ERROR: tseries() must be assigned directly to a map
kprobe:f { @[tseries()] = 1; }
           ~~~~~~~~~~~
)" });
  test("kprobe:f { if(tseries()) { 123 } }", Error{ R"(
stdin:1:12-24: ERROR: tseries() must be assigned directly to a map
kprobe:f { if(tseries()) { 123 } }
           ~~~~~~~~~~~~
)" });
  test("kprobe:f { tseries() ? 0 : 1; }", Error{ R"(
stdin:1:12-21: ERROR: tseries() must be assigned directly to a map
kprobe:f { tseries() ? 0 : 1; }
           ~~~~~~~~~
)" });
  test("kprobe:f { @ = tseries(-1, 10s, 5); }");
  test("kprobe:f { @ = tseries(1, 10s, 0); }", Error{ R"(
stdin:1:16-34: ERROR: tseries() num_intervals must be >= 1 (0 provided)
kprobe:f { @ = tseries(1, 10s, 0); }
               ~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { @ = tseries(1, 10s, -1); }", Error{ R"(
stdin:1:16-35: ERROR: tseries: invalid num_intervals value (must be non-negative literal)
kprobe:f { @ = tseries(1, 10s, -1); }
               ~~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { @ = tseries(1, 10s, 1000001); }", Error{ R"(
stdin:1:16-40: ERROR: tseries() num_intervals must be < 1000000 (1000001 provided)
kprobe:f { @ = tseries(1, 10s, 1000001); }
               ~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { @ = tseries(1, 0, 10); }", Error{ R"(
stdin:1:16-33: ERROR: tseries() interval_ns must be >= 1 (0 provided)
kprobe:f { @ = tseries(1, 0, 10); }
               ~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { @ = tseries(1, -1, 10); }", Error{ R"(
stdin:1:16-34: ERROR: tseries: invalid interval_ns value (must be non-negative literal)
kprobe:f { @ = tseries(1, -1, 10); }
               ~~~~~~~~~~~~~~~~~~
)" });
  // Good duration strings.
  test("kprobe:f { @ = tseries(1, 10ns, 5); }");
  test("kprobe:f { @ = tseries(1, 10us, 5); }");
  test("kprobe:f { @ = tseries(1, 10ms, 5); }");
  test("kprobe:f { @ = tseries(1, 10s, 5); }");
  // All aggregator functions.
  test(R"(kprobe:f { @ = tseries(1, 10s, 5, "avg"); })");
  test(R"(kprobe:f { @ = tseries(1, 10s, 5, "max"); })");
  test(R"(kprobe:f { @ = tseries(1, 10s, 5, "min"); })");
  test(R"(kprobe:f { @ = tseries(1, 10s, 5, "sum"); })");
  // Invalid aggregator function.
  test(R"(kprobe:f { @ = tseries(1, 10s, 5, "stats"); })", Error{ R"(
stdin:1:16-43: ERROR: tseries() expects one of the following aggregation functions: avg, max, min, sum ("stats" provided)
kprobe:f { @ = tseries(1, 10s, 5, "stats"); }
               ~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, call_tseries_posparam)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("10s");
  bpftrace->add_param("5");
  bpftrace->add_param("20");
  test("kprobe:f { @ = tseries(5, $1, $2); }", Mock{ *bpftrace });
}

TEST_F(SemanticAnalyserTest, call_count)
{
  test("kprobe:f { @x = count(); }");
  test("kprobe:f { @x = count(1); }", Error{});
  test("kprobe:f { count(); }", Error{});
  test("kprobe:f { $x = count(); }", Error{});
  test("kprobe:f { @[count()] = 1; }", Error{});
  test("kprobe:f { if(count()) { 123 } }", Error{});
  test("kprobe:f { count() ? 0 : 1; }", Error{});
}

TEST_F(SemanticAnalyserTest, call_sum)
{
  test("kprobe:f { @x = sum(123); }");
  test("kprobe:f { @x = sum(); }", Error{});
  test("kprobe:f { @x = sum(123, 456); }", Error{});
  test("kprobe:f { sum(123); }", Error{});
  test("kprobe:f { $x = sum(123); }", Error{});
  test("kprobe:f { @[sum(123)] = 1; }", Error{});
  test("kprobe:f { if(sum(1)) { 123 } }", Error{});
  test("kprobe:f { sum(1) ? 0 : 1; }", Error{});
}

TEST_F(SemanticAnalyserTest, call_min)
{
  test("kprobe:f { @x = min(123); }");
  test("kprobe:f { @x = min(); }", Error{});
  test("kprobe:f { min(123); }", Error{});
  test("kprobe:f { $x = min(123); }", Error{});
  test("kprobe:f { @[min(123)] = 1; }", Error{});
  test("kprobe:f { if(min(1)) { 123 } }", Error{});
  test("kprobe:f { min(1) ? 0 : 1; }", Error{});
}

TEST_F(SemanticAnalyserTest, call_max)
{
  test("kprobe:f { @x = max(123); }");
  test("kprobe:f { @x = max(); }", Error{});
  test("kprobe:f { max(123); }", Error{});
  test("kprobe:f { $x = max(123); }", Error{});
  test("kprobe:f { @[max(123)] = 1; }", Error{});
  test("kprobe:f { if(max(1)) { 123 } }", Error{});
  test("kprobe:f { max(1) ? 0 : 1; }", Error{});
}

TEST_F(SemanticAnalyserTest, call_avg)
{
  test("kprobe:f { @x = avg(123); }");
  test("kprobe:f { @x = avg(); }", Error{});
  test("kprobe:f { avg(123); }", Error{});
  test("kprobe:f { $x = avg(123); }", Error{});
  test("kprobe:f { @[avg(123)] = 1; }", Error{});
  test("kprobe:f { if(avg(1)) { 123 } }", Error{});
  test("kprobe:f { avg(1) ? 0 : 1; }", Error{});
}

TEST_F(SemanticAnalyserTest, call_stats)
{
  test("kprobe:f { @x = stats(123); }");
  test("kprobe:f { @x = stats(); }", Error{});
  test("kprobe:f { stats(123); }", Error{});
  test("kprobe:f { $x = stats(123); }", Error{});
  test("kprobe:f { @[stats(123)] = 1; }", Error{});
  test("kprobe:f { if(stats(1)) { 123 } }", Error{});
  test("kprobe:f { stats(1) ? 0 : 1; }", Error{});
}

TEST_F(SemanticAnalyserTest, call_delete)
{
  test("kprobe:f { @x = 1; delete(@x); }");
  test("kprobe:f { @y[5] = 5; delete(@y, "
       "5); }");
  test("kprobe:f { @a[1] = 1; delete(@a, "
       "@a[1]); }");
  test("kprobe:f { @a = 1; @b[2] = 2; "
       "delete(@b, @a); }");
  test("kprobe:f { @a[1] = 1; $x = 1; "
       "delete(@a, $x); }");
  test(R"(kprobe:f { @y["hi"] = 5; delete(@y, "longerstr"); })");
  test(R"(kprobe:f { @y["hi", 5] = 5; delete(@y, ("hi", 5)); })");
  test(R"(kprobe:f { @y["longerstr", 5] = 5; delete(@y, ("hi", 5)); })");
  test(R"(kprobe:f { @y["hi", 5] = 5; delete(@y, ("longerstr", 5)); })");
  test("kprobe:f { @y[(3, 4, 5)] = 5; "
       "delete(@y, (1, 2, 3)); }");
  test("kprobe:f { @y[((int8)3, 4, 5)] = "
       "5; delete(@y, (1, 2, 3)); }");
  test("kprobe:f { @y[(3, 4, 5)] = 5; "
       "delete(@y, ((int8)1, 2, 3)); }");
  test("kprobe:f { @x = 1; @y = "
       "delete(@x); }");
  test("kprobe:f { @x = 1; $y = "
       "delete(@x); }");
  test("kprobe:f { @x = 1; @[delete(@x)] = "
       "1; }");
  test("kprobe:f { @x = 1; if(delete(@x)) "
       "{ 123 } }");
  test("kprobe:f { @x = 1; delete(@x) ? 0 "
       ": 1; }");
  // The second arg gets treated like a map
  // key, in terms of int type adjustment
  test("kprobe:f { @y[5] = 5; delete(@y, "
       "(int8)5); }");
  test("kprobe:f { @y[5, 4] = 5; delete(@y, "
       "((int8)5, (int64)4)); }");

  test("kprobe:f { delete(1); }", Error{ R"(
stdin:1:12-20: ERROR: delete() expects a map argument
kprobe:f { delete(1); }
           ~~~~~~~~
)" });

  test("kprobe:f { delete(1, 1); }", Error{ R"(
stdin:1:12-20: ERROR: delete() expects a map argument
kprobe:f { delete(1, 1); }
           ~~~~~~~~
)" });

  test("kprobe:f { @y[(3, 4, 5)] = "
       "5; delete(@y, (1, 2)); }",
       Error{ R"(
stdin:1:42-48: ERROR: Argument mismatch for @y: trying to access with arguments: '(int64,int64)' when map expects arguments: '(int64,int64,int64)'
kprobe:f { @y[(3, 4, 5)] = 5; delete(@y, (1, 2)); }
                                         ~~~~~~
)" });

  test("kprobe:f { @y[1] = 2; delete(@y); }", Error{ R"(
stdin:1:23-32: ERROR: call to delete() expects a map without explicit keys (scalar map)
kprobe:f { @y[1] = 2; delete(@y); }
                      ~~~~~~~~~
)" });

  test("kprobe:f { @a[1] = 1; "
       "delete(@a, @a); }",
       Error{ R"(
stdin:1:34-36: ERROR: @a used as a map without an explicit key (scalar map), previously used with an explicit key (non-scalar map)
kprobe:f { @a[1] = 1; delete(@a, @a); }
                                 ~~
)" });

  // Deprecated API
  test("kprobe:f { @x = 1; delete(@x); }");
  test("kprobe:f { @y[5] = 5; "
       "delete(@y[5]); }");
  test(R"(kprobe:f { @y[1, "hi"] = 5; delete(@y[1, "longerstr"]); })");
  test(R"(kprobe:f { @y[1, "longerstr"] = 5; delete(@y[1, "hi"]); })");

  test("kprobe:f { @x = 1; @y = 5; "
       "delete(@x, @y); }",
       Error{ R"(
stdin:1:28-37: ERROR: call to delete() expects a map with explicit keys (non-scalar map)
kprobe:f { @x = 1; @y = 5; delete(@x, @y); }
                           ~~~~~~~~~
)" });

  test(R"(kprobe:f { @x[1, "hi"] = 1; delete(@x["hi", 1]); })", Error{ R"(
stdin:1:29-47: ERROR: Argument mismatch for @x: trying to access with arguments: '(string,int64)' when map expects arguments: '(int64,string)'
kprobe:f { @x[1, "hi"] = 1; delete(@x["hi", 1]); }
                            ~~~~~~~~~~~~~~~~~~
)" });

  test("kprobe:f { @x[0] = 1; @y[5] = 5; "
       "delete(@x, @y[5], @y[6]); }",
       Error{ R"(
stdin:1:34-58: ERROR: delete() requires 1 or 2 arguments (3 provided)
kprobe:f { @x[0] = 1; @y[5] = 5; delete(@x, @y[5], @y[6]); }
                                 ~~~~~~~~~~~~~~~~~~~~~~~~
)" });

  test("kprobe:f { @x = 1; @y[5] = 5; "
       "delete(@x, @y[5], @y[6]); }",
       Error{ R"(
stdin:1:31-55: ERROR: delete() requires 1 or 2 arguments (3 provided)
kprobe:f { @x = 1; @y[5] = 5; delete(@x, @y[5], @y[6]); }
                              ~~~~~~~~~~~~~~~~~~~~~~~~
)" });

  test("kprobe:f { @x = 1; delete(@x[1]); }", Error{ R"(
stdin:1:20-29: ERROR: call to delete() expects a map with explicit keys (non-scalar map)
kprobe:f { @x = 1; delete(@x[1]); }
                   ~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, call_exit)
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

  test("kprobe:f { exit(1, 2); }", Error{ R"(
stdin:1:12-22: ERROR: exit() takes up to one argument (2 provided)
kprobe:f { exit(1, 2); }
           ~~~~~~~~~~
)" });
  test("kprobe:f { $a = \"1\"; exit($a); }", Error{ R"(
stdin:1:22-30: ERROR: exit() only supports int arguments (string provided)
kprobe:f { $a = "1"; exit($a); }
                     ~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, call_print)
{
  test("kprobe:f { @x = count(); print(@x); }");
  test("kprobe:f { @x = count(); print(@x, 5); }");
  test("kprobe:f { @x = count(); print(@x, 5, 10); }");
  test("kprobe:f { @x = count(); print(@x, 5, 10, 1); }", Error{});
  test("kprobe:f { @x = count(); @x = print(); }", Error{});

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

TEST_F(SemanticAnalyserTest, call_print_map_item)
{
  test(R"_(begin { @x[1] = 1; print(@x[1]); })_");
  test(R"_(begin { @x[1] = 1; @x[2] = 2; print(@x[2]); })_");
  test(R"_(begin { @x[1] = 1; print(@x[2]); })_");
  test(R"_(begin { @x[3, 5] = 1; print(@x[3, 5]); })_");
  test(R"_(begin { @x[1,2] = "asdf"; print((1, 2, @x[1,2])); })_");

  test("begin { @x[1] = 1; print(@x[\"asdf\"]); }", Error{ R"(
stdin:1:20-35: ERROR: Argument mismatch for @x: trying to access with arguments: 'string' when map expects arguments: 'int64'
begin { @x[1] = 1; print(@x["asdf"]); }
                   ~~~~~~~~~~~~~~~
)" });
  test("begin { print(@x[2]); }", Error{ R"(
stdin:1:9-20: ERROR: Undefined map: @x
begin { print(@x[2]); }
        ~~~~~~~~~~~
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

TEST_F(SemanticAnalyserTest, call_print_non_map)
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

TEST_F(SemanticAnalyserTest, call_clear)
{
  test("kprobe:f { @x = count(); clear(@x); }");
  test("kprobe:f { @x = count(); clear(@x, 1); }", Error{});
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

TEST_F(SemanticAnalyserTest, call_zero)
{
  test("kprobe:f { @x = count(); zero(@x); }");
  test("kprobe:f { @x = count(); zero(@x, 1); }", Error{});
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

TEST_F(SemanticAnalyserTest, call_len)
{
  test("kprobe:f { @x[0] = 0; len(@x); }");
  test("kprobe:f { @x[0] = 0; len(); }", Error{});
  test("kprobe:f { @x[0] = 0; len(@x, 1); }", Error{});
  test("kprobe:f { @x[0] = 0; len(@x[2]); }", Error{});
  test("kprobe:f { $x = 0; len($x); }", Error{});
  test("kprobe:f { len(ustack) }");
  test("kprobe:f { len(kstack) }");

  test("kprobe:f { len(0) }", Error{ R"(
stdin:1:12-18: ERROR: len() expects a map or stack to be provided
kprobe:f { len(0) }
           ~~~~~~
)" });

  test("kprobe:f { @x = 1; @s = len(@x) }", Error{ R"(
stdin:1:25-31: ERROR: call to len() expects a map with explicit keys (non-scalar map)
kprobe:f { @x = 1; @s = len(@x) }
                        ~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, call_has_key)
{
  test("kprobe:f { @x[1] = 0; if "
       "(has_key(@x, 1)) {} }");
  test("kprobe:f { @x[1, 2] = 0; if "
       "(has_key(@x, (3, 4))) {} }");
  test("kprobe:f { @x[1, (int8)2] = 0; if "
       "(has_key(@x, (3, 4))) {} }");
  test(R"(kprobe:f { @x[1, "hi"] = 0; if (has_key(@x, (2, "bye"))) {} })");
  test(
      R"(kprobe:f { @x[1, "hi"] = 0; if (has_key(@x, (2, "longerstr"))) {} })");
  test(
      R"(kprobe:f { @x[1, "longerstr"] = 0; if (has_key(@x, (2, "hi"))) {} })");
  test("kprobe:f { @x[1, 2] = 0; $a = (3, "
       "4); if (has_key(@x, $a)) {} }");
  test("kprobe:f { @x[1, 2] = 0; @a = (3, "
       "4); if (has_key(@x, @a)) {} }");
  test("kprobe:f { @x[1, 2] = 0; @a[1] = "
       "(3, 4); if (has_key(@x, @a[1])) {} "
       "}");
  test("kprobe:f { @x[1] = 0; @a = "
       "has_key(@x, 1); }");
  test("kprobe:f { @x[1] = 0; $a = "
       "has_key(@x, 1); }");
  test("kprobe:f { @x[1] = 0; "
       "@a[has_key(@x, 1)] = 1; }");

  test("kprobe:f { @x[1] = 1;  if (has_key(@x)) {} }", Error{ R"(
stdin:1:27-39: ERROR: has_key() requires 2 arguments (1 provided)
kprobe:f { @x[1] = 1;  if (has_key(@x)) {} }
                          ~~~~~~~~~~~~
)" });

  test("kprobe:f { @x[1] = 1;  if (has_key(@x[1], 1)) {} }", Error{ R"(
stdin:1:27-41: ERROR: has_key() expects a map argument
kprobe:f { @x[1] = 1;  if (has_key(@x[1], 1)) {} }
                          ~~~~~~~~~~~~~~
)" });

  test("kprobe:f { @x = 1;  if (has_key(@x, 1)) {} }", Error{ R"(
stdin:1:24-35: ERROR: call to has_key() expects a map with explicit keys (non-scalar map)
kprobe:f { @x = 1;  if (has_key(@x, 1)) {} }
                       ~~~~~~~~~~~
)" });

  test("kprobe:f { @x[1, 2] = 1;  if (has_key(@x, 1)) {} }", Error{ R"(
stdin:1:43-44: ERROR: Argument mismatch for @x: trying to access with arguments: 'int64' when map expects arguments: '(int64,int64)'
kprobe:f { @x[1, 2] = 1;  if (has_key(@x, 1)) {} }
                                          ~
)" });

  test(R"(kprobe:f { @x[1, "hi"] = 0; if (has_key(@x, (2, 1))) {} })",
       Error{ R"(
stdin:1:45-51: ERROR: Argument mismatch for @x: trying to access with arguments: '(int64,int64)' when map expects arguments: '(int64,string)'
kprobe:f { @x[1, "hi"] = 0; if (has_key(@x, (2, 1))) {} }
                                            ~~~~~~
)" });

  test("kprobe:f { @x[1] = 1; $a = 1; if (has_key($a, 1)) {} }", Error{ R"(
stdin:1:34-45: ERROR: has_key() expects a map argument
kprobe:f { @x[1] = 1; $a = 1; if (has_key($a, 1)) {} }
                                 ~~~~~~~~~~~
)" });

  test("kprobe:f { @a[1] = 1; has_key(@a, @a); }", Error{ R"(
stdin:1:35-37: ERROR: @a used as a map without an explicit key (scalar map), previously used with an explicit key (non-scalar map)
kprobe:f { @a[1] = 1; has_key(@a, @a); }
                                  ~~
)" });
}

TEST_F(SemanticAnalyserTest, call_time)
{
  test("kprobe:f { time(); }");
  test("kprobe:f { time(\"%M:%S\"); }");
  test("kprobe:f { time(\"%M:%S\", 1); }", Error{});
  test("kprobe:f { @x = time(); }", Error{});
  test("kprobe:f { $x = time(); }", Error{});
  test("kprobe:f { @[time()] = 1; }", Error{});
  test("kprobe:f { time(1); }", Error{});
  test("kprobe:f { $x = \"str\"; time($x); }", Error{});
  test("kprobe:f { if(time()) { 123 } }", Error{});
  test("kprobe:f { time() ? 0 : 1; }", Error{});
}

TEST_F(SemanticAnalyserTest, call_strftime)
{
  test("kprobe:f { strftime(\"%M:%S\", 1); }");
  test("kprobe:f { strftime(\"%M:%S\", nsecs); }");
  test(R"(kprobe:f { strftime("%M:%S", ""); })", Error{});
  test("kprobe:f { strftime(1, nsecs); }", Error{});
  test("kprobe:f { $var = \"str\"; strftime($var, nsecs); }", Error{});
  test("kprobe:f { strftime(); }", Error{});
  test("kprobe:f { strftime(\"%M:%S\"); }", Error{});
  test("kprobe:f { strftime(\"%M:%S\", 1, 1); }", Error{});
  test("kprobe:f { strftime(1, 1, 1); }", Error{});
  test(R"(kprobe:f { strftime("%M:%S", "", 1); })", Error{});
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

TEST_F(SemanticAnalyserTest, call_str)
{
  test("kprobe:f { str(arg0); }");
  test("kprobe:f { @x = str(arg0); }");
  test("kprobe:f { str(); }", Error{});
  test("kprobe:f { str(\"hello\"); }");
}

TEST_F(SemanticAnalyserTest, call_str_2_lit)
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

TEST_F(SemanticAnalyserTest, call_str_2_expr)
{
  test("kprobe:f { str(arg0, arg1); }");
  test("kprobe:f { @x = str(arg0, arg1); }");
}

TEST_F(SemanticAnalyserTest, call_str_state_leak_regression_test)
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

TEST_F(SemanticAnalyserTest, call_buf)
{
  test("kprobe:f { buf(arg0, 1); }");
  test("kprobe:f { buf(arg0, -1); }", Error{});
  test("kprobe:f { @x = buf(arg0, 1); }");
  test("kprobe:f { $x = buf(arg0, 1); }");
  test("kprobe:f { buf(); }", Error{});
  test("kprobe:f { buf(\"hello\"); }", Error{});
  test("struct x { int c[4] }; kprobe:f { "
       "$foo = (struct x*)0; @x = "
       "buf($foo->c); }");
}

TEST_F(SemanticAnalyserTest, call_buf_lit)
{
  test("kprobe:f { @x = buf(arg0, 3); }");
  test("kprobe:f { buf(arg0, \"hello\"); }", Error{});
}

TEST_F(SemanticAnalyserTest, call_buf_expr)
{
  test("kprobe:f { buf(arg0, arg1); }");
  test("kprobe:f { @x = buf(arg0, arg1); }");
}

TEST_F(SemanticAnalyserTest, call_buf_posparam)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("1");
  bpftrace->add_param("hello");
  test("kprobe:f { buf(arg0, $1); }", Mock{ *bpftrace });
  test("kprobe:f { buf(arg0, $2); }", Mock{ *bpftrace }, Error{});
}

TEST_F(SemanticAnalyserTest, call_ksym)
{
  test("kprobe:f { ksym(arg0); }");
  test("kprobe:f { @x = ksym(arg0); }");
  test("kprobe:f { ksym(); }", Error{});
  test("kprobe:f { ksym(\"hello\"); }", Error{});
}

TEST_F(SemanticAnalyserTest, call_usym)
{
  test("kprobe:f { usym(arg0); }");
  test("kprobe:f { @x = usym(arg0); }");
  test("kprobe:f { usym(); }", Error{});
  test("kprobe:f { usym(\"hello\"); }", Error{});
}

TEST_F(SemanticAnalyserTest, call_ntop)
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

  // Regression test that ntop can use
  // arguments from the prog context
  test("tracepoint:tcp:some_tcp_tp { ntop(args.saddr_v6); }");

  test("kprobe:f { ntop(); }", Error{});
  test("kprobe:f { ntop(2, \"hello\"); }", Error{});
  test("kprobe:f { ntop(\"hello\"); }", Error{});
  test(structs + "kprobe:f { ntop(((struct inet*)0)->invalid); }", Error{});
}

TEST_F(SemanticAnalyserTest, call_pton)
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

  test("kprobe:f { $addr_v4 = pton(); }", Error{});
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

TEST_F(SemanticAnalyserTest, call_kaddr)
{
  test("kprobe:f { kaddr(\"avenrun\"); }");
  test("kprobe:f { @x = kaddr(\"avenrun\"); }");
  test("kprobe:f { kaddr(); }", Error{});
  test("kprobe:f { kaddr(123); }", Error{});
}

TEST_F(SemanticAnalyserTest, call_uaddr)
{
  test("u:/bin/sh:main { "
       "uaddr(\"github.com/golang/"
       "glog.severityName\"); }");
  test("uprobe:/bin/sh:main { "
       "uaddr(\"glob_asciirange\"); }");
  test("u:/bin/sh:main,u:/bin/sh:readline "
       "{ uaddr(\"glob_asciirange\"); }");
  test("uprobe:/bin/sh:main { @x = "
       "uaddr(\"glob_asciirange\"); }");
  test("uprobe:/bin/sh:main { uaddr(); }", Error{});
  test("uprobe:/bin/sh:main { uaddr(123); }", Error{});
  test("uprobe:/bin/sh:main { "
       "uaddr(\"?\"); }",
       Error{});
  test("uprobe:/bin/sh:main { $str = "
       "\"glob_asciirange\"; uaddr($str); }",
       Error{});
  test("uprobe:/bin/sh:main { @str = "
       "\"glob_asciirange\"; uaddr(@str); }",
       Error{});

  test("k:f { uaddr(\"A\"); }", Error{});
  test("i:s:1 { uaddr(\"A\"); }", Error{});

  // The C struct parser should set the
  // is_signed flag on signed types
  BPFtrace bpftrace;
  std::string prog = "uprobe:/bin/sh:main {"
                     "$a = uaddr(\"12345_1\");"
                     "$b = uaddr(\"12345_2\");"
                     "$c = uaddr(\"12345_4\");"
                     "$d = uaddr(\"12345_8\");"
                     "$e = uaddr(\"12345_5\");"
                     "$f = uaddr(\"12345_33\");"
                     "}";

  auto ast = test(prog);

  std::vector<int> sizes = { 8, 16, 32, 64, 64, 64 };

  for (size_t i = 0; i < sizes.size(); i++) {
    auto *v = ast.root->probes.at(0)
                  ->block->stmts.at(i)
                  .as<ast::AssignVarStatement>();
    EXPECT_TRUE(v->var()->var_type.IsPtrTy());
    EXPECT_TRUE(v->var()->var_type.GetPointeeTy()->IsIntTy());
    EXPECT_EQ((unsigned long int)sizes.at(i),
              v->var()->var_type.GetPointeeTy()->GetIntBitWidth());
  }
}

TEST_F(SemanticAnalyserTest, call_cgroupid)
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

TEST_F(SemanticAnalyserTest, call_reg)
{
#ifdef __x86_64__
  test("kprobe:f { reg(\"ip\"); }");
  test("kprobe:f { @x = reg(\"ip\"); }");
#endif
  test("kprobe:f { reg(\"blah\"); }", Error{});
  test("kprobe:f { reg(); }", Error{});
  test("kprobe:f { reg(123); }", Error{});
}

TEST_F(SemanticAnalyserTest, call_func)
{
  test("kprobe:f { @[func] = count(); }");
  test("kprobe:f { printf(\"%s\", func); }");
  test("uprobe:/bin/sh:f { @[func] = count(); }");
  test("uprobe:/bin/sh:f { printf(\"%s\", func);  }");

  test("fentry:f { func }");
  test("fexit:f { func }");
  test("kretprobe:f { func }");
  test("uretprobe:/bin/sh:f { func }");

  // We only care about the
  // BPF_FUNC_get_func_ip feature and error
  // message here, but don't have enough
  // control over the mock features to only
  // disable that.
  test("fentry:f { func }", NoFeatures::Enable, Error{ R"(
ERROR: BPF_FUNC_get_func_ip not available for your kernel version
)" });
  test("fexit:f { func }", NoFeatures::Enable, Error{ R"(
BPF_FUNC_get_func_ip not available for your kernel version
)" });
  test("kretprobe:f { func }", NoFeatures::Enable, Error{ R"(
ERROR: The 'func' builtin is not available for kretprobes on kernels without the get_func_ip BPF feature. Consider using the 'probe' builtin instead.
)" });
  test("uretprobe:/bin/sh:f { func }", NoFeatures::Enable, Error{ R"(
ERROR: The 'func' builtin is not available for uretprobes on kernels without the get_func_ip BPF feature. Consider using the 'probe' builtin instead.
)" });
}

TEST_F(SemanticAnalyserTest, call_probe)
{
  test("kprobe:f { @[probe] = count(); }");
  test("kprobe:f { printf(\"%s\", probe); }");
}

TEST_F(SemanticAnalyserTest, call_cat)
{
  test("kprobe:f { cat(\"/proc/loadavg\"); }");
  test("kprobe:f { cat(\"/proc/%d/cmdline\", 1); }");
  test("kprobe:f { cat(); }", Error{});
  test("kprobe:f { cat(123); }", Error{});
  test("kprobe:f { @x = cat(\"/proc/loadavg\"); }", Error{});
  test("kprobe:f { $x = cat(\"/proc/loadavg\"); }", Error{});
  test("kprobe:f { @[cat(\"/proc/loadavg\")] = 1; }", Error{});
  test("kprobe:f { if(cat(\"/proc/loadavg\")) { 123 } }", Error{});
  test("kprobe:f { cat(\"/proc/loadavg\") ? 0 : 1; }", Error{});
}

TEST_F(SemanticAnalyserTest, call_stack)
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
  test("kprobe:f { kstack(perf, 3, 4) }", Error{});
  test("kprobe:f { ustack(perf, 3, 4) }", Error{});
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
}

TEST_F(SemanticAnalyserTest, call_macaddr)
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

  test("kprobe:f { macaddr(); }", Error{});
  test("kprobe:f { macaddr(\"foo\"); }", Error{});
}

TEST_F(SemanticAnalyserTest, call_bswap)
{
  test("kprobe:f { bswap(arg0); }");

  test("kprobe:f { bswap(0x12); }");
  test("kprobe:f { bswap(0x12 + 0x34); }");

  test("kprobe:f { bswap((int8)0x12); }");
  test("kprobe:f { bswap((int16)0x12); }");
  test("kprobe:f { bswap((int32)0x12); }");
  test("kprobe:f { bswap((int64)0x12); }");

  test("kprobe:f { bswap(); }", Error{});
  test("kprobe:f { bswap(0x12, 0x34); }", Error{});

  test("kprobe:f { bswap(\"hello\"); }", Error{});
}

TEST_F(SemanticAnalyserTest, call_cgroup_path)
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

TEST_F(SemanticAnalyserTest, call_strerror)
{
  test("kprobe:f { strerror(1) }");

  test("kprobe:f { strerror(1, 2) }", Error{});
  test("kprobe:f { strerror(\"1\") }", Error{});

  test("kprobe:f { printf(\"%s\", strerror(1)) }");
  test("kprobe:f { printf(\"%s %s\", strerror(1), strerror(2)) }");
  test("kprobe:f { $var = strerror(0); printf(\"%s %s\", $var, $var) }");

  test("kprobe:f { printf(\"%d\", strerror(1)) }", Error{});
}

TEST_F(SemanticAnalyserTest, map_reassignment)
{
  test("kprobe:f { @x = 1; @x = 2; }");
  test("kprobe:f { @x = 1; @x = \"foo\"; }", Error{});
}

TEST_F(SemanticAnalyserTest, variable_reassignment)
{
  test("kprobe:f { $x = 1; $x = 2; }");
  test("kprobe:f { $x = 1; $x = \"foo\"; }", Error{});
  test(R"(kprobe:f { $b = "hi"; $b = @b; } kprobe:g { @b = "bye"; })");

  test(R"(kprobe:f { $b = "hi"; $b = @b; } kprobe:g { @b = 1; })", Error{ R"(
stdin:1:23-30: ERROR: Type mismatch for $b: trying to assign value of type 'int64' when variable already contains a value of type 'string'
kprobe:f { $b = "hi"; $b = @b; } kprobe:g { @b = 1; }
                      ~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, map_use_before_assign)
{
  test("kprobe:f { @x = @y; @y = 2; }");
}

TEST_F(SemanticAnalyserTest, variable_use_before_assign)
{
  test("kprobe:f { @x = $y; $y = 2; }", Error{});
}

TEST_F(SemanticAnalyserTest, maps_are_global)
{
  test("kprobe:f { @x = 1 } kprobe:g { @y = @x }");
  test("kprobe:f { @x = 1 } kprobe:g { @x = \"abc\" }", Error{});
}

TEST_F(SemanticAnalyserTest, variables_are_local)
{
  test("kprobe:f { $x = 1 } kprobe:g { $x = \"abc\"; }");
  test("kprobe:f { $x = 1 } kprobe:g { @y = $x }", Error{});
}

TEST_F(SemanticAnalyserTest, array_access)
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
       "arg0; $idx = 0; @x = $s->y[$idx];}",
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
  EXPECT_EQ(CreateInt64(), assignment->map->value_type);

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
            array_map_assignment->map->value_type);

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

TEST_F(SemanticAnalyserTest, array_in_map)
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

TEST_F(SemanticAnalyserTest, array_as_map_key)
{
  test("struct MyStruct { int x[2]; int y[4]; }"
       "kprobe:f { @x[((struct MyStruct *)arg0)->x] = 0; }");

  test("struct MyStruct { int x[2]; int y[4]; }"
       "kprobe:f { @x[((struct MyStruct *)arg0)->x, "
       "              ((struct MyStruct *)arg0)->y] = 0; }");

  // Mismatched key types
  test(R"(
    struct MyStruct { int x[2]; int y[4]; }
    begin {
      @x[((struct MyStruct *)0)->x] = 0;
      @x[((struct MyStruct *)0)->y] = 1;
    })",
       Error{ R"(
stdin:4:7-36: ERROR: Argument mismatch for @x: trying to access with arguments: 'int32[4]' when map expects arguments: 'int32[2]'
      @x[((struct MyStruct *)0)->y] = 1;
      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, array_compare)
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

TEST_F(SemanticAnalyserTest, variable_type)
{
  auto ast = test("kprobe:f { $x = 1 }");
  auto st = CreateInt64();
  auto *assignment =
      ast.root->probes.at(0)->block->stmts.at(0).as<ast::AssignVarStatement>();
  EXPECT_EQ(st, assignment->var()->var_type);
}

TEST_F(SemanticAnalyserTest, unroll)
{
  test(R"(kprobe:f { $i = 0; unroll(5) { printf("%d", $i); $i = $i + 1; } })");
  test(R"(kprobe:f { $i = 0; unroll(101) { printf("%d", $i); $i = $i + 1; } })",
       Error{});
  test(R"(kprobe:f { $i = 0; unroll(0) { printf("%d", $i); $i = $i + 1; } })",
       Error{});

  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("10");
  bpftrace->add_param("hello");
  bpftrace->add_param("101");
  test(R"(kprobe:f { unroll($#) { printf("hi\n"); } })", Mock{ *bpftrace });
  test(R"(kprobe:f { unroll($1) { printf("hi\n"); } })", Mock{ *bpftrace });
  test(R"(kprobe:f { unroll($2) { printf("hi\n"); } })",
       Mock{ *bpftrace },
       Error{});
  test(R"(kprobe:f { unroll($3) { printf("hi\n"); } })",
       Mock{ *bpftrace },
       Error{});
}

TEST_F(SemanticAnalyserTest, map_integer_sizes)
{
  auto ast = test("kprobe:f { $x = (int32) -1; @x = $x; }");

  auto *var_assignment =
      ast.root->probes.at(0)->block->stmts.at(0).as<ast::AssignVarStatement>();
  auto *map_assignment =
      ast.root->probes.at(0)->block->stmts.at(1).as<ast::AssignMapStatement>();
  EXPECT_EQ(CreateInt32(), var_assignment->var()->var_type);
  EXPECT_EQ(CreateInt64(), map_assignment->map->value_type);
}

TEST_F(SemanticAnalyserTest, binop_integer_promotion)
{
  auto ast = test("kprobe:f { $x = (int32)5 + (int16)6 }");

  auto *var_assignment =
      ast.root->probes.at(0)->block->stmts.at(0).as<ast::AssignVarStatement>();
  EXPECT_EQ(CreateInt32(), var_assignment->var()->var_type);
}

TEST_F(SemanticAnalyserTest, binop_integer_no_promotion)
{
  auto ast = test("kprobe:f { $x = (int8)5 + (int8)6 }");

  auto *var_assignment =
      ast.root->probes.at(0)->block->stmts.at(0).as<ast::AssignVarStatement>();
  EXPECT_EQ(CreateInt8(), var_assignment->var()->var_type);
}

TEST_F(SemanticAnalyserTest, unop_dereference)
{
  test("kprobe:f { *0; }");
  test("struct X { int n; } kprobe:f { $x = (struct X*)0; *$x; }");
  test("struct X { int n; } kprobe:f { $x = *(struct X*)0; *$x; }", Error{});
  test("kprobe:f { *\"0\"; }", Error{});
}

TEST_F(SemanticAnalyserTest, unop_not)
{
  std::string structs = "struct X { int x; };";
  test("kprobe:f { ~0; }");
  test(structs + "kprobe:f { $x = *(struct X*)0; ~$x; }", Error{});
  test(structs + "kprobe:f { $x = (struct X*)0; ~$x; }", Error{});
  test("kprobe:f { ~\"0\"; }", Error{});
}

TEST_F(SemanticAnalyserTest, unop_lnot)
{
  test("kprobe:f { !0; }");
  test("kprobe:f { !false; }");
  test("kprobe:f { !(int32)0; }");
  test("struct X { int n; } kprobe:f { $x = (struct X*)0; !$x; }", Error{});
  test("struct X { int n; } kprobe:f { $x = *(struct X*)0; !$x; }", Error{});
  test("kprobe:f { !\"0\"; }", Error{});
}

TEST_F(SemanticAnalyserTest, unop_increment_decrement)
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
}

TEST_F(SemanticAnalyserTest, printf_and_errorf)
{
  std::vector<std::string> funcs = { "printf", "errorf" };
  for (const auto &func : funcs) {
    test("kprobe:f { " + func + "(\"hi\") }");
    test("kprobe:f { " + func + "(1234) }", Error{});
    test("kprobe:f { " + func + "() }", Error{});
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

TEST_F(SemanticAnalyserTest, debugf)
{
  test("kprobe:f { debugf(\"warning\") }",
       Warning{ "The debugf() builtin is not "
                "recommended for production use." });
  test("kprobe:f { debugf(\"hi\") }");
  test("kprobe:f { debugf(1234) }", Error{});
  test("kprobe:f { debugf() }", Error{});
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
  test("kprobe:f { debugf(\"%d %d %d %d\", 1, 1, 1, 1) }", Error{});

  {
    // Long format string should be ok
    std::stringstream prog;
    prog << "i:ms:100 { debugf(\"" << std::string(59, 'a')
         << R"(%s\n", "a"); })";
    test(prog.str());
  }
}

TEST_F(SemanticAnalyserTest, system)
{
  test("kprobe:f { system(\"ls\") }", UnsafeMode::Enable);
  test("kprobe:f { system(1234) }", UnsafeMode::Enable, Error{});
  test("kprobe:f { system() }", UnsafeMode::Enable, Error{});
  test("kprobe:f { $fmt = \"mystring\"; system($fmt) }",
       UnsafeMode::Enable,
       Error{});
}

TEST_F(SemanticAnalyserTest, printf_format_int)
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

TEST_F(SemanticAnalyserTest, printf_format_int_with_length)
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

TEST_F(SemanticAnalyserTest, printf_format_string)
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

TEST_F(SemanticAnalyserTest, printf_bad_format_string)
{
  test(R"(kprobe:f { printf("%d", "mystr") })", Error{});
  test("kprobe:f { printf(\"%d\", str(arg0)) }", Error{});
}

TEST_F(SemanticAnalyserTest, printf_format_buf)
{
  test(R"(kprobe:f { printf("%r", buf("mystr", 5)) })");
}

TEST_F(SemanticAnalyserTest, printf_bad_format_buf)
{
  test(R"(kprobe:f { printf("%r", "mystr") })", Error{});
  test("kprobe:f { printf(\"%r\", arg0) }", Error{});
}

TEST_F(SemanticAnalyserTest, printf_format_buf_no_ascii)
{
  test(R"(kprobe:f { printf("%rx", buf("mystr", 5)) })");
}

TEST_F(SemanticAnalyserTest, printf_bad_format_buf_no_ascii)
{
  test(R"(kprobe:f { printf("%rx", "mystr") })", Error{});
  test("kprobe:f { printf(\"%rx\", arg0) }", Error{});
}

TEST_F(SemanticAnalyserTest, printf_format_buf_nonescaped_hex)
{
  test(R"(kprobe:f { printf("%rh", buf("mystr", 5)) })");
}

TEST_F(SemanticAnalyserTest, printf_bad_format_buf_nonescaped_hex)
{
  test(R"(kprobe:f { printf("%rh", "mystr") })", Error{});
  test("kprobe:f { printf(\"%rh\", arg0) }", Error{});
}

TEST_F(SemanticAnalyserTest, printf_format_multi)
{
  test(R"(kprobe:f { printf("%d %d %s", 1, 2, "mystr") })");
  test(R"(kprobe:f { printf("%d %s %d", 1, 2, "mystr") })", Error{});
}

TEST_F(SemanticAnalyserTest, join)
{
  test("kprobe:f { join(arg0) }");
  test("kprobe:f { printf(\"%s\", join(arg0)) }", Error{});
  test("kprobe:f { join() }", Error{});
  test("kprobe:f { $fmt = \"mystring\"; join($fmt) }", Error{});
  test("kprobe:f { @x = join(arg0) }", Error{});
  test("kprobe:f { $x = join(arg0) }", Error{});
}

TEST_F(SemanticAnalyserTest, join_delimiter)
{
  test("kprobe:f { join(arg0, \",\") }");
  test(R"(kprobe:f { printf("%s", join(arg0, ",")) })", Error{});
  test(R"(kprobe:f { $fmt = "mystring"; join($fmt, ",") })", Error{});
  test("kprobe:f { @x = join(arg0, \",\") }", Error{});
  test("kprobe:f { $x = join(arg0, \",\") }", Error{});
  test("kprobe:f { join(arg0, 3) }", Error{});
}

TEST_F(SemanticAnalyserTest, kprobe)
{
  test("kprobe:f { 1 }");
  test("kretprobe:f { 1 }");
}

TEST_F(SemanticAnalyserTest, uprobe)
{
  test("uprobe:/bin/sh:f { 1 }");
  test("u:/bin/sh:f { 1 }");
  test("uprobe:/bin/sh:0x10 { 1 }");
  test("u:/bin/sh:0x10 { 1 }");
  test("uprobe:/bin/sh:f+0x10 { 1 }");
  test("u:/bin/sh:f+0x10 { 1 }");
  test("uprobe:sh:f { 1 }");
  test("uprobe:/bin/sh:cpp:f { 1 }");
  test("uprobe:/notexistfile:f { 1 }", Error{});
  test("uprobe:notexistfile:f { 1 }", Error{});
  test("uprobe:/bin/sh:nolang:f { 1 }", Error{});

  test("uretprobe:/bin/sh:f { 1 }");
  test("ur:/bin/sh:f { 1 }");
  test("uretprobe:sh:f { 1 }");
  test("ur:sh:f { 1 }");
  test("uretprobe:/bin/sh:0x10 { 1 }");
  test("ur:/bin/sh:0x10 { 1 }");
  test("uretprobe:/bin/sh:cpp:f { 1 }");
  test("uretprobe:/notexistfile:f { 1 }", Error{});
  test("uretprobe:notexistfile:f { 1 }", Error{});
  test("uretprobe:/bin/sh:nolang:f { 1 }", Error{});
}

TEST_F(SemanticAnalyserTest, usdt)
{
  test("usdt:/bin/sh:probe { 1 }");
  test("usdt:sh:probe { 1 }");
  test("usdt:/bin/sh:namespace:probe { 1 }");
  test("usdt:/notexistfile:namespace:probe { 1 }", Error{});
  test("usdt:notexistfile:namespace:probe { 1 }", Error{});
}

TEST_F(SemanticAnalyserTest, begin_end_probes)
{
  test("begin { 1 }");
  test("begin { 1 } begin { 2 }", Error{});

  test("end { 1 }");
  test("end { 1 } end { 2 }", Error{});
}

TEST_F(SemanticAnalyserTest, bench_probes)
{
  test("bench:a { 1 } bench:b { 2 }");
  test("bench: { 1 }", Error{ R"(
stdin:1:1-7: ERROR: bench probes must have a name
bench: { 1 }
~~~~~~
)" });
  test("BENCH:a { 1 } BENCH:a { 2 }", Error{ R"(
stdin:1:14-22: ERROR: "a" was used as the name for more than one BENCH probe
BENCH:a { 1 } BENCH:a { 2 }
             ~~~~~~~~
stdin:1:1-8: ERROR: this is the other instance
BENCH:a { 1 } BENCH:a { 2 }
~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, self_probe)
{
  test("self:signal:SIGUSR1 { 1 }");

  test("self:signal:sighup { 1 }", Error{ R"(
stdin:1:1-19: ERROR: sighup is not a supported signal
self:signal:sighup { 1 }
~~~~~~~~~~~~~~~~~~
)" });
  test("self:keypress:space { 1 }", Error{ R"(
stdin:1:1-20: ERROR: keypress is not a supported trigger
self:keypress:space { 1 }
~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, tracepoint)
{
  test("tracepoint:category:event { 1 }");
}

TEST_F(SemanticAnalyserTest, rawtracepoint)
{
  test("rawtracepoint:event { 1 }");
  test("rawtracepoint:event { arg0 }");
  test("rawtracepoint:mod:event { arg0 }");
}

TEST_F(SemanticAnalyserTest, watchpoint_invalid_modes)
{
  if (arch::Host::Machine != arch::ARM64 &&
      arch::Host::Machine != arch::X86_64) {
    GTEST_SKIP() << "Watchpoint tests are only supported on ARM64 and X86_64";
  }

  auto bpftrace = get_mock_bpftrace();
  bpftrace->procmon_ = std::make_unique<MockProcMon>(123);

  if (arch::Host::Machine == arch::ARM64) {
    test("watchpoint:0x1234:8:r { 1 }", Mock{ *bpftrace });
  } else {
    test("watchpoint:0x1234:8:r { 1 }", Mock{ *bpftrace }, Error{});
  }
  test("watchpoint:0x1234:8:rx { 1 }", Mock{ *bpftrace }, Error{});
  test("watchpoint:0x1234:8:wx { 1 }", Mock{ *bpftrace }, Error{});
  test("watchpoint:0x1234:8:xw { 1 }", Mock{ *bpftrace }, Error{});
  test("watchpoint:0x1234:8:rwx { 1 }", Mock{ *bpftrace }, Error{});
  test("watchpoint:0x1234:8:xx { 1 }", Mock{ *bpftrace }, Error{});
  test("watchpoint:0x1234:8:b { 1 }", Mock{ *bpftrace }, Error{});
}

TEST_F(SemanticAnalyserTest, watchpoint_absolute)
{
  if (arch::Host::Machine != arch::ARM64 &&
      arch::Host::Machine != arch::X86_64) {
    GTEST_SKIP() << "Watchpoint tests are only supported on ARM64 and X86_64";
  }

  auto bpftrace = get_mock_bpftrace();
  bpftrace->procmon_ = std::make_unique<MockProcMon>(123);

  test("watchpoint:0x1234:8:rw { 1 }", Mock{ *bpftrace });
  test("watchpoint:0x1234:9:rw { 1 }", Mock{ *bpftrace }, Error{});
  test("watchpoint:0x0:8:rw { 1 }", Mock{ *bpftrace }, Error{});
}

TEST_F(SemanticAnalyserTest, watchpoint_function)
{
  if (arch::Host::Machine != arch::ARM64 &&
      arch::Host::Machine != arch::X86_64) {
    GTEST_SKIP() << "Watchpoint tests are only supported on ARM64 and X86_64";
  }

  auto bpftrace = get_mock_bpftrace();
  bpftrace->procmon_ = std::make_unique<MockProcMon>(123);

  test("watchpoint:func1+arg2:8:rw { 1 }", Mock{ *bpftrace });
  test("w:func1+arg2:8:rw { 1 }", Mock{ *bpftrace });
  test("w:func1.one_two+arg2:8:rw { 1 }", Mock{ *bpftrace });
  test("watchpoint:func1+arg99999:8:rw { 1 }", Mock{ *bpftrace }, Error{});

  bpftrace->procmon_ = nullptr;
  test("watchpoint:func1+arg2:8:rw { 1 }", Mock{ *bpftrace }, Error{});
}

TEST_F(SemanticAnalyserTest, asyncwatchpoint)
{
  if (arch::Host::Machine != arch::ARM64 &&
      arch::Host::Machine != arch::X86_64) {
    GTEST_SKIP() << "Watchpoint tests are only supported on ARM64 and X86_64";
  }

  auto bpftrace = get_mock_bpftrace();
  bpftrace->procmon_ = std::make_unique<MockProcMon>(123);

  test("asyncwatchpoint:func1+arg2:8:rw { 1 }", Mock{ *bpftrace });
  test("aw:func1+arg2:8:rw { 1 }", Mock{ *bpftrace });
  test("aw:func1.one_two+arg2:8:rw { 1 }", Mock{ *bpftrace });
  test("asyncwatchpoint:func1+arg99999:8:rw { 1 }", Mock{ *bpftrace }, Error{});

  // asyncwatchpoint's may not use absolute addresses
  test("asyncwatchpoint:0x1234:8:rw { 1 }", Mock{ *bpftrace }, Error{});

  bpftrace->procmon_ = nullptr;
  test("watchpoint:func1+arg2:8:rw { 1 }", Mock{ *bpftrace }, Error{});
}

TEST_F(SemanticAnalyserTest, args_builtin_wrong_use)
{
  test("begin { args.foo }", Error{});
  test("end { args.foo }", Error{});
  test("kprobe:f { args.foo }", Error{});
  test("kretprobe:f { args.foo }", Error{});
  test("uretprobe:/bin/sh/:f { args.foo }", Error{});
  test("profile:ms:1 { args.foo }", Error{});
  test("usdt:sh:namespace:probe { args.foo }", Error{});
  test("profile:ms:100 { args.foo }", Error{});
  test("hardware:cache-references:1000000 { args.foo }", Error{});
  test("software:faults:1000 { args.foo }", Error{});
  test("interval:s:1 { args.foo }", Error{});
}

TEST_F(SemanticAnalyserTest, profile)
{
  test("profile:hz:997 { 1 }");
  test("profile:s:10 { 1 }");
  test("profile:ms:100 { 1 }");
  test("profile:us:100 { 1 }");
  test("profile:unit:100 { 1 }", Error{});
}

TEST_F(SemanticAnalyserTest, interval)
{
  test("interval:hz:997 { 1 }");
  test("interval:s:10 { 1 }");
  test("interval:ms:100 { 1 }");
  test("interval:us:100 { 1 }");
  test("interval:unit:100 { 1 }", Error{});
}

TEST_F(SemanticAnalyserTest, variable_cast_types)
{
  std::string structs = "struct type1 { int field; } struct "
                        "type2 { int field; }";
  test(structs +
       "kprobe:f { $x = (struct type1*)cpu; $x = (struct type1*)cpu; }");
  test(structs +
           "kprobe:f { $x = (struct type1*)cpu; $x = (struct type2*)cpu; }",
       Error{});
}

TEST_F(SemanticAnalyserTest, map_cast_types)
{
  std::string structs = "struct type1 { int field; } struct "
                        "type2 { int field; }";
  test(structs +
       "kprobe:f { @x = *(struct type1*)cpu; @x = *(struct type1*)cpu; }");
  test(structs +
           "kprobe:f { @x = *(struct type1*)cpu; @x = *(struct type2*)cpu; }",
       Error{});
}

TEST_F(SemanticAnalyserTest, map_aggregations_implicit_cast)
{
  // When assigning an aggregation to a map
  // containing integers, the aggregation is
  // implicitly cast to an integer.
  test("kprobe:f { @x = 1; @y = count(); @x = @y; }", ExpectedAST{ R"(
  =
   map: @x :: [int64]int64
    int: 0 :: [int64]
   (int64)
    [] :: [count_t]
     map: @y :: [int64]count_t
     int: 0 :: [int64]
)" });
  test("kprobe:f { @x = 1; @y = sum(5); @x = @y; }", ExpectedAST{ R"(
  =
   map: @x :: [int64]int64
    int: 0 :: [int64]
   (int64)
    [] :: [sum_t]
     map: @y :: [int64]sum_t
     int: 0 :: [int64]
)" });
  test("kprobe:f { @x = 1; @y = min(5); @x = @y; }", ExpectedAST{ R"(
  =
   map: @x :: [int64]int64
    int: 0 :: [int64]
   (int64)
    [] :: [min_t]
     map: @y :: [int64]min_t
     int: 0 :: [int64]
)" });
  test("kprobe:f { @x = 1; @y = max(5); @x = @y; }", ExpectedAST{ R"(
  =
   map: @x :: [int64]int64
    int: 0 :: [int64]
   (int64)
    [] :: [max_t]
     map: @y :: [int64]max_t
     int: 0 :: [int64]
)" });
  test("kprobe:f { @x = 1; @y = avg(5); @x = @y; }", ExpectedAST{ R"(
  =
   map: @x :: [int64]int64
    int: 0 :: [int64]
   (int64)
    [] :: [avg_t]
     map: @y :: [int64]avg_t
     int: 0 :: [int64]
)" });

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
stdin:1:25-32: ERROR: Map value 'sum_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@x = sum(retval);`.
kprobe:f { @y = sum(5); @x = @y; }
                        ~~~~~~~
HINT: Add a cast to integer if you want the value of the aggregate, e.g. `@x = (int64)@y;`.
)" });
  test("kprobe:f { @y = min(5); @x = @y; }", Error{ R"(
stdin:1:25-32: ERROR: Map value 'min_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@x = min(retval);`.
kprobe:f { @y = min(5); @x = @y; }
                        ~~~~~~~
HINT: Add a cast to integer if you want the value of the aggregate, e.g. `@x = (int64)@y;`.
)" });
  test("kprobe:f { @y = max(5); @x = @y; }", Error{ R"(
stdin:1:25-32: ERROR: Map value 'max_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@x = max(retval);`.
kprobe:f { @y = max(5); @x = @y; }
                        ~~~~~~~
HINT: Add a cast to integer if you want the value of the aggregate, e.g. `@x = (int64)@y;`.
)" });
  test("kprobe:f { @y = avg(5); @x = @y; }", Error{ R"(
stdin:1:25-32: ERROR: Map value 'avg_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@x = avg(retval);`.
kprobe:f { @y = avg(5); @x = @y; }
                        ~~~~~~~
HINT: Add a cast to integer if you want the value of the aggregate, e.g. `@x = (int64)@y;`.
)" });
  test("kprobe:f { @y = stats(5); @x = @y; }", Error{ R"(
stdin:1:27-34: ERROR: Map value 'stats_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@x = stats(arg2);`.
kprobe:f { @y = stats(5); @x = @y; }
                          ~~~~~~~
)" });
  test("kprobe:f { @x = 1; @y = stats(5); @x = @y; }", Error{ R"(
stdin:1:35-42: ERROR: Map value 'stats_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@x = stats(arg2);`.
kprobe:f { @x = 1; @y = stats(5); @x = @y; }
                                  ~~~~~~~
stdin:1:35-42: ERROR: Type mismatch for @x: trying to assign value of type 'stats_t' when map already contains a value of type 'int64'
kprobe:f { @x = 1; @y = stats(5); @x = @y; }
                                  ~~~~~~~
)" });

  test("kprobe:f { @ = count(); if (@ > 0) { print((1)); } }");
  test("kprobe:f { @ = sum(5); if (@ > 0) { print((1)); } }");
  test("kprobe:f { @ = min(5); if (@ > 0) { print((1)); } }");
  test("kprobe:f { @ = max(5); if (@ > 0) { print((1)); } }");
  test("kprobe:f { @ = avg(5); if (@ > 0) { print((1)); } }");

  test("kprobe:f { @ = hist(5); if (@ > 0) { print((1)); } }", Error{ R"(
stdin:1:31-32: ERROR: Type mismatch for '>': comparing hist_t with int64
kprobe:f { @ = hist(5); if (@ > 0) { print((1)); } }
                              ~
stdin:1:28-30: ERROR: left (hist_t)
kprobe:f { @ = hist(5); if (@ > 0) { print((1)); } }
                           ~~
stdin:1:33-34: ERROR: right (int64)
kprobe:f { @ = hist(5); if (@ > 0) { print((1)); } }
                                ~
)" });
  test("kprobe:f { @ = count(); @ += 5 }", Error{ R"(
stdin:1:25-31: ERROR: Type mismatch for @: trying to assign value of type 'uint64' when map already contains a value of type 'count_t'
kprobe:f { @ = count(); @ += 5 }
                        ~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, map_aggregations_explicit_cast)
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

TEST_F(SemanticAnalyserTest, variable_casts_are_local)
{
  std::string structs = "struct type1 { int field; } struct "
                        "type2 { int field; }";
  test(structs + "kprobe:f { $x = *(struct type1 *)cpu } "
                 "kprobe:g { $x = *(struct type2 *)cpu; }");
}

TEST_F(SemanticAnalyserTest, map_casts_are_global)
{
  std::string structs = "struct type1 { int field; } struct "
                        "type2 { int field; }";
  test(structs + "kprobe:f { @x = *(struct type1 *)cpu }"
                 "kprobe:g { @x = *(struct type2 *)cpu }",
       Error{});
}

TEST_F(SemanticAnalyserTest, cast_unknown_type)
{
  test("begin { (struct faketype *)cpu }", Error{ R"(
stdin:1:9-29: ERROR: Cannot resolve unknown type "struct faketype"
begin { (struct faketype *)cpu }
        ~~~~~~~~~~~~~~~~~~~~
)" });
  test("begin { (faketype)cpu }", Error{ R"(
stdin:1:9-19: ERROR: Cannot resolve unknown type "faketype"
begin { (faketype)cpu }
        ~~~~~~~~~~
stdin:1:9-19: ERROR: Cannot cast to "faketype"
begin { (faketype)cpu }
        ~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, cast_c_integers)
{
  // Casting to a C integer type gives a hint with the correct name
  test("begin { (char)cpu }", Error{ R"(
stdin:1:9-15: ERROR: Cannot resolve unknown type "char"
begin { (char)cpu }
        ~~~~~~
stdin:1:9-15: ERROR: Cannot cast to "char"
begin { (char)cpu }
        ~~~~~~
HINT: Did you mean "int8"?
)" });
  test("begin { (short)cpu }", Error{ R"(
stdin:1:9-16: ERROR: Cannot resolve unknown type "short"
begin { (short)cpu }
        ~~~~~~~
stdin:1:9-16: ERROR: Cannot cast to "short"
begin { (short)cpu }
        ~~~~~~~
HINT: Did you mean "int16"?
)" });
  test("begin { (int)cpu }", Error{ R"(
stdin:1:9-14: ERROR: Cannot resolve unknown type "int"
begin { (int)cpu }
        ~~~~~
stdin:1:9-14: ERROR: Cannot cast to "int"
begin { (int)cpu }
        ~~~~~
HINT: Did you mean "int32"?
)" });
  test("begin { (long)cpu }", Error{ R"(
stdin:1:9-15: ERROR: Cannot resolve unknown type "long"
begin { (long)cpu }
        ~~~~~~
stdin:1:9-15: ERROR: Cannot cast to "long"
begin { (long)cpu }
        ~~~~~~
HINT: Did you mean "int64"?
)" });
}

TEST_F(SemanticAnalyserTest, cast_struct)
{
  // Casting struct by value is forbidden
  test("struct mytype { int field; }\n"
       "begin { $s = (struct mytype *)cpu; (uint32)*$s; }",
       Error{ R"(
stdin:2:37-45: ERROR: Cannot cast from struct type "struct mytype"
begin { $s = (struct mytype *)cpu; (uint32)*$s; }
                                    ~~~~~~~~
stdin:2:37-45: ERROR: Cannot cast from "struct mytype" to "uint32"
begin { $s = (struct mytype *)cpu; (uint32)*$s; }
                                    ~~~~~~~~
)" });
  test("struct mytype { int field; } "
       "begin { (struct mytype)cpu }",
       Error{ R"(
stdin:1:38-54: ERROR: Cannot cast to "struct mytype"
struct mytype { int field; } begin { (struct mytype)cpu }
                                     ~~~~~~~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, cast_bool)
{
  test("kprobe:f { $a = (bool)1; }");
  test("kprobe:f { $a = (bool)\"str\"; }");
  test("kprobe:f { $a = (bool)comm; }");
  test("kprobe:f { $a = (int64 *)0; $b = (bool)$a; }");
  test("kprobe:f { $a = (int64)true; $b = (int64)false; }");

  test("kprobe:f { $a = (bool)kstack; }", Error{ R"(
stdin:1:17-23: ERROR: Cannot cast from "kstack" to "bool"
kprobe:f { $a = (bool)kstack; }
                ~~~~~~
)" });

  test("kprobe:f { $a = (bool)pton(\"127.0.0.1\"); }", Error{ R"(
stdin:1:17-23: ERROR: Cannot cast from "uint8[4]" to "bool"
kprobe:f { $a = (bool)pton("127.0.0.1"); }
                ~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, field_access)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { $x = *(struct type1*)cpu; $x.field }");
  test(structs + "kprobe:f { @x = *(struct type1*)cpu; @x.field }");
  test("struct task_struct {int x;} kprobe:f { curtask->x }");
}

TEST_F(SemanticAnalyserTest, field_access_wrong_field)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { ((struct type1 *)cpu)->blah }", Error{});
  test(structs + "kprobe:f { $x = (struct type1 *)cpu; $x->blah }", Error{});
  test(structs + "kprobe:f { @x = (struct type1 *)cpu; @x->blah }", Error{});
}

TEST_F(SemanticAnalyserTest, field_access_wrong_expr)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { 1234->field }", Error{});
}

TEST_F(SemanticAnalyserTest, field_access_types)
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

TEST_F(SemanticAnalyserTest, field_access_pointer)
{
  std::string structs = "struct type1 { int field; }";
  test(structs + "kprobe:f { ((struct type1*)0)->field }");
  test(structs + "kprobe:f { ((struct type1*)0).field }", Error{});
  test(structs + "kprobe:f { *((struct type1*)0) }");
}

TEST_F(SemanticAnalyserTest, field_access_sub_struct)
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

TEST_F(SemanticAnalyserTest, field_access_is_internal)
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
    EXPECT_TRUE(map_assignment->map->value_type.is_internal);
    EXPECT_TRUE(var_assignment2->var()->var_type.is_internal);
  }
}

TEST_F(SemanticAnalyserTest, struct_as_map_key)
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
stdin:4:9-13: ERROR: Argument mismatch for @x: trying to access with arguments: 'struct B' when map expects arguments: 'struct A'
        @x[*((struct B *)0)] = 1;
        ~~~~
)" });
}

TEST_F(SemanticAnalyserTest, per_cpu_map_as_map_key)
{
  test("begin { @x = count(); @y[@x] = 1; }");
  test("begin { @x = sum(10); @y[@x] = 1; }");
  test("begin { @x = min(1); @y[@x] = 1; }");
  test("begin { @x = max(1); @y[@x] = 1; }");
  test("begin { @x = avg(1); @y[@x] = 1; }");

  test("begin { @x = hist(10); @y[@x] = 1; }", Error{ R"(
stdin:1:24-29: ERROR: hist_t cannot be used as a map key
begin { @x = hist(10); @y[@x] = 1; }
                       ~~~~~
)" });

  test("begin { @x = lhist(10, 0, 10, 1); @y[@x] = 1; }", Error{ R"(
stdin:1:35-40: ERROR: lhist_t cannot be used as a map key
begin { @x = lhist(10, 0, 10, 1); @y[@x] = 1; }
                                  ~~~~~
)" });

  test("begin { @x = tseries(10, 1s, 10); @y[@x] = 1; }", Error{ R"(
stdin:1:35-40: ERROR: tseries_t cannot be used as a map key
begin { @x = tseries(10, 1s, 10); @y[@x] = 1; }
                                  ~~~~~
)" });

  test("begin { @x = stats(10); @y[@x] = 1; }", Error{ R"(
stdin:1:25-30: ERROR: stats_t cannot be used as a map key
begin { @x = stats(10); @y[@x] = 1; }
                        ~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, probe_short_name)
{
  test("t:sched:sched_one { args }");
  test("k:f { pid }");
  test("kr:f { pid }");
  test("u:sh:f { 1 }");
  test("ur:sh:f { 1 }");
  test("p:hz:997 { 1 }");
  test("h:cache-references:1000000 { 1 }");
  test("s:faults:1000 { 1 }");
  test("i:s:1 { 1 }");
}

TEST_F(SemanticAnalyserTest, positional_parameters)
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

  auto ast = test("k:f { $1 }");
  auto *stmt =
      ast.root->probes.at(0)->block->stmts.at(0).as<ast::ExprStatement>();
  auto *pp = stmt->expr.as<ast::PositionalParameter>();
  EXPECT_EQ(CreateNone(), pp->type());

  bpftrace->add_param("0999");
  test("kprobe:f { printf(\"%d\", $4); }", Mock{ *bpftrace }, Error{});
}

TEST_F(SemanticAnalyserTest, c_macros)
{
  test("#define A 1\nkprobe:f { printf(\"%d\", A); }");
  test("#define A A\nkprobe:f { printf(\"%d\", A); }", Error{});
  test("enum { A = 1 }\n#define A A\nkprobe:f { printf(\"%d\", A); }");
}

TEST_F(SemanticAnalyserTest, enums)
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

TEST_F(SemanticAnalyserTest, enum_casts)
{
  test("enum named { a = 1, b } kprobe:f { print((enum named)1); }");
  // We can't detect this issue because the cast expr is not a literal
  test("enum named { a = 1, b } kprobe:f { $x = 3; print((enum named)$x); }");

  test("enum named { a = 1, b } kprobe:f { print((enum named)3); }", Error{ R"(
stdin:1:36-55: ERROR: Enum: named doesn't contain a variant value of 3
enum named { a = 1, b } kprobe:f { print((enum named)3); }
                                   ~~~~~~~~~~~~~~~~~~~
)" });

  test("enum Foo { a = 1, b } kprobe:f { print((enum Bar)1); }", Error{ R"(
stdin:1:34-51: ERROR: Unknown enum: Bar
enum Foo { a = 1, b } kprobe:f { print((enum Bar)1); }
                                 ~~~~~~~~~~~~~~~~~
)" });

  test("enum named { a = 1, b } kprobe:f { $a = \"str\"; print((enum "
       "named)$a); }",
       Error{ R"(
stdin:1:48-67: ERROR: Cannot cast from "string" to "enum named"
enum named { a = 1, b } kprobe:f { $a = "str"; print((enum named)$a); }
                                               ~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, signed_int_comparison_warnings)
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

TEST_F(SemanticAnalyserTest, string_comparison)
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

TEST_F(SemanticAnalyserTest, signed_int_arithmetic_warnings)
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

TEST_F(SemanticAnalyserTest, signed_int_division_warnings)
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

TEST_F(SemanticAnalyserTest, signed_int_modulo_warnings)
{
  std::string msg = "signed operands";
  test("kprobe:f { @x = -1; @y = @x % 1 }", Warning{ msg });
  test("kprobe:f { @x = (uint64)1; @y = @x % -1 }", Warning{ msg });

  // These should not trigger a warning. See above re: types.
  test("kprobe:f { @x = (uint64)1; @y = @x % 1 }", NoWarning{ msg });
  test("kprobe:f { @x = (uint64)1; @y = -(@x % 1) }", NoWarning{ msg });
}

TEST_F(SemanticAnalyserTest, map_as_lookup_table)
{
  // Initializing a map should not lead to usage issues
  test("begin { @[0] = \"abc\"; @[1] = \"def\" } "
       "kretprobe:f { printf(\"%s\\n\", @[(int64)retval])}");
}

TEST_F(SemanticAnalyserTest, cast_sign)
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

TEST_F(SemanticAnalyserTest, binop_bool_and_int)
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

TEST_F(SemanticAnalyserTest, binop_arithmetic)
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
    EXPECT_EQ(CreateUInt64(), varB->var()->var_type);
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

TEST_F(SemanticAnalyserTest, binop_compare)
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

TEST_F(SemanticAnalyserTest, int_cast_types)
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

TEST_F(SemanticAnalyserTest, int_cast_usage)
{
  test("kretprobe:f /(int32) retval < 0/ {}");
  test("kprobe:f /(int32) arg0 < 0/ {}");
  test("kprobe:f { @=sum((int32)arg0) }");
  test("kprobe:f { @=avg((int32)arg0) }");
  test("kprobe:f { @=avg((int32)arg0) }");

  test("kprobe:f { @=avg((int32)\"abc\") }", Error{});
}

TEST_F(SemanticAnalyserTest, intptr_cast_types)
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

TEST_F(SemanticAnalyserTest, intptr_cast_usage)
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

TEST_F(SemanticAnalyserTest, intarray_cast_types)
{
  test("kprobe:f { @ = (int8[8])1 }");
  test("kprobe:f { @ = (int16[4])1 }");
  test("kprobe:f { @ = (int32[2])1 }");
  test("kprobe:f { @ = (int64[1])1 }");
  test("kprobe:f { @ = (int8[4])(int32)1 }");
  test("kprobe:f { @ = (int8[2])(int16)1 }");
  test("kprobe:f { @ = (int8[1])(int8)1 }");
  test("kprobe:f { @ = (int8[])1 }");
  test("kprobe:f { @ = (uint8[8])1 }");
  test("kretprobe:f { @ = (int8[8])retval }");

  test("kprobe:f { @ = (int8[4])1 }", Error{});
  test("kprobe:f { @ = (int32[])(int16)1 }", Error{});
  test("kprobe:f { @ = (int8[6])\"hello\" }", Error{});

  test("struct Foo { int x; } kprobe:f { @ = (struct Foo [2])1 }", Error{});
}

TEST_F(SemanticAnalyserTest, bool_array_cast_types)
{
  test("kprobe:f { @ = (bool[8])1 }");
  test("kprobe:f { @ = (bool[4])(uint32)1 }");
  test("kprobe:f { @ = (bool[2])(uint16)1 }");

  test("kprobe:f { @ = (bool[4])1 }", Error{});
  test("kprobe:f { @ = (bool[64])1 }", Error{});
}

TEST_F(SemanticAnalyserTest, intarray_cast_usage)
{
  test("kprobe:f { $a=(int8[8])1; }");
  test("kprobe:f { @=(int8[8])1; }");
  test("kprobe:f { @[(int8[8])1] = 0; }");
  test("kprobe:f { if (((int8[8])1)[0] == 1) {} }");
}

TEST_F(SemanticAnalyserTest, intarray_to_int_cast)
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

TEST_F(SemanticAnalyserTest, mixed_int_var_assignments)
{
  test("kprobe:f { $x = (uint64)0; $x = (uint16)1; }");
  test("kprobe:f { $x = (int8)1; $x = 5; }");
  test("kprobe:f { $x = 1; $x = -1; }");
  test("kprobe:f { $x = (uint8)1; $x = 200; }");
  test("kprobe:f { $x = (int8)1; $x = -2; }");
  test("kprobe:f { $x = (int16)1; $x = 20000; }");
  // We'd like the below to work, but
  // blocked on #3518. TLDR: It looks like a
  // literal and thus amenable to static
  // "fits into" checks. But it's not, the
  // parser has actually desugared it to:
  //    AssignVarStatement(Variable,
  //    Binop(Variable, Integer(1)))
  // test("kprobe:f { $x = (uint32)5; $x +=
  // 1; }");

  test("kprobe:f { $x = (uint8)1; $x = -1; }", Error{ R"(
stdin:1:27-34: ERROR: Type mismatch for $x: trying to assign value of type 'int64' when variable already contains a value of type 'uint8'
kprobe:f { $x = (uint8)1; $x = -1; }
                          ~~~~~~~
)" });
  test("kprobe:f { $x = (int16)1; $x = 100000; }", Error{ R"(
stdin:1:27-38: ERROR: Type mismatch for $x: trying to assign value '100000' which does not fit into the variable of type 'int16'
kprobe:f { $x = (int16)1; $x = 100000; }
                          ~~~~~~~~~~~
)" });
  test("kprobe:f { $a = (uint16)5; $x = (uint8)0; $x = $a; }", Error{ R"(
stdin:1:43-50: ERROR: Integer size mismatch. Assignment type 'uint16' is larger than the variable type 'uint8'.
kprobe:f { $a = (uint16)5; $x = (uint8)0; $x = $a; }
                                          ~~~~~~~
)" });
  test("kprobe:f { $a = (int8)-1; $x = (uint8)0; $x = $a; }", Error{ R"(
stdin:1:42-49: ERROR: Type mismatch for $x: trying to assign value of type 'int8' when variable already contains a value of type 'uint8'
kprobe:f { $a = (int8)-1; $x = (uint8)0; $x = $a; }
                                         ~~~~~~~
)" });
  test("kprobe:f { $x = -1; $x = 10223372036854775807; }", Error{ R"(
stdin:1:21-46: ERROR: Type mismatch for $x: trying to assign value '10223372036854775807' which does not fit into the variable of type 'int64'
kprobe:f { $x = -1; $x = 10223372036854775807; }
                    ~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { $x = (0, (uint32)123); $x = (0, (int32)-123); }", Error{ R"(
stdin:1:35-56: ERROR: Type mismatch for $x: trying to assign value of type '(int64,int32)' when variable already contains a value of type '(int64,uint32)'
kprobe:f { $x = (0, (uint32)123); $x = (0, (int32)-123); }
                                  ~~~~~~~~~~~~~~~~~~~~~
)" });
  test("begin { $x = (uint8)1; $x = 5; }", ExpectedAST{ R"(
Program
 begin
  =
   variable: $x :: [uint8]
   (uint8)
    int: 1 :: [int64]
  =
   variable: $x :: [uint8]
   (uint8)
    int: 5 :: [int64]
)" });
  test("begin { $x = (int8)1; $x = 5; }", ExpectedAST{ R"(
Program
 begin
  =
   variable: $x :: [int8]
   (int8)
    int: 1 :: [int64]
  =
   variable: $x :: [int8]
   (int8)
    int: 5 :: [int64]
)" });
}

TEST_F(SemanticAnalyserTest, mixed_int_like_map_assignments)
{
  // Map values are automatically promoted to 64bit ints
  test("kprobe:f { @x = (uint64)0; @x = (uint16)1; }");
  test("kprobe:f { @x = (int8)1; @x = 5; }");
  test("kprobe:f { @x = 1; @x = -1; }");
  test("kprobe:f { @x = (int8)1; @x = -2; }");
  test("kprobe:f { @x = (int16)1; @x = 20000; }");
  test("kprobe:f { @x = (uint16)1; @x = 200; }");
  test("kprobe:f { @x = (uint16)1; @x = 10223372036854775807; }");
  test("kprobe:f { @x = 1; @x = 9223372036854775807; }");
  test("kprobe:f { @x = 1; @x = -9223372036854775808; }");

  test("kprobe:f { @x = (uint8)1; @x = -1; }", Error{ R"(
stdin:1:27-34: ERROR: Type mismatch for @x: trying to assign value of type 'int64' when map already contains a value of type 'uint64'
kprobe:f { @x = (uint8)1; @x = -1; }
                          ~~~~~~~
)" });

  test("kprobe:f { @x = 1; @x = 10223372036854775807; }", Error{ R"(
stdin:1:20-45: ERROR: Type mismatch for @x: trying to assign value '10223372036854775807' which does not fit into the map of type 'int64'
kprobe:f { @x = 1; @x = 10223372036854775807; }
                   ~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { @x = sum((uint64)1); @x = sum(-1); }", Error{ R"(
stdin:1:38-45: ERROR: Type mismatch for @x: trying to assign value of type 'sum_t' when map already contains a value of type 'usum_t'
kprobe:f { @x = sum((uint64)1); @x = sum(-1); }
                                     ~~~~~~~
)" });
  test("kprobe:f { @x = min((uint64)1); @x = min(-1); }", Error{ R"(
stdin:1:38-45: ERROR: Type mismatch for @x: trying to assign value of type 'min_t' when map already contains a value of type 'umin_t'
kprobe:f { @x = min((uint64)1); @x = min(-1); }
                                     ~~~~~~~
)" });
  test("kprobe:f { @x = max((uint64)1); @x = max(-1); }", Error{ R"(
stdin:1:38-45: ERROR: Type mismatch for @x: trying to assign value of type 'max_t' when map already contains a value of type 'umax_t'
kprobe:f { @x = max((uint64)1); @x = max(-1); }
                                     ~~~~~~~
)" });
  test("kprobe:f { @x = avg((uint64)1); @x = avg(-1); }", Error{ R"(
stdin:1:38-45: ERROR: Type mismatch for @x: trying to assign value of type 'avg_t' when map already contains a value of type 'uavg_t'
kprobe:f { @x = avg((uint64)1); @x = avg(-1); }
                                     ~~~~~~~
)" });
  test("kprobe:f { @x = stats((uint64)1); @x = stats(-1); }", Error{ R"(
stdin:1:40-49: ERROR: Type mismatch for @x: trying to assign value of type 'stats_t' when map already contains a value of type 'ustats_t'
kprobe:f { @x = stats((uint64)1); @x = stats(-1); }
                                       ~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, mixed_int_map_access)
{
  // Map keys are automatically promoted to 64bit ints
  test("kprobe:f { @x[1] = 1; @x[(int16)2] }");
  test("kprobe:f { @x[(int16)1] = 1; @x[2] }");
  test("kprobe:f { @x[(int16)1] = 1; @x[(int64)2] }");
  test("kprobe:f { @x[(uint16)1] = 1; @x[(uint64)2] }");
  test("kprobe:f { @x[(uint64)1] = 1; @x[(uint16)2] }");
  test("kprobe:f { @x[(uint16)1] = 1; @x[2] }");
  test("kprobe:f { @x[(uint16)1] = 1; @x[10223372036854775807] }");
  test("kprobe:f { @x[1] = 1; @x[9223372036854775807] }");
  test("kprobe:f { @x[1] = 1; @x[-9223372036854775808] }");

  test("kprobe:f { @x[1] = 1; @x[10223372036854775807] }", Error{ R"(
stdin:1:23-46: ERROR: Argument mismatch for @x: trying to access with argument '10223372036854775807' which does not fit into the map of key type 'int64'
kprobe:f { @x[1] = 1; @x[10223372036854775807] }
                      ~~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:f { @x[(uint64)1] = 1; @x[-1] }", Error{ R"(
stdin:1:31-35: ERROR: Argument mismatch for @x: trying to access with arguments: 'int64' when map expects arguments: 'uint64'
kprobe:f { @x[(uint64)1] = 1; @x[-1] }
                              ~~~~
)" });
  test("kretprobe:f { @x[1] = 1; @x[(uint64)1] }", Error{ R"(
ERROR: Argument mismatch for @x: trying to access with arguments: 'uint64' when map expects arguments: 'int64'
)" });
}

TEST_F(SemanticAnalyserTest, signal)
{
  // int literals
  test("k:f { signal(1); }", UnsafeMode::Enable);
  test("kr:f { signal(1); }", UnsafeMode::Enable);
  test("u:/bin/sh:f { signal(11); }", UnsafeMode::Enable);
  test("ur:/bin/sh:f { signal(11); }", UnsafeMode::Enable);
  test("p:hz:1 { signal(1); }", UnsafeMode::Enable);

  // vars
  test("k:f { @=1; signal(@); }", UnsafeMode::Enable);
  test("k:f { @=1; signal((int32)arg0); }", UnsafeMode::Enable);

  // String
  test("k:f { signal(\"KILL\"); }", UnsafeMode::Enable);
  test("k:f { signal(\"SIGKILL\"); }", UnsafeMode::Enable);

  // Not allowed for:
  test("hardware:pcm:1000 { signal(1); }", UnsafeMode::Enable, Error{});
  test("software:pcm:1000 { signal(1); }", UnsafeMode::Enable, Error{});
  test("begin { signal(1); }", UnsafeMode::Enable, Error{});
  test("end { signal(1); }", UnsafeMode::Enable, Error{});
  test("i:s:1 { signal(1); }", UnsafeMode::Enable, Error{});

  // invalid signals
  test("k:f { signal(0); }", UnsafeMode::Enable, Error{});
  test("k:f { signal(-100); }", UnsafeMode::Enable, Error{});
  test("k:f { signal(100); }", UnsafeMode::Enable, Error{});
  test("k:f { signal(\"SIGABC\"); }", UnsafeMode::Enable, Error{});
  test("k:f { signal(\"ABC\"); }", UnsafeMode::Enable, Error{});

  // Missing kernel support
  test("k:f { signal(1) }", UnsafeMode::Enable, NoFeatures::Enable, Error{});
  test("k:f { signal(\"KILL\"); }",
       UnsafeMode::Enable,
       NoFeatures::Enable,
       Error{});

  // Positional parameter
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("1");
  bpftrace->add_param("hello");
  test("k:f { signal($1) }", UnsafeMode::Enable, Mock{ *bpftrace });
  test("k:f { signal($2) }", UnsafeMode::Enable, Mock{ *bpftrace }, Error{});
}

TEST_F(SemanticAnalyserTest, strncmp)
{
  // Test strncmp builtin
  test(R"(i:s:1 { $a = "bar"; strncmp("foo", $a, 1) })");
  test(R"(i:s:1 { strncmp("foo", "bar", 1) })");
  test("i:s:1 { strncmp(1) }", Error{});
  test("i:s:1 { strncmp(1,1,1) }", Error{});
  test("i:s:1 { strncmp(\"a\",1,1) }", Error{});
  test(R"(i:s:1 { strncmp("a","a",-1) })", Error{});
  test(R"(i:s:1 { strncmp("a","a","foo") })", Error{});
}

TEST_F(SemanticAnalyserTest, strncmp_posparam)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("1");
  bpftrace->add_param("hello");
  test(R"(i:s:1 { strncmp("foo", "bar", $1) })", Mock{ *bpftrace });
  test(R"(i:s:1 { strncmp("foo", "bar", $2) })", Mock{ *bpftrace }, Error{});
}

TEST_F(SemanticAnalyserTest, strcontains)
{
  // Test strcontains builtin
  test(R"(i:s:1 { $a = "bar"; strcontains("foo", $a) })");
  test(R"(i:s:1 { strcontains("foo", "bar") })");
  test("i:s:1 { strcontains(1) }", Error{});
  test("i:s:1 { strcontains(1,1) }", Error{});
  test("i:s:1 { strcontains(\"a\",1) }", Error{});
}

TEST_F(SemanticAnalyserTest, strcontains_large_warnings)
{
  test("k:f { $s1 = str(arg0); $s2 = str(arg1); $x = strcontains($s1, $s2) }",
       Warning{ "both string sizes is larger" });

  test("k:f { $s1 = str(arg0, 64); $s2 = str(arg1, 16); $x = strcontains($s1, "
       "$s2) }",
       NoWarning{ "both string sizes is larger" });

  auto bpftrace = get_mock_bpftrace();
  bpftrace->config_->max_strlen = 16;

  test("k:f { $s1 = str(arg0); $s2 = str(arg1); $x = strcontains($s1, $s2) }",
       Mock{ *bpftrace },
       NoWarning{ "both string sizes is larger" });
}

TEST_F(SemanticAnalyserTest, strcontains_posparam)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("hello");
  test("i:s:1 { strcontains(\"foo\", str($1)) }", Mock{ *bpftrace });
}

TEST_F(SemanticAnalyserTest, override)
{
  // literals
  test("k:f { override(-1); }", UnsafeMode::Enable);

  // variables
  test("k:f { override(arg0); }", UnsafeMode::Enable);

  // Probe types
  test("kr:f { override(-1); }", UnsafeMode::Enable, Error{});
  test("u:/bin/sh:f { override(-1); }", UnsafeMode::Enable, Error{});
  test("t:syscalls:sys_enter_openat { override(-1); }",
       UnsafeMode::Enable,
       Error{});
  test("i:s:1 { override(-1); }", UnsafeMode::Enable, Error{});
  test("p:hz:1 { override(-1); }", UnsafeMode::Enable, Error{});
}

TEST_F(SemanticAnalyserTest, unwatch)
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

TEST_F(SemanticAnalyserTest, struct_member_keywords)
{
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

TEST_F(SemanticAnalyserTest, jumps)
{
  test("i:s:1 { return; }");
  // must be used in loops
  test("i:s:1 { break; }", Error{});
  test("i:s:1 { continue; }", Error{});
}

TEST_F(SemanticAnalyserTest, while_loop)
{
  test("i:s:1 { $a = 1; while ($a < 10) { $a++ }}");
  test("i:s:1 { $a = 1; while (1) { if($a > 50) { break } $a++ }}");
  test("i:s:1 { $a = 1; while ($a < 10) { $a++ }}");
  test("i:s:1 { $a = 1; while (1) { if($a > 50) { break } $a++ }}");
  test("i:s:1 { $a = 1; while (1) { if($a > 50) { return } $a++ }}");
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

  test("i:s:1 { $a = 1; while ($a < 10) { break; $a++ }}",
       Warning{ "code after a 'break'" });
  test("i:s:1 { $a = 1; while ($a < 10) { continue; $a++ }}",
       Warning{ "code after a 'continue'" });
  test("i:s:1 { $a = 1; while ($a < 10) { return; $a++ }}",
       Warning{ "code after a 'return'" });
  test("i:s:1 { $a = 1; while ($a < 10) { @=$a++; print(@); }}",
       Warning{ "'print()' in a loop" });
}

TEST_F(SemanticAnalyserTest, builtin_args)
{
  auto bpftrace = get_mock_bpftrace();
  test("t:sched:sched_one { args.common_field }", Mock{ *bpftrace });
  test("t:sched:sched_two { args.common_field }", Mock{ *bpftrace });
  test("t:sched:sched_one,t:sched:sched_two { args.common_field }",
       Mock{ *bpftrace });
  test("t:sched:sched_* { args.common_field }", Mock{ *bpftrace });
  test("t:sched:sched_one { args.not_a_field }", Mock{ *bpftrace }, Error{});
  // Backwards compatibility
  test("t:sched:sched_one { args->common_field }", Mock{ *bpftrace });
}

TEST_F(SemanticAnalyserTest, type_ctx)
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

  SizedType chartype;
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
  EXPECT_TRUE(unop->result_type.IsRecordTy());
  fieldaccess = unop->expr.as<ast::FieldAccess>();
  EXPECT_TRUE(fieldaccess->field_type.IsPtrTy());
  unop = fieldaccess->expr.as<ast::Unop>();
  EXPECT_TRUE(unop->result_type.IsCtxAccess());
  var = unop->expr.as<ast::Variable>();
  EXPECT_TRUE(var->var_type.IsPtrTy());

  test("k:f, kr:f { @ = (uint64)ctx; }");
  test("k:f, i:s:1 { @ = (uint64)ctx; }", Error{});
  test("t:sched:sched_one { @ = (uint64)ctx; }", Error{});
}

TEST_F(SemanticAnalyserTest, double_pointer_basic)
{
  test(R"_(begin { $pp = (int8 **)0; $p = *$pp; $val = *$p; })_");
  test(R"_(begin { $pp = (int8 **)0; $val = **$pp; })_");

  const std::string structs = "struct Foo { int x; }";
  test(structs + R"_(begin { $pp = (struct Foo **)0; $val = (*$pp)->x; })_");
}

TEST_F(SemanticAnalyserTest, double_pointer_int)
{
  auto ast = test("kprobe:f { $pp = (int8 **)1; $p = *$pp; $val = *$p; }");
  auto &stmts = ast.root->probes.at(0)->block->stmts;

  // $pp = (int8 **)1;
  auto *assignment = stmts.at(0).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsPtrTy());
  ASSERT_TRUE(assignment->var()->var_type.GetPointeeTy()->IsPtrTy());
  ASSERT_TRUE(
      assignment->var()->var_type.GetPointeeTy()->GetPointeeTy()->IsIntTy());
  EXPECT_EQ(assignment->var()
                ->var_type.GetPointeeTy()
                ->GetPointeeTy()
                ->GetIntBitWidth(),
            8ULL);

  // $p = *$pp;
  assignment = stmts.at(1).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsPtrTy());
  ASSERT_TRUE(assignment->var()->var_type.GetPointeeTy()->IsIntTy());
  EXPECT_EQ(assignment->var()->var_type.GetPointeeTy()->GetIntBitWidth(), 8ULL);

  // $val = *$p;
  assignment = stmts.at(2).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsIntTy());
  EXPECT_EQ(assignment->var()->var_type.GetIntBitWidth(), 8ULL);
}

TEST_F(SemanticAnalyserTest, double_pointer_struct)
{
  auto ast = test(
      "struct Foo { char x; long y; }"
      "kprobe:f { $pp = (struct Foo **)1; $p = *$pp; $val = $p->x; }");
  auto &stmts = ast.root->probes.at(0)->block->stmts;

  // $pp = (struct Foo **)1;
  auto *assignment = stmts.at(0).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsPtrTy());
  ASSERT_TRUE(assignment->var()->var_type.GetPointeeTy()->IsPtrTy());
  ASSERT_TRUE(
      assignment->var()->var_type.GetPointeeTy()->GetPointeeTy()->IsRecordTy());
  EXPECT_EQ(
      assignment->var()->var_type.GetPointeeTy()->GetPointeeTy()->GetName(),
      "struct Foo");

  // $p = *$pp;
  assignment = stmts.at(1).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsPtrTy());
  ASSERT_TRUE(assignment->var()->var_type.GetPointeeTy()->IsRecordTy());
  EXPECT_EQ(assignment->var()->var_type.GetPointeeTy()->GetName(),
            "struct Foo");

  // $val = $p->x;
  assignment = stmts.at(2).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsIntTy());
  EXPECT_EQ(assignment->var()->var_type.GetIntBitWidth(), 8ULL);
}

TEST_F(SemanticAnalyserTest, pointer_arith)
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

TEST_F(SemanticAnalyserTest, pointer_compare)
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
TEST_F(SemanticAnalyserTest, tuple)
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

  test(R"(begin { $t = (1, (int32)2); $t = (2, (int64)3); })", Error{ R"(
stdin:1:29-47: ERROR: Type mismatch for $t: trying to assign value of type '(int64,int64)' when variable already contains a value of type '(int64,int32)'
begin { $t = (1, (int32)2); $t = (2, (int64)3); }
                            ~~~~~~~~~~~~~~~~~~
)" });

  test(R"(struct task_struct { int x; } begin { $t = (1, curtask); })");
  test(R"(struct task_struct { int x[4]; } begin { $t = (1, curtask->x); })");

  test(R"(begin { $t = (1, 2); $t = (4, "other"); })", Error{});
  test(R"(begin { $t = (1, 2); $t = 5; })", Error{});
  test(R"(begin { $t = (1, count()) })", Error{});

  test(R"(begin { @t = (1, 2); @t = (4, "other"); })", Error{});
  test(R"(begin { @t = (1, 2); @t = 5; })", Error{});
  test(R"(begin { @t = (1, count()) })", Error{});

  test(R"(begin { $t = (1, (2, 3)); $t = (4, ((int8)5, 6)); })");

  test(R"(begin { $t = (1, ((int8)2, 3)); $t = (4, (5, 6)); })", Error{ R"(
stdin:1:33-49: ERROR: Type mismatch for $t: trying to assign value of type '(int64,(int64,int64))' when variable already contains a value of type '(int64,(int8,int64))'
begin { $t = (1, ((int8)2, 3)); $t = (4, (5, 6)); }
                                ~~~~~~~~~~~~~~~~
)" });

  test(R"(begin { $t = ((uint8)1, (2, 3)); $t = (4, ((int8)5, 6)); })",
       Error{ R"(
stdin:1:34-56: ERROR: Type mismatch for $t: trying to assign value of type '(int64,(int8,int64))' when variable already contains a value of type '(uint8,(int64,int64))'
begin { $t = ((uint8)1, (2, 3)); $t = (4, ((int8)5, 6)); }
                                 ~~~~~~~~~~~~~~~~~~~~~~
)" });

  test(R"(begin { @t = (1, 2, "hi"); @t = (3, 4, "hellolongstr"); })");
  test(R"(begin { $t = (1, ("hi", 2)); $t = (3, ("hellolongstr", 4)); })");

  test("begin { @x[1] = hist(10); $y = (1, @x[1]); }", Error{ R"(
stdin:1:36-41: ERROR: Map type hist_t cannot exist inside a tuple.
begin { @x[1] = hist(10); $y = (1, @x[1]); }
                                   ~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, tuple_indexing)
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
TEST_F(SemanticAnalyserTest, tuple_assign_var)
{
  SizedType ty = CreateTuple(
      Struct::CreateTuple({ CreateInt64(), CreateString(6) }));
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
TEST_F(SemanticAnalyserTest, tuple_assign_map)
{
  auto ast = test(R"(begin { @ = (1, 3, 3, 7); @ = (0, 0, 0, 0); })");
  auto &stmts = ast.root->probes.at(0)->block->stmts;

  // $t = (1, 3, 3, 7);
  auto *assignment = stmts.at(0).as<ast::AssignMapStatement>();
  SizedType ty = CreateTuple(Struct::CreateTuple(
      { CreateInt64(), CreateInt64(), CreateInt64(), CreateInt64() }));
  EXPECT_EQ(ty, assignment->map->value_type);

  // $t = (0, 0, 0, 0);
  assignment = stmts.at(1).as<ast::AssignMapStatement>();
  ty = CreateTuple(Struct::CreateTuple(
      { CreateInt64(), CreateInt64(), CreateInt64(), CreateInt64() }));
  EXPECT_EQ(ty, assignment->map->value_type);
}

// More in depth inspection of AST
TEST_F(SemanticAnalyserTest, tuple_nested)
{
  SizedType ty_inner = CreateTuple(
      Struct::CreateTuple({ CreateInt64(), CreateInt64() }));
  SizedType ty = CreateTuple(Struct::CreateTuple({ CreateInt64(), ty_inner }));
  auto ast = test(R"(begin { $t = (1,(1,2)); })");
  auto &stmts = ast.root->probes.at(0)->block->stmts;

  // $t = (1, "str");
  auto *assignment = stmts.at(0).as<ast::AssignVarStatement>();
  EXPECT_EQ(ty, assignment->var()->var_type);
}

TEST_F(SemanticAnalyserTest, multi_pass_type_inference_zero_size_int)
{
  // The first pass on processing the Unop
  // does not have enough information to
  // figure out size of `@i` yet. The
  // analyzer figures out the size after
  // seeing the `@i++`. On the second pass
  // the correct size is determined.
  test("begin { if (!@i) { @i++; } }");
}

TEST_F(SemanticAnalyserTest, call_kptr_uptr)
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

TEST_F(SemanticAnalyserTest, call_path)
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

TEST_F(SemanticAnalyserTest, call_offsetof)
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
stdin:1:71-99: ERROR: 'struct Bar *' is not a record type.
struct Foo { struct Bar { int a; } *bar; }               begin { @x = offsetof(struct Foo, bar.a); }
                                                                      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Not exist (sub)field
  test("struct Foo { int x; long l; char c; } \
              begin { @x = offsetof(struct Foo, __notexistfield__); }",
       Error{ R"(
stdin:1:66-106: ERROR: 'struct Foo' has no field named '__notexistfield__'
struct Foo { int x; long l; char c; }               begin { @x = offsetof(struct Foo, __notexistfield__); }
                                                                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("struct Foo { struct Bar { int a; } bar; } \
              begin { @x = offsetof(struct Foo, bar.__notexist_subfield__); }",
       Error{ R"(
stdin:1:70-118: ERROR: 'struct Bar' has no field named '__notexist_subfield__'
struct Foo { struct Bar { int a; } bar; }               begin { @x = offsetof(struct Foo, bar.__notexist_subfield__); }
                                                                     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  // Not exist record
  test("begin { @x = offsetof(__passident__, x); }", Error{});
  test("begin { @x = offsetof(__passident__, x.y.z); }", Error{});
  test("begin { @x = offsetof(struct __notexiststruct__, x); }", Error{});
  test("begin { @x = offsetof(struct __notexiststruct__, x.y.z); }", Error{});
}

TEST_F(SemanticAnalyserTest, int_ident)
{
  test("begin { sizeof(int32) }");
}

TEST_F(SemanticAnalyserTest, tracepoint_common_field)
{
  test("tracepoint:file:filename { args.filename }");
  test("tracepoint:file:filename { args.common_field }", Error{});
}

TEST_F(SemanticAnalyserTest, string_size)
{
  // Size of the variable should be the size of the larger string (incl. null)
  auto ast = test(R"(begin { $x = "hi"; $x = "hello"; })");
  auto stmt = ast.root->probes.at(0)->block->stmts.at(0);
  auto *var_assign = stmt.as<ast::AssignVarStatement>();
  ASSERT_TRUE(var_assign->var()->var_type.IsStringTy());
  ASSERT_EQ(var_assign->var()->var_type.GetSize(), 6UL);

  ast = test(R"(k:f1 {@ = "hi";} k:f2 {@ = "hello";})");
  stmt = ast.root->probes.at(0)->block->stmts.at(0);
  auto *map_assign = stmt.as<ast::AssignMapStatement>();
  ASSERT_TRUE(map_assign->map->value_type.IsStringTy());
  ASSERT_EQ(map_assign->map->value_type.GetSize(), 6UL);

  ast = test(R"(k:f1 {@["hi"] = 0;} k:f2 {@["hello"] = 1;})");
  stmt = ast.root->probes.at(0)->block->stmts.at(0);
  map_assign = stmt.as<ast::AssignMapStatement>();
  ASSERT_TRUE(map_assign->key.type().IsStringTy());
  ASSERT_EQ(map_assign->key.type().GetSize(), 3UL);
  ASSERT_EQ(map_assign->map->key_type.GetSize(), 6UL);

  ast = test(R"(k:f1 {@["hi", 0] = 0;} k:f2 {@["hello", 1] = 1;})");
  stmt = ast.root->probes.at(0)->block->stmts.at(0);
  map_assign = stmt.as<ast::AssignMapStatement>();
  ASSERT_TRUE(map_assign->key.type().IsTupleTy());
  ASSERT_TRUE(map_assign->key.type().GetField(0).type.IsStringTy());
  ASSERT_EQ(map_assign->key.type().GetField(0).type.GetSize(), 3UL);
  ASSERT_EQ(map_assign->map->key_type.GetField(0).type.GetSize(), 6UL);
  ASSERT_EQ(map_assign->key.type().GetSize(), 16UL);
  ASSERT_EQ(map_assign->map->key_type.GetSize(), 16UL);

  ast = test(R"(k:f1 {$x = ("hello", 0);} k:f2 {$x = ("hi", 0); })");
  stmt = ast.root->probes.at(0)->block->stmts.at(0);
  var_assign = stmt.as<ast::AssignVarStatement>();
  ASSERT_TRUE(var_assign->var()->var_type.IsTupleTy());
  ASSERT_TRUE(var_assign->var()->var_type.GetField(0).type.IsStringTy());
  ASSERT_EQ(var_assign->var()->var_type.GetSize(),
            16UL); // tuples are not
                   // packed
  ASSERT_EQ(var_assign->var()->var_type.GetField(0).type.GetSize(), 6UL);
}

TEST_F(SemanticAnalyserTest, call_nsecs)
{
  test("begin { $ns = nsecs(); }");
  test("begin { $ns = nsecs(monotonic); }");
  test("begin { $ns = nsecs(boot); }");
  test("begin { $ns = nsecs(tai); }");
  test("begin { $ns = nsecs(sw_tai); }");
  test("begin { $ns = nsecs(xxx); }", Error{ R"(
stdin:1:15-24: ERROR: Invalid timestamp mode: xxx
begin { $ns = nsecs(xxx); }
              ~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, call_pid_tid)
{
  test("begin { $i = tid(); }");
  test("begin { $i = pid(); }");
  test("begin { $i = tid(curr_ns); }");
  test("begin { $i = pid(curr_ns); }");
  test("begin { $i = tid(init); }");
  test("begin { $i = pid(init); }");
  test("begin { $i = tid(xxx); }", Error{ R"(
stdin:1:14-21: ERROR: Invalid PID namespace mode: xxx (expects: curr_ns or init)
begin { $i = tid(xxx); }
             ~~~~~~~
)" });
  test("begin { $i = tid(1); }", Error{ R"(
stdin:1:14-20: ERROR: tid() only supports curr_ns and init as the argument (int provided)
begin { $i = tid(1); }
             ~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, config)
{
  test("config = { BPFTRACE_MAX_AST_NODES=1 } "
       "begin { $ns = nsecs(); }");
  test("config = { BPFTRACE_MAX_AST_NODES=1; stack_mode=raw } "
       "begin { $ns = nsecs(); }");
}

TEST_F(SemanticAnalyserTest, subprog_return)
{
  test("fn f(): void { return; }");
  test("fn f(): int64 { return 1; }");

  // Error location is incorrect: #3063
  test("fn f(): void { return 1; }", Error{ R"(
stdin:1:17-25: ERROR: Function f is of type void, cannot return int64
fn f(): void { return 1; }
                ~~~~~~~~
)" });
  // Error location is incorrect: #3063
  test("fn f(): int64 { return; }", Error{ R"(
stdin:1:18-24: ERROR: Function f is of type int64, cannot return void
fn f(): int64 { return; }
                 ~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, subprog_arguments)
{
  test("fn f($a : int64): int64 { return $a; }");
  // Error location is incorrect: #3063
  test("fn f($a : int64): string { return $a; }", Error{ R"(
stdin:1:30-39: ERROR: Function f is of type string, cannot return int64
fn f($a : int64): string { return $a; }
                             ~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, subprog_map)
{
  test("fn f(): void { @a = 0; }");
  test("fn f(): int64 { @a = 0; return @a + 1; }");
  test("fn f(): void { @a[0] = 0; }");
  test("fn f(): int64 { @a[0] = 0; return @a[0] + 1; }");
}

TEST_F(SemanticAnalyserTest, subprog_builtin)
{
  test("fn f(): void { print(\"Hello world\"); }");
  test("fn f(): uint64 { return sizeof(int64); }");
  test("fn f(): uint64 { return nsecs; }");
}

TEST_F(SemanticAnalyserTest, subprog_builtin_disallowed)
{
  // Error location is incorrect: #3063
  test("fn f(): int64 { return func; }", Error{ R"(
ERROR: Builtin __builtin_func not supported outside probe
)" });
}

class SemanticAnalyserBTFTest : public SemanticAnalyserHarness,
                                public test_btf {};

TEST_F(SemanticAnalyserBTFTest, fentry)
{
  test("fentry:func_1 { 1 }");
  test("fexit:func_1 { 1 }");
  test("fentry:func_1 { $x = args.a; $y = args.foo1; $z = args.foo2->f.a; }");
  test("fexit:func_1 { $x = retval; }");
  test("fentry:vmlinux:func_1 { 1 }");
  test("fentry:*:func_1 { 1 }");

  test("fexit:func_1 { $x = args.foo; }", Error{ R"(
stdin:1:21-26: ERROR: Can't find function parameter foo
fexit:func_1 { $x = args.foo; }
                    ~~~~~
)" });
  test("fexit:func_1 { $x = args; }");
  test("fentry:func_1 { @ = args; }");
  test("fentry:func_1 { @[args] = 1; }");
  // reg() is not available in fentry
  if (arch::Host::Machine == arch::Machine::X86_64) {
    test("fentry:func_1 { reg(\"ip\") }", Error{ R"(
stdin:1:17-26: ERROR: reg can not be used with "fentry" probes
fentry:func_1 { reg("ip") }
                ~~~~~~~~~
)" });
    test("fexit:func_1 { reg(\"ip\") }", Error{ R"(
stdin:1:16-25: ERROR: reg can not be used with "fexit" probes
fexit:func_1 { reg("ip") }
               ~~~~~~~~~
)" });
  }
  // Backwards compatibility
  test("fentry:func_1 { $x = args->a; }");
}

TEST_F(SemanticAnalyserBTFTest, short_name)
{
  test("f:func_1 { 1 }");
  test("fr:func_1 { 1 }");
}

TEST_F(SemanticAnalyserBTFTest, call_path)
{
  test("fentry:func_1 { @k = path( args.foo1 ) }");
  test("fexit:func_1 { @k = path( retval->foo1 ) }");
  test("fentry:func_1 { path(args.foo1, 16); }");
  test("fentry:func_1 { path(args.foo1, \"Na\"); }", Error{});
  test("fentry:func_1 { path(args.foo1, -1); }", Error{});
}

TEST_F(SemanticAnalyserBTFTest, call_skb_output)
{
  test("fentry:func_1 { $ret = skboutput(\"one.pcap\", args.foo1, 1500, 0); "
       "}");
  test("fexit:func_1 { $ret = skboutput(\"one.pcap\", args.foo1, 1500, 0); }");

  test("fentry:func_1 { $ret = "
       "skboutput(); }",
       Error{ R"(
stdin:1:24-35: ERROR: skboutput() requires 4 arguments (0 provided)
fentry:func_1 { $ret = skboutput(); }
                       ~~~~~~~~~~~
)" });
  test("fentry:func_1 { $ret = skboutput(\"one.pcap\"); }", Error{ R"(
stdin:1:24-45: ERROR: skboutput() requires 4 arguments (1 provided)
fentry:func_1 { $ret = skboutput("one.pcap"); }
                       ~~~~~~~~~~~~~~~~~~~~~
)" });
  test("fentry:func_1 { $ret = skboutput(\"one.pcap\", args.foo1); }",
       Error{ R"(
stdin:1:24-56: ERROR: skboutput() requires 4 arguments (2 provided)
fentry:func_1 { $ret = skboutput("one.pcap", args.foo1); }
                       ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("fentry:func_1 { $ret = skboutput(\"one.pcap\", args.foo1, 1500); }",
       Error{ R"(
stdin:1:24-62: ERROR: skboutput() requires 4 arguments (3 provided)
fentry:func_1 { $ret = skboutput("one.pcap", args.foo1, 1500); }
                       ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:func_1 { $ret = skboutput(\"one.pcap\", arg1, 1500, 0); }",
       Error{ R"(
stdin:1:24-60: ERROR: skboutput can not be used with "kprobe" probes
kprobe:func_1 { $ret = skboutput("one.pcap", arg1, 1500, 0); }
                       ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserBTFTest, call_percpu_kaddr)
{
  test("kprobe:f { percpu_kaddr(\"process_counts\"); }");
  test("kprobe:f { percpu_kaddr(\"process_counts\", 0); }");
  test("kprobe:f { @x = percpu_kaddr(\"process_counts\"); }");
  test("kprobe:f { @x = percpu_kaddr(\"process_counts\", 0); }");
  test("kprobe:f { percpu_kaddr(); }", Error{});
  test("kprobe:f { percpu_kaddr(0); }", Error{});

  test("kprobe:f { percpu_kaddr(\"nonsense\"); }",
       UnsafeMode::Enable,
       Error{ R"(
stdin:1:12-36: ERROR: Could not resolve variable "nonsense" from BTF
kprobe:f { percpu_kaddr("nonsense"); }
           ~~~~~~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserBTFTest, call_socket_cookie)
{
  test("fentry:tcp_shutdown { $ret = socket_cookie(args.sk); }");
  test("fexit:tcp_shutdown { $ret = socket_cookie(args.sk); }");

  test("fentry:tcp_shutdown { $ret = socket_cookie(); }", Error{ R"(
stdin:1:30-45: ERROR: socket_cookie() requires one argument (0 provided)
fentry:tcp_shutdown { $ret = socket_cookie(); }
                             ~~~~~~~~~~~~~~~
)" });
  test("fentry:tcp_shutdown { $ret = socket_cookie(args.how); }", Error{ R"(
stdin:1:30-53: ERROR: socket_cookie() only supports 'struct sock *' as the argument (int provided)
fentry:tcp_shutdown { $ret = socket_cookie(args.how); }
                             ~~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("fentry:func_1 { $ret = socket_cookie(args.foo1); }", Error{ R"(
stdin:1:24-48: ERROR: socket_cookie() only supports 'struct sock *' as the argument ('struct Foo1 *' provided)
fentry:func_1 { $ret = socket_cookie(args.foo1); }
                       ~~~~~~~~~~~~~~~~~~~~~~~~
)" });
  test("kprobe:tcp_shutdown { $ret = socket_cookie((struct sock *)arg0); }",
       Error{ R"(
stdin:1:30-65: ERROR: socket_cookie can not be used with "kprobe" probes
kprobe:tcp_shutdown { $ret = socket_cookie((struct sock *)arg0); }
                             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserBTFTest, iter)
{
  test("iter:task { 1 }");
  test("iter:task { $x = ctx->task->pid }");
  test("iter:task_file { $x = ctx->file->ino }");
  test("iter:task_vma { $x = ctx->vma->vm_start }");
  test("iter:task { printf(\"%d\", ctx->task->pid); }");
  test("iter:task { $x = args.foo; }", Error{ R"(
stdin:1:18-22: ERROR: The args builtin can only be used with tracepoint/fentry/uprobe probes (iter used here)
iter:task { $x = args.foo; }
                 ~~~~
)" });
  test("iter:task,iter:task_file { 1 }", Error{ R"(
stdin:1:1-10: ERROR: Only single iter attach point is allowed.
iter:task,iter:task_file { 1 }
~~~~~~~~~
)" });
  test("iter:task,f:func_1 { 1 }", Error{ R"(
stdin:1:1-10: ERROR: Only single iter attach point is allowed.
iter:task,f:func_1 { 1 }
~~~~~~~~~
)" });
  test("iter:task* { }", Error{ R"(
stdin:1:1-11: ERROR: iter probe type does not support wildcards
iter:task* { }
~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserBTFTest, rawtracepoint)
{
  test("rawtracepoint:event_rt { args.first_real_arg }");

  test("rawtracepoint:event_rt { args.bad_arg }", Error{ R"(
stdin:1:26-31: ERROR: Can't find function parameter bad_arg
rawtracepoint:event_rt { args.bad_arg }
                         ~~~~~
)" });
}

// Sanity check for kfunc/kretfunc aliases
TEST_F(SemanticAnalyserBTFTest, kfunc)
{
  test("kfunc:func_1 { 1 }");
  test("kretfunc:func_1 { 1 }");
  test("kfunc:func_1 { $x = args.a; $y = args.foo1; $z = args.foo2->f.a; }");
  test("kretfunc:func_1 { $x = retval; }");
  test("kfunc:vmlinux:func_1 { 1 }");
  test("kfunc:*:func_1 { 1 }");
  test("kfunc:func_1 { @[func] = 1; }");

  test("kretfunc:func_1 { $x = args.foo; }", Error{ R"(
stdin:1:24-29: ERROR: Can't find function parameter foo
kretfunc:func_1 { $x = args.foo; }
                       ~~~~~
)" });
  test("kretfunc:func_1 { $x = args; }");
  test("kfunc:func_1 { @ = args; }");
  test("kfunc:func_1 { @[args] = 1; }");
  // reg() is not available in kfunc
  if (arch::Host::Machine == arch::Machine::X86_64) {
    test("kfunc:func_1 { reg(\"ip\") }", Error{ R"(
stdin:1:16-25: ERROR: reg can not be used with "fentry" probes
kfunc:func_1 { reg("ip") }
               ~~~~~~~~~
)" });
    test("kretfunc:func_1 { reg(\"ip\") }", Error{ R"(
stdin:1:19-28: ERROR: reg can not be used with "fexit" probes
kretfunc:func_1 { reg("ip") }
                  ~~~~~~~~~
)" });
  }
  // Backwards compatibility
  test("kfunc:func_1 { $x = args->a; }");
}

TEST_F(SemanticAnalyserTest, btf_type_tags)
{
  test("t:btf:tag { args.parent }");
  test("t:btf:tag { args.real_parent }", Error{ R"(
stdin:1:13-18: ERROR: Attempting to access pointer field 'real_parent' with unsupported tag attribute: percpu
t:btf:tag { args.real_parent }
            ~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_map_one_key)
{
  test("begin { @map[0] = 1; for ($kv : @map) { print($kv); } }",
       ExpectedAST{ R"(
Program
 begin
  =
   map: @map :: [int64]int64
    int: 0 :: [int64]
   int: 1 :: [int64]
  for
   decl
    variable: $kv :: [(int64,int64)]
    map: @map :: [int64]int64
   stmts
    call: print
     variable: $kv :: [(int64,int64)]
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_map_two_keys)
{
  test("begin { @map[0,0] = 1; for ($kv : @map) { print($kv); } }",
       ExpectedAST{ R"(
Program
 begin
  =
   map: @map :: [(int64,int64)]int64
    tuple: :: [(int64,int64)]
     int: 0 :: [int64]
     int: 0 :: [int64]
   int: 1 :: [int64]
  for
   decl
    variable: $kv :: [((int64,int64),int64)]
    map: @map :: [(int64,int64)]int64
   stmts
    call: print
     variable: $kv :: [((int64,int64),int64)]
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_map)
{
  test("begin { @map[0] = 1; for ($kv : @map) { print($kv); } }");
  test("begin { @map[0] = 1; for ($kv : @map) { print($kv.0); } }");
  test("begin { @map[0] = 1; for ($kv : @map) { print($kv.1); } }");
  test("begin {@map1[@map2] = 1; @map2 = 1; for ($kv : @map1) {print($kv);}}");
}

TEST_F(SemanticAnalyserTest, for_loop_map_declared_after)
{
  // Regression test: What happens with
  // @map[$kv.0] when @map hasn't been
  // defined yet?
  test("begin { for ($kv : @map) { @map[$kv.0] } @map[0] = 1; }");
}

TEST_F(SemanticAnalyserTest, for_loop_map_no_key)
{
  // Error location is incorrect: #3063
  test("begin { @map = 1; for ($kv : @map) { } }", Error{ R"(
stdin:1:30-35: ERROR: @map has no explicit keys (scalar map), and cannot be used for iteration
begin { @map = 1; for ($kv : @map) { } }
                             ~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_map_undefined)
{
  // Error location is incorrect: #3063
  test("begin { for ($kv : @map) { } }", Error{ R"(
stdin:1:20-25: ERROR: Undefined map: @map
begin { for ($kv : @map) { } }
                   ~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_map_undefined2)
{
  // Error location is incorrect: #3063
  test("begin { @map[0] = 1; for ($kv : @undef) { @map[$kv.0]; } }", Error{ R"(
stdin:1:33-40: ERROR: Undefined map: @undef
begin { @map[0] = 1; for ($kv : @undef) { @map[$kv.0]; } }
                                ~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_map_restricted_types)
{
  test("begin { @map[0] = hist(10); for ($kv : @map) { } }", Error{ R"(
stdin:1:40-45: ERROR: Loop expression does not support type: hist_t
begin { @map[0] = hist(10); for ($kv : @map) { } }
                                       ~~~~~
)" });
  test("begin { @map[0] = lhist(10, 0, 10, 1); for ($kv : @map) { } }",
       Error{ R"(
stdin:1:51-56: ERROR: Loop expression does not support type: lhist_t
begin { @map[0] = lhist(10, 0, 10, 1); for ($kv : @map) { } }
                                                  ~~~~~
)" });
  test("begin { @map[0] = tseries(10, 10s, 10); for ($kv : @map) { } }",
       Error{ R"(
stdin:1:52-57: ERROR: Loop expression does not support type: tseries_t
begin { @map[0] = tseries(10, 10s, 10); for ($kv : @map) { } }
                                                   ~~~~~
)" });
  test("begin { @map[0] = stats(10); for ($kv : @map) { } }", Error{ R"(
stdin:1:41-46: ERROR: Loop expression does not support type: stats_t
begin { @map[0] = stats(10); for ($kv : @map) { } }
                                        ~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_shadowed_decl)
{
  test(R"(
    begin {
      $kv = 1;
      @map[0] = 1;
      for ($kv : @map) { }
    })",
       Error{ R"(
stdin:4:11-15: ERROR: Loop declaration shadows existing variable: $kv
      for ($kv : @map) { }
          ~~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_variables_read_only)
{
  test(R"(
    begin {
      $var = 0;
      @map[0] = 1;
      for ($kv : @map) {
        print($var);
      }
      print($var);
    })",
       ExpectedAST{ R"(
  for
   ctx
    $var :: [int64 *, AS(kernel)]
   decl
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_variables_modified_during_loop)
{
  test(R"(
    begin {
      $var = 0;
      @map[0] = 1;
      for ($kv : @map) {
        $var++;
      }
      print($var);
    })",
       ExpectedAST{ R"(
  for
   ctx
    $var :: [int64 *, AS(kernel)]
   decl
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_variables_created_in_loop)
{
  // $var should not appear in ctx
  test(R"(
    begin {
      @map[0] = 1;
      for ($kv : @map) {
        $var = 2;
        print($var);
      }
    })",
       ExpectedAST{ R"(
  for
   decl
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_variables_multiple)
{
  test(R"(
    begin {
      @map[0] = 1;
      $var1 = 123;
      $var2 = "abc";
      $var3 = "def";
      for ($kv : @map) {
        $var1 = 456;
        print($var3);
      }
    })",
       ExpectedAST{ R"(
  for
   ctx
    $var1 :: [int64 *, AS(kernel)]
    $var3 :: [string[4] *, AS(kernel)]
   decl
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_variables_created_in_loop_used_after)
{
  test(R"(
    begin {
      @map[0] = 1;
      for ($kv : @map) {
        $var = 2;
      }
      print($var);
    })",
       Error{ R"(
stdin:6:7-17: ERROR: Undefined or undeclared variable: $var
      print($var);
      ~~~~~~~~~~
)" });

  test(R"(
    begin {
      @map[0] = 1;
      for ($kv : @map) {
        print($kv);
      }
      print($kv);
    })",
       Error{ R"(
stdin:6:7-16: ERROR: Undefined or undeclared variable: $kv
      print($kv);
      ~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_invalid_expr)
{
  // Error location is incorrect: #3063
  test("begin { for ($x : $var) { } }", Error{ R"(
stdin:1:19-25: ERROR: syntax error, unexpected ), expecting [ or . or ->
begin { for ($x : $var) { } }
                  ~~~~~~
)" });
  test("begin { for ($x : 1+2) { } }", Error{ R"(
stdin:1:19-22: ERROR: syntax error, unexpected +, expecting [ or . or ->
begin { for ($x : 1+2) { } }
                  ~~~
)" });
  test("begin { for ($x : \"abc\") { } }", Error{ R"(
stdin:1:19-26: ERROR: syntax error, unexpected ), expecting [ or . or ->
begin { for ($x : "abc") { } }
                  ~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_multiple_errors)
{
  // Error location is incorrect: #3063
  test(R"(
    begin {
      $kv = 1;
      @map[0] = 1;
      for ($kv : @map) { }
    })",
       Error{ R"(
stdin:4:11-15: ERROR: Loop declaration shadows existing variable: $kv
      for ($kv : @map) { }
          ~~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_control_flow)
{
  test("begin { @map[0] = 1; for ($kv : @map) { break; } }");
  test("begin { @map[0] = 1; for ($kv : @map) { continue; } }");

  // Error location is incorrect: #3063
  test("begin { @map[0] = 1; for ($kv : @map) { return; } }", Error{ R"(
stdin:1:42-48: ERROR: 'return' statement is not allowed in a for-loop
begin { @map[0] = 1; for ($kv : @map) { return; } }
                                         ~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_missing_feature)
{
  test("begin { @map[0] = 1; for ($kv : @map) { print($kv); } }",
       NoFeatures::Enable,
       Error{ R"(
stdin:1:22-25: ERROR: Missing required kernel feature: for_each_map_elem
begin { @map[0] = 1; for ($kv : @map) { print($kv); } }
                     ~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_loop_castable_map_missing_feature)
{
  test("begin { @map[0] = count(); for ($kv : @map) { print($kv); } }",
       NoFeatures::Enable,
       Error{ R"(
stdin:1:28-31: ERROR: Missing required kernel feature: for_each_map_elem
begin { @map[0] = count(); for ($kv : @map) { print($kv); } }
                           ~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_range_loop)
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

TEST_F(SemanticAnalyserTest, for_range_nested)
{
  test("begin { for ($i : 0..5) { "
       "for ($j : 0..$i) { printf(\"%d %d\\n\", $i, $j); } "
       "} }");
}

TEST_F(SemanticAnalyserTest, for_range_variable_use)
{
  test("begin { for ($i : 0..5) { @[$i] = "
       "$i * 2; } }");
}

TEST_F(SemanticAnalyserTest, for_range_shadowing)
{
  test(R"(begin { $i = 10; for ($i : 0..5) { printf("%d", $i); } })", Error{ R"(
stdin:1:22-25: ERROR: Loop declaration shadows existing variable: $i
begin { $i = 10; for ($i : 0..5) { printf("%d", $i); } }
                     ~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_range_invalid_types)
{
  test(R"(begin { for ($i : "str"..5) { printf("%d", $i); } })", Error{ R"(
stdin:1:19-28: ERROR: Loop range requires an integer for the start value
begin { for ($i : "str"..5) { printf("%d", $i); } }
                  ~~~~~~~~~
)" });

  test(R"(begin { for ($i : 0.."str") { printf("%d", $i); } })", Error{ R"(
stdin:1:19-28: ERROR: Loop range requires an integer for the end value
begin { for ($i : 0.."str") { printf("%d", $i); } }
                  ~~~~~~~~~
)" });

  test(R"(begin { for ($i : 0.0..5) { printf("%d", $i); } })", Error{ R"(
stdin:1:19-23: ERROR: Can not access index '0' on expression of type 'int64'
begin { for ($i : 0.0..5) { printf("%d", $i); } }
                  ~~~~
stdin:1:19-26: ERROR: Loop range requires an integer for the start value
begin { for ($i : 0.0..5) { printf("%d", $i); } }
                  ~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_range_control_flow)
{
  test("begin { for ($i : 0..5) { break; } }");
  test("begin { for ($i : 0..5) { continue; } }");

  test("begin { for ($i : 0..5) { return; } }", Error{ R"(
stdin:1:28-34: ERROR: 'return' statement is not allowed in a for-loop
begin { for ($i : 0..5) { return; } }
                           ~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_range_out_of_scope)
{
  test(R"(begin { for ($i : 0..5) { printf("%d", $i); } printf("%d", $i); })",
       Error{ R"(
stdin:1:61-63: ERROR: Undefined or undeclared variable: $i
begin { for ($i : 0..5) { printf("%d", $i); } printf("%d", $i); }
                                                            ~~
)" });
}

TEST_F(SemanticAnalyserTest, for_range_context_access)
{
  test("kprobe:f { for ($i : 0..5) { arg0 } }", Error{ R"(
stdin:1:31-35: ERROR: 'arg0' builtin is not allowed in a for-loop
kprobe:f { for ($i : 0..5) { arg0 } }
                              ~~~~
)" });
}

TEST_F(SemanticAnalyserTest, for_range_nested_range)
{
  test("begin { for ($i : 0..5) { for ($j : 0..$i) { "
       "printf(\"%d %d\\n\", $i, $j); "
       "} } }");
}

TEST_F(SemanticAnalyserTest, castable_map_missing_feature)
{
  test("k:f {  @a = count(); }", NoFeatures::Enable);
  test("k:f {  @a = count(); print(@a) }", NoFeatures::Enable);
  test("k:f {  @a = count(); clear(@a) }", NoFeatures::Enable);
  test("k:f {  @a = count(); zero(@a) }", NoFeatures::Enable);
  test("k:f {  @a[1] = count(); delete(@a, 1) }", NoFeatures::Enable);
  test("k:f { @a[1] = count(); has_key(@a, 1) }", NoFeatures::Enable);

  test("k:f {  @a = count(); len(@a) }", NoFeatures::Enable, Error{ R"(
stdin:1:22-28: ERROR: call to len() expects a map with explicit keys (non-scalar map)
k:f {  @a = count(); len(@a) }
                     ~~~~~~
)" });

  test("begin { @a = count(); print((uint64)@a) }",
       NoFeatures::Enable,
       Error{ R"(
stdin:1:23-39: ERROR: Missing required kernel feature: map_lookup_percpu_elem
begin { @a = count(); print((uint64)@a) }
                      ~~~~~~~~~~~~~~~~
)" });

  test("begin { @a = count(); print((@a, 1)) }", NoFeatures::Enable, Error{ R"(
stdin:1:23-32: ERROR: Missing required kernel feature: map_lookup_percpu_elem
begin { @a = count(); print((@a, 1)) }
                      ~~~~~~~~~
)" });

  test("begin { @a[1] = count(); print(@a[1]) }", NoFeatures::Enable, Error{ R"(
stdin:1:26-37: ERROR: Missing required kernel feature: map_lookup_percpu_elem
begin { @a[1] = count(); print(@a[1]) }
                         ~~~~~~~~~~~
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

TEST_F(SemanticAnalyserTest, for_loop_no_ctx_access)
{
  test("kprobe:f { @map[0] = 1; for ($kv : @map) { arg0 } }", Error{ R"(
stdin:1:45-49: ERROR: 'arg0' builtin is not allowed in a for-loop
kprobe:f { @map[0] = 1; for ($kv : @map) { arg0 } }
                                            ~~~~
)" });
}

TEST_F(SemanticAnalyserBTFTest, args_builtin_mixed_probes)
{
  test("fentry:func_1,tracepoint:sched:sched_one { args }", Error{ R"(
stdin:1:44-48: ERROR: The args builtin can only be used within the context of a single probe type, e.g. "probe1 {args}" is valid while "probe1,probe2 {args}" is not.
fentry:func_1,tracepoint:sched:sched_one { args }
                                           ~~~~
)" });
}

TEST_F(SemanticAnalyserBTFTest, binop_late_ptr_resolution)
{
  test(R"(fentry:func_1 { if (@a[1] == args.foo1) { } @a[1] = args.foo1; })");
}

TEST_F(SemanticAnalyserTest, buf_strlen_too_large)
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

TEST_F(SemanticAnalyserTest, variable_declarations)
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
  test("begin { let $a: struct x; }");
  test("begin { let $a: struct x *; }");
  test("begin { let $a: struct task_struct *; $a = curtask; }");
  test("begin { let $a: struct Foo[10]; }");
  test("begin { if (1) { let $x; } $x = 2; }");
  test("begin { if (1) { let $x; } else { let $x; } let $x; }");

  // https://github.com/bpftrace/bpftrace/pull/3668#issuecomment-2596432923
  test("begin { let $a; print($a); $a = 1; }",
       Warning{ "Variable used before it was assigned:" });

  test("begin { let $a; let $a; }",
       Error{ R"(
stdin:1:17-23: ERROR: Variable $a was already declared. Variable shadowing is not allowed.
begin { let $a; let $a; }
                ~~~~~~
)" },
       Warning{ R"(
stdin:1:9-15: WARNING: This is the initial declaration.
begin { let $a; let $a; }
        ~~~~~~
)" });

  test("begin { let $a: uint16; $a = -1; }", Error{ R"(
stdin:1:26-33: ERROR: Type mismatch for $a: trying to assign value of type 'int64' when variable already has a type 'uint16'
begin { let $a: uint16; $a = -1; }
                         ~~~~~~~
)" });

  test("begin { let $a: uint8 = 1; $a = 10000; }", Error{ R"(
stdin:1:29-39: ERROR: Type mismatch for $a: trying to assign value '10000' which does not fit into the variable of type 'uint8'
begin { let $a: uint8 = 1; $a = 10000; }
                            ~~~~~~~~~~
)" });

  test("begin { let $a: int8 = 1; $a = -10000; }", Error{ R"(
stdin:1:28-39: ERROR: Type mismatch for $a: trying to assign value '-10000' which does not fit into the variable of type 'int8'
begin { let $a: int8 = 1; $a = -10000; }
                           ~~~~~~~~~~~
)" });

  test("begin { let $a; $a = (uint8)1; $a = -1; }", Error{ R"(
stdin:1:32-39: ERROR: Type mismatch for $a: trying to assign value of type 'int64' when variable already contains a value of type 'uint8'
begin { let $a; $a = (uint8)1; $a = -1; }
                               ~~~~~~~
)" });

  test("begin { let $a: int8; $a = 10000; }", Error{ R"(
stdin:1:24-34: ERROR: Type mismatch for $a: trying to assign value '10000' which does not fit into the variable of type 'int8'
begin { let $a: int8; $a = 10000; }
                       ~~~~~~~~~~
)" });

  test("begin { $a = -1; let $a; }", Error{ R"(
stdin:1:18-24: ERROR: Variable declarations need to occur before variable usage or assignment. Variable: $a
begin { $a = -1; let $a; }
                 ~~~~~~
)" });

  test("begin { let $a: uint16 = -1; }", Error{ R"(
stdin:1:9-29: ERROR: Type mismatch for $a: trying to assign value of type 'int64' when variable already has a type 'uint16'
begin { let $a: uint16 = -1; }
        ~~~~~~~~~~~~~~~~~~~~
)" });

  test(R"(begin { let $a: sum_t; })", Error{ R"(
stdin:1:9-23: ERROR: Invalid variable declaration type: sum_t
begin { let $a: sum_t; }
        ~~~~~~~~~~~~~~
)" });

  test(R"(begin { let $a: struct bad_task; $a = *curtask; })", Error{ R"(
stdin:1:34-47: ERROR: Type mismatch for $a: trying to assign value of type 'struct task_struct' when variable already has a type 'struct bad_task'
begin { let $a: struct bad_task; $a = *curtask; }
                                 ~~~~~~~~~~~~~
)" });

  test(R"(begin { $x = 2; if (1) { let $x; } })", Error{ R"(
stdin:1:26-32: ERROR: Variable declarations need to occur before variable usage or assignment. Variable: $x
begin { $x = 2; if (1) { let $x; } }
                         ~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, variable_address)
{
  test("begin { $a = 1; $b = &$a; @c = &$a; }");

  auto ast = test("begin { $a = 1; $b = &$a; }");
  auto &stmts = ast.root->probes.at(0)->block->stmts;

  auto *assignment = stmts.at(1).as<ast::AssignVarStatement>();
  ASSERT_TRUE(assignment->var()->var_type.IsPtrTy());
  ASSERT_TRUE(assignment->var()->var_type.GetPointeeTy()->IsIntTy());

  test("begin { $a = 1; $b = &$c; }", Error{ R"(
stdin:1:22-25: ERROR: Undefined or undeclared variable: $c
begin { $a = 1; $b = &$c; }
                     ~~~
)" });

  test("begin { let $a; $b = &$a; }", Error{ R"(
stdin:1:22-25: ERROR: No type available for variable $a
begin { let $a; $b = &$a; }
                     ~~~
)" });
}

TEST_F(SemanticAnalyserTest, map_address)
{
  test("begin { @a = 1; @b[1] = 2; $x = &@a; $y = &@b; }");

  test("begin { $x = &@a; }", Error{ R"(
stdin:1:14-17: ERROR: Undefined map: @a
begin { $x = &@a; }
             ~~~
)" });
}

TEST_F(SemanticAnalyserTest, block_scoping)
{
  // if/else
  test("begin { $a = 1; if (1) { $b = 2; "
       "print(($a, $b)); } }");
  test(R"(
      begin {
        $a = 1;
        if (1) {
          print(($a));
          $b = 2;
          if (1) {
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
      if (1) {
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

  // if/else
  test("begin { if (1) { $a = 1; } print(($a)); }", Error{ R"(
stdin:1:28-37: ERROR: Undefined or undeclared variable: $a
begin { if (1) { $a = 1; } print(($a)); }
                           ~~~~~~~~~
)" });
  test("begin { if (1) { $a = 1; } else { print(($a)); } }", Error{ R"(
stdin:1:35-44: ERROR: Undefined or undeclared variable: $a
begin { if (1) { $a = 1; } else { print(($a)); } }
                                  ~~~~~~~~~
)" });
  test("begin { if (1) { $b = 1; } else { $b = 2; } print(($b)); }", Error{ R"(
stdin:1:45-54: ERROR: Undefined or undeclared variable: $b
begin { if (1) { $b = 1; } else { $b = 2; } print(($b)); }
                                            ~~~~~~~~~
)" });

  // for loops
  test("kprobe:f { @map[0] = 1; for ($kv : @map) { $a = 1; } "
       "print(($a)); }",
       Error{ R"(
stdin:1:55-64: ERROR: Undefined or undeclared variable: $a
kprobe:f { @map[0] = 1; for ($kv : @map) { $a = 1; } print(($a)); }
                                                      ~~~~~~~~~
)" });

  // while loops
  test("begin { while (1) { $a = 1; } print(($a)); }", Error{ R"(
stdin:1:31-40: ERROR: Undefined or undeclared variable: $a
begin { while (1) { $a = 1; } print(($a)); }
                              ~~~~~~~~~
)" });

  // unroll
  test("begin { unroll(1) { $a = 1; } print(($a)); }", Error{ R"(
stdin:1:31-40: ERROR: Undefined or undeclared variable: $a
begin { unroll(1) { $a = 1; } print(($a)); }
                              ~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, invalid_assignment)
{
  test("begin { @a = hist(10); let $b = @a; }",
       Error{ R"(
stdin:1:24-35: ERROR: Value 'hist_t' cannot be assigned to a scratch variable.
begin { @a = hist(10); let $b = @a; }
                       ~~~~~~~~~~~)" },
       Warning{ R"(
stdin:1:24-30: WARNING: Variable $b never assigned to.
begin { @a = hist(10); let $b = @a; }
                       ~~~~~~
)" });

  test("begin { @a = lhist(123, 0, 123, 1); let $b = @a; }",
       Error{ R"(
stdin:1:37-48: ERROR: Value 'lhist_t' cannot be assigned to a scratch variable.
begin { @a = lhist(123, 0, 123, 1); let $b = @a; }
                                    ~~~~~~~~~~~
)" },
       Warning{ R"(
stdin:1:37-43: WARNING: Variable $b never assigned to.
begin { @a = lhist(123, 0, 123, 1); let $b = @a; }
                                    ~~~~~~
)" });

  test("begin { @a = tseries(10, 10s, 1); let $b = @a; }",
       Error{ R"(
stdin:1:35-46: ERROR: Value 'tseries_t' cannot be assigned to a scratch variable.
begin { @a = tseries(10, 10s, 1); let $b = @a; }
                                  ~~~~~~~~~~~
)" },
       Warning{ R"(
stdin:1:35-41: WARNING: Variable $b never assigned to.
begin { @a = tseries(10, 10s, 1); let $b = @a; }
                                  ~~~~~~
)" });

  test("begin { @a = stats(10); let $b = @a; }",
       Error{ R"(
stdin:1:25-36: ERROR: Value 'stats_t' cannot be assigned to a scratch variable.
begin { @a = stats(10); let $b = @a; }
                        ~~~~~~~~~~~
)" },
       Warning{ R"(
stdin:1:25-31: WARNING: Variable $b never assigned to.
begin { @a = stats(10); let $b = @a; }
                        ~~~~~~
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
stdin:1:25-32: ERROR: Map value 'stats_t' cannot be assigned from one map to another. The function that returns this type must be called directly e.g. `@b = stats(arg2);`.
begin { @a = stats(10); @b = @a; }
                        ~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, no_maximum_passes)
{
  test("interval:s:1 { @j = @i; @i = @h; @h "
       "= @g; @g = @f; @f = @e; @e = @d; "
       "@d = @c; "
       "@c = @b; @b = @a; } interval:s:1 { "
       "@a = 1; }");
}

TEST_F(SemanticAnalyserTest, block_expressions)
{
  // Illegal, check that variable is not available
  test("begin { let $x = { let $y = $x; $y }; print($x) }", Error{ R"(
stdin:1:29-31: ERROR: Undefined or undeclared variable: $x
begin { let $x = { let $y = $x; $y }; print($x) }
                            ~~
)" });

  // Good, variable is not shadowed
  test("begin { let $x = { let $x = 1; $x }; print($x) }", ExpectedAST{ R"(
Program
 begin
  decl
   variable: $x :: [int64]
   decl
    variable: $x :: [int64]
    int: 1 :: [int64]
   variable: $x :: [int64]
  call: print
   variable: $x :: [int64]
)" });
}

TEST_F(SemanticAnalyserTest, map_declarations)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->config_->unstable_map_decl = ConfigUnstable::enable;

  test("let @a = hash(2); begin { @a = 1; }", Mock{ *bpftrace });
  test("let @a = lruhash(2); begin { @a = 1; }", Mock{ *bpftrace });
  test("let @a = percpuhash(2); begin { @a[1] = count(); }", Mock{ *bpftrace });
  test("let @a = percpulruhash(2); begin { @a[1] = count(); }",
       Mock{ *bpftrace });
  test("let @a = percpulruhash(2); begin { @a[1] = count(); }",
       Mock{ *bpftrace });
  test("let @a = percpuarray(1); begin { @a = count(); }", Mock{ *bpftrace });

  test("let @a = hash(2); begin { print(1); }",
       Mock{ *bpftrace },
       Warning{ "WARNING: Unused map: @a" });

  test("let @a = percpuhash(2); begin { @a = 1; }",
       Mock{ *bpftrace },
       Error{ R"(
stdin:1:33-35: ERROR: Incompatible map types. Type from declaration: percpuhash. Type from value/key type: hash
let @a = percpuhash(2); begin { @a = 1; }
                                ~~
)" });
  test("let @a = percpulruhash(2); begin { @a = 1; }",
       Mock{ *bpftrace },
       Error{ R"(
stdin:1:36-38: ERROR: Incompatible map types. Type from declaration: percpulruhash. Type from value/key type: hash
let @a = percpulruhash(2); begin { @a = 1; }
                                   ~~
)" });
  test("let @a = hash(2); begin { @a = count(); }",
       Mock{ *bpftrace },
       Error{ R"(
stdin:1:27-29: ERROR: Incompatible map types. Type from declaration: hash. Type from value/key type: percpuarray
let @a = hash(2); begin { @a = count(); }
                          ~~
)" });
  test("let @a = lruhash(2); begin { @a = count(); }",
       Mock{ *bpftrace },
       Error{ R"(
stdin:1:30-32: ERROR: Incompatible map types. Type from declaration: lruhash. Type from value/key type: percpuarray
let @a = lruhash(2); begin { @a = count(); }
                             ~~
)" });
  test("let @a = percpuarray(1); begin { @a[1] = count(); }",
       Mock{ *bpftrace },
       Error{ R"(
stdin:1:34-36: ERROR: Incompatible map types. Type from declaration: percpuarray. Type from value/key type: percpuhash
let @a = percpuarray(1); begin { @a[1] = count(); }
                                 ~~
)" });
  test("let @a = potato(2); begin { @a[1] = count(); }",
       Mock{ *bpftrace },
       Error{ R"(
stdin:1:1-20: ERROR: Invalid bpf map type: potato
let @a = potato(2); begin { @a[1] = count(); }
~~~~~~~~~~~~~~~~~~~
HINT: Valid map types: percpulruhash, percpuarray, percpuhash, lruhash, hash
)" });

  test("let @a = percpuarray(10); begin { @a = count(); }",
       Mock{ *bpftrace },
       Error{ R"(
stdin:1:1-26: ERROR: Max entries can only be 1 for map type percpuarray
let @a = percpuarray(10); begin { @a = count(); }
~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, macros)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->config_->unstable_macro = ConfigUnstable::enable;

  test("macro set($x) { $x = 1; $x } begin { $a = \"string\"; set($a); }",
       Mock{ *bpftrace },
       Error{ R"(
stdin:1:17-23: ERROR: Type mismatch for $a: trying to assign value of type 'int64' when variable already contains a value of type 'string'
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
stdin:1:21-22: ERROR: Type mismatch for '+': comparing string with int64
macro add2($x) { $x + 1 } macro add1($x) { add2($x) } begin { $a = "string"; add1($a); }
                    ~
stdin:1:18-20: ERROR: left (string)
macro add2($x) { $x + 1 } macro add1($x) { add2($x) } begin { $a = "string"; add1($a); }
                 ~~
stdin:1:23-24: ERROR: right (int64)
macro add2($x) { $x + 1 } macro add1($x) { add2($x) } begin { $a = "string"; add1($a); }
                      ~
stdin:1:78-86: ERROR: expanded from
macro add2($x) { $x + 1 } macro add1($x) { add2($x) } begin { $a = "string"; add1($a); }
                                                                             ~~~~~~~~
stdin:1:44-52: ERROR: expanded from
macro add2($x) { $x + 1 } macro add1($x) { add2($x) } begin { $a = "string"; add1($a); }
                                           ~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, warning_for_empty_positional_parameters)
{
  auto bpftrace = get_mock_bpftrace();
  bpftrace->add_param("1");
  test("begin { print(($1, $2)) }",
       Warning{ "Positional parameter $2 is empty or not provided." },
       Mock{ *bpftrace });
}

TEST_F(SemanticAnalyserTest, warning_for_discared_return_value)
{
  // Non exhaustive testing, just a few examples
  test("k:f { bswap(arg0); }",
       Warning{ "Return value discarded for bswap. "
                "It should be used" });
  test("k:f { cgroup_path(1); }",
       Warning{ "Return value discarded for "
                "cgroup_path. It should be used" });
  test("k:f { @x[1] = 0; has_key(@x, 1); }",
       Warning{ "Return value discarded for has_key. "
                "It should be used" });
  test("k:f { @x[1] = 1; len(@x); }",
       Warning{ "Return value discarded for len. It "
                "should be used" });
  test("k:f { uptr((int8*) arg0); }",
       Warning{ "Return value discarded for uptr. It "
                "should be used" });
  test("k:f { ustack(raw); }",
       Warning{ "Return value discarded for ustack. "
                "It should be used" });
}

TEST_F(SemanticAnalyserTest, external_function)
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
stdin:1:12-23: ERROR: Expected int32 for argument `a` got int64
kprobe:f { foo((int64)1, (int64)2); }
           ~~~~~~~~~~~
stdin:1:12-35: ERROR: Function `foo` requires arguments (int32, int64)
kprobe:f { foo((int64)1, (int64)2); }
           ~~~~~~~~~~~~~~~~~~~~~~~
)" });

  // Test that the return type is well-understood.
  test("kprobe:f { $x = (int32*)0; $x = foo((int32)1, (int64)2); }",
       Types{ types },
       Error{ R"(
stdin:1:28-56: ERROR: Type mismatch for $x: trying to assign value of type 'int32' when variable already contains a value of type 'int32 *'
kprobe:f { $x = (int32*)0; $x = foo((int32)1, (int64)2); }
                           ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });
}

TEST_F(SemanticAnalyserTest, printf_str_conversion)
{
  // %s just uses the default text output representation, and therefore can
  // print any type that can be serialized.
  test("kprobe:f { $x = (uint8)1; printf(\"%s\", $x) }");
  test("kprobe:f { $x = (uint8*)0; printf(\"%s\", $x) }");
  test("kprobe:f { $x = (1, 1); printf(\"%s\", $x) }");
  test(R"(kprobe:f { $x = "foo"; printf("%s", $x) })");
}

} // namespace bpftrace::test::semantic_analyser
