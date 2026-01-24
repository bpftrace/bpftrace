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
#include "ast/passes/type_graph.h"
#include "ast/passes/type_system.h"
#include "ast_matchers.h"
#include "bpftrace.h"
#include "btf_common.h"
#include "driver.h"
#include "mocks.h"
#include "struct.h"

namespace bpftrace::test::type_graph {

using bpftrace::test::AssignMapStatement;
using bpftrace::test::AssignVarStatement;
using bpftrace::test::Binop;
using bpftrace::test::Block;
using bpftrace::test::Builtin;
using bpftrace::test::Cast;
using bpftrace::test::ExprStatement;
using bpftrace::test::FieldAccess;
using bpftrace::test::For;
using bpftrace::test::If;
using bpftrace::test::Integer;
using bpftrace::test::Map;
using bpftrace::test::MapAccess;
using bpftrace::test::MapAddr;
using bpftrace::test::NamedArgument;
using bpftrace::test::Probe;
using bpftrace::test::Program;
using bpftrace::test::Record;
using bpftrace::test::SizedType;
using bpftrace::test::String;
using bpftrace::test::Tuple;
using bpftrace::test::Typeof;
using bpftrace::test::Unop;
using bpftrace::test::VarDeclStatement;
using bpftrace::test::Variable;
using bpftrace::test::VariableAddr;
using ::testing::_;
using ::testing::HasSubstr;

auto IntTy(size_t size, bool is_signed = false)
{
  return SizedType(Type::integer).WithSize(size).WithSigned(is_signed);
}

auto StringTy(size_t size)
{
  return SizedType(Type::string).WithSize(size);
}

auto IntVar(const std::string &name, size_t size, bool is_signed = false)
{
  return Variable(name).WithType(
      SizedType(Type::integer).WithSize(size).WithSigned(is_signed));
}

auto IntMapValue(const std::string &name, size_t size, bool is_signed = false)
{
  return Map(name).WithType(
      SizedType(Type::integer).WithSize(size).WithSigned(is_signed));
}

auto IntMapKey(const std::string &name, size_t size, bool is_signed = false)
{
  return Map(name).WithKeyType(
      SizedType(Type::integer).WithSize(size).WithSigned(is_signed));
}

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
class TypeGraphHarness {
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
      mock->bpftrace.cmd_ = "not-empty"; // Used by TypeChecker.
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
                  .add(ast::CreateMacroExpansionPass())
                  .add(ast::CreateClangParsePass())
                  .add(ast::CreateFoldLiteralsPass())
                  .add(ast::CreateBuiltinsPass())
                  .add(ast::CreateMapSugarPass())
                  .add(ast::CreateTypeGraphPass())
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

class TypeGraphTest : public TypeGraphHarness, public testing::Test {};

TEST_F(TypeGraphTest, variable_basic)
{
  test(R"(begin { $a = 1; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignVarStatement(IntVar("$a", 1), _) })) });

  test(R"(begin { $a = true; })",
       ExpectedAST{ Program().WithProbe(Probe(
           _,
           { AssignVarStatement(
               Variable("$a").WithType(SizedType(Type::boolean)), _) })) });

  test(R"(begin { $a = "str"; })",
       ExpectedAST{ Program().WithProbe(Probe(
           _,
           { AssignVarStatement(Variable("$a").WithType(StringTy(4)), _) })) });

  test(R"(begin { let $b; $a = ($b != 1); $b = 10; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$b", 1)),
                   AssignVarStatement(
                       Variable("$a").WithType(SizedType(Type::boolean)), _),
                   AssignVarStatement(IntVar("$b", 1), _) })) });

  test(R"(begin { let $b; $a = $b; $b = 10; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$b", 1)),
                   AssignVarStatement(IntVar("$a", 1), IntVar("$b", 1)),
                   AssignVarStatement(IntVar("$b", 1), _) })) });

  test(R"(begin { let $y; $z = $y + 10; $y = 10; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$y", 1)),
                   AssignVarStatement(IntVar("$z", 8), _),
                   AssignVarStatement(IntVar("$y", 1), _) })) });

  test(R"(begin { let $h; let $g; $i = $g + $h + 10; $h = 10; $g = 10; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$h", 1)),
                   VarDeclStatement(IntVar("$g", 1)),
                   AssignVarStatement(IntVar("$i", 8), _),
                   AssignVarStatement(IntVar("$h", 1), _),
                   AssignVarStatement(IntVar("$g", 1), _) })) });
  test(R"(begin { if (true) { $x = 10; } else { $x = "str"; } })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { ExprStatement(If(
                     _,
                     Block({ AssignVarStatement(IntVar("$x", 1), _) }),
                     Block({ AssignVarStatement(
                         Variable("$x").WithType(StringTy(4)), _) }))) })) });
  test(
      R"(begin { let $y; if (true) { $x = $y; } else { $x = $y + 10; } $y = -1; })",
      ExpectedAST{ Program().WithProbe(Probe(
          _,
          { VarDeclStatement(IntVar("$y", 1, true)),
            ExprStatement(
                If(_,
                   Block({ AssignVarStatement(IntVar("$x", 1, true),
                                              IntVar("$y", 1, true)) }),
                   Block({ AssignVarStatement(IntVar("$x", 8, true),
                                              Binop(Operator::PLUS, _, _)) }))),
            AssignVarStatement(IntVar("$y", 1, true), _) })) });

  test(
      R"(begin { let $a: uint32 = (uint8)1; })",
      ExpectedAST{ Program().WithProbe(Probe(
          _,
          { AssignVarStatement(
              IntVar("$a", 4),
              Cast(Typeof(bpftrace::test::SizedType(Type::integer).WithSize(4)),
                   Cast(Typeof(bpftrace::test::SizedType(Type::integer)
                                   .WithSize(1)),
                        Integer(1)))) })) });

  test(R"(begin { let $a: uint32 = 1; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignVarStatement(IntVar("$a", 4), Integer(1)) })) });

  test(R"(begin { $a = 0; $a = $a + 1; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignVarStatement(IntVar("$a", 8), _),
                   AssignVarStatement(IntVar("$a", 8), _) })) });

  test(R"(begin { $a = 0; $a = $a - 1; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignVarStatement(IntVar("$a", 8), _),
                   AssignVarStatement(IntVar("$a", 8), _) })) });

  test(R"(begin { $a = 1; $a = "str"; })", Error{ R"(
stdin:1:17-27: ERROR: Type mismatch for $a: trying to assign value of type 'string[4]' when variable already has a type 'uint8'
begin { $a = 1; $a = "str"; }
                ~~~~~~~~~~
)" });

  test(
      R"(begin { let $y; if (true) { $x = $y; if (true) { $x = "str"; } } else { $x = $y + 10; } $y = -1; })",
      Error{ R"(
ERROR: Type mismatch for $x: trying to assign value of type 'int8' when variable already has a type 'string[4]'
begin { let $y; if (true) { $x = $y; if (true) { $x = "str"; } } else { $x = $y + 10; } $y = -1; }
                            ~~~~~~~
)" });

  test(R"(begin { let $a: uint32 = -1; })", Error{});
  test(R"(begin { let $a: uint32 = (uint64)1; })", Error{});
  test(R"(begin { let $b; let $a: typeof($b) = (uint64)1; $b = (uint32)2; })",
       Error{});
  test(
      R"(begin {let $a; let $x: uint32 = (typeof($a))10; $a = (uint16)1; $a = (uint64)2;})",
      Error{});
  test(R"(begin { let $a: string[2] = "muchlongerstr"; })", Error{});
}

TEST_F(TypeGraphTest, variable_no_type)
{
  test(R"(begin { let $z; $a = 1; $b = typeinfo($z); })", Error{ R"(
stdin:1:13-15: ERROR: Could not resolve the type of this variable
begin { let $z; $a = 1; $b = typeinfo($z); }
            ~~
stdin:1:39-41: ERROR: Could not resolve the type of this variable
begin { let $z; $a = 1; $b = typeinfo($z); }
                                      ~~
stdin:1:25-27: ERROR: Could not resolve the type of this variable
begin { let $z; $a = 1; $b = typeinfo($z); }
                        ~~
)" });

  test(R"(begin { let $a; let $b; $b = $a; $a = $b; })", Error{});
}

TEST_F(TypeGraphTest, variable_with_type_decl)
{
  test(R"(begin { let $a: uint32 = 1; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignVarStatement(IntVar("$a", 4), _) })) });
  test(
      R"(begin { let $b; let $a: typeof($b) = (uint64)1; $b = (uint32)2; $b = (uint64)3; })",
      ExpectedAST{ Program().WithProbe(
          Probe(_,
                { VarDeclStatement(IntVar("$b", 8)),
                  AssignVarStatement(IntVar("$a", 8), _),
                  AssignVarStatement(IntVar("$b", 8), _),
                  AssignVarStatement(IntVar("$b", 8), _) })) });
  test(R"(begin { let $b; let $a: typeof($b) = (uint16)1; $b = (uint32)2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$b", 4)),
                   AssignVarStatement(IntVar("$a", 4), _),
                   AssignVarStatement(IntVar("$b", 4), _) })) });
}

TEST_F(TypeGraphTest, map_value_basic)
{
  // Basic type assignments
  test(R"(begin { @a = 1; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignMapStatement(IntMapValue("@a", 1), _, _) })) });
  test(R"(begin { @a = true; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignMapStatement(
                     Map("@a").WithType(SizedType(Type::boolean)), _, _) })) });
  test(R"(begin { @a = "str"; })",
       ExpectedAST{ Program().WithProbe(Probe(
           _,
           { AssignMapStatement(Map("@a").WithType(StringTy(4)), _, _) })) });

  test(R"(begin { @a[1] = 2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignMapStatement(IntMapValue("@a", 1), _, _) })) });

  test(R"(begin { @a = 1; @a = (uint64)2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignMapStatement(IntMapValue("@a", 8), _, _),
                   AssignMapStatement(IntMapValue("@a", 8), _, _) })) });

  test(R"(begin { @a = (uint32)1; @a = (int32)2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignMapStatement(IntMapValue("@a", 8, true), _, _),
                   AssignMapStatement(IntMapValue("@a", 8, true), _, _) })) });

  test(R"(begin { @a = "hi"; @a = "hello world"; })",
       ExpectedAST{ Program().WithProbe(Probe(
           _,
           { AssignMapStatement(Map("@a").WithType(StringTy(12)), _, _),
             AssignMapStatement(Map("@a").WithType(StringTy(12)), _, _) })) });

  // If/else with different types in branches (first assignment wins)
  test(R"(begin { if (true) { @x = 10; } else { @x = "str"; } })", Error{});

  test(R"(begin { if (true) { @x = (uint32)1; } else { @x = (uint64)2; } })",
       ExpectedAST{ Program().WithProbe(Probe(
           _,
           { ExprStatement(If(
               _,
               Block({ AssignMapStatement(IntMapValue("@x", 8), _, _) }),
               Block(
                   { AssignMapStatement(IntMapValue("@x", 8), _, _) }))) })) });

  test(R"(begin { let $v; @a = $v; $v = 10; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$v", 1)),
                   AssignMapStatement(IntMapValue("@a", 1), _, IntVar("$v", 1)),
                   AssignVarStatement(IntVar("$v", 1), _) })) });

  test(R"(begin { let $v; @a = $v + 10; $v = 5; })",
       ExpectedAST{ Program().WithProbe(Probe(
           _,
           { VarDeclStatement(IntVar("$v", 1)),
             AssignMapStatement(IntMapValue("@a", 8),
                                _,
                                Binop(Operator::PLUS, IntVar("$v", 1), _)),
             AssignVarStatement(IntVar("$v", 1), _) })) });

  test(R"(begin { @x = (uint32)1; } end { @x = (uint64)2; })",
       ExpectedAST{ Program().WithProbes(
           { Probe(_, { AssignMapStatement(IntMapValue("@x", 8), _, _) }),
             Probe(_, { AssignMapStatement(IntMapValue("@x", 8), _, _) }) }) });
}

TEST_F(TypeGraphTest, map_key_basic)
{
  test(R"(begin { @a[1] = 2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignMapStatement(IntMapKey("@a", 1), _, _) })) });

  test(
      R"(begin { @a["key"] = 10; })",
      ExpectedAST{ Program().WithProbe(Probe(
          _,
          { AssignMapStatement(Map("@a").WithKeyType(StringTy(4)), _, _) })) });

  test(R"(begin { @a[1] = 1; @a[(uint64)2] = 2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignMapStatement(IntMapKey("@a", 8), _, _),
                   AssignMapStatement(IntMapKey("@a", 8), _, _) })) });

  test(R"(begin { @a[(uint32)1] = 1; @a[(int32)2] = 2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignMapStatement(IntMapKey("@a", 8, true), _, _),
                   AssignMapStatement(IntMapKey("@a", 8, true), _, _) })) });

  test(R"(begin { @a["hi"] = 1; @a["hello world"] = 2; })",
       ExpectedAST{ Program().WithProbe(Probe(
           _,
           { AssignMapStatement(Map("@a").WithKeyType(StringTy(12)), _, _),
             AssignMapStatement(
                 Map("@a").WithKeyType(StringTy(12)), _, _) })) });

  test(R"(begin { @x[(uint32)1] = 1; } end { @x[(uint64)2] = 2; })",
       ExpectedAST{ Program().WithProbes(
           { Probe(_, { AssignMapStatement(IntMapKey("@x", 8), _, _) }),
             Probe(_, { AssignMapStatement(IntMapKey("@x", 8), _, _) }) }) });

  test(R"(begin { let $k; @a[$k] = 1; $k = 10; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$k", 1)),
                   AssignMapStatement(IntMapKey("@a", 1), IntVar("$k", 1), _),
                   AssignVarStatement(IntVar("$k", 1), _) })) });

  test(R"(begin { let $k; @a[$k + 10] = 1; $k = 5; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$k", 1)),
                   AssignMapStatement(IntMapKey("@a", 8),
                                      Binop(Operator::PLUS, IntVar("$k", 1), _),
                                      _),
                   AssignVarStatement(IntVar("$k", 1), _) })) });

  test(R"(begin { @a[1] = 2; } end { @a["str"] = 1; })", Error{});
}

TEST_F(TypeGraphTest, variable_map_promotion)
{
  test(
      R"(begin { $a = 1; @x = (uint32)1; $a = @x; @y = $a; } end { @x = (uint64)2; })",
      ExpectedAST{ Program().WithProbes(
          { Probe(_,
                  { AssignVarStatement(IntVar("$a", 8), _),
                    AssignMapStatement(IntMapValue("@x", 8), _, _),
                    AssignVarStatement(IntVar("$a", 8),
                                       MapAccess(IntMapValue("@x", 8), _)),
                    AssignMapStatement(
                        IntMapValue("@y", 8), _, IntVar("$a", 8)) }),
            Probe(_, { AssignMapStatement(IntMapValue("@x", 8), _, _) }) }) });

  test(
      R"(begin { $a = 1; @x = (uint32)1; if comptime (typeinfo(@x).full_type == "uint64") { $a = (int16)2; } } end { @x = (uint64)2; })",
      ExpectedAST{ Program().WithProbes(
          { Probe(_,
                  { AssignVarStatement(IntVar("$a", 2, true), _),
                    AssignMapStatement(IntMapValue("@x", 8), _, _),
                    _ }),
            Probe(_, { AssignMapStatement(IntMapValue("@x", 8), _, _) }) }) });
}

TEST_F(TypeGraphTest, typeof)
{
  test(R"(begin { $a = (typeof(uint64))1; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignVarStatement(IntVar("$a", 8), _) })) });
  test(R"(begin { let $b; $a = (typeof($b))1; $b = 1; $b = (uint64)2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$b", 8)),
                   AssignVarStatement(IntVar("$a", 8), _),
                   AssignVarStatement(IntVar("$b", 8), Integer(1)),
                   AssignVarStatement(IntVar("$b", 8), _) })) });
  test(
      R"(begin { let $b; let $c; $a = (typeof($b))1; $b = (typeof($c))1; $c = (int64)2; })",
      ExpectedAST{ Program().WithProbe(
          Probe(_,
                { VarDeclStatement(IntVar("$b", 8, true)),
                  VarDeclStatement(IntVar("$c", 8, true)),
                  AssignVarStatement(IntVar("$a", 8, true), _),
                  AssignVarStatement(IntVar("$b", 8, true), _),
                  AssignVarStatement(IntVar("$c", 8, true), _) })) });

  test(R"(begin { @x = 2; $a = (typeof(@x))1; } end { @x = (int32)1; })",
       ExpectedAST{ Program().WithProbes(
           { Probe(_, { _, AssignVarStatement(IntVar("$a", 4, true), _) }),
             Probe(_,
                   { AssignMapStatement(
                       IntMapValue("@x", 4, true), _, _) }) }) });
  test(R"(begin { @x[(int16)1] = 1; $a = (typeof(@x))1; })",
       ExpectedAST{ Program().WithProbes(
           { Probe(_,
                   { AssignMapStatement(IntMapKey("@x", 2, true), _, _),
                     AssignVarStatement(IntVar("$a", 2, true), _) }) }) });

  test(R"(begin { @x[(int16)1] = 1; $a = (typeof({ print(1); @x[0] }))1; })",
       ExpectedAST{ Program().WithProbes(
           { Probe(_,
                   { AssignMapStatement(IntMapValue("@x", 1), _, _),
                     AssignVarStatement(IntVar("$a", 1), _) }) }) });
}

TEST_F(TypeGraphTest, typeinfo)
{
  test(
      R"(begin { $a = 1; $b = typeinfo($a); })",
      ExpectedAST{ Program().WithProbe(Probe(
          _,
          { AssignVarStatement(IntVar("$a", 1), _),
            AssignVarStatement(
                Variable("$b").WithType(SizedType(Type::record)),
                Record({ NamedArgument("btf_id", Integer(0)),
                         NamedArgument("base_type", String("int")),
                         NamedArgument("full_type", String("uint8")) })) })) });

  test(R"(begin { $a = 1; $b = typeinfo({ $z = (uint64)2; $z }); })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignVarStatement(IntVar("$a", 1), _),
                   AssignVarStatement(
                       Variable("$b").WithType(SizedType(Type::record)),
                       Record({ NamedArgument("btf_id", Integer(0)),
                                NamedArgument("base_type", String("int")),
                                NamedArgument("full_type",
                                              String("uint64")) })) })) });

  test(R"(begin { let $a; $b = typeinfo($a); $a = (uint32)1; $a = (int32)2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$a", 8, true)),
                   AssignVarStatement(
                       Variable("$b").WithType(SizedType(Type::record)),
                       Record({ NamedArgument("btf_id", Integer(0)),
                                NamedArgument("base_type", String("int")),
                                NamedArgument("full_type", String("int64")) })),
                   _,
                   _ })) });

  test(
      R"(begin { let $a; $b = typeinfo($a); if comptime (true) { $a = (int64)2; } })",
      ExpectedAST{ Program().WithProbe(
          Probe(_,
                { VarDeclStatement(IntVar("$a", 8, true)),
                  AssignVarStatement(
                      Variable("$b").WithType(SizedType(Type::record)),
                      Record({ NamedArgument("btf_id", Integer(0)),
                               NamedArgument("base_type", String("int")),
                               NamedArgument("full_type", String("int64")) })),
                  _ })) });

  test(
      R"(begin { @m[(int32)1] = 1; $b = typeinfo(@m); })",
      ExpectedAST{ Program().WithProbe(Probe(
          _,
          { AssignMapStatement(IntMapKey("@m", 4, true), _, _),
            AssignVarStatement(
                Variable("$b").WithType(SizedType(Type::record)),
                Record({ NamedArgument("btf_id", Integer(0)),
                         NamedArgument("base_type", String("int")),
                         NamedArgument("full_type", String("int32")) })) })) });

  test(R"(begin { @m[(int64)1] = 1; $b = typeinfo(@m); })",
       ExpectedAST{ Program().WithProbes(
           { Probe(_,
                   { _,
                     AssignVarStatement(
                         Variable("$b").WithType(SizedType(Type::record)),
                         Record({ NamedArgument("btf_id", Integer(0)),
                                  NamedArgument("base_type", String("int")),
                                  NamedArgument("full_type",
                                                String("int64")) })) }) }) });
}

TEST_F(TypeGraphTest, sizeof)
{
  test(R"(begin { $a = sizeof(uint64); })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignVarStatement(IntVar("$a", 1), Integer(8)) })) });

  test(R"(begin { let $b; $a = sizeof($b); $b = (uint64)1; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$b", 8)),
                   AssignVarStatement(IntVar("$a", 1), Integer(8)),
                   AssignVarStatement(IntVar("$b", 8), _) })) });

  test(R"(begin { let $b; $a = sizeof($b); $b = (uint32)1; $b = (uint64)2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$b", 8)),
                   AssignVarStatement(IntVar("$a", 1), Integer(8)),
                   AssignVarStatement(IntVar("$b", 8), _),
                   AssignVarStatement(IntVar("$b", 8), _) })) });

  test(R"(begin { @x = 2; $a = sizeof(@x); } end { @x = (int32)1; })",
       ExpectedAST{ Program().WithProbes(
           { Probe(_, { _, AssignVarStatement(IntVar("$a", 1), Integer(4)) }),
             Probe(_,
                   { AssignMapStatement(
                       IntMapValue("@x", 4, true), _, _) }) }) });
}

TEST_F(TypeGraphTest, offsetof)
{
  test(R"(struct Foo { int x; long l; char c; }
          begin { $a = offsetof(struct Foo, x); })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignVarStatement(IntVar("$a", 1), _) })) });

  test(R"(struct Foo { int x; long l; char c; }
          begin { $foo = (struct Foo *)0; $a = offsetof(*$foo, l); })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { _, AssignVarStatement(IntVar("$a", 1), _) })) });

  test(R"(struct Foo { int x; long l; }
          struct Bar { struct Foo foo; int y; }
          begin { $a = offsetof(struct Bar, foo.l); })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignVarStatement(IntVar("$a", 1), _) })) });
}

TEST_F(TypeGraphTest, tuple)
{
  test(R"(begin { $a = (1, 2); })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignVarStatement(Variable("$a").WithType(
                                          SizedType(Type::tuple)
                                              .WithField("0", IntTy(1))
                                              .WithField("1", IntTy(1))),
                                      _) })) });

  test(R"(begin { $a = (1, "hello"); })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignVarStatement(Variable("$a").WithType(
                                          SizedType(Type::tuple)
                                              .WithField("0", IntTy(1))
                                              .WithField("1", StringTy(6))),
                                      _) })) });

  test(R"(begin { let $b; $a = (1, $b); $b = (uint64)2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$b", 8)),
                   AssignVarStatement(Variable("$a").WithType(
                                          SizedType(Type::tuple)
                                              .WithField("0", IntTy(1))
                                              .WithField("1", IntTy(8))),
                                      _),
                   AssignVarStatement(IntVar("$b", 8), _) })) });

  test(R"(begin { let $b; $a = ($b, 1); $b = "str"; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(_),
                   AssignVarStatement(Variable("$a").WithType(
                                          SizedType(Type::tuple)
                                              .WithField("0", StringTy(4))
                                              .WithField("1", IntTy(1))),
                                      _),
                   _ })) });

  test(R"(begin { $b = 1; $a = ($b, (int16)1); $b = (uint64)2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { _,
                   AssignVarStatement(Variable("$a").WithType(
                                          SizedType(Type::tuple)
                                              .WithField("0", IntTy(8))
                                              .WithField("1", IntTy(2, true))),
                                      _),
                   _ })) });

  test(
      R"(
      begin { $a = (@b, @c[0], (typeof(@c))3, (typeof({ print(1); @b }))10); @b = 1; }
      end { @c[(uint32)2] = "str"; @b = (int16)2; })",
      ExpectedAST{ Program().WithProbes(
          { Probe(_,
                  { AssignVarStatement(Variable("$a").WithType(
                                           SizedType(Type::tuple)
                                               .WithField("0", IntTy(2, true))
                                               .WithField("1", StringTy(4))
                                               .WithField("2", IntTy(4))
                                               .WithField("3", IntTy(2, true))),
                                       _),
                    _ }),
            Probe(_, { _, _ }) }) });
}

TEST_F(TypeGraphTest, record)
{
  test(R"(begin { $a = ( x = 1, y = 2 ); })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignVarStatement(Variable("$a").WithType(
                                          SizedType(Type::record)
                                              .WithField("x", IntTy(1))
                                              .WithField("y", IntTy(1))),
                                      _) })) });

  test(R"(begin { $a = ( name = "hello", count = 42 ); })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignVarStatement(Variable("$a").WithType(
                                          SizedType(Type::record)
                                              .WithField("name", StringTy(6))
                                              .WithField("count", IntTy(1))),
                                      _) })) });

  test(R"(begin { let $b; $a = ( x = 1, y = $b ); $b = (uint64)2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(IntVar("$b", 8)),
                   AssignVarStatement(Variable("$a").WithType(
                                          SizedType(Type::record)
                                              .WithField("x", IntTy(1))
                                              .WithField("y", IntTy(8))),
                                      _),
                   _ })) });

  test(R"(begin { let $b; $a = ( s = $b, n = 1 ); $b = "str"; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { VarDeclStatement(_),
                   AssignVarStatement(Variable("$a").WithType(
                                          SizedType(Type::record)
                                              .WithField("s", StringTy(4))
                                              .WithField("n", IntTy(1))),
                                      _),
                   _ })) });

  test(R"(begin { $b = 1; $a = ( x = $b, y = (int16)1 ); $b = (uint64)2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { _,
                   AssignVarStatement(Variable("$a").WithType(
                                          SizedType(Type::record)
                                              .WithField("x", IntTy(8))
                                              .WithField("y", IntTy(2, true))),
                                      _),
                   _ })) });

  test(
      R"(
      begin { $a = (a=@b, b=@c[0], c=(typeof(@c))3, d=(typeof({ print(1); @b }))10); @b = 1; }
      end { @c[(uint32)2] = "str"; @b = (int16)2; })",
      ExpectedAST{ Program().WithProbes(
          { Probe(_,
                  { AssignVarStatement(Variable("$a").WithType(
                                           SizedType(Type::record)
                                               .WithField("a", IntTy(2, true))
                                               .WithField("b", StringTy(4))
                                               .WithField("c", IntTy(4))
                                               .WithField("d", IntTy(2, true))),
                                       _),
                    _ }),
            Probe(_, { _, _ }) }) });

  auto $a_assign_stmt = AssignVarStatement(
      Variable("$a").WithType(SizedType(Type::record)
                                  .WithField("a", IntTy(8, true))
                                  .WithField("b", StringTy(10))
                                  .WithField("c", IntTy(4))
                                  .WithField("d", IntTy(2, true))),
      _);
  test(
      R"(
      begin {
        $a = (d=1, c=2, b="longerstr", a=(int64)1);
        $a = (a=@b, b=@c[0], c=(typeof(@c))3, d=(typeof({ print(1); @b }))10); @b = 1;
      }
      end { @c[(uint32)2] = "str"; @b = (int16)2; })",
      ExpectedAST{ Program().WithProbes(
          { Probe(_, { $a_assign_stmt, $a_assign_stmt, _ }),
            Probe(_, { _, _ }) }) });
}

TEST_F(TypeGraphTest, comptime)
{
  test(
      R"(begin { let $c; $a = 1; if comptime (typeinfo($a).full_type == "uint64") { $c = (int64)2; } $a = (uint64)2; })",
      ExpectedAST{ Program().WithProbe(
          Probe(_,
                { VarDeclStatement(IntVar("$c", 8, true)),
                  AssignVarStatement(IntVar("$a", 8), _),
                  ExprStatement(
                      Block({ AssignVarStatement(IntVar("$c", 8, true), _) })),
                  AssignVarStatement(IntVar("$a", 8), _) })) });

  test(
      R"(begin { let $c; $a = 1; if comptime (typeinfo(sizeof($a)).base_type == "int") { $c = (int64)2; } $a = (uint64)2; })",
      ExpectedAST{ Program().WithProbe(
          Probe(_,
                { VarDeclStatement(IntVar("$c", 8, true)),
                  AssignVarStatement(IntVar("$a", 8), _),
                  ExprStatement(
                      Block({ AssignVarStatement(IntVar("$c", 8, true), _) })),
                  AssignVarStatement(IntVar("$a", 8), _) })) });

  test(
      R"(begin { let $c; $a = 1; if comptime (typeinfo($a).full_type == "uint64") { let $d; if comptime (typeinfo($d).full_type == "int64") { $c = (int16)3; } $d = (int64)2; } $a = (uint64)2; })",
      ExpectedAST{ Program().WithProbe(
          Probe(_, { VarDeclStatement(IntVar("$c", 2, true)), _, _, _ })) });

  test(
      R"(begin { let $c; let $e; let $d; $a = 1; if comptime (typeinfo($a).full_type == "uint64") { if comptime (typeinfo($d).full_type == "int64") { $c = (int16)3; } $e = (int32)1; } $a = (uint64)2; if comptime (typeinfo($e).full_type == "int32") { $d = (int64)3; } })",
      ExpectedAST{ Program().WithProbe(Probe(
          _, { VarDeclStatement(IntVar("$c", 2, true)), _, _, _, _, _, _ })) });

  test(
      R"(begin { let $c; if comptime (typeinfo($c).base_type == "int") { 1 } })",
      Error{ R"(
ERROR: Unable to resolve comptime expression
begin { let $c; if comptime (typeinfo($c).base_type == "int") { 1 } }
                   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
)" });

  test(
      R"(begin { let $c; if comptime (typeinfo({ let $x = $c; $x }).full_type == "uint32") { $c = (uint64)2; } $c = (uint32)1; })",
      Error{});
  test(
      R"(begin { @x = 1; if comptime (typeinfo(@y[1]).full_type == "uint64") { @x = (int32)2; } } end { @y[1] = (uint64)2; })",
      ExpectedAST{ Program().WithProbes(
          { Probe(_,
                  { AssignMapStatement(IntMapValue("@x", 4, true), _, _), _ }),
            Probe(_, { AssignMapStatement(IntMapValue("@y", 8), _, _) }) }) });
  test(
      R"(begin { @x = 1; if comptime (typeinfo(@y[1]).full_type != "uint64") { @x = (int32)2; } } end { @y[1] = (uint64)2; })",
      ExpectedAST{ Program().WithProbes(
          { Probe(_, { AssignMapStatement(IntMapValue("@x", 1), _, _) }),
            Probe(_, { AssignMapStatement(IntMapValue("@y", 8), _, _) }) }) });
}

TEST_F(TypeGraphTest, locked_types)
{
  test(
      R"(begin { if comptime (typeinfo(@a).full_type == "uint32") { @a = 2; } @a = (uint32)1; })");
  test(
      R"(begin { if comptime (typeinfo(@a).full_type == "uint32") { @a[2] = 2; } @a[(uint32)1] = 1; })");
  test(
      R"(begin { let $c; if comptime (typeinfo($c).full_type == "uint32") { $c = (uint16)2; } $c = (uint32)1; })");

  test(
      R"(begin { let $c; if comptime (typeinfo($c).full_type == "uint32") { $c = (uint64)2; } $c = (uint32)1; })",
      Error{});

  test(
      R"(begin { if comptime (typeinfo(@a).full_type == "uint32") { @a = (uint64)2; } @a = (uint32)1; })",
      Error{});

  test(
      R"(begin { if comptime (typeinfo(@a).full_type == "uint32") { @a[(uint64)2] = 2; } @a[(uint32)1] = 1; })",
      Error{ R"(
ERROR: Type mismatch for @a: this type has been locked because it was used in another part of the type graph that was already resolved (e.g. `sizeof`, `typeinfo`, etc.). The new type 'uint64' doesn't fit into the locked type 'uint32'
begin { if comptime (typeinfo(@a).full_type == "uint32") { @a[(uint64)2] = 2; } @a[(uint32)1] = 1; }
                                                           ~~~~~~~~~~~~~
)" });
}

TEST_F(TypeGraphTest, variable_addr)
{
  test(R"(begin { $a = 1; $b = &$a; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { _,
                   AssignVarStatement(
                       Variable("$b").WithType(
                           SizedType(Type::pointer).WithElement(IntTy(1))),
                       _) })) });

  test(R"(begin { $a = "str"; $b = &$a; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { _,
                   AssignVarStatement(
                       Variable("$b").WithType(
                           SizedType(Type::pointer).WithElement(StringTy(4))),
                       _) })) });

  test(R"(begin { let $a; $b = &$a; $a = (uint64)1; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { _,
                   AssignVarStatement(
                       Variable("$b").WithType(
                           SizedType(Type::pointer).WithElement(IntTy(8))),
                       _),
                   _ })) });

  // Same source and a promotion - ok
  test(R"(begin { $a = (uint32)2; $b = &$a; $a = (int32)1; })",
       ExpectedAST{ Program().WithProbe(Probe(
           _,
           { _,
             AssignVarStatement(
                 Variable("$b").WithType(
                     SizedType(Type::pointer).WithElement(IntTy(8, true))),
                 _),
             _ })) });
  test(R"(begin { $a = (uint32)2; @b = &$a; $a = (int32)1; })",
       ExpectedAST{ Program().WithProbe(Probe(
           _,
           { _,
             AssignMapStatement(
                 Map("@b").WithType(
                     SizedType(Type::pointer).WithElement(IntTy(8, true))),
                 _,
                 _),
             _ })) });
  test(R"(begin { $a = (uint32)2; @b[&$a] = 1; $a = (int32)1; })",
       ExpectedAST{ Program().WithProbe(Probe(
           _,
           { _,
             AssignMapStatement(
                 Map("@b").WithKeyType(
                     SizedType(Type::pointer).WithElement(IntTy(8, true))),
                 _,
                 _),
             _ })) });

  // Two different sources of different sizes - not ok
  test(R"(begin { $a = (int16)2; $b = &$a; $c = (int32)1; $b = &$c; })",
       Error{});
  test(R"(begin { $a = (int16)2; @b = &$a; $c = (int32)1; @b = &$c; })",
       Error{});
  test(R"(begin { $a = (int16)2; @b[&$a] = 1; $c = (int32)1; @b[&$c] = 1; })",
       Error{});

  // Two different sources and same size - ok
  test(R"(begin { $a = (int16)2; $b = &$a; $c = (int16)1; $b = &$c; })");
  test(R"(begin { $a = (int16)2; @b = &$a; $c = (int16)1; @b = &$c; })");
  test(R"(begin { $a = (int16)2; @b[&$a] = 1; $c = (int16)1; @b[&$c] = 1; })");

  // Two different sources and a promotion - not ok
  test(
      R"(begin { $a = (int16)2; $b = &$a; $c = (int16)1; $b = &$c; $a = (int32)3; })",
      Error{});
  test(
      R"(begin { $a = (int16)2; @b = &$a; $c = (int16)1; @b = &$c; $a = (int32)3; })",
      Error{});
  test(
      R"(begin { $a = (int16)2; @b[&$a] = 1; $c = (int16)1; @b[&$c] = 1; $a = (int32)3; })",
      Error{});
}

TEST_F(TypeGraphTest, map_addr)
{
  test(R"(begin { @a = 1; $b = &@a; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { _,
                   AssignVarStatement(
                       Variable("$b").WithType(
                           SizedType(Type::pointer).WithElement(IntTy(1))),
                       _) })) });

  test(R"(begin { @a = "str"; $b = &@a; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { _,
                   AssignVarStatement(
                       Variable("$b").WithType(
                           SizedType(Type::pointer).WithElement(StringTy(4))),
                       _) })) });

  test(R"(begin { $b = &@a; @a = (uint64)1; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignVarStatement(
                       Variable("$b").WithType(
                           SizedType(Type::pointer).WithElement(IntTy(8))),
                       _),
                   _ })) });

  // Same source and a promotion - ok
  test(R"(begin { @a = (int32)1; $b = &@a; @a = (uint32)1; })",
       ExpectedAST{ Program().WithProbe(Probe(
           _,
           { _,
             AssignVarStatement(
                 Variable("$b").WithType(
                     SizedType(Type::pointer).WithElement(IntTy(8, true))),
                 _),
             _ })) });
  test(R"(begin { @a = (int32)1; @b = &@a; @a = (uint32)1; })",
       ExpectedAST{ Program().WithProbe(Probe(
           _,
           { _,
             AssignMapStatement(
                 Map("@b").WithType(
                     SizedType(Type::pointer).WithElement(IntTy(8, true))),
                 _,
                 _),
             _ })) });
  test(R"(begin { @a = (int32)1; @b[&@a] = 1; @a = (uint32)1; })",
       ExpectedAST{ Program().WithProbe(Probe(
           _,
           { _,
             AssignMapStatement(
                 Map("@b").WithKeyType(
                     SizedType(Type::pointer).WithElement(IntTy(8, true))),
                 _,
                 _),
             _ })) });

  // Two different sources of different sizes - not ok
  test(R"(begin { @a = (int16)2; $b = &@a; @c = (int32)1; $b = &@c; })",
       Error{});
  test(R"(begin { @a = (int16)2; @b = &@a; @c = (int32)1; @b = &@c; })",
       Error{});
  test(R"(begin { @a = (int16)2; @b[&@a] = 1; @c = (int32)1; @b[&@c] = 1; })",
       Error{});

  // Two different sources and same size - ok
  test(R"(begin { @a = (int16)2; $b = &@a; @c = (int16)1; $b = &@c; })");
  test(R"(begin { @a = (int16)2; @b = &@a; @c = (int16)1; @b = &@c; })");
  test(R"(begin { @a = (int16)2; @b[&@a] = 1; @c = (int16)1; @b[&@c] = 1; })");

  // Two different sources and a promotion - not ok
  test(
      R"(begin { @a = (int16)2; $b = &@a; $c = (int16)1; $b = &$c; @a = (int32)3; })",
      Error{});
  test(
      R"(begin { @a = (int16)2; @b = &@a; $c = (int16)1; @b = &$c; @a = (int32)3; })",
      Error{});
  test(
      R"(begin { @a = (int16)2; @b[&@a] = 1; $c = (int16)1; @b[&$c] = 1; @a = (int32)3; })",
      Error{});
}

TEST_F(TypeGraphTest, unop)
{
  test(R"(begin { @a = (int16)2; ++@a; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_,
                 { AssignMapStatement(IntMapValue("@a", 8, true), _, _),
                   ExprStatement(Unop(Operator::PRE_INCREMENT, _)
                                     .WithType(IntTy(8, true))) })) });

  test(R"(begin { ++@a; $b = @a; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { _, AssignVarStatement(IntVar("$b", 8, true), _) })) });

  test(R"(begin { $a = 1; ++$a; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignVarStatement(IntVar("$a", 8, true), _), _ })) });

  test(R"(begin { ++$a; $a = 1; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { _, AssignVarStatement(IntVar("$a", 8, true), _) })) });

  test(R"(begin { let $a; ++$a; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { VarDeclStatement(IntVar("$a", 8, true)), _ })) });

  test(R"(begin { $a = 1; $b = &$a; $c = *$b; $a = (uint32)2; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { _, _, AssignVarStatement(IntVar("$c", 4), _), _ })) });

  // Errors
  test(R"(begin { ++@a; @a = "hello"; })", Error{});
  test(R"(begin { ++$a; $a = "hello"; })", Error{});
}

TEST_F(TypeGraphTest, builtin)
{
  // Just a few basic sanity tests
  test(R"(begin { $a = pid; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignVarStatement(IntVar("$a", 4), _) })) });

  test(R"(begin { $a = __builtin_cpu; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignVarStatement(IntVar("$a", 8), _) })) });
}

TEST_F(TypeGraphTest, tuple_access)
{
  test(R"(begin { $a = (1, 2).0; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { AssignVarStatement(IntVar("$a", 1), _) })) });

  test(R"(begin { $b = (1, (int64)2); $a = $b.1; })",
       ExpectedAST{ Program().WithProbe(
           Probe(_, { _, AssignVarStatement(IntVar("$a", 8, true), _) })) });
}

TEST_F(TypeGraphTest, jordan)
{
  //
}

} // namespace bpftrace::test::type_graph
