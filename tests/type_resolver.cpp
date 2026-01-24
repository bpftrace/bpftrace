#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>

#include "ast/ast.h"
#include "ast/passes/builtins.h"
#include "ast/passes/clang_parser.h"
#include "ast/passes/collect_nodes.h"
#include "ast/passes/fold_literals.h"
#include "ast/passes/macro_expansion.h"
#include "ast/passes/map_sugar.h"
#include "ast/passes/named_param.h"
#include "ast/passes/type_resolver.h"
#include "ast/passes/type_system.h"
#include "bpftrace.h"
#include "driver.h"
#include "mocks.h"

namespace bpftrace::test::type_resolver {

using ::testing::HasSubstr;

// Lightweight type query helpers — look up resolved types on AST nodes by name,
// avoiding the need for full AST structure matchers.
::bpftrace::SizedType var_type(ast::ASTContext &ast, const std::string &name)
{
  ast::CollectNodes<ast::Variable> collector;
  collector.visit(*ast.root,
                  [&](const ast::Variable &v) { return v.ident == name; });
  if (collector.nodes().empty()) {
    ADD_FAILURE() << "No variable named " << name;
    return CreateNone();
  }
  return collector.nodes().front().get().var_type;
}

::bpftrace::SizedType map_val_type(ast::ASTContext &ast,
                                   const std::string &name)
{
  ast::CollectNodes<ast::Map> collector;
  collector.visit(*ast.root,
                  [&](const ast::Map &m) { return m.ident == name; });
  if (collector.nodes().empty()) {
    ADD_FAILURE() << "No map named " << name;
    return CreateNone();
  }
  return collector.nodes().front().get().value_type;
}

::bpftrace::SizedType map_key_type(ast::ASTContext &ast,
                                   const std::string &name)
{
  ast::CollectNodes<ast::Map> collector;
  collector.visit(*ast.root,
                  [&](const ast::Map &m) { return m.ident == name; });
  if (collector.nodes().empty()) {
    ADD_FAILURE() << "No map named " << name;
    return CreateNone();
  }
  return collector.nodes().front().get().key_type;
}

struct Error {
  std::string_view str;
};

std::string_view clean_prefix(std::string_view view)
{
  while (!view.empty() && view[0] == '\n')
    view.remove_prefix(1); // Remove initial '\n'
  return view;
}

class TypeResolverHarness {
public:
  ast::ASTContext test(std::string_view input,
                       std::optional<Error> error = std::nullopt)
  {
    ast::ASTContext ast("stdin", std::string(clean_prefix(input)));

    ast::TypeMetadata no_types; // No external types defined.
    auto mock_bpftrace = get_mock_bpftrace();
    BPFtrace &bpftrace = *mock_bpftrace;

    auto ok = ast::PassManager()
                  .put(ast)
                  .put(bpftrace)
                  .put(no_types)
                  .add(CreateParsePass())
                  .add(ast::CreateMacroExpansionPass())
                  .add(ast::CreateClangParsePass())
                  .add(ast::CreateFoldLiteralsPass())
                  .add(ast::CreateBuiltinsPass())
                  .add(ast::CreateMapSugarPass())
                  .add(ast::CreateNamedParamsPass())
                  .add(ast::CreateTypeResolverPass())
                  .run();
    EXPECT_TRUE(bool(ok));

    std::stringstream out;
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

    return ast;
  }
};

class TypeResolverTest : public TypeResolverHarness, public testing::Test {};

TEST_F(TypeResolverTest, variable_promotion_integers)
{
  {
    auto ast = test(R"(begin { $a = 1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt8());
  }
  {
    auto ast = test(R"(begin { $a = -1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt8());
  }
  {
    auto ast = test(R"(begin { $a = 1; $a = (uint32)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt32());
  }
  {
    auto ast = test(R"(begin { $a = (int8)1; $a = (uint8)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt16());
  }
  {
    auto ast = test(R"(begin { $a = (uint32)1; $a = (int32)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { $a = (uint32)1; $b = (int32)2; $a = $b; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { let $v; $a = $v; $v = 10; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt8());
    EXPECT_EQ(var_type(ast, "$v"), CreateUInt8());
  }

  // Errors
  test(R"(begin { $a = (uint64)1; $a = (int64)2 })", Error{});
}

TEST_F(TypeResolverTest, variable_promotion_strings)
{
  {
    auto ast = test(R"(begin { $a = "str"; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateString(4));
  }
  {
    auto ast = test(R"(begin { $a = "str"; $a = "longer" })");
    EXPECT_EQ(var_type(ast, "$a"), CreateString(7));
  }
  {
    auto ast = test(R"(begin { $a = "str"; $b = "longer"; $a = $b; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateString(7));
  }
}

TEST_F(TypeResolverTest, variable_promotion_tuples)
{
  {
    auto ast = test(R"(begin { $a = (1, "str"); })");
    EXPECT_EQ(var_type(ast, "$a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt8(), CreateString(4) })));
  }
  {
    auto ast = test(
        R"(begin { $a = ((uint32)1, "str"); $a = (1, "longer"); })");
    EXPECT_EQ(var_type(ast, "$a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt32(), CreateString(7) })));
  }
  {
    auto ast = test(
        R"(begin { $a = ((uint32)1, "str"); $a = (1, "longer"); $a = ((int64)1, "a"); })");
    EXPECT_EQ(var_type(ast, "$a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateInt64(), CreateString(7) })));
  }
  {
    auto ast = test(
        R"(begin { $a = ((uint32)1, ("str", (int16)2)); $a = (1, ("longer", (uint16)2)); })");
    auto nested_tuple = CreateTuple(
        Struct::CreateTuple({ CreateString(7), CreateInt32() }));
    EXPECT_EQ(var_type(ast, "$a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt32(), nested_tuple })));
  }
  {
    auto ast = test(
        R"(begin { $a = ((uint32)1, (x="str", y=(int16)2)); $a = (1, (x="longer", y=(uint16)2)); })");
    auto nested_record = CreateRecord(
        Struct::CreateRecord({ CreateString(7), CreateInt32() }, { "x", "y" }));
    EXPECT_EQ(var_type(ast, "$a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt32(), nested_record })));
  }
  {
    auto ast = test(
        R"(begin { $b = ("str", (int16)2); $a = ((uint32)1, $b); $c = ("longer", (uint16)2); $a = (1, $c); })");
    auto nested_tuple = CreateTuple(
        Struct::CreateTuple({ CreateString(7), CreateInt32() }));
    EXPECT_EQ(var_type(ast, "$a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt32(), nested_tuple })));
    // Make sure the referenced variables don't change size
    EXPECT_EQ(var_type(ast, "$b"),
              CreateTuple(
                  Struct::CreateTuple({ CreateString(4), CreateInt16() })));
    EXPECT_EQ(var_type(ast, "$c"),
              CreateTuple(
                  Struct::CreateTuple({ CreateString(7), CreateUInt16() })));
  }

  // Errors
  test(
      R"(begin { $a = ((uint64)1, "str"); $a = (1, "longer"); $a = ((int64)1, "a"); })",
      Error{});
  test(
      R"(begin { $a = (1, ("str", (uint64)2)); $a = (1, ("longer", (int64)2)); })",
      Error{});
}

TEST_F(TypeResolverTest, variable_promotion_records)
{
  {
    auto ast = test(R"(begin { $a = (x = 1, y = "str"); })");
    EXPECT_EQ(var_type(ast, "$a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateUInt8(), CreateString(4) }, { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { $a = (x = (uint32)1, y = "str"); $a = (x = 1, y = "longer"); })");
    EXPECT_EQ(var_type(ast, "$a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateUInt32(), CreateString(7) }, { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { $a = (x = (uint32)1, y = "str"); $a = (y = "longer", x = (int32)1); })");
    EXPECT_EQ(var_type(ast, "$a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateInt64(), CreateString(7) }, { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { $a = (x = (uint32)1, y = "str"); $a = (x = 1, y = "longer"); $a = (x = (int64)1, y = "a"); })");
    EXPECT_EQ(var_type(ast, "$a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateInt64(), CreateString(7) }, { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { $a = (x = (uint32)1, y = (s = "str", n = (int16)2)); $a = (x = 1, y = (s = "longer", n = (uint16)2)); })");
    auto nested = CreateRecord(
        Struct::CreateRecord({ CreateString(7), CreateInt32() }, { "s", "n" }));
    EXPECT_EQ(var_type(ast, "$a"),
              CreateRecord(Struct::CreateRecord({ CreateUInt32(), nested },
                                                { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { $a = (x = (uint32)1, y = ("str", (int16)2)); $a = (x = (int32)1, y = ("longer", (uint16)2)); })");
    EXPECT_EQ(var_type(ast, "$a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateInt64(),
                    CreateTuple(Struct::CreateTuple(
                        { CreateString(7), CreateInt32() })) },
                  { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { $b = (s = "str", n = (int16)2); $a = (x = (uint32)1, y = $b); $c = (s = "longer", n = (uint16)2); $a = (x = 1, y = $c); })");
    auto nested_record = CreateRecord(
        Struct::CreateRecord({ CreateString(7), CreateInt32() }, { "s", "n" }));
    EXPECT_EQ(var_type(ast, "$a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateUInt32(), nested_record }, { "x", "y" })));
    // Make sure the referenced variables don't change size
    EXPECT_EQ(var_type(ast, "$b"),
              CreateRecord(Struct::CreateRecord(
                  { CreateString(4), CreateInt16() }, { "s", "n" })));
    EXPECT_EQ(var_type(ast, "$c"),
              CreateRecord(Struct::CreateRecord(
                  { CreateString(7), CreateUInt16() }, { "s", "n" })));
  }

  // Errors
  test(
      R"(begin { $a = (x = (uint64)1, y = "str"); $a = (x = 1, y = "longer"); $a = (x = (int64)1, y = "a"); })",
      Error{});
  test(
      R"(begin { $a = (x = 1, y = (s = "str", n = (uint64)2)); $a = (x = 1, y = (s = "longer", n = (int64)2)); })",
      Error{});
}

TEST_F(TypeResolverTest, variable_castable_maps)
{
  {
    auto ast = test(R"(begin { @a = sum(1); $a = @a; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt64());
  }
  {
    auto ast = test(R"(begin { @a = sum(-1); $a = @a; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { @a = sum(1); @a = sum(-1); $a = @a; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { @a = sum(-1); $a = (int16)2; $a = @a; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
  }

  // Errors
  test(R"(begin { @a = sum(1); $a = (int64)1; $a = @a; })", Error{});
}

TEST_F(TypeResolverTest, map_value_promotion_integers)
{
  {
    auto ast = test(R"(begin { @a = 1; })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateUInt8());
  }
  {
    auto ast = test(R"(begin { @a = -1; })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateInt8());
  }
  {
    auto ast = test(R"(begin { @a = 1; @a = (uint32)2; })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateUInt32());
  }
  {
    auto ast = test(R"(begin { @a = (int8)1; @a = (uint8)2; })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateInt16());
  }
  {
    auto ast = test(R"(begin { @a = (uint32)1; @a = (int32)2; })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { @a = (uint32)1; $b = (int32)2; @a = $b; })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { let $v; @a = $v; $v = 10; })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateUInt8());
    EXPECT_EQ(var_type(ast, "$v"), CreateUInt8());
  }

  // Errors
  test(R"(begin { @a = (uint64)1; @a = (int64)2 })", Error{});
}

TEST_F(TypeResolverTest, map_value_promotion_strings)
{
  {
    auto ast = test(R"(begin { @a = "str"; })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateString(4));
  }
  {
    auto ast = test(R"(begin { @a = "str"; @a = "longer" })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateString(7));
  }
  {
    auto ast = test(R"(begin { @a = "str"; $b = "longer"; @a = $b; })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateString(7));
  }
}

TEST_F(TypeResolverTest, map_value_promotion_tuples)
{
  {
    auto ast = test(R"(begin { @a = (1, "str"); })");
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt8(), CreateString(4) })));
  }
  {
    auto ast = test(
        R"(begin { @a = ((uint32)1, "str"); @a = (1, "longer"); })");
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt32(), CreateString(7) })));
  }
  {
    auto ast = test(
        R"(begin { @a = ((uint32)1, "str"); @a = (1, "longer"); @a = ((int64)1, "a"); })");
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateInt64(), CreateString(7) })));
  }
  {
    auto ast = test(
        R"(begin { @a = ((uint32)1, ("str", (int16)2)); @a = (1, ("longer", (uint16)2)); })");
    auto nested_tuple = CreateTuple(
        Struct::CreateTuple({ CreateString(7), CreateInt32() }));
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt32(), nested_tuple })));
  }
  {
    auto ast = test(
        R"(begin { @a = ((uint32)1, (x="str", y=(int16)2)); @a = (1, (x="longer", y=(uint16)2)); })");
    auto nested_record = CreateRecord(
        Struct::CreateRecord({ CreateString(7), CreateInt32() }, { "x", "y" }));
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt32(), nested_record })));
  }
  {
    auto ast = test(
        R"(begin { $b = ("str", (int16)2); @a = ((uint32)1, $b); $c = ("longer", (uint16)2); @a = (1, $c); })");
    auto nested_tuple = CreateTuple(
        Struct::CreateTuple({ CreateString(7), CreateInt32() }));
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt32(), nested_tuple })));
    // Make sure the referenced variables don't change size
    EXPECT_EQ(var_type(ast, "$b"),
              CreateTuple(
                  Struct::CreateTuple({ CreateString(4), CreateInt16() })));
    EXPECT_EQ(var_type(ast, "$c"),
              CreateTuple(
                  Struct::CreateTuple({ CreateString(7), CreateUInt16() })));
  }

  // Errors
  test(
      R"(begin { @a = ((uint64)1, "str"); @a = (1, "longer"); @a = ((int64)1, "a"); })",
      Error{});
  test(
      R"(begin { @a = (1, ("str", (uint64)2)); @a = (1, ("longer", (int64)2)); })",
      Error{});
}

TEST_F(TypeResolverTest, map_value_promotion_records)
{
  {
    auto ast = test(R"(begin { @a = (x = 1, y = "str"); })");
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateUInt8(), CreateString(4) }, { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { @a = (x = (uint32)1, y = "str"); @a = (x = 1, y = "longer"); })");
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateUInt32(), CreateString(7) }, { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { @a = (x = (uint32)1, y = "str"); @a = (y = "longer", x = (int32)1); })");
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateInt64(), CreateString(7) }, { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { @a = (x = (uint32)1, y = "str"); @a = (x = 1, y = "longer"); @a = (x = (int64)1, y = "a"); })");
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateInt64(), CreateString(7) }, { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { @a = (x = (uint32)1, y = (s = "str", n = (int16)2)); @a = (x = 1, y = (s = "longer", n = (uint16)2)); })");
    auto nested = CreateRecord(
        Struct::CreateRecord({ CreateString(7), CreateInt32() }, { "s", "n" }));
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord({ CreateUInt32(), nested },
                                                { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { @a = (x = (uint32)1, y = ("str", (int16)2)); @a = (x = (int32)1, y = ("longer", (uint16)2)); })");
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateInt64(),
                    CreateTuple(Struct::CreateTuple(
                        { CreateString(7), CreateInt32() })) },
                  { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { $b = (s = "str", n = (int16)2); @a = (x = (uint32)1, y = $b); $c = (s = "longer", n = (uint16)2); @a = (x = 1, y = $c); })");
    auto nested_record = CreateRecord(
        Struct::CreateRecord({ CreateString(7), CreateInt32() }, { "s", "n" }));
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateUInt32(), nested_record }, { "x", "y" })));
    // Make sure the referenced variables don't change size
    EXPECT_EQ(var_type(ast, "$b"),
              CreateRecord(Struct::CreateRecord(
                  { CreateString(4), CreateInt16() }, { "s", "n" })));
    EXPECT_EQ(var_type(ast, "$c"),
              CreateRecord(Struct::CreateRecord(
                  { CreateString(7), CreateUInt16() }, { "s", "n" })));
  }
  {
    auto ast = test(
        R"(begin { @b = (s = "str", n = (int16)2); @a = (x = (uint32)1, y = @b); @c = (s = "longer", n = (uint16)2); @a = (x = 1, y = @c); })");
    auto nested_record = CreateRecord(
        Struct::CreateRecord({ CreateString(7), CreateInt32() }, { "s", "n" }));
    EXPECT_EQ(map_val_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateUInt32(), nested_record }, { "x", "y" })));
    // Make sure the referenced map values don't change size
    EXPECT_EQ(map_val_type(ast, "@b"),
              CreateRecord(Struct::CreateRecord(
                  { CreateString(4), CreateInt16() }, { "s", "n" })));
    EXPECT_EQ(map_val_type(ast, "@c"),
              CreateRecord(Struct::CreateRecord(
                  { CreateString(7), CreateUInt16() }, { "s", "n" })));
  }

  // Errors
  test(
      R"(begin { @a = (x = (uint64)1, y = "str"); @a = (x = 1, y = "longer"); @a = (x = (int64)1, y = "a"); })",
      Error{});
  test(
      R"(begin { @a = (x = 1, y = (s = "str", n = (uint64)2)); @a = (x = 1, y = (s = "longer", n = (int64)2)); })",
      Error{});
}

TEST_F(TypeResolverTest, map_value_castable_maps)
{
  {
    auto ast = test(R"(begin { @a = sum(1); })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateSum(false));
  }
  {
    auto ast = test(R"(begin { @a = sum(-1); })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateSum(true));
  }
  {
    auto ast = test(R"(begin { @a = sum(1); @a = sum(-1); })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateSum(true));
  }

  // Errors
  test(R"(begin { @a = sum(1); @a = avg(-1); })", Error{});
  test(R"(begin { @a = sum(1); @a = 1; })", Error{});
  test(R"(begin { @a = sum((uint64)1); @a = sum((int64)-1); })", Error{});
}

TEST_F(TypeResolverTest, map_key_promotion_integers)
{
  {
    auto ast = test(R"(begin { @a[1] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"), CreateUInt8());
  }
  {
    auto ast = test(R"(begin { @a[-1] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"), CreateInt8());
  }
  {
    auto ast = test(R"(begin { @a[1] = 1; @a[(uint32)2] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"), CreateUInt32());
  }
  {
    auto ast = test(R"(begin { @a[(int8)1] = 1; @a[(uint8)2] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"), CreateInt16());
  }
  {
    auto ast = test(R"(begin { @a[(uint32)1] = 1; @a[(int32)2] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"), CreateInt64());
  }
  {
    auto ast = test(
        R"(begin { @a[(uint32)1] = 1; $b = (int32)2; @a[$b] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"), CreateInt64());
  }

  // Errors
  test(R"(begin { @a[(uint64)1] = 1; @a[(int64)2] = 1 })", Error{});
}

TEST_F(TypeResolverTest, map_key_promotion_strings)
{
  {
    auto ast = test(R"(begin { @a["str"] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"), CreateString(4));
  }
  {
    auto ast = test(R"(begin { @a["str"] = 1; @a["longer"] = 1 })");
    EXPECT_EQ(map_key_type(ast, "@a"), CreateString(7));
  }
  {
    auto ast = test(R"(begin { @a["str"] = 1; $b = "longer"; @a[$b] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"), CreateString(7));
  }
}

TEST_F(TypeResolverTest, map_key_promotion_tuples)
{
  {
    auto ast = test(R"(begin { @a[(1, "str")] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt8(), CreateString(4) })));
  }
  {
    auto ast = test(
        R"(begin { @a[((uint32)1, "str")] = 1; @a[(1, "longer")] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt32(), CreateString(7) })));
  }
  {
    auto ast = test(
        R"(begin { @a[((uint32)1, "str")] = 1; @a[(1, "longer")] = 1; @a[((int64)1, "a")] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateInt64(), CreateString(7) })));
  }
  {
    auto ast = test(
        R"(begin { @a[((uint32)1, ("str", (int16)2))] = 1; @a[(1, ("longer", (uint16)2))] = 1; })");
    auto nested_tuple = CreateTuple(
        Struct::CreateTuple({ CreateString(7), CreateInt32() }));
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt32(), nested_tuple })));
  }
  {
    auto ast = test(
        R"(begin { @a[((uint32)1, (x="str", y=(int16)2))] = 1; @a[(1, (x="longer", y=(uint16)2))] = 1; })");
    auto nested_record = CreateRecord(
        Struct::CreateRecord({ CreateString(7), CreateInt32() }, { "x", "y" }));
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt32(), nested_record })));
  }
  {
    auto ast = test(
        R"(begin { $b = ("str", (int16)2); @a[((uint32)1, $b)] = 1; $c = ("longer", (uint16)2); @a[(1, $c)] = 1; })");
    auto nested_tuple = CreateTuple(
        Struct::CreateTuple({ CreateString(7), CreateInt32() }));
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateTuple(
                  Struct::CreateTuple({ CreateUInt32(), nested_tuple })));
    // Make sure the referenced variables don't change size
    EXPECT_EQ(var_type(ast, "$b"),
              CreateTuple(
                  Struct::CreateTuple({ CreateString(4), CreateInt16() })));
    EXPECT_EQ(var_type(ast, "$c"),
              CreateTuple(
                  Struct::CreateTuple({ CreateString(7), CreateUInt16() })));
  }

  // Errors
  test(
      R"(begin { @a[((uint64)1, "str")] = 1; @a[(1, "longer")] = 1; @a[((int64)1, "a")] = 1; })",
      Error{});
  test(
      R"(begin { @a[(1, ("str", (uint64)2))] = 1; @a[(1, ("longer", (int64)2))] = 1; })",
      Error{});
}

TEST_F(TypeResolverTest, map_key_promotion_records)
{
  {
    auto ast = test(R"(begin { @a[(x = 1, y = "str")] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateUInt8(), CreateString(4) }, { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { @a[(x = (uint32)1, y = "str")] = 1; @a[(x = 1, y = "longer")] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateUInt32(), CreateString(7) }, { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { @a[(x = (uint32)1, y = "str")] = 1; @a[(y = "longer", x = (int32)1)] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateInt64(), CreateString(7) }, { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { @a[(x = (uint32)1, y = "str")] = 1; @a[(x = 1, y = "longer")] = 1; @a[(x = (int64)1, y = "a")] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateInt64(), CreateString(7) }, { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { @a[(x = (uint32)1, y = (s = "str", n = (int16)2))] = 1; @a[(x = 1, y = (s = "longer", n = (uint16)2))] = 1; })");
    auto nested = CreateRecord(
        Struct::CreateRecord({ CreateString(7), CreateInt32() }, { "s", "n" }));
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord({ CreateUInt32(), nested },
                                                { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { @a[(x = (uint32)1, y = ("str", (int16)2))] = 1; @a[(x = (int32)1, y = ("longer", (uint16)2))] = 1; })");
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateInt64(),
                    CreateTuple(Struct::CreateTuple(
                        { CreateString(7), CreateInt32() })) },
                  { "x", "y" })));
  }
  {
    auto ast = test(
        R"(begin { $b = (s = "str", n = (int16)2); @a[(x = (uint32)1, y = $b)] = 1; $c = (s = "longer", n = (uint16)2); @a[(x = 1, y = $c)] = 1; })");
    auto nested_record = CreateRecord(
        Struct::CreateRecord({ CreateString(7), CreateInt32() }, { "s", "n" }));
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateUInt32(), nested_record }, { "x", "y" })));
    // Make sure the referenced variables don't change size
    EXPECT_EQ(var_type(ast, "$b"),
              CreateRecord(Struct::CreateRecord(
                  { CreateString(4), CreateInt16() }, { "s", "n" })));
    EXPECT_EQ(var_type(ast, "$c"),
              CreateRecord(Struct::CreateRecord(
                  { CreateString(7), CreateUInt16() }, { "s", "n" })));
  }
  {
    auto ast = test(
        R"(begin { @b = (s = "str", n = (int16)2); @a[(x = (uint32)1, y = @b)] = 1; @c = (s = "longer", n = (uint16)2); @a[(x = 1, y = @c)] = 1; })");
    auto nested_record = CreateRecord(
        Struct::CreateRecord({ CreateString(7), CreateInt32() }, { "s", "n" }));
    EXPECT_EQ(map_key_type(ast, "@a"),
              CreateRecord(Struct::CreateRecord(
                  { CreateUInt32(), nested_record }, { "x", "y" })));
    // Make sure the referenced map values don't change size
    EXPECT_EQ(map_val_type(ast, "@b"),
              CreateRecord(Struct::CreateRecord(
                  { CreateString(4), CreateInt16() }, { "s", "n" })));
    EXPECT_EQ(map_val_type(ast, "@c"),
              CreateRecord(Struct::CreateRecord(
                  { CreateString(7), CreateUInt16() }, { "s", "n" })));
  }

  // Errors
  test(
      R"(begin { @a[(x = (uint64)1, y = "str")] = 1; @a[(x = 1, y = "longer")] = 1; @a[(x = (int64)1, y = "a")] = 1; })",
      Error{});
  test(
      R"(begin { @a[(x = 1, y = (s = "str", n = (uint64)2))] = 1; @a[(x = 1, y = (s = "longer", n = (int64)2))] = 1; })",
      Error{});
}

TEST_F(TypeResolverTest, variable_no_type)
{
  test(R"(begin { let $z; $a = 1; $b = typeinfo($z); })", Error{ R"(
ERROR: Could not resolve the type of this variable
begin { let $z; $a = 1; $b = typeinfo($z); }
            ~~
stdin:1:25-27: ERROR: Could not resolve the type of this variable
begin { let $z; $a = 1; $b = typeinfo($z); }
                        ~~
stdin:1:39-41: ERROR: Could not resolve the type of this variable
begin { let $z; $a = 1; $b = typeinfo($z); }
                                      ~~
)" });

  test(R"(begin { let $a; let $b; $b = $a; $a = $b; })", Error{});
}

TEST_F(TypeResolverTest, variable_with_type_decl)
{
  {
    auto ast = test(R"(begin { let $a: uint32 = 1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt32());
  }
  {
    auto ast = test(
        R"(begin { let $b; let $a: typeof($b) = (uint64)1; $b = (uint32)2; $b = (uint64)3; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt64());
    EXPECT_EQ(var_type(ast, "$b"), CreateUInt64());
  }
  {
    auto ast = test(
        R"(begin { let $b; let $a: typeof($b) = (uint16)1; $b = (uint32)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt32());
    EXPECT_EQ(var_type(ast, "$b"), CreateUInt32());
  }
}

TEST_F(TypeResolverTest, variable_map_promotion)
{
  {
    auto ast = test(
        R"(begin { $a = 1; @x = (uint32)1; $a = @x; @y = $a; } end { @x = (uint64)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt64());
    EXPECT_EQ(map_val_type(ast, "@x"), CreateUInt64());
    EXPECT_EQ(map_val_type(ast, "@y"), CreateUInt64());
  }
  {
    auto ast = test(
        R"(begin { $a = 1; @x = (uint32)1; if comptime (typeinfo(@x).full_type == "uint64") { $a = (int16)2; } } end { @x = (uint64)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt16());
    EXPECT_EQ(map_val_type(ast, "@x"), CreateUInt64());
  }
}

TEST_F(TypeResolverTest, typeof)
{
  {
    auto ast = test(R"(begin { $a = (typeof(uint64))1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt64());
  }
  {
    auto ast = test(
        R"(begin { let $b; $a = (typeof($b))1; $b = 1; $b = (uint64)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt64());
    EXPECT_EQ(var_type(ast, "$b"), CreateUInt64());
  }
  {
    auto ast = test(
        R"(begin { let $b; let $c; $a = (typeof($b))1; $b = (typeof($c))1; $c = (int64)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
    EXPECT_EQ(var_type(ast, "$b"), CreateInt64());
    EXPECT_EQ(var_type(ast, "$c"), CreateInt64());
  }
  {
    auto ast = test(
        R"(begin { @x = 2; $a = (typeof(@x))1; } end { @x = (int32)1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt32());
    EXPECT_EQ(map_val_type(ast, "@x"), CreateInt32());
  }
  {
    auto ast = test(R"(begin { @x[(int16)1] = 1; $a = (typeof(@x))1; })");
    EXPECT_EQ(map_key_type(ast, "@x"), CreateInt16());
    EXPECT_EQ(var_type(ast, "$a"), CreateInt16());
  }
  {
    auto ast = test(
        R"(begin { @x[(int16)1] = 1; $a = (typeof({ print(1); @x[0] }))1; })");
    EXPECT_EQ(map_val_type(ast, "@x"), CreateUInt8());
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt8());
  }
}

TEST_F(TypeResolverTest, comptime)
{
  {
    auto ast = test(
        R"(begin { let $c; $a = 1; if comptime (typeinfo($a).full_type == "uint64") { $c = (int64)2; } $a = (uint64)2; })");
    EXPECT_EQ(var_type(ast, "$c"), CreateInt64());
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt64());
  }
  {
    auto ast = test(
        R"(begin { let $c; $a = 1; if comptime (typeinfo(sizeof($a)).base_type == "int") { $c = (int64)2; } $a = (uint64)2; })");
    EXPECT_EQ(var_type(ast, "$c"), CreateInt64());
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt64());
  }
  {
    auto ast = test(
        R"(begin { let $c; $a = 1; if comptime (typeinfo($a).full_type == "uint64") { let $d; if comptime (typeinfo($d).full_type == "int64") { $c = (int16)3; } $d = (int64)2; } $a = (uint64)2; })");
    EXPECT_EQ(var_type(ast, "$c"), CreateInt16());
  }
  {
    auto ast = test(
        R"(begin { let $c; let $e; let $d; $a = 1; if comptime (typeinfo($a).full_type == "uint64") { if comptime (typeinfo($d).full_type == "int64") { $c = (int16)3; } $e = (int32)1; } $a = (uint64)2; if comptime (typeinfo($e).full_type == "int32") { $d = (int64)3; } })");
    EXPECT_EQ(var_type(ast, "$c"), CreateInt16());
  }
  {
    auto ast = test(
        R"(begin { @x = 1; if comptime (typeinfo(@y[1]).full_type == "uint64") { @x = (int32)2; } } end { @y[1] = (uint64)2; })");
    EXPECT_EQ(map_val_type(ast, "@x"), CreateInt32());
    EXPECT_EQ(map_val_type(ast, "@y"), CreateUInt64());
  }
  {
    auto ast = test(
        R"(begin { @x = 1; if comptime (typeinfo(@y[1]).full_type != "uint64") { @x = (int32)2; } } end { @y[1] = (uint64)2; })");
    EXPECT_EQ(map_val_type(ast, "@x"), CreateUInt8());
    EXPECT_EQ(map_val_type(ast, "@y"), CreateUInt64());
  }

  // Errors
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
}

TEST_F(TypeResolverTest, locked_types)
{
  test(
      R"(begin { if comptime (typeinfo(@a).full_type == "uint32") { @a = 2; } @a = (uint32)1; })");
  test(
      R"(begin { if comptime (typeinfo(@a).full_type == "uint32") { @a[2] = 2; } @a[(uint32)1] = 1; })");
  test(
      R"(begin { let $c; if comptime (typeinfo($c).full_type == "uint32") { $c = (uint16)2; } $c = (uint32)1; })");

  // Errors
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

  test(
      R"(begin { if comptime (typeinfo(@a).full_type == "uint32") { $a = 1; if comptime (typeinfo($a).full_type == "uint8") { @a[(uint64)2] = 2; } } @a[(uint32)1] = 1; })",
      Error{ R"(
ERROR: Type mismatch for @a: this type has been locked because it was used in another part of the type graph that was already resolved (e.g. `sizeof`, `typeinfo`, etc.). The new type 'uint64' doesn't fit into the locked type 'uint32'
begin { if comptime (typeinfo(@a).full_type == "uint32") { $a = 1; if comptime (typeinfo($a).full_type == "uint8") { @a[(uint64)2] = 2; } } @a[(uint32)1] = 1; }
                                                                                                                     ~~~~~~~~~~~~~
)" });
}

TEST_F(TypeResolverTest, unop)
{
  {
    auto ast = test(R"(begin { @a = (int16)2; ++@a; })");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { @a = 0; ++@a; $b = @a; })");
    EXPECT_EQ(var_type(ast, "$b"), CreateUInt64());
  }
  {
    auto ast = test(R"(begin { ++@a; $b = @a; })");
    EXPECT_EQ(var_type(ast, "$b"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { @a = (int64)0; ++@a; $b = @a; })");
    EXPECT_EQ(var_type(ast, "$b"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { $a = 1; $c = ++$a; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt64());
    EXPECT_EQ(var_type(ast, "$c"), CreateUInt64());
  }
  {
    auto ast = test(R"(begin { let $a: int16; $c = ++$a; $b = $a; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt16());
    EXPECT_EQ(var_type(ast, "$c"), CreateInt16());
    EXPECT_EQ(var_type(ast, "$b"), CreateInt16());
  }
  {
    auto ast = test(R"(begin { $a = 1; $b = &$a; $c = *$b; $a = (uint32)2; })");
    EXPECT_EQ(var_type(ast, "$c"), CreateUInt32());
  }

  // Errors
  test(R"(begin { ++$a; })", Error{});
  test(R"(begin { ++@a; @a = "hello"; })", Error{});
  test(R"(begin { ++$a; $a = "hello"; })", Error{});
}

TEST_F(TypeResolverTest, binop)
{
  {
    auto ast = test(R"(begin { $a = (uint32)1 + (uint32)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt64());
  }
  {
    auto ast = test(R"(begin { $a = (int32)1 + (int32)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { $a = (uint32)1 + (int32)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { $a = (int8)1 * 2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { $a = ((uint32)1 == (uint32)2); })");
    EXPECT_EQ(var_type(ast, "$a"), CreateBool());
  }
  {
    auto ast = test(R"(begin { $a = ((int32)1 < (int32)2); })");
    EXPECT_EQ(var_type(ast, "$a"), CreateBool());
  }
  {
    auto ast = test(R"(begin { $a = ((uint32)1 != (int32)2); })");
    EXPECT_EQ(var_type(ast, "$a"), CreateBool());
  }
  {
    auto ast = test(R"(begin { $a = (1 && 2); })");
    EXPECT_EQ(var_type(ast, "$a"), CreateBool());
  }
  {
    auto ast = test(R"(begin { $a = (1 || 0); })");
    EXPECT_EQ(var_type(ast, "$a"), CreateBool());
  }
  {
    auto ast = test(R"(begin { $x = (1 == 2); $a = $x + $x; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateBool());
  }
  {
    auto ast = test(R"(begin { $a = (uint16)1 & (uint16)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt64());
  }
  {
    auto ast = test(R"(begin { $a = (uint16)1 | (uint16)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt64());
  }
  {
    auto ast = test(R"(begin { $a = (uint16)1 ^ (uint16)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt64());
  }
  {
    auto ast = test(R"(begin { $a = (int16)1 & (int16)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { $a = (uint32)1 << (int32)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { $a = (int32)1 << (uint32)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { $a = (int32)1 >> (uint32)2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { $a = 3; $a = (int8)1 + 2; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt64());
  }
  {
    auto ast = test(R"(begin { $pv = 1; $p = &$pv; $a = $p + 1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreatePointer(CreateUInt8()));
  }
  {
    auto ast = test(R"(begin { $pv = 1; $p = &$pv; $a = $p - 1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreatePointer(CreateUInt8()));
  }
  {
    auto ast = test(
        R"(begin { $pv = 1; $p = &$pv; $qv = 1; $q = &$qv; $a = ($p == $q); })");
    EXPECT_EQ(var_type(ast, "$a"), CreateBool());
  }
  {
    auto ast = test(
        R"(begin { $pv = 1; $p = &$pv; $qv = 1; $q = &$qv; $a = ($p != $q); })");
    EXPECT_EQ(var_type(ast, "$a"), CreateBool());
  }

  // Errors
  test(R"(begin { $pv = 1; $p = &$pv; $a = 1 - $p; })", Error{});
  test(R"(begin { $pv = 1; $p = &$pv; $qv = 1; $q = &$qv; $a = $p * $q; })",
       Error{});
}

TEST_F(TypeResolverTest, cast)
{
  {
    auto ast = test(
        R"(begin { $a = (uint8)1; $b = (int8)1; $c = (int32)1; $d = (uint64)1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt8());
    EXPECT_EQ(var_type(ast, "$b"), CreateInt8());
    EXPECT_EQ(var_type(ast, "$c"), CreateInt32());
    EXPECT_EQ(var_type(ast, "$d"), CreateUInt64());
  }
  {
    auto ast = test(R"(begin { $a = (int32)-1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt32());
  }
  {
    auto ast = test(R"(begin { $a = (uint64)-1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateUInt64());
  }
  {
    auto ast = test(R"(begin { $a = (int8)(uint64)1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt8());
  }
  {
    auto ast = test(R"(begin { $a = (int32)1; $b = $a; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateInt32());
    EXPECT_EQ(var_type(ast, "$b"), CreateInt32());
  }
  {
    auto ast = test(R"(begin { $a = (int8[])1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateArray(1, CreateInt8()));
  }
  {
    auto ast = test("begin { $a = (int8[])\"hello\"; }");
    EXPECT_EQ(var_type(ast, "$a"), CreateArray(6, CreateInt8()));
  }
  {
    auto ast = test(R"(begin { $a = (int8[8])1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateArray(8, CreateInt8()));
  }
  {
    auto ast = test(R"(begin { $a = (int8[2])(int16)1; })");
    EXPECT_EQ(var_type(ast, "$a"), CreateArray(2, CreateInt8()));
  }
  {
    auto ast = test("begin { $a = (int8[6])\"hello\"; }");
    EXPECT_EQ(var_type(ast, "$a"), CreateArray(6, CreateInt8()));
  }
  {
    auto ast = test("begin { @a = (int8[])\"hello\"; }");
    EXPECT_EQ(map_val_type(ast, "@a"), CreateArray(6, CreateInt8()));
  }
}

} // namespace bpftrace::test::type_resolver
