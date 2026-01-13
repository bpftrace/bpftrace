#pragma once

#include <functional>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ast/ast.h"
#include "ast/context.h"
#include "struct.h"
#include "types.h"

namespace bpftrace::ast {
void PrintTo(const ASTContext& ast, std::ostream* os);
}

namespace bpftrace::test {

using ast::Operator;
using ::testing::_;
using ::testing::AllOf;
using ::testing::Matcher;
using ::testing::MatcherInterface;
using ::testing::MatchResultListener;

template <typename NodeType, typename MatcherType, typename TargetType>
bool MatchWith(const NodeType& node,
               const MatcherType& matcher,
               const TargetType& target);

template <typename NodeType>
auto CheckField(auto NodeType::*member,
                const auto& expected,
                const std::string& name);

template <typename NodeType, typename ContainerType, typename MatcherType>
bool CheckList(const NodeType& node,
               const ContainerType& container,
               const std::vector<MatcherType>& matchers,
               const std::string& item_name);

template <typename Derived, typename NodeType, typename PredicateType>
class PredicateMatcher {
public:
  PredicateMatcher() = default;

  Derived& Where(PredicateType predicate)
  {
    predicates_.push_back(predicate);
    return static_cast<Derived&>(*this);
  }

  const std::vector<PredicateType>& predicates() const {
    return predicates_;
  }

protected:
  std::vector<PredicateType> predicates_;
};

template <typename Derived, typename NodeType>
class NodeMatcher
    : public PredicateMatcher<Derived,
                              NodeType,
                              std::function<bool(const NodeType&)>> {
public:
  NodeMatcher() = default;

  using PredicateMatcher<Derived, NodeType, std::function<bool(const NodeType&)>>::predicates;

  operator Matcher<const NodeType&>() const
  {
    return ::testing::MakeMatcher(new Impl<NodeType>(predicates()));
  }

  operator Matcher<const ast::ASTContext&>() const
  {
    return ::testing::MakeMatcher(new Impl<ast::ASTContext>(predicates()));
  }

  template <typename U>
  operator Matcher<const U&>() const
    requires requires(NodeType* ptr) { U(ptr); }
  {
    return ::testing::MakeMatcher(new Impl<U>(predicates()));
  }

  Derived& WithValue(const auto& value)
    requires requires(NodeType t) { t.value; }
  {
    return this->Where(CheckField(&NodeType::value, value, "value"));
  }

  Derived& WithIdent(const std::string& ident)
    requires requires(NodeType t) { t.ident; }
  {
    return this->Where(CheckField(&NodeType::ident, ident, "ident"));
  }

  Derived& WithExpr(const Matcher<const ast::Expression&>& expr_matcher)
    requires requires(NodeType t) { t.expr; }
  {
    return this->Where([expr_matcher](const NodeType& node) {
      return MatchWith(node, expr_matcher, node.expr);
    });
  }

  Derived& WithLeft(const Matcher<const ast::Expression&>& left_matcher)
    requires requires(NodeType t) { t.left; }
  {
    return this->Where([left_matcher](const NodeType& node) {
      return MatchWith(node, left_matcher, node.left);
    });
  }

  Derived& WithRight(const Matcher<const ast::Expression&>& right_matcher)
    requires requires(NodeType t) { t.right; }
  {
    return this->Where([right_matcher](const NodeType& node) {
      return MatchWith(node, right_matcher, node.right);
    });
  }

  Derived& WithOperator(Operator op)
    requires requires(NodeType t) { t.op; }
  {
    return this->Where([op](const NodeType& node) {
      return node.op == op ||
             (node.addError() << "has operator " << static_cast<int>(node.op)
                              << " instead of " << static_cast<int>(op),
              false);
    });
  }

  Derived& WithCondition(const Matcher<const ast::Expression&>& cond_matcher)
    requires requires(NodeType t) { t.cond; }
  {
    return this->Where([cond_matcher](const NodeType& node) {
      return MatchWith(node, cond_matcher, node.cond);
    });
  }

  Derived& WithStatements(
      const std::vector<Matcher<const ast::Statement&>>& statements)
    requires requires(NodeType t) { t.block; };

  Derived& WithStatements(
      const std::vector<Matcher<const ast::Statement&>>& statements)
    requires requires(NodeType t) { t.stmts; };

  Derived& WithType(const Matcher<const SizedType&>& type_matcher)
    requires requires(NodeType* ptr) { ptr->type(); }
  {
    return this->Where([type_matcher](const NodeType& node) {
      return MatchWith(node, type_matcher, node.type());
    });
  }

private:
  template <typename U = NodeType>
  class Impl : public MatcherInterface<const U&> {
  public:
    explicit Impl(
        const std::vector<std::function<bool(const NodeType&)>>& predicates)
        : predicates_(predicates) {};

    bool MatchAndExplain(const U& node,
                         MatchResultListener* listener) const override
    {
      if constexpr (std::is_same_v<U, ast::Expression> ||
                    std::is_same_v<U, ast::Statement>) {
        if (!node.template is<NodeType>()) {
          const auto& n = node.node();
          std::string actual_type_name = std::visit(
              [](auto* v) -> std::string {
                using T = std::decay_t<decltype(*v)>;
                return ::testing::internal::GetTypeName<T>();
              },
              node.value);
          n.addError() << "is not the expected type; got " << actual_type_name;
          return false;
        } else {
          const NodeType& concrete = *node.template as<NodeType>();
          return std::ranges::all_of(predicates_, [&](const auto& pred) {
            return pred(concrete);
          });
        }
      } else if constexpr (std::is_same_v<U, ast::ASTContext>) {
        bool ok = std::ranges::all_of(predicates_, [&](const auto& pred) {
          return pred(*node.root);
        });
        if (!ok) {
          std::stringstream ss;
          node.diagnostics().emit(ss);
          *listener << "\n";
          *listener << ss.str();
          node.diagnostics().clear();
        }
        return ok;
      } else {
        return std::ranges::all_of(predicates_, [&](const auto& pred) {
          return pred(node);
        });
      }
    }

    void DescribeTo(std::ostream* os) const override
    {
      *os << "matches predicates";
    }

    std::vector<std::function<bool(const NodeType&)>> predicates_;
  };
};

template <typename T>
class NodeMatchResultListener : public testing::MatchResultListener {
public:
  NodeMatchResultListener(const T& node)
      : testing::MatchResultListener(&ss_), node_(node) {};
  ~NodeMatchResultListener() override
  {
    auto s = ss_.str();
    if (s.empty()) {
      return;
    }
    if constexpr (std::is_same_v<T, ast::Expression> ||
                  std::is_same_v<T, ast::Statement>) {
      node_.node().addError() << s;
    } else {
      node_.addError() << s;
    }
  }

private:
  const T& node_;
  std::stringstream ss_;
};

template <typename NodeType, typename MatcherType, typename TargetType>
bool MatchWith(const NodeType& node,
               const MatcherType& matcher,
               const TargetType& target)
{
  auto node_listener = NodeMatchResultListener<NodeType>(node);
  return matcher.MatchAndExplain(target, &node_listener);
}

template <typename NodeType>
auto CheckField(auto NodeType::*member,
                const auto& expected,
                const std::string& name)
{
  return [member, expected, name](const NodeType& node) {
    const auto& actual = node.*member;
    if (actual == expected) {
      return true;
    }
    if constexpr (
        requires { std::declval<std::ostream&>() << actual; } &&
        requires { std::declval<std::ostream&>() << expected; }) {
      node.addError() << "has " << name << " " << actual << " instead of "
                      << expected;
    } else {
      node.addError() << "has incorrect " << name;
    }
    return false;
  };
}

template <typename NodeType, typename ContainerType, typename MatcherType>
bool CheckList(const NodeType& node,
               const ContainerType& container,
               const std::vector<MatcherType>& matchers,
               const std::string& item_name)
{
  return (container.size() == matchers.size() ||
          (node.addError() << item_name << " count mismatch, expected "
                           << matchers.size() << ", got " << container.size(),
           false)) &&
         [&]() {
           for (size_t i = 0; i < matchers.size(); ++i) {
             if constexpr (requires { *container[i]; }) {
               if (!MatchWith(node, matchers[i], *container[i]))
                 return false;
             } else {
               if (!MatchWith(node, matchers[i], container[i]))
                 return false;
             }
           }
           return true;
         }();
}

class NoneMatcher : public NodeMatcher<NoneMatcher, ast::None> {};

inline NoneMatcher None()
{
  return {};
}

class PositionalParameterCountMatcher
    : public NodeMatcher<PositionalParameterCountMatcher,
                         ast::PositionalParameterCount> {};

inline PositionalParameterCountMatcher PositionalParameterCount()
{
  return {};
}

class BlockExprMatcher : public NodeMatcher<BlockExprMatcher, ast::BlockExpr> {
};

inline BlockExprMatcher Block(
    const std::vector<Matcher<const ast::Statement&>>& statements,
    const Matcher<const ast::Expression&>& value)
{
  return BlockExprMatcher().WithStatements(statements).WithExpr(value);
}

inline BlockExprMatcher Block(
    const std::vector<Matcher<const ast::Statement&>>& statements)
{
  return BlockExprMatcher().WithStatements(statements).WithExpr(None());
}

class SizedTypeMatcher
    : public PredicateMatcher<
          SizedTypeMatcher,
          SizedType,
          std::function<bool(const SizedType&, MatchResultListener*)>> {
public:
  SizedTypeMatcher& WithSize(size_t size)
  {
    return Where([size](const SizedType& type, MatchResultListener* listener) {
      return type.GetSize() == size ||
             (*listener << "has size " << type.GetSize() << " instead of "
                        << size,
              false);
    });
  }

  SizedTypeMatcher& WithType(Type ty)
  {
    return Where(
        [ty](const SizedType& type_obj, MatchResultListener* listener) {
          return type_obj.GetTy() == ty ||
                 (*listener << "has type " << static_cast<int>(type_obj.GetTy())
                            << " instead of " << static_cast<int>(ty),
                  false);
        });
  }

  SizedTypeMatcher& WithSigned(bool is_signed)
  {
    return Where(
        [is_signed](const SizedType& type_obj, MatchResultListener* listener) {
          return type_obj.IsSigned() == is_signed ||
             (*listener << "has signed " << type_obj.IsSigned() << " instead of "
                        << is_signed,
              false);
        });
  }

  SizedTypeMatcher& WithName(const std::string& name)
  {
    return Where(
        [name](const SizedType& type_obj, MatchResultListener* listener) {
          return type_obj.GetName() == name ||
                 (*listener << "has name \"" << type_obj.GetName()
                            << "\" instead of \"" << name << "\"",
                  false);
        });
  }

  SizedTypeMatcher& WithElement(
      const Matcher<const SizedType&>& element_matcher)
  {
    return Where([element_matcher](const SizedType& type_obj,
                                   MatchResultListener* listener) {
      // For arrays, check element type.
      if (type_obj.IsArrayTy()) {
        const SizedType* element_type = type_obj.GetElementTy();
        if (!element_type) {
          *listener << "array has no element type";
          return false;
        }
        return element_matcher.MatchAndExplain(*element_type, listener);
      }
      // For pointers, check pointee type.
      else if (type_obj.IsPtrTy()) {
        const SizedType* pointee_type = type_obj.GetPointeeTy();
        if (!pointee_type) {
          *listener << "pointer has no pointee type";
          return false;
        }
        return element_matcher.MatchAndExplain(*pointee_type, listener);
      } else {
        *listener << "type is neither array nor pointer, cannot have element";
        return false;
      }
    });
  }

  SizedTypeMatcher& WithField(
      const std::string& field_name,
      const Matcher<const class SizedType&>& field_type_matcher)
  {
    return Where(
        [field_name, field_type_matcher](const class SizedType& type_obj,
                                         MatchResultListener* listener) {
          // Check if this is a record type (struct/union) or tuple.
          if (!type_obj.IsCStructTy() && !type_obj.IsTupleTy()) {
            *listener << "type is not a record or tuple, cannot have fields";
            return false;
          }
          // Check if the field exists.
          if (!type_obj.HasField(field_name)) {
            *listener << "does not have field \"" << field_name << "\"";
            return false;
          }
          // Check the field type.
          const Field& field = type_obj.GetField(field_name);
          return field_type_matcher.MatchAndExplain(field.type, listener);
        });
  }

  bool MatchAndExplain(const SizedType& type,
                       MatchResultListener* listener) const
  {
    return std::ranges::all_of(predicates_, [&](const auto& pred) {
      return pred(type, listener);
    });
  }

  operator Matcher<const SizedType&>() const
  {
    return ::testing::MakeMatcher(new Impl(predicates_));
  }

private:
  class Impl : public MatcherInterface<const SizedType&> {
  public:
    explicit Impl(const std::vector<
                  std::function<bool(const SizedType&, MatchResultListener*)>>&
                      predicates)
        : predicates_(predicates) {};

    bool MatchAndExplain(const SizedType& type,
                         MatchResultListener* listener) const override
    {
      return std::ranges::all_of(predicates_, [&](const auto& pred) {
        return pred(type, listener);
      });
    }

    void DescribeTo(std::ostream* os) const override
    {
      *os << "is a SizedType";
    }

    std::vector<std::function<bool(const SizedType&, MatchResultListener*)>>
        predicates_;
  };
};

inline SizedTypeMatcher SizedType(Type ty)
{
  return SizedTypeMatcher().WithType(ty);
}

class ProgramMatcher : public NodeMatcher<ProgramMatcher, ast::Program> {
public:
  ProgramMatcher& WithProbe(const Matcher<const ast::Probe&>& probe_matcher)
  {
    return WithProbes({ probe_matcher });
  }

  ProgramMatcher& WithProbes(
      const std::vector<Matcher<const ast::Probe&>>& probe_matchers)
  {
    return Where([probe_matchers](const ast::Program& prog) {
      return CheckList(prog, prog.probes, probe_matchers, "probes");
    });
  }

  ProgramMatcher& WithCStatements(
      const std::vector<Matcher<const ast::CStatement&>>& cstmt_matchers)
  {
    return Where([cstmt_matchers](const ast::Program& prog) {
      return CheckList(prog, prog.c_statements, cstmt_matchers, "C statements");
    });
  }

  ProgramMatcher& WithConfig(const Matcher<const ast::Config&>& config_matcher)
  {
    return Where([config_matcher](const ast::Program& prog) {
      if (!prog.config) {
        prog.addError() << "has no config";
        return false;
      }
      return MatchWith(prog, config_matcher, *prog.config);
    });
  }

  ProgramMatcher& WithRootImports(
      const std::vector<Matcher<const ast::RootImport&>>& import_matchers)
  {
    return Where([import_matchers](const ast::Program& prog) {
      return CheckList(prog, prog.imports, import_matchers, "imports");
    });
  }

  ProgramMatcher& WithMapDecls(
      const std::vector<Matcher<const ast::MapDeclStatement&>>&
          map_decl_matchers)
  {
    return Where([map_decl_matchers](const ast::Program& prog) {
      return CheckList(
          prog, prog.map_decls, map_decl_matchers, "map declarations");
    });
  }

  ProgramMatcher& WithMacros(
      const std::vector<Matcher<const ast::Macro&>>& macro_matchers)
  {
    return Where([macro_matchers](const ast::Program& prog) {
      return CheckList(prog, prog.macros, macro_matchers, "macros");
    });
  }

  ProgramMatcher& WithFunction(
      const Matcher<const ast::Subprog&>& function_matcher)
  {
    return WithFunctions({ function_matcher });
  }

  ProgramMatcher& WithFunctions(
      const std::vector<Matcher<const ast::Subprog&>>& function_matchers)
  {
    return Where([function_matchers](const ast::Program& prog) {
      return CheckList(prog, prog.functions, function_matchers, "functions");
    });
  }

  ProgramMatcher& WithHeader(const std::string& header)
  {
    return Where([header](const ast::Program& prog) {
      return (prog.header.has_value() && *prog.header == header) ||
             (!prog.header.has_value() &&
              (prog.addError() << "has no header", false)) ||
             (*prog.header != header &&
              (prog.addError() << "has header \"" << *prog.header
                               << "\" instead of \"" << header << "\"",
               false));
    });
  }

  ProgramMatcher& HasNoHeader()
  {
    return Where([](const ast::Program& prog) {
      if (prog.header.has_value()) {
        prog.addError() << "expected no header, but has \"" << *prog.header
                        << "\"";
        return false;
      }
      return true;
    });
  }
};

inline ProgramMatcher Program()
{
  return {};
}

class ProbeMatcher : public NodeMatcher<ProbeMatcher, ast::Probe> {
public:
  ProbeMatcher& WithAttachPoints(const std::vector<std::string>& names)
  {
    return Where([names](const ast::Probe& probe) {
      return (probe.attach_points.size() == names.size() ||
              (probe.addError()
                   << "attach points count mismatch, expected " << names.size()
                   << ", got " << probe.attach_points.size(),
               false)) &&
             [&]() {
               for (size_t i = 0; i < names.size(); ++i) {
                 if (probe.attach_points[i]->name() != names[i]) {
                   probe.attach_points[i]->addError()
                       << "attach point is \"" << probe.attach_points[i]->name()
                       << "\" instead of \"" << names[i] << "\"";
                   return false;
                 }
               }
               return true;
             }();
    });
  }

  ProbeMatcher& WithPredicateAndBody(
      const Matcher<const ast::Expression&>& pred_matcher,
      const std::vector<Matcher<const ast::Statement&>>& statements)
  {
    return Where([pred_matcher, statements](const ast::Probe& probe) {
      if (!probe.block->stmts.empty()) {
        probe.addError() << "has statements ahead of predicate";
        return false;
      }
      auto* if_expr = probe.block->expr.as<ast::IfExpr>();
      if (!if_expr) {
        probe.addError() << "does not have predicate";
        return false;
      }
      if (!if_expr->right.is<ast::None>()) {
        probe.addError() << "has predicate with non-none right";
        return false;
      }
      if (!MatchWith(probe, pred_matcher, if_expr->cond)) {
        return false;
      }
      Matcher<const ast::Expression&> matcher = Block(statements, None());
      return MatchWith(probe, matcher, if_expr->left);
    });
  }

  ProbeMatcher& WithBody(const Matcher<const ast::BlockExpr&> matcher)
  {
    return Where([matcher](const ast::Probe& probe) {
      return MatchWith(probe, matcher, *probe.block);
    });
  }
};

inline ProbeMatcher Probe(
    const std::vector<std::string>& attach_points,
    const std::vector<Matcher<const ast::Statement&>>& statements)
{
  return ProbeMatcher()
      .WithAttachPoints(attach_points)
      .WithStatements(statements);
}

inline ProbeMatcher Probe(
    const std::vector<std::string>& attach_points,
    const Matcher<const ast::Expression&>& predicate,
    const std::vector<Matcher<const ast::Statement&>>& statements)
{
  return ProbeMatcher()
      .WithAttachPoints(attach_points)
      .WithPredicateAndBody(predicate, statements);
}

class IntegerMatcher : public NodeMatcher<IntegerMatcher, ast::Integer> {};

inline IntegerMatcher Integer(uint64_t value)
{
  return IntegerMatcher().WithValue(value);
}

class StringMatcher : public NodeMatcher<StringMatcher, ast::String> {};

inline StringMatcher String(const std::string& value)
{
  return StringMatcher().WithValue(value);
}

class BooleanMatcher : public NodeMatcher<BooleanMatcher, ast::Boolean> {};

inline BooleanMatcher Boolean(bool value)
{
  return BooleanMatcher().WithValue(value);
}

class BinopMatcher : public NodeMatcher<BinopMatcher, ast::Binop> {};

inline BinopMatcher Binop(Operator op,
                          const Matcher<const ast::Expression&>& left,
                          const Matcher<const ast::Expression&>& right)
{
  return BinopMatcher().WithOperator(op).WithLeft(left).WithRight(right);
}

class CallMatcher : public NodeMatcher<CallMatcher, ast::Call> {
public:
  CallMatcher& WithFunction(const std::string& name)
  {
    return Where(CheckField(&ast::Call::func, name, "function name"));
  }

  CallMatcher& WithArgs(
      const std::vector<Matcher<const ast::Expression&>>& args_matchers)
  {
    return Where([args_matchers](const ast::Call& call) {
      return CheckList(call, call.vargs, args_matchers, "arguments");
    });
  }
};

inline CallMatcher Call(
    const std::string& name,
    const std::vector<Matcher<const ast::Expression&>>& args)
{
  return CallMatcher().WithFunction(name).WithArgs(args);
}

class MapMatcher : public NodeMatcher<MapMatcher, ast::Map> {};

inline MapMatcher Map(const std::string& ident)
{
  return MapMatcher().WithIdent(ident);
}

class VariableMatcher : public NodeMatcher<VariableMatcher, ast::Variable> {};

inline VariableMatcher Variable(const std::string& ident)
{
  return VariableMatcher().WithIdent(ident);
}

class BuiltinMatcher : public NodeMatcher<BuiltinMatcher, ast::Builtin> {};

inline BuiltinMatcher Builtin(const std::string& ident)
{
  return BuiltinMatcher().WithIdent(ident);
}

class PositionalParameterMatcher
    : public NodeMatcher<PositionalParameterMatcher, ast::PositionalParameter> {
public:
  PositionalParameterMatcher& WithIndex(long n)
  {
    return Where(
        CheckField(&ast::PositionalParameter::n, n, "parameter index"));
  }
};

inline PositionalParameterMatcher PositionalParameter(long n)
{
  return PositionalParameterMatcher().WithIndex(n);
}

class UnopMatcher : public NodeMatcher<UnopMatcher, ast::Unop> {};

inline UnopMatcher Unop(Operator op,
                        const Matcher<const ast::Expression&>& expr)
{
  return UnopMatcher().WithOperator(op).WithExpr(expr);
}

class FieldAccessMatcher
    : public NodeMatcher<FieldAccessMatcher, ast::FieldAccess> {
public:
  FieldAccessMatcher& WithField(const std::string& field)
  {
    return Where(CheckField(&ast::FieldAccess::field, field, "field name"));
  }
};

inline FieldAccessMatcher FieldAccess(
    const std::string& field,
    const Matcher<const ast::Expression&>& expr)
{
  return FieldAccessMatcher().WithField(field).WithExpr(expr);
}

class CastMatcher : public NodeMatcher<CastMatcher, ast::Cast> {
public:
  CastMatcher& WithTypeOf(const Matcher<const ast::Typeof&>& type_matcher)
  {
    return Where([type_matcher](const ast::Cast& node) {
      return MatchWith(node, type_matcher, *node.typeof);
    });
  }
};

inline CastMatcher Cast(const Matcher<const ast::Typeof&>& type_matcher,
                        const Matcher<const ast::Expression&>& expr_matcher)
{
  return CastMatcher().WithTypeOf(type_matcher).WithExpr(expr_matcher);
}

class TypeofMatcher : public NodeMatcher<TypeofMatcher, ast::Typeof> {
public:
  TypeofMatcher& WithExpr(const Matcher<const ast::Expression&>& expr_matcher)
  {
    return Where([expr_matcher](const ast::Typeof& node) {
      if (!std::holds_alternative<ast::Expression>(node.record)) {
        node.addError() << "record is not an expression";
        return false;
      }
      return MatchWith(node,
                       expr_matcher,
                       std::get<ast::Expression>(node.record));
    });
  }

  TypeofMatcher& WithType(const Matcher<const class SizedType&>& type_matcher)
  {
    return Where([type_matcher](const ast::Typeof& node) {
      if (!std::holds_alternative<class SizedType>(node.record)) {
        node.addError() << "record is not a SizedType";
        return false;
      }
      const auto& type = std::get<class SizedType>(node.record);
      return MatchWith(node, type_matcher, type);
    });
  }
};

inline TypeofMatcher Typeof(const Matcher<const ast::Expression&>& expr_matcher)
{
  return TypeofMatcher().WithExpr(expr_matcher);
}

inline TypeofMatcher Typeof(const Matcher<const class SizedType&>& type_matcher)
{
  return TypeofMatcher().WithType(type_matcher);
}

class TypeinfoMatcher : public NodeMatcher<TypeinfoMatcher, ast::Typeinfo> {
public:
  TypeinfoMatcher& WithTypeOf(const Matcher<const ast::Typeof&>& typeof_matcher)
  {
    return Where([typeof_matcher](const ast::Typeinfo& node) {
      return MatchWith(node, typeof_matcher, *node.typeof);
    });
  }
};

inline TypeinfoMatcher Typeinfo(
    const Matcher<const ast::Typeof&>& typeof_matcher)
{
  return TypeinfoMatcher().WithTypeOf(typeof_matcher);
}

class ComptimeMatcher : public NodeMatcher<ComptimeMatcher, ast::Comptime> {};

inline ComptimeMatcher Comptime(
    const Matcher<const ast::Expression&>& expr_matcher)
{
  return ComptimeMatcher().WithExpr(expr_matcher);
}

class TupleAccessMatcher
    : public NodeMatcher<TupleAccessMatcher, ast::TupleAccess> {
public:
  TupleAccessMatcher& WithExpr(
      const Matcher<const ast::Expression&>& expr_matcher)
  {
    return Where([expr_matcher](const ast::TupleAccess& node) {
      return MatchWith(node, expr_matcher, node.expr);
    });
  }

  TupleAccessMatcher& WithIndex(size_t index)
  {
    return Where([index](const ast::TupleAccess& node) {
      return node.index == index ||
             (node.addError()
                  << "has index " << node.index << " instead of " << index,
              false);
    });
  }
};

inline TupleAccessMatcher TupleAccess(
    const Matcher<const ast::Expression&>& expr,
    size_t index)
{
  return TupleAccessMatcher().WithExpr(expr).WithIndex(index);
}

class MapAccessMatcher : public NodeMatcher<MapAccessMatcher, ast::MapAccess> {
public:
  MapAccessMatcher& WithMap(const Matcher<const ast::Map&>& map_matcher)
  {
    return Where([map_matcher](const ast::MapAccess& node) {
      return MatchWith(node, map_matcher, *node.map);
    });
  }

  MapAccessMatcher& WithKey(const Matcher<const ast::Expression&>& key_matcher)
  {
    return Where([key_matcher](const ast::MapAccess& node) {
      return MatchWith(node, key_matcher, node.key);
    });
  }
};

inline MapAccessMatcher MapAccess(const Matcher<const ast::Map&>& map,
                                  const Matcher<const ast::Expression&>& key)
{
  return MapAccessMatcher().WithMap(map).WithKey(key);
}

class VariableAddrMatcher
    : public NodeMatcher<VariableAddrMatcher, ast::VariableAddr> {
public:
  VariableAddrMatcher& WithVariable(
      const Matcher<const ast::Variable&>& var_matcher)
  {
    return Where([var_matcher](const ast::VariableAddr& node) {
      return MatchWith(node, var_matcher, *node.var);
    });
  }
};

inline VariableAddrMatcher VariableAddr(
    const Matcher<const ast::Variable&>& var)
{
  return VariableAddrMatcher().WithVariable(var);
}

class MapAddrMatcher : public NodeMatcher<MapAddrMatcher, ast::MapAddr> {
public:
  MapAddrMatcher& WithMap(const Matcher<const ast::Map&>& map_matcher)
  {
    return Where([map_matcher](const ast::MapAddr& node) {
      return MatchWith(node, map_matcher, *node.map);
    });
  }
};

inline MapAddrMatcher MapAddr(const Matcher<const ast::Map&>& map)
{
  return MapAddrMatcher().WithMap(map);
}

class JumpMatcher : public NodeMatcher<JumpMatcher, ast::Jump> {
public:
  JumpMatcher& WithType(ast::JumpType jump_type)
  {
    return Where(CheckField(&ast::Jump::ident, jump_type, "jump type"));
  }

  JumpMatcher& WithReturnValue(
      const Matcher<const ast::Expression&>& expr_matcher)
  {
    return Where([expr_matcher](const ast::Jump& node) {
      if (!node.return_value) {
        node.addError() << "has no return value";
        return false;
      }
      return MatchWith(node, expr_matcher, *node.return_value);
    });
  }

  JumpMatcher& HasNoReturnValue()
  {
    return Where([](const ast::Jump& node) {
      if (node.return_value) {
        node.addError() << "expected no return value, but has one";
        return false;
      }
      return true;
    });
  }
};

inline JumpMatcher Jump(ast::JumpType type)
{
  return JumpMatcher().WithType(type);
}

inline JumpMatcher Return(const Matcher<const ast::Expression&>& return_value)
{
  return JumpMatcher()
      .WithType(ast::JumpType::RETURN)
      .WithReturnValue(return_value);
}

class WhileMatcher : public NodeMatcher<WhileMatcher, ast::While> {};

inline WhileMatcher While(
    const Matcher<const ast::Expression&>& condition,
    const std::vector<Matcher<const ast::Statement&>>& statements)
{
  return WhileMatcher().WithCondition(condition).WithStatements(statements);
}

class RangeMatcher : public NodeMatcher<RangeMatcher, ast::Range> {
public:
  RangeMatcher& WithStart(const Matcher<const ast::Expression&>& start_matcher)
  {
    return Where([start_matcher](const ast::Range& node) {
      return MatchWith(node, start_matcher, node.start);
    });
  }

  RangeMatcher& WithEnd(const Matcher<const ast::Expression&>& end_matcher)
  {
    return Where([end_matcher](const ast::Range& node) {
      return MatchWith(node, end_matcher, node.end);
    });
  }
};

inline RangeMatcher Range(const Matcher<const ast::Expression&>& start,
                          const Matcher<const ast::Expression&>& end)
{
  return RangeMatcher().WithStart(start).WithEnd(end);
}

class ForMatcher : public NodeMatcher<ForMatcher, ast::For> {
public:
  ForMatcher& WithVariable(const Matcher<const ast::Variable&>& var_matcher)
  {
    return Where([var_matcher](const ast::For& node) {
      return MatchWith(node, var_matcher, *node.decl);
    });
  }

  ForMatcher& WithIterable(const Matcher<const ast::Map&>& map_matcher)
  {
    return Where([map_matcher](const ast::For& node) {
      if (!node.iterable.is<ast::Map>())
        return false;
      return MatchWith(node, map_matcher, *node.iterable.as<ast::Map>());
    });
  }

  ForMatcher& WithRange(const Matcher<const ast::Range&>& range_matcher)
  {
    return Where([range_matcher](const ast::For& node) {
      if (!node.iterable.is<ast::Range>())
        return false;
      return MatchWith(node, range_matcher, *node.iterable.as<ast::Range>());
    });
  }

  ForMatcher& WithContext(
      const Matcher<const class SizedType&>& context_matcher)
  {
    return Where([context_matcher](const ast::For& node) {
      return MatchWith(node, context_matcher, node.ctx_type);
    });
  }
};

inline ForMatcher For(
    const Matcher<const ast::Variable&>& var,
    const Matcher<const ast::Map&>& map,
    const std::vector<Matcher<const ast::Statement&>>& statements)
{
  return ForMatcher().WithVariable(var).WithIterable(map).WithStatements(
      statements);
}

inline ForMatcher For(
    const Matcher<const ast::Variable&>& var,
    const Matcher<const ast::Range&>& range,
    const std::vector<Matcher<const ast::Statement&>>& statements)
{
  return ForMatcher().WithVariable(var).WithRange(range).WithStatements(
      statements);
}

class ArrayAccessMatcher
    : public NodeMatcher<ArrayAccessMatcher, ast::ArrayAccess> {
public:
  ArrayAccessMatcher& WithIndexExpr(
      const Matcher<const ast::Expression&>& index_matcher)
  {
    return Where([index_matcher](const ast::ArrayAccess& node) {
      return MatchWith(node, index_matcher, node.indexpr);
    });
  }
};

inline ArrayAccessMatcher ArrayAccess(
    const Matcher<const ast::Expression&>& expr,
    const Matcher<const ast::Expression&>& index_expr)
{
  return ArrayAccessMatcher().WithExpr(expr).WithIndexExpr(index_expr);
}

class AssignScalarMapStatementMatcher
    : public NodeMatcher<AssignScalarMapStatementMatcher,
                         ast::AssignScalarMapStatement> {
public:
  AssignScalarMapStatementMatcher& WithMap(
      const Matcher<const ast::Map&>& map_matcher)
  {
    return Where([map_matcher](const ast::AssignScalarMapStatement& node) {
      return MatchWith(node, map_matcher, *node.map);
    });
  }
};

inline AssignScalarMapStatementMatcher AssignScalarMapStatement(
    const Matcher<const ast::Map&>& map_matcher,
    const Matcher<const ast::Expression&>& expr_matcher)
{
  return AssignScalarMapStatementMatcher()
      .WithMap(map_matcher)
      .WithExpr(expr_matcher);
}

class AssignMapStatementMatcher
    : public NodeMatcher<AssignMapStatementMatcher, ast::AssignMapStatement> {
public:
  AssignMapStatementMatcher& WithMap(
      const Matcher<const ast::Map&>& map_matcher)
  {
    return Where([map_matcher](const ast::AssignMapStatement& node) {
      return MatchWith(node, map_matcher, *node.map_access->map);
    });
  }

  AssignMapStatementMatcher& WithKey(
      const Matcher<const ast::Expression&>& key_matcher)
  {
    return Where([key_matcher](const ast::AssignMapStatement& node) {
      return MatchWith(node, key_matcher, node.map_access->key);
    });
  }
};

inline AssignMapStatementMatcher AssignMapStatement(
    const Matcher<const ast::Map&>& map_matcher,
    const Matcher<const ast::Expression&>& key_matcher,
    const Matcher<const ast::Expression&>& expr_matcher)
{
  return AssignMapStatementMatcher()
      .WithMap(map_matcher)
      .WithKey(key_matcher)
      .WithExpr(expr_matcher);
}

class AssignVarStatementMatcher
    : public NodeMatcher<AssignVarStatementMatcher, ast::AssignVarStatement> {
public:
  AssignVarStatementMatcher& WithVariable(
      const Matcher<const ast::Variable&>& var_matcher)
  {
    return Where([var_matcher](const ast::AssignVarStatement& node) {
      return MatchWith(node, var_matcher, *node.var());
    });
  }
};

inline AssignVarStatementMatcher AssignVarStatement(
    const Matcher<const ast::Variable&>& var_matcher,
    const Matcher<const ast::Expression&>& expr_matcher)
{
  return AssignVarStatementMatcher()
      .WithVariable(var_matcher)
      .WithExpr(expr_matcher);
}

class ExprStatementMatcher
    : public NodeMatcher<ExprStatementMatcher, ast::ExprStatement> {};

inline ExprStatementMatcher ExprStatement(
    const Matcher<const ast::Expression&>& expr_matcher)
{
  return ExprStatementMatcher().WithExpr(expr_matcher);
}

class DiscardExprMatcher
    : public NodeMatcher<DiscardExprMatcher, ast::DiscardExpr> {};

inline DiscardExprMatcher DiscardExpr(
    const Matcher<const ast::Expression&>& expr_matcher)
{
  return DiscardExprMatcher().WithExpr(expr_matcher);
}

class IfExprMatcher : public NodeMatcher<IfExprMatcher, ast::IfExpr> {};

inline IfExprMatcher If(const Matcher<const ast::Expression&>& cond,
                        const Matcher<const ast::Expression&>& left,
                        const Matcher<const ast::Expression&>& right)
{
  return IfExprMatcher().WithCondition(cond).WithLeft(left).WithRight(right);
}

inline IfExprMatcher If(
    const Matcher<const ast::Expression&>& cond,
    const std::vector<Matcher<const ast::Statement&>>& statements)
{
  return IfExprMatcher()
      .WithCondition(cond)
      .WithLeft(Block(statements))
      .WithRight(None());
}

class CStatementMatcher
    : public NodeMatcher<CStatementMatcher, ast::CStatement> {
public:
  CStatementMatcher& WithData(const std::string& data)
  {
    return Where(CheckField(&ast::CStatement::data, data, "data"));
  }
};

inline CStatementMatcher CStatement(const std::string& data)
{
  return CStatementMatcher().WithData(data);
}

class AssignConfigVarStatementMatcher
    : public NodeMatcher<AssignConfigVarStatementMatcher,
                         ast::AssignConfigVarStatement> {
public:
  AssignConfigVarStatementMatcher& WithVar(const std::string& var)
  {
    return Where([var](const ast::AssignConfigVarStatement& node) {
      return node.var == var ||
             (node.addError() << "has variable \"" << node.var
                              << "\" instead of \"" << var << "\"",
              false);
    });
  }
};

inline AssignConfigVarStatementMatcher AssignConfigVarStatement(
    const std::string& var,
    const std::variant<uint64_t, std::string, bool>& value)
{
  return AssignConfigVarStatementMatcher().WithVar(var).WithValue(value);
}

class ConfigMatcher : public NodeMatcher<ConfigMatcher, ast::Config> {
public:
  ConfigMatcher& WithStatements(
      const std::vector<Matcher<const ast::AssignConfigVarStatement&>>&
          stmt_matchers)
  {
    return Where([stmt_matchers](const ast::Config& node) {
      return CheckList(node, node.stmts, stmt_matchers, "config statements");
    });
  }
};

inline ConfigMatcher Config(
    const std::vector<Matcher<const ast::AssignConfigVarStatement&>>&
        statements)
{
  return ConfigMatcher().WithStatements(statements);
}

class RootImportMatcher : public NodeMatcher<RootImportMatcher, ast::RootImport> {
public:
  RootImportMatcher& WithName(const std::string& name)
  {
    return Where(CheckField(&ast::RootImport::name, name, "name"));
  }
};

inline RootImportMatcher RootImport(const std::string& name)
{
  return RootImportMatcher().WithName(name);
}

class StatementImportMatcher : public NodeMatcher<StatementImportMatcher, ast::StatementImport> {
public:
  StatementImportMatcher& WithName(const std::string& name)
  {
    return Where(CheckField(&ast::StatementImport::name, name, "name"));
  }
};

inline StatementImportMatcher StatementImport(const std::string& name)
{
  return StatementImportMatcher().WithName(name);
}

class MapDeclStatementMatcher
    : public NodeMatcher<MapDeclStatementMatcher, ast::MapDeclStatement> {
public:
  MapDeclStatementMatcher& WithBpfType(const std::string& bpf_type)
  {
    return Where(
        CheckField(&ast::MapDeclStatement::bpf_type, bpf_type, "BPF type"));
  }

  MapDeclStatementMatcher& WithMaxEntries(int max_entries)
  {
    return Where(CheckField(&ast::MapDeclStatement::max_entries,
                            max_entries,
                            "max entries"));
  }
};

inline MapDeclStatementMatcher MapDeclStatement(const std::string& ident,
                                                const std::string& bpf_type,
                                                int max_entries)
{
  return MapDeclStatementMatcher()
      .WithIdent(ident)
      .WithBpfType(bpf_type)
      .WithMaxEntries(max_entries);
}

class MacroMatcher : public NodeMatcher<MacroMatcher, ast::Macro> {
public:
  MacroMatcher& WithName(const std::string& name)
  {
    return Where(CheckField(&ast::Macro::name, name, "name"));
  }

  MacroMatcher& WithArgs(
      const std::vector<Matcher<const ast::Expression&>>& arg_matchers)
  {
    return Where([arg_matchers](const ast::Macro& node) {
      return CheckList(node, node.vargs, arg_matchers, "arguments");
    });
  }

  MacroMatcher& WithBlock(const Matcher<const ast::BlockExpr&>& block_matcher)
  {
    return Where([block_matcher](const ast::Macro& node) {
      return MatchWith(node, block_matcher, *node.block);
    });
  }
};

inline MacroMatcher Macro(
    const std::string& name,
    const std::vector<Matcher<const ast::Expression&>>& args,
    const Matcher<const ast::BlockExpr&>& block)
{
  return MacroMatcher().WithName(name).WithArgs(args).WithBlock(block);
}

class SubprogArgMatcher
    : public NodeMatcher<SubprogArgMatcher, ast::SubprogArg> {
public:
  SubprogArgMatcher& WithVariable(
      const Matcher<const ast::Variable&>& var_matcher)
  {
    return Where([var_matcher](const ast::SubprogArg& node) {
      return MatchWith(node, var_matcher, *node.var);
    });
  }

  SubprogArgMatcher& WithTypeOf(
      const Matcher<const ast::Typeof&>& typeof_matcher)
  {
    return Where([typeof_matcher](const ast::SubprogArg& node) {
      return MatchWith(node, typeof_matcher, *node.typeof);
    });
  }
};

inline SubprogArgMatcher SubprogArg(
    const Matcher<const ast::Variable&>& var,
    const Matcher<const ast::Typeof&>& typeof_matcher)
{
  return SubprogArgMatcher().WithVariable(var).WithTypeOf(typeof_matcher);
}

class SubprogMatcher : public NodeMatcher<SubprogMatcher, ast::Subprog> {
public:
  SubprogMatcher& WithName(const std::string& name)
  {
    return Where(CheckField(&ast::Subprog::name, name, "name"));
  }

  SubprogMatcher& WithReturnType(
      const Matcher<const ast::Typeof&>& return_type_matcher)
  {
    return Where([return_type_matcher](const ast::Subprog& node) {
      return MatchWith(node, return_type_matcher, *node.return_type);
    });
  }

  SubprogMatcher& WithArgs(
      const std::vector<Matcher<const ast::SubprogArg&>>& arg_matchers)
  {
    return Where([arg_matchers](const ast::Subprog& node) {
      return CheckList(node, node.args, arg_matchers, "arguments");
    });
  }

  SubprogMatcher& WithStatements(
      const std::vector<Matcher<const ast::Statement&>>& statements)
  {
    return Where([statements](const ast::Subprog& node) {
      Matcher<const ast::BlockExpr&> matcher = Block(statements, None());
      return MatchWith(node, matcher, *node.block);
    });
  }
};

inline SubprogMatcher Subprog(
    const std::string& name,
    const Matcher<const ast::Typeof&>& return_type,
    const std::vector<Matcher<const ast::SubprogArg&>>& args,
    const std::vector<Matcher<const ast::Statement&>>& statements)
{
  return SubprogMatcher()
      .WithName(name)
      .WithReturnType(return_type)
      .WithArgs(args)
      .WithStatements(statements);
}

class VarDeclStatementMatcher
    : public NodeMatcher<VarDeclStatementMatcher, ast::VarDeclStatement> {
public:
  VarDeclStatementMatcher& WithVariable(
      const Matcher<const ast::Variable&>& var_matcher)
  {
    return Where([var_matcher](const ast::VarDeclStatement& node) {
      return MatchWith(node, var_matcher, *node.var);
    });
  }

  VarDeclStatementMatcher& WithTypeOf(
      const Matcher<const ast::Typeof&>& typeof_matcher)
  {
    return Where([typeof_matcher](const ast::VarDeclStatement& node) {
      return (node.typeof ||
              (node.addError() << "vardecl does not have a type specified",
               false)) &&
             MatchWith(node, typeof_matcher, *node.typeof);
    });
  }
};

inline VarDeclStatementMatcher VarDeclStatement(
    const Matcher<const ast::Variable&>& var)
{
  return VarDeclStatementMatcher().WithVariable(var);
}

inline VarDeclStatementMatcher VarDeclStatement(
    const Matcher<const ast::Variable&>& var,
    const Matcher<const ast::Typeof&>& typeof_matcher)
{
  return VarDeclStatementMatcher().WithVariable(var).WithTypeOf(typeof_matcher);
}

class UnrollMatcher : public NodeMatcher<UnrollMatcher, ast::Unroll> {};

inline UnrollMatcher Unroll(
    const Matcher<const ast::Expression&>& expr,
    const std::vector<Matcher<const ast::Statement&>>& statements)
{
  return UnrollMatcher().WithExpr(expr).WithStatements(statements);
}

class SizeofMatcher : public NodeMatcher<SizeofMatcher, ast::Sizeof> {
public:
  SizeofMatcher& WithExpr(const Matcher<const ast::Expression&>& expr_matcher)
  {
    return Where([expr_matcher](const ast::Sizeof& node) {
      if (!std::holds_alternative<ast::Expression>(node.record)) {
        node.addError() << "record is not an expression";
        return false;
      }
      return MatchWith(node,
                       expr_matcher,
                       std::get<ast::Expression>(node.record));
    });
  }

  SizeofMatcher& WithType(const Matcher<const class SizedType&>& type_matcher)
  {
    return Where([type_matcher](const ast::Sizeof& node) {
      if (!std::holds_alternative<class SizedType>(node.record)) {
        node.addError() << "record is not a SizedType";
        return false;
      }
      const auto& type = std::get<class SizedType>(node.record);
      return MatchWith(node, type_matcher, type);
    });
  }
};

inline SizeofMatcher Sizeof(const Matcher<const ast::Expression&>& expr)
{
  return SizeofMatcher().WithExpr(expr);
}

inline SizeofMatcher Sizeof(const Matcher<const class SizedType&>& type)
{
  return SizeofMatcher().WithType(type);
}

class OffsetofMatcher : public NodeMatcher<OffsetofMatcher, ast::Offsetof> {
public:
  OffsetofMatcher& WithExpr(const Matcher<const ast::Expression&>& expr_matcher)
  {
    return Where([expr_matcher](const ast::Offsetof& node) {
      if (!std::holds_alternative<ast::Expression>(node.record)) {
        node.addError() << "record is not an expression";
        return false;
      }
      return MatchWith(node,
                       expr_matcher,
                       std::get<ast::Expression>(node.record));
    });
  }

  OffsetofMatcher& WithType(const Matcher<const class SizedType&>& type_matcher)
  {
    return Where([type_matcher](const ast::Offsetof& node) {
      if (!std::holds_alternative<class SizedType>(node.record)) {
        node.addError() << "record is not a SizedType";
        return false;
      }
      const auto& type = std::get<class SizedType>(node.record);
      return MatchWith(node, type_matcher, type);
    });
  }

  OffsetofMatcher& WithField(const std::vector<std::string>& field)
  {
    return Where(CheckField(&ast::Offsetof::field, field, "field path"));
  }
};

inline OffsetofMatcher Offsetof(const Matcher<const ast::Expression&>& expr,
                                const std::vector<std::string>& field)
{
  return OffsetofMatcher().WithExpr(expr).WithField(field);
}

inline OffsetofMatcher Offsetof(const Matcher<const class SizedType&>& type,
                                const std::vector<std::string>& field)
{
  return OffsetofMatcher().WithType(type).WithField(field);
}

class IdentifierMatcher
    : public NodeMatcher<IdentifierMatcher, ast::Identifier> {};

inline IdentifierMatcher Identifier(const std::string& ident)
{
  return IdentifierMatcher().WithIdent(ident);
}

class NegativeIntegerMatcher
    : public NodeMatcher<NegativeIntegerMatcher, ast::NegativeInteger> {};

inline NegativeIntegerMatcher NegativeInteger(int64_t value)
{
  return NegativeIntegerMatcher().WithValue(value);
}

class TupleMatcher : public NodeMatcher<TupleMatcher, ast::Tuple> {
public:
  TupleMatcher& WithElems(
      const std::vector<Matcher<const ast::Expression&>>& exprs_matchers)
  {
    return Where([exprs_matchers](const ast::Tuple& tuple) {
      return CheckList(tuple, tuple.elems, exprs_matchers, "elements");
    });
  }
};

inline TupleMatcher Tuple(
    const std::vector<Matcher<const ast::Expression&>>& elems)
{
  return TupleMatcher().WithElems(elems);
}

template <typename Derived, typename NodeType>
Derived& NodeMatcher<Derived, NodeType>::WithStatements(
    const std::vector<Matcher<const ast::Statement&>>& statements)
  requires requires(NodeType t) { t.block; }
{
  return this->Where([statements](const NodeType& node) {
    Matcher<const ast::BlockExpr&> matcher = Block(statements, None());
    return MatchWith(node, matcher, *node.block);
  });
}

template <typename Derived, typename NodeType>
Derived& NodeMatcher<Derived, NodeType>::WithStatements(
    const std::vector<Matcher<const ast::Statement&>>& statements)
  requires requires(NodeType t) { t.stmts; }
{
  return this->Where([statements](const NodeType& node) {
    return CheckList(node, node.stmts, statements, "statements");
  });
}

} // namespace bpftrace::test
