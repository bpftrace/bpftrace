#include "ast/passes/fold_literals.h"
#include "ast/ast.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"
#include "util/int_parser.h"

namespace bpftrace::ast {

namespace {

class LiteralFolder : public Visitor<LiteralFolder, Expression *> {
public:
  LiteralFolder(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace) {};

  using Visitor<LiteralFolder, Expression *>::visit;

  template <typename T>
  T *replace(T *node, [[maybe_unused]] Expression **result)
  {
    if constexpr (std::is_same_v<T, Expression>) {
      if (*result != nullptr && *result != node) {
        return *result;
      }
    }
    return node;
  }

  Expression *visit(Binop &op);
  Expression *visit(PositionalParameterCount &param);
  Expression *visit(PositionalParameter &param);
  Expression *visit(Call &call);

private:
  ASTContext &ast_;
  BPFtrace &bpftrace_;
};

} // namespace

template <typename T>
static std::optional<std::variant<uint64_t, int64_t>> eval_binop(T left,
                                                                 T right,
                                                                 Operator op)
{
  switch (op) {
    case Operator::EQ:
      return static_cast<uint64_t>(left == right);
    case Operator::NE:
      return static_cast<uint64_t>(left != right);
    case Operator::LE:
      return static_cast<uint64_t>(left <= right);
    case Operator::GE:
      return static_cast<uint64_t>(left >= right);
    case Operator::LT:
      return static_cast<uint64_t>(left < right);
    case Operator::GT:
      return static_cast<uint64_t>(left > right);
    case Operator::PLUS:
      if (left == 0 || right == 0) {
        return static_cast<uint64_t>(left + right);
      }
      if (left > 0 && right > 0) {
        auto res = static_cast<uint64_t>(left) + static_cast<uint64_t>(right);
        if (res > static_cast<uint64_t>(left) &&
            res > static_cast<uint64_t>(right)) {
          return res;
        }
      }
      if constexpr (std::is_same_v<T, int64_t>) {
        if ((left > 0 && right < 0) || (left < 0 && right > 0)) {
          auto res = left + right;
          if (res < 0) {
            return res;
          }
          return static_cast<uint64_t>(res);
        }
        if (left < 0 && right < 0) {
          auto res = left + right;
          if (res < left && res < right) {
            return res;
          }
          return std::nullopt;
        }
      }
      return std::nullopt;
    case Operator::MINUS:
      if constexpr (std::is_same_v<T, uint64_t>) {
        if (left >= right) {
          return left - right;
        } else {
          return -static_cast<int64_t>(right - left);
        }
      } else {
        if (right == 0) {
          return left;
        } else if (right < 0) {
          auto res = left - right;
          if (res < left) {
            return std::nullopt;
          }
          if (res > 0) {
            return static_cast<uint64_t>(res);
          }
          return res;
        } else {
          auto res = left - right;
          if (res > left) {
            return std::nullopt;
          }
          if (res > 0) {
            return static_cast<uint64_t>(res);
          }
          return res;
        }
      }
    case Operator::MUL:
      if (left == 0 || right == 0) {
        return 0;
      }
      if (left > 0 && right > 0) {
        if (left <= std::numeric_limits<T>::max() / right) {
          return left * right;
        }
        return std::nullopt;
      }
      if constexpr (std::is_same_v<T, int64_t>) {
        if (left > 0 && right < 0 &&
            left <= std::numeric_limits<T>::min() / right) {
          return left * right;
        }
        if (left < 0 && right > 0 &&
            right <= std::numeric_limits<T>::min() / left) {
          return left * right;
        }
        if (left < 0 && right < 0) {
          return eval_binop(static_cast<uint64_t>(left),
                            static_cast<uint64_t>(right),
                            op);
        }
        __builtin_unreachable();
      }
      return std::nullopt;
    case Operator::DIV:
      if (right == 0) {
        return std::nullopt;
      }
      return left / right;
    case Operator::MOD:
      if (right == 0) {
        return std::nullopt;
      }
      return left % right;
    case Operator::BAND:
      return left & right;
    case Operator::BOR:
      return left | right;
    case Operator::BXOR:
      return left ^ right;
    case Operator::LEFT:
      return left << right;
    case Operator::RIGHT:
      return left >> right;
    case Operator::LAND:
      return static_cast<uint64_t>(left && right);
    case Operator::LOR:
      return static_cast<uint64_t>(left || right);
    case Operator::INVALID:
    case Operator::ASSIGN:
    case Operator::INCREMENT:
    case Operator::DECREMENT:
    case Operator::LNOT:
    case Operator::BNOT:
      break;
  }
  LOG(BUG) << "Unexpected binary operator: " << static_cast<int>(op);
  __builtin_unreachable();
}

Expression *LiteralFolder::visit(Binop &op)
{
  visitAndReplace(&op.left);
  visitAndReplace(&op.right);

  // Check for string cases.
  auto *str = dynamic_cast<String *>(op.left);
  auto *other = op.right;
  if (str == nullptr) {
    str = dynamic_cast<String *>(op.right);
    other = op.left;
  }
  if (str) {
    // For whatever reason you are allowed to fold "foo"+3.
    auto *integer = dynamic_cast<Integer *>(other);
    if (op.op == Operator::PLUS && integer) {
      if (integer->value >= static_cast<uint64_t>(str->value.size())) {
        op.addWarning() << "literal string will always be empty";
        return ast_.make_node<String>("", Location(op.loc));
      }
      return ast_.make_node<String>(str->value.substr(integer->value),
                                    Location(op.loc));
    }

    // Check for another string.
    auto *rs = dynamic_cast<String *>(other);
    if (!rs) {
      // Let's just make sure it's not a negative literal.
      if (dynamic_cast<NegativeInteger *>(other)) {
        op.addError() << "illegal literal operation with strings";
      }
      // This is a mix of a string and something else. This may be a runtime
      // type, and we need to leave it up to the semantic analysis.
      return nullptr;
    }

    switch (op.op) {
      case Operator::EQ:
        return ast_.make_node<Integer>(str->value == rs->value,
                                       Location(op.loc));
      case Operator::NE:
        return ast_.make_node<Integer>(str->value != rs->value,
                                       Location(op.loc));
      case Operator::LE:
        return ast_.make_node<Integer>(str->value <= rs->value,
                                       Location(op.loc));
      case Operator::GE:
        return ast_.make_node<Integer>(str->value >= rs->value,
                                       Location(op.loc));
      case Operator::LT:
        return ast_.make_node<Integer>(str->value < rs->value,
                                       Location(op.loc));
      case Operator::GT:
        return ast_.make_node<Integer>(str->value > rs->value,
                                       Location(op.loc));
      case Operator::LAND:
        return ast_.make_node<Integer>(!str->value.empty() && rs->value.empty(),
                                       Location(op.loc));
      case Operator::LOR:
        return ast_.make_node<Integer>(!str->value.empty() || rs->value.empty(),
                                       Location(op.loc));
      case Operator::PLUS:
        return ast_.make_node<String>(str->value + rs->value, Location(op.loc));
      default:
        // What are they tring to do?
        op.addError() << "illegal literal operation with strings";
        return nullptr;
    }
  }

  // Handle all integer cases.
  std::optional<std::variant<uint64_t, int64_t>> result;
  auto *lu = dynamic_cast<Integer *>(op.left);
  auto *ls = dynamic_cast<NegativeInteger *>(op.left);
  auto *ru = dynamic_cast<Integer *>(op.right);
  auto *rs = dynamic_cast<NegativeInteger *>(op.right);

  // Only allow operations when we can safely marshall to two of the same type.
  // Then `eval_binop` effectively handles all overflow/underflow calculations.
  if (lu && ru) {
    result = eval_binop(lu->value, ru->value, op.op);
  } else if (ls && rs) {
    result = eval_binop(ls->value, rs->value, op.op);
  } else if (lu && rs) {
    if (lu->value <= std::numeric_limits<int64_t>::max()) {
      result = eval_binop(static_cast<int64_t>(lu->value), rs->value, op.op);
    }
  } else if (ls && ru) {
    if (ru->value <= std::numeric_limits<int64_t>::max()) {
      result = eval_binop(ls->value, static_cast<int64_t>(ru->value), op.op);
    }
  } else {
    // This is not an integer expression at all.
    return nullptr;
  }

  if (!result) {
    // This is not a valid expression.
    op.addError() << "unable to fold literals due to overflow or underflow";
    return nullptr;
  }

  return std::visit(
      [&](const auto &v) -> Expression * {
        if constexpr (std::is_same_v<std::decay_t<decltype(v)>, uint64_t>) {
          return ast_.make_node<Integer>(v, Location(op.loc));
        } else {
          return ast_.make_node<NegativeInteger>(v, Location(op.loc));
        }
      },
      result.value());
}

Expression *LiteralFolder::visit(PositionalParameterCount &param)
{
  // This is always an unsigned integer value.
  return ast_.make_node<Integer>(bpftrace_.num_params(), Location(param.loc));
}

Expression *LiteralFolder::visit(PositionalParameter &param)
{
  // By default, we treat parameters as integer literals if we can, and
  // rely on the user to have an explicit `str` cast.
  const std::string &val = bpftrace_.get_param(param.n);
  // If empty, treat as zero. This is the documented behavior.
  if (val.empty()) {
    return ast_.make_node<Integer>(static_cast<uint64_t>(0),
                                   Location(param.loc));
  }
  try {
    if (val[0] == '-') {
      auto v = util::to_int(val, 0);
      return ast_.make_node<NegativeInteger>(v, Location(param.loc));
    } else {
      auto v = util::to_uint(val, 0);
      return ast_.make_node<Integer>(v, Location(param.loc));
    }
  } catch (const std::exception &e) {
    // Treat this as the original string.
    return ast_.make_node<String>(val, Location(param.loc));
  }
}

Expression *LiteralFolder::visit(Call &call)
{
  Visitor<LiteralFolder, Expression *>::visit(call);

  // If this is the string function, then we can evaluate the given literal
  // as a string (e.g. this covers str(0) and str($3)).
  if (call.func == "str" && call.vargs.size() == 1) {
    // If this is an integer of some kind, then fold it into a string.
    if (auto *n = dynamic_cast<Integer *>(call.vargs.at(0))) {
      std::stringstream ss;
      ss << n->value;
      return ast_.make_node<String>(ss.str(), Location(call.loc));
    } else if (auto *n = dynamic_cast<NegativeInteger *>(call.vargs.at(0))) {
      std::stringstream ss;
      ss << n->value;
      return ast_.make_node<String>(ss.str(), Location(call.loc));
    } else if (auto *s = dynamic_cast<String *>(call.vargs.at(0))) {
      return ast_.make_node<String>(s->value, Location(call.loc));
    }
  }
  return nullptr;
}

Pass CreateFoldLiteralsPass()
{
  auto fn = [](ASTContext &ast, BPFtrace &b) {
    LiteralFolder folder(ast, b);
    folder.visit(ast.root);
  };

  return Pass::create("FoldLiterals", fn);
}

} // namespace bpftrace::ast
