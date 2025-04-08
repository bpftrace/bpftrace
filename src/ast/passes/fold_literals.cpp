#include "ast/passes/fold_literals.h"
#include "ast/ast.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"
#include "util/int_parser.h"

namespace bpftrace::ast {

namespace {

class LiteralFolder : public Visitor<LiteralFolder, std::optional<Expression>> {
public:
  LiteralFolder(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(bpftrace) {};

  using Visitor<LiteralFolder, std::optional<Expression>>::visit;

  std::optional<Expression> visit(Cast &cast);
  std::optional<Expression> visit(Unop &op);
  std::optional<Expression> visit(Binop &op);
  std::optional<Expression> visit(PositionalParameterCount &param);
  std::optional<Expression> visit(PositionalParameter &param);
  std::optional<Expression> visit(Call &call);
  std::optional<Expression> visit(Expression &expr);

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
  auto clamp = [](auto v) -> std::variant<uint64_t, int64_t> {
    if constexpr (std::is_same_v<T, int64_t>) {
      if (v >= 0) {
        return static_cast<uint64_t>(v);
      }
    }
    return v;
  };

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
        return clamp(left + right);
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
          return clamp(left + right);
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
          // Ensure that this is representable during conversion. We know that
          // right > left, therefore the delta here is guaranteed to be greater
          // than zero.
          uint64_t delta = right - left - 1;
          auto max = static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
          if (delta > max) {
            return std::nullopt;
          } else {
            return -static_cast<int64_t>(delta) - 1;
          }
        }
      } else {
        if (right == 0) {
          return clamp(left);
        } else if (right < 0) {
          auto res = left - right;
          if (res < left) {
            return std::nullopt;
          }
          return clamp(res);
        } else {
          auto res = left - right;
          if (res > left) {
            return std::nullopt;
          }
          return clamp(res);
        }
      }
    case Operator::MUL:
      if (left == 0 || right == 0) {
        return static_cast<uint64_t>(0);
      } else {
        if constexpr (std::is_same_v<T, int64_t>) {
          // Spill into unsigned.
          if (left < 0 && right < 0) {
            return eval_binop(static_cast<uint64_t>(-(left + 1)) + 1,
                              static_cast<uint64_t>(-(right + 1)) + 1,
                              op);
          }
        }
        auto result = left * right;
        if (result / left != right) {
          return std::nullopt; // Overflow.
        }
        return clamp(result);
      }
    case Operator::DIV:
      if (right == 0) {
        return std::nullopt;
      }
      return clamp(left / right);
    case Operator::MOD:
      if (right == 0) {
        return std::nullopt;
      }
      return clamp(left % right);
    case Operator::BAND:
      return clamp(left & right);
    case Operator::BOR:
      return clamp(left | right);
    case Operator::BXOR:
      return clamp(left ^ right);
    case Operator::LEFT:
      return clamp(left << right);
    case Operator::RIGHT:
      return clamp(left >> right);
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

std::optional<Expression> LiteralFolder::visit(Cast &cast)
{
  visit(cast.expr);
  return std::nullopt;
}

std::optional<Expression> LiteralFolder::visit(Unop &op)
{
  visit(op.expr);

  if (auto *integer = op.expr.as<Integer>()) {
    if (op.op == Operator::BNOT) {
      // Still positive.
      return ast_.make_node<Integer>(~integer->value, Location(op.loc));
    } else if (op.op == Operator::LNOT) {
      // Still positive.
      return ast_.make_node<Integer>(!integer->value, Location(op.loc));
    } else if (op.op == Operator::MINUS) {
      // Ensure that it is representable as a negative value.
      if (integer->value >
          static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1) {
        op.addError() << "negative value will underflow";
        return std::nullopt;
      }
      // Carefully make the conversion. We need to ensure that this does not
      // overflow/underflow while doing the math.
      if (integer->value == 0) {
        return integer; // Drop the operation.
      } else if (integer->value <= 1) {
        return ast_.make_node<NegativeInteger>(
            -static_cast<int64_t>(integer->value), Location(op.loc));
      } else {
        int64_t value = -1;
        value -= static_cast<int64_t>(integer->value - 1);
        return ast_.make_node<NegativeInteger>(value, Location(op.loc));
      }
    }
  } else if (auto *integer = op.expr.as<NegativeInteger>()) {
    if (op.op == Operator::BNOT) {
      // Always positive.
      return ast_.make_node<Integer>(static_cast<uint64_t>(~integer->value),
                                     Location(op.loc));
    } else if (op.op == Operator::LNOT) {
      // Always positive.
      return ast_.make_node<Integer>(static_cast<uint64_t>(!integer->value),
                                     Location(op.loc));
    } else if (op.op == Operator::MINUS) {
      // Ensure that it doesn't overflow. We do this by ensuring that is
      // representable as a positive number, casting, and then adding 1 to
      // the unsigned form.
      int64_t value = integer->value + 1;
      value = -value;
      return ast_.make_node<Integer>(static_cast<uint64_t>(value) + 1,
                                     Location(op.loc));
    }
  }
  return std::nullopt;
}

std::optional<Expression> LiteralFolder::visit(Binop &op)
{
  visit(op.left);
  visit(op.right);

  // Check for string cases.
  auto *str = op.left.as<String>();
  auto other = op.right;
  if (str == nullptr) {
    str = op.right.as<String>();
    other = op.left;
  }
  if (str) {
    // For whatever reason you are allowed to fold "foo"+3.
    auto *integer = other.as<Integer>();
    if (op.op == Operator::PLUS && integer) {
      if (integer->value >= static_cast<uint64_t>(str->value.size())) {
        op.addWarning() << "literal string will always be empty";
        return ast_.make_node<String>("", Location(op.loc));
      }
      return ast_.make_node<String>(str->value.substr(integer->value),
                                    Location(op.loc));
    }

    // Check for another string.
    auto *rs = other.as<String>();
    if (!rs) {
      // Let's just make sure it's not a negative literal.
      if (other.is<NegativeInteger>()) {
        op.addError() << "illegal literal operation with strings";
      }
      // This is a mix of a string and something else. This may be a runtime
      // type, and we need to leave it up to the semantic analysis.
      return std::nullopt;
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
        return std::nullopt;
    }
  }

  // Handle all integer cases.
  std::optional<std::variant<uint64_t, int64_t>> result;
  auto *lu = op.left.as<Integer>();
  auto *ls = op.left.as<NegativeInteger>();
  auto *ru = op.right.as<Integer>();
  auto *rs = op.right.as<NegativeInteger>();

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
    return std::nullopt;
  }

  if (!result) {
    // This is not a valid expression.
    op.addError() << "unable to fold literals due to overflow or underflow";
    return std::nullopt;
  }

  return std::visit(
      [&](const auto &v) -> Expression {
        if constexpr (std::is_same_v<std::decay_t<decltype(v)>, uint64_t>) {
          return ast_.make_node<Integer>(v, Location(op.loc));
        } else {
          return ast_.make_node<NegativeInteger>(v, Location(op.loc));
        }
      },
      result.value());
}

std::optional<Expression> LiteralFolder::visit(PositionalParameterCount &param)
{
  // This is always an unsigned integer value.
  return ast_.make_node<Integer>(bpftrace_.num_params(), Location(param.loc));
}

std::optional<Expression> LiteralFolder::visit(PositionalParameter &param)
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

std::optional<Expression> LiteralFolder::visit(Call &call)
{
  // If this is the string function, then we can evaluate the given literal
  // as a string (e.g. this covers str(0) and str($3)).
  if (call.func == "str" && !call.vargs.empty()) {
    std::string s;

    // First, we need to check if this directly wraps a positional parameter.
    // If yes, then we prevent it from expanding to zero as is the default.
    if (auto *param = call.vargs.at(0).as<PositionalParameter>()) {
      call.vargs[0] = ast_.make_node<String>(bpftrace_.get_param(param->n),
                                             Location(param->loc));
    } else if (auto *binop = call.vargs.at(0).as<Binop>()) {
      auto *param = binop->left.as<PositionalParameter>();
      if (param && binop->op == Operator::PLUS) {
        binop->left = ast_.make_node<String>(bpftrace_.get_param(param->n),
                                             Location(param->loc));
      }
    }

    // Now we can expand normally.
    Visitor<LiteralFolder, std::optional<Expression>>::visit(call);

    // If this is an integer of some kind, then fold it into a string.
    if (auto *n = call.vargs.at(0).as<Integer>()) {
      std::stringstream ss;
      ss << n->value;
      s = ss.str();
    } else if (auto *n = call.vargs.at(0).as<NegativeInteger>()) {
      std::stringstream ss;
      ss << n->value;
      s = ss.str();
    } else if (auto *str = call.vargs.at(0).as<String>()) {
      s = str->value;
    } else {
      return std::nullopt;
    }

    // Handle optional truncation.
    if (call.vargs.size() >= 2) {
      if (auto *n = call.vargs.at(1).as<Integer>()) {
        // Truncate the string.
        if (s.size() >= n->value) {
          s = s.substr(0, n->value);
        }
      } else {
        return std::nullopt;
      }
    }
    return ast_.make_node<String>(s, Location(call.loc));
  } else {
    // Visit normally.
    Visitor<LiteralFolder, std::optional<Expression>>::visit(call);
  }

  return std::nullopt;
}

std::optional<Expression> LiteralFolder::visit(Expression &expr)
{
  auto r = Visitor<LiteralFolder, std::optional<Expression>>::visit(expr.value);
  if (r) {
    expr.value = r->value;
  }
  return std::nullopt;
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
