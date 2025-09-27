#include <optional>

#include "ast/ast.h"
#include "ast/passes/fold_literals.h"
#include "ast/visitor.h"
#include "bpftrace.h"
#include "log.h"
#include "util/int_parser.h"

namespace bpftrace::ast {

namespace {

const auto FLOW_ERROR = "unable to fold literals due to overflow or underflow";

class LiteralFolder : public Visitor<LiteralFolder, std::optional<Expression>> {
public:
  LiteralFolder(ASTContext &ast) : ast_(ast) {};
  LiteralFolder(ASTContext &ast, BPFtrace &bpftrace)
      : ast_(ast), bpftrace_(std::ref(bpftrace)) {};

  using Visitor<LiteralFolder, std::optional<Expression>>::visit;

  std::optional<Expression> visit(Cast &cast);
  std::optional<Expression> visit(Unop &op);
  std::optional<Expression> visit(Binop &op);
  std::optional<Expression> visit(IfExpr &if_expr);
  std::optional<Expression> visit(PositionalParameterCount &param);
  std::optional<Expression> visit(PositionalParameter &param);
  std::optional<Expression> visit(Call &call);
  std::optional<Expression> visit(Expression &expr);
  std::optional<Expression> visit(Probe &probe);
  std::optional<Expression> visit(Builtin &builtin);
  std::optional<Expression> visit(BlockExpr &block_expr);
  std::optional<Expression> visit(ArrayAccess &acc);
  std::optional<Expression> visit(TupleAccess &acc);
  std::optional<Expression> visit(Comptime &comptime);
  std::optional<Expression> visit(Variable &var);
  std::optional<Expression> visit(Map &map);

  // Skip visiting in type expressions.
  std::optional<Expression> visit([[maybe_unused]] Typeof &typeof)
  {
    return std::nullopt;
  }

private:
  // Return nullopt if we can't compare the tuples now
  // e.g. they contain variables, which are resolved at runtime
  std::optional<bool> compare_tuples(Tuple *left_tuple, Tuple *right_tuple);

  ASTContext &ast_;
  std::optional<std::reference_wrapper<BPFtrace>> bpftrace_;

  bool comptime = false; // Set recursively.
  Node *top_level_node_ = nullptr;
};

} // namespace

static bool eval_bool(Expression expr)
{
  if (auto *integer = expr.as<Integer>()) {
    return integer->value != 0;
  }
  if (expr.is<NegativeInteger>()) {
    return true;
  }
  if (auto *str = expr.as<String>()) {
    return !str->value.empty();
  }
  if (auto *boolean = expr.as<Boolean>()) {
    return boolean->value;
  }
  LOG(BUG) << "Expression is not a literal";
  return false;
}

template <typename T>
static Expression make_boolean(ASTContext &ast, T left, T right, Binop &op)
{
  bool value = true;
  switch (op.op) {
    case Operator::EQ:
      value = left == right;
      break;
    case Operator::NE:
      value = left != right;
      break;
    case Operator::LE:
      value = left <= right;
      break;
    case Operator::GE:
      value = left >= right;
      break;
    case Operator::LT:
      value = left < right;
      break;
    case Operator::GT:
      value = left > right;
      break;
    case Operator::LAND:
      value = left && right;
      break;
    case Operator::LOR:
      value = left || right;
      break;
    case Operator::PLUS:
      value = left + right;
      break;
    case Operator::MINUS:
      value = left - right;
      break;
    case Operator::MUL:
      value = left && right;
      break;
    case Operator::DIV: {
      if (!right) {
        op.addError() << FLOW_ERROR;
      }
      value = static_cast<bool>(left && right);
      break;
    }
    case Operator::MOD:
      if (!right) {
        op.addError() << FLOW_ERROR;
      }
      value = false;
      break;
    case Operator::BAND:
      value = left & right;
      break;
    case Operator::BOR:
      value = left | right;
      break;
    case Operator::BXOR:
      value = left ^ right;
      break;
    case Operator::LEFT:
      value = left < right;
      break;
    case Operator::RIGHT:
      value = left > right;
      break;
    case Operator::LNOT:
    case Operator::BNOT:
    case Operator::INVALID:
    case Operator::ASSIGN:
    case Operator::INCREMENT:
    case Operator::DECREMENT:
      LOG(BUG) << "binary operator is not valid: " << static_cast<int>(op.op);
  }

  return ast.make_node<Boolean>(value, Location(op.loc));
}

std::optional<bool> LiteralFolder::compare_tuples(Tuple *left_tuple,
                                                  Tuple *right_tuple)
{
  if (left_tuple->elems.size() != right_tuple->elems.size()) {
    return false;
  }

  for (size_t i = 0; i < left_tuple->elems.size(); ++i) {
    auto l_expr = left_tuple->elems[i];
    auto r_expr = right_tuple->elems[i];

    visit(l_expr);
    visit(r_expr);

    if (!l_expr.is_literal() || !r_expr.is_literal()) {
      return std::nullopt;
    }

    if (auto *l_int = l_expr.as<Integer>()) {
      if (auto *r_int = r_expr.as<Integer>()) {
        if (l_int->value != r_int->value) {
          return false;
        }
        continue;
      }
      return false;
    }

    if (auto *l_nint = l_expr.as<NegativeInteger>()) {
      if (auto *r_nint = r_expr.as<NegativeInteger>()) {
        if (l_nint->value != r_nint->value) {
          return false;
        }
        continue;
      }
      return false;
    }

    if (auto *l_str = l_expr.as<String>()) {
      if (auto *r_str = r_expr.as<String>()) {
        if (l_str->value != r_str->value) {
          return false;
        }
        continue;
      }
      return false;
    }

    if (auto *l_bool = l_expr.as<Boolean>()) {
      if (auto *r_bool = r_expr.as<Boolean>()) {
        if (l_bool->value != r_bool->value) {
          return false;
        }
        continue;
      }
      return false;
    }

    if (auto *l_tuple = l_expr.as<Tuple>()) {
      if (auto *r_tuple = r_expr.as<Tuple>()) {
        return compare_tuples(l_tuple, r_tuple);
      }
      return false;
    }
  }

  return true;
}

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
        return std::nullopt;
      }
      if constexpr (std::is_same_v<T, int64_t>) {
        if ((left > 0 && right < 0) || (left < 0 && right > 0)) {
          return clamp(left + right);
        }
        if (left < 0 && right < 0) {
          if (std::numeric_limits<int64_t>::min() - left > right)
            return std::nullopt;
          return left + right;
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
        } else {
          if (left > 0 && right < 0 &&
              std::numeric_limits<int64_t>::max() - left < -right) {
            return std::nullopt;
          } else if (left < 0 && right > 0 &&
                     std::numeric_limits<int64_t>::min() - left > -right) {
            return std::nullopt;
          }
          return clamp(left - right);
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
      // Shifting negative amount of bits or more bits than the width of `left`
      // (which is always 64 in our case) is undefined behavior in C++
      if (right < 0 || right >= 64)
        return std::nullopt;
      return clamp(left << right);
    case Operator::RIGHT:
      // Same as above
      if (right < 0 || right >= 64)
        return std::nullopt;
      return clamp(left >> right);
    // Comparison operators are handled in `make_boolean` and checked in
    // `is_comparison_op`.
    case Operator::EQ:
    case Operator::NE:
    case Operator::LE:
    case Operator::GE:
    case Operator::LT:
    case Operator::GT:
    case Operator::LAND:
    case Operator::LOR:
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
  if (cast.type().IsBoolTy() && cast.expr.is_literal()) {
    return ast_.make_node<Boolean>(eval_bool(cast.expr),
                                   Location(cast.expr.loc()));
  }
  return std::nullopt;
}

std::optional<Expression> LiteralFolder::visit(Unop &op)
{
  visit(op.expr);

  if (auto *integer = op.expr.as<Integer>()) {
    bool force_unsigned = !integer->type().IsSigned();
    if (op.op == Operator::BNOT) {
      // Still positive.
      return ast_.make_node<Integer>(~integer->value,
                                     Location(op.loc),
                                     force_unsigned);
    } else if (op.op == Operator::LNOT) {
      return ast_.make_node<Boolean>(!integer->value, Location(op.loc));
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
      return ast_.make_node<Boolean>(!integer->value, Location(op.loc));
    } else if (op.op == Operator::MINUS) {
      // Ensure that it doesn't overflow. We do this by ensuring that is
      // representable as a positive number, casting, and then adding 1 to
      // the unsigned form.
      int64_t value = integer->value + 1;
      value = -value;
      return ast_.make_node<Integer>(static_cast<uint64_t>(value) + 1,
                                     Location(op.loc));
    }
  } else if (auto *boolean = op.expr.as<Boolean>()) {
    // Just supporting logical not for now but we could support other
    // operations like BNOT (e.g. ~false == -1) in the future.
    if (op.op == Operator::LNOT) {
      return ast_.make_node<Boolean>(!boolean->value, Location(op.loc));
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

    auto *rb = other.as<Boolean>();
    if (rb) {
      if (op.op == Operator::LAND || op.op == Operator::LOR) {
        return make_boolean(ast_, !str->value.empty(), rb->value, op);
      }
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
        return ast_.make_node<Boolean>(str->value == rs->value,
                                       Location(op.loc));
      case Operator::NE:
        return ast_.make_node<Boolean>(str->value != rs->value,
                                       Location(op.loc));
      case Operator::LE:
        return ast_.make_node<Boolean>(str->value <= rs->value,
                                       Location(op.loc));
      case Operator::GE:
        return ast_.make_node<Boolean>(str->value >= rs->value,
                                       Location(op.loc));
      case Operator::LT:
        return ast_.make_node<Boolean>(str->value < rs->value,
                                       Location(op.loc));
      case Operator::GT:
        return ast_.make_node<Boolean>(str->value > rs->value,
                                       Location(op.loc));
      case Operator::LAND:
        return ast_.make_node<Boolean>(!str->value.empty() && rs->value.empty(),
                                       Location(op.loc));
      case Operator::LOR:
        return ast_.make_node<Boolean>(!str->value.empty() || rs->value.empty(),
                                       Location(op.loc));
      case Operator::PLUS:
        return ast_.make_node<String>(str->value + rs->value, Location(op.loc));
      default:
        // What are they tring to do?
        op.addError() << "illegal literal operation with strings";
        return std::nullopt;
    }
  }

  // Handle boolean cases.
  auto *boolean = op.left.as<Boolean>();
  other = op.right;
  if (boolean == nullptr) {
    boolean = op.right.as<Boolean>();
    other = op.left;
  }
  if (boolean) {
    auto *other_boolean = other.as<Boolean>();
    if (other_boolean) {
      return make_boolean(ast_, boolean->value, other_boolean->value, op);
    }

    auto *ru = other.as<Integer>();
    if (ru) {
      if (op.op == Operator::LAND || op.op == Operator::LOR) {
        return make_boolean(ast_, boolean->value, ru->value != 0, op);
      }
    }

    auto *rs = other.as<NegativeInteger>();
    if (rs) {
      if (op.op == Operator::LAND || op.op == Operator::LOR) {
        // Negatives are always true.
        return make_boolean(ast_, boolean->value, true, op);
      }
    }
  }

  if (op.left.is<Tuple>() && op.right.is<Tuple>() &&
      (op.op == Operator::EQ || op.op == Operator::NE)) {
    auto *left_tuple = op.left.as<Tuple>();
    auto *right_tuple = op.right.as<Tuple>();
    auto same = compare_tuples(left_tuple, right_tuple);
    if (same) {
      return ast_.make_node<Boolean>(*same ? op.op == Operator::EQ
                                           : op.op == Operator::NE,
                                     Location(op.loc));
    } else {
      // Can't compare here
      return std::nullopt;
    }
  }

  // Handle all integer cases.
  std::optional<std::variant<uint64_t, int64_t>> result;
  auto *lu = op.left.as<Integer>();
  auto *ls = op.left.as<NegativeInteger>();
  auto *ru = op.right.as<Integer>();
  auto *rs = op.right.as<NegativeInteger>();
  bool force_unsigned = false;

  // Only allow operations when we can safely marshall to two of the same type.
  // Then `eval_binop` effectively handles all overflow/underflow calculations.
  if (lu && ru) {
    force_unsigned = !lu->type().IsSigned() || !ru->type().IsSigned();
    if (is_comparison_op(op.op)) {
      return make_boolean(ast_, lu->value, ru->value, op);
    }
    result = eval_binop(lu->value, ru->value, op.op);
  } else if (ls && rs) {
    if (is_comparison_op(op.op)) {
      return make_boolean(ast_, ls->value, rs->value, op);
    }
    result = eval_binop(ls->value, rs->value, op.op);
  } else if (lu && rs) {
    force_unsigned = !lu->type().IsSigned();
    if (lu->value <= std::numeric_limits<int64_t>::max()) {
      if (is_comparison_op(op.op)) {
        return make_boolean(
            ast_, static_cast<int64_t>(lu->value), rs->value, op);
      }
      result = eval_binop(static_cast<int64_t>(lu->value), rs->value, op.op);
    }
  } else if (ls && ru) {
    force_unsigned = !ru->type().IsSigned();
    if (ru->value <= std::numeric_limits<int64_t>::max()) {
      if (is_comparison_op(op.op)) {
        return make_boolean(
            ast_, ls->value, static_cast<int64_t>(ru->value), op);
      }
      result = eval_binop(ls->value, static_cast<int64_t>(ru->value), op.op);
    }
  } else {
    // This is not an integer expression at all.
    return std::nullopt;
  }

  if (!result) {
    // This is not a valid expression.
    op.addError() << FLOW_ERROR;
    return std::nullopt;
  }

  return std::visit(
      [&](const auto &v) -> Expression {
        if constexpr (std::is_same_v<std::decay_t<decltype(v)>, uint64_t>) {
          return ast_.make_node<Integer>(v, Location(op.loc), force_unsigned);
        } else {
          return ast_.make_node<NegativeInteger>(v, Location(op.loc));
        }
      },
      result.value());
}

std::optional<Expression> LiteralFolder::visit(IfExpr &if_expr)
{
  visit(if_expr.left);
  visit(if_expr.right);

  if (auto *comptime = if_expr.cond.as<Comptime>()) {
    visit(comptime->expr);
    if (comptime->expr.is_literal()) {
      if (eval_bool(comptime->expr)) {
        return if_expr.left;
      } else {
        return if_expr.right;
      }
    }
  } else {
    visit(if_expr.cond);
    if (if_expr.cond.is_literal()) {
      // If everything is a literal, we can still fold.
      if (if_expr.left.is_literal() && if_expr.right.is_literal()) {
        if (eval_bool(if_expr.cond)) {
          return if_expr.left;
        } else {
          return if_expr.right;
        }
      } else {
        // At least simplify the conditional expression.
        if_expr.cond = ast_.make_node<Boolean>(eval_bool(if_expr.cond),
                                               Location(if_expr.cond.loc()));
      }
    }
  }

  return std::nullopt;
}

std::optional<Expression> LiteralFolder::visit(PositionalParameterCount &param)
{
  if (!bpftrace_) {
    return std::nullopt;
  }
  // This is always an unsigned integer value.
  return ast_.make_node<Integer>(bpftrace_->get().num_params(),
                                 Location(param.loc),
                                 /*force_unsigned=*/true);
}

std::optional<Expression> LiteralFolder::visit(PositionalParameter &param)
{
  if (!bpftrace_) {
    return std::nullopt;
  }
  // By default, we treat parameters as integer literals if we can, and
  // rely on the user to have an explicit `str` cast.
  const std::string &val = bpftrace_->get().get_param(param.n);
  // If empty, treat as zero. This is the documented behavior.
  if (val.empty()) {
    param.addWarning() << "Positional parameter $" << param.n
                       << " is empty or not provided. ";
    return ast_.make_node<Integer>(static_cast<uint64_t>(0),
                                   Location(param.loc));
  }
  if (val[0] == '-') {
    auto v = util::to_int(val);
    if (!v) {
      // Not parsed, treat it as a string.
      return ast_.make_node<String>(val, Location(param.loc));
    }
    return ast_.make_node<NegativeInteger>(*v, Location(param.loc));
  } else {
    auto v = util::to_uint(val);
    if (!v) {
      // Not parsed, treat it as a string.
      return ast_.make_node<String>(val, Location(param.loc));
    }
    return ast_.make_node<Integer>(*v, Location(param.loc));
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
      if (!bpftrace_) {
        return std::nullopt; // Can't fold yet.
      }
      call.vargs[0] = ast_.make_node<String>(
          bpftrace_->get().get_param(param->n), Location(param->loc));
    } else if (auto *binop = call.vargs.at(0).as<Binop>()) {
      auto *param = binop->left.as<PositionalParameter>();
      if (param && binop->op == Operator::PLUS) {
        if (!bpftrace_) {
          return std::nullopt; // Can't fold yet.
        }
        binop->left = ast_.make_node<String>(
            bpftrace_->get().get_param(param->n), Location(param->loc));
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
    if (!comptime) {
      // Visit normally; we are just simplifying literals.
      Visitor<LiteralFolder, std::optional<Expression>>::visit(call);
    } else {
      // We can't evalute the call here; ensure the error is recorded.
      call.addError() << "Unable to evaluate call at compilation time.";
    }
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

std::optional<Expression> LiteralFolder::visit(Probe &probe)
{
  top_level_node_ = &probe;
  return Visitor<LiteralFolder, std::optional<Expression>>::visit(probe);
}

std::optional<Expression> LiteralFolder::visit(Builtin &builtin)
{
  if (builtin.ident == "__builtin_usermode") {
    if (auto *probe = dynamic_cast<Probe *>(top_level_node_)) {
      for (auto *ap : probe->attach_points) {
        if (!ap->check_available(builtin.ident)) {
          auto probe_type = probetype(ap->provider);
          if (probe_type == ProbeType::special) {
            return ast_.make_node<Integer>(1, Location(builtin.loc));
          }
          return ast_.make_node<Integer>(0, Location(builtin.loc));
        }
      }
    }
  }

  return std::nullopt;
}

std::optional<Expression> LiteralFolder::visit(BlockExpr &expr)
{
  Visitor<LiteralFolder, std::optional<Expression>>::visit(expr);

  // We fold this only if the statement list is empty, and we find a literal
  // as the expression value. We should have recorded an error if there was an
  // attempt to access variables, calls, or generally do anything non-hermetic.
  if (expr.stmts.empty() && (expr.expr.is_literal() || expr.expr.is<Tuple>())) {
    return expr.expr;
  }

  return std::nullopt;
}

std::optional<Expression> LiteralFolder::visit(ArrayAccess &acc)
{
  visit(acc.expr);
  visit(acc.indexpr);

  if (auto *str = acc.expr.as<String>()) {
    if (auto *index = acc.indexpr.as<Integer>()) {
      if (index->value > str->value.size()) {
        // This error happens later on.
        return std::nullopt;
      }
      const char *s = str->value.c_str();
      return ast_.make_node<Integer>(static_cast<uint64_t>(s[index->value]),
                                     Location(acc.loc));
    }
  } else if (comptime) {
    acc.addError() << "Unable to evaluate at compile time.";
  }

  return std::nullopt;
}

std::optional<Expression> LiteralFolder::visit(TupleAccess &acc)
{
  visit(acc.expr);

  // Other elements may contain blocks or statements that are evaluated. We
  // only toss these if we are in a comptime block.
  if (acc.expr.is<Tuple>() && (comptime || acc.expr.is_literal())) {
    auto *tuple = acc.expr.as<Tuple>();
    if (acc.index >= tuple->elems.size()) {
      // This access error happens in a later pass.
      return std::nullopt;
    }
    return tuple->elems[acc.index];
  }

  return std::nullopt;
}

std::optional<Expression> LiteralFolder::visit(Comptime &comptime)
{
  // This will fold into an expression directly. If this should not be used for
  // cases where folding needs to happen above the comptime, e.g. `IfExpr`,
  // which handles this in a special way.
  bool old_comptime = this->comptime;
  this->comptime = true;
  visit(comptime.expr);
  this->comptime = old_comptime;
  if (comptime.expr.is_literal()) {
    return comptime.expr;
  }
  if (auto *nested = comptime.expr.as<Comptime>()) {
    return nested->expr; // Prune redundant comptime.
  }
  return std::nullopt;
}

std::optional<Expression> LiteralFolder::visit(Variable &var)
{
  if (comptime) {
    var.addError() << "Unable to evaluate at compile time.";
  }
  return std::nullopt;
}

std::optional<Expression> LiteralFolder::visit(Map &map)
{
  if (comptime) {
    map.addError() << "Unable to evaluate at compile time.";
  }
  return std::nullopt;
}

void fold(ASTContext &ast, Expression &expr)
{
  LiteralFolder folder(ast);
  folder.visit(expr);
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
