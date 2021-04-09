#include "remove_positional_params.h"
#include "log.h"
#include "parser.tab.hh"

namespace bpftrace {
namespace ast {

namespace {

Call *new_call(Call &call, ExpressionList args)
{
  auto c = call.leafcopy();
  c->vargs = new ExpressionList;
  for (auto e : args)
    c->vargs->push_back(e);
  return c;
}

} // namespace

Node *PositionalParamTransformer::visit(PositionalParameter &param)
{
  auto make_int = [&param](int n) { return new Integer(n, param.loc); };

  switch (param.ptype)
  {
    case PositionalParameterType::count: {
      if (in_str_)
      {
        LOG(ERROR, param.loc, err_) << "use $#, not str($#)";
        return new String("", param.loc);
      }
      return make_int(bpftrace_->num_params());
    }
    case PositionalParameterType::positional: {
      if (param.n <= 0)
      {
        LOG(ERROR, param.loc, err_)
            << "$" << std::to_string(param.n) + " is not a valid parameter";
        return make_int(0);
      }

      auto pstr = bpftrace_->get_param(param.n, in_str_);
      auto numeric = is_numeric(pstr);

      if (in_str_)
      {
        return new String(pstr, param.loc);
      }

      if (!numeric && !in_str_)
      {
        LOG(ERROR, param.loc, err_)
            << "$" << param.n << " used numerically but given \"" << pstr
            << "\". Try using str($" << param.n << ").";
        return make_int(0);
      }

      auto n = std::stoll(pstr, nullptr, 0);
      return make_int(n);
    }
    default:
      LOG(ERROR, param.loc, err_) << "unknown parameter type";
      return make_int(0);
  }

  return param.leafcopy();
}

Node *PositionalParamTransformer::visit(Binop &binop)
{
  /*
     Simplify addition on string literals

     We allow str($1 +3) as a construct to offset into a string. As str() only
     sees a binop() we simplify it here
   */
  if (!in_str_ || binop.op != bpftrace::Parser::token::PLUS)
    return Mutator::visit(binop);

  auto left = Value<Expression>(binop.left);
  auto right = Value<Expression>(binop.right);

  auto str_node = dynamic_cast<String *>(left);
  auto offset_node = dynamic_cast<Integer *>(right);
  if (!str_node)
  {
    str_node = dynamic_cast<String *>(right);
    offset_node = dynamic_cast<Integer *>(left);
  }

  if (!(str_node && offset_node))
  {
    auto b = binop.leafcopy();
    b->left = left;
    b->right = right;
    return b;
  }

  auto len = str_node->str.length();
  auto offset = offset_node->n;

  Node *node = nullptr;
  if (offset < 0 || (size_t)offset >= len)
  {
    LOG(ERROR, binop.loc, err_)
        << "cannot use offset that exceeds string length"
        << "(" << offset << " >= " << len << ")";

    node = new String("", binop.loc);
  }
  else
  {
    node = new String(str_node->str.substr(offset, std::string::npos),
                      binop.loc);
  }

  delete offset_node;
  delete str_node;
  return node;
}

Node *PositionalParamTransformer::visit(Call &call)
{
  /*
     Simplify str() with positional param calls.

     We allow some "weird" construct inside str(), e.g.
     str($1), str($1 + 3), str($1 + 3, 3) all valid.

     This simplifies these calls and replaces them with their
     string constant which makes the semantic analysis easier
     and the codegen more efficient.

     $1 == "123456789"; str($1+3, 3)  => "456"

   */
  if (call.func != "str" || !call.vargs)
    return Mutator::visit(call);

  // Invalid, let semantic phase handle this
  if (call.vargs->size() > 2)
    return Mutator::visit(call);

  /*
     with str($1, $2) we need an integer value for $2, so only
     set `in_str_` for the first expr
  */
  in_str_ = true;
  ast::Expression *arg0 = Value<Expression>(call.vargs->at(0));
  in_str_ = false;

  auto str_val = dynamic_cast<String *>(arg0);

  if (call.vargs->size() == 1)
  {
    // str("abc") => "abc"
    if (str_val)
      return arg0;
    // str(arg0) => str(arg0)
    return new_call(call, { arg0 });
  }

  auto arg1 = Value<Expression>(call.vargs->at(1));
  auto size_val = dynamic_cast<Integer *>(arg1);
  // str("abc", 3)
  if (str_val && size_val)
  {
    auto ret = new String(str_val->str.substr(0, size_val->n), call.loc);
    delete arg0;
    delete arg1;
    return ret;
  }
  // str("abc", arg0) | str(arg0, arg1)
  return new_call(call, { arg0, arg1 });
}

Pass CreateRemovePositionalParamPass()
{
  auto passname = "RemovePositionalParams";
  auto fn = [passname](Node &n, PassContext &ctx) {
    auto pass = PositionalParamTransformer(&ctx.b);
    auto newroot = pass.Visit(n);
    auto errors = pass.err_.str();
    if (!errors.empty())
    {
      ctx.out << errors;
      return PassResult::Error(passname, 1);
    }
    return PassResult::Success(newroot);
  };

  return Pass(passname, fn);
};

} // namespace ast
} // namespace bpftrace
