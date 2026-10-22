#pragma once

#include <cassert>
#include <cstddef>
#include <sstream>

#include "ast/ast.h"

namespace bpftrace::ast {

inline bool check_nargs(const Call &call, size_t min_args, size_t max_args)
{
  auto nargs = call.vargs.size();
  assert(nargs >= call.injected_args);
  assert(min_args >= call.injected_args);
  assert(max_args >= call.injected_args);
  nargs -= call.injected_args;
  min_args -= call.injected_args;
  max_args -= call.injected_args;

  if (nargs >= min_args && nargs <= max_args) {
    return true;
  }

  std::stringstream err;
  if (min_args == max_args) {
    if (max_args == 0) {
      err << call.func << "() requires no arguments";
    } else if (max_args == 1) {
      err << call.func << "() requires one argument";
    } else {
      err << call.func << "() requires " << max_args << " arguments";
    }
  } else if (nargs < min_args) {
    if (min_args == 1) {
      err << call.func << "() requires at least one argument";
    } else {
      err << call.func << "() requires at least " << min_args << " arguments";
    }
  } else if (max_args == 0) {
    err << call.func << "() requires no arguments";
  } else if (max_args == 1) {
    err << call.func << "() takes up to one argument";
  } else {
    err << call.func << "() takes up to " << max_args << " arguments";
  }
  err << " (" << nargs << " provided)";
  call.addError() << err.str();
  return false;
}

} // namespace bpftrace::ast
