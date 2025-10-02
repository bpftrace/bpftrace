#pragma once

#include <iostream>

#include "ast/context.h"

namespace bpftrace {

void gendoc(ast::ASTContext &ast, std::ostream &out);

} // namespace bpftrace
