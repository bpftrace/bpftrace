#pragma once

#include "types.h"

namespace bpftrace::ast {
class ASTContext;
class ParsedType;
class LocationChain;
using Location = std::shared_ptr<LocationChain>;
} // namespace bpftrace::ast

namespace bpftrace {

SizedType parsed_type_to_sized_type(const ast::ParsedType &type);
ast::ParsedType *sized_type_to_parsed_type(ast::ASTContext &ctx,
                                           const ast::Location &loc,
                                           const SizedType &type);

} // namespace bpftrace
