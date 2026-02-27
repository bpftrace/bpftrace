#pragma once

#include <optional>

#include "types.h"

namespace bpftrace {
class BPFtrace;
} // namespace bpftrace

namespace bpftrace::ast {

class ASTContext;
class Expression;
struct Program;

std::optional<SizedType> try_tuple_cast(ASTContext &ctx,
                                        Expression &exp,
                                        const SizedType &expr_type,
                                        const SizedType &target_type);

std::optional<SizedType> try_record_cast(ASTContext &ctx,
                                         Expression &exp,
                                         const SizedType &expr_type,
                                         const SizedType &target_type);

void RunCastCreator(ASTContext &ast, BPFtrace &bpftrace);

} // namespace bpftrace::ast
