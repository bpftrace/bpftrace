#pragma once

namespace bpftrace::ast {

class ASTContext;
class TypeMap;

void RunTypeApplicator(ASTContext &ast, const TypeMap &type_map);

} // namespace bpftrace::ast
