#pragma once

namespace bpftrace {
class BPFtrace;
}

namespace bpftrace::ast {

class ASTContext;
class TypeMap;
struct CDefinitions;
struct TypeMetadata;

void RunTypeChecker(ASTContext &ast,
                    BPFtrace &b,
                    CDefinitions &c_definitions,
                    TypeMetadata &types,
                    const TypeMap &type_map);

} // namespace bpftrace::ast
