#pragma once

namespace bpftrace {
class BPFtrace;
}

namespace bpftrace::ast {

class ASTContext;
struct CDefinitions;
struct TypeMetadata;

void RunTypeChecker(ASTContext &ast,
                    BPFtrace &b,
                    CDefinitions &c_definitions,
                    TypeMetadata &types);

} // namespace bpftrace::ast
