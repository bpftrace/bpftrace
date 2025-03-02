#include "ast/context.h"

#include "ast/ast.h"
#include "ast/diagnostic.h"

namespace bpftrace::ast {

ASTContext::ASTContext(std::string &&filename, std::string &&contents)
    : source_(std::make_shared<ASTSource>(std::move(filename),
                                          std::move(contents))),
      diagnostics_(std::make_unique<Diagnostics>(*source_.get()))
{
}

ASTContext::ASTContext(const std::string &filename, const std::string &contents)
    : ASTContext(std::string(filename), std::string(contents))
{
}

ASTContext::ASTContext() : ASTContext("", "")
{
}

} // namespace bpftrace::ast
