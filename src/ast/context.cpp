#include "ast/context.h"

#include "ast/ast.h"
#include "ast/diagnostic.h"

namespace bpftrace::ast {

ASTSource::ASTSource(std::string &&filename, std::string &&input)
    : filename(std::move(filename)), contents(std::move(input))
{
  std::stringstream ss(contents);
  std::string line;
  while (std::getline(ss, line)) {
    lines_.emplace_back(std::move(line));
  }
}

ASTContext::ASTContext(std::string &&filename, std::string &&contents)
    : diagnostics_(std::make_unique<Diagnostics>()),
      source_(
          std::make_shared<ASTSource>(std::move(filename), std::move(contents)))
{
}

ASTContext::ASTContext(const std::string &filename, const std::string &contents)
    : ASTContext(std::string(filename), std::string(contents))
{
}

ASTContext::ASTContext() : ASTContext("", "")
{
}

void ASTContext::clear()
{
  root = nullptr;
  nodes_.clear();
  diagnostics_->clear();
}

} // namespace bpftrace::ast
