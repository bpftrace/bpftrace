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

std::string ASTSource::read(const SourceLocation &loc)
{
  std::stringstream ss;
  for (int line = loc.begin.line; line <= loc.end.line; line++) {
    auto &srcline = lines_[line - 1];
    if (line == loc.begin.line && line == loc.end.line) {
      ss << srcline.substr(loc.begin.column - 1,
                           loc.end.column - loc.begin.column);
    } else if (line == loc.begin.line) {
      ss << srcline.substr(loc.begin.column - 1);
    } else if (line < loc.end.line - 1) {
      ss << srcline;
    } else {
      ss << srcline.substr(0, loc.end.column - 1);
    }
  }
  return ss.str();
}

std::vector<MetadataIndex::Variant> MetadataIndex::all()
{
  if (map_.empty()) {
    return {};
  }
  std::vector<Variant> result;
  for (const auto &entry : map_) {
    if (std::holds_alternative<VspaceSentinel>(entry.second)) {
      // Just provide the vspace count.
      result.emplace_back(std::get<VspaceSentinel>(entry.second).amount);
    } else if (std::holds_alternative<MetadataIndex::CommentSentinel>(
                   entry.second)) {
      // Load the comment from the serialized source.
      result.emplace_back(source_->read(entry.first));
    }
  }
  return result;
}

MetadataIndex MetadataIndex::before(const SourceLocation::Position &pos)
{
  MetadataIndex result(source_);
  auto it = map_.begin();
  while (it != map_.end()) {
    if (it->first.begin.line > pos.line ||
        (it->first.begin.line == pos.line &&
         it->first.begin.column > pos.column)) {
      break;
    }
    result.map_.emplace(it->first, it->second);
    it = map_.erase(it);
  }
  return result;
}

ASTContext::ASTContext(std::string &&filename, std::string &&contents)
    : state_(std::make_unique<State>()),
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
  state_->nodes_.clear();
  state_->diagnostics_->clear();
}

ASTContext::State::State() : diagnostics_(std::make_unique<Diagnostics>())
{
}

} // namespace bpftrace::ast
