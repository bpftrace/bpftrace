#include "ast/pass_manager.h"
#include "ast/context.h"
#include "log.h"
#include "util/result.h"

namespace bpftrace::ast {

std::atomic<int> PassContext::next_type_id_;
std::unordered_map<int, std::string> PassContext::type_names_;

PassContext::~PassContext()
{
  // If there are any ordering constraints between passes, it's possible that
  // the pass state objects have encoded references and may use them in their
  // destructors. Therefore, we need to teardown the state in the opposite
  // order that it was added.
  while (!state_.empty()) {
    state_.pop_back();
  }
}

bool PassContext::ok() const
{
  int type_id = TypeId<ASTContext>::type_id();
  if (state_index_.contains(type_id)) {
    return get<ASTContext>().diagnostics().ok();
  }
  return true;
}

void PassContext::no_object_failure(int type_id)
{
  // Rely on the type being available, otherwise how did we get here?
  LOG(BUG) << "get<" << type_names_[type_id]
           << "> failed; no object available.";
  __builtin_unreachable();
}

PassManager &PassManager::add(Pass &&pass)
{
  // Check that the inputs are all available.
  for (const int type_id : pass.inputs()) {
    if (!outputs_.contains(type_id)) {
      auto type_name = PassContext::type_names_[type_id];
      LOG(BUG)
          << "Pass " << pass.name() << " requires output " << type_name
          << ", which is not available; it must be provided by a prior pass.";
    }
  }
  // Check that the registered output is unique.
  const int pass_id = passes_.size();
  for (const int type_id : pass.outputs()) {
    if (outputs_.contains(type_id)) {
      auto &orig_pass = passes_[outputs_[type_id]];
      auto type_name = PassContext::type_names_[type_id];
      LOG(BUG) << "Pass " << pass.name() << " attempting to register output "
               << type_name << ", which is already registered by pass "
               << orig_pass.name() << ".";
    }
    // Register the output.
    outputs_.emplace(type_id, pass_id);
  }
  // Add the actual pass.
  passes_.emplace_back(std::move(pass));
  return *this;
}

PassManager &PassManager::add(std::vector<Pass> &&passes)
{
  for (auto &pass : passes) {
    add(std::move(pass));
  }
  return *this;
}

Result<> PassManager::foreach(std::function<Result<>(const Pass &)> fn)
{
  for (const auto &pass : passes_) {
    auto err = fn(pass);
    if (!err) {
      return err;
    }
  }
  return OK();
}

} // namespace bpftrace::ast
