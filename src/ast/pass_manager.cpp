#include "ast/pass_manager.h"

#include "log.h"
#include "util/error.h"

namespace bpftrace::ast {

std::atomic<int> PassContext::next_type_id_;
std::unordered_map<int, std::string> PassContext::type_names_;

void PassContext::fail(int type_id)
{
  // Rely on the type being available, otherwise how did we get here?
  LOG(BUG) << "get<" << lookup_type(type_id)
           << "> failed; no object available.";
  __builtin_unreachable();
}

PassManager& PassManager::add(Pass &&pass)
{
  // Check that the inputs are all available.
  for (const int type_id : pass.inputs()) {
    if (!outputs_.contains(type_id)) {
      auto type_name = PassContext::lookup_type(type_id);
      LOG(BUG) << "Pass " << pass.name() << " requires output " << type_name
               << ", which is not available.";
    }
  }
  // Check that the registered output is unique.
  const int pass_id = passes_.size();
  for (const int type_id : pass.outputs()) {
    if (outputs_.contains(type_id)) {
      auto &orig_pass = passes_[outputs_[type_id]];
      auto type_name = PassContext::lookup_type(type_id);
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

Error PassManager::foreach(std::function<Error(const Pass &)> fn)
{
  for (const auto &pass : passes_) {
    auto err = fn(pass);
    if (!err) {
      return err;
    }
  }
  return success();
}

} // namespace bpftrace::ast
