#include "rustdemangler.h"

#include "log.h"

namespace bpftrace {

// We may choose to parse the v0 mangled symbols defined by:
// https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html
//
// Or may vendor/link an alternate library to do so.
char* rustdemangle([[maybe_unused]] const char* mangled)
{
  LOG(WARNING) << "Rust demangling is not available.";
  return nullptr;
}

} // namespace bpftrace
