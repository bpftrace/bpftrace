#pragma once

#include <iostream>

#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/raw_os_ostream.h"

namespace bpftrace {

// In LLVM, ErrorOr maps a std::error_code, and Expected maps a richer Error
// object. The latter is preferred for newer code, as it allows richer
// expression of errors to be propagated. We map our internal Error type to
// this, but use the `Expected` type. In the future, this could map to
// something like `std::expected<T, Error>`, and we could replace the LLVM
// `Error` with our own.
//
// Out of the box, the LLVM `Error` class provides mandatory checking (errors
// cannot be ignored, they must be explicitly forward or consumed).
template <typename T>
using ErrorOr = llvm::Expected<T>;

// success is used locally in order to indicate success.
//
// It is effectively a monostate class, but using this instead of the default
// llvm `ErrorSuccess` or `Error` means that the bool operator is consistent.
class success {};
using Error = ErrorOr<success>;

// For error types, one can define custom error type by inheriting from
// `ErrorInfo`. For example, you may construct an error as follows:
//
//    class BpfVerifierError : public ErrorInfo<BpfVerifierError> {
//    public:
//      static char ID;
//      void log(llvm::raw_ostream &OS) const override {
//        OS << "End of file reached.";
//      }
//    };
//
template <typename T>
class ErrorInfo : public llvm::ErrorInfo<T> {
public:
  std::error_code convertToErrorCode() const override
  {
    return llvm::inconvertibleErrorCode();
  }
};

// LLVM has its own set of stream classes and wrappers. Provide a simple
// wrappers that supports `std::ostream` using the standardized wrappers.
std::ostream& operator<<(std::ostream& out, const llvm::Error& err);

// All errors are constructed using `make_error<...>` with the error class.
template <typename E, typename... Ts>
auto make_error(Ts... args)
{
  return llvm::make_error<E>(std::forward<Ts>(args)...);
}

// For error handling there are several cases to consider:
//
// (1) If you want to propagate the error, you can return as expected:
//
//   auto ok = doAThing();
//   if (!ok) {
//     return ok.takeError();
//   }
//
// (2) If you need to handle some cases, you can use `handleErrors`. Note that
// you will still need to propagate unhandled cases via (1).
//
//   auto ok = doAThing();
//   if (!ok) {
//     auto ok = handleErrors(ok.takeError(),
//                            [](const BpfVerifierError&) { ... });
//     if (!ok) {
//       return ok.takeError();
//     }
//  }
template <typename E, typename... Ts>
Error handleErrors(E err, Ts... args)
{
  // This changes the semantics of the error propagation to return the wrapper
  // above. This keeps the `operator bool` behavior consistent.
  auto llvmErr = llvm::handleErrors(std::forward<E>(err),
                                    std::forward<Ts>(args)...);
  if (!llvmErr) {
    return success();
  }
  return llvmErr;
}

}; // namespace bpftrace
