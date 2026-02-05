#pragma once

#include <iostream>

#include "llvm/Support/Error.h"

namespace bpftrace {

// OK is used in order to indicate success without a value type.
//
// It is effectively a monostate class, but using this instead of the default
// llvm `ErrorSuccess` or `Error` means that the bool operator is consistent.
//
// To indicate success, you can merely do `return OK()`.
class OK {};

// Despite the name, in LLVM `ErrorOr` corresponds to a `std::error_code`
// whilst `Expected` corresponds to a richer LLVM `Error`. The latter is
// broadly preferred for newer code, as it allows a much richer expression of
// error information. In an attempt to avoid confusion, we standardize on only
// the modern versions, but call it `Result` to make its purpose clear. In the
// future, this could map to a newer standard, such as the standard library
// `std::expected<T, Error>`, independently of the names in this namespace. The
// purpose of this file is to approximately insulate against such changes (but
// not to provide a perfect abstraction, a little bit of leakage is okay).
//
// For now, the LLVM `Error` class provides mandatory checking (errors cannot
// be ignored, they must be explicitly forward or consumed), which is useful.
//
// You can use Result as follows:
//
//     Result<> foo() {
//       return OK();
//     }
//
//     Result<Value> bar() {
//       return Value();
//     }
//
template <typename T = OK>
using Result = llvm::Expected<T>;

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

// All errors are constructed using `make_error<...>` with the error class.
template <typename E, typename... Ts>
auto make_error(Ts... args)
{
  return llvm::make_error<E>(std::forward<Ts>(args)...);
}

// As a generalized helper, you may use `make_error<SystemError>` to capture a
// specific errno value with a given message. This may be used for general
// purpose utility classes that don't really need specialized error handling.
class SystemError : public ErrorInfo<SystemError> {
public:
  static char ID;
  void log(llvm::raw_ostream& OS) const override;

  SystemError(std::string msg, int err) : msg_(std::move(msg)), err_(err) {};
  SystemError(std::string msg) : SystemError(std::move(msg), errno) {};

  int err() const
  {
    return err_;
  }

private:
  std::string msg_;
  int err_;
};

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
//     auto nowOk = handleErrors(std::move(ok),
//                               [](const BpfVerifierError&) { ... });
//     if (!nowOk) {
//       return nowOk.takeError();
//     }
//  }
//
// (3) You can also in-line error handling if you prefer.
//
//   auto ok = handleErrors(doAThing(), [&](const MyError&) {...});
//
template <typename T, typename... Ts>
Result<> handleErrors(Result<T>&& ok, Ts&&... args)
{
  // If this is being done inline, then we can simply propagate the good news
  // back to the caller.
  if (ok) {
    return OK();
  }

  // This changes the semantics of the error propagation to return the wrapper
  // above. This keeps the `operator bool` behavior consistent.
  auto llvmErr = llvm::handleErrors(ok.takeError(), std::forward<Ts>(args)...);
  if (!llvmErr) {
    return OK();
  }
  return llvmErr;
}

// Silently swallow an error. This method should be used only when an error can
// be considered a reasonable and expected return value.
template <typename T>
void consumeError(Result<T> result)
{
  llvm::consumeError(result.takeError());
}

}; // namespace bpftrace

namespace llvm {

// LLVM has its own set of stream classes and wrappers. Provide a simple
// wrapper that supports `std::ostream` for convenience.
std::ostream& operator<<(std::ostream& out, const Error& err);

} // namespace llvm
