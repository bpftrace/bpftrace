#include <clang/CodeGen/CodeGenAction.h>
#include <clang/Driver/Driver.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Frontend/TextDiagnosticPrinter.h>
#include <llvm/ADT/IntrusiveRefCntPtr.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/VirtualFileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/TargetParser/Host.h>

#include "ast/passes/clang_build.h"
#include "ast/passes/resolve_imports.h"
#include "stdlib/stdlib.h"
#include "util/result.h"

namespace bpftrace::ast {

char ClangBuildError::ID;

void ClangBuildError::log(llvm::raw_ostream &OS) const
{
  OS << msg_;
}

ast::Pass CreateClangBuildPass(std::vector<std::string> &&extra_flags)
{
  return ast::Pass::create(
      "ClangBuilder",
      [extra_flags = std::move(extra_flags)](
          ast::Imports &imports) -> Result<BitcodeModules> {
        BitcodeModules result;

        // For each fo the source files in the imports, we build it and turn it
        // into a bitcode file.
        for (auto &[name, obj] : imports.c_sources) {
          llvm::IntrusiveRefCntPtr<llvm::vfs::InMemoryFileSystem> vfs(
              new llvm::vfs::InMemoryFileSystem());
          vfs->addFile(name, 0, llvm::MemoryBuffer::getMemBuffer(obj.data()));
          for (const auto &[name, data] : stdlib::Stdlib::files) {
            vfs->addFile(name, 0, llvm::MemoryBuffer::getMemBuffer(obj.data()));
          }
          for (const auto &[name, data] : imports.c_headers) {
            vfs->addFile(name, 0, llvm::MemoryBuffer::getMemBuffer(obj.data()));
          }

          // Create the diagnostic options and client. We just print to stderr,
          // because we don't have a node that we can associate errors with
          // anyways. It's fine if it looks like we're just running clang, as
          // long as we don't actually need to have clang installed.
          auto diagOpts = llvm::makeIntrusiveRefCnt<clang::DiagnosticOptions>();
          auto diags = std::make_unique<clang::DiagnosticsEngine>(
              llvm::makeIntrusiveRefCnt<clang::DiagnosticIDs>(),
              diagOpts,
              new clang::TextDiagnosticPrinter(llvm::errs(), diagOpts.get()));

          // Create the compiler invocation.
          std::vector<const char *> args = { "-emit-llvm",
                                             "-O2",
                                             name.c_str() };
          for (const auto &arg : extra_flags) {
            args.push_back(arg.c_str());
          }

          // Configure the instance. We want to read the source file named
          // by `name` above, enable debug information and optimization.
          auto inv = std::make_shared<clang::CompilerInvocation>();
          clang::CompilerInvocation::CreateFromArgs(
              *inv, llvm::ArrayRef<const char *>(args), *diags);

          clang::CompilerInstance ci;
          ci.setInvocation(inv);
          ci.setDiagnostics(diags.release());
          ci.setFileManager(
              new clang::FileManager(clang::FileSystemOptions(), vfs));
          ci.createSourceManager(ci.getFileManager());

          // Generate the bitcode for the file.
          std::unique_ptr<clang::CodeGenAction> action =
              std::make_unique<clang::EmitLLVMOnlyAction>();
          if (!ci.ExecuteAction(*action)) {
            return make_error<ClangBuildError>("Failed to build");
          }
          std::unique_ptr<llvm::Module> m = action->takeModule();
          if (!m) {
            return make_error<ClangBuildError>(
                "Failed to generate LLVM module");
          }
          result.modules.emplace_back(std::move(m));
        }

        return result;
      });
}

} // namespace bpftrace::ast
