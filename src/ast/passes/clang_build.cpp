#include <clang/CodeGen/CodeGenAction.h>
#include <clang/Driver/Driver.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Frontend/TextDiagnosticPrinter.h>
#include <fcntl.h>
#include <fstream>
#include <llvm/ADT/IntrusiveRefCntPtr.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/VirtualFileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/TargetParser/Host.h>
#include <sstream>

#if LLVM_VERSION_MAJOR <= 16
#include <clang/Basic/DebugInfoOptions.h>
#endif

#include "ast/ast.h"
#include "ast/passes/clang_build.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/resolve_imports.h"
#include "stdlib/stdlib.h"
#include "util/result.h"

namespace bpftrace::ast {

char ClangBuildError::ID;

void ClangBuildError::log(llvm::raw_ostream &OS) const
{
  OS << msg_;
}

namespace {

class PipeFds {
public:
  PipeFds(int rfd, int wfd)
      : rfd_(rfd),
        wfd_(wfd),
        read_("/dev/fd/" + std::to_string(rfd)),
        write_("/dev/fd/" + std::to_string(wfd)) {};
  PipeFds(PipeFds &&other)
      : rfd_(other.rfd_),
        wfd_(other.wfd_),
        read_(other.read_),
        write_(other.write_)
  {
    other.rfd_ = -1;
    other.wfd_ = -1;
  }
  PipeFds(const PipeFds &other) = delete;
  ~PipeFds()
  {
    close_read();
    close_write();
  }

  const std::string &write_file()
  {
    return write_;
  }

  std::string read_all()
  {
    close_write();
    std::ifstream file(read_);
    if (file.fail()) {
      return ""; // Nothing to read.
    }
    std::stringstream contents;
    contents << file.rdbuf();
    return contents.str();
  }

  void close_read()
  {
    if (rfd_ >= 0) {
      close(rfd_);
      rfd_ = -1;
    }
  }

  void close_write()
  {
    if (wfd_ >= 0) {
      close(wfd_);
      wfd_ = -1;
    }
  }

private:
  int rfd_ = -1;
  int wfd_ = -1;
  std::string read_;
  std::string write_;
};

Result<PipeFds> create_pipe()
{
  int fds[2];
  if (pipe2(fds, O_CLOEXEC) < 0) {
    return make_error<ClangBuildError>("failed to create pipes");
  }
  return PipeFds(fds[0], fds[1]);
}

} // namespace

static Result<> build(CompileContext &ctx,
                      const std::string &name,
                      LoadedObject &obj,
                      Imports &imports,
                      BitcodeModules &result)
{
  llvm::IntrusiveRefCntPtr<llvm::vfs::InMemoryFileSystem> vfs(
      new llvm::vfs::InMemoryFileSystem());
  vfs->addFile(name, 0, llvm::MemoryBuffer::getMemBuffer(obj.data()));
  for (const auto &[name, other] : stdlib::Stdlib::files) {
    vfs->addFile(name, 0, llvm::MemoryBuffer::getMemBuffer(other));
  }
  for (auto &[name, other] : imports.c_headers) {
    vfs->addFile(name, 0, llvm::MemoryBuffer::getMemBuffer(other.data()));
  }

  // Create the diagnostic options and client. We emit the error to
  // a string, which we can then capture and associate with the import.
  std::string errstr;
  llvm::raw_string_ostream err(errstr);
  auto diagOpts = llvm::makeIntrusiveRefCnt<clang::DiagnosticOptions>();
  auto diags = std::make_unique<clang::DiagnosticsEngine>(
      llvm::makeIntrusiveRefCnt<clang::DiagnosticIDs>(),
      diagOpts,
      new clang::TextDiagnosticPrinter(err, diagOpts.get()));

  // We create a temporary pipe that we can use to splurp the output,
  // since the ClangDriver API is framed in terms of filenames. Perhaps
  // we could use the internals here, but that carries other risks.
  auto pipefds = create_pipe();
  if (!pipefds) {
    return pipefds.takeError();
  }

  // Create the compiler invocation. Note that the `-O2` introduces some passes
  // that seem to be load-bearing with respect to generating useful debug
  // information, for some reason. The generated module will be linked and
  // optimized again regardless, but it is better safe than sorry.
  std::vector<const char *> args = {
    "-O2", "-Iinclude", "-o", pipefds->write_file().c_str(), name.c_str()
  };

  // Configure the instance. We want to read the source file named
  // by `name` above, enable debug information and optimization.
  auto inv = std::make_shared<clang::CompilerInvocation>();
  clang::CompilerInvocation::CreateFromArgs(*inv,
                                            llvm::ArrayRef<const char *>(args),
                                            *diags);
  inv->getTargetOpts().Triple = "bpf";
#if LLVM_VERSION_MAJOR <= 16
  inv->getCodeGenOpts().setDebugInfo(clang::codegenoptions::FullDebugInfo);
#else
  inv->getCodeGenOpts().setDebugInfo(llvm::codegenoptions::FullDebugInfo);
#endif
  inv->getCodeGenOpts().DebugColumnInfo = true;

  clang::CompilerInstance ci;
  ci.setInvocation(inv);
  ci.setDiagnostics(diags.release());
  ci.setFileManager(new clang::FileManager(clang::FileSystemOptions(), vfs));
  ci.createSourceManager(ci.getFileManager());

  // Generate the object file, which should include the required BTF
  // debug information. This also generates the module as a
  // side-effect, which is what we actually extract for linking.
  std::unique_ptr<clang::CodeGenAction> action =
      std::make_unique<clang::EmitObjAction>(ctx.context.get());
  if (!ci.ExecuteAction(*action)) {
    // This is likely a build failure, we can surface this directly
    // into the user context. We first highlight the location of the
    // original import, then include the C message as a "hint".
    auto &e = obj.node.addError();
    e << "failed to build";
    e.addHint() << errstr;
    return OK();
  }
  if (!errstr.empty()) {
    // If the compilation didn't fail, then these weren't errors but we
    // can surface them as compilation warnings.
    auto &e = obj.node.addWarning();
    e << "found external warnings";
    e.addHint() << errstr;
  }
  std::unique_ptr<llvm::Module> mod = action->takeModule();
  if (!mod) {
    // This is an internal error, not suitable to surface as a user
    // diagnostic. Surface it directly as an error in the pipeline.
    return make_error<ClangBuildError>("failed to generate module");
  }
  result.modules.emplace_back(std::move(mod));
  result.objects.emplace_back(pipefds->read_all());
  return OK();
}

ast::Pass CreateClangBuildPass()
{
  return ast::Pass::create("ClangBuilder",
                           [](CompileContext &ctx,
                              ast::Imports &imports) -> Result<BitcodeModules> {
                             BitcodeModules result;

                             // For each of the source files in the imports, we
                             // build it and turn it into a bitcode file.
                             for (auto &[name, obj] : imports.c_sources) {
                               auto ok = build(ctx, name, obj, imports, result);
                               if (!ok) {
                                 return ok.takeError();
                               }
                             }

                             return result;
                           });
}

} // namespace bpftrace::ast
