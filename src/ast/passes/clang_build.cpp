#include <clang/CodeGen/CodeGenAction.h>
#include <clang/Driver/Driver.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Frontend/TextDiagnosticPrinter.h>
#include <fcntl.h>
#include <llvm/ADT/IntrusiveRefCntPtr.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/VirtualFileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/TargetParser/Host.h>
#include <sys/mman.h>

#include "arch/arch.h"
#include "ast/ast.h"
#include "ast/passes/clang_build.h"
#include "ast/passes/codegen_llvm.h"
#include "ast/passes/resolve_imports.h"
#include "bpftrace.h"
#include "stdlib/stdlib.h"
#include "util/cache.h"
#include "util/memfd.h"
#include "util/result.h"

namespace bpftrace::ast {

using util::CacheObject;

char ClangBuildError::ID;

void ClangBuildError::log(llvm::raw_ostream &OS) const
{
  OS << msg_;
}

static Result<std::map<std::string, CacheObject>> build(
    CompileContext &ctx,
    const std::string &name,
    const std::map<std::string, std::unique_ptr<llvm::MemoryBuffer>> &headers,
    const std::unique_ptr<llvm::MemoryBuffer> &source,
    Node &node)
{
  // Add all the files to our internal VFS.
  llvm::IntrusiveRefCntPtr<llvm::vfs::InMemoryFileSystem> vfs(
      new llvm::vfs::InMemoryFileSystem());
  vfs->addFileNoOwn(name, 0, source->getMemBufferRef());
  for (const auto &[header_name, header_obj] : headers) {
    vfs->addFileNoOwn(header_name, 0, header_obj->getMemBufferRef());
  }

  // Create the diagnostic options and client. We emit the error to
  // a string, which we can then capture and associate with the import.
  std::string errstr;
  llvm::raw_string_ostream err(errstr);
#if LLVM_VERSION_MAJOR < 21
  auto diagOpts = llvm::makeIntrusiveRefCnt<clang::DiagnosticOptions>();
  auto diags = std::make_unique<clang::DiagnosticsEngine>(
      llvm::makeIntrusiveRefCnt<clang::DiagnosticIDs>(),
      diagOpts,
      new clang::TextDiagnosticPrinter(err, diagOpts.get()));
#else
  // Clang 21: DiagnosticOptions is NOT intrusive-refcounted anymore.
  // Keep it alive for the program lifetime (or store it on a longer-lived
  // object).
  static std::shared_ptr<clang::DiagnosticOptions> diagOpts =
      std::make_shared<clang::DiagnosticOptions>();
  llvm::IntrusiveRefCntPtr<clang::DiagnosticIDs> diagID(
      new clang::DiagnosticIDs());
  auto client = std::make_unique<clang::TextDiagnosticPrinter>(err, *diagOpts);
  auto diags = std::make_unique<clang::DiagnosticsEngine>(diagID,
                                                          *diagOpts,
                                                          client.release());
#endif
  // We create a temporary memfd that we can use to store the output,
  // since the ClangDriver API is framed in terms of filenames. Perhaps
  // we could use the internals here, but that carries other risks.
  auto memfd = util::MemFd::create(name);
  if (!memfd) {
    return memfd.takeError();
  }

  // Create the compiler invocation. Note that the `-O2` introduces some passes
  // that seem to be load-bearing with respect to generating useful debug
  // information, for some reason. The generated module will be linked and
  // optimized again regardless, but it is better safe than sorry.
  std::vector<const char *> args;
  args.push_back("-O2");
  args.push_back("-Iinclude");
  for (const auto &s : arch::Host::c_defs()) {
    args.push_back("-D");
    args.push_back(s.c_str());
  }
  args.push_back("-o");
  args.push_back(memfd->path().c_str());
  args.push_back(name.c_str());

  // Configure the instance. We want to read the source file named
  // by `name` above, enable debug information and optimization.
  auto inv = std::make_shared<clang::CompilerInvocation>();
  clang::CompilerInvocation::CreateFromArgs(*inv,
                                            llvm::ArrayRef<const char *>(args),
                                            *diags);
  inv->getTargetOpts().Triple = "bpf";
  inv->getCodeGenOpts().setDebugInfo(llvm::codegenoptions::FullDebugInfo);
  inv->getCodeGenOpts().DebugColumnInfo = true;

  clang::CompilerInstance ci;
  // Cross-version friendly: assign into the existing invocation
  // (works across modern Clang majors, including 21)
  ci.getInvocation() = *inv;
  ci.setDiagnostics(diags.release());
  ci.setFileManager(new clang::FileManager(clang::FileSystemOptions(), vfs));
#if LLVM_VERSION_MAJOR >= 22
  ci.createSourceManager();
#else
  ci.createSourceManager(ci.getFileManager());
#endif

  // Generate the object file, which should include the required BTF
  // debug information. This also generates the module as a
  // side-effect, which is what we actually extract for linking.
  std::unique_ptr<clang::CodeGenAction> action =
      std::make_unique<clang::EmitObjAction>(ctx.context.get());
  if (!ci.ExecuteAction(*action)) {
    // This is likely a build failure, we can surface this
    // directly into the user context. We first highlight the
    // location of the original import, then include the C message
    // as a "hint".
    auto &e = node.addError();
    e << "failed to build";
    e.addHint() << errstr;
    return make_error<ClangBuildError>("compilation failed");
  }
  if (!errstr.empty()) {
    // If the compilation didn't fail, then these weren't errors but we
    // can surface them as compilation warnings.
    auto &e = node.addWarning();
    e << "found external warnings";
    e.addHint() << errstr;
  }
  std::unique_ptr<llvm::Module> mod = action->takeModule();
  if (!mod) {
    // This is an internal error, not suitable to surface as a user
    // diagnostic. Surface it directly as an error in the pipeline.
    return make_error<ClangBuildError>("failed to generate module");
  }
  auto data = memfd->read_all();
  if (!data) {
    return data.takeError();
  }

  // Serialize the LLVM module to bitcode.
  std::string bitcode;
  llvm::raw_string_ostream rso(bitcode);
  llvm::WriteBitcodeToFile(*mod, rso);
  rso.flush();

  // All set.
  return std::map<std::string, CacheObject>{
    { "bc", CacheObject(std::move(bitcode)) },
    { "o", CacheObject(std::move(*data)) },
  };
}

ast::Pass CreateClangBuildPass()
{
  return ast::Pass::create(
      "ClangBuilder",
      [](BPFtrace &bpftrace,
         CompileContext &ctx,
         ast::Imports &imports) -> Result<BitcodeModules> {
        BitcodeModules result;

        // Construct our list of all inputs. We first include all headers,
        // because they are made available to all source files, and therefore
        // any change here could result in something changing in the build.
        util::CacheManager cache;
        std::map<std::string, std::unique_ptr<llvm::MemoryBuffer>> all_headers;
        std::vector<std::string> all_keys = { "clang_build" };
        std::vector<std::reference_wrapper<const CacheObject>> all_inputs;
        for (auto &[name, import] : imports.c_headers) {
          all_keys.push_back(name);
          all_headers.emplace(name,
                              llvm::MemoryBuffer::getMemBufferCopy(
                                  llvm::StringRef(import.obj.data()), name));
          all_inputs.emplace_back(std::cref(import.obj));
        }

        // Add all the internal headers. N.B. It is critical that we reserve
        // this vector up front, since we store references to the objects that
        // we are adding to the vector, and they must not move from this point.
        std::vector<CacheObject> internal_headers;
        internal_headers.reserve(stdlib::Stdlib::files.size());
        std::string asm_dir = "include/asm/" + arch::Host::asm_arch() + "/";
        for (const auto &[name, other] : stdlib::Stdlib::files) {
          // If this include file is an arch-specific assembly file, then we
          // skip if it does not match the current architecture. If it *does*
          // match the current architecture, then we remap it as the `asm`
          // directory (without the arch prefix).
          if (name.starts_with("include/asm/")) {
            if (!name.starts_with(asm_dir)) {
              continue; // Not our architecture.
            }
            // Replace the arch-specific path with just the asm path.
            std::string nn = "include/asm/" + name.substr(asm_dir.size());
            auto &header = internal_headers.emplace_back(std::string(other));
            all_keys.push_back(nn);
            all_headers.emplace(nn,
                                llvm::MemoryBuffer::getMemBufferCopy(
                                    llvm::StringRef(header.data()), name));
            all_inputs.emplace_back(std::cref(header));
          } else {
            // Just use the existing name.
            auto &header = internal_headers.emplace_back(std::string(other));
            all_keys.push_back(name);
            all_headers.emplace(name,
                                llvm::MemoryBuffer::getMemBufferCopy(
                                    llvm::StringRef(header.data()), name));
            all_inputs.emplace_back(std::cref(header));
          }
        }

        // Next, attempt to load our vmlinux.h. This is always made available
        // as part of the headers in a special spot, and is cached separately.
        auto vmlinux_result = cache.lookup(
            { "vmlinux_h" }, {}, "vmlinux.h", [&]() -> Result<CacheObject> {
              return CacheObject(bpftrace.btf_->c_def());
            });
        if (!vmlinux_result) {
          return vmlinux_result.takeError();
        }
        auto vmlinux_h = std::move(*vmlinux_result);
        all_keys.emplace_back("include/vmlinux.h");
        all_headers.emplace("include/vmlinux.h",
                            llvm::MemoryBuffer::getMemBufferCopy(
                                llvm::StringRef(vmlinux_h.data()),
                                "include/vmlinux.h"));
        all_inputs.emplace_back(std::cref(vmlinux_h));

        // For each of the source files in the imports, we build it and cache
        // both the serialized LLVM bitcode, and the object file.
        for (auto &[name, import] : imports.c_sources) {
          all_keys.push_back(name);
          all_inputs.emplace_back(std::cref(import.obj)); // Popped below.
          auto fn = [&]() -> auto {
            return build(ctx,
                         name,
                         all_headers,
                         llvm::MemoryBuffer::getMemBufferCopy(import.obj.data(),
                                                              name),
                         import.node);
          };

          // Each compilation must be cached separately.
          auto ok = cache.lookup(all_keys, all_inputs, { "bc", "o" }, fn);
          if (ok) {
            // On success, we need to deserialize the bitcode.
            auto bitcode = llvm::MemoryBuffer::getMemBufferCopy(
                llvm::StringRef(ok->at("bc").data()), name);
            auto mod = llvm::parseBitcodeFile(bitcode->getMemBufferRef(),
                                              *ctx.context);
            if (!mod) {
              return make_error<ClangBuildError>(
                  "failed to parse generated bitcode");
            }
            // Add to our result set.
            result.modules.emplace_back(std::move(*mod));
            result.objects.emplace_back(std::move(ok->at("o")));
          }

          all_keys.pop_back();
          all_inputs.pop_back(); // See above.
        }
        return result;
      });
}

} // namespace bpftrace::ast
