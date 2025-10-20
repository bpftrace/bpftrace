#include <bpf/libbpf.h>
#include <bpf/libbpf_version.h>
#include <cstring>

#include "ast/passes/codegen_llvm.h"
#include "ast/passes/link.h"
#include "ast/passes/resolve_imports.h"
#include "bpfbytecode.h"
#include "scopeguard.h"
#include "util/memfd.h"

namespace bpftrace::ast {

char LinkError::ID;
void LinkError::log(llvm::raw_ostream &OS) const
{
  OS << "linking " << origin_ << ": " << strerror(err_);
}

Pass CreateLinkPass()
{
  return Pass::create(
      "link", [](BpfObject &obj, Imports &imports) -> Result<BpfBytecode> {
        // If there are no other objects to link, then just return our own.
        if (imports.objects.empty()) {
          return BpfBytecode{ obj.data };
        }

        // Construct our list of inputs for the linking.
        util::CacheManager cache;
        std::vector<std::reference_wrapper<const util::CacheObject>> inputs;
        for (auto &[name, import] : imports.objects) {
          inputs.emplace_back(std::cref(import.obj));
        }

        // Add our own binary as the final input.
        auto main = util::CacheObject(
            std::string(obj.data.data(), obj.data.size()));
        inputs.emplace_back(std::cref(main));

        // Our generator function.
        auto link = [&]() -> Result<std::map<std::string, util::CacheObject>> {
          auto memfd = util::MemFd::create("link");
          if (!memfd) {
            return memfd.takeError();
          }

          // In order to craft the final output, since we may have external
          // maps and probes, we delegate the heavy lifting to libbpf.
          struct bpf_linker *linker = bpf_linker__new_fd(memfd->fd(), nullptr);
          if (linker == nullptr) {
            // Hopefully an empty 'origin' here is sufficient to distinguish the
            // case where this failed. I believe that it's likely to be ENOMEM
            // or something equally obvious to the user?
            return make_error<LinkError>("", errno);
          }
          SCOPE_EXIT
          {
            bpf_linker__free(linker);
          };

          // Link in our own program.
          int rc = bpf_linker__add_buf(linker,
                                       const_cast<char *>(main.data().data()),
                                       main.data().size(),
                                       nullptr);
          if (rc != 0) {
            return make_error<LinkError>("main", errno);
          }

          // Next, we iterate through the list of link targets that we collected
          // from import statements.
          for (auto &[name, import] : imports.objects) {
            int rc = bpf_linker__add_buf(linker,
                                         const_cast<char *>(
                                             import.obj.data().data()),
                                         import.obj.data().size(),
                                         nullptr);
            if (rc != 0) {
              return make_error<LinkError>(name, errno);
            }
          }

          // Finalize the linking, and free our underlying library handle.
          rc = bpf_linker__finalize(linker);
          if (rc != 0) {
            return make_error<LinkError>("main", errno);
          }

          // Reload the final output and return it.
          auto result = memfd->read_all();
          if (!result) {
            return result.takeError();
          }
          std::map<std::string, util::CacheObject> m;
          m.emplace("elf", std::move(*result));
          return m;
        };

        // This includes the libbpf version, in case the linking behavior
        // changes across kernels. Note that the kernel version is already
        // encoded here, so this caching should be sensitive to those changes
        // already.
        std::string libpf_ver = std::to_string(LIBBPF_MAJOR_VERSION) + "." +
                                std::to_string(LIBBPF_MINOR_VERSION);
        auto result = cache.lookup(
            { "link", libpf_ver }, inputs, { "elf" }, link);
        if (!result) {
          return result.takeError();
        }
        std::string data = std::string(result->at("elf").data());
        return BpfBytecode{ data };
      });
}

} // namespace bpftrace::ast
