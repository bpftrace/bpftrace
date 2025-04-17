#include <cstring>
#include <fstream>

#include "ast/passes/codegen_llvm.h"
#include "ast/passes/link.h"
#include "ast/passes/resolve_imports.h"
#include "bpfbytecode.h"
#include "scopeguard.h"
#include "util/temp.h"

namespace bpftrace::ast {

char LinkError::ID;
void LinkError::log(llvm::raw_ostream &OS) const
{
  OS << "linking " << origin_ << ": " << strerror(err_);
}

Pass CreateExternObjectPass()
{
  return Pass::create("extern", [](Imports &imports) {
    BpfExternObjects result;
    for (const auto &[name, obj] : imports.objects) {
      result.objects.emplace_back(obj.path);
    }
    return result;
  });
}

Pass CreateLinkPass()
{
  return Pass::create(
      "link", [](BpfObject &obj, BpfExternObjects &ext) -> Result<BpfBytecode> {
        // If there are no other objects to link, then just return our own.
        if (ext.objects.empty()) {
          return BpfBytecode{ obj.data };
        }

        // Create a working directory.
        auto dir = util::TempDir::create();
        if (!dir) {
          return dir.takeError();
        }

        // Otherwise, dump the intermediate object.
        auto object = dir->create_file();
        if (!object) {
          return object.takeError();
        }
        auto ok = object->write_all(obj.data);
        if (!ok) {
          return ok.takeError();
        }

        // Create an output file on disk. In the future, we may want to accept
        // some flags that allow this file to persist.
        auto output = dir->create_file();
        if (!output) {
          return output.takeError();
        }

        // In order to craft the final output, since we may have external maps
        // and probes, we delegate the heavy lifting to libbpf. First, we open a
        // new memfd as output, and add our top-level output to the linker.
        struct bpf_linker *linker = bpf_linker__new(output->path().c_str(),
                                                    nullptr);
        if (linker == nullptr) {
          // Hopefully an empty 'origin' here is sufficient to distinguish the
          // case where this failed. I believe that it's likely to be ENOMEM or
          // something equally obvious to the user?
          return make_error<LinkError>("", errno);
        }
        SCOPE_EXIT
        {
          bpf_linker__free(linker);
        };

        // Link in our own program.
        int rc = bpf_linker__add_file(linker, object->path().c_str(), nullptr);
        if (rc != 0) {
          return make_error<LinkError>(output->path().string(), errno);
        }

        // Next, we iterate through the list of link targets that we collected
        // from import statements. These are added to the link target one at a
        // time.
        for (auto &path : ext.objects) {
          int rc = bpf_linker__add_file(linker, path.c_str(), nullptr);
          if (rc != 0) {
            return make_error<LinkError>(path.string(), errno);
          }
        }

        // Finalize the linking, and free our underlying library handle.
        rc = bpf_linker__finalize(linker);
        if (rc != 0) {
          return make_error<LinkError>(output->path().string(), errno);
        }

        // Reload the final output and return it.
        std::ifstream file(output->path(), std::ios::binary);
        if (!file.is_open()) {
          return make_error<LinkError>(output->path().string(), errno);
        }
        std::vector<char> data(std::istreambuf_iterator<char>(file), {});
        return BpfBytecode{ data };
      });
}

} // namespace bpftrace::ast
