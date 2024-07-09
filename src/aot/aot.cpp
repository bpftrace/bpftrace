#include "aot.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <fstream>
#include <gelf.h>
#include <libelf.h>
#include <optional>
#include <sys/mman.h>
#include <sys/stat.h>

#include <cereal/archives/binary.hpp>
#include <cereal/archives/json.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/vector.hpp>

#include "filesystem.h"
#include "log.h"
#include "utils.h"
#include "version.h"

#define AOT_ELF_SECTION ".btaot"
static constexpr auto AOT_MAGIC = 0xA07;
static constexpr auto AOT_SECDATA_TEMPFILE = ".temp_btaot";

// AOT payload will have this header at the beginning. We don't worry about
// versioning the header b/c we enforce that an AOT compiled script may only
// be run with the corresponding runtime shim. We enforce it through the
// `version` field, which is the "Robert Sedgwicks hash" of BPFTRACE_VERSION
// macro defined in cmake.
struct Header {
  uint16_t magic;      // Header magic (can be useful to detect endianness)
  uint16_t unused;     // For future use
  uint32_t header_len; // Length of this struct
  uint64_t version;    // Hash of version string
  uint64_t rr_off;     // RequiredResources offset from start of file
  uint64_t rr_len;     // RequiredResources length
  uint64_t elf_off;    // ELF offset from start of file
  uint64_t elf_len;    // ELF length
};

static_assert(sizeof(Header) == 48);
static_assert(sizeof(std::size_t) <= sizeof(uint64_t));

namespace bpftrace {
namespace aot {
namespace {

uint32_t rs_hash(std::string_view str)
{
  unsigned int b = 378551;
  unsigned int a = 63689;
  unsigned int hash = 0;

  for (char c : str) {
    hash = hash * a + c;
    a = a * b;
  }

  return hash;
}

int load_required_resources(BPFtrace &bpftrace, uint8_t *ptr, size_t len)
{
  try {
    bpftrace.resources.load_state(ptr, len);
  } catch (const std::exception &ex) {
    LOG(ERROR) << "Failed to deserialize metadata: " << ex.what();
    return 1;
  }

  return 0;
}

std::optional<std::vector<uint8_t>> generate_btaot_section(
    const RequiredResources &resources,
    void *const elf,
    size_t elf_size)
{
  // Serialize RuntimeResources
  std::string serialized_metadata;
  try {
    std::ostringstream serialized(std::ios::binary);
    resources.save_state(serialized);
    serialized_metadata = serialized.str();
  } catch (const std::exception &ex) {
    LOG(ERROR) << "Failed to serialize runtime metadata: " << ex.what();
    return std::nullopt;
  }

  // Construct the header
  auto hdr_len = sizeof(Header);
  Header hdr = {
    .magic = AOT_MAGIC,
    .unused = 0,
    .header_len = sizeof(Header),
    .version = rs_hash(BPFTRACE_VERSION),
    .rr_off = hdr_len,
    .rr_len = serialized_metadata.size(),
    .elf_off = hdr_len + serialized_metadata.size(),
    .elf_len = elf_size,
  };

  // Resize the output buffer appropriately
  std::vector<uint8_t> out;
  out.resize(sizeof(Header) + hdr.rr_len + hdr.elf_len);
  uint8_t *p = out.data();

  // Write out header
  memcpy(p, &hdr, sizeof(Header));
  p += sizeof(Header);

  // Write out metadata
  memcpy(p, serialized_metadata.data(), hdr.rr_len);
  p += hdr.rr_len;

  // Write out ELF
  memcpy(p, elf, hdr.elf_len);
  p += hdr.elf_len;

  return out;
}

// Clones the shim to final destination while also injecting
// the custom .btaot section.
int build_binary(const std_filesystem::path &shim,
                 const std::string &out,
                 const std::vector<uint8_t> &section)
{
  std::error_code ec;
  char cmd[1024];
  int written;
  int ret = 0;

  // Write out section data in a temporary file
  std::ofstream secdata(AOT_SECDATA_TEMPFILE, std::ios_base::binary);
  secdata.write(reinterpret_cast<const char *>(section.data()), section.size());
  secdata.close();

  // Respect user provided BPFTRACE_OBJCOPY if present
  std::string_view objcopy = "objcopy";
  if (auto c = std::getenv("BPFTRACE_OBJCOPY"))
    objcopy = c;

  // Resolve objcopy binary to full path
  auto objcopy_full = find_in_path(objcopy);
  if (!objcopy_full) {
    ret = 1;
    LOG(ERROR) << "Failed to find " << objcopy << " in $PATH";
    goto out;
  }

  written = snprintf(cmd,
                     sizeof(cmd),
                     "%s --add-section .btaot=%s %s %s",
                     objcopy_full->c_str(),
                     AOT_SECDATA_TEMPFILE,
                     shim.c_str(),
                     out.c_str());
  if (written < 0 || written == sizeof(cmd)) {
    ret = 1;
    LOG(ERROR) << "Failed to construct objcopy command";
    goto out;
  }

  if ((ret = std::system(cmd))) {
    LOG(ERROR) << "Failed to execute: " << cmd;
    goto out;
  }

out:
  if (!std_filesystem::remove(AOT_SECDATA_TEMPFILE, ec) || ec) {
    ret = 1;
    LOG(ERROR) << "Failed to remove " << AOT_SECDATA_TEMPFILE << ": " << ec;
  }
  return ret;
}

} // namespace

int generate(const RequiredResources &resources,
             const std::string &out,
             void *const elf,
             size_t elf_size)
{
  auto section = generate_btaot_section(resources, elf, elf_size);
  if (!section)
    return 1;

  // For development, we want to use the locally built AOT shim instead of a
  // "real" one that could be present elsewhere in $PATH. So we give precedence
  // to shim found "next" to the running binary.
  auto rel = std_filesystem::path("aot") / AOT_SHIM_NAME;
  auto local = find_near_self(rel.native());
  auto path = find_in_path(AOT_SHIM_NAME);
  auto shim = local ? local : path;
  if (!shim) {
    LOG(ERROR) << "Failed to locate " << AOT_SHIM_NAME
               << " shim binary. Is it in $PATH?";
    return 1;
  }

  if (shim == local)
    LOG(WARNING) << "Using development shim (" << *shim
                 << "). Ensure you are a developer!";

  if (auto err = build_binary(*shim, out, *section))
    return err;

  return 0;
}

int load(BPFtrace &bpftrace, const std::string &in)
{
  int err = 0;

  int infd = ::open(in.c_str(), O_RDONLY);
  if (infd < 0) {
    auto saved_err = errno;
    LOG(ERROR) << "Failed to open: " << in << ": " << std::strerror(saved_err);
    return 1;
  }

  std::error_code ec;
  std_filesystem::path in_path{ in };
  std::uintmax_t in_file_size = std::filesystem::file_size(in_path, ec);

  if (in_file_size == static_cast<std::uintmax_t>(-1)) {
    LOG(ERROR) << "Failed to stat: " << in << ": " << ec.message();
    return 1;
  }

  // Find .btaot section
  Elf *elf = NULL;
  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;
  char *secname = NULL;
  Elf_Data *data = NULL;
  uint8_t *btaot_section = NULL;
  const Header *hdr;

  if (elf_version(EV_CURRENT) == EV_NONE) {
    LOG(ERROR) << "Cannot set libelf version: " << elf_errmsg(-1);
    err = 1;
    goto out;
  }

  elf = elf_begin(infd, ELF_C_READ, NULL);
  if (!elf) {
    LOG(ERROR) << "Cannot read ELF file: " << elf_errmsg(-1);
    err = 1;
    goto out;
  }

  size_t strndx;
  if (elf_getshdrstrndx(elf, &strndx) < 0) {
    LOG(ERROR) << "Failed to get ELF section index of the string table: "
               << elf_errmsg(-1);
    err = 1;
    goto out;
  }

  int i;
  i = 0;
  while ((scn = elf_nextscn(elf, scn))) {
    i++;
    if (!gelf_getshdr(scn, &shdr)) {
      LOG(ERROR) << "Failed to get ELF section(" << i
                 << ") hdr: " << elf_errmsg(-1);
      err = 1;
      goto out;
    }

    secname = elf_strptr(elf, strndx, shdr.sh_name);
    if (!secname) {
      LOG(ERROR) << "Failed to get ELF section(" << i
                 << ") hdr name: " << elf_errmsg(-1);
      err = 1;
      goto out;
    }

    if (std::string_view(secname) == AOT_ELF_SECTION) {
      data = elf_getdata(scn, 0);
      if (!data) {
        LOG(ERROR) << "Failed to get BTAOT ELF section(" << i
                   << ") data: " << elf_errmsg(-1);
        err = 1;
        goto out;
      }

      btaot_section = static_cast<uint8_t *>(data->d_buf);
      break;
    }
  }

  // Validate .btaot header
  hdr = reinterpret_cast<const Header *>(btaot_section);
  if (!hdr) {
    LOG(ERROR) << "Couldn't find " << AOT_ELF_SECTION << " section in " << in;
    err = 1;
    goto out;
  }
  if (hdr->magic != AOT_MAGIC) {
    LOG(ERROR) << "Invalid magic in " << in << ": " << hdr->magic;
    err = 1;
    goto out;
  }
  if (hdr->unused != 0) {
    LOG(ERROR) << "Unused bytes are used: " << hdr->unused;
    err = 1;
    goto out;
  }
  if (hdr->header_len != sizeof(Header)) {
    LOG(ERROR) << "Invalid header len: " << hdr->header_len;
    err = 1;
    goto out;
  }
  if (hdr->version != rs_hash(BPFTRACE_VERSION)) {
    LOG(ERROR) << "Build hash mismatch! "
               << "Did you build with a different bpftrace version?";
    err = 1;
    goto out;
  }
  if ((hdr->rr_off + hdr->rr_len) > static_cast<uint64_t>(in_file_size) ||
      (hdr->elf_off + hdr->elf_len) > static_cast<uint64_t>(in_file_size)) {
    LOG(ERROR) << "Corrupted AOT bpftrace file: incomplete payload";
    err = 1;
    goto out;
  }

  // Load payloads
  err = load_required_resources(bpftrace,
                                btaot_section + hdr->rr_off,
                                hdr->rr_len);
  if (err)
    goto out;

  bpftrace.bytecode_ = BpfBytecode(btaot_section + hdr->elf_off,
                                   hdr->elf_len,
                                   bpftrace);
  if (err)
    goto out;

out:
  if (elf)
    elf_end(elf);

  close(infd);
  return err;
}

} // namespace aot
} // namespace bpftrace
