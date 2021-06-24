#include "aot.h"

#include <cstdint>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <fstream>
#include <istream>
#include <streambuf>
#include <sys/mman.h>
#include <sys/stat.h>

#include <cereal/archives/binary.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/vector.hpp>

#include "log.h"
#include "utils.h"

static constexpr auto AOT_MAGIC = 0xA07;

// AOT payload will have this header at the beginning. We don't worry about
// versioning the header b/c we enforce that an AOT compiled script may only
// be run with the corresponding runtime shim. We enforce it through the
// `version` field, which is the "Robert Sedgwicks hash" of BPFTRACE_VERSION
// macro defined in cmake.
struct Header
{
  uint16_t magic;      // Header magic (can be useful to detect endianness)
  uint16_t unused;     // For future use
  uint32_t header_len; // Length of this struct
  uint64_t version;    // Hash of version string
  uint64_t rr_off;     // RequiredResources offset from start of file
  uint64_t rr_len;     // RequiredResources length
  uint64_t bc_off;     // Bytecode offset from start of file
  uint64_t bc_len;     // Bytecode length
};

static_assert(sizeof(Header) == 48);
static_assert(sizeof(std::size_t) <= sizeof(uint64_t));

namespace bpftrace {
namespace aot {
namespace {

uint32_t rs_hash(const std::string &str)
{
  unsigned int b = 378551;
  unsigned int a = 63689;
  unsigned int hash = 0;

  for (char c : str)
  {
    hash = hash * a + c;
    a = a * b;
  }

  return hash;
}

void serialize_bytecode(const BpfBytecode &bytecode, std::ostream &out)
{
  cereal::BinaryOutputArchive archive(out);
  archive(bytecode);
}

int load_required_resources(BPFtrace &bpftrace, uint8_t *ptr, size_t len)
{
  try
  {
    bpftrace.resources.load_state(ptr, len);
  }
  catch (const std::exception &ex)
  {
    LOG(ERROR) << "Failed to deserialize metadata: " << ex.what();
    return 1;
  }

  return 0;
}

int load_bytecode(BPFtrace &bpftrace, uint8_t *ptr, size_t len)
{
  try
  {
    Membuf mbuf(ptr, ptr + len);
    std::istream istream(&mbuf);
    cereal::BinaryInputArchive archive(istream);
    archive(bpftrace.bytecode_);
  }
  catch (const std::exception &ex)
  {
    LOG(ERROR) << "Failed to deserialize metadata: " << ex.what();
    return 1;
  }

  return 0;
}

} // namespace

int generate(const RequiredResources &resources,
             const BpfBytecode &bytecode,
             const std::string &out)
{
  // Serialize RuntimeResources
  std::string serialized_metadata;
  try
  {
    std::ostringstream serialized(std::ios::binary);
    resources.save_state(serialized);
    serialized_metadata = serialized.str();
  }
  catch (const std::exception &ex)
  {
    LOG(ERROR) << "Failed to serialize runtime metadata: " << ex.what();
    return 1;
  }

  // Serialize bytecode
  std::string serialized_bytecode;
  try
  {
    std::ostringstream serialized(std::ios::binary);
    serialize_bytecode(bytecode, serialized);
    serialized_bytecode = serialized.str();
  }
  catch (const std::exception &ex)
  {
    LOG(ERROR) << "Failed to serialize bytecode: " << ex.what();
    return 1;
  }

  auto hdr_len = sizeof(Header);
  Header hdr = {
    .magic = AOT_MAGIC,
    .unused = 0,
    .header_len = sizeof(Header),
    .version = rs_hash(BPFTRACE_VERSION),
    .rr_off = hdr_len,
    .rr_len = serialized_metadata.size(),
    .bc_off = hdr_len + serialized_metadata.size(),
    .bc_len = serialized_bytecode.size(),
  };

  std::ofstream outf(out, std::ios::binary | std::ios::out | std::ios::trunc);
  if (outf.fail())
  {
    LOG(ERROR) << "Failed to open: " << out;
    return 1;
  }

  // Write out header
  outf.write(reinterpret_cast<const char *>(&hdr), sizeof(hdr));
  if (outf.fail())
  {
    LOG(ERROR) << "Failed to write header to: " << out;
    return 1;
  }

  // Write out metadata
  outf << serialized_metadata;
  if (outf.fail())
  {
    LOG(ERROR) << "Failed to write metadata to:" << out;
    return 1;
  }

  // Write out bytecode
  outf << serialized_bytecode;
  if (outf.fail())
  {
    LOG(ERROR) << "Failed to write bytecode to:" << out;
    return 1;
  }

  outf.flush();
  if (outf.fail())
  {
    LOG(ERROR) << "Failed to flush: " << out;
    return 1;
  }

  return 0;
}

int load(BPFtrace &bpftrace, const std::string &in)
{
  int err = 0;

  int infd = ::open(in.c_str(), O_RDONLY);
  if (infd < 0)
  {
    auto saved_err = errno;
    LOG(ERROR) << "Failed to open: " << in << ": " << std::strerror(saved_err);
    return 1;
  }

  struct stat sb;
  if (fstat(infd, &sb))
  {
    auto saved_err = errno;
    LOG(ERROR) << "Failed to stat: " << in << ": " << std::strerror(saved_err);
    return 1;
  }

  uint8_t *ptr = static_cast<uint8_t *>(
      ::mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, infd, 0));
  if (ptr == MAP_FAILED)
  {
    auto saved_err = errno;
    LOG(ERROR) << "Failed to mmap: " << in << ": " << std::strerror(saved_err);
    return 1;
  }

  // Validate header
  auto hdr = reinterpret_cast<const Header *>(ptr);
  if (hdr->magic != AOT_MAGIC)
  {
    LOG(ERROR) << "Invalid magic in " << in << ": " << hdr->magic;
    err = 1;
    goto out;
  }
  if (hdr->unused != 0)
  {
    LOG(ERROR) << "Unused bytes are used: " << hdr->unused;
    err = 1;
    goto out;
  }
  if (hdr->header_len != sizeof(Header))
  {
    LOG(ERROR) << "Invalid header len: " << hdr->header_len;
    err = 1;
    goto out;
  }
  if (hdr->version != rs_hash(BPFTRACE_VERSION))
  {
    LOG(ERROR) << "Build hash mismatch! "
               << "Did you build with a different bpftrace version?";
    err = 1;
    goto out;
  }
  if ((hdr->rr_off + hdr->rr_len) > static_cast<uint64_t>(sb.st_size) ||
      (hdr->bc_off + hdr->bc_len) > static_cast<uint64_t>(sb.st_size))
  {
    LOG(ERROR) << "Corrupted AOT bpftrace file: incomplete payload";
    err = 1;
    goto out;
  }

  // Load payloads
  err = load_required_resources(bpftrace, ptr + hdr->rr_off, hdr->rr_len);
  if (err)
    goto out;

  err = load_bytecode(bpftrace, ptr + hdr->bc_off, hdr->bc_len);
  if (err)
    goto out;

out:
  if (::munmap(ptr, sb.st_size))
  {
    auto saved_err = errno;
    LOG(ERROR) << "Failed to munmap(): " << in << ": "
               << std::strerror(saved_err);
  }

  return err;
}

} // namespace aot
} // namespace bpftrace
