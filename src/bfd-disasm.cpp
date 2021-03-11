#include <fcntl.h>
#include <memory>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
// bfd.h assumes everyone is using autotools and will error out unless
// PACKAGE is defined. Some distros patch this check out.
#define PACKAGE "bpftrace"
#include "bfd-disasm.h"
#include "utils.h"
#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <bfd.h>
#include <dis-asm.h>

namespace bpftrace {

BfdDisasm::BfdDisasm(std::string &path) : size_(0)
{
  fd_ = open(path.c_str(), O_RDONLY);

  if (fd_ >= 0) {
    struct stat st;

    if (fstat(fd_, &st) == 0)
      size_ = st.st_size;
  }
}

BfdDisasm::~BfdDisasm()
{
  if (fd_ >= 0)
    close(fd_);
}

static int fprintf_nop(void *out __attribute__((unused)), const char *fmt __attribute__((unused)), ...)
{
  return 0;
}

static AlignState is_aligned_buf(void *buf, uint64_t size, uint64_t offset)
{
  disassembler_ftype disassemble;
  struct disassemble_info info;
  std::string tpath = get_pid_exe("self");
  bfd *bfdf;

  bfdf = bfd_openr(tpath.c_str(), nullptr);
  if (bfdf == nullptr)
    return AlignState::Fail;

  if (!bfd_check_format(bfdf, bfd_object))
  {
    bfd_close(bfdf);
    return AlignState::Fail;
  }

  init_disassemble_info(&info, stdout, fprintf_nop);

  info.arch = bfd_get_arch(bfdf);
  info.mach = bfd_get_mach(bfdf);
  info.buffer = static_cast<bfd_byte*>(buf);
  info.buffer_length = size;

  disassemble_init_for_target(&info);

#ifdef LIBBFD_DISASM_FOUR_ARGS_SIGNATURE
  disassemble = disassembler(info.arch,
           bfd_big_endian(bfdf),
           info.mach,
           bfdf);
#else
  disassemble = disassembler(bfdf);
#endif

  uint64_t pc = 0;
  int count;

  do {
    count = disassemble(pc, &info);
    pc += static_cast<uint64_t>(count);

    if (pc == offset)
    {
      bfd_close(bfdf);
      return AlignState::Ok;
    }

  } while (static_cast<uint64_t>(count) > 0 && pc < size && pc < offset);

  bfd_close(bfdf);
  return AlignState::NotAlign;
}

AlignState BfdDisasm::is_aligned(uint64_t offset, uint64_t pc)
{
  AlignState aligned = AlignState::Fail;
  // 100 bytes should be enough to cover next instruction behind pc
  uint64_t size = std::min(pc + 100, size_);
  auto buf = std::make_unique<char[]>(size);

  if (fd_ < 0)
    return aligned;

  uint64_t sz = pread(fd_, buf.get(), size, offset);
  if (sz == size)
    aligned = is_aligned_buf(buf.get(), size, pc);
  else
    perror("pread failed");

  return aligned;
}

} // namespace bpftrace
