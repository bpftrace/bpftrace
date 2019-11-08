#include <iostream>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
// bfd.h assumes everyone is using autotools and will error out unless
// PACKAGE is defined. Some distros patch this check out.
#define PACKAGE "bpftrace"
#include <bfd.h>
#include <dis-asm.h>
#include "bcc_syms.h"
#include "bcc_elf.h"
#include "bfd-disasm.h"

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

static void get_exec_path(char *tpath, size_t size)
{
  const char *path = "/proc/self/exe";
  ssize_t len;

  len = readlink(path, tpath, size - 1);
  if (len < 0)
    len = 0;

  tpath[len] = 0;
}

static int fprintf_nop(void *out __attribute__((unused)), const char *fmt __attribute__((unused)), ...)
{
  return 0;
}

static AlignState is_aligned_buf(void *buf, uint64_t size, uint64_t offset)
{
  disassembler_ftype disassemble;
  struct disassemble_info info;
  char tpath[4096];
  bfd *bfdf;

  get_exec_path(tpath, sizeof(tpath));

  bfdf = bfd_openr(tpath, NULL);
  if (bfdf == NULL)
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
  void *buf;

  if (fd_ < 0)
    return aligned;

  buf = malloc(size);
  if (!buf) {
    perror("malloc failed");
    return aligned;
  }

  uint64_t sz;

  sz = pread(fd_, buf, size, offset);
  if (sz == size)
    aligned = is_aligned_buf(buf, size, pc);
  else
    perror("pread failed");

  free(buf);
  return aligned;
}

} // namespace bpftrace
