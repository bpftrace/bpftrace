#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <elf.h>
#include <gelf.h>
#include <libelf.h>

#include "util/result.h"

namespace bpftrace::util {

constexpr short USDT_NOTE_TYPE = 3;
constexpr std::string USDT_NOTE_SEC = ".note.stapsdt";
constexpr std::string USDT_NOTE_NAME = "stapsdt";

class ELFParseError : public ErrorInfo<ELFParseError> {
public:
  ELFParseError(std::string&& msg) : msg_(std::move(msg)){};
  ELFParseError() = default;
  static char ID;
  void log(llvm::raw_ostream& OS) const override;
  const std::string& msg() const
  {
    return msg_;
  }

private:
  std::string msg_;
};

struct elf_segment {
  long start;
  long end;
  long offset;
  bool is_exec;

  elf_segment(long s, long e, long o, bool exec)
      : start(s), end(e), offset(o), is_exec(exec)
  {
  }
};

struct usdt_probe_entry {
  std::string path;
  std::string provider;
  std::string name;
  long sema_addr;
  uint64_t sema_offset;

  usdt_probe_entry() = default;
  usdt_probe_entry(std::string path,
                   std::string provider,
                   std::string name,
                   long sema_addr = 0,
                   uint64_t sema_offset = 0)
      : path(std::move(path)),
        provider(std::move(provider)),
        name(std::move(name)),
        sema_addr(sema_addr),
        sema_offset(sema_offset)
  {
  }
};

using usdt_probe_list = std::vector<usdt_probe_entry>;

class USDTProbeEnumerator {
public:
  USDTProbeEnumerator(std::string path, int fd, Elf* elf)
      : elf_path(std::move(path)), fd(fd), elf(elf)
  {
  }

  USDTProbeEnumerator(const USDTProbeEnumerator&) = delete;
  USDTProbeEnumerator& operator=(const USDTProbeEnumerator&) = delete;
  USDTProbeEnumerator(USDTProbeEnumerator&& other) noexcept
      : elf_path(std::move(other.elf_path)), fd(other.fd), elf(other.elf)
  {
    other.fd = -1;
    other.elf = nullptr;
  }

  USDTProbeEnumerator& operator=(USDTProbeEnumerator&& other) = delete;

  ~USDTProbeEnumerator()
  {
    if (elf) {
      elf_end(elf);
      elf = nullptr;
    }
    if (fd >= 0) {
      close(fd);
      fd = -1;
    }
  }
  Result<std::vector<usdt_probe_entry>> enumerate_probes();

private:
  const std::string elf_path;
  int fd;
  Elf* elf;
};

Result<USDTProbeEnumerator> make_usdt_probe_enumerator(const std::string& path);

} // namespace bpftrace::util
