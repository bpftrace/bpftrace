#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <unistd.h>
#include <elf.h>
#include <gelf.h>
#include <libelf.h>

#include "util/result.h"

namespace bpftrace::symbols {

constexpr short USDT_NOTE_TYPE = 3;
constexpr std::string_view USDT_NOTE_SEC = ".note.stapsdt";
constexpr std::string_view USDT_NOTE_NAME = "stapsdt";

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
  std::string provider;
  std::string name;
  long sema_addr;
  uint64_t sema_offset;

  usdt_probe_entry() = default;
  usdt_probe_entry(const usdt_probe_entry&) = default;
  usdt_probe_entry& operator=(const usdt_probe_entry&) = default;
  usdt_probe_entry(std::string provider,
                   std::string name,
                   long sema_addr = 0,
                   uint64_t sema_offset = 0)
      : provider(std::move(provider)),
        name(std::move(name)),
        sema_addr(sema_addr),
        sema_offset(sema_offset)
  {
  };

  bool operator==(const usdt_probe_entry& other) const = default;
  auto operator<=>(const usdt_probe_entry& other) const = default;
};

// ELFParser encapsulates low-level ELF parsing operations.
// It stores the ELF descriptor and file path as members, eliminating
// the need to pass them as parameters to parsing functions.
class ELFParser {
public:
  ELFParser(std::string path, Elf* elf);

  // Accessor methods
  const std::string& path() const
  {
    return path_;
  }
  Elf* elf() const
  {
    return elf_;
  }

  // Parse ELF program headers to extract PT_LOAD segments
  Result<std::vector<struct elf_segment>> parse_segments();

  // Find ELF section by name
  Result<std::pair<Elf_Scn*, GElf_Shdr>> find_section_by_name(
      std::string_view sec_name);

private:
  std::string path_;
  Elf* elf_;
};

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

} // namespace bpftrace::symbols
