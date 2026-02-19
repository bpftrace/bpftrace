#pragma once

#include <cstdint>
#include <map>
#include <unordered_map>
#include <string>
#include <vector>

#include <llvm/Config/llvm-config.h>
#include "llvm/DebugInfo/DWARF/DWARFDebugFrame.h"

#if (defined(__x86_64__) || defined(__amd64__)) && LLVM_VERSION_MAJOR >= 21
#define DWUNWIND
#endif

enum class DWARFError {
  Success = 0,
  FileNotFound,
  ParseError,
  UnsupportedFormat,
  InternalError,
  TooManyObjects,
};
std::ostream& operator<<(std::ostream& os, const DWARFError& err);

struct TableMapping {
  uint64_t file_offset;
  uint32_t table_id;
  uint64_t table_offset;
};

enum class TableType {
  UnwindTable,
  UnwindEntries,
  Expressions,
  Mappings,
};

class DWARFUnwind {
  public:
    using TableFeedCallback = std::function<void(TableType type, uint32_t key,
      const std::vector<uint8_t> &value)>;

    DWARFUnwind(TableFeedCallback cb) {
      table_feed_cb_ = std::move(cb);
    }

    DWARFError add_object_file(const std::string &filename);
    DWARFError add_pid(pid_t pid);

  private:
    uint32_t add_expression(llvm::DWARFExpression &expr);
    DWARFError add_new_file(const std::string &filename, int pid,
                            uint32_t &out_oid);
    DWARFError add_file_nopush(const std::string &filename, int pid,
                               uint32_t &out_oid);
    void push_current_table();
    DWARFError read_eh_frame(const std::string &filename, uint32_t oid,
      const std::map<uint64_t, uint64_t> &map_offsets);

    TableFeedCallback table_feed_cb_;
    uint32_t next_oid_{0};
    uint32_t current_table_id_{0};
    std::map<std::vector<uint8_t>, uint32_t> expressions_;
    std::map<std::vector<uint8_t>, uint32_t> entries_;
    std::unordered_map<uint32_t, std::vector<TableMapping>> table_mappings_;
    std::unordered_map<std::string, uint32_t> tables_;
    std::vector<uint8_t> current_table_;
    std::unordered_map<std::string, uint32_t> files_seen_;
};

