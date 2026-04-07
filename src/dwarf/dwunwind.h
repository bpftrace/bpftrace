#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "llvm/DebugInfo/DWARF/DWARFDebugFrame.h"

#define DWUNWIND_MAPPINGS "dwunwind_mappings"
#define DWUNWIND_OFFSETMAPS "dwunwind_offsetmaps"
#define DWUNWIND_CFTS "dwunwind_cfts"
#define DWUNWIND_EXPRESSIONS "dwunwind_expressions"

enum class DWARFError {
  Success = 0,
  FileNotFound,
  ParseError,
  UnsupportedFormat,
  InternalError,
  TooManyObjects,
};
std::ostream &operator<<(std::ostream &os, const DWARFError &err);

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
  using TableFeedCallback = std::function<
      int(TableType type, uint32_t key, const std::vector<uint8_t> &value)>;

  DWARFUnwind(TableFeedCallback cb)
  {
    table_feed_cb_ = std::move(cb);
  }

  DWARFError add_object_file(const std::string &filename);
  DWARFError add_pid(pid_t pid);

private:
  std::optional<uint32_t> add_expression(llvm::DWARFExpression &expr);
  DWARFError add_new_file(const std::string &filename,
                          int pid,
                          uint32_t &out_oid);
  DWARFError add_file_nopush(const std::string &filename,
                             int pid,
                             uint32_t &out_oid);
  DWARFError push_current_table();
  DWARFError read_eh_frame(const std::string &filename,
                           uint32_t oid,
                           const std::map<uint64_t, uint64_t> &map_offsets);
  static std::string resolve_path(const std::string &filename, int pid);
  std::string file_cache_key(const std::string &filename, int pid);

  TableFeedCallback table_feed_cb_;
  uint32_t next_oid_{ 0 };
  uint32_t current_table_id_{ 0 };
  std::map<std::vector<uint8_t>, uint32_t> expressions_;
  std::map<std::vector<uint8_t>, uint32_t> entries_;
  std::unordered_map<uint32_t, std::vector<TableMapping>> table_mappings_;
  std::unordered_map<std::string, uint32_t> tables_;
  std::vector<uint8_t> current_table_;
  std::unordered_map<std::string, std::optional<uint32_t>> files_seen_;
};
