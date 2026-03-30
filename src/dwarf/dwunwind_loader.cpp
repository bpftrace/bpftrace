#include "dwarf/dwunwind_loader.h"

#include "bpfmap.h"
#include "log.h"
#include "util/result.h"

namespace bpftrace {

/*
 * Parse all DWARF unwind information here and buffer in RAM, so we
 * know how much space we need in the maps. Once dynamically allocated
 * hash maps are widely available, we can omit this step and directly
 * push to the maps in the step that is currently feed_dwarf_unwind().
 */
int parse_dwarf_unwind(
    BpfBytecode &bytecode,
    const std::vector<uint64_t> &pids,
    std::map<TableType, std::vector<std::vector<uint8_t>>> &unwind_data,
    std::map<uint32_t, std::vector<uint8_t>> &unwind_mappings)
{
  auto unwind = DWARFUnwind(
      [&unwind_data, &unwind_mappings](TableType t,
                                       uint32_t k,
                                       const std::vector<uint8_t> &v) {
        if (t != TableType::Mappings) {
          if (!unwind_data.contains(t)) {
            unwind_data[t] = std::vector<std::vector<uint8_t>>();
          }
          auto &table = unwind_data[t];
          if (k < table.size()) {
            table[k] = v;
          } else if (k == table.size()) {
            table.emplace_back(v);
          } else {
            LOG(BUG) << "Unwind mapping key " << k << " out of order, expected "
                     << table.size();
            return -1;
          }
        } else {
          unwind_mappings[k] = v;
        }
        return 0;
      });
  for (const auto &pid : pids) {
    auto ret = unwind.add_pid(pid);
    if (ret != DWARFError::Success)
      return -1;
  }

  // resize maps
  for (auto const &t : unwind_data) {
    Result<> ret = OK();
    auto size = t.second.size();
    if (t.first == TableType::UnwindTable) {
      ret = bytecode.getMap(DWUNWIND_OFFSETMAPS).resize(size);
    } else if (t.first == TableType::UnwindEntries) {
      ret = bytecode.getMap(DWUNWIND_CFTS).resize(size);
    } else if (t.first == TableType::Expressions) {
      ret = bytecode.getMap(DWUNWIND_EXPRESSIONS).resize(size);
    } else {
      LOG(BUG) << "Unknown table type: " << static_cast<int>(t.first);
      return -1;
    }
    if (!ret) {
      LOG(BUG) << "Failed to resize unwind table: " << ret.takeError();
      return -1;
    }
  }
  auto ret = bytecode.getMap(DWUNWIND_MAPPINGS).resize(unwind_mappings.size());
  if (!ret) {
    LOG(BUG) << "Failed to resize unwind table: " << ret.takeError();
    return -1;
  }

  return 0;
}

int feed_dwarf_unwind(
    BpfBytecode &bytecode,
    const std::map<TableType, std::vector<std::vector<uint8_t>>> &unwind_data,
    const std::map<uint32_t, std::vector<uint8_t>> &unwind_mappings)
{
  // update arrays
  for (auto const &t : unwind_data) {
    std::string name;
    const BpfMap *table;
    if (t.first == TableType::UnwindTable) {
      table = &bytecode.getMap(DWUNWIND_OFFSETMAPS);
    } else if (t.first == TableType::UnwindEntries) {
      table = &bytecode.getMap(DWUNWIND_CFTS);
    } else if (t.first == TableType::Expressions) {
      table = &bytecode.getMap(DWUNWIND_EXPRESSIONS);
    } else {
      LOG(BUG) << "Unknown table type: " << static_cast<int>(t.first);
      return -1;
    }
    for (size_t i = 0; i < t.second.size(); i++) {
      auto ret = table->update_elem(&i, t.second[i].data());
      if (!ret) {
        LOG(BUG) << "Failed to add unwind entry: " << ret.takeError();
        return -1;
      }
    }
  }
  // unwind mappings are indexed by pid, so they are stored in a hash map
  auto table = bytecode.getMap(DWUNWIND_MAPPINGS);
  for (auto const &m : unwind_mappings) {
    auto ret = table.update_elem(&m.first, m.second.data());
    if (!ret) {
      LOG(BUG) << "Failed to add unwind mapping: " << ret.takeError();
      return -1;
    }
  }

  return 0;
}

} // namespace bpftrace
