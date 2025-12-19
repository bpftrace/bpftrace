#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overread"
#include <vector>
#pragma GCC diagnostic pop
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>

#include "dwunwind.h"
#include "log.h"
#include "table.h"

#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/DebugInfo/DWARF/DWARFDebugFrame.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ObjectFile.h"
#include <llvm/Config/llvm-config.h>

#include "stdlib/stack/expression.h"

const int NUM_REGISTERS = 17;
const int CFT_ENTRY_SIZE = 228;
const int MAX_MAPPINGS = 1000;
const int CHUNK_SIZE = 256 * 1024;

std::ostream &operator<<(std::ostream &os, const DWARFError &err)
{
  switch (err) {
    case DWARFError::Success:
      os << "Success";
      break;
    case DWARFError::FileNotFound:
      os << "FileNotFound";
      break;
    case DWARFError::ParseError:
      os << "ParseError";
      break;
    case DWARFError::UnsupportedFormat:
      os << "UnsupportedFormat";
      break;
    case DWARFError::InternalError:
      os << "InternalError";
      break;
    case DWARFError::TooManyObjects:
      os << "TooManyObjects";
      break;
    default:
      os << "UnknownError";
      break;
  }
  return os;
}

static void append_u8(std::vector<uint8_t> &buf, uint8_t val)
{
  if (buf.capacity() < buf.size() + 1)
    throw std::bad_alloc();
  buf.emplace_back(val);
}

static void append_u32(std::vector<uint8_t> &buf, uint32_t val)
{
  if (buf.capacity() < buf.size() + 4)
    throw std::bad_alloc();
  buf.emplace_back(static_cast<uint8_t>(val & 0xff));
  buf.emplace_back(static_cast<uint8_t>((val >> 8) & 0xff));
  buf.emplace_back(static_cast<uint8_t>((val >> 16) & 0xff));
  buf.emplace_back(static_cast<uint8_t>((val >> 24) & 0xff));
}

static void append_u64(std::vector<uint8_t> &buf, uint64_t val)
{
  if (buf.capacity() < buf.size() + 8)
    throw std::bad_alloc();
  buf.emplace_back(static_cast<uint8_t>(val & 0xff));
  buf.emplace_back(static_cast<uint8_t>((val >> 8) & 0xff));
  buf.emplace_back(static_cast<uint8_t>((val >> 16) & 0xff));
  buf.emplace_back(static_cast<uint8_t>((val >> 24) & 0xff));
  buf.emplace_back(static_cast<uint8_t>((val >> 32) & 0xff));
  buf.emplace_back(static_cast<uint8_t>((val >> 40) & 0xff));
  buf.emplace_back(static_cast<uint8_t>((val >> 48) & 0xff));
  buf.emplace_back(static_cast<uint8_t>((val >> 56) & 0xff));
}

static uint64_t expr_get(const std::vector<uint8_t> &expr_u8,
                         size_t size,
                         size_t &ix)
{
  if (ix + size > expr_u8.size())
    throw std::out_of_range("expr_get out of range");

  uint64_t v = 0;
  for (size_t j = 0; j < size; ++j) {
    v |= static_cast<uint64_t>(expr_u8[ix + j]) << (j * 8);
  }
  return v;
}

static uint64_t expr_get_leb(const std::vector<uint8_t> &expr_u8,
                             bool is_signed,
                             size_t &ix)
{
  uint64_t result = 0;
  unsigned shift = 0;
  uint8_t byte;
  while (true) {
    if (ix >= expr_u8.size())
      throw std::out_of_range("expr_get_sleb out of range");

    byte = expr_u8[ix++];
    result |= static_cast<uint64_t>(byte & 0x7f) << shift;
    shift += 7;
    if ((byte & 0x80) == 0)
      break;
  }
  // sign extend
  if (is_signed && (shift < 64) && (byte & 0x40))
    result |= -(1 << shift);
  return result;
}

static void convert_expression(const std::vector<uint8_t> &expr_u8,
                               std::vector<uint8_t> &eout)
{
  eout.emplace_back(0); // placeholder for number of instructions
  uint64_t v;
  uint64_t w;
  size_t i = 0;
  uint8_t nexpr = 0;
  while (i < expr_u8.size()) {
    if (nexpr == MAX_EXPR_INSTRUCTIONS)
      throw std::runtime_error("DWARF expression too long");
    ++nexpr;
    uint8_t op = expr_u8[i++];
    switch (op) {
      case llvm::dwarf::DW_OP_addr:
        // XXX handle 32 bit case
        v = expr_get(expr_u8, 8, i);
        append_u8(eout, EXPR_OP_CONST);
        append_u64(eout, v);
        break;
      case llvm::dwarf::DW_OP_deref:
        append_u8(eout, EXPR_OP_DEREF);
        break;
      case llvm::dwarf::DW_OP_const1u:
        v = expr_get(expr_u8, 1, i);
        append_u8(eout, EXPR_OP_CONST);
        append_u64(eout, v);
        break;
      case llvm::dwarf::DW_OP_const1s:
        v = static_cast<int8_t>(expr_get(expr_u8, 1, i));
        append_u8(eout, EXPR_OP_CONST);
        append_u64(eout, v);
        break;
      case llvm::dwarf::DW_OP_const2u:
        v = expr_get(expr_u8, 2, i);
        append_u8(eout, EXPR_OP_CONST);
        append_u64(eout, v);
        break;
      case llvm::dwarf::DW_OP_const2s:
        v = static_cast<int16_t>(expr_get(expr_u8, 2, i));
        append_u8(eout, EXPR_OP_CONST);
        append_u64(eout, v);
        break;
      case llvm::dwarf::DW_OP_const4u:
        v = expr_get(expr_u8, 4, i);
        append_u8(eout, EXPR_OP_CONST);
        append_u64(eout, v);
        break;
      case llvm::dwarf::DW_OP_const4s:
        v = static_cast<int32_t>(expr_get(expr_u8, 4, i));
        append_u8(eout, EXPR_OP_CONST);
        append_u64(eout, v);
        break;
      case llvm::dwarf::DW_OP_const8u:
      case llvm::dwarf::DW_OP_const8s:
        v = expr_get(expr_u8, 8, i);
        append_u8(eout, EXPR_OP_CONST);
        append_u64(eout, v);
        break;
      case llvm::dwarf::DW_OP_constu:
        v = expr_get_leb(expr_u8, false, i);
        append_u8(eout, EXPR_OP_CONST);
        append_u64(eout, v);
        break;
      case llvm::dwarf::DW_OP_consts:
        v = expr_get_leb(expr_u8, true, i);
        append_u8(eout, EXPR_OP_CONST);
        append_u64(eout, v);
        break;
      case llvm::dwarf::DW_OP_lit0... llvm::dwarf::DW_OP_lit31:
        v = op - llvm::dwarf::DW_OP_lit0;
        append_u8(eout, EXPR_OP_CONST);
        append_u64(eout, v);
        break;
      case llvm::dwarf::DW_OP_reg0... llvm::dwarf::DW_OP_reg31:
        v = op - llvm::dwarf::DW_OP_reg0;
        append_u8(eout, EXPR_OP_BREG);
        append_u8(eout, v);
        append_u64(eout, 0);
        break;
      case llvm::dwarf::DW_OP_breg0... llvm::dwarf::DW_OP_breg31:
        v = op - llvm::dwarf::DW_OP_breg0;
        w = expr_get_leb(expr_u8, true, i);
        append_u8(eout, EXPR_OP_BREG);
        append_u8(eout, v);
        append_u64(eout, w);
        break;
      case llvm::dwarf::DW_OP_and:
        append_u8(eout, EXPR_OP_AND);
        break;
      case llvm::dwarf::DW_OP_ge:
        append_u8(eout, EXPR_OP_GE);
        break;
      case llvm::dwarf::DW_OP_shl:
        append_u8(eout, EXPR_OP_SHL);
        break;
      case llvm::dwarf::DW_OP_plus:
        append_u8(eout, EXPR_OP_PLUS);
        break;
      case llvm::dwarf::DW_OP_mul:
        append_u8(eout, EXPR_OP_MUL);
        break;
      case llvm::dwarf::DW_OP_plus_uconst:
        v = expr_get_leb(expr_u8, false, i);
        append_u8(eout, EXPR_OP_PLUS_CONST);
        append_u64(eout, v);
        break;
      case llvm::dwarf::DW_OP_addrx:
      case llvm::dwarf::DW_OP_call2:
      case llvm::dwarf::DW_OP_call4:
      case llvm::dwarf::DW_OP_call_ref:
      case llvm::dwarf::DW_OP_const_type:
      case llvm::dwarf::DW_OP_constx:
      case llvm::dwarf::DW_OP_convert:
      case llvm::dwarf::DW_OP_deref_type:
      case llvm::dwarf::DW_OP_regval_type:
      case llvm::dwarf::DW_OP_reinterpret:
      case llvm::dwarf::DW_OP_push_object_address:
      case llvm::dwarf::DW_OP_call_frame_cfa:
        LOG(ERROR) << "DWARF expression op 0x" << std::hex
                   << static_cast<int>(op) << std::dec << " not allowed here.";
        throw std::runtime_error("invalid DWARF expression");
        break;
      default:
        LOG(ERROR) << "DWARF expression op 0x" << std::hex
                   << static_cast<int>(op) << std::dec
                   << " not implemented yet.";
        throw std::runtime_error("unsupported DWARF expression");
        break;
    }
  }
  eout[0] = nexpr;
}

uint32_t DWARFUnwind::add_expression(llvm::DWARFExpression &expr)
{
  auto expr_bytes = expr.getData();
  auto expr_u8 = std::vector<uint8_t>(expr_bytes.begin(), expr_bytes.end());
  auto it = expressions_.find(expr_u8);
  if (it != expressions_.end())
    return it->second;

  uint32_t id = expressions_.size();
  expressions_[expr_u8] = id;

  //
  // preprocess expression to simplify bpf code
  // mainly we expand all arguments to 64 bits (registers to 8 bits)
  //
  std::vector<uint8_t> expr_out;
  expr_out.reserve(256);

  try {
    convert_expression(expr_u8, expr_out);
  } catch (const std::exception &e) {
    LOG(ERROR) << "Failed to convert DWARF expression: " << e.what();
    return UINT32_MAX;
  }
  expr_out.resize(256, 0);

  table_feed_cb_(TableType::Expressions, id, expr_out);

  return id;
}

DWARFError DWARFUnwind::add_object_file(const std::string &filename)
{
  uint32_t out_oid;

  auto ret = add_file_nopush(filename, -1, out_oid);
  push_current_table();

  return ret;
}

DWARFError DWARFUnwind::add_file_nopush(const std::string &filename,
                                        int pid,
                                        uint32_t &out_oid)
{
  auto f = files_seen_.find(filename);
  if (f != files_seen_.end()) {
    out_oid = f->second;
    return DWARFError::Success;
  }

  DWARFError err = add_new_file(filename, pid, out_oid);
  if (err != DWARFError::Success) {
    files_seen_[filename] = 0; // mark as seen but failed
  } else {
    files_seen_[filename] = out_oid;
  }

  return err;
}

// Template function to handle specific ELF bit-widths and endianness
template <typename ELFT>
void build_map_offsets(const llvm::object::ELFObjectFile<ELFT> *Obj,
                       std::map<uint64_t, uint64_t> &map_offsets)
{
  for (const auto &Section : Obj->sections()) {
    const typename ELFT::Shdr *header = Obj->getSection(
        Section.getRawDataRefImpl());
    if ((header->sh_flags & llvm::ELF::SHF_ALLOC) == 0)
      continue; // Skip non-allocated sections
    if (header->sh_addr == header->sh_offset)
      continue;

    map_offsets[header->sh_addr] = header->sh_addr - header->sh_offset;
  }
}

DWARFError DWARFUnwind::add_new_file(const std::string &filename,
                                     int pid,
                                     uint32_t &out_oid)
{
  auto oid = next_oid_;
  if (oid == UINT16_MAX) {
    LOG(ERROR) << "Maximum number of object IDs reached.";
    return DWARFError::TooManyObjects;
  }
  if (oid == 0) {
    std::vector<uint8_t> empty;
    empty.resize(CFT_ENTRY_SIZE, 0);
    table_feed_cb_(TableType::UnwindEntries, 0, empty);
  }
  ++next_oid_;
  out_oid = oid;

  std::string fn;
  if (pid >= 0)
    fn = "/proc/" + std::to_string(pid) + "/root/" + filename;
  else
    fn = filename;

  LOG(V1) << "Adding file " << fn << " with OID " << oid;
  auto ExpectedBinary = llvm::object::createBinary(fn);
  if (!ExpectedBinary) {
    LOG(ERROR) << "Cannot open " << fn << " to extract stack walk information";
    return DWARFError::FileNotFound;
  }

  auto *Bin = ExpectedBinary.get().getBinary();
  auto *Obj = llvm::dyn_cast<llvm::object::ObjectFile>(Bin);
  if (!Obj)
    return DWARFError::UnsupportedFormat;

  std::map<uint64_t, uint64_t> map_offsets;
  if (auto *ELF64LE = llvm::dyn_cast<llvm::object::ELF64LEObjectFile>(Obj)) {
    build_map_offsets(ELF64LE, map_offsets);
  } else if (auto *ELF64BE = llvm::dyn_cast<llvm::object::ELF64BEObjectFile>(
                 Obj)) {
    build_map_offsets(ELF64BE, map_offsets);
  } else if (auto *ELF32LE = llvm::dyn_cast<llvm::object::ELF32LEObjectFile>(
                 Obj)) {
    build_map_offsets(ELF32LE, map_offsets);
  } else if (auto *ELF32BE = llvm::dyn_cast<llvm::object::ELF32BEObjectFile>(
                 Obj)) {
    build_map_offsets(ELF32BE, map_offsets);
  } else {
    LOG(V1) << "Not a recognized ELF object file.";
    return DWARFError::UnsupportedFormat;
  }

  return read_eh_frame(fn, oid, map_offsets);
}

void DWARFUnwind::push_current_table()
{
  if (current_table_.empty())
    return;

  auto ext_table = current_table_;
  ext_table.resize(CHUNK_SIZE, 0);
  table_feed_cb_(TableType::UnwindTable, current_table_id_, ext_table);
}

DWARFError DWARFUnwind::read_eh_frame(
    const std::string &filename,
    uint32_t oid,
    const std::map<uint64_t, uint64_t> &map_offsets)
{
#if LLVM_VERSION_MAJOR >= 21
  auto ExpectedBinary = llvm::object::createBinary(filename);
  if (!ExpectedBinary)
    return DWARFError::FileNotFound;

  auto *Bin = ExpectedBinary.get().getBinary();
  auto *Obj = llvm::dyn_cast<llvm::object::ObjectFile>(Bin);
  if (!Obj)
    return DWARFError::UnsupportedFormat;

  auto DICtx = llvm::DWARFContext::create(*Obj);
  llvm::Expected<const llvm::DWARFDebugFrame *> FrameOrErr = nullptr;

  if (!DICtx->getDWARFObj().getEHFrameSection().Data.empty()) {
    FrameOrErr = DICtx->getEHFrame();
  } else {
    FrameOrErr = DICtx->getDebugFrame();
  }

  if (!FrameOrErr) {
    LOG(ERROR) << "object " << filename
               << " does not contain a .eh_frame "
                  "or .debug_frame section, can't extract information for "
                  "stack walking";
    return DWARFError::ParseError;
  }

  const llvm::DWARFDebugFrame *Frame = *FrameOrErr;
  int fdeCount = 0;
  int rowCount = 0;
  std::map<uint64_t, uint32_t> rows;

  std::vector<uint8_t> s;
  s.reserve(CFT_ENTRY_SIZE);
  std::vector<uint8_t> rs;
  rs.reserve(12);
  for (const auto &Entry : Frame->entries()) {
    if (Entry.getKind() == llvm::dwarf::FrameEntry::FK_FDE) {
      fdeCount++;
      const auto *fde = llvm::cast<llvm::dwarf::FDE>(&Entry);

      // find the largest mapping offset <= initial location
      uint64_t map_offset = 0;
      auto map_it = map_offsets.lower_bound(fde->getInitialLocation() + 1);
      if (map_it != map_offsets.begin()) {
        --map_it;
        map_offset = map_it->second;
      }

      auto table = llvm::dwarf::createUnwindTable(fde);
      for (const auto &row : *table) {
        ++rowCount;
        if (!row.hasAddress()) {
          LOG(V1) << "Row has no address.";
          return DWARFError::ParseError;
        }

        auto locations = row.getRegisterLocations();
        if (!locations.hasLocations()) {
          LOG(V1) << "Row has no register locations.";
          return DWARFError::ParseError;
        }

        s.clear();

#ifdef notyet
        // Current llvm doesn't give us access to DW_CFA_GNU_args_size
        // It is also unclear to me atm when exactly we need to account
        // for it
        // https://github.com/llvm/llvm-project/issues/176318
        append_u64(s, row.getGnuArgsSize());
#else
        append_u64(s, 0);
#endif

        /*
         * convert row into the format used by our eBPF program
         */
        auto cfa = row.getCFAValue();
        if (cfa.getDereference()) {
          LOG(V1) << "CFA dereference not supported.";
          return DWARFError::ParseError;
        }
        switch (cfa.getLocation()) {
          case llvm::dwarf::UnwindLocation::RegPlusOffset: {
            append_u32(s, 1);
            append_u32(s, cfa.getRegister());
            append_u64(s, cfa.getOffset());
            break;
          }
          case llvm::dwarf::UnwindLocation::DWARFExpr: {
            auto expr_opt = cfa.getDWARFExpressionBytes();
            if (!expr_opt.has_value()) {
              LOG(V1) << "Missing DWARF expression bytes for CFA.";
              return DWARFError::ParseError;
            }
            auto expr_id = add_expression(expr_opt.value());
            append_u32(s, 2);
            append_u32(s, expr_id);
            append_u64(s, 0);
            break;
          }

          default:
            LOG(V1) << "Unsupported CFA location type.";
            return DWARFError::ParseError;
        }

        std::vector<std::vector<uint8_t>> reg_rules(NUM_REGISTERS);

        for (uint32_t reg : locations.getRegisters()) {
          auto loc_opt = locations.getRegisterLocation(reg);
          if (!loc_opt.has_value()) {
            LOG(V1) << "Missing location for register " << reg;
            continue;
          }
          auto loc = loc_opt.value();
          if (reg >= NUM_REGISTERS) {
            LOG(V1) << "Register " << reg << " out of range.";
            continue;
          }

          rs.clear();

          switch (loc.getLocation()) {
            case llvm::dwarf::UnwindLocation::Unspecified:
              LOG(V1) << "Unspecified location not expected.";
              continue;
            case llvm::dwarf::UnwindLocation::Undefined:
              append_u32(rs, 1);
              append_u64(rs, 0);
              break;
            case llvm::dwarf::UnwindLocation::Same:
              append_u32(rs, 2);
              append_u64(rs, 0);
              break;
            case llvm::dwarf::UnwindLocation::CFAPlusOffset:
              if (loc.getDereference())
                append_u32(rs, 3); // offset(N)
              else
                append_u32(rs, 4); // val_offset(N)
              append_u64(rs, loc.getOffset());
              break;
            case llvm::dwarf::UnwindLocation::RegPlusOffset:
              if (loc.getOffset() != 0) {
                LOG(V1) << "RegPlusOffset with non-zero offset not supported "
                           "for reg "
                        << reg;
                return DWARFError::ParseError;
              }
              append_u32(rs, 5); // register(R)
              append_u64(rs, loc.getRegister());
              break;
            case llvm::dwarf::UnwindLocation::DWARFExpr: {
              auto expr_opt = loc.getDWARFExpressionBytes();
              if (!expr_opt.has_value()) {
                LOG(V1) << "Missing DWARF expression bytes for register.";
                continue;
              }
              auto expr_id = add_expression(expr_opt.value());
              if (loc.getDereference())
                append_u32(rs, 6); // expression(E)
              else
                append_u32(rs, 7); // val_expression(E)
              append_u64(rs, expr_id);
              break;
            }
            case llvm::dwarf::UnwindLocation::Constant:
              append_u32(rs, 9);
              append_u64(rs, loc.getOffset());
              break;

            default:
              LOG(V1) << "Unsupported location type for reg " << reg;
              return DWARFError::ParseError;
          }
          reg_rules[reg] = rs;
        }

        for (int reg = 0; reg < NUM_REGISTERS; reg++) {
          if (reg_rules[reg].empty()) {
            // default to unspecifed
            append_u32(s, 0);
            append_u64(s, 0);
          } else {
            s.insert(s.end(), reg_rules[reg].begin(), reg_rules[reg].end());
          }
        }

        if (s.size() != CFT_ENTRY_SIZE) {
          LOG(V1) << "Serialized row size " << s.size()
                  << " does not match expected " << CFT_ENTRY_SIZE << " bytes.";
          return DWARFError::InternalError;
        }

        auto it = entries_.find(s);
        uint32_t id;
        if (it != entries_.end()) {
          id = it->second;
        } else {
          id = entries_.size() + 1; // reserve 0 for no entry
          entries_[s] = id;

          table_feed_cb_(TableType::UnwindEntries, id, s);
        }

        auto start = row.getAddress() - map_offset;
        // start may override end
        // start may not override start
        // end overrides nothing
        // in case an FDE ends with advance_loc(0), we may have duplicate
        //   entries
        auto r = rows.find(start);
        if (r != rows.end() && r->second != 0 && r->second != id) {
          LOG(V1) << "Start address " << std::hex << start
                  << " already exists in rows" << std::dec;
          // XXX error out?
        }
        rows[start] = id;
      }
      auto end = fde->getInitialLocation() + fde->getAddressRange() -
                 map_offset;
      auto r = rows.find(end);
      if (r == rows.end())
        rows[end] = 0;
    }
  }

  if (fdeCount == 0) {
    LOG(WARNING) << "object " << filename
                 << " does not contain information for stack walking";
  }

  LOG(V1) << "Summary: Found " << fdeCount << " FDEs and " << rowCount
          << " rows.";
  LOG(V1) << "expressions: " << expressions_.size()
          << ", entries: " << entries_.size() << ", rows: " << rows.size();

  std::vector<std::pair<uint64_t, uint64_t>> table_entries;
  for (const auto &row : rows) {
    table_entries.emplace_back(row.first, row.second);
  }
  size_t start = 0;
  while (start < table_entries.size()) {
    size_t out_entries = 0;
    auto sz = CHUNK_SIZE - current_table_.size() - 16;
    auto table_data = build_table(table_entries, start, sz, out_entries);
    LOG(V1) << "Built table chunk with " << out_entries << " entries, size "
            << table_data.size() << " bytes.";
    auto e = table_mappings_.emplace(oid, std::vector<TableMapping>{});
    e.first->second.push_back(
        TableMapping{ .file_offset = table_entries[start].first,
                      .table_id = current_table_id_,
                      .table_offset = current_table_.size() });
    if (current_table_.empty()) {
      swap(current_table_, table_data);
    } else {
      current_table_.insert(current_table_.end(),
                            table_data.begin(),
                            table_data.end());
    }
    if (current_table_.size() >= CHUNK_SIZE - 200) {
      push_current_table();
      current_table_.clear();
      ++current_table_id_;
    }
    start += out_entries;
  }

  return DWARFError::Success;
#else
  // avoid unused parameter warnings when DWARF_UNWIND is not defined
  (void)filename;
  (void)oid;
  (void)map_offsets;
  throw std::runtime_error("DWARF unwind not supported");
#endif
}

struct ProcessMapEntry {
  uint64_t vm_start;
  uint64_t vm_end;
  uint64_t offset;
  std::string file_path;
};

std::vector<ProcessMapEntry> read_process_maps(int pid)
{
  std::vector<ProcessMapEntry> maps;
  std::string filename = "/proc/" + std::to_string(pid) + "/maps";
  std::ifstream file(filename);

  if (!file.is_open())
    return maps;

  std::string line;
  while (std::getline(file, line)) {
    std::istringstream iss(line);

    std::uintptr_t start = 0;
    std::uintptr_t end = 0;
    std::uint64_t offset = 0;
    unsigned long inode = 0;
    char dash = 0;
    std::string perms;
    std::string dev;
    std::string path;

    if (iss >> std::hex >> start >> dash >> end >> perms >> offset >> dev >>
        std::dec >> inode) {
      iss >> std::ws;
      // Read the remainder of the line as the path
      if (std::getline(iss, path) && !path.empty()) {
        if (!(path[0] == '/'))
          continue;
        if (perms.find("x") == std::string::npos)
          continue;
        if (path.size() > 10 && path.substr(path.size() - 10) == " (deleted)") {
          LOG(ERROR) << "object not available: " << path;
          continue;
        }
        maps.emplace_back(ProcessMapEntry{ .vm_start = start,
                                           .vm_end = end,
                                           .offset = offset,
                                           .file_path = std::move(path) });
      }
    }
  }

  return maps;
}

DWARFError DWARFUnwind::add_pid(pid_t pid)
{
  auto maps = read_process_maps(pid);
  // output mapping vector, reserve room for nentries record at the beginning
  std::vector<uint8_t> s = { 0, 0, 0, 0, 0, 0, 0, 0 };
  int num_entries = 0;
  s.reserve((MAX_MAPPINGS * 24) + 8);

  for (const auto &map : maps) {
    uint32_t oid;
    auto err = add_file_nopush(map.file_path, pid, oid);
    if (err != DWARFError::Success) {
      LOG(V1) << "File " << map.file_path << " not added: Error " << err;
      return err;
    }
    auto e = table_mappings_.find(oid);
    if (e == table_mappings_.end()) {
      LOG(V1) << "No table mapping found for OID " << oid;
      continue;
    }
    auto mapping = e->second;
    auto map_offset_end = map.offset + (map.vm_end - map.vm_start);
    for (const auto &me : mapping) {
      if (me.file_offset >= map_offset_end) {
        break;
      }
      if (me.file_offset < map.offset) {
        continue;
      }
      auto delta = me.file_offset - map.offset;

      auto start = map.vm_start + delta;
      auto offset = map.offset + delta;
      auto table_id = me.table_id;
      auto table_offset = me.table_offset;

      s.reserve(s.size() + 24);
      append_u64(s, start);
      append_u64(s, offset);
      append_u32(s, table_id);
      append_u32(s, table_offset);

      ++num_entries;
    }
  }

  push_current_table();

  // set number of entries at the beginning
  std::vector<uint8_t> nentries;
  nentries.reserve(8);
  append_u64(nentries, num_entries);
  for (int i = 0; i < 8; i++)
    s[i] = nentries[i];

  // fill up to expected size
  s.resize((MAX_MAPPINGS * 24) + 8, 0);

  table_feed_cb_(TableType::Mappings, pid, s);

  return DWARFError::Success;
}
