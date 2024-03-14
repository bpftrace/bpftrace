#include "bpfbytecode.h"

#include "log.h"
#include "utils.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <elf.h>
#include <stdexcept>

namespace bpftrace {

BpfBytecode::BpfBytecode(const void *elf, size_t elf_size)
{
  bpf_object_ = std::unique_ptr<struct bpf_object, bpf_object_deleter>(
      bpf_object__open_mem(elf, elf_size, nullptr));
  if (!bpf_object_)
    LOG(BUG) << "The produced ELF is not a valid BPF object";

  struct bpf_map *m;
  bpf_map__for_each (m, bpf_object_.get()) {
    maps_.emplace(bpftrace_map_name(bpf_map__name(m)), m);
  }

  struct bpf_program *p;
  bpf_object__for_each_program(p, bpf_object_.get())
  {
    programs_.emplace(bpf_program__name(p), p);
  }
}

void BpfBytecode::addSection(const std::string &name,
                             std::vector<uint8_t> &&data)
{
  sections_.emplace(name, data);
}

bool BpfBytecode::hasSection(const std::string &name) const
{
  return sections_.find(name) != sections_.end();
}

const std::vector<uint8_t> &BpfBytecode::getSection(
    const std::string &name) const
{
  if (!hasSection(name)) {
    LOG(BUG) << "Bytecode is missing section: " << name;
  }
  return sections_.at(name);
}

const BpfProgram &BpfBytecode::getProgramForProbe(const Probe &probe) const
{
  auto usdt_location_idx = (probe.type == ProbeType::usdt)
                               ? std::make_optional<int>(
                                     probe.usdt_location_idx)
                               : std::nullopt;

  auto prog = programs_.find(
      get_function_name_for_probe(probe.name, probe.index, usdt_location_idx));
  if (prog == programs_.end()) {
    prog = programs_.find(get_function_name_for_probe(probe.orig_name,
                                                      probe.index,
                                                      usdt_location_idx));
  }

  if (prog == programs_.end()) {
    std::stringstream msg;
    if (probe.name != probe.orig_name)
      msg << "Code not generated for probe: " << probe.name
          << " from: " << probe.orig_name;
    else
      msg << "Code not generated for probe: " << probe.name;
    throw std::runtime_error(msg.str());
  }

  return prog->second;
}

BpfProgram &BpfBytecode::getProgramForProbe(const Probe &probe)
{
  return const_cast<BpfProgram &>(
      const_cast<const BpfBytecode *>(this)->getProgramForProbe(probe));
}

void BpfBytecode::load_progs(const RequiredResources &resources,
                             BTF &btf,
                             BPFfeature &feature)
{
  load_progs(resources.probes, btf, feature);
  load_progs(resources.special_probes, btf, feature);
  load_progs(resources.watchpoint_probes, btf, feature);
}

void BpfBytecode::load_progs(const std::vector<Probe> &probes,
                             BTF &btf,
                             BPFfeature &feature)
{
  for (auto &probe : probes) {
    auto &program = getProgramForProbe(probe);
    program.assemble(*this);
    program.load(probe, *this, btf, feature);
  }
}

bool BpfBytecode::create_maps()
{
  int failed_maps = 0;
  for (auto &map : maps_) {
    BPFTRACE_LIBBPF_OPTS(bpf_map_create_opts, opts);
    map.second.fd = bpf_map_create(static_cast<::bpf_map_type>(
                                       map.second.type()),
                                   map.second.bpf_name().c_str(),
                                   map.second.key_size(),
                                   map.second.value_size(),
                                   map.second.max_entries(),
                                   &opts);
    if (map.second.fd < 0) {
      failed_maps++;
      LOG(ERROR) << "failed to create map: '" << map.first
                 << "': " << strerror(errno);
    }
  }

  if (failed_maps > 0) {
    LOG(ERROR) << "Creation of the required BPF maps has failed. \nMake sure "
                  "you have all the required permissions and are not confined "
                  "(e.g. like snapcraft does).\n`dmesg` will likely have "
                  "useful output for further troubleshooting";
    return false;
  }
  return true;
}

bool BpfBytecode::hasMap(MapType internal_type) const
{
  return maps_.find(to_string(internal_type)) != maps_.end();
}

bool BpfBytecode::hasMap(const StackType &stack_type) const
{
  return maps_.find(stack_type.name()) != maps_.end();
}

const BpfMap &BpfBytecode::getMap(const std::string &name) const
{
  auto map = maps_.find(name);
  if (map == maps_.end()) {
    LOG(BUG) << "Unknown map: " << name;
  }
  return map->second;
}

const BpfMap &BpfBytecode::getMap(MapType internal_type) const
{
  return getMap(to_string(internal_type));
}

const BpfMap &BpfBytecode::getMap(int map_id) const
{
  auto map = maps_by_id_.find(map_id);
  if (map == maps_by_id_.end()) {
    LOG(BUG) << "Unknown map id: " << std::to_string(map_id);
  }
  return *map->second;
}

const std::map<std::string, BpfMap> &BpfBytecode::maps() const
{
  return maps_;
}

int BpfBytecode::countStackMaps() const
{
  int n = 0;
  for (auto &map : maps_) {
    if (map.second.is_stack_map())
      n++;
  }
  return n;
}

void BpfBytecode::set_map_ids(RequiredResources &resources)
{
  for (auto &map : maps_) {
    auto map_info = resources.maps_info.find(map.first);
    if (map_info != resources.maps_info.end() && map_info->second.id != -1)
      maps_by_id_.emplace(map_info->second.id, &map.second);
  }
}

// This is taken from libbpf (btf.c) and we need it to manually iterate BTF
// entries so that we can fix them up in place.
// Should go away once we let libbpf do the BTF fixup.
static int btf_type_size(const struct btf_type *t)
{
  const int base_size = sizeof(struct btf_type);
  __u16 vlen = btf_vlen(t);

  switch (btf_kind(t)) {
    case BTF_KIND_FWD:
    case BTF_KIND_CONST:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_RESTRICT:
    case BTF_KIND_PTR:
    case BTF_KIND_TYPEDEF:
    case BTF_KIND_FUNC:
    case BTF_KIND_FLOAT:
    case BTF_KIND_TYPE_TAG:
      return base_size;
    case BTF_KIND_INT:
      return base_size + sizeof(__u32);
    case BTF_KIND_ENUM:
      return base_size + vlen * sizeof(struct btf_enum);
    case BTF_KIND_ENUM64:
      /* struct btf_enum64 is not available in UAPI header until v6.0,
       * calculate its size with array instead. Its definition is:
       *
       * struct btf_enum64 {
       *	__u32	name_off;
       *	__u32	val_lo32;
       *	__u32	val_hi32;
       * };
       */
      return base_size + vlen * sizeof(__u32[3]);
    case BTF_KIND_ARRAY:
      return base_size + sizeof(struct btf_array);
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:
      return base_size + vlen * sizeof(struct btf_member);
    case BTF_KIND_FUNC_PROTO:
      return base_size + vlen * sizeof(struct btf_param);
    case BTF_KIND_VAR:
      return base_size + sizeof(struct btf_var);
    case BTF_KIND_DATASEC:
      return base_size + vlen * sizeof(struct btf_var_secinfo);
    case BTF_KIND_DECL_TAG:
      /* struct btf_decl_tag is not available until v5.16. Use the same trick
       * as btf_enum64 above. Its definition is:
       *
       * struct btf_decl_tag {
       *  __s32   component_idx;
       * };
       */
      return base_size + sizeof(__s32);
    default:
      return -EINVAL;
  }
}

uint64_t getSymbolOffset(std::string_view name,
                         const std::vector<uint8_t> &symtab,
                         const std::vector<uint8_t> &strtab)
{
  auto *ptr = symtab.data();
  while (ptr < symtab.data() + symtab.size()) {
    auto *sym = reinterpret_cast<const Elf64_Sym *>(ptr);
    auto *sym_name = reinterpret_cast<const char *>(strtab.data() +
                                                    sym->st_name);
    if (sym_name == name)
      return sym->st_value;

    ptr += sizeof(Elf64_Sym);
  }
  throw std::invalid_argument("Entry for " + std::string(name) +
                              " not found in the symbol table");
}

// There are cases when BTF generated by LLVM needs to be patched. This is
// normally done by libbpf but only when loading via bpf_object is used. We're
// currently using direct loading using bpf_btf_load and bpf_prog_load so we
// need to mimic libbpf's behavior and do the patching manually.
// This should go away once we move to bpf_object-based loading.
//
// Transformations done:
// - If running on a kernel not supporting BTF func entries with BTF_FUNC_GLOBAL
//   linkage, change the linkage type to 0. We cannot do this directly in
//   codegen b/c LLVM would optimize our functions away.
// - Fill section size and symbol offsets to DATASEC BTF entries which describe
//   sections with data (in our case ".maps").
void BpfBytecode::fixupBTF(BPFfeature &feature)
{
  if (!hasSection(".BTF"))
    return;

  auto &symtab = sections_.find(".symtab")->second;
  auto &strtab = sections_.find(".strtab")->second;

  auto &btfsec = sections_[".BTF"];
  auto *btfhdr = reinterpret_cast<struct btf_header *>(btfsec.data());
  auto *btf = btf__new(btfsec.data(), btfsec.size());

  auto *types_start = btfsec.data() + sizeof(struct btf_header) +
                      btfhdr->type_off;
  auto *types_end = types_start + btfhdr->type_len;

  // Unfortunately, libbpf's btf__type_by_id returns a const pointer which
  // doesn't allow modification. So, we must iterate the types manually.
  auto *ptr = types_start;
  while (ptr + sizeof(struct btf_type) <= types_end) {
    auto *btf_type = reinterpret_cast<struct btf_type *>(ptr);
    ptr += btf_type_size(btf_type);

    // Change linkage type to 0 if the kernel doesn't support BTF_FUNC_GLOBAL.
    if (!feature.has_btf_func_global() &&
        BTF_INFO_KIND(btf_type->info) == BTF_KIND_FUNC) {
      btf_type->info = BTF_INFO_ENC(BTF_KIND_FUNC, 0, 0);
    }

    // Fill section size and offsets for DATASEC entries
    if (BTF_INFO_KIND(btf_type->info) == BTF_KIND_DATASEC) {
      auto *sec_name = btf__name_by_offset(btf, btf_type->name_off);

      if (!hasSection(sec_name)) {
        btf__free(btf);
        throw std::logic_error("Found BTF entry for section " +
                               std::string(sec_name) +
                               " but the section was not found");
      }

      // Fix section size
      btf_type->size = getSection(sec_name).size();

      auto *members = btf_var_secinfos(btf_type);
      for (unsigned i = 0; i < BTF_INFO_VLEN(btf_type->info); i++) {
        auto *sym = btf__type_by_id(btf, members[i].type);
        if (!sym) {
          btf__free(btf);
          throw std::logic_error("No BTF entry for type id " +
                                 std::to_string(members[i].type));
        }
        auto *sym_name = btf__name_by_offset(btf, sym->name_off);
        // Fix symbol offsets
        members[i].offset = getSymbolOffset(sym_name, symtab, strtab);
      }
    }
  }
  btf__free(btf);
}

} // namespace bpftrace
