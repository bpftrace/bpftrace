#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <filesystem>
#include <optional>
#include <cstring>
#include <unordered_map>
#include <libelf.h>
#include <gelf.h>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <algorithm>

#include "log.h"
#include "util/elf_parser.h"
#include "util/hash.h"

namespace bpftrace::util {

char ELFParseError::ID;

void ELFParseError::log(llvm::raw_ostream &OS) const {
    OS << msg_;
}

struct PairHash {
    std::size_t operator()(const std::pair<std::string, std::string>& p) const {
        std::size_t seed = 0;
        hash_combine(seed, p.first);
        hash_combine(seed, p.second);
        return seed;
    }
};

static Result<std::vector<struct elf_seg>> parse_elf_segs(Elf *elf, const std::string &path)
{
    std::vector<struct elf_seg> segs;
	GElf_Phdr phdr;
	size_t n;

	if (elf_getphdrnum(elf, &n)) {
		using namespace std::string_literals;
		return make_error<ELFParseError>("usdt: failed to process ELF program segments for '"s + path + "': " + strerror(-errno));
	}

	for (size_t i = 0; i < n; i++) {
		if (!gelf_getphdr(elf, i, &phdr)) {
			using namespace std::string_literals;
            return make_error<ELFParseError>("usdt: failed to process ELF program segments for '"s + path + "': " + strerror(-errno));
		}

		if (phdr.p_type != PT_LOAD)
			continue;
        segs.emplace_back(static_cast<long>(phdr.p_vaddr), 
                          static_cast<long>(phdr.p_vaddr + phdr.p_memsz), 
                          static_cast<long>(phdr.p_offset), 
                          static_cast<bool>(phdr.p_flags & PF_X));
	}

	if (segs.empty()) {
		LOG(WARNING) << "failed to find PT_LOAD program headers in '" << path;
	}

    std::sort(segs.begin(), segs.end(), [](const elf_seg& a, const elf_seg& b){
        return a.start < b.start;
    });
	return segs;
}

static Result<std::pair<Elf_Scn*, GElf_Shdr>> find_elf_sec_by_name(const std::string& path, Elf *elf, const std::string_view sec_name)
{
	Elf_Scn *sec = NULL;
	size_t shstrndx;
	GElf_Shdr shdr;

    // get elf string table index
	if (elf_getshdrstrndx(elf, &shstrndx)) {
        return make_error<ELFParseError>("failed to get string table index from " + path + ": " + elf_errmsg(-1));
    }

	/* check if ELF is corrupted and avoid calling elf_strptr if yes */
	if (!elf_rawdata(elf_getscn(elf, shstrndx), NULL))
		return make_error<ELFParseError>("ELF is corrupted : " + path);

	while ((sec = elf_nextscn(elf, sec)) != NULL) {

		if (!gelf_getshdr(sec, &shdr))
			return make_error<ELFParseError>("failed to get ELF section header" + path);

		auto name = elf_strptr(elf, shstrndx, shdr.sh_name);
		if (name && sec_name == name) {
			return std::make_pair(sec, shdr);
		}
	}

	return make_error<ELFParseError>("usdt: no notes section (" + std::string(sec_name) + ") found in " + path);
}

static Result<struct usdt_spec_meta> parse_usdt_spec_meta(const std::string& elf_path, GElf_Nhdr *nhdr,
    const char *data, size_t name_off, size_t desc_off)
{
    const char *provider, *name;
    long addrs[3];
    size_t len;

    /* sanity check USDT note name and type first */
    if (nhdr->n_namesz != USDT_NOTE_NAME.size() + 1 ||  // +1 for null terminator
        std::string_view(data + name_off, USDT_NOTE_NAME.size()).compare(USDT_NOTE_NAME) != 0)
        return make_error<ELFParseError>("usdt: invalid USDT note name");
    if (nhdr->n_type != USDT_NOTE_TYPE)
        return make_error<ELFParseError>("usdt: invalid USDT note type");

    /* sanity check USDT note contents ("description" in ELF terminology) */
    len = nhdr->n_descsz;
    data = data + desc_off;

    /* +3 is the very minimum required to store three empty strings */
    if (len < sizeof(addrs) + 3)
        return make_error<ELFParseError>("usdt: invalid USDT note contents");

    /* get location, base, and semaphore addrs */
    memcpy(&addrs, data, sizeof(addrs));

    /* parse string fields: provider, name, args */
    provider = data + sizeof(addrs);

    name = (const char *)memchr(provider, '\0', data + len - provider);
    if (!name) /* non-zero-terminated provider */
        return make_error<ELFParseError>("usdt: invalid USDT note contents");
    name++;
    if (name >= data + len || *name == '\0') /* missing or empty name */
        return make_error<ELFParseError>("usdt: invalid USDT note contents");

    struct usdt_spec_meta note(provider, name, elf_path, addrs[2], 0);

    return note;
}



Result<USDTProbeEnumerator> make_usdt_probe_enumerator(const std::string& path) {
    std::filesystem::path file_path(path);
    if (!std::filesystem::exists(file_path)) {
        return make_error<ELFParseError>("file doesn't exist");
    }
        
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        return make_error<ELFParseError>("Cannot open ELF file: " + path );
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        return make_error<ELFParseError>("Unsupported ELF version: " + path);
    }
    
    Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) {
        return make_error<ELFParseError>("Failed to create ELF descriptor: " + path);
    }
    
    if (elf_kind(elf) != ELF_K_ELF) {
        return make_error<ELFParseError>(path + "is not an ELF file");
    }
    
    GElf_Ehdr ehdr;
    if (gelf_getehdr(elf, &ehdr) != &ehdr) {
        return make_error<ELFParseError>("Failed to get ELF header: " + path);
    }
    
    if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
        return make_error<ELFParseError>("Unsupported ELF type: " + std::to_string(ehdr.e_type) + "(Only support executable and shared library)");
    }
    
    return USDTProbeEnumerator(path, fd, elf);
}

Result<std::vector<usdt_spec_meta>> USDTProbeEnumerator::enumerate_probes() {
    std::unordered_map<std::pair<std::string, std::string>, usdt_spec_meta, PairHash> unique_probes;
    std::vector<usdt_spec_meta> probes;

    size_t off, name_off, desc_off;
    GElf_Ehdr ehdr;
    GElf_Nhdr nhdr;
    Elf_Data* data;
    
    auto notes_scn_res = find_elf_sec_by_name(std::string(elf_path), elf, USDT_NOTE_SEC);
    if (!notes_scn_res) {
        return notes_scn_res.takeError();
    }
    auto [notes_scn, notes_shdr] = *notes_scn_res; 

    if (notes_shdr.sh_type != SHT_NOTE || !gelf_getehdr(elf, &ehdr)) {
        return make_error<ELFParseError>("invalid USDT notes section (" + USDT_NOTE_SEC + ") in '" + std::string(elf_path) + "'");
    }

    auto segs_res = parse_elf_segs(elf, std::string(elf_path));
    if (!segs_res) {
        return segs_res.takeError();
    }
    auto segs = *segs_res;
    
    data = elf_getdata(notes_scn, 0);
    off = 0;
    while ((off = gelf_getnote(data, off, &nhdr, &name_off, &desc_off)) > 0) {
        auto note_res = parse_usdt_spec_meta(elf_path, &nhdr, (const char*)data->d_buf, name_off, desc_off);
        if (!note_res) {
            continue;
        }
        auto note = *note_res;
        note.bin_path = elf_path;
        if (note.sema_addr) {
            /* for ELF binaries (both executables and shared libraries), we are
            * given virtual address (absolute for executables, relative for
            * libraries) which should match address range of [seg_start, seg_end)
            */
            auto seg = std::find_if(segs.begin(), segs.end(), 
                [note](const elf_seg& seg) {
                    return seg.start <= note.sema_addr && note.sema_addr < seg.end;
                }
            );
            if (seg == segs.end()) {
                return make_error<ELFParseError>("usdt: failed to find ELF loadable segment with semaphore of '" + note.provider + ":" + note.name + "' in '" + std::string(elf_path) + "' at 0x" + std::to_string(note.sema_addr));
            }
            if (seg->is_exec) {
                return make_error<ELFParseError>("usdt: matched ELF binary '" + std::string(elf_path) + "' segment [0x" + std::to_string(seg->start) + ", 0x" + std::to_string(seg->end) + "] for semaphore of '" + note.provider + ":" + note.name + "' at 0x" + std::to_string(note.sema_addr) + " is executable");
            }
            note.sema_offset = note.sema_addr - seg->start + seg->offset;
        }
        auto key = std::make_pair(note.provider, note.name);
        auto target = unique_probes.find(key);
        if (target == unique_probes.end()) {
            unique_probes.emplace(key, note);
        } else {
#ifndef HAVE_LIBBPF_UPROBE_MULTI
            ++target->second.num_locations;
#endif
        }
    }
    std::transform(unique_probes.begin(), unique_probes.end(), std::back_inserter(probes),
                [](const auto& pair) { return pair.second; });
    
    return probes;
}

} // namespace bpftrace::util