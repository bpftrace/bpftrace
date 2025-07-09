#include <bpf/bpf.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#include <bpf/btf.h>
#pragma GCC diagnostic pop
#include <limits>
#include <linux/btf.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "log.h"
#include "scopeguard.h"
#include "util/fd.h"

namespace bpftrace::util {

std::string get_prog_full_name(const struct bpf_prog_info *prog_info,
                               int prog_fd)
{
  const char *prog_name = prog_info->name;
  const struct btf_type *func_type;
  struct bpf_func_info finfo = {};
  struct bpf_prog_info info = {};
  __u32 info_len = sizeof(info);

  std::string name = std::string(prog_name);

  if (!prog_info->btf_id || prog_info->nr_func_info == 0) {
    return name;
  }

  info.nr_func_info = 1;
  info.func_info_rec_size = prog_info->func_info_rec_size;
  info.func_info_rec_size = std::min<unsigned long>(info.func_info_rec_size,
                                                    sizeof(finfo));
  info.func_info = reinterpret_cast<__u64>(&finfo);

  if (bpf_prog_get_info_by_fd(prog_fd, &info, &info_len)) {
    return name;
  }

  struct btf *prog_btf = btf__load_from_kernel_by_id(info.btf_id);
  if (!prog_btf) {
    return name;
  }

  func_type = btf__type_by_id(prog_btf, finfo.type_id);
  if (!func_type || !btf_is_func(func_type)) {
    btf__free(prog_btf);
    return name;
  }

  prog_name = btf__name_by_offset(prog_btf, func_type->name_off);
  name = std::string(prog_name);
  btf__free(prog_btf);
  return name;
}

std::vector<std::pair<__u32, std::string>> get_bpf_progs()
{
  std::vector<std::pair<__u32, std::string>> ids_and_syms;
  __u32 id = 0;
  while (bpf_prog_get_next_id(id, &id) == 0) {
    int raw_fd = bpf_prog_get_fd_by_id(id);

    if (raw_fd < 0) {
      continue;
    }

    auto fd = FD(raw_fd);

    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);

    if (bpf_obj_get_info_by_fd(fd, &info, &info_len) != 0) {
      continue;
    }

    if (!info.btf_id) {
      // BPF programs that don't have a BTF id won't load
      continue;
    }

    ids_and_syms.emplace_back(id, get_prog_full_name(&info, fd));

    // Now let's look at the subprograms for this program
    // if they exist
    if (info.nr_func_info == 0) {
      continue;
    }

    size_t nr_func_info = info.nr_func_info;
    size_t rec_size = info.func_info_rec_size;

    if (rec_size > std::numeric_limits<std::size_t>::max() / nr_func_info) {
      // This shouldn't happen
      continue;
    }

    std::vector<char> fi_mem(nr_func_info * rec_size);

    struct btf *btf = btf__load_from_kernel_by_id(info.btf_id);
    if (!btf) {
      continue;
    }

    SCOPE_EXIT
    {
      btf__free(btf);
    };

    info = {};
    info.nr_func_info = nr_func_info;
    info.func_info_rec_size = rec_size;
    info.func_info = reinterpret_cast<__u64>(fi_mem.data());

    if (bpf_prog_get_info_by_fd(fd, &info, &info_len) != 0) {
      continue;
    }

    auto *func_info = reinterpret_cast<struct bpf_func_info *>(fi_mem.data());

    for (__u32 i = 0; i < nr_func_info; i++) {
      const struct btf_type *t = btf__type_by_id(btf, (func_info + i)->type_id);
      if (!t) {
        continue;
      }

      const char *func_name = btf__name_by_offset(btf, t->name_off);
      ids_and_syms.emplace_back(id, std::string(func_name));
    }
  }

  return ids_and_syms;
}

} // namespace bpftrace::util
