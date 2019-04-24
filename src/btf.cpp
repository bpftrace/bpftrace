#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <string.h>
#include <linux/limits.h>
#include "btf.h"
#include "types.h"
#include "bpftrace.h"

#ifdef HAVE_LIBBPF_BTF_DUMP
#include <linux/bpf.h>
#include <linux/btf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

namespace bpftrace {

struct btf_location {
  const char *path; // path with possible "%s" format to be replaced current release
  bool        raw;  // file is either as ELF (false) or raw BTF data (true)
};

static unsigned char *get_data(const char *file, ssize_t *sizep)
{
  struct stat st;

  if (stat(file, &st))
    return nullptr;

  FILE *f;

  f = fopen(file, "rb");
  if (!f)
    return nullptr;

  unsigned char *data;
  unsigned int size;

  size = st.st_size;

  data = (unsigned char *) malloc(size);
  if (!data)
  {
    fclose(f);
    return nullptr;
  }

  ssize_t ret = fread(data, 1, st.st_size, f);

  if (ret != st.st_size)
  {
    free(data);
    fclose(f);
    return nullptr;
  }

  fclose(f);

  *sizep = size;
  return data;
}

static struct btf* btf_raw(char *file)
{
  unsigned char *data;
  ssize_t size;
  struct btf *btf;

  data = get_data(file, &size);
  if (!data)
  {
    std::cerr << "BTF: failed to read data from: " << file << std::endl;
    return nullptr;
  }

  btf = btf__new(data, (__u32) size);
  free(data);
  return btf;
}

static int libbpf_print(enum libbpf_print_level level, const char *msg, va_list ap)
{
  fprintf(stderr, "BTF: (%d) ", level);
  return vfprintf(stderr, msg, ap);
}

static struct btf *btf_open(struct btf_location *locs)
{
  struct utsname buf;

  uname(&buf);

  for (int i = 0; locs[i].path; i++)
  {
    char path[PATH_MAX + 1];

    snprintf(path, PATH_MAX, locs[i].path, buf.release);
    if (access(path, R_OK))
      continue;

    struct btf *btf;

    if (locs[i].raw)
      btf = btf_raw(path);
    else
      btf = btf__parse_elf(path, nullptr);

    int err = libbpf_get_error(btf);

    if (err)
    {
      if (bt_verbose)
      {
        char err_buf[256];

        libbpf_strerror(libbpf_get_error(btf), err_buf, sizeof(err_buf));
        std::cerr << "BTF: failed to read data (" << err_buf << ") from: " << path << std::endl;
      }
      continue;
    }

    if (bt_verbose)
    {
      std::cerr << "BTF: using data from " << path << std::endl;
    }
    return btf;
  }

  return nullptr;
}

BTF::BTF(void) : btf(nullptr), state(NODATA)
{
  // 'borrowed' from libbpf's bpf_core_find_kernel_btf
  // from Andrii Nakryiko
  struct btf_location locs_normal[] =
  {
    { "/sys/kernel/btf/vmlinux",                 true  },
    { "/boot/vmlinux-%1$s",                      false },
    { "/lib/modules/%1$s/vmlinux-%1$s",          false },
    { "/lib/modules/%1$s/build/vmlinux",         false },
    { "/usr/lib/modules/%1$s/kernel/vmlinux",    false },
    { "/usr/lib/debug/boot/vmlinux-%1$s",        false },
    { "/usr/lib/debug/boot/vmlinux-%1$s.debug",  false },
    { "/usr/lib/debug/lib/modules/%1$s/vmlinux", false },
    { nullptr, false },
  };

  struct btf_location locs_test[] =
  {
    { nullptr, true  },
    { nullptr, false },
  };

  struct btf_location *locs = locs_normal;

  // Try to get BTF file from BPFTRACE_BTF_TEST env
  char *path = std::getenv("BPFTRACE_BTF_TEST");

  if (path)
  {
    locs_test[0].path = path;
    locs = locs_test;
  }

  btf = btf_open(locs);
  if (btf)
  {
    libbpf_set_print(libbpf_print);
    state = OK;
  }
  else
  {
    std::cerr << "BTF: failed to find BTF data " << std::endl;
  }
}

BTF::~BTF()
{
  btf__free(btf);
}

} // namespace bpftrace

#else // HAVE_LIBBPF_BTF_DUMP

namespace bpftrace {

BTF::BTF() { }

BTF::~BTF() { }

} // namespace bpftrace

#endif // HAVE_LIBBPF_BTF_DUMP
