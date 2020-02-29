#include "btf.h"
#include "bpftrace.h"
#include "types.h"
#include "utils.h"
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/limits.h>
#include <regex>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifdef HAVE_LIBBPF_BTF_DUMP
#include <linux/bpf.h>
#include <linux/btf.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#include <bpf/btf.h>
#pragma GCC diagnostic pop
#include <bpf/libbpf.h>

namespace bpftrace {

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

static struct btf *btf_open(const struct vmlinux_location *locs)
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
  struct vmlinux_location locs_env[] = {
    { nullptr, true },
    { nullptr, false },
  };

  const struct vmlinux_location *locs = vmlinux_locs;

  // Try to get BTF file from BPFTRACE_BTF env
  char *path = std::getenv("BPFTRACE_BTF");

  if (path)
  {
    locs_env[0].path = path;
    locs = locs_env;
  }

  btf = btf_open(locs);
  if (btf)
  {
    libbpf_set_print(libbpf_print);
    state = OK;
  }
  else if (bt_debug != DebugLevel::kNone)
  {
    std::cerr << "BTF: failed to find BTF data " << std::endl;
  }
}

BTF::~BTF()
{
  btf__free(btf);
}

static void dump_printf(void *ctx, const char *fmt, va_list args)
{
  std::string *ret = static_cast<std::string*>(ctx);
  char *str;

  if (vasprintf(&str, fmt, args) < 0)
    return;

  *ret += str;
  free(str);
}

static const char *btf_str(const struct btf *btf, __u32 off)
{
  if (!off)
    return "(anon)";

  return btf__name_by_offset(btf, off) ? : "(invalid)";
}

static std::string full_type_str(const struct btf *btf, const struct btf_type *type)
{
  const char *str = btf_str(btf, type->name_off);

  if (BTF_INFO_KIND(type->info) == BTF_KIND_STRUCT)
    return std::string("struct ") + str;

  if (BTF_INFO_KIND(type->info) == BTF_KIND_UNION)
    return std::string("union ") + str;

  return str;
}

static std::string btf_type_str(const std::string& type)
{
  return std::regex_replace(type, std::regex("^(struct )|(union )"), "");
}

std::string BTF::c_def(std::unordered_set<std::string>& set)
{
  std::string ret = std::string("");
  struct btf_dump_opts opts = { .ctx = &ret, };
  struct btf_dump *dump;
  char err_buf[256];
  int err;

  dump = btf_dump__new(btf, nullptr, &opts, dump_printf);
  err = libbpf_get_error(dump);
  if (err)
  {
      libbpf_strerror(err, err_buf, sizeof(err_buf));
      std::cerr << "BTF: failed to initialize dump (" << err_buf << ")" << std::endl;
      return std::string("");
  }

  std::unordered_set<std::string> myset(set);
  __s32 id, max = (__s32) btf__get_nr_types(btf);

  for (id = 1; id <= max && myset.size(); id++)
  {
    const struct btf_type *t = btf__type_by_id(btf, id);
    std::string str = full_type_str(btf, t);

    auto it = myset.find(str);
    if (it != myset.end())
    {
      btf_dump__dump_type(dump, id);
      myset.erase(it);
    }
  }

  btf_dump__free(dump);
  return ret;
}

std::string BTF::type_of(const std::string& name, const std::string& field)
{
  __s32 type_id = btf__find_by_name(btf, btf_type_str(name).c_str());

  if (type_id < 0)
    return std::string("");

  const struct btf_type *type = btf__type_by_id(btf, type_id);
  return type_of(type, field);
}

std::string BTF::type_of(const btf_type *type, const std::string &field)
{
  if (!type ||
      (BTF_INFO_KIND(type->info) != BTF_KIND_STRUCT &&
       BTF_INFO_KIND(type->info) != BTF_KIND_UNION))
    return std::string("");

  // We need to walk through oaa the struct/union members
  // and try to find the requested field name.
  //
  // More info on struct/union members:
  //  https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-union
  const struct btf_member *m = reinterpret_cast<const struct btf_member*>(type + 1);

  for (unsigned int i = 0; i < BTF_INFO_VLEN(type->info); i++)
  {
    std::string m_name = btf__name_by_offset(btf, m[i].name_off);

    // anonymous struct/union
    if (m_name == "")
    {
      const struct btf_type *type = btf__type_by_id(btf, m[i].type);
      std::string type_name = type_of(type, field);
      if (!type_name.empty())
        return type_name;
    }

    if (m_name != field)
      continue;

    const struct btf_type *f = btf__type_by_id(btf, m[i].type);

    if (!f)
      break;

    // Get rid of all the pointers and qualifiers on the way to the actual type.
    while (BTF_INFO_KIND(f->info) == BTF_KIND_PTR ||
           BTF_INFO_KIND(f->info) == BTF_KIND_CONST ||
           BTF_INFO_KIND(f->info) == BTF_KIND_VOLATILE ||
           BTF_INFO_KIND(f->info) == BTF_KIND_RESTRICT)
    {
      f = btf__type_by_id(btf, f->type);
    }

    return full_type_str(btf, f);
  }

  return std::string("");
}

} // namespace bpftrace

#else // HAVE_LIBBPF_BTF_DUMP

namespace bpftrace {

BTF::BTF() { }

BTF::~BTF() { }

std::string BTF::c_def(std::unordered_set<std::string>& set __attribute__((__unused__))) { return std::string(""); }

std::string BTF::type_of(const std::string& name __attribute__((__unused__)),
                         const std::string& field __attribute__((__unused__))) {
  return std::string("");
}

} // namespace bpftrace

#endif // HAVE_LIBBPF_BTF_DUMP
