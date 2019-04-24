#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <string.h>
#include "btf.h"
#include "types.h"
#include "bpftrace.h"

#ifdef HAVE_LIBBPF
#include <linux/bpf.h>
#include <linux/btf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

namespace bpftrace {

static inline long PTR_ERR(const void *ptr)
{
  return (long) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
  return IS_ERR_VALUE((unsigned long) ptr);
}

static int libbpf_print(enum libbpf_print_level level, const char *msg, va_list ap)
{
  fprintf(stderr, "BTF: (%d) ", level);
  return vfprintf(stderr, msg, ap);
}

void BTF::init(unsigned char *data, unsigned int size)
{
  libbpf_set_print(libbpf_print);

  btf = btf__new(data, (__u32) size);
  if (IS_ERR(btf))
  {
    std::cerr << "BTF: failed to initialize data" << std::endl;
    btf = NULL;
    return;
  }

  state = OK;
}

BTF::BTF(unsigned char *data, unsigned int size) : btf(NULL), state(NODATA)
{
  init(data, size);
}

static unsigned char *get_data(const char *file, ssize_t *sizep)
{
  ssize_t ret;
  int fd;

  fd = open(file, O_RDONLY);
  if (fd < 0)
    return NULL;

  struct stat st;

  if (fstat(fd, &st))
  {
    close(fd);
    return NULL;
  }

  unsigned char *data;
  unsigned int size;

  size = st.st_size;

  data = (unsigned char *) malloc(size);
  if (!data)
  {
    close(fd);
    return NULL;
  }

  ret = read(fd, data, size);
  if (ret <= 0)
  {
    close(fd);
    free(data);
    return NULL;
  }

  close(fd);

  *sizep = size;
  return data;
}

BTF::BTF(void) : btf(NULL), state(NODATA)
{
  struct stat st;
  unsigned char *data;
  ssize_t size;
  const char *path_env;
  char *path;

  // Try to get BTF file from BPFTRACE_BTF env,
  // if not present, try /lib/modules/`uname -r`/btf path
  path_env = std::getenv("BPFTRACE_BTF");
  if (path_env)
  {
    path = strdup(path_env);
  }
  else
  {
    struct utsname uts;

    if (uname(&uts))
    {
      std::cerr << "BTF: failed to get uname" << std::endl;
      return;
    }

    asprintf(&path, "/lib/modules/%s/btf", uts.release);
  }

  if (!path)
  {
      std::cerr << "BTF: failed to get BTF path" << std::endl;
      return;
  }

  if (stat(path, &st))
  {
    if (bt_verbose && path_env)
      std::cerr << "BTF: wrong data path: " << path << std::endl;
    return;
  }

  data = get_data(path, &size);
  if (!data)
  {
    std::cerr << "BTF: failed to read data: " << path << std::endl;
    free(path);
    return;
  }

  init(data, size);

  free(path);
  free(data);
}

static std::string fix_name(std::string& name, __u32 id)
{
  if (name.empty())
    return "type_" + std::to_string(id);

  return name;
}

int BTF::resolve_field(__u32 type_id, Field& field, std::map<std::string, Struct> &structs)
{
  const struct btf_type *ptr_type, *type = btf__type_by_id(btf, type_id);
  std::string name;
  int actual_type_id;

  __s64 size = btf__resolve_size(btf, type_id);

  switch (BTF_INFO_KIND(type->info))
  {
  case BTF_KIND_INT:
  case BTF_KIND_ENUM:
    field.type = SizedType(Type::integer, size);
    break;
  case BTF_KIND_PTR:
    ptr_type = btf__type_by_id(btf, type->type);
    name = btf__name_by_offset(btf, ptr_type->name_off);
    name = fix_name(name, type->type);

    resolve_struct_id(type->type, name, structs);

    field.type = SizedType(Type::cast, size);
    field.type.is_pointer = true;
    field.type.cast_type = name;
    field.type.pointee_size = structs[name].size;
    break;
  case BTF_KIND_ARRAY:
    field.type = SizedType(Type::string, size);
    break;
  case BTF_KIND_UNION:
  case BTF_KIND_STRUCT:
    name = btf__name_by_offset(btf, type->name_off);
    name = fix_name(name, type_id);

    resolve_struct_id(type_id, name, structs);

    field.type = SizedType(Type::cast, size);
    field.type.cast_type = name;
    break;
  case BTF_KIND_VOLATILE:
  case BTF_KIND_CONST:
  case BTF_KIND_RESTRICT:
  case BTF_KIND_TYPEDEF:
    actual_type_id = btf__resolve_type(btf, type_id);
    if (actual_type_id < 0)
      return -1;

    if (resolve_field(actual_type_id, field, structs))
      return -1;
    break;
  case BTF_KIND_UNKN:
  case BTF_KIND_FWD:
    return -1;
  default:
    break;
  }

  return 0;
}

static __u32 member_bit_offset(const struct btf_type *struct_type,
                               const struct btf_member *member)
{
  return BTF_INFO_KFLAG(struct_type->info) ?
         BTF_MEMBER_BIT_OFFSET(member->offset) : member->offset;
}

void BTF::resolve_struct_id(__u32 type_id, std::string name, std::map<std::string, Struct> &structs,
                            bool new_struct)
{
  const struct btf_type *type = btf__type_by_id(btf, type_id);

  if ((BTF_INFO_KIND(type->info) != BTF_KIND_STRUCT) &&
      (BTF_INFO_KIND(type->info) != BTF_KIND_UNION))
    return;

  if (new_struct && structs.count(name))
    return;

  if (new_struct)
    structs[name].size = type->size;

  const struct btf_member *m = reinterpret_cast<const struct btf_member*>(type + 1);

  for (unsigned int i = 0; i < BTF_INFO_VLEN(type->info); i++)
  {
    std::string m_name = btf__name_by_offset(btf, m[i].name_off);

    /* add annonymous struct/unions to the parent */
    if (m_name.empty()) {
      resolve_struct_id(m[i].type, name, structs, false);
      continue;
    }

    Field& field = structs[name].fields[m_name];
    field.offset = member_bit_offset(type, &m[i]) / 8;

    if (resolve_field(m[i].type, field, structs))
      break;
  }
}

void BTF::resolve_struct(std::string name, std::map<std::string, Struct> &structs)
{
  __s32 type_id;

  if (!btf || name.empty() || structs.count(name))
    return;

  type_id = btf__find_by_name(btf, name.c_str());
  if (type_id < 0)
    return;

  resolve_struct_id(type_id, name, structs);
}

BTF::~BTF()
{
  btf__free(btf);
}

} // namespace bpftrace

#else // HAVE_LIBBPF

// TODO(jolsa) - add this to act_helpers.h and use it globaly
#define __maybe_unused __attribute__((__unused__))

namespace bpftrace {

BTF::BTF() { }

BTF::BTF(unsigned char *data __maybe_unused, unsigned int size __maybe_unused) { }

void BTF::resolve_struct(std::string name __maybe_unused,
                         std::map<std::string, Struct> &structs __maybe_unused) { }

BTF::~BTF() { }

} // namespace bpftrace

#endif // HAVE_LIBBPF
