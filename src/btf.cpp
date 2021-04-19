#include "btf.h"
#include "arch/arch.h"
#include "bpftrace.h"
#include "log.h"
#include "probe_matcher.h"
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

#include "bpftrace.h"

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
    LOG(ERROR) << "BTF: failed to read data from: " << file;
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
      if (bt_debug != DebugLevel::kNone)
      {
        char err_buf[256];

        libbpf_strerror(libbpf_get_error(btf), err_buf, sizeof(err_buf));
        LOG(ERROR) << "BTF: failed to read data (" << err_buf
                   << ") from: " << path;
      }
      continue;
    }

    if (bt_debug != DebugLevel::kNone)
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
    LOG(ERROR) << "BTF: failed to find BTF data ";
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

  if (BTF_INFO_KIND(type->info) == BTF_KIND_ENUM)
    return std::string("enum ") + str;

  return str;
}

static std::string btf_type_str(const std::string& type)
{
  return std::regex_replace(type, std::regex("^(struct )|(union )"), "");
}

std::string BTF::c_def(const std::unordered_set<std::string> &set) const
{
  if (!has_data())
    return std::string("");

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
      LOG(ERROR) << "BTF: failed to initialize dump (" << err_buf << ")";
      return std::string("");
  }

  std::unordered_set<std::string> myset(set);
  __s32 id, max = (__s32) btf__get_nr_types(btf);

  for (id = 1; id <= max && myset.size(); id++)
  {
    const struct btf_type *t = btf__type_by_id(btf, id);
    // Allow users to reference enum values by name to pull in entire enum defs
    if (btf_is_enum(t))
    {
      const struct btf_enum *p = btf_enum(t);
      uint16_t vlen = btf_vlen(t);
      for (int e = 0; e < vlen; ++e, ++p)
      {
        std::string str = btf_str(btf, p->name_off);
        auto it = myset.find(str);
        if (it != myset.end())
        {
          btf_dump__dump_type(dump, id);
          myset.erase(it);
          break;
        }
      }
    }

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
  if (!has_data())
    return std::string("");

  __s32 type_id = btf__find_by_name(btf, btf_type_str(name).c_str());

  if (type_id < 0)
    return std::string("");

  const struct btf_type *type = btf__type_by_id(btf, type_id);
  return type_of(type, field);
}

std::string BTF::type_of(const btf_type *type, const std::string &field)
{
  if (!has_data())
    return std::string("");

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

static bool btf_type_is_modifier(const struct btf_type *t)
{
  // Some of them is not strictly a C modifier
  // but they are grouped into the same bucket
  // for BTF concern:
  // A type (t) that refers to another
  // type through t->type AND its size cannot
  // be determined without following the t->type.
  // ptr does not fall into this bucket
  // because its size is always sizeof(void *).

  switch (BTF_INFO_KIND(t->info))
  {
    case BTF_KIND_TYPEDEF:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_CONST:
    case BTF_KIND_RESTRICT:
      return true;
    default:
      return false;
  }
}

const struct btf_type *BTF::btf_type_skip_modifiers(const struct btf_type *t)
{
  while (btf_type_is_modifier(t))
  {
    t = btf__type_by_id(btf, t->type);
  }

  return t;
}

SizedType BTF::get_stype(__u32 id)
{
  const struct btf_type *t = btf__type_by_id(btf, id);

  if (!t)
    return CreateNone();

  t = btf_type_skip_modifiers(t);

  auto stype = CreateNone();

  if (btf_is_int(t) || btf_is_enum(t))
  {
    stype = CreateInteger(btf_int_bits(t),
                          btf_int_encoding(t) & BTF_INT_SIGNED);
  }
  else if (btf_is_composite(t))
  {
    const char *cast = btf_str(btf, t->name_off);
    assert(cast);
    std::string comp = btf_is_struct(t) ? "struct" : "union";
    std::string name = comp + " " + cast;
    // We're usually resolving types before running ClangParser, so the struct
    // definitions are not yet pulled into the struct map. We initialize them
    // now and fill them later.
    stype = CreateRecord(name, bpftrace_->structs.LookupOrAdd(name, t->size));
  }
  else if (btf_is_ptr(t))
  {
    // t->type is the pointee type
    stype = CreatePointer(get_stype(t->type));
  }

  return stype;
}

int BTF::resolve_args(const std::string &func,
                      std::map<std::string, SizedType> &args,
                      bool ret)
{
  if (!has_data())
    throw std::runtime_error("BTF data not available");

  __s32 id, max = (__s32)btf__get_nr_types(btf);
  std::string name = func;

  for (id = 1; id <= max; id++)
  {
    const struct btf_type *t = btf__type_by_id(btf, id);

    if (!btf_is_func(t))
      continue;

    const char *str = btf_str(btf, t->name_off);

    if (name != str)
      continue;

    t = btf__type_by_id(btf, t->type);
    if (!btf_is_func_proto(t))
    {
      throw std::runtime_error("not a function");
    }

    if (bpftrace_ && !bpftrace_->is_traceable_func(name))
    {
      if (bpftrace_->traceable_funcs_.empty())
        throw std::runtime_error("could not read traceable functions from " +
                                 kprobe_path + " (is debugfs mounted?)");
      else
        throw std::runtime_error("function not traceable (probably it is "
                                 "inlined or marked as \"notrace\")");
    }

    const struct btf_param *p = btf_params(t);
    __u16 vlen = btf_vlen(t);
    if (vlen > arch::max_arg() + 1)
    {
      throw std::runtime_error("functions with more than 6 parameters are "
                               "not supported.");
    }

    int j = 0;

    for (; j < vlen; j++, p++)
    {
      str = btf_str(btf, p->name_off);
      if (!str)
      {
        throw std::runtime_error("failed to resolve arguments");
      }

      SizedType stype = get_stype(p->type);
      stype.kfarg_idx = j;
      stype.is_kfarg = true;
      args.insert({ str, stype });
    }

    if (ret)
    {
      SizedType stype = get_stype(t->type);
      stype.kfarg_idx = j;
      stype.is_kfarg = true;
      args.insert({ "$retval", stype });
    }

    return 0;
  }

  throw std::runtime_error("no BTF data for the function");
}

std::unique_ptr<std::istream> BTF::get_all_funcs() const
{
  __s32 id, max = (__s32)btf__get_nr_types(btf);
  std::string type = std::string("");
  struct btf_dump_opts opts = {
    .ctx = &type,
  };
  struct btf_dump *dump;
  std::string funcs;
  char err_buf[256];
  int err;

  dump = btf_dump__new(btf, nullptr, &opts, dump_printf);
  err = libbpf_get_error(dump);
  if (err)
  {
    libbpf_strerror(err, err_buf, sizeof(err_buf));
    LOG(ERROR) << "BTF: failed to initialize dump (" << err_buf << ")";
    return nullptr;
  }

  for (id = 1; id <= max; id++)
  {
    const struct btf_type *t = btf__type_by_id(btf, id);

    if (!btf_is_func(t))
      continue;

    const char *str = btf__name_by_offset(btf, t->name_off);
    std::string func_name = str;

    t = btf__type_by_id(btf, t->type);
    if (!btf_is_func_proto(t))
    {
      /* bad.. */
      if (!bt_verbose)
        LOG(ERROR) << func_name << " function does not have FUNC_PROTO record";
      break;
    }

    if (bpftrace_ && !bpftrace_->is_traceable_func(func_name))
      continue;

    if (btf_vlen(t) > arch::max_arg() + 1)
      continue;

    funcs += std::string(func_name) + "\n";
  }

  if (id != (max + 1))
    LOG(ERROR) << "BTF data inconsistency " << id << "," << max;

  btf_dump__free(dump);

  return std::make_unique<std::istringstream>(funcs);
}

std::map<std::string, std::vector<std::string>> BTF::get_params(
    const std::set<std::string> &funcs) const
{
#ifdef HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL
  __s32 id, max = (__s32)btf__get_nr_types(btf);
  std::string type = std::string("");
  struct btf_dump_opts opts = {
    .ctx = &type,
  };
  struct btf_dump *dump;
  char err_buf[256];
  int err;

  dump = btf_dump__new(btf, nullptr, &opts, dump_printf);
  err = libbpf_get_error(dump);
  if (err)
  {
    libbpf_strerror(err, err_buf, sizeof(err_buf));
    LOG(ERROR) << "BTF: failed to initialize dump (" << err_buf << ")";
    return {};
  }

  std::map<std::string, std::vector<std::string>> params;
  for (id = 1; id <= max; id++)
  {
    const struct btf_type *t = btf__type_by_id(btf, id);

    if (!btf_is_func(t))
      continue;

    const char *str = btf__name_by_offset(btf, t->name_off);
    std::string func_name = str;

    if (funcs.find(func_name) == funcs.end())
      continue;

    t = btf__type_by_id(btf, t->type);

    _Pragma("GCC diagnostic push")
        _Pragma("GCC diagnostic ignored \"-Wmissing-field-initializers\"")

            DECLARE_LIBBPF_OPTS(btf_dump_emit_type_decl_opts,
                                decl_opts,
                                .field_name = "");

    _Pragma("GCC diagnostic pop")

        const struct btf_param *p;
    int j;

    for (j = 0, p = btf_params(t); j < btf_vlen(t); j++, p++)
    {
      // set by dump_printf callback
      type = std::string("");
      const char *arg_name = btf__name_by_offset(btf, p->name_off);

      err = btf_dump__emit_type_decl(dump, p->type, &decl_opts);
      if (err)
      {
        LOG(ERROR) << "failed to dump argument: " << arg_name;
        break;
      }

      params[func_name].push_back(type + " " + arg_name);
    }

    if (!t->type)
      continue;

    // set by dump_printf callback
    type = std::string("");

    err = btf_dump__emit_type_decl(dump, t->type, &decl_opts);
    if (err)
    {
      LOG(ERROR) << "failed to dump return type for: " << func_name;
      break;
    }

    params[func_name].push_back(type + " retval");
  }

  if (id != (max + 1))
    LOG(ERROR) << "BTF data inconsistency " << id << "," << max;

  btf_dump__free(dump);

  return params;
#else
  LOG(ERROR) << "Could not get kfunc arguments "
                "(HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL is not set)" return {};
  return {};
#endif
}

std::set<std::string> BTF::get_all_structs() const
{
  std::set<std::string> struct_set;
  __s32 id, max = (__s32)btf__get_nr_types(btf);
  std::string types = std::string("");
  struct btf_dump_opts opts = {
    .ctx = &types,
  };
  struct btf_dump *dump;
  char err_buf[256];
  int err;

  dump = btf_dump__new(btf, nullptr, &opts, dump_printf);
  err = libbpf_get_error(dump);
  if (err)
  {
    libbpf_strerror(err, err_buf, sizeof(err_buf));
    LOG(ERROR) << "BTF: failed to initialize dump (" << err_buf << ")";
    return {};
  }

  for (id = 1; id <= max; id++)
  {
    const struct btf_type *t = btf__type_by_id(btf, id);

    if (!(btf_is_struct(t) || btf_is_union(t) || btf_is_enum(t)))
      continue;

    const std::string name = full_type_str(btf, t);

    if (name.find("(anon)") != std::string::npos)
      continue;

    if (bt_verbose)
      btf_dump__dump_type(dump, id);
    else
      struct_set.insert(name);
  }

  if (id != (max + 1))
    LOG(ERROR) << " BTF data inconsistency " << id << "," << max;

  btf_dump__free(dump);

  if (bt_verbose)
  {
    // BTF dump contains definitions of all types in a single string, here we
    // split it
    std::istringstream type_stream(types);
    std::string line, type;
    bool in_def = false;
    while (std::getline(type_stream, line))
    {
      if (in_def)
      {
        type += line + "\n";
        if (line == "};")
        {
          // end of type definition
          struct_set.insert(type);
          type.clear();
          in_def = false;
        }
      }
      else if (!line.empty() && line.back() == '{')
      {
        // start of type definition
        type += line + "\n";
        in_def = true;
      }
    }
  }

  return struct_set;
}

} // namespace bpftrace
#else // HAVE_LIBBPF_BTF_DUMP

namespace bpftrace {

BTF::BTF() { }

BTF::~BTF() { }

std::string BTF::c_def(const std::unordered_set<std::string>& set
                       __attribute__((__unused__))) const
{
  return std::string("");
}

std::string BTF::type_of(const std::string& name __attribute__((__unused__)),
                         const std::string& field __attribute__((__unused__))) {
  return std::string("");
}

int BTF::resolve_args(const std::string &func __attribute__((__unused__)),
                      std::map<std::string, SizedType>& args
                      __attribute__((__unused__)),
                      bool ret __attribute__((__unused__)))
{
  return -1;
}

std::set<std::string> BTF::get_all_structs() const
{
  return {};
}

std::unique_ptr<std::istream> BTF::get_all_funcs() const
{
  return nullptr;
}

std::map<std::string, std::vector<std::string>> BTF::get_params(
    const std::set<std::string>& funcs __attribute__((__unused__))) const
{
  return {};
}
} // namespace bpftrace

#endif // HAVE_LIBBPF_BTF_DUMP
