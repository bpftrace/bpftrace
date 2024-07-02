#include "btf.h"
#include "arch/arch.h"
#include "bpftrace.h"
#include "log.h"
#include "probe_matcher.h"
#include "tracefs.h"
#include "types.h"
#include "utils.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/limits.h>
#include <optional>
#include <regex>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/btf.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#include <bpf/btf.h>
#pragma GCC diagnostic pop
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpftrace.h"

namespace bpftrace {

static __u32 type_cnt(const struct btf *btf)
{
  return btf__type_cnt(btf) - 1;
}

__s32 BTF::start_id(const struct btf *btf) const
{
  return btf == vmlinux_btf ? 1 : vmlinux_btf_size + 1;
}

BTF::BTF(const std::set<std::string> &modules) : state(NODATA)
{
  // Try to get BTF file from BPFTRACE_BTF env
  char *path = std::getenv("BPFTRACE_BTF");
  if (path) {
    btf_objects.push_back(
        BTFObj{ .btf = btf__parse_raw(path), .id = 0, .name = "" });
    vmlinux_btf = btf_objects.back().btf;
  } else
    load_kernel_btfs(modules);

  if (btf_objects.empty()) {
    LOG(V1) << "BTF: failed to find BTF data";
    return;
  }

  vmlinux_btf_size = (__s32)type_cnt(vmlinux_btf);

  state = OK;
}

BTF::~BTF()
{
  for (auto &btf_obj : btf_objects)
    btf__free(btf_obj.btf);
}

void BTF::load_kernel_btfs(const std::set<std::string> &modules)
{
  vmlinux_btf = btf__load_vmlinux_btf();
  if (libbpf_get_error(vmlinux_btf)) {
    LOG(V1) << "BTF: failed to find BTF data for vmlinux, errno " << errno;
    return;
  }
  btf_objects.push_back(
      BTFObj{ .btf = vmlinux_btf, .id = 0, .name = "vmlinux" });

  if (bpftrace_ && !bpftrace_->feature_->has_module_btf())
    return;

  // Note that we cannot parse BTFs from /sys/kernel/btf/ as we need BTF object
  // IDs, so the only way is to iterate through all loaded BTF objects
  __u32 id = 0;
  while (true) {
    int err = bpf_btf_get_next_id(id, &id);
    if (err) {
      if (errno != ENOENT)
        LOG(V1) << "BTF: failed to iterate modules BTF objects";
      break;
    }

    // Get BTF object FD
    int fd = bpf_btf_get_fd_by_id(id);
    if (fd < 0) {
      LOG(V1) << "BTF: failed to get FD for object with id " << id;
      continue;
    }

    // Get BTF object info - needed to determine if this is a kernel module BTF
    char name[64];
    struct bpf_btf_info info = {};
    info.name = (__u64)name;
    info.name_len = sizeof(name);

    __u32 info_len = sizeof(info);
    err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
    close(fd); // close the FD not to leave too many files open
    if (err) {
      LOG(V1) << "BTF: failed to get info for object with id " << id;
      continue;
    }

    auto mod_name = std::string(name);
    if (!info.kernel_btf)
      continue;

    if (mod_name == "vmlinux") {
      btf_objects.front().id = id;
    } else if (modules.find(mod_name) != modules.end()) {
      btf_objects.push_back(
          BTFObj{ .btf = btf__load_from_kernel_by_id_split(id, vmlinux_btf),
                  .id = id,
                  .name = mod_name });
    }
  }
}

static void dump_printf(void *ctx, const char *fmt, va_list args)
{
  std::string *ret = static_cast<std::string *>(ctx);
  char *str;

  if (vasprintf(&str, fmt, args) < 0)
    return;

  *ret += str;
  free(str);
}

static struct btf_dump *dump_new(const struct btf *btf,
                                 btf_dump_printf_fn_t dump_printf,
                                 void *ctx)
{
  return btf_dump__new(btf, dump_printf, ctx, nullptr);
}

static const char *btf_str(const struct btf *btf, __u32 off)
{
  if (!off)
    return "(anon)";

  return btf__name_by_offset(btf, off) ?: "(invalid)";
}

static std::string full_type_str(const struct btf *btf,
                                 const struct btf_type *type)
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

static std::string btf_type_str(const std::string &type)
{
  return std::regex_replace(type, std::regex("^(struct )|(union )"), "");
}

std::string BTF::dump_defs_from_btf(
    const struct btf *btf,
    std::unordered_set<std::string> &types) const
{
  std::string ret = std::string("");
  struct btf_dump *dump;
  char err_buf[256];
  int err;

  dump = dump_new(btf, dump_printf, &ret);
  err = libbpf_get_error(dump);
  if (err) {
    libbpf_strerror(err, err_buf, sizeof(err_buf));
    LOG(ERROR) << "BTF: failed to initialize dump (" << err_buf << ")";
    return std::string("");
  }

  __s32 id, max = (__s32)type_cnt(btf);

  // note that we're always iterating from 1 here as we need to go through the
  // vmlinux BTF entries, too (even for kernel module BTFs)
  for (id = 1; id <= max && !types.empty(); id++) {
    const struct btf_type *t = btf__type_by_id(btf, id);
    if (!t)
      continue;

    // Allow users to reference enum values by name to pull in entire enum defs
    if (btf_is_enum(t)) {
      const struct btf_enum *p = btf_enum(t);
      uint16_t vlen = btf_vlen(t);
      for (int e = 0; e < vlen; ++e, ++p) {
        std::string str = btf_str(btf, p->name_off);
        auto it = types.find(str);
        if (it != types.end()) {
          btf_dump__dump_type(dump, id);
          types.erase(it);
          break;
        }
      }
    }

    std::string str = full_type_str(btf, t);

    auto it = types.find(str);
    if (it != types.end()) {
      btf_dump__dump_type(dump, id);
      types.erase(it);
    }
  }

  btf_dump__free(dump);
  return ret;
}

std::string BTF::c_def(const std::unordered_set<std::string> &set) const
{
  if (!has_data())
    return std::string("");

  // Definition dumping from multiple modules would require to resolve type
  // conflicts, so we allow dumping from a single module or from vmlinux only.
  std::unordered_set<std::string> to_dump(set);
  if (btf_objects.size() == 2) {
    auto *mod_btf = btf_objects[0].btf == vmlinux_btf ? btf_objects[1].btf
                                                      : btf_objects[0].btf;
    return dump_defs_from_btf(mod_btf, to_dump);
  }

  return dump_defs_from_btf(vmlinux_btf, to_dump);
}

std::string BTF::type_of(const std::string &name, const std::string &field)
{
  if (!has_data())
    return std::string("");

  auto btf_name = btf_type_str(name);

  auto type_id = find_id(btf_name);
  if (!type_id.btf)
    return std::string("");

  return type_of(type_id, field);
}

std::string BTF::type_of(const BTFId &type_id, const std::string &field)
{
  if (!has_data())
    return std::string("");

  const struct btf_type *type = btf__type_by_id(type_id.btf, type_id.id);

  if (!type || (BTF_INFO_KIND(type->info) != BTF_KIND_STRUCT &&
                BTF_INFO_KIND(type->info) != BTF_KIND_UNION))
    return std::string("");

  // We need to walk through oaa the struct/union members
  // and try to find the requested field name.
  //
  // More info on struct/union members:
  //  https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-union
  const struct btf_member *m = btf_members(type);

  for (unsigned int i = 0; i < BTF_INFO_VLEN(type->info); i++) {
    std::string m_name = btf__name_by_offset(type_id.btf, m[i].name_off);

    // anonymous struct/union
    if (m_name == "") {
      std::string type_name = type_of(
          BTFId{ .btf = type_id.btf, .id = m[i].type }, field);
      if (!type_name.empty())
        return type_name;
    }

    if (m_name != field)
      continue;

    const struct btf_type *f = btf__type_by_id(type_id.btf, m[i].type);

    if (!f)
      break;

    // Get rid of all the pointers and qualifiers on the way to the actual type.
    while (BTF_INFO_KIND(f->info) == BTF_KIND_PTR ||
           BTF_INFO_KIND(f->info) == BTF_KIND_CONST ||
           BTF_INFO_KIND(f->info) == BTF_KIND_VOLATILE ||
           BTF_INFO_KIND(f->info) == BTF_KIND_RESTRICT) {
      f = btf__type_by_id(type_id.btf, f->type);
      if (!f)
        return std::string("");
    }

    return full_type_str(type_id.btf, f);
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

  switch (BTF_INFO_KIND(t->info)) {
    case BTF_KIND_TYPEDEF:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_CONST:
    case BTF_KIND_RESTRICT:
      return true;
    default:
      return false;
  }
}

const struct btf_type *BTF::btf_type_skip_modifiers(const struct btf_type *t,
                                                    const struct btf *btf)
{
  while (t && btf_type_is_modifier(t)) {
    t = btf__type_by_id(btf, t->type);
  }

  return t;
}

__u32 BTF::get_type_tags(std::unordered_set<std::string> &tags,
                         const BTFId &btf_id) const
{
  __u32 id = btf_id.id;
  const struct btf_type *t = btf__type_by_id(btf_id.btf, btf_id.id);

  while (t && btf_is_type_tag(t)) {
    tags.insert(btf_str(btf_id.btf, t->name_off));
    id = t->type;
    t = btf__type_by_id(btf_id.btf, t->type);
  }

  return id;
}

SizedType BTF::get_stype(const BTFId &btf_id, bool resolve_structs)
{
  const struct btf_type *t = btf__type_by_id(btf_id.btf, btf_id.id);

  if (!t)
    return CreateNone();

  t = btf_type_skip_modifiers(t, btf_id.btf);

  auto stype = CreateNone();

  if (btf_is_int(t)) {
    stype = CreateInteger(btf_int_bits(t),
                          btf_int_encoding(t) & BTF_INT_SIGNED);
  } else if (btf_is_enum(t)) {
    stype = CreateInteger(t->size * 8, false);
  } else if (btf_is_composite(t)) {
    std::string cast = btf_str(btf_id.btf, t->name_off);
    if (cast.empty() || cast == "(anon)")
      return CreateNone();
    std::string comp = btf_is_struct(t) ? "struct" : "union";
    std::string name = comp + " " + cast;

    stype = CreateRecord(name, bpftrace_->structs.LookupOrAdd(name, t->size));
    if (resolve_structs)
      resolve_fields(stype);
  } else if (btf_is_ptr(t)) {
    const BTFId pointee_btf_id = { .btf = btf_id.btf, .id = t->type };
    std::unordered_set<std::string> tags;
    auto id = get_type_tags(tags, pointee_btf_id);
    stype = CreatePointer(
        get_stype(BTFId{ .btf = btf_id.btf, .id = id }, false));
    stype.SetBtfTypeTags(std::move(tags));
  } else if (btf_is_array(t)) {
    auto *array = btf_array(t);
    const auto &elem_type = get_stype(
        BTFId{ .btf = btf_id.btf, .id = array->type });
    if (elem_type.IsIntTy() && elem_type.GetSize() == 1) {
      stype = CreateString(array->nelems);
    } else {
      stype = CreateArray(array->nelems, elem_type);
    }
  }

  return stype;
}

std::optional<Struct> BTF::resolve_args(const std::string &func,
                                        bool ret,
                                        std::string &err)
{
  if (!has_data()) {
    err = "BTF data not available";
    return std::nullopt;
  }

  auto func_id = find_id(func, BTF_KIND_FUNC);
  if (!func_id.btf) {
    err = "no BTF data for " + func;
    return std::nullopt;
  }

  const struct btf_type *t = btf__type_by_id(func_id.btf, func_id.id);
  t = btf__type_by_id(func_id.btf, t->type);
  if (!t || !btf_is_func_proto(t)) {
    err = func + " is not a function";
    return std::nullopt;
  }

  if (bpftrace_ && !bpftrace_->is_traceable_func(func)) {
    if (bpftrace_->get_traceable_funcs().empty()) {
      err = "could not read traceable functions from " +
            tracefs::available_filter_functions() + " (is tracefs mounted?)";
    } else {
      err = "function not traceable (probably it is "
            "inlined or marked as \"notrace\")";
    }
    return std::nullopt;
  }

  const struct btf_param *p = btf_params(t);
  __u16 vlen = btf_vlen(t);
  if (vlen > arch::max_arg() + 1) {
    err = "functions with more than 6 parameters are "
          "not supported.";
    return std::nullopt;
  }

  Struct args(0, false);
  int j = 0;
  int arg_idx = 0;
  __u32 type_size = 0;
  for (; j < vlen; j++, p++) {
    const char *str = btf_str(func_id.btf, p->name_off);
    if (!str) {
      err = "failed to resolve arguments";
      return std::nullopt;
    }

    SizedType stype = get_stype(BTFId{ .btf = func_id.btf, .id = p->type });
    stype.funcarg_idx = arg_idx;
    stype.is_funcarg = true;
    args.AddField(str, stype, args.size, std::nullopt, false);
    // kfunc (fentry/fexit) args are stored in a u64 array.
    // Note that it's ok to represent them by a struct as we will use GEP with
    // funcarg_idx to access them in codegen.
    type_size = btf__resolve_size(func_id.btf, p->type);
    args.size += type_size;
    arg_idx += std::ceil((float)type_size / (float)8);
  }

  if (ret) {
    SizedType stype = get_stype(BTFId{ .btf = func_id.btf, .id = t->type });
    stype.funcarg_idx = arg_idx;
    stype.is_funcarg = true;
    args.AddField("$retval", stype, args.size, std::nullopt, false);
    // kfunc (fentry/fexit) args (incl. retval) are stored in a u64 array
    args.size += btf__resolve_size(func_id.btf, t->type);
  }
  return args;
}

std::string BTF::get_all_funcs_from_btf(const BTFObj &btf_obj) const
{
  std::string funcs;
  __s32 id, max = (__s32)type_cnt(btf_obj.btf);

  for (id = start_id(btf_obj.btf); id <= max; id++) {
    const struct btf_type *t = btf__type_by_id(btf_obj.btf, id);

    if (!t)
      continue;

    if (!btf_is_func(t))
      continue;

    const char *str = btf__name_by_offset(btf_obj.btf, t->name_off);
    std::string func_name = str;

    t = btf__type_by_id(btf_obj.btf, t->type);
    if (!t || !btf_is_func_proto(t)) {
      /* bad.. */
      LOG(ERROR) << func_name << " function does not have FUNC_PROTO record";
      break;
    }

    if (bpftrace_ && !bpftrace_->is_traceable_func(func_name))
      continue;

    if (btf_vlen(t) > arch::max_arg() + 1)
      continue;

    funcs += btf_obj.name + ":" + std::string(func_name) + "\n";
  }

  return funcs;
}

std::unique_ptr<std::istream> BTF::get_all_funcs() const
{
  auto funcs = std::make_unique<std::stringstream>();
  for (auto &btf_obj : btf_objects)
    *funcs << get_all_funcs_from_btf(btf_obj);
  return funcs;
}

std::map<std::string, std::vector<std::string>> BTF::get_params_from_btf(
    const BTFObj &btf_obj,
    const std::set<std::string> &funcs) const
{
  __s32 id, max = (__s32)type_cnt(btf_obj.btf);
  std::string type = std::string("");
  struct btf_dump *dump;
  char err_buf[256];
  int err;

  dump = dump_new(btf_obj.btf, dump_printf, &type);
  err = libbpf_get_error(dump);
  if (err) {
    libbpf_strerror(err, err_buf, sizeof(err_buf));
    LOG(ERROR) << "BTF: failed to initialize dump (" << err_buf << ")";
    return {};
  }

  std::map<std::string, std::vector<std::string>> params;
  for (id = start_id(btf_obj.btf); id <= max; id++) {
    const struct btf_type *t = btf__type_by_id(btf_obj.btf, id);

    if (!t)
      continue;

    if (!btf_is_func(t))
      continue;

    const char *str = btf__name_by_offset(btf_obj.btf, t->name_off);
    std::string func_name = btf_obj.name + ":" + str;

    if (funcs.find(func_name) == funcs.end())
      continue;

    t = btf__type_by_id(btf_obj.btf, t->type);
    if (!t)
      continue;

    BPFTRACE_LIBBPF_OPTS(btf_dump_emit_type_decl_opts,
                         decl_opts,
                         .field_name = "");

    const struct btf_param *p;
    int j;

    for (j = 0, p = btf_params(t); j < btf_vlen(t); j++, p++) {
      // set by dump_printf callback
      type = std::string("");
      const char *arg_name = btf__name_by_offset(btf_obj.btf, p->name_off);

      err = btf_dump__emit_type_decl(dump, p->type, &decl_opts);
      if (err) {
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
    if (err) {
      LOG(ERROR) << "failed to dump return type for: " << func_name;
      break;
    }

    params[func_name].push_back(type + " retval");
  }

  if (id != (max + 1))
    LOG(ERROR) << "BTF data inconsistency " << id << "," << max;

  btf_dump__free(dump);

  return params;
}

std::map<std::string, std::vector<std::string>> BTF::get_params(
    const std::set<std::string> &funcs) const
{
  std::map<std::string, std::vector<std::string>> params;
  auto all_resolved = [&params](const std::string &f) {
    return params.find(f) != params.end();
  };

  for (auto &btf_obj : btf_objects) {
    if (std::all_of(funcs.begin(), funcs.end(), all_resolved))
      break;

    auto mod_params = get_params_from_btf(btf_obj, funcs);
    params.insert(mod_params.begin(), mod_params.end());
  }

  return params;
}

std::set<std::string> BTF::get_all_structs_from_btf(const struct btf *btf) const
{
  std::set<std::string> struct_set;
  __s32 id, max = (__s32)type_cnt(btf);
  std::string types = std::string("");
  struct btf_dump *dump;
  char err_buf[256];
  int err;

  dump = dump_new(btf, dump_printf, &types);
  err = libbpf_get_error(dump);
  if (err) {
    libbpf_strerror(err, err_buf, sizeof(err_buf));
    LOG(ERROR) << "BTF: failed to initialize dump (" << err_buf << ")";
    return {};
  }

  for (id = start_id(btf); id <= max; id++) {
    const struct btf_type *t = btf__type_by_id(btf, id);

    if (!t || !(btf_is_struct(t) || btf_is_union(t) || btf_is_enum(t)))
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

  if (bt_verbose) {
    // BTF dump contains definitions of all types in a single string, here we
    // split it
    std::istringstream type_stream(types);
    std::string line, type;
    bool in_def = false;
    while (std::getline(type_stream, line)) {
      if (in_def) {
        type += line + "\n";
        if (line == "};") {
          // end of type definition
          struct_set.insert(type);
          type.clear();
          in_def = false;
        }
      } else if (!line.empty() && line.back() == '{') {
        // start of type definition
        type += line + "\n";
        in_def = true;
      }
    }
  }

  return struct_set;
}

std::set<std::string> BTF::get_all_structs() const
{
  std::set<std::string> structs;
  for (auto &btf_obj : btf_objects) {
    auto mod_structs = get_all_structs_from_btf(btf_obj.btf);
    structs.insert(mod_structs.begin(), mod_structs.end());
  }
  return structs;
}

std::unordered_set<std::string> BTF::get_all_iters_from_btf(
    const struct btf *btf) const
{
  std::unordered_set<std::string> iter_set;
  const std::string prefix = "bpf_iter__";
  // kernel commit 6fcd486b3a0a("bpf: Refactor RCU enforcement in the
  // verifier.") add 'struct bpf_iter__task__safe_trusted'
  const std::string suffix___safe_trusted = "__safe_trusted";
  __s32 id, max = (__s32)type_cnt(btf);
  for (id = start_id(btf); id <= max; id++) {
    const struct btf_type *t = btf__type_by_id(btf, id);

    if (!t || !(btf_is_struct(t)))
      continue;

    const std::string name = btf_str(btf, t->name_off);

    // skip __safe_trusted suffix struct
    if (suffix___safe_trusted.length() < name.length() &&
        name.rfind(suffix___safe_trusted) ==
            (name.length() - suffix___safe_trusted.length()))
      continue;
    if (name.size() > prefix.size() &&
        name.compare(0, prefix.size(), prefix) == 0) {
      iter_set.insert(name.substr(prefix.size()));
    }
  }
  return iter_set;
}

std::unordered_set<std::string> BTF::get_all_iters() const
{
  std::unordered_set<std::string> iters;
  for (auto &btf_obj : btf_objects) {
    auto mod_iters = get_all_iters_from_btf(btf_obj.btf);
    iters.insert(mod_iters.begin(), mod_iters.end());
  }
  return iters;
}

int BTF::get_btf_id(std::string_view func, std::string_view mod) const
{
  for (auto &btf_obj : btf_objects) {
    if (!mod.empty() && mod != btf_obj.name)
      continue;

    auto id = find_id_in_btf(btf_obj.btf, func, BTF_KIND_FUNC);
    if (id >= 0)
      return id;
  }

  return -1;
}

BTF::BTFId BTF::find_id(const std::string &name,
                        std::optional<__u32> kind) const
{
  for (auto &btf_obj : btf_objects) {
    __s32 id = kind ? btf__find_by_name_kind(btf_obj.btf, name.c_str(), *kind)
                    : btf__find_by_name(btf_obj.btf, name.c_str());
    if (id >= 0)
      return { btf_obj.btf, (__u32)id };
  }

  return { nullptr, 0 };
}

__s32 BTF::find_id_in_btf(struct btf *btf,
                          std::string_view name,
                          std::optional<__u32> kind) const
{
  for (__s32 id = start_id(btf), max = (__s32)type_cnt(btf); id <= max; ++id) {
    const struct btf_type *t = btf__type_by_id(btf, id);
    if (!t)
      continue;
    if (kind && btf_kind(t) != *kind)
      continue;

    std::string type_name = btf__name_by_offset(btf, t->name_off);
    if (type_name == name)
      return id;
  }
  return -1;
}

void BTF::resolve_fields(SizedType &type)
{
  if (!type.IsRecordTy())
    return;

  auto record = bpftrace_->structs.Lookup(type.GetName()).lock();
  if (record->HasFields())
    return;

  auto type_name = btf_type_str(type.GetName());
  auto type_id = find_id(type_name, BTF_KIND_STRUCT);
  if (!type_id.btf)
    type_id = find_id(type_name, BTF_KIND_UNION);
  if (!type_id.btf)
    return;

  resolve_fields(type_id, record.get(), 0);
}

static std::optional<Bitfield> resolve_bitfield(
    const struct btf_type *record_type,
    __u32 member_idx)
{
  __u32 bitfield_width = btf_member_bitfield_size(record_type, member_idx);
  if (bitfield_width <= 0)
    return std::nullopt;

  return Bitfield(btf_member_bit_offset(record_type, member_idx) % 8,
                  bitfield_width);
}

void BTF::resolve_fields(const BTFId &type_id,
                         Struct *record,
                         __u32 start_offset)
{
  auto btf_type = btf__type_by_id(type_id.btf, type_id.id);
  if (!btf_type)
    return;
  auto members = btf_members(btf_type);
  for (__u32 i = 0; i < BTF_INFO_VLEN(btf_type->info); i++) {
    BTFId field_id{ .btf = type_id.btf, .id = members[i].type };
    auto field_type = btf__type_by_id(field_id.btf, field_id.id);
    if (!field_type) {
      LOG(ERROR) << "Inconsistent BTF data (no type found for id "
                 << members[i].type << ")";
      record->ClearFields();
      break;
    }

    std::string field_name = btf__name_by_offset(type_id.btf,
                                                 members[i].name_off);

    __u32 field_offset = start_offset + btf_member_bit_offset(btf_type, i) / 8;

    if (btf_is_composite(field_type) &&
        (field_name.empty() || field_name == "(anon)")) {
      resolve_fields(field_id, record, field_offset);
      continue;
    }

    record->AddField(field_name,
                     get_stype(field_id),
                     field_offset,
                     resolve_bitfield(btf_type, i),
                     false);
  }
}

SizedType BTF::get_stype(const std::string &type_name)
{
  auto btf_name = btf_type_str(type_name);
  auto type_id = find_id(btf_name);
  if (type_id.btf)
    return get_stype(type_id);

  return CreateNone();
}

} // namespace bpftrace
