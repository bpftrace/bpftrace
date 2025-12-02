#include "scopeguard.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/limits.h>
#include <optional>
#include <regex>
#include <sstream>
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

#include "arch/arch.h"
#include "ast/context.h"
#include "ast/pass_manager.h"
#include "ast/passes/args_resolver.h"
#include "bpftrace.h"
#include "btf.h"
#include "log.h"
#include "tracefs/tracefs.h"
#include "types.h"
#include "util/strings.h"

using namespace std::literals::string_view_literals;

namespace bpftrace {

static __u32 type_cnt(const struct btf *btf)
{
  const auto count = btf__type_cnt(btf);
  return count ? count - 1 : 0;
}

__u32 BTF::start_id(const struct btf *btf) const
{
  return btf == vmlinux_btf ? 1 : vmlinux_btf_size + 1;
}

BTF::BTF() : BTF(nullptr)
{
}

BTF::BTF(BPFtrace *bpftrace) : bpftrace_(bpftrace)
{
}

BTF::~BTF()
{
  for (auto &btf_obj : btf_objects)
    btf__free(btf_obj.btf);
}

void BTF::load_vmlinux_btf()
{
  if (state != INIT) {
    // Don't attempt to reload vmlinux even if it fails below
    return;
  }
  state = ERROR;
  // Try to get BTF file from BPFTRACE_BTF env
  char *path = std::getenv("BPFTRACE_BTF");
  if (path) {
    btf_objects.push_back(BTFObj{ .btf = btf__parse_raw(path), .name = "" });
    vmlinux_btf = btf_objects.back().btf;
    if (!vmlinux_btf) {
      LOG(WARNING) << "BTF: failed to parse BTF from " << path;
      return;
    }
  } else {
    vmlinux_btf = btf__load_vmlinux_btf();
    if (libbpf_get_error(vmlinux_btf)) {
      LOG(V1) << "BTF: failed to find BTF data for vmlinux: "
              << strerror(errno);
      return;
    }
    btf_objects.push_back(BTFObj{ .btf = vmlinux_btf, .name = "vmlinux" });
  }

  if (btf_objects.empty()) {
    LOG(V1) << "BTF: failed to find BTF data";
    return;
  }

  vmlinux_btf_size = type_cnt(vmlinux_btf);

  state = VMLINUX_LOADED;
}

bool BTF::has_module_btf()
{
  if (has_module_btf_.has_value())
    return *has_module_btf_;

  char name[64];
  struct bpf_btf_info info = {};
  info.name = reinterpret_cast<uintptr_t>(name);
  info.name_len = sizeof(name);
  __u32 id = 0, info_len = sizeof(info);
  int err = 0, fd = -1;

  err = bpf_btf_get_next_id(id, &id);
  if (err)
    goto not_support;

  fd = bpf_btf_get_fd_by_id(id);
  if (fd < 0)
    goto not_support;

  err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
  close(fd);
  if (err)
    goto not_support;

  has_module_btf_ = true;
  return *has_module_btf_;

not_support:
  has_module_btf_ = false;
  return *has_module_btf_;
}

void BTF::load_module_btfs(const std::set<std::string> &modules)
{
  load_vmlinux_btf();
  if ((bpftrace_ && !has_module_btf()) || state != VMLINUX_LOADED)
    return;

  // Note that we cannot parse BTFs from /sys/kernel/btf/ as we need BTF object
  // IDs, so the only way is to iterate through all loaded BTF objects
  __u32 id = 0;
  while (true) {
    if (bpf_btf_get_next_id(id, &id)) {
      if (errno != ENOENT)
        LOG(V1) << "BTF: failed to iterate modules BTF objects: "
                << strerror(errno);
      break;
    }

    // Get BTF object FD
    int fd = bpf_btf_get_fd_by_id(id);
    if (fd < 0) {
      LOG(V1) << "BTF: failed to get FD for object with id " << id;
      continue;
    }

    // Get BTF object info - needed to determine if this is a kernel module BTF
    char name[64] = {};
    struct bpf_btf_info info = {};
    info.name = reinterpret_cast<uintptr_t>(name);
    info.name_len = sizeof(name);

    uint32_t info_len = sizeof(info);
    auto err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
    close(fd); // close the FD not to leave too many files open
    if (err) {
      LOG(V1) << "BTF: failed to get info for object with id " << id;
      continue;
    }

    if (!info.kernel_btf)
      continue;

    if (modules.contains(name)) {
      btf_objects.push_back(
          BTFObj{ .btf = btf__load_from_kernel_by_id_split(id, vmlinux_btf),
                  .name = name });
    }
  }

  state = VMLINUX_AND_MODULES_LOADED;
}

static void dump_printf(void *ctx, const char *fmt, va_list args)
{
  auto *ret = static_cast<std::stringstream *>(ctx);
  char *str;

  if (vasprintf(&str, fmt, args) < 0)
    return;

  *ret << str;
  free(str);
}

static struct btf_dump *dump_new(const struct btf *btf,
                                 btf_dump_printf_fn_t dump_printf,
                                 std::stringstream *ctx)
{
  return btf_dump__new(btf, dump_printf, static_cast<void *>(ctx), nullptr);
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

static std::string_view btf_type_str(std::string_view type)
{
  if (type.starts_with("struct "))
    return type.substr("struct "sv.length());
  if (type.starts_with("union "))
    return type.substr("union "sv.length());
  if (type.starts_with("enum "))
    return type.substr("enum "sv.length());
  return type;
}

std::string BTF::dump_defs_from_btf(
    const struct btf *btf,
    std::unordered_set<std::string> &types) const
{
  std::stringstream ret;
  auto *dump = dump_new(btf, dump_printf, &ret);
  if (auto err = libbpf_get_error(dump)) {
    char err_buf[256] = {};
    libbpf_strerror(err, err_buf, sizeof(err_buf));
    LOG(ERROR) << "BTF: failed to initialize dump (" << err_buf << ")";
    return {};
  }
  SCOPE_EXIT
  {
    btf_dump__free(dump);
  };

  // note that we're always iterating from 1 here as we need to go through the
  // vmlinux BTF entries, too (even for kernel module BTFs)
  bool all = types.empty();
  __u32 max = type_cnt(btf);
  for (__u32 id = 1; id <= max && (all || !types.empty()); id++) {
    const auto *t = btf__type_by_id(btf, id);
    if (!t)
      continue;

    // Allow users to reference enum values by name to pull in entire enum defs
    if (btf_is_enum(t)) {
      const auto *p = btf_enum(t);
      for (__u16 e = 0, vlen = btf_vlen(t); e < vlen; ++e, ++p) {
        if (all || types.erase(btf_str(btf, p->name_off))) {
          btf_dump__dump_type(dump, id);
          break;
        }
      }
    }

    if (all || types.erase(full_type_str(btf, t))) {
      btf_dump__dump_type(dump, id);
    }
  }

  return ret.str();
}

std::string BTF::c_def(const std::unordered_set<std::string> &set)
{
  if (!has_data())
    return {};

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

std::string BTF::type_of(std::string_view name, std::string_view field)
{
  if (!has_data())
    return {};

  auto btf_name = btf_type_str(name);

  auto type_id = find_id(btf_name);
  if (!type_id.btf)
    return {};

  return type_of(type_id, field);
}

std::string BTF::type_of(const BTFId &type_id, std::string_view field)
{
  if (!has_data())
    return {};

  const struct btf_type *type = btf__type_by_id(type_id.btf, type_id.id);

  if (!type || (BTF_INFO_KIND(type->info) != BTF_KIND_STRUCT &&
                BTF_INFO_KIND(type->info) != BTF_KIND_UNION))
    return {};

  // We need to walk through oaa the struct/union members
  // and try to find the requested field name.
  //
  // More info on struct/union members:
  //  https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-union
  const struct btf_member *m = btf_members(type);

  for (unsigned int i = 0; i < BTF_INFO_VLEN(type->info); i++) {
    std::string m_name = btf__name_by_offset(type_id.btf, m[i].name_off);

    // anonymous struct/union
    if (m_name.empty()) {
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
        return {};
    }

    return full_type_str(type_id.btf, f);
  }

  return {};
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

static bool is_anon_btf_typename(const std::string &name)
{
  return name.empty() || name == "(anon)";
}

BTF::BTFId BTF::parse_anon_btf_name(const std::string &fullname)
{
  unsigned int btf_id;

  // First, find BTF_ANON_STRUCT_PREFIX
  auto prefix_pos = fullname.find(BTF_ANON_STRUCT_PREFIX);
  if (prefix_pos == std::string::npos)
    return BTFId{ .btf = nullptr };

  // After BTF_ANON_STRUCT_PREFIX, should have <id>_<objname>
  auto tail_pos = prefix_pos + BTF_ANON_STRUCT_PREFIX.length();
  auto underscore_pos = fullname.find("_", tail_pos);
  if (underscore_pos == std::string::npos)
    return BTFId{ .btf = nullptr };

  std::string idstr = fullname.substr(tail_pos, underscore_pos - tail_pos);
  std::string btf_obj_name = fullname.substr(underscore_pos + 1);

  try {
    btf_id = std::stoul(idstr);
  } catch (const std::invalid_argument &e) {
    return BTFId{ .btf = nullptr };
  }

  for (const auto &btf_obj : btf_objects) {
    if (btf_obj.name == btf_obj_name) {
      struct btf *btf = btf__type_by_id(btf_obj.btf, btf_id) ? btf_obj.btf
                                                             : nullptr;
      return BTFId{ .btf = btf, .id = btf_id };
    }
  }

  return BTFId{ .btf = nullptr };
}

std::string BTF::create_anon_btf_name(BTFId &btf_id)
{
  for (const auto &btf_obj : btf_objects) {
    if (btf_obj.btf == btf_id.btf) {
      return std::string(BTF_ANON_STRUCT_PREFIX) + std::to_string(btf_id.id) +
             "_" + btf_obj.name;
    }
  }
  return "";
}

SizedType BTF::get_stype(const BTFId &btf_id, bool resolve_structs)
{
  const struct btf_type *t;
  BTFId id;

  id = btf_id;

  while ((t = btf__type_by_id(id.btf, id.id))) {
    if (!btf_type_is_modifier(t))
      break;
    id.id = t->type;
  }

  if (!t)
    return CreateNone();

  auto stype = CreateNone();

  if (btf_is_int(t)) {
    auto encoding = btf_int_encoding(t);
    if (encoding & BTF_INT_BOOL) {
      return CreateBool();
    }
    stype = CreateInteger(btf_int_bits(t), encoding & BTF_INT_SIGNED);
  } else if (btf_is_enum(t)) {
    stype = CreateInteger(t->size * 8, false);
  } else if (btf_is_composite(t)) {
    bool is_anon = false;
    std::string recprefix = btf_is_struct(t) ? "struct " : "union ";
    std::string rname = btf_str(btf_id.btf, t->name_off);

    if (is_anon_btf_typename(rname)) {
      is_anon = true;
      rname = create_anon_btf_name(id);
      if (rname.empty())
        return CreateNone();
    }
    auto name = recprefix + rname;

    auto record = bpftrace_->structs.LookupOrAdd(name, t->size).lock();
    stype = CreateRecord(name, record);
    if (is_anon)
      stype.SetAnon();
    if (resolve_structs)
      resolve_fields(id, std::move(record), 0);
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
    // Auto convert char arrays to strings.
    // This is the least worse option since users have come to expect
    // strings when they call `print`, `printf` or do string literal
    // comparison to this BTF type but note that we don't add 1
    // to the length to ensure it's well formed because
    // string.GetSize() will return len + 1, which is a mismatch with the actual
    // type. So this is making the assumption that the string
    // IS well formed (NULL terminated), which is not guaranteed.
    // A string that is missing the NULL terminator at the end
    // will appear as a truncated string, e.g. `...` as a trailing suffix.
    // If this conversion is incorrect, because it's not an actual string, users
    // have the option to cast all strings to int8 arrays, e.g.
    // `(int8[])"mystring"`.
    if (elem_type.IsIntTy() && elem_type.GetSize() == 1) {
      stype = CreateString(array->nelems);
    } else {
      stype = CreateArray(array->nelems, elem_type);
    }
  }

  return stype;
}

Result<std::shared_ptr<Struct>> BTF::resolve_args(std::string_view func,
                                                  bool ret,
                                                  bool check_traceable,
                                                  bool skip_first_arg)
{
  if (!has_data()) {
    return make_error<ast::ArgParseError>(func, "BTF data not available");
  }

  auto func_id = find_id(func, BTF_KIND_FUNC);
  if (!func_id.btf) {
    return make_error<ast::ArgParseError>(
        func, "BTF data for the function not found");
  }

  const struct btf_type *t = btf__type_by_id(func_id.btf, func_id.id);
  t = btf__type_by_id(func_id.btf, t->type);
  if (!t || !btf_is_func_proto(t)) {
    return make_error<ast::ArgParseError>(func, "not a function");
  }

  if (check_traceable) {
    if (bpftrace_ && !bpftrace_->is_traceable_func(std::string(func))) {
      if (bpftrace_->get_traceable_funcs().empty()) {
        return make_error<ast::ArgParseError>(
            func,
            "could not read traceable functions from " +
                tracefs::available_filter_functions() +
                " (is tracefs mounted?)");
      } else {
        return make_error<ast::ArgParseError>(
            func,
            "function not traceable (probably it is inlined or marked as "
            "\"notrace\")");
      }
      return nullptr;
    }
  }

  const struct btf_param *p = btf_params(t);
  __u16 vlen = btf_vlen(t);
  if (vlen > arch::Host::arguments().size()) {
    return make_error<ast::ArgParseError>(
        func,
        "functions with more than " +
            std::to_string(arch::Host::arguments().size()) +
            " parameters are not supported.");
  }

  int arg_idx = 0;
  auto args = std::make_shared<Struct>(0, false);
  for (__u16 j = 0; j < vlen; j++, p++) {
    if (j == 0 && skip_first_arg) {
      continue;
    }

    const char *str = btf_str(func_id.btf, p->name_off);
    if (!str) {
      return make_error<ast::ArgParseError>(func,
                                            "failed to resolve arguments");
    }

    SizedType stype = get_stype(BTFId{ .btf = func_id.btf, .id = p->type });
    stype.funcarg_idx = arg_idx;
    stype.is_funcarg = true;
    args->AddField(str, stype, args->size);
    // fentry args are stored in a u64 array.
    // Note that it's ok to represent them by a struct as we will use GEP with
    // funcarg_idx to access them in codegen.
    auto type_size = btf__resolve_size(func_id.btf, p->type);
    args->size += type_size;
    arg_idx += std::ceil(static_cast<float>(type_size) / static_cast<float>(8));
  }

  if (ret) {
    SizedType stype = get_stype(BTFId{ .btf = func_id.btf, .id = t->type });
    stype.funcarg_idx = arg_idx;
    stype.is_funcarg = true;
    args->AddField(RETVAL_FIELD_NAME, stype, args->size);
    // fentry args (incl. retval) are stored in a u64 array
    args->size += btf__resolve_size(func_id.btf, t->type);
  }
  return args;
}

Result<std::shared_ptr<Struct>> BTF::resolve_raw_tracepoint_args(
    std::string_view func)
{
  for (const auto &prefix : RT_BTF_PREFIXES) {
    auto args = resolve_args(
        std::string(prefix) + std::string(func), false, true, true);
    if (args) {
      return args;
    }
  }
  return make_error<ast::ArgParseError>(
      func, "BTF data for the tracepoint not found");
}

std::string BTF::get_all_funcs_from_btf(const BTFObj &btf_obj) const
{
  std::string funcs;

  auto id = start_id(btf_obj.btf), max = type_cnt(btf_obj.btf);
  for (; id <= max; id++) {
    const struct btf_type *t = btf__type_by_id(btf_obj.btf, id);
    if (!t)
      continue;

    if (!btf_is_func(t))
      continue;

    std::string func_name = btf__name_by_offset(btf_obj.btf, t->name_off);

    t = btf__type_by_id(btf_obj.btf, t->type);
    if (!t || !btf_is_func_proto(t)) {
      /* bad.. */
      LOG(ERROR) << func_name << " function does not have FUNC_PROTO record";
      break;
    }

    if (bpftrace_ && !bpftrace_->is_traceable_func(func_name))
      continue;

    if (btf_vlen(t) > arch::Host::arguments().size())
      continue;

    funcs += btf_obj.name + ":" + func_name + "\n";
  }

  return funcs;
}

std::unique_ptr<std::istream> BTF::get_all_funcs()
{
  if (!all_funcs_.empty()) {
    return std::make_unique<std::stringstream>(all_funcs_);
  }
  for (const auto &btf_obj : btf_objects)
    all_funcs_ += get_all_funcs_from_btf(btf_obj);
  return std::make_unique<std::stringstream>(all_funcs_);
}

std::string BTF::get_all_raw_tracepoints_from_btf(const BTFObj &btf_obj) const
{
  std::set<std::string> func_set;

  auto id = start_id(btf_obj.btf), max = type_cnt(btf_obj.btf);
  for (; id <= max; id++) {
    const struct btf_type *t = btf__type_by_id(btf_obj.btf, id);
    if (!t)
      continue;

    if (!btf_is_func(t))
      continue;

    std::string_view func_name = btf__name_by_offset(btf_obj.btf, t->name_off);

    t = btf__type_by_id(btf_obj.btf, t->type);
    if (!t || !btf_is_func_proto(t)) {
      /* bad.. */
      LOG(ERROR) << func_name << " function does not have FUNC_PROTO record";
      break;
    }

    if (btf_vlen(t) > arch::Host::arguments().size())
      continue;

    bool found = false;
    for (const auto &prefix : RT_BTF_PREFIXES) {
      if (func_name.starts_with(prefix)) {
        found = true;
        func_name.remove_prefix(prefix.length());
        break;
      }
    }

    if (!found)
      continue;

    // TODO: remove the std::string on C++26
    func_set.insert(btf_obj.name + ':' + std::string(func_name) + '\n');
  }

  std::string funcs;
  for (const auto &func : func_set) {
    funcs += func;
  }
  return funcs;
}

std::unique_ptr<std::istream> BTF::get_all_raw_tracepoints()
{
  if (!all_rawtracepoints_.empty()) {
    return std::make_unique<std::stringstream>(all_rawtracepoints_);
  }
  for (const auto &btf_obj : btf_objects)
    all_rawtracepoints_ += get_all_raw_tracepoints_from_btf(btf_obj);
  return std::make_unique<std::stringstream>(all_rawtracepoints_);
}

FuncParamLists BTF::get_params_from_btf(
    const BTFObj &btf_obj,
    const std::set<std::string> &funcs) const
{
  std::stringstream type;
  auto *dump = dump_new(btf_obj.btf, dump_printf, &type);
  if (auto err = libbpf_get_error(dump)) {
    char err_buf[256] = {};
    libbpf_strerror(err, err_buf, sizeof(err_buf));
    LOG(ERROR) << "BTF: failed to initialize dump (" << err_buf << ")";
    return {};
  }
  SCOPE_EXIT
  {
    btf_dump__free(dump);
  };

  FuncParamLists params;
  auto id = start_id(btf_obj.btf), max = type_cnt(btf_obj.btf);
  for (; id <= max; id++) {
    const struct btf_type *t = btf__type_by_id(btf_obj.btf, id);
    if (!t)
      continue;

    if (!btf_is_func(t))
      continue;

    const auto func_name = btf_obj.name + ":" +
                           btf__name_by_offset(btf_obj.btf, t->name_off);
    if (!funcs.contains(func_name))
      continue;

    t = btf__type_by_id(btf_obj.btf, t->type);
    if (!t)
      continue;

    DECLARE_LIBBPF_OPTS(btf_dump_emit_type_decl_opts, decl_opts);
    decl_opts.field_name = "";

    const auto *p = btf_params(t);
    for (__u16 j = 0, len = btf_vlen(t); j < len; j++, p++) {
      const char *arg_name = btf__name_by_offset(btf_obj.btf, p->name_off);

      // set by dump_printf callback
      type.str("");
      if (btf_dump__emit_type_decl(dump, p->type, &decl_opts)) {
        LOG(ERROR) << "failed to dump argument: " << arg_name;
        break;
      }

      params[func_name].push_back(type.str() + " " + arg_name);
    }

    if (!t->type)
      continue;

    // set by dump_printf callback
    type.str("");
    if (btf_dump__emit_type_decl(dump, t->type, &decl_opts)) {
      LOG(ERROR) << "failed to dump return type for: " << func_name;
      break;
    }

    params[func_name].push_back(type.str() + " retval");
  }

  if (id != (max + 1))
    LOG(ERROR) << "BTF data inconsistency " << id << "," << max;

  return params;
}

FuncParamLists BTF::get_kprobes_params_from_btf(
    const BTFObj &btf_obj,
    const std::set<std::string> &funcs,
    bool is_kretprobe) const
{
  std::stringstream type;
  auto *dump = dump_new(btf_obj.btf, dump_printf, &type);
  if (auto err = libbpf_get_error(dump)) {
    char err_buf[256] = {};
    libbpf_strerror(err, err_buf, sizeof(err_buf));
    LOG(V1) << "BTF: failed to initialize dump (" << err_buf << ")";
    return {};
  }
  SCOPE_EXIT
  {
    btf_dump__free(dump);
  };

  FuncParamLists params;
  auto id = start_id(btf_obj.btf), max = type_cnt(btf_obj.btf);
  for (; id <= max; id++) {
    const struct btf_type *t = btf__type_by_id(btf_obj.btf, id);
    if (!t)
      continue;

    if (!btf_is_func(t))
      continue;

    std::string func_name;
    const std::string pure_func_name = btf__name_by_offset(btf_obj.btf,
                                                           t->name_off);
    const std::string obj_func_name = btf_obj.name + ":" + pure_func_name;

    // First match the module prefix name, then match the pure function name.
    // For example, first match "kprobe:vmlinux:do_sys*", then "kprobe:do_sys*".
    // The same goes for other modules, such as "kvm".
    if (funcs.contains(obj_func_name))
      func_name = obj_func_name;
    else if (funcs.contains(pure_func_name))
      func_name = pure_func_name;
    else
      continue;

    t = btf__type_by_id(btf_obj.btf, t->type);
    if (!t)
      continue;

    DECLARE_LIBBPF_OPTS(btf_dump_emit_type_decl_opts, decl_opts);
    decl_opts.field_name = "";

    if (!is_kretprobe) {
      const auto *p = btf_params(t);

      for (__u16 j = 0, argN = 0, len = btf_vlen(t); j < len; j++, p++) {
        const std::string arg_name = "arg" + std::to_string(argN);

        // set by dump_printf callback
        type.str("");
        if (btf_dump__emit_type_decl(dump, p->type, &decl_opts)) {
          LOG(V1) << "failed to dump argument: " << arg_name;
          break;
        }

        // Note that floating point arguments are typically passed in special
        // registers which don’t count as argN arguments. e.g. on x86_64 the
        // first 6 non-floating point arguments are passed in registers and
        // all following arguments are passed on the stack
        const auto *pt = btf__type_by_id(btf_obj.btf, p->type);
        if (pt && BTF_INFO_KIND(pt->info) == BTF_KIND_FLOAT)
          continue;

        params[func_name].push_back(type.str() + " " + arg_name);
        argN++;
      }
    } else {
      if (!t->type) {
        params[func_name].emplace_back("void");
        continue;
      }

      // set by dump_printf callback
      type.str("");
      if (btf_dump__emit_type_decl(dump, t->type, &decl_opts)) {
        LOG(ERROR) << "failed to dump return type for: " << func_name;
        break;
      }

      params[func_name].push_back(type.str() + " retval");
    }
  }

  if (id != (max + 1))
    LOG(BUG) << "BTF data inconsistency " << id << "," << max;

  return params;
}

FuncParamLists BTF::get_raw_tracepoints_params_from_btf(
    const BTFObj &btf_obj,
    const std::set<std::string> &rawtracepoints) const
{
  std::stringstream type;
  auto *dump = dump_new(btf_obj.btf, dump_printf, &type);
  if (auto err = libbpf_get_error(dump)) {
    char err_buf[256] = {};
    libbpf_strerror(err, err_buf, sizeof(err_buf));
    LOG(ERROR) << "BTF: failed to initialize dump (" << err_buf << ")";
    return {};
  }
  SCOPE_EXIT
  {
    btf_dump__free(dump);
  };

  FuncParamLists params;
  auto id = start_id(btf_obj.btf), max = type_cnt(btf_obj.btf);
  for (; id <= max; id++) {
    const struct btf_type *t = btf__type_by_id(btf_obj.btf, id);
    if (!t)
      continue;

    if (!btf_is_func(t))
      continue;

    std::string_view tp_name = btf__name_by_offset(btf_obj.btf, t->name_off);
    for (const auto &prefix : RT_BTF_PREFIXES) {
      if (tp_name.starts_with(prefix))
        tp_name.remove_prefix(prefix.length());
    }

    // Checking multiple prefixes so make sure we don't add duplicates
    // TODO: remove the std::string ctor on C++26
    auto mod_tp_name = btf_obj.name + ":" + std::string(tp_name);
    if (!rawtracepoints.contains(mod_tp_name) || params.contains(mod_tp_name))
      continue;

    t = btf__type_by_id(btf_obj.btf, t->type);
    if (!t)
      continue;

    DECLARE_LIBBPF_OPTS(btf_dump_emit_type_decl_opts, decl_opts);
    decl_opts.field_name = "";

    const struct btf_param *p = btf_params(t);
    for (__u16 j = 0, len = btf_vlen(t); j < len; j++, p++) {
      if (j == 0) {
        // The first param is void *, which is not really part of the
        // rawtracepoint params
        continue;
      }

      const char *arg_name = btf__name_by_offset(btf_obj.btf, p->name_off);

      // set by dump_printf callback
      type.str("");
      if (btf_dump__emit_type_decl(dump, p->type, &decl_opts)) {
        LOG(ERROR) << "failed to dump argument: " << arg_name;
        break;
      }

      params[mod_tp_name].push_back(type.str() + " " + arg_name);
    }
  }

  if (id != (max + 1))
    LOG(ERROR) << "BTF data inconsistency " << id << "," << max;

  return params;
}

FuncParamLists BTF::get_params_impl(
    const std::set<std::string> &funcs,
    std::function<FuncParamLists(const BTFObj &btf_obj,
                                 const std::set<std::string> &funcs)>
        get_param_btf_cb) const
{
  FuncParamLists params;
  auto all_resolved = [&params](const std::string &f) {
    return params.contains(f);
  };

  for (const auto &btf_obj : btf_objects) {
    if (std::ranges::all_of(funcs, all_resolved))
      break;

    auto mod_params = get_param_btf_cb(btf_obj, funcs);
    params.insert(mod_params.begin(), mod_params.end());
  }

  return params;
}

FuncParamLists BTF::get_params(const std::set<std::string> &funcs) const
{
  return get_params_impl(
      funcs, [this](const BTFObj &btf_obj, const std::set<std::string> &funcs) {
        return get_params_from_btf(btf_obj, funcs);
      });
}

FuncParamLists BTF::get_kprobes_params(const std::set<std::string> &funcs) const
{
  return get_params_impl(
      funcs, [this](const BTFObj &btf_obj, const std::set<std::string> &funcs) {
        return get_kprobes_params_from_btf(btf_obj, funcs, false);
      });
}

FuncParamLists BTF::get_kretprobes_params(
    const std::set<std::string> &funcs) const
{
  return get_params_impl(
      funcs, [this](const BTFObj &btf_obj, const std::set<std::string> &funcs) {
        return get_kprobes_params_from_btf(btf_obj, funcs, true);
      });
}

FuncParamLists BTF::get_rawtracepoint_params(
    const std::set<std::string> &rawtracepoints) const
{
  return get_params_impl(
      rawtracepoints,
      [this](const BTFObj &btf_obj, const std::set<std::string> &funcs) {
        return get_raw_tracepoints_params_from_btf(btf_obj, funcs);
      });
}

std::set<std::string> BTF::get_all_structs_from_btf(const struct btf *btf) const
{
  std::set<std::string> struct_set;

  std::stringstream types;
  auto *dump = dump_new(btf, dump_printf, &types);
  if (auto err = libbpf_get_error(dump)) {
    char err_buf[256] = { 0 };
    libbpf_strerror(err, err_buf, sizeof(err_buf));
    LOG(ERROR) << "BTF: failed to initialize dump (" << err_buf << ")";
    return {};
  }
  SCOPE_EXIT
  {
    btf_dump__free(dump);
  };

  auto id = start_id(btf), max = type_cnt(btf);
  for (; id <= max; id++) {
    const struct btf_type *t = btf__type_by_id(btf, id);

    if (!t || !(btf_is_struct(t) || btf_is_union(t) || btf_is_enum(t)))
      continue;

    const std::string name = full_type_str(btf, t);
    if (name.find("(anon)") != std::string::npos)
      continue;

    if (bt_verbose)
      btf_dump__dump_type(dump, id);
    else
      struct_set.insert(std::move(name));
  }

  if (id != (max + 1))
    LOG(ERROR) << " BTF data inconsistency " << id << "," << max;

  if (bt_verbose) {
    // BTF dump contains definitions of all types in a single string, here we
    // split it
    std::istringstream type_stream(types.str());
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
  for (const auto &btf_obj : btf_objects) {
    auto mod_structs = get_all_structs_from_btf(btf_obj.btf);
    structs.insert(mod_structs.begin(), mod_structs.end());
  }
  return structs;
}

std::unordered_set<std::string> BTF::get_all_iters_from_btf(
    const struct btf *btf) const
{
  constexpr std::string_view prefix = "bpf_iter__";
  // kernel commit 6fcd486b3a0a("bpf: Refactor RCU enforcement in the
  // verifier.") add 'struct bpf_iter__task__safe_trusted'
  constexpr std::string_view suffix___safe_trusted = "__safe_trusted";

  std::unordered_set<std::string> iter_set;

  auto id = start_id(btf), max = type_cnt(btf);
  for (; id <= max; id++) {
    const struct btf_type *t = btf__type_by_id(btf, id);
    if (!t || !btf_is_struct(t))
      continue;

    std::string_view name = btf_str(btf, t->name_off);

    // skip __safe_trusted suffix struct
    if (name.ends_with(suffix___safe_trusted))
      continue;
    if (name.starts_with(prefix)) {
      name.remove_prefix(prefix.length());
      iter_set.insert(std::string(name));
    }
  }

  return iter_set;
}

std::unordered_set<std::string> BTF::get_all_iters() const
{
  std::unordered_set<std::string> iters;
  for (const auto &btf_obj : btf_objects) {
    auto mod_iters = get_all_iters_from_btf(btf_obj.btf);
    iters.insert(mod_iters.begin(), mod_iters.end());
  }
  return iters;
}

int BTF::get_btf_id(std::string_view func,
                    std::string_view mod,
                    __u32 kind) const
{
  for (const auto &btf_obj : btf_objects) {
    if (!mod.empty() && mod != btf_obj.name)
      continue;

    auto id = find_id_in_btf(btf_obj.btf, func, kind);
    if (id >= 0)
      return id;
  }

  return -1;
}

BTF::BTFId BTF::find_id(std::string_view name, std::optional<__u32> kind) const
{
  for (const auto &btf_obj : btf_objects) {
    __s32 id = kind ? btf__find_by_name_kind(btf_obj.btf, name.data(), *kind)
                    : btf__find_by_name(btf_obj.btf, name.data());
    if (id >= 0)
      return { .btf = btf_obj.btf, .id = static_cast<__u32>(id) };
  }

  return { .btf = nullptr, .id = 0 };
}

__s32 BTF::find_id_in_btf(struct btf *btf,
                          std::string_view name,
                          std::optional<__u32> kind) const
{
  for (auto id = start_id(btf), max = type_cnt(btf); id <= max; ++id) {
    const struct btf_type *t = btf__type_by_id(btf, id);
    if (!t)
      continue;
    if (kind && btf_kind(t) != *kind)
      continue;

    const auto *type_name = btf__name_by_offset(btf, t->name_off);
    if (name == type_name)
      return id;
  }
  return -1;
}

void BTF::resolve_fields(const SizedType &type)
{
  BTFId type_id;

  if (!type.IsRecordTy())
    return;

  auto const &name = type.GetName();
  auto record = bpftrace_->structs.Lookup(name).lock();
  if (record->HasFields())
    return;

  if (type.IsAnonTy())
    type_id = parse_anon_btf_name(name);
  else {
    __u32 kind = name.starts_with("struct") ? BTF_KIND_STRUCT : BTF_KIND_UNION;
    auto type_name = btf_type_str(name);

    type_id = find_id(type_name, kind);
    if (!type_id.btf)
      return;
  }

  resolve_fields(type_id, std::move(record), 0);
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
                         std::shared_ptr<Struct> record,
                         __u32 start_offset)
{
  const auto *btf_type = btf__type_by_id(type_id.btf, type_id.id);
  if (!btf_type)
    return;
  auto *members = btf_members(btf_type);
  for (__u32 i = 0; i < BTF_INFO_VLEN(btf_type->info); i++) {
    BTFId field_id{ .btf = type_id.btf, .id = members[i].type };
    const auto *field_type = btf__type_by_id(field_id.btf, field_id.id);
    if (!field_type) {
      LOG(ERROR) << "Inconsistent BTF data (no type found for id "
                 << members[i].type << ")";
      record->ClearFields();
      break;
    }

    std::string field_name = btf__name_by_offset(type_id.btf,
                                                 members[i].name_off);

    __u32 field_offset = start_offset +
                         (btf_member_bit_offset(btf_type, i) / 8);

    if (btf_is_composite(field_type) && is_anon_btf_typename(field_name)) {
      resolve_fields(field_id, record, field_offset);
      continue;
    }

    record->AddField(field_name,
                     get_stype(field_id),
                     field_offset,
                     resolve_bitfield(btf_type, i));
  }
}

SizedType BTF::get_stype(std::string_view type_name)
{
  auto btf_name = btf_type_str(type_name);
  auto type_id = find_id(btf_name);
  if (type_id.btf)
    return get_stype(type_id);

  if (type_name.starts_with("const "))
    return get_stype(type_name.substr("const "sv.length()));

  if (type_name.ends_with(" const") || type_name.ends_with("*const")) {
    auto new_name = std::string(type_name.substr(0, type_name.rfind("const")));
    util::rtrim(new_name);
    return get_stype(new_name);
  }

  if (type_name.ends_with("*")) {
    auto pointee = std::string(type_name.substr(0, type_name.length() - 1));
    util::rtrim(pointee);
    return CreatePointer(get_stype(pointee));
  }

  if (type_name == "unsigned")
    return get_stype("unsigned int");
  if (type_name == "short")
    return get_stype("short int");
  if (type_name == "unsigned short")
    return get_stype("short unsigned int");
  if (type_name == "long")
    return get_stype("long int");
  if (type_name == "unsigned long")
    return get_stype("long unsigned int");
  if (type_name == "long long")
    return get_stype("long long int");
  if (type_name == "unsigned long long")
    return get_stype("long long unsigned int");

  if (type_name.ends_with(" short")) {
    auto pos = type_name.rfind(" short");
    return get_stype("short " + std::string(type_name.substr(0, pos)));
  }

  if (type_name.ends_with(" long")) {
    auto pos = type_name.rfind(" long");
    return get_stype("long " + std::string(type_name.substr(0, pos)));
  }

  if (type_name.ends_with(" unsigned")) {
    auto pos = type_name.rfind(" long");
    return get_stype("long " + std::string(type_name.substr(0, pos)));
  }

  return CreateNone();
}

SizedType BTF::get_var_type(std::string_view var_name)
{
  auto var_id = find_id(var_name, BTF_KIND_VAR);
  if (!var_id.btf)
    return CreateNone();

  const struct btf_type *t = btf__type_by_id(var_id.btf, var_id.id);
  if (!t)
    return CreateNone();

  return get_stype(BTFId{ .btf = var_id.btf, .id = t->type });
}

ast::Pass CreateParseBTFPass()
{
  return ast::Pass::create(
      "btf", []([[maybe_unused]] ast::ASTContext &ast, BPFtrace &b) {
        b.parse_module_btf(b.list_modules(ast));
      });
}

} // namespace bpftrace
