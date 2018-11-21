#include <clang-c/Index.h>
#include <iostream>
#include <string.h>
#include <sys/utsname.h>

#include "frontends/clang/kbuild_helper.h"

#include "ast.h"
#include "bpftrace.h"
#include "clang_parser.h"
#include "types.h"

extern "C" const char __stddef_max_align_t_h[];
extern "C" const unsigned __stddef_max_align_t_h_len;
extern "C" const char float_h[];
extern "C" const unsigned float_h_len;
extern "C" const char limits_h[];
extern "C" const unsigned limits_h_len;
extern "C" const char stdarg_h[];
extern "C" const unsigned stdarg_h_len;
extern "C" const char stddef_h[];
extern "C" const unsigned stddef_h_len;
extern "C" const char stdint_h[];
extern "C" const unsigned stdint_h_len;

namespace bpftrace {

static std::string get_clang_string(CXString string)
{
  std::string str = clang_getCString(string);
  clang_disposeString(string);
  return str;
}

static void remove_struct_prefix(std::string &str)
{
  if (strncmp(str.c_str(), "struct ", 7) == 0)
    str.erase(0, 7);
}

static CXCursor get_indirect_field_parent_struct(CXCursor c)
{
  CXCursor parent = clang_getCursorSemanticParent(c);

  while (!clang_Cursor_isNull(parent) && clang_Cursor_isAnonymous(parent))
     parent = clang_getCursorSemanticParent(parent);

  return parent;
}

static std::string get_parent_struct_name(CXCursor c)
{
  CXCursor parent = get_indirect_field_parent_struct(c);

  return get_clang_string(clang_getCursorSpelling(parent));
}

static int get_indirect_field_offset(CXCursor c)
{
  int offset = 0;
  CXCursor parent = get_indirect_field_parent_struct(c);
  auto ident = get_clang_string(clang_getCursorSpelling(c));
  offset = clang_Type_getOffsetOf(clang_getCursorType(parent), ident.c_str()) / 8;

  return offset;
}

static SizedType get_sized_type(CXType clang_type)
{
  auto size = clang_Type_getSizeOf(clang_type);
  auto typestr = get_clang_string(clang_getTypeSpelling(clang_type));
  remove_struct_prefix(typestr);

  switch (clang_type.kind)
  {
    case CXType_Bool:
    case CXType_Char_S:
    case CXType_Char_U:
    case CXType_SChar:
    case CXType_UChar:
    case CXType_Short:
    case CXType_UShort:
    case CXType_Int:
    case CXType_UInt:
    case CXType_Long:
    case CXType_ULong:
    case CXType_LongLong:
    case CXType_ULongLong:
      return SizedType(Type::integer, size);
    case CXType_Record:
      return SizedType(Type::cast, size, typestr);
    case CXType_Pointer:
    {
      auto pointee_type = clang_getPointeeType(clang_type);
      SizedType type;
      if (pointee_type.kind == CXType_Record)
      {
        auto pointee_typestr = get_clang_string(clang_getTypeSpelling(pointee_type));
        remove_struct_prefix(pointee_typestr);
        type = SizedType(Type::cast, sizeof(uintptr_t), pointee_typestr);
      }
      else
      {
        type = SizedType(Type::integer, sizeof(uintptr_t));
      }
      auto pointee_size = clang_Type_getSizeOf(pointee_type);
      type.is_pointer = true;
      type.pointee_size = pointee_size;
      return type;
    }
    case CXType_ConstantArray:
    {
      auto elem_type = clang_getArrayElementType(clang_type);
      auto size = clang_getArraySize(clang_type);
      if (elem_type.kind == CXType_Char_S || elem_type.kind == CXType_Char_U)
      {
        return SizedType(Type::string, size);
      }
      // TODO add support for arrays
      return SizedType(Type::none, 0);
    }
    default:
      return SizedType(Type::none, 0);
  }
}

static bool is_dir(const std::string& path)
{
  struct stat buf;

  if (::stat(path.c_str(), &buf) < 0)
    return false;

  return S_ISDIR(buf.st_mode);
}

static std::pair<bool, std::string> get_kernel_path_info(const std::string &kdir)
{
  if (is_dir(kdir + "/build") && is_dir(kdir + "/source"))
    return std::make_pair(true, "source");
  return std::make_pair(false, "build");
}

void ClangParser::parse(ast::Program *program, StructMap &structs)
{
  auto input = program->c_definitions;
  if (input.size() == 0)
    return; // We occasionally get crashes in libclang otherwise

  CXUnsavedFile unsaved_files[] =
  {
    {
      .Filename = "definitions.h",
      .Contents = input.c_str(),
      .Length = input.size(),
    },
    {
      .Filename = "/bpftrace/include/__stddef_max_align_t.h",
      .Contents = __stddef_max_align_t_h,
      .Length = __stddef_max_align_t_h_len,
    },
    {
      .Filename = "/bpftrace/include/float.h",
      .Contents = float_h,
      .Length = float_h_len,
    },
    {
      .Filename = "/bpftrace/include/limits.h",
      .Contents = limits_h,
      .Length = limits_h_len,
    },
    {
      .Filename = "/bpftrace/include/stdarg.h",
      .Contents = stdarg_h,
      .Length = stdarg_h_len,
    },
    {
      .Filename = "/bpftrace/include/stddef.h",
      .Contents = stddef_h,
      .Length = stddef_h_len,
    },
    {
      .Filename = "/bpftrace/include/stdint.h",
      .Contents = stdint_h,
      .Length = stdint_h_len,
    },
  };

  struct utsname utsname;
  uname(&utsname);
  const char *kpath_env = ::getenv("BPFTRACE_KERNEL_SOURCE");
  const char *kpath_fixed =
  #ifdef KERNEL_HEADERS_DIR
    kpath_env ? kpath_env : KERNEL_HEADERS_DIR;
  #else
    kpath_env;
  #endif
  std::string kdir = kpath_fixed ?
    std::string(kpath_fixed) :
    std::string("/lib/modules/") + utsname.release;

  auto kpath_info = get_kernel_path_info(kdir);
  auto kpath = kpath_fixed ?
    kdir :
    kdir + "/" + kpath_info.second;
  bool has_kpath_source = kpath_fixed ? false : kpath_info.first;

  std::vector<std::string> kflags;

  ebpf::DirStack dstack(kpath);
  if (dstack.ok())
  {
    ebpf::KBuildHelper kbuild_helper(kdir, has_kpath_source);
    kbuild_helper.get_flags(utsname.machine, &kflags);
  }

  std::vector<const char *> args =
  {
    "-I", "/bpftrace/include",
  };
  for (auto &flag : kflags)
  {
    args.push_back(flag.c_str());
  }

  CXIndex index = clang_createIndex(1, 1);
  CXTranslationUnit translation_unit;
  CXErrorCode error = clang_parseTranslationUnit2(
      index,
      "definitions.h",
      &args[0], args.size(),
      unsaved_files, sizeof(unsaved_files)/sizeof(CXUnsavedFile),
      CXTranslationUnit_None,
      &translation_unit);
  if (error)
  {
    std::cerr << "Clang error while parsing C definitions: " << error << std::endl;
    std::cerr << "Input (" << input.size() << "): " << input << std::endl;
  }

  CXCursor cursor = clang_getTranslationUnitCursor(translation_unit);

  clang_visitChildren(
      cursor,
      [](CXCursor c, CXCursor parent, CXClientData client_data)
      {
        auto &structs = *static_cast<StructMap*>(client_data);

        if (clang_getCursorKind(parent) != CXCursor_StructDecl &&
            clang_getCursorKind(parent) != CXCursor_UnionDecl)
          return CXChildVisit_Recurse;

        if (clang_getCursorKind(c) == CXCursor_FieldDecl)
        {
          auto struct_name = get_parent_struct_name(c);
          auto ident = get_clang_string(clang_getCursorSpelling(c));
          auto offset = clang_Cursor_getOffsetOfField(c) / 8;
          auto type = clang_getCanonicalType(clang_getCursorType(c));

          auto ptype = clang_getCanonicalType(clang_getCursorType(parent));
          auto ptypestr = get_clang_string(clang_getTypeSpelling(ptype));
          auto ptypesize = clang_Type_getSizeOf(ptype);

          if(clang_Cursor_isAnonymous(parent))
            offset = get_indirect_field_offset(c);

          if (struct_name == "")
            struct_name = ptypestr;
          remove_struct_prefix(struct_name);

          structs[struct_name].fields[ident].offset = offset;
          structs[struct_name].fields[ident].type = get_sized_type(type);
          structs[struct_name].size = ptypesize;
        }

        return CXChildVisit_Recurse;
      },
      &structs);

  clang_disposeTranslationUnit(translation_unit);
  clang_disposeIndex(index);
}

} // namespace bpftrace
