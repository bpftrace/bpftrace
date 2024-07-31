#include "dwarf_parser.h"

#ifdef HAVE_LIBLLDB

#include "bpftrace.h"
#include "log.h"
#include "types.h"

#include <atomic>
#include <lldb/API/LLDB.h>
#include <llvm/Config/llvm-config.h>
#include <memory>
#include <string>

namespace bpftrace {

std::atomic<size_t> Dwarf::instance_count = 0;

Dwarf::Dwarf(BPFtrace *bpftrace, std::string file_path)
    : bpftrace_(bpftrace), file_path_(std::move(file_path))
{
  if (instance_count++ == 0)
    lldb::SBDebugger::Initialize();

  // Create a "hardened" debugger instance with no scripting, nor .lldbinit.
  // We don't want a Python extension or .lldbinit to influence the byte-code
  // that will get executed by the Kernel. It would be a security risk!
  debugger_ = lldb::SBDebugger::Create(/* source_init_file = */ false);
  debugger_.SetScriptLanguage(lldb::ScriptLanguage::eScriptLanguageNone);

  lldb::SBError error;
  target_ = debugger_.CreateTarget(
      file_path_.c_str(), nullptr, nullptr, true, error);
  if (!error.Success() || !target_.IsValid()) {
    throw error;
  }
}

Dwarf::~Dwarf()
{
  if (--instance_count == 0)
    lldb::SBDebugger::Terminate();
}

std::unique_ptr<Dwarf> Dwarf::GetFromBinary(BPFtrace *bpftrace,
                                            std::string file_path)
{
  try {
    // Can't use std::make_unique because Dwarf's constructor is private
    return std::unique_ptr<Dwarf>(new Dwarf(bpftrace, std::move(file_path)));
  } catch (const lldb::SBError &error) {
    LOG(ERROR) << "Failed to parse DebugInfo: " << error.GetCString();
    return nullptr;
  }
}

std::vector<uint64_t> Dwarf::get_function_locations(const std::string &function,
                                                    bool include_inlined)
{
  // Locating every inlined instances of a function is expensive,
  // so we only do it if the user explicitly requests it.
  if (!include_inlined) {
    auto syms = target_.FindSymbols(function.c_str(),
                                    lldb::SymbolType::eSymbolTypeCode);
    // The given function name MUST identify a unique symbol!
    if (syms.GetSize() != 1)
      return {};
    auto sym = syms.GetContextAtIndex(0).GetSymbol();
    return { sym.GetStartAddress().GetFileAddress() +
             sym.GetPrologueByteSize() };
  } else {
    auto bps = target_.BreakpointCreateByName(function.c_str());
    std::vector<uint64_t> result(bps.GetNumLocations());
    for (uint32_t i = 0; i < bps.GetNumLocations(); i++) {
      auto loc = bps.GetLocationAtIndex(i);
      result[i] = loc.GetAddress().GetFileAddress();
    }
    return result;
  }
}

std::string Dwarf::get_type_name(lldb::SBType type)
{
  std::string type_name = type.GetDisplayTypeName() ?: "<anonymous type>";

  // Get Pointee type to add the struct/union/enum prefix for C
  while (type.IsPointerType())
    type = type.GetPointeeType();

  switch (type.GetTypeClass()) {
    case lldb::eTypeClassStruct:
      return "struct " + type_name;
    case lldb::eTypeClassUnion:
      return "union " + type_name;
    case lldb::eTypeClassEnumeration:
      return "enum " + type_name;
    default:
      return type_name;
  }
}

lldb::SBValueList Dwarf::function_params(const std::string &function)
{
  auto functions = target_.FindFunctions(function.c_str());
  // The given function name MUST identify a unique function!
  if (functions.GetSize() != 1)
    return lldb::SBValueList();

  auto fn = functions.GetContextAtIndex(0).GetFunction();
  return fn.GetBlock().GetVariables(
      target_, /*arguments=*/true, /*locals=*/false, /*statics=*/false);
}

std::vector<std::string> Dwarf::get_function_params(const std::string &function)
{
  auto params = function_params(function);

  std::vector<std::string> result;
  result.reserve(params.GetSize());
  for (uint32_t i = 0; i < params.GetSize(); i++) {
    auto param = params.GetValueAtIndex(i);
    std::string param_name = param.GetName() ?: "";
    std::string param_type_name = get_type_name(param.GetType());
    result.push_back(param_type_name +
                     (param_name.empty() ? "" : " " + param_name));
  }
  return result;
}

Struct Dwarf::resolve_args(const std::string &function)
{
  auto params = function_params(function);

  Struct result(0, false);
  for (uint32_t i = 0; i < params.GetSize(); i++) {
    auto param = params.GetValueAtIndex(i);
    auto name = param.GetName() ?: "";
    auto arg_type = get_stype(param.GetType());
    arg_type.is_funcarg = true;
    arg_type.funcarg_idx = i;
    result.AddField(name, arg_type, result.size, std::nullopt, false);
    result.size += arg_type.GetSize();
  }
  return result;
}

SizedType Dwarf::get_stype(lldb::SBType type, bool resolve_structs)
{
  if (!type.IsValid())
    return CreateNone();

  auto bit_size = 8 * type.GetByteSize();

  switch (type.GetTypeClass()) {
    case lldb::eTypeClassBuiltin: {
      switch (type.GetBasicType()) {
        case lldb::eBasicTypeBool:
        case lldb::eBasicTypeChar:
        case lldb::eBasicTypeSignedChar:
        case lldb::eBasicTypeWChar:
        case lldb::eBasicTypeSignedWChar:
#if LLVM_VERSION_MAJOR >= 15
        case lldb::eBasicTypeChar8:
#endif
        case lldb::eBasicTypeChar16:
        case lldb::eBasicTypeChar32:
        case lldb::eBasicTypeShort:
        case lldb::eBasicTypeInt:
        case lldb::eBasicTypeInt128:
        case lldb::eBasicTypeLong:
        case lldb::eBasicTypeLongLong:
          return CreateInt(bit_size);
        case lldb::eBasicTypeUnsignedChar:
        case lldb::eBasicTypeUnsignedWChar:
        case lldb::eBasicTypeUnsignedShort:
        case lldb::eBasicTypeUnsignedInt:
        case lldb::eBasicTypeUnsignedInt128:
        case lldb::eBasicTypeUnsignedLong:
        case lldb::eBasicTypeUnsignedLongLong:
          return CreateUInt(bit_size);
        default:
          return CreateNone();
      }
      break;
    }
    case lldb::eTypeClassEnumeration:
      return CreateUInt(bit_size);
    case lldb::eTypeClassPointer:
    case lldb::eTypeClassReference: {
      if (auto inner_type = type.GetPointeeType()) {
        return CreatePointer(get_stype(inner_type, false));
      }
      // void *
      return CreatePointer(CreateNone());
    }
    case lldb::eTypeClassClass:
    case lldb::eTypeClassStruct:
    case lldb::eTypeClassUnion: {
      auto name = get_type_name(type);
      auto result = CreateRecord(
          name, bpftrace_->structs.LookupOrAdd(name, bit_size / 8));
      if (resolve_structs)
        resolve_fields(result);
      return result;
    }
    case lldb::eTypeClassArray: {
      auto inner_type = type.GetArrayElementType();
      auto inner_stype = get_stype(inner_type);
      // Create a fake array instance to get its length
      auto val = target_.CreateValueFromData("__field", lldb::SBData(), type);
      auto length = val.GetNumChildren();
      switch (inner_type.GetBasicType()) {
        case lldb::eBasicTypeChar:
        case lldb::eBasicTypeSignedChar:
        case lldb::eBasicTypeUnsignedChar:
#if LLVM_VERSION_MAJOR >= 15
        case lldb::eBasicTypeChar8:
#endif
          return CreateString(length);
        default:
          return CreateArray(length, inner_stype);
      }
    }
    case lldb::eTypeClassTypedef:
      return get_stype(type.GetTypedefedType(), resolve_structs);
    default:
      return CreateNone();
  }
}

SizedType Dwarf::get_stype(const std::string &type_name)
{
  if (auto type = target_.FindFirstType(type_name.c_str()))
    return get_stype(type);

  return CreateNone();
}

void Dwarf::resolve_fields(const SizedType &type)
{
  if (!type.IsRecordTy())
    return;

  auto type_name = type.GetName();
  auto str = bpftrace_->structs.Lookup(type_name).lock();
  if (str->HasFields())
    return;

  auto type_dbg = target_.FindFirstType(type_name.c_str());
  if (!type_dbg)
    return;

  for (uint32_t i = 0; i < type_dbg.GetNumberOfFields(); i++) {
    auto field = type_dbg.GetFieldAtIndex(i);
    auto field_type = get_stype(field.GetType());
    str->AddField(field.GetName() ?: "",
                  get_stype(field.GetType()),
                  field.GetOffsetInBytes(),
                  resolve_bitfield(field),
                  false);
  }
}

std::optional<Bitfield> Dwarf::resolve_bitfield(lldb::SBTypeMember field)
{
  if (!field.IsBitfield())
    return std::nullopt;

  auto bit_offset = field.GetOffsetInBits();
  auto bitfield_width = field.GetBitfieldSizeInBits();
  return Bitfield(bit_offset % 8, bitfield_width);
}

} // namespace bpftrace

#endif // HAVE_LIBLLDB
