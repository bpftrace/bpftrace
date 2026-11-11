#include "btf/helper_protos.h"

namespace bpftrace::btf {

template <typename T>
static Result<uint32_t> type_id(Result<T> &&type)
{
  if (!type) {
    return type.takeError();
  }
  return type->type_id();
}

static Result<uint32_t> add_type(Types &types,
                                 const HelperType &type,
                                 const std::vector<uint32_t> &ids)
{
  if (type.kind == HelperType::Kind::Integer) {
    return type_id(
        types.add<Integer>(std::string(type.name), type.size, type.encoding));
  }
  if (type.kind == HelperType::Kind::ForwardStruct) {
    return type_id(
        types.add<ForwardDecl>(std::string(type.name), ForwardDecl::Struct));
  }
  auto ref = types.lookup<AnyType>(ids.at(type.type));
  if (!ref) {
    return ref.takeError();
  }
  switch (type.kind) {
    case HelperType::Kind::Typedef:
      return type_id(types.add<Typedef>(std::string(type.name), *ref));
    case HelperType::Kind::Pointer:
      return type_id(types.add<Pointer>(*ref));
    case HelperType::Kind::Const:
      return type_id(types.add<Const>(*ref));
    case HelperType::Kind::Integer:
    case HelperType::Kind::ForwardStruct:
      break;
  }
  __builtin_unreachable();
}

Result<Types> load_helper_protos()
{
  Types types;

  // Maps from the index in `helper_types` to the type_id in `types`.
  std::vector<uint32_t> ids = { 0 };
  ids.reserve(helper_types.size() + 1);
  for (const auto &type : helper_types) {
    auto id = add_type(types, type, ids);
    if (!id) {
      return id.takeError();
    }
    ids.push_back(*id);
  }

  for (const auto &helper : helper_protos) {
    auto return_type = types.lookup<ValueType>(ids.at(helper.return_type));
    if (!return_type) {
      return return_type.takeError();
    }
    std::vector<std::pair<std::string, ValueType>> args;
    for (auto arg : helper.args) {
      auto arg_type = types.lookup<ValueType>(ids.at(arg));
      if (!arg_type) {
        return arg_type.takeError();
      }
      args.emplace_back("", std::move(*arg_type));
    }
    auto proto = types.add<FunctionProto>(*return_type, args);
    if (!proto) {
      return proto.takeError();
    }
    auto func = types.add<Function>(std::string(helper.name),
                                    Function::Linkage::Global,
                                    *proto);
    if (!func) {
      return func.takeError();
    }
  }

  return types;
}

} // namespace bpftrace::btf
