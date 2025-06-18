#include <sstream>

#include "types/helpers.h"
#include "types/types.h"

namespace bpftrace::types {

Result<Struct> createTuple(BTF &btf, const std::vector<ValueType> &types)
{
  size_t element = 0;
  std::map<std::string, ValueType> fields;
  for (const auto &type : types) {
    std::stringstream ss;
    ss << "elem_" << element;
    fields.emplace(ss.str(), type);
  }
  return btf.add<Struct>("", fields);
}

Result<Struct> createMap(BTF &btf, const struct MapInfo &info)
{
  std::map<std::string, ValueType> fields;
  // First, we need an "int" type.
  auto i = btf.lookup<Integer>("int");
  if (!i) {
    i = btf.add<Integer>("int", sizeof(int), true);
    if (!i) {
      return i.takeError();
    }
  }
  // Now we need an `__ARRAY_SIZE_TYPE__`.
  auto sz = btf.lookup<Integer>("__ARRAY_SIZE_TYPE__");
  if (!sz) {
    sz = btf.add<Integer>("__ARRAY_SIZE_TYPE__", sizeof(int), true);
    if (!sz) {
      return sz.takeError();
    }
  }

  // Now we need to encode the type and max_entries.
  auto enc_type_arr = btf.add<Array>(*sz,
                                     *i,
                                     static_cast<size_t>(info.map_type));
  if (!enc_type_arr) {
    return enc_type_arr.takeError();
  }
  auto enc_type_ptr = btf.add<Pointer>(*enc_type_arr);
  if (!enc_type_ptr) {
    return enc_type_ptr.takeError();
  }
  auto enc_max_entries_arr = btf.add<Array>(*sz, *i, info.nr_elements);
  if (!enc_max_entries_arr) {
    return enc_max_entries_arr.takeError();
  }
  auto enc_max_entries_ptr = btf.add<Pointer>(*enc_max_entries_arr);
  if (!enc_max_entries_ptr) {
    return enc_max_entries_ptr.takeError();
  }
  auto enc_key = btf.add<Pointer>(info.key);
  if (!enc_key) {
    return enc_key.takeError();
  }
  auto enc_value = btf.add<Pointer>(info.value);
  if (!enc_value) {
    return enc_value.takeError();
  }
  fields.emplace("type", *enc_type_ptr);
  fields.emplace("max_entries", *enc_max_entries_ptr);
  fields.emplace("key", *enc_key);
  fields.emplace("value", *enc_value);
  auto r = btf.add<Struct>("", fields);
  if (!r) {
    return r.takeError();
  }
  return std::move(*r);
}

Result<std::optional<MapInfo>> getMapInfo(const AnyType &type)
{
  if (!type.is<Struct>()) {
    return std::nullopt;
  }
  const auto &s = type.as<Struct>();
  auto fields = s.fields();
  if (!fields) {
    return fields.takeError();
  }

  // Validate that all fields are present and in order.
  if (fields->size() != 4) {
    return std::nullopt;
  }
  static const std::vector<std::string> expected = {
    "type", "max_entries", "key", "value"
  };
  size_t elem = 0;
  for (const auto &[name, _] : *fields) {
    if (name != expected[elem]) {
      return std::nullopt;
    }
    elem++;
  }

  // Extract the type.
  auto &type_info = fields->at("type");
  ::bpf_map_type map_type = BPF_MAP_TYPE_ARRAY;
  if (!type_info.type.is<Pointer>()) {
    return std::nullopt;
  } else {
    auto arr = type_info.type.as<Pointer>().element_type();
    if (!arr || !arr->is<Array>()) {
      return std::nullopt;
    }
    map_type = static_cast<::bpf_map_type>(arr->as<Array>().element_count());
  }

  // Extract the number of elements.
  auto &max_entries = fields->at("max_entries");
  size_t nr_elements = 0;
  if (!max_entries.type.is<Pointer>()) {
    return std::nullopt;
  } else {
    auto arr = type_info.type.as<Pointer>().element_type();
    if (!arr || !arr->is<Array>()) {
      return std::nullopt;
    }
    nr_elements = arr->as<Array>().element_count();
  }

  // Extract the key and value types.
  auto &key = fields->at("key");
  auto &value = fields->at("value");
  struct MapInfo info = {
    .map_type = map_type,
    .key = key.type,
    .value = value.type,
    .nr_elements = nr_elements,
  };
  return info;
}

} // namespace bpftrace::types
