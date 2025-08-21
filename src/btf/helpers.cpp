#include "btf/helpers.h"

namespace bpftrace::btf {

char MapError::ID;

void MapError::log(llvm::raw_ostream &OS) const
{
  OS << msg_;
}

Result<Struct> createTuple(Types &btf, const std::vector<ValueType> &types)
{
  std::vector<std::pair<std::string, ValueType>> fields;
  for (const auto &type : types) {
    fields.emplace_back("", type);
  }
  return btf.add<Struct>("", fields);
}

Result<Struct> createMap(Types &btf, const struct MapInfo &info)
{
  std::vector<std::pair<std::string, ValueType>> fields;
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
  fields.emplace_back("type", *enc_type_ptr);
  fields.emplace_back("max_entries", *enc_max_entries_ptr);
  fields.emplace_back("key", *enc_key);
  fields.emplace_back("value", *enc_value);
  auto r = btf.add<Struct>("", fields);
  if (!r) {
    return r.takeError();
  }
  return std::move(*r);
}

Result<MapInfo> getMapInfo(const AnyType &type)
{
  if (!type.is<Struct>()) {
    return make_error<MapError>("not a struct");
  }
  const auto &s = type.as<Struct>();
  auto fields = s.fields();
  if (!fields) {
    return fields.takeError();
  }

  // Validate that all fields are present and in order.
  if (fields->size() != 4) {
    return make_error<MapError>("does not have four fields");
  }
  static const std::vector<std::string> expected = {
    "type", "max_entries", "key", "value"
  };
  size_t elem = 0;
  for (const auto &[name, _] : *fields) {
    if (name != expected[elem]) {
      return make_error<MapError>("field names do not match");
    }
    elem++;
  }

  // Extract the type.
  auto &type_info = fields->at(0).second;
  ::bpf_map_type map_type = BPF_MAP_TYPE_ARRAY;
  if (!type_info.type.is<Pointer>()) {
    return make_error<MapError>("type field is not a pointer");
  } else {
    auto arr = type_info.type.as<Pointer>().element_type();
    if (!arr || !arr->is<Array>()) {
      return make_error<MapError>("type field is not a pointer to an array");
    }
    map_type = static_cast<bpf_map_type>(arr->as<Array>().element_count());
  }

  // Extract the number of elements.
  auto &max_entries = fields->at(1).second;
  size_t nr_elements = 0;
  if (!max_entries.type.is<Pointer>()) {
    return make_error<MapError>("max_entries field is not a pointer");
  } else {
    auto arr = max_entries.type.as<Pointer>().element_type();
    if (!arr || !arr->is<Array>()) {
      return make_error<MapError>(
          "max_entries field is not a pointer to an array");
    }
    nr_elements = arr->as<Array>().element_count();
  }

  // Extract the key and value types.
  auto &key_ptr = fields->at(2).second.type;
  if (!key_ptr.is<Pointer>()) {
    return make_error<MapError>("key field is not a pointer");
  }
  auto key_type = key_ptr.as<Pointer>().element_type();
  if (!key_type) {
    return key_type.takeError();
  }
  auto &value_ptr = fields->at(3).second.type;
  if (!value_ptr.is<Pointer>()) {
    return make_error<MapError>("value field is not a pointer");
  }
  auto value_type = value_ptr.as<Pointer>().element_type();
  if (!value_type) {
    return value_type.takeError();
  }
  struct MapInfo info = {
    .map_type = map_type,
    .key = *key_type,
    .value = *value_type,
    .nr_elements = nr_elements,
  };
  return info;
}

} // namespace bpftrace::btf
