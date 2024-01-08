#include "required_resources.h"

#include <cereal/archives/binary.hpp>
#include <cereal/types/map.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/optional.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/tuple.hpp>
#include <cereal/types/unordered_set.hpp>
#include <cereal/types/vector.hpp>

#include "bpftrace.h"
#include "fake_map.h"
#include "log.h"
#include "utils.h"

namespace bpftrace {

int RequiredResources::create_maps(BPFtrace &bpftrace, bool fake)
{
  if (fake)
    return create_maps_impl<bpftrace::FakeMap>(bpftrace, fake);
  else
    return create_maps_impl<bpftrace::Map>(bpftrace, fake);
}

template <typename T>
int RequiredResources::create_maps_impl(BPFtrace &bpftrace, bool fake)
{
  uint32_t failed_maps = 0;
  auto is_invalid_map = [=](int a) -> uint8_t {
    return (!fake && a < 0) ? 1 : 0;
  };
  for (auto &map_val : map_vals) {
    std::string map_name = map_val.first;
    SizedType type = map_val.second;

    auto search_args = map_keys.find(map_name);
    if (search_args == map_keys.end())
      LOG(FATAL) << "map key \"" << map_name << "\" not found";

    auto &key = search_args->second;
    auto max_map_keys = bpftrace.config_.get(ConfigKeyInt::max_map_keys);

    if (type.IsLhistTy()) {
      auto args = lhist_args.find(map_name);
      if (args == lhist_args.end())
        LOG(FATAL) << "map arg \"" << map_name << "\" not found";

      auto min = args->second.min;
      auto max = args->second.max;
      auto step = args->second.step;
      auto map = std::make_unique<T>(
          map_name, type, key, min, max, step, max_map_keys);
      failed_maps += is_invalid_map(map->mapfd_);
      bpftrace.maps.Add(std::move(map));
    } else if (type.IsHistTy()) {
      auto args = hist_bits_arg.find(map_name);
      if (args == hist_bits_arg.end())
        LOG(FATAL) << "map arg \"" << map_name << "\" not found";
      // the 'step' argument is used to pass 'bits'
      auto map = std::make_unique<T>(map_name,
                                     type,
                                     key,
                                     0,
                                     0,
                                     args->second,
                                     bpftrace.config_.get(
                                         ConfigKeyInt::max_map_keys));
      failed_maps += is_invalid_map(map->mapfd_);
      bpftrace.maps.Add(std::move(map));
    } else {
      auto map = std::make_unique<T>(map_name, type, key, max_map_keys);
      failed_maps += is_invalid_map(map->mapfd_);
      bpftrace.maps.Add(std::move(map));
    }
  }

  for (StackType stack_type : stackid_maps) {
    // The stack type doesn't matter here, so we use kstack to force SizedType
    // to set stack_size.
    auto map = std::make_unique<T>(CreateStack(true, stack_type));
    failed_maps += is_invalid_map(map->mapfd_);
    bpftrace.maps.Set(stack_type, std::move(map));
  }

  if (failed_maps > 0) {
    std::cerr << "Creation of the required BPF maps has failed." << std::endl;
    std::cerr << "Make sure you have all the required permissions and are not";
    std::cerr << " confined (e.g. like" << std::endl;
    std::cerr << "snapcraft does). `dmesg` will likely have useful output for";
    std::cerr << " further troubleshooting" << std::endl;
  }

  return failed_maps;
}

template <typename T>
std::unique_ptr<T> RequiredResources::prepareFormatStringDataMap(
    const std::vector<std::tuple<FormatString, std::vector<Field>>> &args,
    int *ret)
{
  // get size of all the format strings
  size_t size = 0;
  for (auto &it : args)
    size += std::get<0>(it).size() + 1;

  // compute buffer size to hold all the formats and create map with that
  int ptr_size = sizeof(unsigned long);
  size = (size / ptr_size + 1) * ptr_size;
  auto map = std::make_unique<T>(
      "mapped_printf_data", libbpf::BPF_MAP_TYPE_ARRAY, 4, size, 1, 0);

  return map;
}

void RequiredResources::save_state(std::ostream &out) const
{
  cereal::BinaryOutputArchive archive(out);
  archive(*this);
}

void RequiredResources::load_state(std::istream &in)
{
  cereal::BinaryInputArchive archive(in);
  archive(*this);
}

void RequiredResources::load_state(const uint8_t *ptr, size_t len)
{
  auto addr = const_cast<uint8_t *>(ptr);
  Membuf mbuf(addr, addr + len);
  std::istream istream(&mbuf);
  cereal::BinaryInputArchive archive(istream);
  archive(*this);
}

} // namespace bpftrace
