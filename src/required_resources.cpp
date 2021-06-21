#include "required_resources.h"

#include <cereal/archives/binary.hpp>
#include <cereal/types/map.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/tuple.hpp>
#include <cereal/types/unordered_set.hpp>
#include <cereal/types/vector.hpp>

#include "bpftrace.h"
#include "fake_map.h"
#include "log.h"

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
  for (auto &map_val : map_vals)
  {
    std::string map_name = map_val.first;
    SizedType type = map_val.second;

    auto search_args = map_keys.find(map_name);
    if (search_args == map_keys.end())
      LOG(FATAL) << "map key \"" << map_name << "\" not found";

    auto &key = search_args->second;

    if (type.IsLhistTy())
    {
      auto args = lhist_args.find(map_name);
      if (args == lhist_args.end())
        LOG(FATAL) << "map arg \"" << map_name << "\" not found";

      auto min = args->second.min;
      auto max = args->second.max;
      auto step = args->second.step;
      auto map = std::make_unique<T>(
          map_name, type, key, min, max, step, bpftrace.mapmax_);
      failed_maps += is_invalid_map(map->mapfd_);
      bpftrace.maps.Add(std::move(map));
    }
    else
    {
      auto map = std::make_unique<T>(map_name, type, key, bpftrace.mapmax_);
      failed_maps += is_invalid_map(map->mapfd_);
      bpftrace.maps.Add(std::move(map));
    }
  }

  for (StackType stack_type : stackid_maps)
  {
    // The stack type doesn't matter here, so we use kstack to force SizedType
    // to set stack_size.
    auto map = std::make_unique<T>(CreateStack(true, stack_type));
    failed_maps += is_invalid_map(map->mapfd_);
    bpftrace.maps.Set(stack_type, std::move(map));
  }

  if (needs_join_map)
  {
    // join uses map storage as we'd like to process data larger than can fit on
    // the BPF stack.
    int value_size = 8 + 8 + bpftrace.join_argnum_ * bpftrace.join_argsize_;
    auto map = std::make_unique<T>(
        "join", BPF_MAP_TYPE_PERCPU_ARRAY, 4, value_size, 1, 0);
    failed_maps += is_invalid_map(map->mapfd_);
    bpftrace.maps.Set(MapManager::Type::Join, std::move(map));
  }
  if (needs_elapsed_map)
  {
    std::string map_ident = "elapsed";
    SizedType type = CreateUInt64();
    MapKey key;
    auto map = std::make_unique<T>(map_ident, type, key, 1);
    failed_maps += is_invalid_map(map->mapfd_);
    bpftrace.maps.Set(MapManager::Type::Elapsed, std::move(map));
  }
  if (needs_data_map)
  {
    // get size of all the format strings
    size_t size = 0;
    for (auto it : seq_printf_args)
      size += std::get<0>(it).size() + 1;

    // compute buffer size to hold all the formats and create map with that
    int ptr_size = sizeof(unsigned long);
    size = (size / ptr_size + 1) * ptr_size;
    auto map = std::make_unique<T>("data", BPF_MAP_TYPE_ARRAY, 4, size, 1, 0);

    // copy all the format strings to buffer, head to tail
    uint32_t idx = 0;
    std::vector<uint8_t> formats(size, 0);
    for (auto &arg : seq_printf_args)
    {
      auto str = std::get<0>(arg).c_str();
      auto len = std::get<0>(arg).size();
      memcpy(&formats.data()[idx], str, len);
      idx += len + 1;
    }

    // store the data in map
    uint64_t id = 0;
    int ret = bpf_update_elem(map->mapfd_, &id, formats.data(), 0);

    if (is_invalid_map(map->mapfd_) || (!fake && ret == -1))
      failed_maps += 1;

    bpftrace.maps.Set(MapManager::Type::SeqPrintfData, std::move(map));
  }
  {
    auto map = std::make_unique<T>(BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    failed_maps += is_invalid_map(map->mapfd_);
    bpftrace.maps.Set(MapManager::Type::PerfEvent, std::move(map));
  }

  if (failed_maps > 0)
  {
    std::cerr << "Creation of the required BPF maps has failed." << std::endl;
    std::cerr << "Make sure you have all the required permissions and are not";
    std::cerr << " confined (e.g. like" << std::endl;
    std::cerr << "snapcraft does). `dmesg` will likely have useful output for";
    std::cerr << " further troubleshooting" << std::endl;
  }

  return failed_maps;
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

} // namespace bpftrace
