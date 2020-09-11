#include <cstring>
#include <iostream>
#include <unistd.h>
#include <linux/version.h>

#include "bpftrace.h"
#include "log.h"
#include "utils.h"
#include <bcc/libbpf.h>

#include "map.h"
#include "mapmanager.h"

namespace bpftrace {

int Map::create_map(enum bpf_map_type map_type, const char *name, int key_size, int value_size, int max_entries, int flags) {
#ifdef HAVE_BCC_CREATE_MAP
  return bcc_create_map(map_type, name, key_size, value_size, max_entries, flags);
#else
  return bpf_create_map(map_type, name, key_size, value_size, max_entries, flags);
#endif
}

Map::Map(const std::string &name, const SizedType &type, const MapKey &key, int min, int max, int step, int max_entries)
{
  name_ = name;
  type_ = type;
  key_ = key;
  // for lhist maps:
  lqmin = min;
  lqmax = max;
  lqstep = step;

  int key_size = key.size();
  if (type.IsHistTy() || type.IsLhistTy() || type.IsAvgTy() || type.IsStatsTy())
    key_size += 8;
  if (key_size == 0)
    key_size = 8;

  if (type.IsCountTy() && !key.args_.size())
  {
    map_type_ = BPF_MAP_TYPE_PERCPU_ARRAY;
    max_entries = 1;
    key_size = 4;
  }
  else if ((type.IsHistTy() || type.IsLhistTy() || type.IsCountTy() ||
            type.IsSumTy() || type.IsMinTy() || type.IsMaxTy() ||
            type.IsAvgTy() || type.IsStatsTy()) &&
           (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)))
  {
      map_type_ = BPF_MAP_TYPE_PERCPU_HASH;
  }
  else if (type.IsJoinTy())
  {
    map_type_ = BPF_MAP_TYPE_PERCPU_ARRAY;
    max_entries = 1;
    key_size = 4;
  }
  else
    map_type_ = BPF_MAP_TYPE_HASH;

  int value_size = type.size;
  int flags = 0;
  mapfd_ = create_map(map_type_, name.c_str(), key_size, value_size, max_entries, flags);
  if (mapfd_ < 0)
  {
    LOG(ERROR) << "failed to create map: '" << name_
               << "': " << strerror(errno);
  }
}

Map::Map(const SizedType &type) {
#ifdef DEBUG
  // TODO (mmarchini): replace with DCHECK
  if (!type.IsStack()) {
    LOG(FATAL) << "Map::Map(SizedType) constructor should be called only with "
                  "stack types";
  }
#endif
  type_ = type;
  int key_size = 4;
  int value_size = sizeof(uintptr_t) * type.stack_type.limit;
  std::string name = "stack";
  int max_entries = 4096;
  int flags = 0;
  enum bpf_map_type map_type = BPF_MAP_TYPE_STACK_TRACE;

  mapfd_ = create_map(map_type, name.c_str(), key_size, value_size, max_entries, flags);
  if (mapfd_ < 0)
  {
    LOG(ERROR)
        << "failed to create stack id map\n"
        // TODO (mmarchini): Check perf_event_max_stack in the semantic_analyzer
        << "This might have happened because kernel.perf_event_max_stack "
        << "is smaller than " << type.stack_type.limit
        << ". Try to tweak this value with "
        << "sysctl kernel.perf_event_max_stack=<new value>";
  }
}

Map::Map(enum bpf_map_type map_type)
{
  int key_size, value_size, max_entries, flags;
  map_type_ = map_type;

  std::string name;
#ifdef DEBUG
  // TODO (mmarchini): replace with DCHECK
  if (map_type == BPF_MAP_TYPE_STACK_TRACE)
  {
    LOG(FATAL) << "Use Map::Map(SizedType) constructor instead";
  }
#endif
  if (map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY)
  {
    std::vector<int> cpus = get_online_cpus();
    name = "printf";
    key_size = 4;
    value_size = 4;
    max_entries = cpus.size();
    flags = 0;
  }
  else
  {
    LOG(FATAL) << "invalid map type";
  }

  mapfd_ = create_map(map_type, name.c_str(), key_size, value_size, max_entries, flags);
  if (mapfd_ < 0)
  {
    LOG(ERROR) << "failed to create " << name << " map: " << strerror(errno);
  }
}

Map::~Map()
{
  if (mapfd_ >= 0)
    close(mapfd_);
}

void MapManager::Add(std::unique_ptr<IMap> map)
{
  auto name = map->name_;
  if (name.empty())
    throw std::runtime_error("Map without name cannot be stored");

  auto count = maps_by_name_.count(name);
  if (count > 0)
    throw std::runtime_error("Map with name: @" + name + " already exists");

  auto id = maps_by_id_.size();
  map->id = id;
  maps_by_name_[name] = map.get();
  maps_by_id_.emplace_back(std::move(map));
}

bool MapManager::Has(const std::string &name)
{
  return maps_by_name_.find(name) != maps_by_name_.end();
}

std::optional<IMap *> MapManager::Lookup(const std::string &name)
{
  auto search = maps_by_name_.find(name);
  if (search == maps_by_name_.end())
  {
    return {};
  }

  return search->second;
}

std::optional<IMap *> MapManager::Lookup(ssize_t id)
{
  if (id >= (ssize_t)maps_by_id_.size())
    return {};
  return maps_by_id_[id].get();
}

void MapManager::Set(MapManager::Type t, std::unique_ptr<IMap> map)
{
  maps_by_type_[t] = std::move(map);
}

std::optional<IMap *> MapManager::Lookup(Type t)
{
  auto search = maps_by_type_.find(t);
  if (search == maps_by_type_.end())
  {
    return {};
  }

  return search->second.get();
}

bool MapManager::Has(Type t)
{
  return maps_by_type_.find(t) != maps_by_type_.end();
}

void MapManager::Set(StackType t, std::unique_ptr<IMap> map)
{
  stackid_maps_[t] = std::move(map);
}

std::optional<IMap *> MapManager::Lookup(StackType t)
{
  return stackid_maps_[t].get();
}

bool MapManager::Has(StackType t)
{
  return stackid_maps_.find(t) != stackid_maps_.end();
}

std::string to_string(MapManager::Type t)
{
  switch (t)
  {
    case MapManager::Type::PerfEvent:
      return "perf_event";
    case MapManager::Type::Join:
      return "join";
    case MapManager::Type::Elapsed:
      return "elapsed";
  }
  return {}; // unreached
}
} // namespace bpftrace
