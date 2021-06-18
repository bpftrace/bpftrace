#include <cstring>
#include <iostream>
#include <unistd.h>

#include "bpftrace.h"
#include "log.h"
#include "utils.h"
#include <bcc/libbpf.h>

#include "map.h"
#include "mapmanager.h"

namespace bpftrace {

namespace {

int create_map(enum bpf_map_type map_type,
               const std::string &name,
               int key_size,
               int value_size,
               int max_entries,
               int flags)
{
  std::string fixed_name;
  const std::string *name_ptr = &name;
  if (!name.empty() && name[0] == '@')
  {
    fixed_name = "AT_" + name.substr(1);
    name_ptr = &fixed_name;
  }
#ifdef HAVE_BCC_CREATE_MAP
  return bcc_create_map(
      map_type, name_ptr->c_str(), key_size, value_size, max_entries, flags);
#else
  return bpf_create_map(
      map_type, name_ptr->c_str(), key_size, value_size, max_entries, flags);
#endif
}

} // namespace

Map::Map(const std::string &name,
         const SizedType &type,
         const MapKey &key,
         int min,
         int max,
         int step,
         int max_entries)
    : IMap(name, type, key, min, max, step, max_entries)
{
  int key_size = key.size();
  if (type.IsHistTy() || type.IsLhistTy() || type.IsAvgTy() || type.IsStatsTy())
    key_size += 8;
  if (key_size == 0)
    key_size = 8;
  if (type.IsCountTy() && !key.args_.size())
  {
    max_entries = 1;
    key_size = 4;
  }

  int value_size = type.GetSize();
  int flags = 0;
  mapfd_ = create_map(
      map_type_, name, key_size, value_size, max_entries, flags);
  if (mapfd_ < 0)
  {
    LOG(ERROR) << "failed to create map: '" << name_
               << "': " << strerror(errno);
  }
}

Map::Map(const std::string &name,
         enum bpf_map_type type,
         int key_size,
         int value_size,
         int max_entries,
         int flags)
    : IMap(name, type, key_size, value_size, max_entries, flags)
{
  mapfd_ = create_map(
      map_type_, name_, key_size, value_size, max_entries, flags);
  if (mapfd_ < 0)
  {
    LOG(ERROR) << "failed to create map: '" << name_
               << "': " << strerror(errno);
  }
}

// bpf_get_stackid() is kind of broken by design.
//
// First, stacks can suffer from hash collisions and we can lose stacks. We
// receive collision errors in userspace b/c we do not set BPF_F_REUSE_STACKID.
// Note that we should **NEVER** set this flag b/c then we can silently receive
// unrelated stacks in userspace.
//
// Second, there is not a great way to reduce the frequency of collision (other
// than increasing map size) b/c multiple probes can be sharing the same stack
// (remember they are hashed). As a result, we cannot delete entries in this
// map b/c we don't know when all the sharers are gone.
//
// Fortunately, we haven't seen many bug reports about missing stacks (or maybe
// people don't care that much). The proper solution would be to use
// bpf_get_stack() to get the actual stack trace and pass it to userspace
// through the ring buffer.  However, there is additional complexity with this
// b/c we need to set up a percpu map to use as scratch space for
// bpf_get_stack() to write into. Using the stack directly wouldn't work well
// b/c it would take too much stack space.
//
// The temporary fix is to bump the map size to 128K. Any futher bumps should
// warrant consideration of the previous paragraph.
Map::Map(const SizedType &type) : IMap(type)
{
  int key_size = 4;
  int value_size = sizeof(uintptr_t) * type.stack_type.limit;
  int max_entries = 128 << 10;
  int flags = 0;

  mapfd_ = create_map(
      map_type_, "stack", key_size, value_size, max_entries, flags);
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

Map::Map(enum bpf_map_type map_type) : IMap(map_type)
{
  std::vector<int> cpus = get_online_cpus();
  int key_size = 4;
  int value_size = 4;
  int max_entries = cpus.size();
  int flags = 0;

  mapfd_ = create_map(
      map_type, "printf", key_size, value_size, max_entries, flags);
  if (mapfd_ < 0)
  {
    LOG(ERROR) << "failed to create " << name_ << " map: " << strerror(errno);
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
  auto id = maps_by_id_.size();
  map->id = id;
  map->printable_ = false;
  maps_by_type_[t] = map.get();
  maps_by_id_.emplace_back(std::move(map));
}

std::optional<IMap *> MapManager::Lookup(Type t)
{
  auto search = maps_by_type_.find(t);
  if (search == maps_by_type_.end())
  {
    return {};
  }

  return search->second;
}

bool MapManager::Has(Type t)
{
  return maps_by_type_.find(t) != maps_by_type_.end();
}

void MapManager::Set(StackType t, std::unique_ptr<IMap> map)
{
  auto id = maps_by_id_.size();
  map->id = id;
  map->printable_ = false;
  stackid_maps_[t] = map.get();
  maps_by_id_.emplace_back(std::move(map));
}

std::optional<IMap *> MapManager::Lookup(StackType t)
{
  auto search = stackid_maps_.find(t);
  if (search == stackid_maps_.end())
  {
    return {};
  }

  return search->second;
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
    case MapManager::Type::SeqPrintfData:
      return "seq_printf_data";
  }
  return {}; // unreached
}
} // namespace bpftrace
