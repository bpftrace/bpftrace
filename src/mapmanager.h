#pragma once

#include "imap.h"
#include <map>
#include <memory>
#include <optional>
#include <unordered_map>

namespace bpftrace {

/**
   A container for all maps created during program execution.

*/
class MapManager
{
public:
  MapManager() = default;
  MapManager &operator=(MapManager &&) = default;

  MapManager(const MapManager &) = delete;
  MapManager &operator=(const MapManager &) = delete;
  MapManager(MapManager &&) = delete;

  /**
     Store and lookup named maps
  */
  void Add(std::unique_ptr<IMap> map);
  bool Has(const std::string &name);
  std::optional<IMap *> Lookup(const std::string &name);
  std::optional<IMap *> Lookup(ssize_t id);

  std::optional<IMap *> operator[](ssize_t id)
  {
    return Lookup(id);
  };
  std::optional<IMap *> operator[](const std::string &name)
  {
    return Lookup(name);
  };

  /**
     Iterate over named maps, vector like iteration
  */
  auto begin()
  {
    return maps_by_id_.begin();
  };
  auto end()
  {
    return maps_by_id_.end();
  };

  /**
     Internal maps
  */
  enum class Type
  {
    // Also update to_string
    PerfEvent,
    Join,
    Elapsed,
    SeqPrintfData,
  };

  void Set(Type t, std::unique_ptr<IMap> map);
  std::optional<IMap *> Lookup(Type t);
  std::optional<IMap *> operator[](Type t)
  {
    return Lookup(t);
  };
  bool Has(Type t);

  /**
     Stack maps
  */
  void Set(StackType t, std::unique_ptr<IMap> map);
  std::optional<IMap *> Lookup(StackType t);
  std::optional<IMap *> operator[](StackType t)
  {
    return Lookup(t);
  };
  bool Has(StackType t);
  ssize_t CountStackTypes()
  {
    return stackid_maps_.size();
  };

private:
  // `maps_by_id_` holds *all* maps
  std::vector<std::unique_ptr<IMap>> maps_by_id_;

  std::unordered_map<std::string, IMap *> maps_by_name_;
  std::unordered_map<Type, IMap *> maps_by_type_;
  std::unordered_map<StackType, IMap *> stackid_maps_;
};

std::string to_string(MapManager::Type t);

} // namespace bpftrace
