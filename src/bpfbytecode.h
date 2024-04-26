#pragma once

#include "bpffeature.h"
#include "bpfmap.h"
#include "required_resources.h"
#include "types.h"

#include <bpf/libbpf.h>
#include <cereal/access.hpp>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace bpftrace {

using SectionMap = std::unordered_map<std::string, std::vector<uint8_t>>;

class BpfBytecode {
public:
  BpfBytecode()
  {
  }
  BpfBytecode(const void *elf, size_t elf_size);

  BpfBytecode(const BpfBytecode &) = delete;
  BpfBytecode &operator=(const BpfBytecode &) = delete;
  BpfBytecode(BpfBytecode &&) = default;
  BpfBytecode &operator=(BpfBytecode &&) = default;

  void addSection(const std::string &name, std::vector<uint8_t> &&data);
  bool hasSection(const std::string &name) const;
  const std::vector<uint8_t> &getSection(const std::string &name) const;

  bool create_maps();
  bool hasMap(MapType internal_type) const;
  bool hasMap(const StackType &stack_type) const;
  const BpfMap &getMap(const std::string &name) const;
  const BpfMap &getMap(MapType internal_type) const;
  const BpfMap &getMap(int map_id) const;
  void set_map_ids(RequiredResources &resources);

  const std::map<std::string, BpfMap> &maps() const;
  int countStackMaps() const;

  void fixupBTF(BPFfeature &feature);

private:
  SectionMap sections_;

  // We need a custom deleter for bpf_object which will call bpf_object__close.
  // Note that it is not possible to run bpf_object__close in ~BpfBytecode
  // as the desctuctor may be called upon move assignment.
  struct bpf_object_deleter {
    void operator()(struct bpf_object *object)
    {
      bpf_object__close(object);
    }
  };
  std::unique_ptr<struct bpf_object, bpf_object_deleter> bpf_object_;

  std::map<std::string, BpfMap> maps_;
  std::map<int, BpfMap *> maps_by_id_;

  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(sections_);
  }
};

} // namespace bpftrace
