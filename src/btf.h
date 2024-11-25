#pragma once

#include <bpf/btf.h>
#include <cstddef>
#include <iterator>
#include <linux/types.h>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <unistd.h>
#include <unordered_set>
#include <vector>

#include "types.h"

// Taken from libbpf
#define BTF_INFO_ENC(kind, kind_flag, vlen)                                    \
  ((!!(kind_flag) << 31) | ((kind) << 24) | ((vlen)&BTF_MAX_VLEN))
#define BTF_TYPE_ENC(name, info, size_or_type) (name), (info), (size_or_type)
#define BTF_INT_ENC(encoding, bits_offset, nr_bits)                            \
  ((encoding) << 24 | (bits_offset) << 16 | (nr_bits))
#define BTF_TYPE_INT_ENC(name, encoding, bits_offset, bits, sz)                \
  BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_INT, 0, 0), sz),                    \
      BTF_INT_ENC(encoding, bits_offset, bits)
#define BTF_PARAM_ENC(name, type) (name), (type)

struct bpf_object;
struct btf;
struct btf_type;

namespace bpftrace {

class BpfBytecode;
class BPFtrace;
class StructManager;

namespace btf {
class Functions;

/**
 * Wrapper class around a single `btf` object.
 */
class BtfObject {
public:
  /**
   * Construct with the kernel's base BTF (normally from vmlinux)
   */
  BtfObject(struct btf* base_btf);

  /**
   * Construct with BTF from a kernel module
   */
  BtfObject(uint32_t id, struct btf* base_btf);

  /**
   * Load BTF from a bpf_object
   */
  BtfObject(const struct bpf_object* obj);

  const struct btf* btf() const;
  Functions functions() const;

private:
  enum class Origin {
    Invalid,
    Kernel,
    Object,
  };

  class BtfDeleter {
  public:
    BtfDeleter()
    {
    }
    BtfDeleter(Origin origin) : origin_(origin)
    {
    }

    void operator()(struct btf* obj)
    {
      assert(origin_ != Origin::Invalid);

      if (origin_ == Origin::Kernel) {
        btf__free(obj);
      }
    }

  private:
    Origin origin_ = Origin::Invalid;
  };
  std::unique_ptr<struct btf, BtfDeleter> obj_;
};

/**
 * Holds a top-level BTF object and the name of the module it originates from.
 */
struct NamedBtfObj {
  BtfObject btf;
  std::string_view name;
};

/**
 * Wrapper around BTF data.
 *
 * The data can either be from a single BPF object or from multiple split BTF
 * objects.
 */
class BTF {
  // It is often necessary to store a BTF id along with the BTF data containing
  // its definition.
  struct BTFId {
    const struct btf* btf;
    __u32 id;
  };

public:
  BTF(const std::set<std::string>& modules);
  BTF(BPFtrace* bpftrace, const std::set<std::string>& modules) : BTF(modules)
  {
    bpftrace_ = bpftrace;
  };

  bool has_data(void) const;
  size_t objects_cnt() const
  {
    return btf_objects_.size();
  }

  Functions functions() const;

  std::string c_def(const std::unordered_set<std::string>& set) const;
  std::string type_of(const std::string& name, const std::string& field);
  std::string type_of(const BTFId& type_id, const std::string& field);
  SizedType get_stype(const std::string& type_name);
  SizedType get_var_type(const std::string& var_name);

  std::set<std::string> get_all_structs() const;
  std::unique_ptr<std::istream> get_all_funcs() const;
  std::unordered_set<std::string> get_all_iters() const;
  std::map<std::string, std::vector<std::string>> get_params(
      const std::set<std::string>& funcs) const;

  std::optional<Struct> resolve_args(const std::string& func,
                                     bool ret,
                                     std::string& err);
  void resolve_fields(SizedType& type);

  int get_btf_id(std::string_view func, std::string_view mod) const;

private:
  void load_kernel_btfs(const std::set<std::string>& modules);
  SizedType get_stype(const BTFId& btf_id, bool resolve_structs = true);
  static const struct btf_type* btf_type_skip_modifiers(
      const struct btf_type* t,
      const struct btf* btf);
  BTFId find_id(const std::string& name,
                std::optional<__u32> kind = std::nullopt) const;
  __s32 find_id_in_btf(const struct btf* btf,
                       std::string_view name,
                       std::optional<__u32> = std::nullopt) const;

  std::string dump_defs_from_btf(const struct btf* btf,
                                 std::unordered_set<std::string>& types) const;
  std::string get_all_funcs_from_btf(const NamedBtfObj& btf_obj) const;
  std::map<std::string, std::vector<std::string>> get_params_from_btf(
      const NamedBtfObj& btf_obj,
      const std::set<std::string>& funcs) const;
  std::set<std::string> get_all_structs_from_btf(const struct btf* btf) const;
  std::unordered_set<std::string> get_all_iters_from_btf(
      const struct btf* btf) const;
  /*
   * Similar to btf_type_skip_modifiers this returns the id of the first
   * type that is not a BTF_KIND_TYPE_TAG while also populating the tags set
   * with the tag/attribute names from the BTF_KIND_TYPE_TAG types it finds.
   */
  static __u32 get_type_tags(std::unordered_set<std::string>& tags,
                             const BTFId& btf_id);

  __s32 start_id(const struct btf* btf) const;

  struct btf* base_btf_ = nullptr;
  __s32 base_btf_size_;
  std::vector<NamedBtfObj> btf_objects_;
  BPFtrace* bpftrace_ = nullptr;
};

inline bool BTF::has_data(void) const
{
  return !btf_objects_.empty();
}

/**
 * A function parameter defined in BTF
 */
class Param {
public:
  Param(const struct btf* btf, const struct btf_param* param)
      : btf_(btf), param_(param)
  {
  }

  std::string_view name() const;
  SizedType type(StructManager& structs) const;

private:
  const struct btf* btf_;
  const struct btf_param* param_;
};

/**
 * Pseudo-container providing access to function parameters
 *
 * TODO make this a random access iterator
 */
class Parameters {
public:
  Parameters(const struct btf* btf, const struct btf_type* proto_type);

  uint16_t size() const;

  class Iterator {
  public:
    using iterator_category = std::forward_iterator_tag;
    using difference_type = std::ptrdiff_t; // TODO
    using value_type = Param;
    using pointer = Param;
    using reference = Param;

    Iterator()
    {
    }
    Iterator(const struct btf* btf, const struct btf_param* param)
        : btf_(btf), param_(param)
    {
    }

    reference operator*() const
    {
      return Param{ btf_, param_ };
    }
    pointer operator->()
    {
      return Param{ btf_, param_ };
    }

    Iterator& operator++()
    {
      ++param_;
      return *this;
    }
    Iterator operator++(int)
    {
      Iterator tmp = *this;
      ++(*this);
      return tmp;
    }

    friend bool operator==(const Iterator& a, const Iterator& b)
    {
      return a.btf_ == b.btf_ && a.param_ == b.param_;
    }
    // TODO operator!= ?
  private:
    const struct btf* btf_ = nullptr;
    const struct btf_param* param_ = nullptr;
  };
  static_assert(std::forward_iterator<Iterator>);

  Iterator begin()
  {
    return Iterator(btf_, btf_params(proto_type_));
  }

  Iterator end()
  {
    return Iterator(btf_, btf_params(proto_type_) + btf_vlen(proto_type_));
  }

private:
  const struct btf* btf_;
  const struct btf_type* proto_type_;
};

/**
 * A function defined in BTF
 */
class Function {
public:
  Function(const struct btf* btf, uint32_t id);

  std::string_view name() const;
  SizedType returnType(StructManager& structs) const;
  Parameters parameters() const;

private:
  const struct btf* btf_;
  const struct btf_type* func_type_;
};

/**
 * Pseudo-container providing access to BTF functions
 */
class Functions {
public:
  Functions(const struct btf* btf, uint32_t start_id)
      : btf_(btf), start_id_(start_id)
  {
  }

  class Iterator {
  public:
    using iterator_category = std::forward_iterator_tag;
    using difference_type = std::ptrdiff_t; // TODO
    using value_type = Function;
    using pointer = Function;
    using reference = Function;

    Iterator()
    {
    }
    Iterator(const struct btf* btf, uint32_t start_id)
        : btf_(btf), id_(start_id)
    {
      advance();
    }

    reference operator*() const
    {
      return Function{ btf_, id_ };
    }
    pointer operator->()
    {
      return Function{ btf_, id_ };
    }

    Iterator& operator++()
    {
      ++id_;
      advance();
      return *this;
    }
    Iterator operator++(int)
    {
      Iterator tmp = *this;
      ++(*this);
      return tmp;
    }

    friend bool operator==(const Iterator& a, const Iterator& b)
    {
      return a.btf_ == b.btf_ && a.id_ == b.id_;
    }
    // TODO operator!= ?
  private:
    /**
     * Advances the iterator to the next BTF function, if it is not currently
     * pointing to one.
     */
    void advance()
    {
      if (!btf_)
        return;
      uint32_t num_ids = btf__type_cnt(btf_);
      for (; id_ < num_ids; id_++) {
        const struct btf_type* t = btf__type_by_id(btf_, id_);
        if (t && btf_is_func(t))
          return;
      }

      // No more valid functions
      btf_ = nullptr;
      id_ = 0;
    }

    const struct btf* btf_ = nullptr;
    uint32_t id_ = 0;
  };
  static_assert(std::forward_iterator<Iterator>);

  Iterator begin()
  {
    return Iterator(btf_, start_id_);
  }
  Iterator end()
  {
    return Iterator(nullptr, 0);
  }

private:
  const struct btf* btf_;
  uint32_t start_id_;
};

} // namespace btf
} // namespace bpftrace
