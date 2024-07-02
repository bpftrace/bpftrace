#pragma once

namespace bpftrace {
namespace ast {

// Add new ids here
#define FOR_LIST_OF_ASYNC_IDS(DO)                                              \
  DO(cat)                                                                      \
  DO(cgroup_path)                                                              \
  DO(helper_error)                                                             \
  DO(join)                                                                     \
  DO(bpf_print)                                                                \
  DO(non_map_print)                                                            \
  DO(printf)                                                                   \
  DO(skb_output)                                                               \
  DO(strftime)                                                                 \
  DO(str)                                                                      \
  DO(system)                                                                   \
  DO(time)                                                                     \
  DO(watchpoint)

#define DEFINE_MEMBER_VAR(id, ...) int _##id = 0;
#define DEFINE_ACCESS_METHOD(id, ...)                                          \
  int id()                                                                     \
  {                                                                            \
    return _##id++;                                                            \
  }
#define LOCAL_SAVE(id, ...) local_##id = _##id,
#define LOCAL_RESTORE(id, ...) this->_##id = local_##id;

class AsyncIds {
public:
  explicit AsyncIds() = default;

  FOR_LIST_OF_ASYNC_IDS(DEFINE_ACCESS_METHOD)

  /*
   * For 'create_reset_ids' return a lambda that has captured-by-value
   * CodegenLLVM's async id state. Running the returned lambda will restore
   * `CodegenLLVM`s async id state back to when this function was first called.
   */
  std::function<void()> create_reset_ids()
  {
    return [FOR_LIST_OF_ASYNC_IDS(LOCAL_SAVE) this] {
      FOR_LIST_OF_ASYNC_IDS(LOCAL_RESTORE)
    };
  }

private:
  FOR_LIST_OF_ASYNC_IDS(DEFINE_MEMBER_VAR)
};

} // namespace ast
} // namespace bpftrace
