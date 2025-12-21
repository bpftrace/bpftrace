#pragma once

#include <functional>

namespace bpftrace::ast {

// Add new ids here
#define FOR_LIST_OF_ASYNC_IDS(DO)                                              \
  DO(call_stack)                                                                 \
  DO(map_key)                                                                  \
  DO(read_map_value)                                                           \
  DO(runtime_error)                                                            \
  DO(str)                                                                      \
  DO(tuple)                                                                    \
  DO(variable)                                                                 \
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

  // For 'create_reset_ids' return a lambda that has captured-by-value
  // CodegenLLVM's async id state. Running the returned lambda will restore
  // `CodegenLLVM`s async id state back to when this function was first called.
  std::function<void()> create_reset_ids()
  {
    return [FOR_LIST_OF_ASYNC_IDS(LOCAL_SAVE) this] {
      FOR_LIST_OF_ASYNC_IDS(LOCAL_RESTORE)
    };
  }

private:
  FOR_LIST_OF_ASYNC_IDS(DEFINE_MEMBER_VAR)
};

} // namespace bpftrace::ast
