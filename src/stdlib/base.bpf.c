#include <stddef.h>

// Unlike standard memcmp, we return 1 for true and 0 for false.
_Bool __memcmp(const char * mem_left, const char * mem_right, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    if (mem_left[i] != mem_right[i]){
      return 0;
    }
  }

  return 1;
}
