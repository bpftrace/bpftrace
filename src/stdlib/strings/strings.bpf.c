#define __KERNEL__
#include <asm/errno.h>
#include <asm/posix_types.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>
#include "errors.h"
#include "signal.h"
#include "syscall.h"

extern int bpf_strnlen(const char *s__ign, size_t count) __ksym __weak;

struct strnlen_ctx {
  const char *str;
  __u32 sz;
};

static int strnlen_cb(__u32 index, void *data)
{
  struct strnlen_ctx *ctx = data;
  if (index >= ctx->sz) {
    return 1;
  }
  char ch;
  bpf_probe_read_kernel(&ch, sizeof(char), (void *)(ctx->str + index));
  if (ch == '\0') {
    // terminate the bpf_loop()
    return 1;
  }
  return 0;
}

long __bpf_strnlen(const char *ptr, size_t max_size)
{
  if (bpf_strnlen) {
    return bpf_strnlen(ptr, max_size);
  }
  // To allow the external interface function __bpf_strnlen to be called by
  // other functions in strings.bpf.c and to solve the problem of
  // `The sequence of xxxx jumps is too complex`, bpf_loop() first is used
  // instead of a for loop.
  // TODO: use bpf_for() macro instead of bpf_loop() since linux >= v6.4
  struct strnlen_ctx ctx = {
    .str = ptr,
    .sz = max_size,
  };
  return bpf_loop(max_size, strnlen_cb, &ctx, 0);
}

extern int bpf_strnstr(const char *s1__ign,
                       const char *s2__ign,
                       size_t len) __ksym __weak;

int __bpf_strnstr(const char *haystack,
                   const char *needle,
                   size_t haystack_size,
                   size_t needle_size)
{
  if (bpf_strnstr) {
    return bpf_strnstr(haystack, needle, haystack_size);
  }
  if (needle_size > haystack_size) {
    return -1;
  }
  for (size_t i = 0; i < haystack_size; i++) {
    size_t j;
    if (haystack[i] == 0) {
      break;
    }
    for (j = 0; j < needle_size; j++) {
      if (needle[j] == 0) {
        return (int)i;
      }
      size_t k = i + j;
      if (k > haystack_size) {
        break;
      }
      if (haystack[k] != needle[j]) {
        break;
      }
    }

    if (j == needle_size) {
      return (int)i;
    }
  }
  return -1;
}

long __bpf_str_concat(char *dst, size_t dst_sz, const char *src)
{
  long dst_len = __bpf_strnlen(dst, dst_sz);
  if (dst_len < 0 || dst_len >= dst_sz)
    return 0;
  return bpf_probe_read_kernel_str(dst + dst_len, dst_sz - dst_len, src);
}

int __strerror(int errno, err_str *out) {
  if (errno < 0) {
    errno = -errno;
  }
  if (errno >= 0 && errno < ERROR_INDEX_MASK) {
    errno &= ERROR_INDEX_MASK;

    // The array 'errors' is not fully populated, skip the empty 'errno'.
    //
    // There is another benefit to doing this. BPF 512-byte stack limit.
    // 1. When the code has extremely simple control flow, LLVM will allocate a
    //    64-byte temporary stack buffer, which can exceed the limit when
    //    accumulated.
    // 2. By increasing the complexity of the code control flow, the LLVM
    //    optimization strategy for memcpy was changed, allowing it to avoid
    //    using a temporary stack buffer and instead use more direct memory
    //    access instructions, thereby keeping the stack frame size within
    //    limits.
    if (errors[errno][0] == '\0') {
      __builtin_memcpy(out, &unknown_error, sizeof(*out));
    } else {
      __builtin_memcpy(out, &errors[errno], sizeof(*out));
    }
  } else {
    __builtin_memcpy(out, &unknown_error, sizeof(*out));
  }
  return 0;
}

void __signal_name(int sig, sig_str *out) {
  if (sig >= 0 && sig < SIGNAL_INDEX_MASK) {
    sig &= SIGNAL_INDEX_MASK;

    if (signals[sig][0] == '\0') {
      __builtin_memcpy(out, &unknown_signal, sizeof(*out));
    } else {
      __builtin_memcpy(out, &signals[sig], sizeof(*out));
    }
  } else {
    __builtin_memcpy(out, &unknown_signal, sizeof(*out));
  }
}

int __syscall_name(int n, syscall_str *out) {
  if (n >= 0 && n < SYSCALL_INDEX_MASK) {
    n &= SYSCALL_INDEX_MASK;

    // System call numbers are not sequential, so when syscall_names is empty,
    // we return "unknown system call".
    if (syscall_names[n][0] == '\0') {
      __builtin_memcpy(out, &unknown_syscall, sizeof(*out));
    } else {
      __builtin_memcpy(out, &syscall_names[n], sizeof(*out));
    }
  } else {
    __builtin_memcpy(out, &unknown_syscall, sizeof(*out));
  }
  return 0;
}
