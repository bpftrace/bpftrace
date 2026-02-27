#define __KERNEL__
#include <asm/errno.h>
#include <asm/posix_types.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>

#include <bpf/bpf_helpers.h>
#include "errors.h"
#include "syscall.h"

extern int bpf_strnlen(const char *s__ign, size_t count) __ksym __weak;

long __bpf_strnlen(const char *ptr, size_t max_size)
{
  if (bpf_strnlen) {
    return bpf_strnlen(ptr, max_size);
  }
  long sz = 0;
  for (size_t i = 0; i < max_size; ++i) {
    if (ptr[i] == 0) {
      break;
    }
    ++sz;
  }
  return sz;
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

bool __bpf_glob_match(const char *str, size_t str_size, const char *pat, size_t pat_size)
{
  /*
   * Backtrack to previous * on mismatch and retry starting one
   * character later in the string.  Because * matches all characters
   * (no exception for /), it can be easily proved that there's
   * never a need to backtrack multiple levels.
   */
  ptrdiff_t back_pat = -1;
  size_t back_str = 0;

  size_t s = 0; /* Index into str */
  size_t p = 0; /* Index into pat */

  /*
   * Loop over each token (character or class) in pat, matching
   * it against the remaining unmatched tail of str.  Return false
   * on mismatch, or true after matching the trailing nul bytes.
   */
  for (;;) {
    /*
     * Strings may run to the full size without a final NUL, or they may be
     * terminated early by a NUL. Handle this by wrapping all string accesses
     * with checks that produce '\0' when reading past the end.
     */
    unsigned char c = s < str_size ? str[s++] : '\0';
    unsigned char d = p < pat_size ? pat[p++] : '\0';

    switch (d) {
    case '?':  /* Wildcard: anything but nul */
      if (c == '\0')
        return false;
      break;
    case '*': {  /* Any-length wildcard */
      char pat_next = p < pat_size ? pat[p] : '\0';
      if (pat_next == '\0')  /* Optimize trailing * case */
        return true;
      back_pat = p;
      back_str = s > 0 ? --s : 0;  /* Allow zero-length match */
      }
      break;
    case '[': {  /* Character class */
      unsigned char pat_next = p < pat_size ? pat[p] : '\0';
      bool match = false, inverted = (pat_next == '!');
      size_t class = p + inverted;
      unsigned char a = class < pat_size ? pat[class++] : '\0';

      /*
       * Iterate over each span in the character class.
       * A span is either a single character a, or a
       * range a-b.  The first span may begin with ']'.
       */
      do {
        unsigned char b = a;

        if (a == '\0')  /* Malformed */
          goto literal;

        if (class + 2 < pat_size && pat[class] == '-' && pat[class + 1] != ']') {
          b = pat[class + 1];

          if (b == '\0')
            goto literal;

          class += 2;
        }
        match |= (a <= c && c <= b);
        a = class < pat_size ? pat[class++] : '\0';
      } while (a != ']');

      if (match == inverted)
        goto backtrack;
      p = class;
      }
      break;
    case '\\':
      d = p < pat_size ? pat[p++] : '\0';
      fallthrough;
    default:  /* Literal character */
literal:
      if (c == d) {
        if (d == '\0')
          return true;
        break;
      }
backtrack:
      if (c == '\0' || back_pat < 0)
        return false;  /* No point continuing */
      /* Try again from last *, one character later in str. */
      p = back_pat;
      s = ++back_str;
      break;
    }
  }
  return false;
}

int __strerror(int errno, err_str *out) {
  if (errno < 0) {
    errno = -errno;
  }
  if (errno >= 0 && errno <= EHWPOISON) {
    __builtin_memcpy(out, &errors[errno], sizeof(*out));
  } else {
    __builtin_memcpy(out, &unknown_error, sizeof(*out));
  }
  return 0;
}

int __syscall_name(int n, syscall_str *out) {
  if (n >= 0 && n < NR_SYSCALL_ALIGN_BITS) {
    // To resolve the verifier's complaint that the off range is too large,
    // resulting in "possible" access beyond the range of syscall_names[],
    // we use a constant value to constrain n to help the verifier.
    n &= NR_SYSCALL_ALIGN_BITS;

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
