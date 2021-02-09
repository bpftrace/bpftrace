#ifdef HAVE_SYSTEMTAP_SYS_SDT_H
#include <sys/sdt.h>
#else
#define DTRACE_PROBE1(a, b, d) (void)0
#endif
#include <stddef.h>
#include <stdint.h>
/* For best results compile using gcc -O1 (or higher)
 *
 * Clang likes to always put the argument on stack rather than outputting an
 * operand to access it directly.
 *
 * Note: The macros might not always output the type of probe claimed as this
 * varies depending on compiler and optimisation settings.
 *
 * So I've used macros to make the repeated code easier to fix in the
 * future.
 */

#if (defined(__GNUC__) && !defined(__clang__))
#pragma GCC optimize("O1")
#else
#pragma message("non-gcc compiler: the correct probes might not be installed")
#endif

#define test_value 0xf7f6f5f4f3f2f1f0
volatile uint64_t one = 1;

typedef union all_types
{
  int8_t i_8;
  uint8_t i_u8;
  uint16_t i_u16;
  int16_t i_16;
  uint32_t i_u32;
  int32_t i_32;
  uint64_t i_u64;
  int64_t i_64;
} all_types_t;

#ifdef __x86_64__
/* Force the value to be stored in a register, works for both gcc and clang
 *
 * PROBE_REG(al, u, 8) expands to:
 * register uint8_t _reg_u8 asm("al") = (uint8_t)test_value;
 * DTRACE_PROBE1(usdt_args, reg_u8, _reg_u8)
 */
#define PROBE_REG(register_, sign, size)                                       \
  register sign##int##size##_t _reg_##sign##size asm(                          \
      #register_) = (sign##int##size##_t)test_value;                           \
  DTRACE_PROBE1(usdt_args, reg_##sign##size, _reg_##sign##size)
#else
/* Force a calculation to get the value into a register
 * works for gcc (-O1+) but not clang
 *
 * PROBE_REG(al, u, 8) expands to:
 * uint8_t _reg_u8 = (uint8_t)(test_value * one);
 * DTRACE_PROBE1(usdt_args, reg_u8, _reg_u8);
 * */
#define PROBE_REG(register_, sign, size)                                       \
  sign##int##size##_t _reg_##sign##size = (sign##int##size##_t)(test_value *   \
                                                                one);          \
  DTRACE_PROBE1(usdt_args, reg_##sign##size, _reg_##sign##size)
#endif

/* Read a value of the stack, expect an offset here
 * Works with optimisation -O1+
 *
 * PROBE_ADDRESS(u, 8) expands to:
 * array[1].i_u8 = (uint8_t) test_value;
 * DTRACE_PROBE1(usdt_args, addr_u8, array[1].i_u8)
 */
#define PROBE_ADDRESS(sign, size)                                              \
  array[1].i_##sign##size = (sign##int##size##_t)test_value;                   \
  DTRACE_PROBE1(usdt_args, addr_##sign##size, array[1].i_##sign##size)

/* Read a value of the stack, expect an offset here
 * Works only with gcc optimisation -O1+
 *
 * PROBE_INDEX(u, 8) expands to:
 * DTRACE_PROBE1(usdt_args, index_u8, array[i].i_u8)
 */
#define PROBE_INDEX(sign, size)                                                \
  DTRACE_PROBE1(usdt_args, index_##sign##size, array[i].i_##sign##size)

int main(int argc, char **argv)
{
  (void)argv;
  volatile all_types_t array[10];

  if (argc > 1)
  // If we don't have Systemtap headers, we should skip USDT tests. Returning 1
  // can be used as validation in the REQUIRE
#ifndef HAVE_SYSTEMTAP_SYS_SDT_H
    return 1;
#else
    return 0;
#endif

  for (volatile size_t i = 0; i < sizeof(array) / sizeof(array[0]); i++)
  {
    array[i].i_u64 = test_value;
  }

#ifdef HAVE_SYSTEMTAP_SYS_SDT_H
  /* Constants */
  DTRACE_PROBE1(usdt_args, const_u64, (uint64_t)test_value);
  DTRACE_PROBE1(usdt_args, const_64, (int64_t)test_value);
  DTRACE_PROBE1(usdt_args, const_u32, (uint32_t)test_value);
  DTRACE_PROBE1(usdt_args, const_32, (int32_t)test_value);
  DTRACE_PROBE1(usdt_args, const_u16, (uint16_t)test_value);
  DTRACE_PROBE1(usdt_args, const_16, (int16_t)test_value);
  DTRACE_PROBE1(usdt_args, const_u8, (uint8_t)test_value);
  DTRACE_PROBE1(usdt_args, const_8, (int8_t)test_value);

  /* Direct register reads - start from 64 and work down
   * to verify the correct number of bytes are read */
  PROBE_REG(rax, u, 64);
  PROBE_REG(rax, , 64);
  PROBE_REG(eax, u, 32);
  PROBE_REG(eax, , 32);
  PROBE_REG(ax, u, 16);
  PROBE_REG(ax, , 16);
  PROBE_REG(al, u, 8);
  PROBE_REG(al, , 8);

  /* Base address most likely with and offset(aka. displacement) */
  PROBE_ADDRESS(u, 64);
  PROBE_ADDRESS(, 64);
  PROBE_ADDRESS(u, 32);
  PROBE_ADDRESS(, 32);
  PROBE_ADDRESS(u, 16);
  PROBE_ADDRESS(, 16);
  PROBE_ADDRESS(u, 8);
  PROBE_ADDRESS(, 8);

  /* Base address + offset + (index * scale) */
  for (volatile int i = 7; i <= 7; i++)
  {
    PROBE_INDEX(u, 64);
    PROBE_INDEX(, 64);
    PROBE_INDEX(u, 32);
    PROBE_INDEX(, 32);
    PROBE_INDEX(u, 16);
    PROBE_INDEX(, 16);
    PROBE_INDEX(u, 8);
    PROBE_INDEX(, 8);
  }

/* TLS not yet supported, need label and segment support */
#if 0
  volatile static __thread uint64_t tls_64 = (uint64_t)test_value;
  DTRACE_PROBE1(usdt_args, tls_u64, tls_64);
#endif
#endif /* HAVE_SYSTEMTAP_SYS_SDT_H */

  return 0;
}
