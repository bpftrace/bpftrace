/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_COMPILER_TYPES_H
#define __LINUX_COMPILER_TYPES_H

/*
 * __has_builtin is supported on gcc >= 10, clang >= 3 and icc >= 21.
 * In the meantime, to support gcc < 10, we implement __has_builtin
 * by hand.
 */
#ifndef __has_builtin
#define __has_builtin(x) (0)
#endif

#ifndef __ASSEMBLY__

/*
 * Skipped when running bindgen due to a libclang issue;
 * see https://github.com/rust-lang/rust-bindgen/issues/2244.
 */
#if defined(CONFIG_DEBUG_INFO_BTF) && defined(CONFIG_PAHOLE_HAS_BTF_TAG) && \
	__has_attribute(btf_type_tag) && !defined(__BINDGEN__)
# define BTF_TYPE_TAG(value) __attribute__((btf_type_tag(#value)))
#else
# define BTF_TYPE_TAG(value) /* nothing */
#endif

/* sparse defines __CHECKER__; see Documentation/dev-tools/sparse.rst */
#ifdef __CHECKER__
/* address spaces */
# define __kernel	__attribute__((address_space(0)))
# define __user		__attribute__((noderef, address_space(__user)))
# define __iomem	__attribute__((noderef, address_space(__iomem)))
# define __percpu	__attribute__((noderef, address_space(__percpu)))
# define __rcu		__attribute__((noderef, address_space(__rcu)))
static inline void __chk_user_ptr(const volatile void __user *ptr) { }
static inline void __chk_io_ptr(const volatile void __iomem *ptr) { }
/* context/locking */
# define __must_hold(x)	__attribute__((context(x,1,1)))
# define __acquires(x)	__attribute__((context(x,0,1)))
# define __cond_acquires(x) __attribute__((context(x,0,-1)))
# define __releases(x)	__attribute__((context(x,1,0)))
# define __acquire(x)	__context__(x,1)
# define __release(x)	__context__(x,-1)
# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)
/* other */
# define __force	__attribute__((force))
# define __nocast	__attribute__((nocast))
# define __safe		__attribute__((safe))
# define __private	__attribute__((noderef))
# define ACCESS_PRIVATE(p, member) (*((typeof((p)->member) __force *) &(p)->member))
#else /* __CHECKER__ */
/* address spaces */
# define __kernel
# ifdef STRUCTLEAK_PLUGIN
#  define __user	__attribute__((user))
# else
#  define __user	BTF_TYPE_TAG(user)
# endif
# define __iomem
# define __percpu	__percpu_qual BTF_TYPE_TAG(percpu)
# define __rcu		BTF_TYPE_TAG(rcu)

# define __chk_user_ptr(x)	(void)0
# define __chk_io_ptr(x)	(void)0
/* context/locking */
# define __must_hold(x)
# define __acquires(x)
# define __cond_acquires(x)
# define __releases(x)
# define __acquire(x)	(void)0
# define __release(x)	(void)0
# define __cond_lock(x,c) (c)
/* other */
# define __force
# define __nocast
# define __safe
# define __private
# define ACCESS_PRIVATE(p, member) ((p)->member)
# define __builtin_warning(x, y...) (1)
#endif /* __CHECKER__ */

/* Indirect macros required for expanded argument pasting, eg. __LINE__. */
#define ___PASTE(a,b) a##b
#define __PASTE(a,b) ___PASTE(a,b)

#ifdef __KERNEL__

/* Attributes */
#include <linux/compiler_attributes.h>

#if CONFIG_FUNCTION_ALIGNMENT > 0
#define __function_aligned		__aligned(CONFIG_FUNCTION_ALIGNMENT)
#else
#define __function_aligned
#endif

/*
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-cold-function-attribute
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Label-Attributes.html#index-cold-label-attribute
 *
 * When -falign-functions=N is in use, we must avoid the cold attribute as
 * GCC drops the alignment for cold functions. Worse, GCC can implicitly mark
 * callees of cold functions as cold themselves, so it's not sufficient to add
 * __function_aligned here as that will not ensure that callees are correctly
 * aligned.
 *
 * See:
 *
 *   https://lore.kernel.org/lkml/Y77%2FqVgvaJidFpYt@FVFF77S0Q05N
 *   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=88345#c9
 */
#if defined(CONFIG_CC_HAS_SANE_FUNCTION_ALIGNMENT) || (CONFIG_FUNCTION_ALIGNMENT == 0)
#define __cold				__attribute__((__cold__))
#else
#define __cold
#endif

/*
 * On x86-64 and arm64 targets, __preserve_most changes the calling convention
 * of a function to make the code in the caller as unintrusive as possible. This
 * convention behaves identically to the C calling convention on how arguments
 * and return values are passed, but uses a different set of caller- and callee-
 * saved registers.
 *
 * The purpose is to alleviates the burden of saving and recovering a large
 * register set before and after the call in the caller.  This is beneficial for
 * rarely taken slow paths, such as error-reporting functions that may be called
 * from hot paths.
 *
 * Note: This may conflict with instrumentation inserted on function entry which
 * does not use __preserve_most or equivalent convention (if in assembly). Since
 * function tracing assumes the normal C calling convention, where the attribute
 * is supported, __preserve_most implies notrace.  It is recommended to restrict
 * use of the attribute to functions that should or already disable tracing.
 *
 * Optional: not supported by gcc.
 *
 * clang: https://clang.llvm.org/docs/AttributeReference.html#preserve-most
 */
#if __has_attribute(__preserve_most__) && (defined(CONFIG_X86_64) || defined(CONFIG_ARM64))
# define __preserve_most notrace __attribute__((__preserve_most__))
#else
# define __preserve_most
#endif

/*
 * Annotating a function/variable with __retain tells the compiler to place
 * the object in its own section and set the flag SHF_GNU_RETAIN. This flag
 * instructs the linker to retain the object during garbage-cleanup or LTO
 * phases.
 *
 * Note that the __used macro is also used to prevent functions or data
 * being optimized out, but operates at the compiler/IR-level and may still
 * allow unintended removal of objects during linking.
 *
 * Optional: only supported since gcc >= 11, clang >= 13
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#index-retain-function-attribute
 * clang: https://clang.llvm.org/docs/AttributeReference.html#retain
 */
#if __has_attribute(__retain__) && \
	(defined(CONFIG_LD_DEAD_CODE_DATA_ELIMINATION) || \
	 defined(CONFIG_LTO_CLANG))
# define __retain			__attribute__((__retain__))
#else
# define __retain
#endif

/* Compiler specific macros. */
#ifdef __clang__
#include <linux/compiler-clang.h>
#elif defined(__GNUC__)
/* The above compilers also define __GNUC__, so order is important here. */
#include <linux/compiler-gcc.h>
#else
#error "Unknown compiler"
#endif

/*
 * Some architectures need to provide custom definitions of macros provided
 * by linux/compiler-*.h, and can do so using asm/compiler.h. We include that
 * conditionally rather than using an asm-generic wrapper in order to avoid
 * build failures if any C compilation, which will include this file via an
 * -include argument in c_flags, occurs prior to the asm-generic wrappers being
 * generated.
 */
#ifdef CONFIG_HAVE_ARCH_COMPILER_H
#include <asm/compiler.h>
#endif

struct ftrace_branch_data {
	const char *func;
	const char *file;
	unsigned line;
	union {
		struct {
			unsigned long correct;
			unsigned long incorrect;
		};
		struct {
			unsigned long miss;
			unsigned long hit;
		};
		unsigned long miss_hit[2];
	};
};

struct ftrace_likely_data {
	struct ftrace_branch_data	data;
	unsigned long			constant;
};

#if defined(CC_USING_HOTPATCH)
#define notrace			__attribute__((hotpatch(0, 0)))
#elif defined(CC_USING_PATCHABLE_FUNCTION_ENTRY)
#define notrace			__attribute__((patchable_function_entry(0, 0)))
#else
#define notrace			__attribute__((__no_instrument_function__))
#endif

/*
 * it doesn't make sense on ARM (currently the only user of __naked)
 * to trace naked functions because then mcount is called without
 * stack and frame pointer being set up and there is no chance to
 * restore the lr register to the value before mcount was called.
 */
#define __naked			__attribute__((__naked__)) notrace

/*
 * Prefer gnu_inline, so that extern inline functions do not emit an
 * externally visible function. This makes extern inline behave as per gnu89
 * semantics rather than c99. This prevents multiple symbol definition errors
 * of extern inline functions at link time.
 * A lot of inline functions can cause havoc with function tracing.
 */
#define inline inline __gnu_inline __inline_maybe_unused notrace

/*
 * gcc provides both __inline__ and __inline as alternate spellings of
 * the inline keyword, though the latter is undocumented. New kernel
 * code should only use the inline spelling, but some existing code
 * uses __inline__. Since we #define inline above, to ensure
 * __inline__ has the same semantics, we need this #define.
 *
 * However, the spelling __inline is strictly reserved for referring
 * to the bare keyword.
 */
#define __inline__ inline

/*
 * GCC does not warn about unused static inline functions for -Wunused-function.
 * Suppress the warning in clang as well by using __maybe_unused, but enable it
 * for W=1 build. This will allow clang to find unused functions. Remove the
 * __inline_maybe_unused entirely after fixing most of -Wunused-function warnings.
 */
#ifdef KBUILD_EXTRA_WARN1
#define __inline_maybe_unused
#else
#define __inline_maybe_unused __maybe_unused
#endif

/*
 * Rather then using noinline to prevent stack consumption, use
 * noinline_for_stack instead.  For documentation reasons.
 */
#define noinline_for_stack noinline

/*
 * Use noinline_for_tracing for functions that should not be inlined.
 * For tracing reasons.
 */
#define noinline_for_tracing noinline

/*
 * Sanitizer helper attributes: Because using __always_inline and
 * __no_sanitize_* conflict, provide helper attributes that will either expand
 * to __no_sanitize_* in compilation units where instrumentation is enabled
 * (__SANITIZE_*__), or __always_inline in compilation units without
 * instrumentation (__SANITIZE_*__ undefined).
 */
#ifdef __SANITIZE_ADDRESS__
/*
 * We can't declare function 'inline' because __no_sanitize_address conflicts
 * with inlining. Attempt to inline it may cause a build failure.
 *     https://gcc.gnu.org/bugzilla/show_bug.cgi?id=67368
 * '__maybe_unused' allows us to avoid defined-but-not-used warnings.
 */
# define __no_kasan_or_inline __no_sanitize_address notrace __maybe_unused
# define __no_sanitize_or_inline __no_kasan_or_inline
#else
# define __no_kasan_or_inline __always_inline
#endif

#ifdef __SANITIZE_THREAD__
/*
 * Clang still emits instrumentation for __tsan_func_{entry,exit}() and builtin
 * atomics even with __no_sanitize_thread (to avoid false positives in userspace
 * ThreadSanitizer). The kernel's requirements are stricter and we really do not
 * want any instrumentation with __no_kcsan.
 *
 * Therefore we add __disable_sanitizer_instrumentation where available to
 * disable all instrumentation. See Kconfig.kcsan where this is mandatory.
 */
# define __no_kcsan __no_sanitize_thread __disable_sanitizer_instrumentation
/*
 * Type qualifier to mark variables where all data-racy accesses should be
 * ignored by KCSAN. Note, the implementation simply marks these variables as
 * volatile, since KCSAN will treat such accesses as "marked".
 */
# define __data_racy volatile
# define __no_sanitize_or_inline __no_kcsan notrace __maybe_unused
#else
# define __no_kcsan
# define __data_racy
#endif

#ifdef __SANITIZE_MEMORY__
/*
 * Similarly to KASAN and KCSAN, KMSAN loses function attributes of inlined
 * functions, therefore disabling KMSAN checks also requires disabling inlining.
 *
 * __no_sanitize_or_inline effectively prevents KMSAN from reporting errors
 * within the function and marks all its outputs as initialized.
 */
# define __no_sanitize_or_inline __no_kmsan_checks notrace __maybe_unused
#endif

#ifndef __no_sanitize_or_inline
#define __no_sanitize_or_inline __always_inline
#endif

/*
 * Optional: only supported since gcc >= 15
 * Optional: only supported since clang >= 18
 *
 *   gcc: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108896
 * clang: https://github.com/llvm/llvm-project/pull/76348
 *
 * __bdos on clang < 19.1.2 can erroneously return 0:
 * https://github.com/llvm/llvm-project/pull/110497
 *
 * __bdos on clang < 19.1.3 can be off by 4:
 * https://github.com/llvm/llvm-project/pull/112636
 */
#ifdef CONFIG_CC_HAS_COUNTED_BY
# define __counted_by(member)		__attribute__((__counted_by__(member)))
#else
# define __counted_by(member)
#endif

/*
 * Optional: only supported since gcc >= 15
 * Optional: not supported by Clang
 *
 * gcc: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=117178
 */
#ifdef CONFIG_CC_HAS_MULTIDIMENSIONAL_NONSTRING
# define __nonstring_array		__attribute__((__nonstring__))
#else
# define __nonstring_array
#endif

/*
 * Apply __counted_by() when the Endianness matches to increase test coverage.
 */
#ifdef __LITTLE_ENDIAN
#define __counted_by_le(member)	__counted_by(member)
#define __counted_by_be(member)
#else
#define __counted_by_le(member)
#define __counted_by_be(member)	__counted_by(member)
#endif

/* Do not trap wrapping arithmetic within an annotated function. */
#ifdef CONFIG_UBSAN_INTEGER_WRAP
# define __signed_wrap __attribute__((no_sanitize("signed-integer-overflow")))
#else
# define __signed_wrap
#endif

/* Section for code which can't be instrumented at all */
#define __noinstr_section(section)					\
	noinline notrace __attribute((__section__(section)))		\
	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
	__no_sanitize_memory __signed_wrap

#define noinstr __noinstr_section(".noinstr.text")

/*
 * The __cpuidle section is used twofold:
 *
 *  1) the original use -- identifying if a CPU is 'stuck' in idle state based
 *     on it's instruction pointer. See cpu_in_idle().
 *
 *  2) supressing instrumentation around where cpuidle disables RCU; where the
 *     function isn't strictly required for #1, this is interchangeable with
 *     noinstr.
 */
#define __cpuidle __noinstr_section(".cpuidle.text")

#endif /* __KERNEL__ */

#endif /* __ASSEMBLY__ */

/*
 * The below symbols may be defined for one or more, but not ALL, of the above
 * compilers. We don't consider that to be an error, so set them to nothing.
 * For example, some of them are for compiler specific plugins.
 */
#ifndef __latent_entropy
# define __latent_entropy
#endif

#if defined(RANDSTRUCT) && !defined(__CHECKER__)
# define __randomize_layout __designated_init __attribute__((randomize_layout))
# define __no_randomize_layout __attribute__((no_randomize_layout))
/* This anon struct can add padding, so only enable it under randstruct. */
# define randomized_struct_fields_start	struct {
# define randomized_struct_fields_end	} __randomize_layout;
#else
# define __randomize_layout __designated_init
# define __no_randomize_layout
# define randomized_struct_fields_start
# define randomized_struct_fields_end
#endif

#ifndef __noscs
# define __noscs
#endif

#ifndef __nocfi
# define __nocfi
#endif

/*
 * Any place that could be marked with the "alloc_size" attribute is also
 * a place to be marked with the "malloc" attribute, except those that may
 * be performing a _reallocation_, as that may alias the existing pointer.
 * For these, use __realloc_size().
 */
#ifdef __alloc_size__
# define __alloc_size(x, ...)	__alloc_size__(x, ## __VA_ARGS__) __malloc
# define __realloc_size(x, ...)	__alloc_size__(x, ## __VA_ARGS__)
#else
# define __alloc_size(x, ...)	__malloc
# define __realloc_size(x, ...)
#endif

/*
 * When the size of an allocated object is needed, use the best available
 * mechanism to find it. (For cases where sizeof() cannot be used.)
 *
 * Optional: only supported since gcc >= 12
 *
 *   gcc: https://gcc.gnu.org/onlinedocs/gcc/Object-Size-Checking.html
 * clang: https://clang.llvm.org/docs/LanguageExtensions.html#evaluating-object-size
 */
#if __has_builtin(__builtin_dynamic_object_size)
#define __struct_size(p)	__builtin_dynamic_object_size(p, 0)
#define __member_size(p)	__builtin_dynamic_object_size(p, 1)
#else
#define __struct_size(p)	__builtin_object_size(p, 0)
#define __member_size(p)	__builtin_object_size(p, 1)
#endif

/*
 * Determine if an attribute has been applied to a variable.
 * Using __annotated needs to check for __annotated being available,
 * or negative tests may fail when annotation cannot be checked. For
 * example, see the definition of __is_cstr().
 */
#if __has_builtin(__builtin_has_attribute)
#define __annotated(var, attr)	__builtin_has_attribute(var, attr)
#endif

/*
 * Some versions of gcc do not mark 'asm goto' volatile:
 *
 *  https://gcc.gnu.org/bugzilla/show_bug.cgi?id=103979
 *
 * We do it here by hand, because it doesn't hurt.
 */
#ifndef asm_goto_output
#define asm_goto_output(x...) asm volatile goto(x)
#endif

/*
 * Clang has trouble with constraints with multiple
 * alternative behaviors (mainly "g" and "rm").
 */
#ifndef ASM_INPUT_G
  #define ASM_INPUT_G "g"
  #define ASM_INPUT_RM "rm"
#endif

#ifdef CONFIG_CC_HAS_ASM_INLINE
#define asm_inline asm __inline
#else
#define asm_inline asm
#endif

/* Are two types/vars the same type (ignoring qualifiers)? */
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

/*
 * __unqual_scalar_typeof(x) - Declare an unqualified scalar type, leaving
 *			       non-scalar types unchanged.
 */
/*
 * Prefer C11 _Generic for better compile-times and simpler code. Note: 'char'
 * is not type-compatible with 'signed char', and we define a separate case.
 */
#define __scalar_type_to_expr_cases(type)				\
		unsigned type:	(unsigned type)0,			\
		signed type:	(signed type)0

#define __unqual_scalar_typeof(x) typeof(				\
		_Generic((x),						\
			 char:	(char)0,				\
			 __scalar_type_to_expr_cases(char),		\
			 __scalar_type_to_expr_cases(short),		\
			 __scalar_type_to_expr_cases(int),		\
			 __scalar_type_to_expr_cases(long),		\
			 __scalar_type_to_expr_cases(long long),	\
			 default: (x)))

/* Is this type a native word size -- useful for atomic operations */
#define __native_word(t) \
	(sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || \
	 sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))

#ifdef __OPTIMIZE__
/*
 * #ifdef __OPTIMIZE__ is only a good approximation; for instance "make
 * CFLAGS_foo.o=-Og" defines __OPTIMIZE__, does not elide the conditional code
 * and can break compilation with wrong error message(s). Combine with
 * -U__OPTIMIZE__ when needed.
 */
# define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		/*							\
		 * __noreturn is needed to give the compiler enough	\
		 * information to avoid certain possibly-uninitialized	\
		 * warnings (regardless of the build failing).		\
		 */							\
		__noreturn extern void prefix ## suffix(void)		\
			__compiletime_error(msg);			\
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)
#else
# define __compiletime_assert(condition, msg, prefix, suffix) ((void)(condition))
#endif

#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)

/**
 * compiletime_assert - break build and emit msg if condition is false
 * @condition: a compile-time constant condition to check
 * @msg:       a message to emit if condition is false
 *
 * In tradition of POSIX assert, this macro will break the build if the
 * supplied condition is *false*, emitting the supplied error message if the
 * compiler has support to do so.
 */
#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)

#define compiletime_assert_atomic_type(t)				\
	compiletime_assert(__native_word(t),				\
		"Need native word sized stores/loads for atomicity.")

/* Helpers for emitting diagnostics in pragmas. */
#ifndef __diag
#define __diag(string)
#endif

#ifndef __diag_GCC
#define __diag_GCC(version, severity, string)
#endif

#define __diag_push()	__diag(push)
#define __diag_pop()	__diag(pop)

#define __diag_ignore(compiler, version, option, comment) \
	__diag_ ## compiler(version, ignore, option)
#define __diag_warn(compiler, version, option, comment) \
	__diag_ ## compiler(version, warn, option)
#define __diag_error(compiler, version, option, comment) \
	__diag_ ## compiler(version, error, option)

#ifndef __diag_ignore_all
#define __diag_ignore_all(option, comment)
#endif

#endif /* __LINUX_COMPILER_TYPES_H */
