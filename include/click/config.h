/* include/click/config.h.  Generated from config.h.in by configure.  */
/* Process this file with configure to produce config.h. -*- mode: c -*- */
#ifndef CLICK_CONFIG_H
#define CLICK_CONFIG_H

/* Define to byte order of target machine. */
#define CLICK_BYTE_ORDER 1234
#define CLICK_BIG_ENDIAN	4321
#define CLICK_LITTLE_ENDIAN	1234
#define CLICK_NO_ENDIAN		0

/* Define for Click memory allocation debugging. */
/* #undef CLICK_DMALLOC */

/* Version number of package */
#define CLICK_VERSION "1.7.0rc1"

/* Version number of package, in CLICK_MAKE_VERSION_CODE format */
#define CLICK_VERSION_CODE CLICK_MAKE_VERSION_CODE(1,7,0rc1)

/* Define to desired statistics level. */
#define CLICK_STATS 0

/* Define if PollDevice should run fast to get good benchmark numbers */
/* #undef CLICK_WARP9 */

/* Define if you have the __builtin_clz function. */
#define HAVE___BUILTIN_CLZ 1

/* Define if you have the __builtin_clzl function. */
#define HAVE___BUILTIN_CLZL 1

/* Define if you have the __builtin_clzll function. */
#define HAVE___BUILTIN_CLZLL 1

/* Define if you have the __builtin_ffs function. */
#define HAVE___BUILTIN_FFS 1

/* Define if you have the __builtin_ffsl function. */
#define HAVE___BUILTIN_FFSL 1

/* Define if you have the __builtin_ffsll function. */
#define HAVE___BUILTIN_FFSLL 1

/* Define if the va_list type is addressable. */
#define HAVE_ADDRESSABLE_VA_LIST 1

/* Define if right shift of signed integers acts by sign extension. */
#define HAVE_ARITHMETIC_RIGHT_SHIFT 1

/* Define if the machine is indifferent to alignment. */
#define HAVE_INDIFFERENT_ALIGNMENT 1

/* Define if you want to use Intel-specific instructions. */
/* #undef HAVE_INTEL_CPU */

/* Define if 64-bit integer types are enabled. */
#define HAVE_INT64_TYPES 1

/* Define if IPv6 support is enabled. */
/* #undef HAVE_IP6 */

/* Define if IPsec support is enabled. */
/* #undef HAVE_IPSEC */

/* Define to 1 if the system has the type `long long'. */
#define HAVE_LONG_LONG 1

/* Define if nanosecond-granularity timestamps are enabled. */
/* #undef HAVE_NANOTIMESTAMP_ENABLED */

/* Define if you want to use the stride scheduler. */
#define HAVE_STRIDE_SCHED 1

/* Define to 1 since we have Strings. */
#define HAVE_STRING 1

/* Define to 1 if the system has the type `struct timespec'. */
#define HAVE_STRUCT_TIMESPEC 1

#ifdef HAVE_STRIDE_SCHED
/* Define if you want task scheduling to use a heap, not a linked list. */
/* #undef HAVE_TASK_HEAP */
#endif

/* The size of a `int', as computed by sizeof. */
#define SIZEOF_INT 4

/* The size of a `long', as computed by sizeof. */
#define SIZEOF_LONG 4

/* The size of a `long long', as computed by sizeof. */
#define SIZEOF_LONG_LONG 8

/* The size of a `size_t', as computed by sizeof. */
#define SIZEOF_SIZE_T 4

/* The size of a `struct timespec', as computed by sizeof. */
#define SIZEOF_STRUCT_TIMESPEC 8

/* The size of a `struct timeval', as computed by sizeof. */
#define SIZEOF_STRUCT_TIMEVAL 8

/* Define if you want to run multithreaded Click. */
/* #undef __MTCLICK__ */
#define NUM_CLICK_CPUS 1

#ifndef __cplusplus
/* Define inline, if necessary. C only. */
/* #undef inline */
#endif

#ifdef __cplusplus
/* Explicit template instances? */
#if __GNUC__ == 2 && __GNUC_MINOR__ < 90
#define EXPLICIT_TEMPLATE_INSTANCES 1
#endif
#endif /* __cplusplus */

/* Define macro for creating Click version codes (a la Linux version codes). */
#define CLICK_MAKE_VERSION_CODE(major, minor, patch) \
		(((major) << 16) | ((minor) << 8) | (patch))

/* Define macros for declaring packed structures. */
#ifdef __GNUC__
#define CLICK_PACKED_STRUCTURE(open, close) open close __attribute__((packed))
#define CLICK_SIZE_PACKED_STRUCTURE(open, close) open close __attribute__((packed)) /* deprecated */
#define CLICK_SIZE_PACKED_ATTRIBUTE __attribute__((packed))
#else
#define CLICK_PACKED_STRUCTURE(open, close) _Cannot_pack_structure__Use_GCC
#define CLICK_SIZE_PACKED_STRUCTURE(open, close) open close /* deprecated */
#define CLICK_SIZE_PACKED_ATTRIBUTE
#endif

/* Define macro for deprecated functions. */
#if __GNUC__ < 3 || (__GNUC__ == 3 && __GNUC_MINOR__ == 0)
# define CLICK_DEPRECATED /* nothing */
#else
# define CLICK_DEPRECATED __attribute__((deprecated))
#endif

/* Define macro for deprecated enumerations. */
#if __GNUC__ < 3 || (__GNUC__ == 3 && __GNUC_MINOR__ < 4)
# define CLICK_DEPRECATED_ENUM /* nothing */
#else
# define CLICK_DEPRECATED_ENUM __attribute__((deprecated))
#endif

/* Define macro for functions whose results should not be ignored. */
#if __GNUC__ < 3 || (__GNUC__ == 3 && __GNUC_MINOR__ < 4)
# define CLICK_WARN_UNUSED_RESULT /* nothing */
#else
# define CLICK_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#endif

/* Define ARCH_IS_BIG_ENDIAN based on CLICK_BYTE_ORDER. */
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
# define ARCH_IS_BIG_ENDIAN	1
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
# define ARCH_IS_BIG_ENDIAN	0
#endif

/* Define macro for htons() on constants (allows htons() in switch cases). */
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
# define click_constant_htons(x)	(x)
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
# define click_constant_htons(x)	((((x) >> 8) & 255) | (((x) & 255) << 8))
#endif

/* EXPORT_ELEMENT, ELEMENT_REQUIRES, ELEMENT_PROVIDES, ELEMENT_HEADER,
   ELEMENT_LIBS, and ELEMENT_MT_SAFE are noops. */
#define EXPORT_ELEMENT(x)
#define ELEMENT_REQUIRES(x)
#define ELEMENT_PROVIDES(x)
#define ELEMENT_HEADER(x)
#define ELEMENT_LIBS(x)
#define ELEMENT_MT_SAFE(x)

/* Assume CLICK_USERLEVEL unless otherwise defined. */
#if !defined(CLICK_USERLEVEL) && !defined(CLICK_TOOL) && !defined(CLICK_LINUXMODULE) && !defined(CLICK_BSDMODULE)
# define CLICK_USERLEVEL 1
#endif

/* Define stuff under a Linux module. */
#ifdef CLICK_LINUXMODULE
# include <click/config-linuxmodule.h>
#endif

/* Define stuff under a FreeBSD module. */
#ifdef CLICK_BSDMODULE
# include <click/config-bsdmodule.h>
#endif

/* Define stuff under nsclick. */
#ifdef CLICK_NS
# include <click/config-ns.h>
#endif

/* Define stuff under tools or a user-level driver. */
#if defined(CLICK_USERLEVEL) || defined(CLICK_TOOL)
# include <click/config-userlevel.h>
#endif

#endif /* CLICK_CONFIG_H */
