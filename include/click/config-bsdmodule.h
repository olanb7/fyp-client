/* include/click/config-bsdmodule.h.  Generated from config-bsdmodule.h.in by configure.  */
/* Process this file with configure to produce config-bsdmodule.h. -*- mode: c -*- */
#ifndef CLICK_CONFIG_BSDMODULE_H
#define CLICK_CONFIG_BSDMODULE_H

/* Define stuff under a FreeBSD module. */
#ifndef __FreeBSD__
# error "I must be compiled on a FreeBSD machine"
#endif
#define KERNEL 1
#define _KERNEL 1
#define KLD_MODULE 1

/* Define if Click should use an adaptive scheduler to share the CPU(s) more
   fairly with the kernel. */
/* #undef HAVE_ADAPTIVE_SCHEDULER */

/* Define if your BSD kernel has polling extensions. */
/* #undef HAVE_BSD_POLLING */

/* Define if your BSD kernel has Click extensions. */
/* #undef HAVE_CLICK_BSD_KERNEL */

/* Define if 'int64_t' is typedefed to 'long' in bsdmodule. */
/* #undef HAVE_INT64_IS_LONG_BSDMODULE */

/* Define if 'int64_t' is typedefed to 'long long' in bsdmodule. */
/* #undef HAVE_INT64_IS_LONG_LONG_BSDMODULE */

/* Include integer and other type definitions. */
#include <sys/types.h>

/* Define assert macro. */
#define assert(x) /* nada */

/* Define likely and unlikely macros. */
#define likely(x)	(x)
#define unlikely(x)	(x)

/* Define HAVE_INT64_IS_LONG based on HAVE_INT64_IS_LONG_BSDMODULE. */
#ifdef HAVE_INT64_IS_LONG_BSDMODULE
# define HAVE_INT64_IS_LONG HAVE_INT64_IS_LONG_BSDMODULE
#endif

/* Define HAVE_INT64_IS_LONG_LONG based on HAVE_INT64_IS_LONG_LONG_BSDMODULE. */
#if HAVE_LONG_LONG && defined(HAVE_INT64_IS_LONG_LONG_BSDMODULE)
# define HAVE_INT64_IS_LONG_LONG HAVE_INT64_IS_LONG_LONG_BSDMODULE
#endif

#ifdef __cplusplus

/* Declare operator new. */
void *operator new(size_t) throw ();
void *operator new[](size_t) throw ();

/* Provide placement new. */
inline void *operator new(size_t, void *v) throw () { return v; }
#define HAVE_PLACEMENT_NEW 1

/* Define macros that surround Click declarations. */
#define CLICK_DECLS		namespace Click {
#define CLICK_ENDDECLS		}
#define CLICK_USING_DECLS	using namespace Click;
#define CLICK_NAME(name)	::Click::name

#endif /* __cplusplus */

#endif /* CLICK_CONFIG_BSDMODULE_H */
