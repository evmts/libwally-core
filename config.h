#ifndef LIBWALLYCORE_CONFIG_H
#define LIBWALLYCORE_CONFIG_H

/* Auto-generated config.h for Zig builds */
#include <stddef.h>

/* Define if you have unaligned access support */
#if defined(__x86_64__) || defined(__i386__) || defined(__aarch64__) || defined(__arm__)
#define HAVE_UNALIGNED_ACCESS 1
#endif

/* Include CCAN config */
#include "ccan_config.h"

#endif /* LIBWALLYCORE_CONFIG_H */
