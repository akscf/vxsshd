/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_CTYPE_H
#define VXSSH_CTYPE_H

#include <vxWorks.h>

#ifndef true
 #define true    1
 #undef  false
 #define false   0
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) ((sizeof(a))/(sizeof((a)[0])))
#endif

#ifndef MIN
#define MIN(a, b) (((a)<(b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a)>(b)) ? (a) : (b))
#endif


typedef unsigned char bool;

#endif



