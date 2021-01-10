/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_DEBUG_H
#define VXSSH_DEBUG_H
#include <vxWorks.h>


//#define VXSSH_DEBUG_HOST_KEY
//#define VXSSH_DEBUG_USER_KEY
#define VXSSH_DEBUG_CON_MGR
#define VXSSH_DEBUG_SESSION
//#define VXSSH_DEBUG_KEX_INIT
//#define VXSSH_DEBUG_KEX
//#define VXSSH_DEBUG_KEX_DH
//#define VXSSH_DEBUG_KEX_KEYS


#define VXSSH_INCLUDE_DEBUG_FUNCTIONS
#ifdef VXSSH_INCLUDE_DEBUG_FUNCTIONS
 void vxssh_hexdump(const void *p, size_t len);
 void vxssh_hexdump2(const char *msg, const void *p, size_t len);
#endif

#endif

