/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_DEBUG_H
#define EMSSH_DEBUG_H
#include <vxWorks.h>


//#define EM_SSH_DEBUG_HOST_KEY
//#define EM_SSH_DEBUG_USER_KEY
#define EM_SSH_DEBUG_CON_MGR
#define EM_SSH_DEBUG_SESSION
//#define EM_SSH_DEBUG_KEX_INIT
//#define EM_SSH_DEBUG_KEX
//#define EM_SSH_DEBUG_KEX_DH
//#define EM_SSH_DEBUG_KEX_KEYS



#define EM_SSH_DEBUG_FUNC_INCLUDE
#ifdef EM_SSH_DEBUG_FUNC_INCLUDE
 void em_ssh_hexdump(const void *p, size_t len);
 void em_ssh_hexdump2(const char *msg, const void *p, size_t len);
#endif

#endif

