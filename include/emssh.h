/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_H
#define EMSSH_H

#include <vxWorks.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sockLib.h>
#include <wdLib.h>
#include <shellLib.h>
#include <ptyDrv.h>
#include <errnoLib.h>
#include <logLib.h>
#include <envLib.h>
#include <in.h>
#include <ioLib.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <selectLib.h>
#include <version.h>

#include "mini-gmp.h"
#include "emssh_ssh2.h"
#include "emssh_ctype.h"
#include "emssh_errors.h"
#include "emssh_debug.h"
#include "emssh_log.h"
#include "emssh_mem.h"
#include "emssh_mbuf.h"
#include "emssh_neg.h"
#include "emssh_digest.h"
#include "emssh_hmac.h"
#include "emssh_mac.h"
#include "emssh_cipher.h"
#include "emssh_compress.h"
#include "emssh_kex.h"
#include "emssh_channel.h"
#include "emssh_session.h"
#include "emssh_crypto.h"
#include "emssh_packet.h"

#define EM_SSH_VERSION              "2.0.1"

#define EM_SSH_INCLUDE_SERVER_TEST

/* security options */
#define EM_SSH_HELLO_HIDE_OS_VERSION
#define EM_SSH_LOG_ERROR_AUTH_ATTEMPTS
#define EM_SSH_USE_MEMORY_CLEARING
#define EM_SSH_USE_RANDOM_PADDING
#define EM_SSH_CONSTANT_TIME_INCREMENT

/* limits and default values */
#define EM_SSH_AUTH_TRIES_MAX       3
#define EM_SSH_DEFAULT_PORT         22


typedef enum {
    EM_SSH_AUTH_PUBKEY,
    EM_SSH_AUTH_PASSWORD,
    EM_SSH_AUTH_BOTH
} em_ssh_auth_type_t;

typedef struct {
    char                    *server_key;
    char                    *user_key;
    char                    *listen_address;
    int                     listen_port;
    em_ssh_auth_type_t      auth_type;
} em_ssh_server_config_t;

typedef struct {
    SEM_ID                  sem;
    struct sockaddr_in      srv_addr;
    em_ssh_auth_type_t      auth_type;
    em_ssh_crypto_object_t  *server_key;
    em_ssh_crypto_object_t  *user_key;
    int                     sessions;
    int                     sessions_max;
    int                     auth_tries_max;
    int                     srv_sock;
    int                     con_mgr_tid;
    bool                    fl_running;
    bool                    fl_do_shutdown;
    em_ssh_session_t        *session;

} em_ssh_server_runtime_t;


//----------------------------------------------------------------------------------------------------------
bool em_ssh_server_is_shutdown();
bool em_ssh_server_is_running();
em_ssh_server_runtime_t *em_ssh_server_get_runtime();

#endif

