/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_H
#define VXSSH_H

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
#include "vxssh_ssh2.h"
#include "vxssh_ctype.h"
#include "vxssh_errors.h"
#include "vxssh_debug.h"
#include "vxssh_log.h"
#include "vxssh_mem.h"
#include "vxssh_mbuf.h"
#include "vxssh_neg.h"
#include "vxssh_digest.h"
#include "vxssh_hmac.h"
#include "vxssh_mac.h"
#include "vxssh_cipher.h"
#include "vxssh_compress.h"
#include "vxssh_kex.h"
#include "vxssh_channel.h"
#include "vxssh_session.h"
#include "vxssh_crypto.h"
#include "vxssh_packet.h"

#define VXSSH_VERSION              "2.0.1"

/* tests */
#define VXSSH_INCLUDE_SERVER_TEST

/* security options */
#define VXSSH_HELLO_HIDE_OS_INFO
#define VXSSH_MEMORY_CLEAR_ON_DEREF
#define VXSSH_USE_RANDOM_PADDING
#define VXSSH_LOG_ERROR_AUTH_ATTEMPTS
#define VXSSH_CONSTANT_TIME_INCREMENT

/* limits and default values */
#define VXSSH_AUTH_TRIES_MAX       3
#define VXSSH_DEFAULT_PORT         22


typedef enum {
    VXSSH_AUTH_PUBKEY,
    VXSSH_AUTH_PASSWORD,
    VXSSH_AUTH_BOTH
} vxssh_auth_type_t;

typedef struct {
    char                    *server_key;
    char                    *user_key;
    char                    *listen_address;
    int                     listen_port;
    vxssh_auth_type_t      auth_type;
} vxssh_server_config_t;

typedef struct {
    SEM_ID                  sem;
    struct sockaddr_in      srv_addr;
    vxssh_auth_type_t      auth_type;
    vxssh_crypto_object_t  *server_key;
    vxssh_crypto_object_t  *user_key;
    int                     sessions;
    int                     sessions_max;
    int                     auth_tries_max;
    int                     srv_sock;
    int                     con_mgr_tid;
    bool                    fl_running;
    bool                    fl_do_shutdown;
    vxssh_session_t        *session;

} vxssh_server_runtime_t;


//----------------------------------------------------------------------------------------------------------
bool vxssh_server_is_shutdown();
bool vxssh_server_is_running();
vxssh_server_runtime_t *vxssh_server_get_runtime();

#endif

