/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_SESSION_H
#define VXSSH_SESSION_H

#include <vxWorks.h>
#include "vxssh_ctype.h"
#include "vxssh_channel.h"
#include "vxssh_kex.h"

typedef enum {
    VXSSH_SESSION_STATE_HELLO,
    VXSSH_SESSION_STATE_NEG,
    VXSSH_SESSION_STATE_AUTH,
    VXSSH_SESSION_STATE_WORK,
    VXSSH_SESSION_STATE_TERMINATE
} vxssh_session_state_t;


typedef struct {
    int                     id;
    int                     socfd;
    char                    *peerip;    /* client ip */
    char                    *username;  /* authorized username */
    vxssh_session_state_t  state;
    vxssh_kex_t            *kex;
    vxssh_mbuf_t           *iobuf;
    vxssh_channel_t        *channel;
    uint32_t                send_seq;
    uint32_t                recv_seq;
    bool                    fl_rekeying_done;
    bool                    fl_authorized;

} vxssh_session_t;

int vxssh_session_alloc(vxssh_session_t **session);
int vxssh_session_set_peerip(vxssh_session_t *session, char *ip);
int vxssh_session_start_io_helper(vxssh_session_t *session);

#endif
