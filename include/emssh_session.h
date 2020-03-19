/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_SESSION_H
#define EMSSH_SESSION_H

#include <vxWorks.h>
#include "emssh_ctype.h"
#include "emssh_channel.h"
#include "emssh_kex.h"

typedef enum {
    EM_SSH_SESSION_STATE_HELLO,
    EM_SSH_SESSION_STATE_NEG,
    EM_SSH_SESSION_STATE_AUTH,
    EM_SSH_SESSION_STATE_WORK,
    EM_SSH_SESSION_STATE_TERMINATE
} em_ssh_session_state_t;


typedef struct {
    int                     id;
    int                     socfd;
    char                    *peerip;    /* client ip */
    char                    *username;  /* authorized username */
    em_ssh_session_state_t  state;
    em_ssh_kex_t            *kex;
    em_ssh_mbuf_t           *iobuf;
    em_ssh_channel_t        *channel;
    uint32_t                send_seq;
    uint32_t                recv_seq;
    bool                    fl_rekeying_done;
    bool                    fl_authorized;

} em_ssh_session_t;

int em_ssh_session_alloc(em_ssh_session_t **session);
int em_ssh_session_set_peerip(em_ssh_session_t *session, char *ip);
int em_ssh_session_start_io_helper(em_ssh_session_t *session);

#endif
