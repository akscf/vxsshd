/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

static  void mem_destructor_vxssh_session_t(void *data) {
    vxssh_session_t *session = data;
    //
    if(session->socfd) {
        close(session->socfd);
    }

    vxssh_mem_deref(session->iobuf);
    vxssh_mem_deref(session->kex);
    vxssh_mem_deref(session->peerip);
    vxssh_mem_deref(session->username);
    vxssh_mem_deref(session->channel);
}

// ----------------------------------------------------------------------------------------------------------------------------------------
// public api
// ----------------------------------------------------------------------------------------------------------------------------------------
/**
 *
 **/
int vxssh_session_alloc(vxssh_session_t **session) {
    int err = OK;
    vxssh_session_t *tses = NULL;

    if(!session) {
        return EINVAL;
    }

    if((tses = vxssh_mem_zalloc(sizeof(vxssh_session_t), mem_destructor_vxssh_session_t)) == NULL) {
        err = ENOMEM;
        goto out;
    }
    tses->state = VXSSH_SESSION_STATE_HELLO;
    tses->recv_seq = 0;
    tses->send_seq = 0;

    if((err = vxssh_mbuf_alloc(&tses->iobuf, 2048)) != OK) {
        goto out;
    }

    if((err = vxssh_kex_alloc(&tses->kex)) != OK) {
        err = ENOMEM;
        goto out;
    }

    *session = tses;

out:
    if(err != OK) {
        vxssh_mem_deref(tses);
    }
    return err;
}

/**
 *
 **/
int vxssh_session_set_peerip(vxssh_session_t *session, char *ip) {
    size_t len = ip ? strlen(ip) : 0;

    if(!session || !ip || len > 64) {
        return EINVAL;
    }

    if((session->peerip = vxssh_mem_zalloc(len + 1, NULL)) == NULL) {
        return ENOMEM;
    }

    memcpy(session->peerip, ip, len);

    return OK;
}

