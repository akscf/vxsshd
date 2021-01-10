/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

/**
 *
 **/
int vxssh_packet_send_disconnect(vxssh_session_t *session, int reason, char *message) {
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session || !mbuf) {
        return EINVAL;
    }

    vxssh_packet_start(mbuf, SSH_MSG_DISCONNECT);
    vxssh_mbuf_write_u32(mbuf, reason);
    vxssh_mbuf_write_str_sz(mbuf, message);
    vxssh_mbuf_write_u32(mbuf, 0);
    vxssh_packet_end(session, mbuf);

    if((err = vxssh_packet_send(session, mbuf)) != OK) {
        goto out;
    }
out:
    return err;
}

