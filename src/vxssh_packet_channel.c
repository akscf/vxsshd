/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"
#define CHANNEL_TYPE_SESSION    "session"
#define CHANNEL_IS_PTY_REQ      "pty-req"
#define CHANNEL_IS_SHELL        "shell"

static int send_open_failure(vxssh_session_t *session, int chid, int reason, char *message) {
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session) {
        return EINVAL;
    }

    vxssh_packet_start(mbuf, SSH_MSG_CHANNEL_OPEN_FAILURE);
    vxssh_mbuf_write_u32(mbuf, chid);
    vxssh_mbuf_write_u32(mbuf, reason);
    vxssh_mbuf_write_str_sz(mbuf, message);
    vxssh_mbuf_write_u32(mbuf, 0);
    vxssh_packet_end(session, mbuf);

    err = vxssh_packet_send(session, mbuf);
    return err;
}

static int send_request_suceess(vxssh_session_t *session, int chid) {
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session) {
        return EINVAL;
    }

    vxssh_packet_start(mbuf, SSH_MSG_CHANNEL_SUCCESS);
    vxssh_mbuf_write_u32(mbuf, chid);
    vxssh_packet_end(session, mbuf);

    err = vxssh_packet_send(session, mbuf);
    return err;
}

static int send_request_failure(vxssh_session_t *session, int chid) {
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session) {
        return EINVAL;
    }

    vxssh_packet_start(mbuf, SSH_MSG_CHANNEL_FAILURE);
    vxssh_mbuf_write_u32(mbuf, chid);
    vxssh_packet_end(session, mbuf);

    err = vxssh_packet_send(session, mbuf);
    return err;
}

// -----------------------------------------------------------------------------------------------------------------
// public
// -----------------------------------------------------------------------------------------------------------------
/**
 *
 **/
int vxssh_packet_do_channel_request(vxssh_session_t *session) {
    vxssh_server_runtime_t *rt = vxssh_server_get_runtime();
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;
    uint32_t chid = 0, itmp = 0;
    uint8_t req_reqply = 0;
    char *ctype = NULL;


    if(!session) {
        return EINVAL;
    }

    if(err = vxssh_packet_expect(mbuf, SSH_MSG_CHANNEL_REQUEST) != OK) {
        goto out;
    }
    /* chid */
    chid = vxssh_mbuf_read_u32(mbuf);

    /* type */
    itmp = vxssh_mbuf_read_u32(mbuf);
    if(itmp == 0 || itmp > 128) {
        err = VXSSH_ERR_PROTO_ERROR;
        goto out;
    }
    if((err = vxssh_mbuf_strdup(mbuf, &ctype, (size_t *)&itmp)) != OK) {
        goto out;
    }
    req_reqply = vxssh_mbuf_read_u8(mbuf);

    /* pty */
    if(vxssh_str_equal(CHANNEL_IS_PTY_REQ, strlen(CHANNEL_IS_PTY_REQ), ctype, itmp)) {
        if((err = vxssh_channel_create_pty(session->channel)) == OK) {
            if(req_reqply) {
                err = send_request_suceess(session, chid);
            }
            goto out;
        }
        vxssh_log_warn("pty_create() fail (%i)", err);
        goto reject;
    }

    /* shell */
    if(vxssh_str_equal(CHANNEL_IS_SHELL, strlen(CHANNEL_IS_SHELL), ctype, itmp)) {
        if((err = vxssh_channel_start_shell(session->channel)) == OK) {
            if(req_reqply) {
                err = send_request_suceess(session, chid);
            }
            goto out;
        }
        vxssh_log_warn("start_shell() fail (%i)", err);
        goto reject;
    }

reject:
    if(req_reqply) {
        err = send_request_failure(session, chid);
    }

out:
    vxssh_mem_deref(ctype);
    return err;
}

/**
 *
 **/
int vxssh_packet_do_channel_open(vxssh_session_t *session) {
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;
    uint32_t chid = 0, iwsz = 0, mpsz = 0, itmp = 0;
    char *ctype = NULL;

    if(!session) {
        return EINVAL;
    }

    if(err = vxssh_packet_expect(mbuf, SSH_MSG_CHANNEL_OPEN) != OK) {
        goto out;
    }

    /* channel type */
    itmp = vxssh_mbuf_read_u32(mbuf);
    if(itmp == 0 || itmp > 128) {
        err = VXSSH_ERR_PROTO_ERROR;
        goto out;
    }
    if((err = vxssh_mbuf_strdup(mbuf, &ctype,(size_t *)&itmp)) != OK) {
        goto out;
    }
    chid = vxssh_mbuf_read_u32(mbuf);
    iwsz = vxssh_mbuf_read_u32(mbuf);
    mpsz = vxssh_mbuf_read_u32(mbuf);
    if(mpsz > VXSSH_PACKET_PAYLOAD_SIZE_MAX) {
        mpsz = VXSSH_PACKET_PAYLOAD_SIZE_MAX;
    }
    if(session->channel != NULL) {
        err = send_open_failure(session, chid, SSH_OPEN_RESOURCE_SHORTAGE, "Too many opened channels");
        goto out;
    }

    if(!vxssh_str_equal(CHANNEL_TYPE_SESSION, strlen(CHANNEL_TYPE_SESSION), ctype, itmp)) {
        err = send_open_failure(session, chid, SSH_OPEN_UNKNOWN_CHANNEL_TYPE, "Unsupported channel type");
        goto out;
    }

    /* create channel */
    if((err = vxssh_channel_alloc(&session->channel, chid, iwsz, mpsz)) != OK) {
        err = send_open_failure(session, chid, SSH_OPEN_RESOURCE_SHORTAGE, "No enough resources");
        goto out;
    }

    /* send confirmation */
    vxssh_packet_start(mbuf, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    vxssh_mbuf_write_u32(mbuf, session->channel->id); /* recipient */
    vxssh_mbuf_write_u32(mbuf, session->channel->id); /* sender*/
    vxssh_mbuf_write_u32(mbuf, session->channel->local_wsz);
    vxssh_mbuf_write_u32(mbuf, session->channel->packet_size);
    vxssh_packet_end(session, mbuf);

    if((err = vxssh_packet_send(session, mbuf)) != OK) {
        goto out;
    }

out:
    vxssh_mem_deref(ctype);
    return err;
}


/**
 * correct session iobuffer pos
 **/
int vxssh_packet_do_channel_data(vxssh_session_t *session, size_t *data_len) {
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;
    uint32_t chid = 0, dsz = 0;

    if(!session) {
        return EINVAL;
    }
    if(err = vxssh_packet_expect(mbuf, SSH_MSG_CHANNEL_DATA) != OK) {
        goto out;
    }

    chid = vxssh_mbuf_read_u32(mbuf);
    if(session->channel == NULL || session->channel->id != chid) {
        vxssh_log_warn("unknwon channel: %i", chid);
        *data_len = 0;
        goto out;
    }
    if(session->channel->feof) {
        vxssh_log_warn("channel already eof");
        *data_len = 0;
        goto out;
    }

    dsz = vxssh_mbuf_read_u32(mbuf);
    *data_len = dsz;

out:
    return err;
}

/**
 *
 **/
int vxssh_packet_do_channel_eof(vxssh_session_t *session) {
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;
    uint32_t chid = 0;

    if(!session) {
        return EINVAL;
    }
    if(err = vxssh_packet_expect(mbuf, SSH_MSG_CHANNEL_EOF) != OK) {
        goto out;
    }

    chid = vxssh_mbuf_read_u32(mbuf);
    if(session->channel == NULL || session->channel->id != chid) {
        vxssh_log_warn("unknwon channel: %i", chid);
        goto out;
    }

    vxssh_channel_eof(session->channel);

out:
    return err;
}

/**
 *
 **/
int vxssh_packet_do_channel_close(vxssh_session_t *session) {
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;
    uint32_t chid = 0;

    if(!session) {
        return EINVAL;
    }
    if(err = vxssh_packet_expect(mbuf, SSH_MSG_CHANNEL_CLOSE) != OK) {
        goto out;
    }

    chid = vxssh_mbuf_read_u32(mbuf);
    if(session->channel == NULL || session->channel->id != chid) {
        vxssh_log_warn("unknwon channel: %i", chid);
        goto out;
    }

    vxssh_channel_close(session->channel);

out:
    return err;
}


// -----------------------------------------------------------------------------------------------------------------
/***
 *
 **/
int vxssh_packet_send_channel_eof(vxssh_session_t *session, vxssh_channel_t *channel) {
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session || !channel) {
        return EINVAL;
    }

    vxssh_packet_start(mbuf, SSH_MSG_CHANNEL_EOF);
    vxssh_mbuf_write_u32(mbuf, channel->id);
    vxssh_packet_end(session, mbuf);

    err = vxssh_packet_send(session, mbuf);
    return err;
}

/***
 *
 **/
int vxssh_packet_send_channel_close(vxssh_session_t *session, vxssh_channel_t *channel) {
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session || !channel) {
        return EINVAL;
    }

    vxssh_packet_start(mbuf, SSH_MSG_CHANNEL_CLOSE);
    vxssh_mbuf_write_u32(mbuf, channel->id);
    vxssh_packet_end(session, mbuf);

    err = vxssh_packet_send(session, mbuf);
    return err;
}

/***
 *
 **/
int vxssh_packet_send_channel_data(vxssh_session_t *session, vxssh_channel_t *channel, uint8_t *data, size_t data_len) {
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session || !channel) {
        return EINVAL;
    }

    vxssh_packet_start(mbuf, SSH_MSG_CHANNEL_DATA);
    vxssh_mbuf_write_u32(mbuf, channel->id);
    vxssh_mbuf_write_mem_sz(mbuf, data, data_len);
    vxssh_packet_end(session, mbuf);

    err = vxssh_packet_send(session, mbuf);
    return err;
}
