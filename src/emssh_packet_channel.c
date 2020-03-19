/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"
#define CHANNEL_TYPE_SESSION    "session"
#define CHANNEL_IS_PTY_REQ      "pty-req"
#define CHANNEL_IS_SHELL        "shell"

static int send_open_failure(em_ssh_session_t *session, int chid, int reason, char *message) {
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session) {
        return EINVAL;
    }

    em_ssh_packet_start(mbuf, SSH_MSG_CHANNEL_OPEN_FAILURE);
    em_ssh_mbuf_write_u32(mbuf, chid);
    em_ssh_mbuf_write_u32(mbuf, reason);
    em_ssh_mbuf_write_str_sz(mbuf, message);
    em_ssh_mbuf_write_u32(mbuf, 0);
    em_ssh_packet_end(session, mbuf);

    err = em_ssh_packet_send(session, mbuf);
    return err;
}

static int send_request_suceess(em_ssh_session_t *session, int chid) {
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session) {
        return EINVAL;
    }

    em_ssh_packet_start(mbuf, SSH_MSG_CHANNEL_SUCCESS);
    em_ssh_mbuf_write_u32(mbuf, chid);
    em_ssh_packet_end(session, mbuf);

    err = em_ssh_packet_send(session, mbuf);
    return err;
}

static int send_request_failure(em_ssh_session_t *session, int chid) {
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session) {
        return EINVAL;
    }

    em_ssh_packet_start(mbuf, SSH_MSG_CHANNEL_FAILURE);
    em_ssh_mbuf_write_u32(mbuf, chid);
    em_ssh_packet_end(session, mbuf);

    err = em_ssh_packet_send(session, mbuf);
    return err;
}

// -----------------------------------------------------------------------------------------------------------------
// public
// -----------------------------------------------------------------------------------------------------------------
/**
 *
 **/
int em_ssh_packet_do_channel_request(em_ssh_session_t *session) {
    em_ssh_server_runtime_t *rt = em_ssh_server_get_runtime();
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;
    uint32_t chid = 0, itmp = 0;
    uint8_t req_reqply = 0;
    char *ctype = NULL;


    if(!session) {
        return EINVAL;
    }

    if(err = em_ssh_packet_expect(mbuf, SSH_MSG_CHANNEL_REQUEST) != OK) {
        goto out;
    }
    /* chid */
    chid = em_ssh_mbuf_read_u32(mbuf);

    /* type */
    itmp = em_ssh_mbuf_read_u32(mbuf);
    if(itmp == 0 || itmp > 128) {
        err = EM_SSH_ERR_PROTO_ERROR;
        goto out;
    }
    if((err = em_ssh_mbuf_strdup(mbuf, &ctype, &itmp)) != OK) {
        goto out;
    }
    req_reqply = em_ssh_mbuf_read_u8(mbuf);

    /* pty */
    if(em_ssh_str_equal(CHANNEL_IS_PTY_REQ, strlen(CHANNEL_IS_PTY_REQ), ctype, itmp)) {
        if((err = em_ssh_channel_create_pty(session->channel)) == OK) {
            if(req_reqply) {
                err = send_request_suceess(session, chid);
            }
            goto out;
        }
        em_ssh_log_warn("pty_create() failed (%i)", err);
        goto reject;
    }

    /* shell */
    if(em_ssh_str_equal(CHANNEL_IS_SHELL, strlen(CHANNEL_IS_SHELL), ctype, itmp)) {
        if((err = em_ssh_channel_start_shell(session->channel)) == OK) {
            if(req_reqply) {
                err = send_request_suceess(session, chid);
            }
            goto out;
        }
        em_ssh_log_warn("start_shell() failed (%i)", err);
        goto reject;
    }

reject:
    if(req_reqply) {
        err = send_request_failure(session, chid);
    }

out:
    em_ssh_mem_deref(ctype);
    return err;
}

/**
 *
 **/
int em_ssh_packet_do_channel_open(em_ssh_session_t *session) {
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;
    uint32_t chid = 0, iwsz = 0, mpsz = 0, itmp = 0;
    char *ctype = NULL;

    if(!session) {
        return EINVAL;
    }

    if(err = em_ssh_packet_expect(mbuf, SSH_MSG_CHANNEL_OPEN) != OK) {
        goto out;
    }

    /* channel type */
    itmp = em_ssh_mbuf_read_u32(mbuf);
    if(itmp == 0 || itmp > 128) {
        err = EM_SSH_ERR_PROTO_ERROR;
        goto out;
    }
    if((err = em_ssh_mbuf_strdup(mbuf, &ctype, &itmp)) != OK) {
        goto out;
    }
    chid = em_ssh_mbuf_read_u32(mbuf);
    iwsz = em_ssh_mbuf_read_u32(mbuf);
    mpsz = em_ssh_mbuf_read_u32(mbuf);
    if(mpsz > EM_SSH_PACKET_PAYLOAD_SIZE_MAX) {
        mpsz = EM_SSH_PACKET_PAYLOAD_SIZE_MAX;
    }
    if(session->channel != NULL) {
        err = send_open_failure(session, chid, SSH_OPEN_RESOURCE_SHORTAGE, "Too many opened channels");
        goto out;
    }

    if(!em_ssh_str_equal(CHANNEL_TYPE_SESSION, strlen(CHANNEL_TYPE_SESSION), ctype, itmp)) {
        err = send_open_failure(session, chid, SSH_OPEN_UNKNOWN_CHANNEL_TYPE, "Unsupported channel type");
        goto out;
    }

    /* create channel */
    if((err = em_ssh_channel_alloc(&session->channel, chid, iwsz, mpsz)) != OK) {
        err = send_open_failure(session, chid, SSH_OPEN_RESOURCE_SHORTAGE, "No enough resources");
        goto out;
    }

    /* send confirmation */
    em_ssh_packet_start(mbuf, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    em_ssh_mbuf_write_u32(mbuf, session->channel->id); /* recipient */
    em_ssh_mbuf_write_u32(mbuf, session->channel->id); /* sender*/
    em_ssh_mbuf_write_u32(mbuf, session->channel->local_wsz);
    em_ssh_mbuf_write_u32(mbuf, session->channel->packet_size);
    em_ssh_packet_end(session, mbuf);

    if((err = em_ssh_packet_send(session, mbuf)) != OK) {
        goto out;
    }

out:
    em_ssh_mem_deref(ctype);
    return err;
}


/**
 * correct session iobuffer pos
 **/
int em_ssh_packet_do_channel_data(em_ssh_session_t *session, size_t *data_len) {
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;
    uint32_t chid = 0, dsz = 0;

    if(!session) {
        return EINVAL;
    }
    if(err = em_ssh_packet_expect(mbuf, SSH_MSG_CHANNEL_DATA) != OK) {
        goto out;
    }

    chid = em_ssh_mbuf_read_u32(mbuf);
    if(session->channel == NULL || session->channel->id != chid) {
        em_ssh_log_warn("unknwon channel: %i", chid);
        *data_len = 0;
        goto out;
    }
    if(session->channel->feof) {
        em_ssh_log_warn("channel already eof");
        *data_len = 0;
        goto out;
    }

    dsz = em_ssh_mbuf_read_u32(mbuf);
    *data_len = dsz;

out:
    return err;
}

/**
 *
 **/
int em_ssh_packet_do_channel_eof(em_ssh_session_t *session) {
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;
    uint32_t chid = 0;

    if(!session) {
        return EINVAL;
    }
    if(err = em_ssh_packet_expect(mbuf, SSH_MSG_CHANNEL_EOF) != OK) {
        goto out;
    }

    chid = em_ssh_mbuf_read_u32(mbuf);
    if(session->channel == NULL || session->channel->id != chid) {
        em_ssh_log_warn("unknwon channel: %i", chid);
        goto out;
    }

    em_ssh_channel_eof(session->channel);

out:
    return err;
}

/**
 *
 **/
int em_ssh_packet_do_channel_close(em_ssh_session_t *session) {
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;
    uint32_t chid = 0;

    if(!session) {
        return EINVAL;
    }
    if(err = em_ssh_packet_expect(mbuf, SSH_MSG_CHANNEL_CLOSE) != OK) {
        goto out;
    }

    chid = em_ssh_mbuf_read_u32(mbuf);
    if(session->channel == NULL || session->channel->id != chid) {
        em_ssh_log_warn("unknwon channel: %i", chid);
        goto out;
    }

    em_ssh_channel_close(session->channel);

out:
    return err;
}


// -----------------------------------------------------------------------------------------------------------------
/***
 *
 **/
int em_ssh_packet_send_channel_eof(em_ssh_session_t *session, em_ssh_channel_t *channel) {
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session || !channel) {
        return EINVAL;
    }

    em_ssh_packet_start(mbuf, SSH_MSG_CHANNEL_EOF);
    em_ssh_mbuf_write_u32(mbuf, channel->id);
    em_ssh_packet_end(session, mbuf);

    err = em_ssh_packet_send(session, mbuf);
    return err;
}

/***
 *
 **/
int em_ssh_packet_send_channel_close(em_ssh_session_t *session, em_ssh_channel_t *channel) {
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session || !channel) {
        return EINVAL;
    }

    em_ssh_packet_start(mbuf, SSH_MSG_CHANNEL_CLOSE);
    em_ssh_mbuf_write_u32(mbuf, channel->id);
    em_ssh_packet_end(session, mbuf);

    err = em_ssh_packet_send(session, mbuf);
    return err;
}

/***
 *
 **/
int em_ssh_packet_send_channel_data(em_ssh_session_t *session, em_ssh_channel_t *channel, uint8_t *data, size_t data_len) {
    em_ssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;

    if(!session || !channel) {
        return EINVAL;
    }

    em_ssh_packet_start(mbuf, SSH_MSG_CHANNEL_DATA);
    em_ssh_mbuf_write_u32(mbuf, channel->id);
    em_ssh_mbuf_write_mem_sz(mbuf, data, data_len);
    em_ssh_packet_end(session, mbuf);

    err = em_ssh_packet_send(session, mbuf);
    return err;
}
