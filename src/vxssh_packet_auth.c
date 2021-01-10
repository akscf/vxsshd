/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"
#include <loginLib.h>

#define FILED_LENGHT_MAX        128
#define SERVICE_USERAUTH        "ssh-userauth"
#define SERVICE_SSH_CONNECTION  "ssh-connection"
#define METHOD_NONE             "none"
#define METHOD_PASSWORD         "password"
//#define AUTH_METHOD_PUBKEY      "publickey"

static int read_cstr(vxssh_mbuf_t *mbuf, char **str, size_t *slen) {
    int err = OK;
    char *s = NULL;
    size_t itmp;

    itmp = vxssh_mbuf_read_u32(mbuf);
    if(!itmp || itmp > FILED_LENGHT_MAX) {
        err = VXSSH_ERR_PROTO_ERROR;
        goto out;
    }
    if((err = vxssh_mbuf_strdup(mbuf, &s, &itmp)) != OK) {
        goto out;
    }

    *slen = itmp;
    *str = s;
out:
    return err;

}
// -----------------------------------------------------------------------------------------------------------------
// public
// -----------------------------------------------------------------------------------------------------------------
/**
 *
 **/
int vxssh_packet_io_auth(vxssh_session_t *session, int timeout) {
    vxssh_server_runtime_t *rt = vxssh_server_get_runtime();
    vxssh_kex_t *kex = (session ? session->kex : NULL);
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int auth_tries = 0, err = OK;
    bool authorized = false;
    char *service=NULL, *username=NULL, *password=NULL;
    size_t itmp;

    if(!session || !kex) {
        return EINVAL;
    }

    /* wait service request */
    if((err = vxssh_packet_receive(session, mbuf, timeout)) != OK) {
        goto out;
    }
    if(err = vxssh_packet_expect(mbuf, SSH_MSG_SERVICE_REQUEST) != OK) {
        goto out;
    }

    /* check service name */
    if((itmp = vxssh_mbuf_read_u32(mbuf)) != strlen(SERVICE_USERAUTH)) {
        err = ERROR; goto out;
    }
    if((err = vxssh_mbuf_strdup(mbuf, &service, &itmp)) != OK) {
        goto out;
    }
    if(!vxssh_str_equal(SERVICE_USERAUTH, itmp, service, itmp)) {
        err = ERROR; goto out;
    }

    /* send service accept */
    vxssh_packet_start(mbuf, SSH_MSG_SERVICE_ACCEPT);
    vxssh_mbuf_write_str_sz(mbuf, SERVICE_USERAUTH);
    vxssh_packet_end(session, mbuf);
    if((err = vxssh_packet_send(session, mbuf)) != OK) {
        goto out;
    }

    /* auth loop */
    auth_tries = rt->auth_tries_max;
    while(auth_tries > 0 && !vxssh_server_is_shutdown()) {
        authorized = false;
        vxssh_mem_deref(service);
        vxssh_mem_deref(username);
        vxssh_mem_deref(password);

        /* get request */
        if((err = vxssh_packet_receive(session, mbuf, timeout)) != OK) {
            break;
        }
        if(err = vxssh_packet_expect(mbuf, SSH_MSG_USERAUTH_REQUEST) != OK) {
            break;
        }

        /* username */
        if((err = read_cstr(mbuf, &username, &itmp)) != OK) {
            break;
        }

        /* service */
        if((err = read_cstr(mbuf, &service, &itmp)) != OK) {
            break;
        }
        if(!vxssh_str_equal(service, itmp, SERVICE_SSH_CONNECTION, strlen(SERVICE_SSH_CONNECTION))) {
            err = VXSSH_ERR_PROTO_ERROR;
            break;
        }

        /* method */
        vxssh_mem_deref(service);
        if((err = read_cstr(mbuf, &service, &itmp)) != OK) {
            break;
        }
        if(vxssh_str_equal(service, itmp, METHOD_PASSWORD, strlen(METHOD_PASSWORD))) {
            vxssh_mbuf_read_u8(mbuf);
            if((err = read_cstr(mbuf, &password, &itmp)) != OK) {
                break;
            }
            if(loginUserVerify(username, password) == OK) {
                session->username = username;
                authorized = true;
                break;
            }

#ifdef VXSSH_LOG_ERROR_AUTH_ATTEMPTS
            vxssh_log_warn("authentication fail: '%s' from '%s'", username, session->peerip);
#endif
        }

        /* auth failure */
        vxssh_packet_start(mbuf, SSH_MSG_USERAUTH_FAILURE);
        vxssh_mbuf_write_str_sz(mbuf, METHOD_PASSWORD);
        vxssh_mbuf_write_u8(mbuf, 0);
        vxssh_packet_end(session, mbuf);
        if((err = vxssh_packet_send(session, mbuf)) != OK) {
            break;
        }
    }
    if(err != OK) {
        goto out;
    }
    if(!authorized) {
        vxssh_packet_send_disconnect(session, SSH_DISCONNECT_BY_APPLICATION, "Authentication failure");
    } else {
        vxssh_packet_start(mbuf, SSH_MSG_USERAUTH_SUCCESS);
        vxssh_mbuf_write_str_sz(mbuf, SERVICE_SSH_CONNECTION);
        vxssh_packet_end(session, mbuf);
        if((err = vxssh_packet_send(session, mbuf)) != OK) {
            goto out;
        }
    }
out:
    if(err == VXSSH_ERR_PROTO_ERROR) {
        vxssh_packet_send_disconnect(session, SSH_DISCONNECT_PROTOCOL_ERROR, NULL);
    }
    if(err != OK) {
        vxssh_mem_deref(username);
    }

    vxssh_mem_deref(service);
    vxssh_mem_deref(password);

    return err;
}
