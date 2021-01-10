/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

static void callback_wd_expiry(int *flag) {
    *flag = true;
}

static int packet_receive_encypted(vxssh_session_t *session, vxssh_mbuf_t *mbuf, int timeout) {
    vxssh_kex_t *kex = session->kex;
    int err = OK, rds = 0;
    char buf[VXSSH_CIPHER_BLOCK_SIZE_MAX], ch = 0;
    size_t packet_len = 0, extra_len = 0, pos = 0;
    int expiry_flag = false;
    WDOG_ID expiry_wd = NULL;

    if(kex->keys_in.enc->block_len > sizeof(buf)) {
        vxssh_log_error("fix me: dec chipher block > %i", sizeof(buf));
        return ERROR;
    }

    if ((expiry_wd = wdCreate()) == NULL)  {
        vxssh_log_warn("wdCreate() fail");
        err = ERROR;
        goto out;
    }
    if((err = wdStart(expiry_wd, (timeout * CLOCKS_PER_SEC), (FUNCPTR)callback_wd_expiry, (int) &expiry_flag)) != OK) {
        vxssh_log_warn("wdStart() fail (%i)", err);
        goto out;
    }

    vxssh_mbuf_clear(mbuf);
    while(!vxssh_server_is_shutdown()) {
        if(expiry_flag) {
            err = ETIME;
            break;
        }
        if(!vxssh_fd_select_read(session->socfd, 1000)) {
            continue;
        }

        if(packet_len > 0) {
            const int rsz = ((mbuf->pos + sizeof(buf)) > packet_len ? packet_len - mbuf->pos : sizeof(buf));
            rds = read(session->socfd, (char *) buf, rsz);
        } else {
            rds = read(session->socfd, &ch, 1);
        }

        if(rds > 0) {
            if(packet_len > 0) {
                if((err = vxssh_mbuf_write_mem(mbuf, (uint8_t *)buf, rds)) != OK) {
                    break;
                }
                if(mbuf->pos >= packet_len) {
                    if(extra_len > 0) {
                        packet_len += extra_len;
                        extra_len = 0;
                        continue;
                    }
                    break;
                }
            } else {
                if(mbuf->pos < kex->keys_in.enc->block_len) {
                    vxssh_mbuf_write_u8(mbuf, ch);
                    if(mbuf->pos == kex->keys_in.enc->block_len) {
                        if((err = vxssh_cipher_decrypt(kex->keys_in.enc, mbuf->buf, kex->keys_in.enc->block_len, (uint8_t *) buf, kex->keys_in.enc->block_len)) != OK) {
                            vxssh_log_warn("decrypt faild (#1): %i", err);
                            break;
                        }
                        vxssh_mbuf_set_pos(mbuf, 0);
                        if((err = vxssh_mbuf_write_mem(mbuf, (uint8_t *) buf, kex->keys_in.enc->block_len)) != OK) {
                            break;
                        }
                        vxssh_mbuf_set_pos(mbuf, 0);

                        extra_len = kex->keys_in.mac->mac_len;
                        packet_len = vxssh_mbuf_read_u32(mbuf) + 4;
                        vxssh_mbuf_set_pos(mbuf, kex->keys_in.enc->block_len);

                        if(packet_len < VXSSH_CIPHER_BLOCK_SIZE_MIN || packet_len > VXSSH_PACKET_PAYLOAD_SIZE_MAX) {
                            vxssh_log_warn("invalid packet lenght: %u", packet_len);
                            err = ERANGE; break;
                        }
                        if(packet_len % kex->keys_in.enc->block_len > 0) {
                            vxssh_log_warn("invalid packet alignment: %u (%u)", packet_len, kex->keys_in.enc->block_len);
                            err = ERANGE; break;
                        }
                    }
                }
            }
        }
    }
    if(err != OK) {
        goto out;
    }

    vxssh_mbuf_set_pos(mbuf, 0);
    packet_len = (vxssh_mbuf_read_u32(mbuf) + 4);

    pos = kex->keys_in.enc->block_len;
    while(pos < packet_len) {
        if((err = vxssh_cipher_decrypt(kex->keys_in.enc, mbuf->buf + pos, kex->keys_in.enc->block_len, (uint8_t *)buf, kex->keys_in.enc->block_len)) != OK) {
            vxssh_log_warn("decrypt faild (#2): %i", err);
            goto out;
        }
        vxssh_mbuf_set_pos(mbuf, pos);
        if((err = vxssh_mbuf_write_mem(mbuf, (uint8_t *) buf, kex->keys_in.enc->block_len)) != OK) {
            break;
        }
        pos += kex->keys_in.enc->block_len;
    }
    if(err != OK) {
        goto out;
    }

    uint8_t *macp = (mbuf->buf + packet_len);
    if((err = vxssh_mac_check(kex->keys_in.mac, session->recv_seq, mbuf->buf, packet_len, macp, kex->keys_in.mac->mac_len)) != OK) {
        vxssh_log_warn("mac mismatch (%i)", err);
        goto out;
    }

    /* correct postions */
    vxssh_mbuf_set_pos(mbuf, 0);
    packet_len = vxssh_mbuf_read_u32(mbuf);
    extra_len = vxssh_mbuf_read_u8(mbuf); /* padding */
    mbuf->end = (mbuf->end - extra_len - kex->keys_in.mac->mac_len);
out:
    if(expiry_wd) {
        wdCancel(expiry_wd);
        wdDelete(expiry_wd);
    }
    return err;
}

static int packet_receive_plain(vxssh_session_t *session, vxssh_mbuf_t *mbuf, int timeout) {
    char buf[32], ch = 0;
    int err = OK, rds = 0;
    size_t packet_len = 0;
    uint8_t padding_len = 0;
    int expiry_flag = false;
    WDOG_ID expiry_wd = NULL;

    if ((expiry_wd = wdCreate()) == NULL)  {
        vxssh_log_warn("wdCreate() fail");
        err = ERROR;
        goto out;
    }
    if((err = wdStart(expiry_wd, (timeout * CLOCKS_PER_SEC), (FUNCPTR)callback_wd_expiry, (int) &expiry_flag)) != OK) {
        vxssh_log_warn("wdStart() fail (%i)", err);
        goto out;
    }

    vxssh_mbuf_clear(mbuf);
    while(!vxssh_server_is_shutdown()) {
        if(expiry_flag) {
            err = ETIME;
            break;
        }

        if(!vxssh_fd_select_read(session->socfd, 1000)) {
            continue;
        }

        if(packet_len > 0) {
            const int rsz = ((mbuf->pos + sizeof(buf)) > packet_len ? packet_len - mbuf->pos : sizeof(buf));
            rds = read(session->socfd, (char *) buf, rsz);
        } else {
            rds = read(session->socfd, &ch, 1);
        }

        if(rds > 0) {
            if(packet_len > 0) {
                err = vxssh_mbuf_write_mem(mbuf, (uint8_t *)buf, rds);
                if(err != OK || mbuf->pos >= packet_len) {
                    break;
                }
            } else {
                if(mbuf->pos < 4) {
                    vxssh_mbuf_write_u8(mbuf, ch);
                    if(mbuf->pos == 4) {
                        vxssh_mbuf_set_pos(mbuf, 0);
                        packet_len = vxssh_mbuf_read_u32(mbuf) + 4;
                        if(packet_len < VXSSH_CIPHER_BLOCK_SIZE_MIN || packet_len > VXSSH_PACKET_PAYLOAD_SIZE_MAX) {
                            vxssh_log_warn("invalid packet lenght: %u", packet_len);
                            err = ERANGE; break;
                        }
                    }
                }
            }
        }
    }
    if(err != OK) {
        goto out;
    }

    vxssh_mbuf_set_pos(mbuf, 0);
    packet_len = vxssh_mbuf_read_u32(mbuf);
    padding_len = vxssh_mbuf_read_u8(mbuf);
    if(padding_len > packet_len) {
        err = ERANGE;
        goto out;
    }

    /* correct postions */
    mbuf->end = (mbuf->end - padding_len);

out:
    if(expiry_wd) {
        wdCancel(expiry_wd);
        wdDelete(expiry_wd);
    }
    return err;
}


static int packet_send_plain(vxssh_session_t *session, vxssh_mbuf_t *mbuf) {
    int err = OK, wrs = 0;
    char *p = NULL;

    mbuf->pos = 0;
    wrs = mbuf->end;

    while (mbuf->pos < mbuf->end) {
        if (wrs > VXWORKS_TCP_MAX_SIZE) {
            wrs = VXWORKS_TCP_MAX_SIZE;
        }
        p = (char *) mbuf->buf + mbuf->pos;
        wrs = write(session->socfd, p, wrs);
        if (wrs < 0) {
            err = errno;
            break;
        }
        mbuf->pos += wrs;
    }

    return err;
}

static int packet_send_encypted(vxssh_session_t *session, vxssh_mbuf_t *mbuf) {
    vxssh_kex_t *kex = session->kex;
    int err = OK;
    size_t pos = 0, packet_len = 0;
    char buf[VXSSH_CIPHER_BLOCK_SIZE_MAX];
    char mac[VXSSH_DIGEST_LENGTH_MAX];

    if(kex->keys_out.enc->block_len > sizeof(buf)) {
        vxssh_log_error("fixme: enc chipher block > %i", sizeof(buf));
        return ERROR;
    }

    if((err = vxssh_mac_compute(kex->keys_out.mac, session->send_seq, mbuf->buf, mbuf->end, (uint8_t *)mac, kex->keys_out.mac->mac_len)) != OK) {
        vxssh_log_warn("mac_compute fail (%i)", err);
        goto out;
    }

    pos = 0;
    packet_len = mbuf->end;
    while(pos < packet_len) {
        if((err = vxssh_cipher_encrypt(kex->keys_out.enc, mbuf->buf + pos, kex->keys_out.enc->block_len, (uint8_t *)buf, kex->keys_out.enc->block_len)) != OK) {
            vxssh_log_warn("encrypt faild: %i", err);
            goto out;
        }
        vxssh_mbuf_set_pos(mbuf, pos);
        if((err = vxssh_mbuf_write_mem(mbuf, (uint8_t *) buf, kex->keys_out.enc->block_len)) != OK) {
            break;
        }
        pos += kex->keys_out.enc->block_len;
    }
    if(err != OK) {
        goto out;
    }

    if((err = vxssh_mbuf_write_mem(mbuf, (uint8_t *)mac, kex->keys_out.mac->mac_len)) != OK){
        goto out;
    }

    err = packet_send_plain(session, mbuf);

out:
    return err;
}

// -----------------------------------------------------------------------------------------------------------------
// public
// -----------------------------------------------------------------------------------------------------------------
/**
 *
 **/
int vxssh_packet_start(vxssh_mbuf_t *mbuf, uint8_t type) {

    if(!mbuf) {
        return EINVAL;
    }
    /* clear mbuf */
    vxssh_mbuf_clear(mbuf);
    //
    vxssh_mbuf_write_u32(mbuf, 0);
    vxssh_mbuf_write_u8(mbuf, 0);
    vxssh_mbuf_write_u8(mbuf, type);
    //
    return OK;
}

/**
 *
 **/
int vxssh_packet_end(vxssh_session_t *session, vxssh_mbuf_t *mbuf) {
    vxssh_kex_t *kex = (session ? session->kex : NULL);
    size_t block_len = VXSSH_CIPHER_BLOCK_SIZE_MIN;
    size_t packet_len = 0;
    uint8_t padding_len = 0;
    int i;

    if(!session || !mbuf) {
        return EINVAL;
    }

    if(session->fl_rekeying_done) {
        block_len = kex->keys_in.enc->block_len;
        if(block_len < VXSSH_CIPHER_BLOCK_SIZE_MIN) {
            block_len = VXSSH_CIPHER_BLOCK_SIZE_MIN;
        }
    }

    padding_len = (block_len - (mbuf->end % block_len));
    if(padding_len < 4) {
        padding_len += block_len;
    }
    if(!session->fl_rekeying_done) {
        vxssh_mbuf_fill(mbuf, 0, padding_len);
    } else {
#ifndef VXSSH_USE_RANDOM_PADDING
        vxssh_mbuf_fill(mbuf, 0, padding_len);
#else
        for(i = 0; i < padding_len; i++) {
            const uint8_t c;
            vxssh_rnd_bin((char *)&c, 1);
            vxssh_mbuf_write_u8(mbuf, c);
        }
#endif
    }
    packet_len = (mbuf->end - 4);

    vxssh_mbuf_set_pos(mbuf, 0);
    vxssh_mbuf_write_u32(mbuf, packet_len);
    vxssh_mbuf_write_u8(mbuf, padding_len);
    vxssh_mbuf_set_pos(mbuf, mbuf->end);

    return OK;
}

/**
 *
 *
 **/
int vxssh_packet_expect(vxssh_mbuf_t *mbuf, uint8_t type) {
    uint8_t c;

    if(!mbuf) {
        return EINVAL;
    }
    if((c = vxssh_mbuf_read_u8(mbuf)) != type) {
        vxssh_log_warn("unexpected packet: %i (req: %i)", c, type);
        return ERROR;
    }
    return OK;
}

/**
 *
 **/
int vxssh_packet_receive(vxssh_session_t *session, vxssh_mbuf_t *mbuf, int timeout) {
    int err = OK;

    if(!session || !mbuf) {
        return EINVAL;
    }

    if(session->fl_rekeying_done) {
        err = packet_receive_encypted(session, mbuf, timeout);
    } else {
        err = packet_receive_plain(session, mbuf, timeout);
    }

    if(err == OK) {
        session->recv_seq++;

        uint8_t c = mbuf->buf[mbuf->pos];
        if(c == SSH_MSG_DISCONNECT) {
            err = VXSSH_ERR_MSG_DISCONNECT;
        } else if(c == SSH_MSG_IGNORE || c == SSH_MSG_DEBUG) {
            err = VXSSH_ERR_MSG_IGNORE;
        }
    }

    return err;
}

/**
 *
 **/
int vxssh_packet_send(vxssh_session_t *session, vxssh_mbuf_t *mbuf) {
    int err = OK;

    if(!session || !mbuf) {
        return EINVAL;
    }

    if(session->fl_rekeying_done) {
        err = packet_send_encypted(session, mbuf);
    } else {
        err = packet_send_plain(session, mbuf);
    }

    if(err == OK) {
        session->send_seq++;
    }

    return err;
}
