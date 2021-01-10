/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

/**
 * curve25519
 *
 **/
int vxssh_packet_io_kexecdh(vxssh_session_t *session, int timeout) {
    vxssh_server_runtime_t *rt = vxssh_server_get_runtime();
    vxssh_kex_t *kex = (session ? session->kex : NULL);
    vxssh_mbuf_t *mbuf = (session ? session->iobuf : NULL);
    int err = OK;
    size_t hash_len, dh_shared_key_len, dh_client_pub_key_len;
    vxssh_mbuf_t *hk_blob = NULL, *sign_blob = NULL;
    vxssh_crypto_object_t *signature;
    uint8_t *dh_client_pub_key = NULL;
    uint8_t *dh_shared_key = NULL;
    uint8_t *hash = NULL;
    uint8_t dh_server_prv_key[CRYPTO_CURVE25519_SIZE];
    uint8_t dh_server_pub_key[CRYPTO_CURVE25519_SIZE];

    if(!session || !kex) {
        return EINVAL;
    }
    if((err = vxssh_mbuf_alloc(&hk_blob, 512)) != OK) {
        goto out;
    }
    if((err = vxssh_mbuf_alloc(&sign_blob, 255)) != OK) {
        goto out;
    }
    /* generate server key pair */
    vxssh_kex_c25519_keygen(dh_server_prv_key, dh_server_pub_key);

    /* --- SSH2_MSG_KEX_ECDH_INIT --- */
    if((err = vxssh_packet_receive(session, mbuf, timeout)) != OK) {
        goto out;
    }
    if(err = vxssh_packet_expect(mbuf, SSH2_MSG_KEX_ECDH_INIT) != OK) {
        goto out;
    }
    /* Q_C */
    dh_client_pub_key_len = vxssh_mbuf_read_u32(mbuf);
    if(dh_client_pub_key_len != CRYPTO_CURVE25519_SIZE) {
        vxssh_log_warn("invalid Q_C len: %i", dh_client_pub_key_len);
        err = ERROR; goto out;
    }
    if((dh_client_pub_key = vxssh_mem_zalloc(dh_client_pub_key_len, NULL)) == NULL) {
        err = ENOMEM;
        goto out;
    }
    if((err = vxssh_mbuf_read_mem(mbuf, dh_client_pub_key, &dh_client_pub_key_len)) != OK) {
        goto out;
    }
    /* make shared secret */
    vxssh_kex_c25519_shared_key(dh_server_prv_key, dh_client_pub_key, &dh_shared_key, &dh_shared_key_len);
    // hostkey
    if((err = vxssh_rsa_encode_public_key2(hk_blob, (vxssh_crypto_rsa_private_key_t *)rt->server_key->obj)) != OK) {
        goto out;
    }
    /* calc H */
    if((hash_len = vxssh_digest_bytes(kex->hash_alg)) == 0) {
        err = ERROR;
        goto out;
    }
    if((hash = vxssh_mem_zalloc(hash_len, NULL)) == NULL)  {
        err = ENOMEM;
        goto out;
    }
    if((err = vxssh_kex_c25519_hash(
        kex->hash_alg,
        kex->client_version, kex->client_version_len,
        kex->server_version, kex->server_version_len,
        kex->client_kex_init, kex->client_kex_init_len,
        kex->server_kex_init, kex->server_kex_init_len,
        hk_blob->buf, hk_blob->pos,
        dh_client_pub_key, dh_server_pub_key,
        dh_shared_key, dh_shared_key_len,
        hash, hash_len)) != OK) {
            goto out;
        }
    /* sign hash */
    if((err = vxssh_rsa_sign((vxssh_crypto_rsa_private_key_t *)rt->server_key->obj, hash, hash_len, &signature)) != OK) {
        goto out;
    }
    if((err = vxssh_rsa_encode_signature(sign_blob, ((vxssh_crypto_rsa_signature_t *)signature->obj))) != OK) {
        goto out;
    }
    /* copy session_id */
    if (kex->session_id == NULL) {
        kex->session_id_len = hash_len;
        if((kex->session_id = vxssh_mem_alloc(kex->session_id_len, NULL)) == NULL) {
            err = ENOMEM;
            goto out;
        }
        memcpy(kex->session_id, hash, kex->session_id_len);
    }

#ifdef VXSSH_DEBUG_KEX_DH
    vxssh_hexdump2("kex-dh: sesion id....: ", kex->session_id, kex->session_id_len);
    vxssh_hexdump2("kex-dh: client key...: ", dh_client_pub_key, dh_client_pub_key_len);
    vxssh_hexdump2("kex-dh: server pub...: ", dh_server_pub_key, sizeof(dh_server_pub_key));
    vxssh_hexdump2("kex-dh: shared key...: ", dh_shared_key, dh_shared_key_len);
#endif

    /* --- SSH2_MSG_KEX_ECDH_REPLY --- */
    vxssh_packet_start(mbuf, SSH2_MSG_KEX_ECDH_REPLY);
    vxssh_mbuf_write_mem_sz(mbuf, hk_blob->buf, hk_blob->pos);
    vxssh_mbuf_write_mem_sz(mbuf, dh_server_pub_key, CRYPTO_CURVE25519_SIZE);
    vxssh_mbuf_write_mem_sz(mbuf, sign_blob->buf, sign_blob->pos);
    vxssh_packet_end(session, mbuf);

    if((err = vxssh_packet_send(session, mbuf)) != OK) {
        goto out;
    }

    /* key derivation */
    if((err = vxssh_kex_derive_keys(kex, hash, hash_len, dh_shared_key, dh_shared_key_len)) != OK) {
        goto out;
    }

    /* SSH_MSG_NEWKEYS */
    vxssh_packet_start(mbuf, SSH_MSG_NEWKEYS);
    vxssh_packet_end(session, mbuf);

    if((err = vxssh_packet_send(session, mbuf)) != OK) {
        goto out;
    }
    if((err = vxssh_packet_receive(session, mbuf, timeout)) != OK) {
        goto out;
    }
    if(err = vxssh_packet_expect(mbuf, SSH_MSG_NEWKEYS) != OK) {
        goto out;
    }

out:
    vxssh_mem_deref(hk_blob);
    vxssh_mem_deref(sign_blob);
    vxssh_mem_deref(signature);
    vxssh_mem_deref(dh_shared_key);
    vxssh_mem_deref(dh_client_pub_key);
    vxssh_mem_deref(hash);

#ifdef VXSSH_CLEAR_MEMORY_ON_DEREF
    explicit_bzero(dh_server_prv_key, sizeof(dh_server_prv_key));
#endif

    return err;
}
