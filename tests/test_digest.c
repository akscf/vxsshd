/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

static int digest_test(int alg, char *msg, size_t mlen, uint8_t *digest, size_t dlen) {
    vxssh_digest_ctx_t *ctx = NULL;
    uint8_t hash[VXSSH_DIGEST_LENGTH_MAX];
    size_t hlen = 0;
    int i, err = OK;

    hlen = vxssh_digest_bytes(alg);
    if(hlen == 0) {
        vxssh_log_error("hlen == 0");
        return ERROR;
    }
    if(hlen > sizeof(hash)) {
        vxssh_log_error("hlen > CRYPTO_DIGEST_MAX_LENGTH");
        return ERROR;
    }
    if(hlen != dlen) {
        vxssh_log_error("hlen != dlen");
        return ERROR;
    }

    err = vxssh_digest_alloc(&ctx, alg);
    if(err != OK) {
        vxssh_log_error("vxssh_digest_alloc() fail, err=%i", err);
        return err;
    }
    err = vxssh_digest_update(ctx, msg, mlen);
    if(err != OK) {
        vxssh_log_error("vxssh_digest_update() fail, err=%i", err);
        return err;
    }
    err = vxssh_digest_final(ctx, hash, hlen);
    if(err != OK) {
        vxssh_log_error("vxssh_digest_update() fail, err=%i", err);
        return err;
    }
    if (memcmp(hash, digest, hlen)) {
        for (i = 0; i < hlen; i++) {
            vxssh_log_error("[%zu] %2.2x %2.2x", i, hash[i], digest[i]);
        }
        vxssh_log_error("mismatch");
        err = ERROR;
    } else {
        err = OK;
    }

    vxssh_mem_deref(ctx);
    return err;
}

int vxssh_test_digest() {
    int err = OK;
    char *msg = "what do ya want for nothing?";

    uint8_t h_md5[]={
        0xd0,0x3c,0xb6,0x59,0xcb,0xf9,0x19,0x2d,0xcd,0x06,0x62,0x72,0x24,0x9f,0x84,0x12
    };
    uint8_t h_sha1[]={
        0x8f,0x82,0x03,0x94,0xf9,0x53,0x35,0x18,0x20,0x45,0xda,0x24,0xf3,0x4d,0xe5,0x2b,0xf8,0xbc,0x34,0x32
    };
    uint8_t h_sha256[]={
        0xb3,0x81,0xe7,0xfe,0xc6,0x53,0xfc,0x3a,0xb9,0xb1,0x78,0x27,0x23,0x66,0xb8,0xac,0x87,0xfe,0xd8,0xd3,0x1c,0xb2,0x5e,0xd1,0xd0,0xe1,0xf3,0x31,0x86,0x44,0xc8,0x9c
    };

    vxssh_log_debug("Digest tests...");
    err = digest_test(VXSSH_DIGEST_MD5, msg, strlen(msg), h_md5, sizeof(h_md5));
    err = digest_test(VXSSH_DIGEST_SHA1, msg, strlen(msg), h_sha1, sizeof(h_sha1));
    err = digest_test(VXSSH_DIGEST_SHA256, msg, strlen(msg), h_sha256, sizeof(h_sha256));
    vxssh_log_debug("%s", err == OK ? "SUCCESS" : "FAIL");

    return err;
}
