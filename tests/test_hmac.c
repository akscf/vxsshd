/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

static int hmac_test(void *key, size_t klen, void *m, size_t mlen, uint8_t *e, size_t elen) {
    vxssh_hmac_ctx_t *ctx;
    uint8_t digest[VXSSH_DIGEST_MD5_LENGTH];
    int  i, err = OK;

    err = vxssh_hmac_alloc(&ctx, VXSSH_DIGEST_MD5);
    if(err != OK) {
        vxssh_log_error("vxssh_hmac_alloc() fail, err=%i", err);
        return err;
    }
    err = vxssh_hmac_init(ctx, key, klen);
    if(err != OK) {
        vxssh_log_error("vxssh_hmac_init() fail, err=%i", err);
        return err;
    }
    err = vxssh_hmac_update(ctx, m, mlen);
    if(err != OK) {
        vxssh_log_error("vxssh_hmac_update() fail, err=%i", err);
        return err;
    }
    err = vxssh_hmac_final(ctx, digest, sizeof(digest));
    if(err != OK) {
        vxssh_log_error("vxssh_hmac_final() fail, err=%i", err);
        return err;
    }

    if (memcmp(e, digest, elen)) {
        for (i = 0; i < elen; i++) {
            vxssh_log_error("[%03i] %2.2x %2.2x", i, e[i], digest[i]);
        }
        vxssh_log_error("mismatch");
        err = ERROR;
    } else {
        err = OK;
    }

    vxssh_mem_deref(ctx);
    return err;
}

int vxssh_test_hmac() {
    int err = OK;

    uint8_t key1[16] = {
        0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb,
        0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb, 0xb
    };
    char *data1 = "Hi There";
    uint8_t dig1[16] = {
        0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
        0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d
    };

    char *key2 = "Jefe";
    char *data2 = "what do ya want for nothing?";
    uint8_t dig2[16] = {
        0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
        0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38
    };

    uint8_t key3[16];
    uint8_t data3[50];
    uint8_t dig3[16] = {
        0x56, 0xbe, 0x34, 0x52, 0x1d, 0x14, 0x4c, 0x88,
        0xdb, 0xb8, 0xc7, 0x33, 0xf0, 0xe8, 0xb3, 0xf6
    };
    memset(key3, 0xaa, sizeof(key3));
    memset(data3, 0xdd, sizeof(data3));

    vxssh_log_debug("HMAC tests (MD5)...");

    err = hmac_test(key1, sizeof(key1), data1, strlen(data1), dig1, sizeof(dig1));
    err = hmac_test(key2, strlen(key2), data2, strlen(data2), dig2, sizeof(dig2));
    err = hmac_test(key3, sizeof(key3), data3, sizeof(data3), dig3, sizeof(dig3));

    vxssh_log_debug("%s", err == OK ? "SUCCESS" : "FAIL");

    return err;
}
