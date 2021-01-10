/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

int vxssh_test_mac() {
    int err = OK;
    uint8_t digest_t[] = {0xa3,0x5d,0x2b,0x07,0x2d,0x3f,0x6d,0x24,0x2d,0x4d,0x29,0xca,0xe3,0x7f,0x33,0xfe};

    uint8_t msg[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x77, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x20, 0x31, 0x32, 0x33, 0x2d, 0x34, 0x35, 0x36, 0x2d, 0x37, 0x38, 0x39, 0x2d, 0x31, 0x32, 0x33, 0x2d, 0x34, 0x35, 0x36};
    uint8_t key[] = {0x31, 0x4f, 0x78, 0x37, 0x6e, 0x30, 0x39, 0x73, 0x6b, 0x50, 0x57, 0x46, 0x58, 0x7a, 0x36, 0x49};

    vxssh_mac_alg_props_t mac_cfg = {"hmac-md5", VXSSH_MAC_DIGEST, VXSSH_DIGEST_MD5, VXSSH_DIGEST_MD5_LENGTH, 00};
    uint8_t msgMac[VXSSH_DIGEST_MD5_LENGTH];
    vxssh_mac_ctx_t *ctx = NULL;

    vxssh_log_debug("MAC tests (HMAC-MD5)...");

    if((err = vxssh_mac_alloc(&ctx, &mac_cfg)) != OK) {
        vxssh_log_error("vxssh_mac_alloc() fail, err=%i", err);
        goto out;
    }
    ctx->key = vxssh_mem_dup(key, sizeof(key));

    if((err = vxssh_mac_init(ctx)) != OK) {
        vxssh_log_error("vxssh_mac_init() fail, err=%i", err);
        goto out;
    }

    if((err = vxssh_mac_compute(ctx, 0, msg, sizeof(msg), msgMac, VXSSH_DIGEST_MD5_LENGTH)) != OK) {
        vxssh_log_error("vxssh_mac_compute() fail, err=%i", err);
        goto out;
    }

    if (memcmp(msgMac, digest_t, VXSSH_DIGEST_MD5_LENGTH)) {
        vxssh_hexdump2("CUR_MAC...: ", digest_t, VXSSH_DIGEST_MD5_LENGTH);
        vxssh_hexdump2("T_MAC.....: ", msgMac, VXSSH_DIGEST_MD5_LENGTH);

        vxssh_log_error("mac mismatch");
        err = ERROR;
    } else {
        err = OK;
    }

    vxssh_log_debug("%s", err == OK ? "SUCCESS" : "FAIL");
out:
    vxssh_mem_deref(ctx);
    return err;
}
