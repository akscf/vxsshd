/**
 * PRN generators
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

static inline uint32_t rnd_u32(void) {
    return rand();
}

// ----------------------------------------------------------------------------------------------
/**
 *
 **/
int em_ssh_rnd_init() {
    time_t s = em_ssh_get_time();
    srand(s);

    return OK;
}

/**
 *
 **/
int em_ssh_rnd_bin(char *buf, size_t size) {
    if(!buf || !size) {
        return EINVAL;
    }
    while (size--) {
        buf[size] = (uint8_t) rnd_u32();
    }
    return OK;
}

