/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "emssh.h"

void *em_ssh_mem_alloc(size_t size, em_ssh_mem_destructor_h *dh) {
    em_ssh_mem_t *m = NULL;

    m = malloc(sizeof(em_ssh_mem_t) + size);
    if (!m) {
        return NULL;
    }

    m->nrefs = 1;
    m->dh = dh;

    return (void *)(m + 1);
}

void *em_ssh_mem_zalloc(size_t size, em_ssh_mem_destructor_h *dh) {
    void *p = NULL;

    p = em_ssh_mem_alloc(size, dh);
    if (!p) return NULL;

    explicit_bzero(p, size);

    return p;
}

void *em_ssh_mem_realloc(void *data, size_t size) {
    em_ssh_mem_t *m = NULL, *m2 = NULL;

    if (!data) {
        return NULL;
    }
    m = ((em_ssh_mem_t *) data) - 1;
    m2 = realloc(m, sizeof(em_ssh_mem_t) + size);
    if (!m2) {
        return NULL;
    }
    return (void *)(m2 + 1);
}

void em_ssh_mem_clean(void *data, size_t size) {
    if(!data) return;
    memset(data, 0x0, size);
}

void *em_ssh_mem_dup(const void *m, size_t n) {
    void *res = NULL;

    if (m == NULL) {
        return NULL;
    }
    if((res = em_ssh_mem_alloc(n, NULL)) == NULL) {
        return NULL;
    }
    memcpy(res, m, n);

    return res;
}

void *em_ssh_mem_ref(void *data) {
    em_ssh_mem_t *m = NULL;

    if (!data) return NULL;

    m = ((em_ssh_mem_t *)data) - 1;
    ++m->nrefs;

    return data;
}

void *em_ssh_mem_deref(void *data) {
    em_ssh_mem_t *m = NULL;

    if (!data) {
        return NULL;
    }

    m = ((em_ssh_mem_t *) data) - 1;
    if (--m->nrefs > 0) {
        return NULL;
    }
    if (m->dh) {
        m->dh(data);
    }

    if (m->nrefs > 0) {
        return NULL;
    }

    free(m);
    m = NULL;

    return NULL;
}

uint32_t em_ssh_mem_get_refs(const void *data) {
    em_ssh_mem_t *m = NULL;

    if (!data) return 0;

    m = ((em_ssh_mem_t *) data) - 1;

    return m->nrefs;
}

