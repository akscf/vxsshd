/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

void *vxssh_mem_alloc(size_t size, vxssh_mem_destructor_h *dh) {
    vxssh_mem_t *m = NULL;

    m = malloc(sizeof(vxssh_mem_t) + size);
    if (!m) {
        return NULL;
    }

    m->nrefs = 1;
    m->dh = dh;

    return (void *)(m + 1);
}

void *vxssh_mem_zalloc(size_t size, vxssh_mem_destructor_h *dh) {
    void *p = NULL;

    p = vxssh_mem_alloc(size, dh);
    if (!p) return NULL;

    explicit_bzero(p, size);

    return p;
}

void *vxssh_mem_realloc(void *data, size_t size) {
    vxssh_mem_t *m = NULL, *m2 = NULL;

    if (!data) {
        return NULL;
    }
    m = ((vxssh_mem_t *) data) - 1;
    m2 = realloc(m, sizeof(vxssh_mem_t) + size);
    if (!m2) {
        return NULL;
    }
    return (void *)(m2 + 1);
}

void vxssh_mem_clean(void *data, size_t size) {
    if(!data) return;
    memset(data, 0x0, size);
}

void *vxssh_mem_dup(const void *m, size_t n) {
    void *res = NULL;

    if (m == NULL) {
        return NULL;
    }
    if((res = vxssh_mem_alloc(n, NULL)) == NULL) {
        return NULL;
    }
    memcpy(res, m, n);

    return res;
}

void *vxssh_mem_ref(void *data) {
    vxssh_mem_t *m = NULL;

    if (!data) return NULL;

    m = ((vxssh_mem_t *)data) - 1;
    ++m->nrefs;

    return data;
}

void *vxssh_mem_deref(void *data) {
    vxssh_mem_t *m = NULL;

    if (!data) {
        return NULL;
    }

    m = ((vxssh_mem_t *) data) - 1;
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

uint32_t vxssh_mem_get_refs(const void *data) {
    vxssh_mem_t *m = NULL;

    if (!data) return 0;

    m = ((vxssh_mem_t *) data) - 1;

    return m->nrefs;
}

