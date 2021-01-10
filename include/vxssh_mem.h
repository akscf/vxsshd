/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_MEM_H
#define VXSSH_MEM_H
#include <vxWorks.h>

typedef void (vxssh_mem_destructor_h)(void *data);
typedef struct {
    uint32_t nrefs;
    vxssh_mem_destructor_h *dh;
} vxssh_mem_t;

void *vxssh_mem_alloc(size_t size, vxssh_mem_destructor_h *dh);
void *vxssh_mem_zalloc(size_t size, vxssh_mem_destructor_h *dh);
void *vxssh_mem_realloc(void *data, size_t size);

void vxssh_mem_clean(void *data, size_t size);
void *vxssh_mem_dup(const void *m, size_t n);
void *vxssh_mem_ref(void *data);
void *vxssh_mem_deref(void *data);
uint32_t vxssh_mem_get_refs(const void *data);


#endif
