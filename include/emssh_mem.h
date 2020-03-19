/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_MEM_H
#define EMSSH_MEM_H
#include <vxWorks.h>

typedef void (em_ssh_mem_destructor_h)(void *data);
typedef struct {
    uint32_t nrefs;
    em_ssh_mem_destructor_h *dh;
} em_ssh_mem_t;

void *em_ssh_mem_alloc(size_t size, em_ssh_mem_destructor_h *dh);
void *em_ssh_mem_zalloc(size_t size, em_ssh_mem_destructor_h *dh);
void *em_ssh_mem_realloc(void *data, size_t size);

void em_ssh_mem_clean(void *data, size_t size);
void *em_ssh_mem_dup(const void *m, size_t n);
void *em_ssh_mem_ref(void *data);
void *em_ssh_mem_deref(void *data);
uint32_t em_ssh_mem_get_refs(const void *data);


#endif
