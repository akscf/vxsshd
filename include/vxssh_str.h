/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_STR_H
#define VXSSH_STR_H

#include <vxWorks.h>

bool vxssh_str_equal(const char *s1, int s1_len, const char *s2, int s2_len);
int vxssh_str_index(const char *s1, int s1_len, const char *s2, int s2_len);
char *vxssh_str_split(const char *buf, int buf_len, char c, int *tlen);
char* vxssh_str_dup(const char *str, int slen);

#endif

