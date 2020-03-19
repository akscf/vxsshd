/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef EMSSH_STR_H
#define EMSSH_STR_H

#include <vxWorks.h>

bool em_ssh_str_equal(const char *s1, int s1_len, const char *s2, int s2_len);
int em_ssh_str_index(const char *s1, int s1_len, const char *s2, int s2_len);
char *em_ssh_str_split(const char *buf, int buf_len, char c, int *tlen);
char* em_ssh_str_dup(const char *str, int slen);

#endif

