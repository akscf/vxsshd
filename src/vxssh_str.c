/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

/**
 * s1 - buffer
 * s2 - substring
 **/
int vxssh_str_index(const char *s1, int s1_len, const char *s2, int s2_len) {
    int i, j;

    if(!s1 || !s2 ) {
        return EINVAL;
    }
    if(s2_len > s1_len) {
        return -1;
    }
    for (i = 0; i <= (s1_len - s2_len); i++) {
        for (j = 0; j < s2_len; j++) {
            if (s1[i + j] != s2[j]) {
                break;
            }
        }
        if (j == s2_len)  return i;
    }
    return -1;
}

/**
 *
 **/
bool vxssh_str_equal(const char *s1, int s1_len, const char *s2, int s2_len) {
    int i, j;

    if(!s1 || !s2 ) {
        return EINVAL;
    }
    if(s1_len != s2_len) {
        return false;
    }
    return (strncmp(s1, s2, s1_len) == 0 ? true : false);
}


/**
 * buf      - buffer
 * c        - separator
 * tlen     - strlen
 * return   - pnt to str
 **/
char *vxssh_str_split(const char *buf, int buf_len, char c, int *tlen) {
    int i = 0;
    char *p = (void *)buf;

    if(buf_len == 0) {
        *tlen = 0;
        return OK;
    }

    while(true) {
        if(buf[i] == c) {
            *tlen = i;
            break;
        }
        if(i >= buf_len) {
            *tlen = i;
            break;
        }
        i++;
    }

    return p;
}

/**
 *
 **/
char *vxssh_str_dup(const char *str, int slen) {
    char *s = NULL;

    if (str == NULL || !slen) {
        return NULL;
    }

    if((s = vxssh_mem_alloc(slen, NULL)) == NULL) {
        return NULL;
    }
    memcpy(s, str, slen);
    s[slen] = '\0';

    return s;
}
