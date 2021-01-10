/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#include "vxssh.h"

/**
 * set/clear FIONBIO to fd
 **/
int vxssh_fd_set_blocking(int sockfd, bool flag) {
    int val = !flag;
    return ioctl(sockfd, FIONBIO, val);
}

/**
 *
 **/
int vxssh_fd_select_read(int sockfd, int usec) {
    struct timeval tv = { 0 };
    int err = 0;
    fd_set fd_rd_flags;

    //tv.tv_sec = sec;
    tv.tv_usec = usec;
    FD_ZERO(&fd_rd_flags);
    FD_SET(sockfd, &fd_rd_flags);

    err = select(sockfd + 1, &fd_rd_flags, NULL, NULL, &tv);
    if(err < 0 || !FD_ISSET(sockfd, &fd_rd_flags)) {
        return 0;
    }
    FD_CLR(sockfd, &fd_rd_flags);

    return 1;
}

/**
 * cur time in msec
 **/
time_t vxssh_get_time() {
    struct timespec ts;

    if(clock_gettime(CLOCK_REALTIME, &ts) != OK) {
        return 0;
    }

    return (time_t) (ts.tv_sec * 1000L) + (ts.tv_nsec / 1000L);
}

/**
 * delay in sec
 **/
void vxssh_sleep(int sec) {
    taskDelay(CLOCKS_PER_SEC * sec);
}

/**
 *
 **/
void explicit_bzero(void *s, size_t len) {
    memset (s, 0, len);
    asm volatile ("" ::: "memory");
}

/**
 *
 **/
int timingsafe_bcmp(const void *b1, const void *b2, size_t n) {
        const unsigned char *p1 = b1, *p2 = b2;
        int ret = 0;

        for (; n > 0; n--)
            ret |= *p1++ ^ *p2++;

        return (ret != 0);
}
