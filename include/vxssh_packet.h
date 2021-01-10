/**
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.org/
 **/
#ifndef VXSSH_PACKET_H
#define VXSSH_PACKET_H
#include <vxWorks.h>

#define VXWORKS_TCP_MAX_SIZE            65535
#define VXSSH_PACKET_SIZE_MAX          35000
#define VXSSH_PACKET_PAYLOAD_SIZE_MAX  32768

int vxssh_packet_start(vxssh_mbuf_t *mbuf, uint8_t type);
int vxssh_packet_end(vxssh_session_t *session, vxssh_mbuf_t *mbuf);
int vxssh_packet_expect(vxssh_mbuf_t *mbuf, uint8_t type);

int vxssh_packet_receive(vxssh_session_t *session, vxssh_mbuf_t *mbuf, int timeout);
int vxssh_packet_send(vxssh_session_t *session, vxssh_mbuf_t *mbuf);

int vxssh_packet_io_hello(vxssh_session_t *session, int timeout);
int vxssh_packet_io_kexinit(vxssh_session_t *session, int timeout);
int vxssh_packet_io_kexecdh(vxssh_session_t *session, int timeout);
int vxssh_packet_io_auth(vxssh_session_t *session, int timeout);

int vxssh_packet_do_channel_request(vxssh_session_t *session);
int vxssh_packet_do_channel_open(vxssh_session_t *session);
int vxssh_packet_do_channel_eof(vxssh_session_t *session);
int vxssh_packet_do_channel_close(vxssh_session_t *session);
int vxssh_packet_do_channel_data(vxssh_session_t *session, size_t *data_len);


int vxssh_packet_send_channel_eof(vxssh_session_t *session, vxssh_channel_t *channel);
int vxssh_packet_send_channel_close(vxssh_session_t *session, vxssh_channel_t *channel);
int vxssh_packet_send_channel_data(vxssh_session_t *session, vxssh_channel_t *channel, uint8_t *data, size_t data_len);

int vxssh_packet_send_disconnect(vxssh_session_t *session, int reason, char *message);
int vxssh_packet_send_unimplemented(vxssh_session_t *session);

#endif
