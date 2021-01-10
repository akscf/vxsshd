# gnuarm-4.0.2
TOOLCHAIN=./toolchain/gnuarm-4.0.2/bin/arm-elf
CC=$(TOOLCHAIN)-gcc
AS=$(TOOLCHAIN)-as
LD=$(TOOLCHAIN)-ld
OC=$(TOOLCHAIN)-objcopy
OD=$(TOOLCHAIN)-objdump
SIZE=$(TOOLCHAIN)-size

CFLAGS=-Os -mcpu=arm7 -DCPU=ARM7TDMI -DBYTE_ORDER=BIG_ENDIAN -mbig-endian -I./include -I./vxworks55
CFLAGS+=-Wno-implicit-function-declaration
LDFLAGS=--export-dynamic --relocatable --strip-all -EB

DST=vxsshd.elf
OBJECTS=$(SOURCES:.c=.o)
SOURCES=src/vxsshd.c
SOURCES+=src/vxssh_log.c src/vxssh_mem.c src/vxssh_mbuf.c src/vxssh_str.c src/vxssh_utils.c src/vxssh_neg.c src/vxssh_digest.c src/vxssh_mac.c src/vxssh_hmac.c src/vxssh_cipher.c src/vxssh_compress.c
SOURCES+=src/vxssh_kex.c src/vxssh_kexc25519s.c src/vxssh_session.c src/vxssh_channel.c
SOURCES+=src/vxssh_packet.c src/vxssh_packet_hello.c src/vxssh_packet_kexinit.c src/vxssh_packet_kexecdh.c src/vxssh_packet_auth.c src/vxssh_packet_disconnect.c src/vxssh_packet_channel.c src/vxssh_packet_unimplemented.c
SOURCES+=src/vxssh_crypto_rnd.c src/vxssh_crypto_obj.c src/vxssh_crypto_asn1.c src/vxssh_crypto_pem.c
SOURCES+=src/vxssh_crypto_md5.c src/vxssh_crypto_sha1.c src/vxssh_crypto_sha2.c
SOURCES+=src/vxssh_crypto_rsa.c src/vxssh_crypto_aes.c
SOURCES+=src/vxssh_crypto_chacha.c src/vxssh_crypto_poly1305.c 
SOURCES+=src/vxssh_debug.c
SOURCES+=src/mini-gmp.c src/smult_curve25519_ref.c
# tests
#SOURCES+=src/test_cipher_aes.c src/test_cipher_aes_cbc.c src/test_cipher_aes_ctr.c src/test_digest.c src/test_hmac.c src/test_mac.c src/test_rsa.c

all:    $(SOURCES) $(DST)

$(DST): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS)
	$(OC) --remove-section=.comment $(DST)
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o ${DST}

