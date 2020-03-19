TOOLCHAIN=/opt/toolchain/gnuarm-4.0.2/bin
CC=$(TOOLCHAIN)/arm-elf-gcc
LD=$(TOOLCHAIN)/arm-elf-ld
OBJCPY=$(TOOLCHAIN)/arm-elf-objcopy

CFLAGS=-Os -mcpu=arm7 -DCPU=ARM7TDMI -DBYTE_ORDER=BIG_ENDIAN -mbig-endian -I./include -I/opt/toolchain/vxworks55/h
LDFLAGS=--export-dynamic --relocatable --strip-all -EB

SOURCES=src/emssh.c src/emssh_log.c src/emssh_mem.c src/emssh_mbuf.c src/emssh_str.c src/emssh_utils.c src/emssh_neg.c src/emssh_digest.c src/emssh_mac.c src/emssh_hmac.c src/emssh_cipher.c src/emssh_compress.c
SOURCES+=src/emssh_kex.c src/emssh_kexc25519s.c src/emssh_session.c src/emssh_channel.c
SOURCES+=src/emssh_packet.c src/emssh_packet_hello.c src/emssh_packet_kexinit.c src/emssh_packet_kexecdh.c src/emssh_packet_auth.c src/emssh_packet_disconnect.c src/emssh_packet_channel.c src/emssh_packet_unimplemented.c
SOURCES+=src/emssh_crypto_rnd.c src/emssh_crypto_obj.c src/emssh_crypto_asn1.c src/emssh_crypto_pem.c
SOURCES+=src/emssh_crypto_md5.c src/emssh_crypto_sha1.c src/emssh_crypto_sha2.c
SOURCES+=src/emssh_crypto_rsa.c src/emssh_crypto_aes.c
SOURCES+=src/emssh_debug.c
SOURCES+=src/mini-gmp.c src/smult_curve25519_ref.c
# tests
#SOURCES+=src/test_cipher_aes.c src/test_cipher_aes_cbc.c src/test_cipher_aes_ctr.c src/test_digest.c src/test_hmac.c src/test_mac.c src/test_rsa.c

OBJECTS=$(SOURCES:.c=.o)
DST=emsshd2.elf

all:    $(SOURCES) $(DST)

$(DST): $(OBJECTS)
	$(LD) $(LDFLAGS) -o $@ $(OBJECTS)
	$(OBJCPY) --remove-section=.comment $(DST)
.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o ${DST}

