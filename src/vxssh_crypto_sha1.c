/*
By Steve Reid <sreid@sea-to-sky.net>
100% Public Domain
*/
#include "vxssh.h"

#if !defined(BYTE_ORDER) || (BYTE_ORDER != LITTLE_ENDIAN && BYTE_ORDER != BIG_ENDIAN)
#error Define BYTE_ORDER to be equal to either LITTLE_ENDIAN or BIG_ENDIAN
#endif

#define SHA1HANDSOFF 1
#define SHA1_DIGEST_LENGTH  20    /* 160 bit */
#define SHA1_BLOCK_LENGTH   64    /* 512 bit */

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
/* FIXME: can we do this in an endian-proof way? */
#ifdef BYTE_ORDER
 #define blk0(i) block->l[i]
#else
 #define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xff00ff00) |(rol(block->l[i],8)&0x00ff00ff))
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] ^block->l[(i+2)&15]^block->l[i&15],1))
/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5a827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5a827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ed9eba1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8f1bbcdc+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xca62c1d6+rol(v,5);w=rol(w,30);

typedef struct _SHA1_CTX {
    uint32_t    state[5];
    uint32_t    count[2];
    uint8_t     buffer[SHA1_BLOCK_LENGTH];
} SHA1_CTX;


// ----------------------------------------------------------------------------------------------------------
/* Hash a single 512-bit block. This is the core of the algorithm. */
static void SHA1_Transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e;
    typedef union {
        uint8_t  c[64];
        uint32_t l[16];
    } CHAR64LONG16;
    CHAR64LONG16* block;

#ifdef SHA1HANDSOFF
    CHAR64LONG16 workspace;
    block = &workspace;
    memcpy(block, buffer, 64);
#else
    block = (CHAR64LONG16*)buffer;
#endif

    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0);
    R0(e,a,b,c,d, 1);
    R0(d,e,a,b,c, 2);
    R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4);
    R0(a,b,c,d,e, 5);
    R0(e,a,b,c,d, 6);
    R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8);
    R0(b,c,d,e,a, 9);
    R0(a,b,c,d,e,10);
    R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12);
    R0(c,d,e,a,b,13);
    R0(b,c,d,e,a,14);
    R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16);
    R1(d,e,a,b,c,17);
    R1(c,d,e,a,b,18);
    R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20);
    R2(e,a,b,c,d,21);
    R2(d,e,a,b,c,22);
    R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24);
    R2(a,b,c,d,e,25);
    R2(e,a,b,c,d,26);
    R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28);
    R2(b,c,d,e,a,29);
    R2(a,b,c,d,e,30);
    R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32);
    R2(c,d,e,a,b,33);
    R2(b,c,d,e,a,34);
    R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36);
    R2(d,e,a,b,c,37);
    R2(c,d,e,a,b,38);
    R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40);
    R3(e,a,b,c,d,41);
    R3(d,e,a,b,c,42);
    R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44);
    R3(a,b,c,d,e,45);
    R3(e,a,b,c,d,46);
    R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48);
    R3(b,c,d,e,a,49);
    R3(a,b,c,d,e,50);
    R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52);
    R3(c,d,e,a,b,53);
    R3(b,c,d,e,a,54);
    R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56);
    R3(d,e,a,b,c,57);
    R3(c,d,e,a,b,58);
    R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60);
    R4(e,a,b,c,d,61);
    R4(d,e,a,b,c,62);
    R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64);
    R4(a,b,c,d,e,65);
    R4(e,a,b,c,d,66);
    R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68);
    R4(b,c,d,e,a,69);
    R4(a,b,c,d,e,70);
    R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72);
    R4(c,d,e,a,b,73);
    R4(b,c,d,e,a,74);
    R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76);
    R4(d,e,a,b,c,77);
    R4(c,d,e,a,b,78);
    R4(b,c,d,e,a,79);

    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

    /* Wipe variables */
    a = b = c = d = e = 0;
}

static void SHA1_Reset(SHA1_CTX* context) {

    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
    context->state[4] = 0xc3d2e1f0;
    context->count[0] = context->count[1] = 0;
}

/**
 * Initialize new context
 *
 * @param context SHA1-Context
 */
static void SHA1_Init(SHA1_CTX* context) {

    SHA1_Reset(context);

}

/**
 * Run your data through this
 *
 * @param context SHA1-Context
 * @param p       Buffer to run SHA1 on
 * @param len     Number of bytes
 */
static void SHA1_Update(SHA1_CTX* context, const void *p, size_t len) {
    const uint8_t* data = p;
    size_t i, j;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += (uint32_t)(len << 3)) < (len << 3)) {
        context->count[1]++;
    }
    context->count[1] += (uint32_t)(len >> 29);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64-j));
        SHA1_Transform(context->state, context->buffer);
        for ( ; i + 63 < len; i += 64) {
            SHA1_Transform(context->state, data + i);
        }
        j = 0;
    } else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}


/**
 * Add padding and return the message digest
 *
 * @param digest  Generated message digest
 * @param context SHA1-Context
 */
static void SHA1_Final(uint8_t digest[SHA1_DIGEST_LENGTH], SHA1_CTX* context) {
    uint32_t i;
    uint8_t  finalcount[8];

    for (i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((context->count[(i >= 4 ? 0 : 1)] >> ((3-(i & 3)) * 8) ) & 255);
    }
    SHA1_Update(context, (uint8_t *)"\200", 1);
    while ((context->count[0] & 504) != 448) {
        SHA1_Update(context, (uint8_t *)"\0", 1);
    }
    SHA1_Update(context, finalcount, 8); /* Should cause SHA1_Transform */
    for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
        digest[i] = (uint8_t) ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }

    /* Wipe variables */
    i = 0;
    memset(context->buffer, 0, 64);
    memset(context->state, 0, 20);
    memset(context->count, 0, 8);
    memset(finalcount, 0, 8);	/* SWR */

#ifdef SHA1HANDSOFF  /* make SHA1Transform overwrite its own static vars */
    SHA1_Transform(context->state, context->buffer);
#endif
}

// -----------------------------------------------------------------------------------------------------------------------------------------------------
// PUBLIC
// -----------------------------------------------------------------------------------------------------------------------------------------------------
size_t vxssh_sha1_digest_len() {
    return SHA1_DIGEST_LENGTH;
}

size_t vxssh_sha1_block_len() {
    return SHA1_BLOCK_LENGTH;
}

size_t vxssh_sha1_ctx_size() {
    return sizeof(SHA1_CTX);
}

int vxssh_sha1_init(vxssh_sha1_ctx_t **ctx) {
    vxssh_sha1_ctx_t *md_ctx = NULL;
    //
    if (!ctx) {
        return EINVAL;
    }
    md_ctx = vxssh_mem_zalloc(sizeof(vxssh_sha1_ctx_t), NULL);
    if(md_ctx == NULL) {
        return ENOMEM;
    }
    SHA1_Init(md_ctx);
    *ctx = md_ctx;
    //
    return OK;
}

int vxssh_sha1_update(vxssh_sha1_ctx_t *ctx, const void *data, size_t data_size) {
    if (!ctx || !data) {
        return EINVAL;
    }
    SHA1_Update(ctx, data, data_size);
    return OK;
}

int vxssh_sha1_final(vxssh_sha1_ctx_t *ctx, uint8_t *digest) {
    if (!ctx || !digest) {
        return EINVAL;
    }
    SHA1_Final(digest, ctx);
    return OK;
}

int vxssh_sha1_digest(const void *input, size_t input_len, uint8_t *digest, size_t digest_len) {
    SHA1_CTX context;

    if (!input) {
        return EINVAL;
    }
    if(digest_len < SHA1_DIGEST_LENGTH) {
        return ERANGE;
    }

    SHA1_Init(&context);
    SHA1_Update(&context, input, input_len);
    SHA1_Final(digest, &context);

    return OK;
}
