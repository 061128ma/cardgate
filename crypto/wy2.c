/* wy2.c —— 微验 动态密钥 v2 协议实现（自包含，无第三方依赖） */
#include "wy2.h"
#include "tweetnacl.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if defined(__APPLE__)
#include <stdlib.h>   /* arc4random_buf */
#else
#include <stdio.h>
#endif

void wy2_random(void *buf, size_t len)
{
#if defined(__APPLE__)
    arc4random_buf(buf, len);
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { size_t got = fread(buf, 1, len, f); (void)got; fclose(f); }
#endif
}

/* ---------------- hex ---------------- */
static const char HEXD[] = "0123456789abcdef";

void wy2_to_hex(const uint8_t *in, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = HEXD[in[i] >> 4];
        out[i * 2 + 1] = HEXD[in[i] & 0x0F];
    }
    out[n * 2] = 0;
}

static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int wy2_from_hex(const char *hex, uint8_t *out, size_t maxlen)
{
    size_t n = strlen(hex);
    if (n % 2) return -1;
    n /= 2;
    if (n > maxlen) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hexv(hex[i * 2]), lo = hexv(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)n;
}

/* ---------------- SHA-256 ---------------- */
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

typedef struct { uint32_t h[8]; uint64_t len; uint8_t buf[64]; size_t n; } sha256_ctx;

static void sha256_block(sha256_ctx *c, const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR32(w[i-15],7) ^ ROTR32(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTR32(w[i-2],17) ^ ROTR32(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3],e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR32(e,6) ^ ROTR32(e,11) ^ ROTR32(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROTR32(a,2) ^ ROTR32(a,13) ^ ROTR32(a,22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void sha256_init(sha256_ctx *c)
{
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->len = 0; c->n = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *p, size_t n)
{
    c->len += n;
    while (n) {
        size_t take = 64 - c->n;
        if (take > n) take = n;
        memcpy(c->buf + c->n, p, take);
        c->n += take; p += take; n -= take;
        if (c->n == 64) { sha256_block(c, c->buf); c->n = 0; }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->len * 8;
    uint8_t z = 0, pad = 0x80;
    sha256_update(c, &pad, 1);
    while (c->n != 56) sha256_update(c, &z, 1);
    uint8_t lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (uint8_t)(bits >> (56 - i*8));
    sha256_update(c, lb, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

void wy2_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

void wy2_hmac_sha256(const uint8_t *key, size_t klen,
                     const uint8_t *msg, size_t mlen, uint8_t out[32])
{
    uint8_t k[64];
    memset(k, 0, sizeof k);
    if (klen > 64) wy2_sha256(key, klen, k);
    else memcpy(k, key, klen);

    uint8_t ipad[64], opad[64], inner[32];
    for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }

    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, ipad, 64);
    sha256_update(&c, msg, mlen);
    sha256_final(&c, inner);

    sha256_init(&c);
    sha256_update(&c, opad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);
}

int wy2_hkdf_sha256(const uint8_t *ikm, size_t ikmlen,
                    const uint8_t *salt, size_t saltlen,
                    const uint8_t *info, size_t infolen,
                    uint8_t *out, size_t outlen)
{
    uint8_t prk[32], t[32];
    if (salt && saltlen) wy2_hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
    else {
        uint8_t zero[32]; memset(zero, 0, 32);
        wy2_hmac_sha256(zero, 32, ikm, ikmlen, prk);
    }

    size_t tlen = 0, done = 0;
    uint8_t counter = 1;
    while (done < outlen) {
        size_t mlen = tlen + infolen + 1;
        uint8_t *m = (uint8_t *)malloc(mlen);
        if (!m) return -1;
        if (tlen) memcpy(m, t, tlen);
        if (infolen) memcpy(m + tlen, info, infolen);
        m[tlen + infolen] = counter;
        wy2_hmac_sha256(prk, 32, m, mlen, t);
        free(m);
        tlen = 32;
        size_t take = (outlen - done) < 32 ? (outlen - done) : 32;
        memcpy(out + done, t, take);
        done += take;
        counter++;
    }
    return 0;
}

/* ---------------- ChaCha20 ---------------- */
#define ROTL32(v,c) (((v) << (c)) | ((v) >> (32 - (c))))

static void chacha20_block(const uint8_t key[32], const uint8_t nonce[12],
                           uint32_t counter, uint8_t out[64])
{
    uint32_t st[16], x[16];
    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
    for (int i = 0; i < 8; i++)
        st[4+i] = (uint32_t)key[i*4] | ((uint32_t)key[i*4+1] << 8) |
                  ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    st[12] = counter;
    for (int i = 0; i < 3; i++)
        st[13+i] = (uint32_t)nonce[i*4] | ((uint32_t)nonce[i*4+1] << 8) |
                   ((uint32_t)nonce[i*4+2] << 16) | ((uint32_t)nonce[i*4+3] << 24);
    memcpy(x, st, sizeof x);

#define QR(a,b,c,d) \
    x[a]+=x[b]; x[d]^=x[a]; x[d]=ROTL32(x[d],16); \
    x[c]+=x[d]; x[b]^=x[c]; x[b]=ROTL32(x[b],12); \
    x[a]+=x[b]; x[d]^=x[a]; x[d]=ROTL32(x[d],8);  \
    x[c]+=x[d]; x[b]^=x[c]; x[b]=ROTL32(x[b],7);

    for (int i = 0; i < 10; i++) {
        QR(0,4,8,12)  QR(1,5,9,13)   QR(2,6,10,14) QR(3,7,11,15)
        QR(0,5,10,15) QR(1,6,11,12)  QR(2,7,8,13)  QR(3,4,9,14)
    }
#undef QR
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + st[i];
        out[i*4]   = (uint8_t)v;
        out[i*4+1] = (uint8_t)(v >> 8);
        out[i*4+2] = (uint8_t)(v >> 16);
        out[i*4+3] = (uint8_t)(v >> 24);
    }
}

static void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                         uint32_t counter, const uint8_t *in, size_t len, uint8_t *out)
{
    uint8_t ks[64];
    size_t off = 0;
    while (off < len) {
        chacha20_block(key, nonce, counter++, ks);
        size_t take = (len - off) < 64 ? (len - off) : 64;
        for (size_t i = 0; i < take; i++) out[off+i] = in[off+i] ^ ks[i];
        off += take;
    }
}

/* ---------------- AEAD ---------------- */
static void aead_tag(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *aad, size_t aadlen,
                     const uint8_t *ct, size_t ctlen, uint8_t tag[16])
{
    uint8_t block0[64];
    chacha20_block(key, nonce, 0, block0);

    size_t aadpad = aadlen ? ((16 - (aadlen % 16)) % 16) : 0;
    size_t ctpad  = ctlen  ? ((16 - (ctlen  % 16)) % 16) : 0;
    size_t total  = aadlen + aadpad + ctlen + ctpad + 16;

    uint8_t *buf = (uint8_t *)calloc(1, total ? total : 1);
    if (!buf) return;
    size_t p = 0;
    if (aadlen) { memcpy(buf, aad, aadlen); p += aadlen + aadpad; }
    if (ctlen)  { memcpy(buf + p, ct, ctlen); p += ctlen + ctpad; }

    uint64_t a = aadlen, b = ctlen;
    for (int i = 0; i < 8; i++) buf[p+i]     = (uint8_t)(a >> (8*i));
    for (int i = 0; i < 8; i++) buf[p+8+i]   = (uint8_t)(b >> (8*i));

    crypto_onetimeauth(tag, buf, p + 16, block0);
    free(buf);
}

int wy2_aead_seal(const uint8_t key[32], const uint8_t nonce[12],
                  const uint8_t *aad, size_t aadlen,
                  const uint8_t *plain, size_t plen, uint8_t *out)
{
    if (plen) chacha20_xor(key, nonce, 1, plain, plen, out);
    aead_tag(key, nonce, aad, aadlen, out, plen, out + plen);
    return 0;
}

int wy2_aead_open(const uint8_t key[32], const uint8_t nonce[12],
                  const uint8_t *aad, size_t aadlen,
                  const uint8_t *ct, size_t ctlen, uint8_t *out)
{
    if (ctlen < 16) return -1;
    size_t plen = ctlen - 16;
    uint8_t tag[16];
    aead_tag(key, nonce, aad, aadlen, ct, plen, tag);
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (uint8_t)(tag[i] ^ ct[plen + i]);
    if (diff) return -2;
    if (plen) chacha20_xor(key, nonce, 1, ct, plen, out);
    return 0;
}

/* ---------------- 协议 ---------------- */
static const uint8_t SALT[] = "wy-v2-secure";
static const uint8_t INFO_REQ[] = "request";
static const uint8_t INFO_RES[] = "response";

static int lic_secret(const uint8_t lic_pub[32], const uint8_t lic_cli[32], uint8_t out[32])
{
    uint8_t shared[32];
    if (crypto_scalarmult(shared, lic_cli, lic_pub) != 0) return -1;
    memcpy(out, shared, 32);
    return 0;
}

int wy2_seal(const uint8_t srv_x25519_pub[32], const uint8_t lic_pub[32],
             const uint8_t lic_cli[32], const char *appkey,
             const char *plain, const char *kami,
             char **body_out, uint8_t resp_key[32])
{
    if (!plain || !body_out) return -1;

    uint8_t eph_priv[32], eph_pub[32], shared[32];
    wy2_random(eph_priv, 32);
    /* X25519 会自行 clamp 私钥 */
    if (crypto_scalarmult(eph_pub, eph_priv, (const uint8_t *)"\x09\x00\x00\x00\x00\x00\x00\x00"
                          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                          "\x00\x00\x00\x00\x00\x00\x00\x00") != 0) return -1;
    if (crypto_scalarmult(shared, eph_priv, srv_x25519_pub) != 0) return -1;

    uint8_t allzero = 1;
    for (int i = 0; i < 32; i++) if (shared[i]) { allzero = 0; break; }
    if (allzero) return -1;

    uint8_t req_key[32];
    if (wy2_hkdf_sha256(shared, 32, SALT, sizeof(SALT) - 1, INFO_REQ, sizeof(INFO_REQ) - 1, req_key, 32) != 0)
        return -1;
    if (wy2_hkdf_sha256(shared, 32, SALT, sizeof(SALT) - 1, INFO_RES, sizeof(INFO_RES) - 1, resp_key, 32) != 0)
        return -1;

    size_t plen = strlen(plain);
    uint8_t nonce[12];
    wy2_random(nonce, 12);

    uint8_t *ct = (uint8_t *)malloc(plen + 16);
    if (!ct) return -1;
    wy2_aead_seal(req_key, nonce, NULL, 0, (const uint8_t *)plain, plen, ct);

    /* 组装 hex 帧 */
    char *body = (char *)malloc(64 + 64 + (plen + 16) * 2 + 80);
    if (!body) { free(ct); return -1; }
    char h_eph[65], h_nonce[25];
    wy2_to_hex(eph_pub, 32, h_eph);
    wy2_to_hex(nonce, 12, h_nonce);
    int len = sprintf(body, "%s.%s.", h_eph, h_nonce);
    wy2_to_hex(ct, plen + 16, body + len);
    len += (int)((plen + 16) * 2);

    /* rk 证明：proof = HMAC(rk, nonce)，rk = HKDF(appkey \0 kami \0 licSecret, "wy-lic-rk") */
    if (appkey && *appkey && kami && *kami) {
        uint8_t secret[32];
        if (lic_secret(lic_pub, lic_cli, secret) == 0) {
            size_t ak = strlen(appkey), km = strlen(kami);
            size_t seedlen = ak + 1 + km + 1 + 32;
            uint8_t *seed = (uint8_t *)malloc(seedlen);
            if (seed) {
                memcpy(seed, appkey, ak);
                seed[ak] = 0;
                memcpy(seed + ak + 1, kami, km);
                seed[ak + 1 + km] = 0;
                memcpy(seed + ak + 1 + km + 1, secret, 32);

                uint8_t rk[32], proof[32];
                if (wy2_hkdf_sha256(seed, seedlen, SALT, sizeof(SALT) - 1,
                                    (const uint8_t *)"wy-lic-rk", 9, rk, 32) == 0) {
                    wy2_hmac_sha256(rk, 32, nonce, 12, proof);
                    body[len++] = '.';
                    wy2_to_hex(proof, 32, body + len);
                    len += 64;
                }
                free(seed);
            }
        }
    }

    body[len] = 0;
    free(ct);
    *body_out = body;
    return 0;
}

int wy2_open(const uint8_t srv_ed25519_pub[32], const uint8_t resp_key[32],
             const char *data_hex, const char *sig_hex, char **plain_out)
{
    if (!data_hex || !sig_hex || !plain_out) return -1;

    size_t dn = strlen(data_hex) / 2;
    uint8_t *payload = (uint8_t *)malloc(dn ? dn : 1);
    uint8_t sig[64];
    if (!payload) return -1;
    if (wy2_from_hex(data_hex, payload, dn) != (int)dn) { free(payload); return -1; }
    if (wy2_from_hex(sig_hex, sig, 64) != 64) { free(payload); return -1; }
    if (dn < 28) { free(payload); return -1; }

    /* 验签对象 = resp_key || payload */
    uint8_t msg[32 + 4096];
    if (dn + 32 > sizeof msg) { free(payload); return -1; }
    memcpy(msg, resp_key, 32);
    memcpy(msg + 32, payload, dn);

    uint8_t *sigbuf = (uint8_t *)malloc(64 + sizeof msg);
    uint8_t *out = (uint8_t *)malloc(64 + sizeof msg);
    if (!sigbuf || !out) { free(payload); free(sigbuf); free(out); return -1; }

    memcpy(sigbuf, sig, 64);
    memcpy(sigbuf + 64, msg, 32 + dn);

    unsigned long long mlen = 0;
    int ok = crypto_sign_open(out, &mlen, sigbuf, 64 + 32 + dn, srv_ed25519_pub);
    if (ok != 0) {
        free(payload); free(sigbuf); free(out);
        return -2;
    }

    /* payload = nonce(12) || ct */
    uint8_t nonce[12];
    memcpy(nonce, payload, 12);
    size_t ctlen = dn - 12;
    uint8_t *pt = (uint8_t *)malloc(ctlen + 1);
    if (!pt) { free(payload); free(sigbuf); free(out); return -1; }
    if (wy2_aead_open(resp_key, nonce, NULL, 0, payload + 12, ctlen, pt) != 0) {
        free(payload); free(sigbuf); free(out); free(pt);
        return -3;
    }
    pt[ctlen - 16] = 0;
    free(payload); free(sigbuf); free(out);
    *plain_out = (char *)pt;
    return 0;
}
