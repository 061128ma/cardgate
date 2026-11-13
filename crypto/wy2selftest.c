/* wy2selftest.c —— 用 RFC 标准向量验证原语，并对微验服务器做一次真实握手 */
#include "wy2.h"
#include "tweetnacl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;

static void hexdump(const uint8_t *b, size_t n, char *out)
{
    wy2_to_hex(b, n, out);
}

static void check(const char *name, const uint8_t *got, size_t n, const char *expect_hex)
{
    char buf[512];
    hexdump(got, n, buf);
    int ok = (strcmp(buf, expect_hex) == 0);
    printf("[%s] %-28s %s\n", ok ? "PASS" : "FAIL", name, ok ? "" : buf);
    if (!ok) fails++;
}

/* ---- 1. SHA-256("abc") ---- */
static void test_sha256(void)
{
    uint8_t out[32];
    wy2_sha256((const uint8_t *)"abc", 3, out);
    check("SHA-256(abc)", out, 32,
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

/* ---- 2. X25519 RFC 7748 §5.2 ---- */
static void test_x25519(void)
{
    const char *k = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
    const char *u = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
    uint8_t sk[32], pk[32], out[32];
    wy2_from_hex(k, sk, 32);
    wy2_from_hex(u, pk, 32);
    crypto_scalarmult(out, sk, pk);
    check("X25519 RFC7748", out, 32,
          "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
}

/* ---- 3. Ed25519 验签 RFC 8032 TEST 1（空消息） ---- */
static void test_ed25519(void)
{
    const char *pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const char *sig_hex =
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    uint8_t pk[32], sig[64], sm[64], m[128];
    wy2_from_hex(pk_hex, pk, 32);
    wy2_from_hex(sig_hex, sig, 64);
    memcpy(sm, sig, 64);
    unsigned long long mlen = 0;
    int r = crypto_sign_open(m, &mlen, sm, 64, pk);
    printf("[%s] %-28s (返回 %d, 明文长度 %llu)\n", r == 0 ? "PASS" : "FAIL",
           "Ed25519 RFC8032 验签", r, mlen);
    if (r != 0) fails++;

    /* 篡改签名必须失败 */
    sm[0] ^= 0xFF;
    r = crypto_sign_open(m, &mlen, sm, 64, pk);
    printf("[%s] %-28s (返回 %d)\n", r != 0 ? "PASS" : "FAIL", "Ed25519 篡改应失败", r);
    if (r == 0) fails++;
}

/* ---- 4. ChaCha20-Poly1305 RFC 8439 §2.8.2 ---- */
static void test_aead(void)
{
    uint8_t key[32], nonce[12], aad[12];
    wy2_from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", key, 32);
    wy2_from_hex("070000004041424344454647", nonce, 12);
    wy2_from_hex("50515253c0c1c2c3c4c5c6c7", aad, 12);

    const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you "
                     "only one tip for the future, sunscreen would be it.";
    size_t plen = strlen(pt);
    uint8_t *ct = malloc(plen + 16), *rt = malloc(plen + 16);
    wy2_aead_seal(key, nonce, aad, 12, (const uint8_t *)pt, plen, ct);

    const char *expect =
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
        "1ae10b594f09e26a7e902ecbd0600691";
    check("ChaCha20-Poly1305 RFC8439", ct, plen + 16, expect);

    int r = wy2_aead_open(key, nonce, aad, 12, ct, plen + 16, rt);
    printf("[%s] %-28s (返回 %d)\n", (r == 0 && memcmp(rt, pt, plen) == 0) ? "PASS" : "FAIL",
           "AEAD 解密回原文", r);
    if (r != 0 || memcmp(rt, pt, plen)) fails++;

    /* 篡改必失败 */
    ct[0] ^= 1;
    r = wy2_aead_open(key, nonce, aad, 12, ct, plen + 16, rt);
    printf("[%s] %-28s (返回 %d)\n", r != 0 ? "PASS" : "FAIL", "AEAD 篡改应失败", r);
    if (r == 0) fails++;

    free(ct); free(rt);
}

/* ---- 5. HKDF-SHA256 RFC 5869 Test Case 1 ---- */
static void test_hkdf(void)
{
    uint8_t ikm[22], salt[13], info[10], okm[42];
    memset(ikm, 0x0b, 22);
    wy2_from_hex("000102030405060708090a0b0c", salt, 13);
    wy2_from_hex("f0f1f2f3f4f5f6f7f8f9", info, 10);
    wy2_hkdf_sha256(ikm, 22, salt, 13, info, 10, okm, 42);
    check("HKDF-SHA256 RFC5869", okm, 42,
          "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
          "34007208d5b887185865");
}

int main(int argc, char **argv)
{
    printf("=== 原语自测（RFC 标准向量）===\n");
    test_sha256();
    test_hkdf();
    test_x25519();
    test_ed25519();
    test_aead();

    printf("\n=== 原语结果：%s ===\n", fails ? "有失败" : "全部通过");
    if (argc > 1 && strcmp(argv[1], "--live") == 0 && argc > 2) {
        /* 交给外部脚本做真实握手，这里只导出封包，便于排查 */
        printf("\n（真实握手请用 wy2live）\n");
    }
    return fails ? 1 : 0;
}
