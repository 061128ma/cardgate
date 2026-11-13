/* tweetnacl.h —— 仅保留本项目所需部分（公有领域，D. J. Bernstein 等） */
#ifndef TWEETNACL_H
#define TWEETNACL_H
#include <stdint.h>

/* X25519: q = n * p */
int crypto_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p);

/* Ed25519 验签：m 输出长度 *mlen，返回 0 表示签名有效 */
int crypto_sign_open(uint8_t *m, unsigned long long *mlen,
                     const uint8_t *sm, unsigned long long n,
                     const uint8_t *pk);

/* Poly1305 一次性认证 */
int crypto_onetimeauth(uint8_t *out, const uint8_t *m,
                       unsigned long long n, const uint8_t *k);

int crypto_verify_16(const uint8_t *x, const uint8_t *y);
int crypto_verify_32(const uint8_t *x, const uint8_t *y);

#endif
