/* wy2.h —— 微验 动态密钥 v2 客户端协议实现 */
#ifndef WY2_H
#define WY2_H
#include <stddef.h>
#include <stdint.h>

/* 填充随机字节（iOS 用 arc4random_buf，其他平台用 /dev/urandom） */
void wy2_random(void *buf, size_t len);

/* 十六进制 */
void wy2_to_hex(const uint8_t *in, size_t n, char *out);          /* out 需要 2n+1 */
int  wy2_from_hex(const char *hex, uint8_t *out, size_t maxlen);  /* 返回字节数，失败 -1 */

/* SHA-256 / HMAC-SHA256 / HKDF-SHA256 */
void wy2_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void wy2_hmac_sha256(const uint8_t *key, size_t klen,
                     const uint8_t *msg, size_t mlen, uint8_t out[32]);
int  wy2_hkdf_sha256(const uint8_t *ikm, size_t ikmlen,
                     const uint8_t *salt, size_t saltlen,
                     const uint8_t *info, size_t infolen,
                     uint8_t *out, size_t outlen);

/* ChaCha20-Poly1305 (IETF, AAD 长度可为 0) */
int wy2_aead_seal(const uint8_t key[32], const uint8_t nonce[12],
                  const uint8_t *aad, size_t aadlen,
                  const uint8_t *plain, size_t plen, uint8_t *out);   /* out = plen+16 */
int wy2_aead_open(const uint8_t key[32], const uint8_t nonce[12],
                  const uint8_t *aad, size_t aadlen,
                  const uint8_t *ct, size_t ctlen, uint8_t *out);     /* ct 含 16B tag */

/* 协议：封装请求
 * plain   —— 明文查询串（id=..&kami=..&markcode=..&t=..&sign=..&value=..）
 * appkey  —— 应用密钥；kami 非空时会在帧尾追加 rk 证明
 * 返回 0 成功；body_out 由调用方 free()
 */
int wy2_seal(const uint8_t srv_x25519_pub[32], const uint8_t lic_pub[32],
             const uint8_t lic_cli[32], const char *appkey,
             const char *plain, const char *kami,
             char **body_out, uint8_t resp_key[32]);

/* 协议：解响应信封
 * data_hex / sig_hex 来自响应 JSON
 * 验签失败返回 -2，解密失败返回 -3，成功 0 且 plain_out 由调用方 free()
 */
int wy2_open(const uint8_t srv_ed25519_pub[32], const uint8_t resp_key[32],
             const char *data_hex, const char *sig_hex, char **plain_out);

#endif
