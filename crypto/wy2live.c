/* wy2live.c —— 用真实的 C 实现向微验服务器做一次握手，验证协议实现正确 */
#include "wy2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>

#define HOST     "wy.llua.cn"
#define APITOKRN "992664d2b407c0f899284d7d5c0df89a"
#define APPKEY   "S0ZyYe9JJypNRRSY"
#define LOGIN_ID "8EE5C3CDF"

static const char *SRV_X =
    "2fc060d1a94db93817765b2f8d79e083dd24963aa1266428c9e619ace7426103";
static const char *SRV_ED =
    "97a8a1c13919f437fade2c27d2b0ccdefa74ed1532ff82029eb4e7aa754a9f01";
static const char *LIC_PUB =
    "b88f2bb3257985e0f192324dcb9dbf05f39ec065b2ccdc0dcecf8d0f13f1272e";
static const char *LIC_CLI =
    "9dd3d639dd59172726c6a44f936d411956de680b5a6e6ce0ef9fdf3b5337f5cb";

struct membuf { char *data; size_t len; };

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct membuf *m = (struct membuf *)userdata;
    size_t add = size * nmemb;
    char *p = realloc(m->data, m->len + add + 1);
    if (!p) return 0;
    m->data = p;
    memcpy(m->data + m->len, ptr, add);
    m->len += add;
    m->data[m->len] = 0;
    return add;
}

/* 从 JSON 里取出 "key":"value" 的字符串值（key 为 hex 串，不会出现在别处） */
static int json_str(const char *json, const char *key, char *out, size_t outlen)
{
    char pat[160];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p && *p != ':') p++;
    if (!*p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outlen) out[i++] = *p++;
    out[i] = 0;
    return (int)i;
}

/* 简易 MD5 */
#include <stdint.h>
static void md5_hex(const char *s, char out[33])
{
    /* 用系统 openssl? 为避免依赖，这里调用 sha 不行。改用外部提供的 openssl 命令太重。
       微验的 sign 是 MD5，这里借 libcrypto。*/
    extern unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);
    unsigned char md[16];
    MD5((const unsigned char *)s, strlen(s), md);
    for (int i = 0; i < 16; i++) sprintf(out + i * 2, "%02x", md[i]);
    out[32] = 0;
}

int main(void)
{
    uint8_t srv_x[32], srv_ed[32], lic_pub[32], lic_cli[32];
    wy2_from_hex(SRV_X, srv_x, 32);
    wy2_from_hex(SRV_ED, srv_ed, 32);
    wy2_from_hex(LIC_PUB, lic_pub, 32);
    wy2_from_hex(LIC_CLI, lic_cli, 32);

    const char *card = getenv("WY_CARD");
    if (!card) card = "TEST-CARD-0000";
    const char *mark = "testdevice0123456789abcdef";

    long T = (long)time(NULL);
    srand((unsigned)T);
    char value[64];
    snprintf(value, sizeof value, "%ld%d", T, rand() % 900000 + 100000);

    char sign_src[512], sign[33];
    snprintf(sign_src, sizeof sign_src, "kami=%s&markcode=%s&t=%ld&%s", card, mark, T, APPKEY);
    md5_hex(sign_src, sign);

    char plain[1024];
    snprintf(plain, sizeof plain,
             "id=%s&kami=%s&markcode=%s&t=%ld&sign=%s&value=%s",
             LOGIN_ID, card, mark, T, sign, value);

    char *body = NULL;
    uint8_t resp_key[32];
    if (wy2_seal(srv_x, lic_pub, lic_cli, APPKEY, plain, card, &body, resp_key) != 0) {
        printf("封包失败\n");
        return 1;
    }
    printf("明文: %s\n", plain);
    printf("帧长: %zu 字节, 段数: ", strlen(body));
    int dots = 0; for (char *p = body; *p; p++) if (*p == '.') dots++;
    printf("%d\n", dots + 1);

    char url[256];
    snprintf(url, sizeof url, "https://%s/v2/%s", HOST, APITOKRN);

    CURL *c = curl_easy_init();
    struct membuf resp = {0};
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: text/plain");
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 20L);

    CURLcode rc = curl_easy_perform(c);
    if (rc != CURLE_OK) {
        printf("HTTP 失败: %s\n", curl_easy_strerror(rc));
        return 1;
    }
    printf("响应: %.120s...\n", resp.data ? resp.data : "");

    static char data_hex[8192], sig_hex[256];
    if (json_str(resp.data, "data", data_hex, sizeof data_hex) < 0 ||
        json_str(resp.data, "sig", sig_hex, sizeof sig_hex) < 0) {
        printf("没有信封字段 → 明文响应: %s\n", resp.data);
        return 0;
    }

    char *pt = NULL;
    int r = wy2_open(srv_ed, resp_key, data_hex, sig_hex, &pt);
    if (r != 0) {
        printf("信封处理失败: %d（-2=验签失败, -3=解密失败）\n", r);
        return 1;
    }
    printf("\n[成功] 验签+解密通过\n业务明文: %s\n", pt);
    free(pt);
    free(body);
    free(resp.data);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(c);
    return 0;
}
