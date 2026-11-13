/* wy2live.c —— 完整模拟客户端逻辑（含时间校正重试），对微验真实服务器验证 */
#include "wy2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include <openssl/md5.h>

#define HOST     "wy.llua.cn"
#define APITOKRN "992664d2b407c0f899284d7d5c0df89a"
#define APPKEY   "S0ZyYe9JJypNRRSY"
#define LOGIN_ID "8EE5C3CDF"

static const char *SRV_X  = "2fc060d1a94db93817765b2f8d79e083dd24963aa1266428c9e619ace7426103";
static const char *SRV_ED = "97a8a1c13919f437fade2c27d2b0ccdefa74ed1532ff82029eb4e7aa754a9f01";
static const char *LIC_PUB = "b88f2bb3257985e0f192324dcb9dbf05f39ec065b2ccdc0dcecf8d0f13f1272e";
static const char *LIC_CLI = "9dd3d639dd59172726c6a44f936d411956de680b5a6e6ce0ef9fdf3b5337f5cb";

static uint8_t srvX[32], srvEd[32], licPub[32], licCli[32];

struct buf { char *p; size_t n; };

static size_t wr(void *ptr, size_t s, size_t n, void *ud)
{
    struct buf *b = (struct buf *)ud;
    char *np = realloc(b->p, b->n + s * n + 1);
    if (!np) return 0;
    b->p = np;
    memcpy(b->p + b->n, ptr, s * n);
    b->n += s * n;
    b->p[b->n] = 0;
    return s * n;
}

static int jstr(const char *j, const char *key, char *out, size_t cap)
{
    char pat[200];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(j, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p && *p != ':') p++;
    if (!*p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    size_t i = 0;
    if (*p == '"') {           /* 字符串值 */
        p++;
        while (*p && *p != '"' && i + 1 < cap) out[i++] = *p++;
    } else {                   /* 数字/布尔值 */
        while (*p && *p != ',' && *p != '}' && i + 1 < cap) out[i++] = *p++;
    }
    /* 去掉尾部空白 */
    while (i > 0 && (out[i-1] == ' ' || out[i-1] == '\t' || out[i-1] == '\r' || out[i-1] == '\n')) i--;
    out[i] = 0;
    return (int)i;
}

static long long now_ts(void) { return (long long)time(NULL); }

/* 一次完整登录；返回业务 code，serverTime 回填服务器时间 */
static long exec_login(const char *card, long long t_off, long long *serverTime,
                       char *outPlain, size_t cap)
{
    long long T = now_ts() + t_off;
    char val[64];
    snprintf(val, sizeof val, "%lld%u", T, (unsigned)(100000 + rand() % 900000));

    char src[512], sign[33];
    snprintf(src, sizeof src, "kami=%s&markcode=%s&t=%lld&%s", card,
             "testdevice0123456789abcdef", T, APPKEY);
    unsigned char md[16];
    MD5((const unsigned char *)src, strlen(src), md);
    for (int i = 0; i < 16; i++) sprintf(sign + i * 2, "%02x", md[i]);

    char plain[1024];
    snprintf(plain, sizeof plain, "id=%s&kami=%s&markcode=%s&t=%lld&sign=%s&value=%s",
             LOGIN_ID, card, "testdevice0123456789abcdef", T, sign, val);

    char *frame = NULL;
    uint8_t rk[32];
    if (wy2_seal(srvX, licPub, licCli, APPKEY, plain, card, &frame, rk) != 0) return -100;

    char url[256];
    snprintf(url, sizeof url, "https://%s/v2/%s", HOST, APITOKRN);

    CURL *c = curl_easy_init();
    struct buf b = {0};
    struct curl_slist *h = NULL;
    h = curl_slist_append(h, "Content-Type: text/plain");
    curl_easy_setopt(c, CURLOPT_URL, url);
    curl_easy_setopt(c, CURLOPT_POST, 1L);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, frame);
    curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)strlen(frame));
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, wr);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &b);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 20L);
    CURLcode rc = curl_easy_perform(c);
    if (rc != CURLE_OK) { curl_easy_cleanup(c); free(frame); return -101; }

    static char dh[16384], sh[512];
    if (jstr(b.p, "data", dh, sizeof dh) < 0 || jstr(b.p, "sig", sh, sizeof sh) < 0) {
        curl_easy_cleanup(c); free(frame); free(b.p);
        return -102;
    }
    char *pt = NULL;
    int r = wy2_open(srvEd, rk, dh, sh, &pt);
    if (r != 0) { curl_easy_cleanup(c); free(frame); free(b.p); return (r == -2) ? -103 : -104; }

    snprintf(outPlain, cap, "%s", pt);
    /* 解析 code 与服务器时间 */
    char codebuf[32] = {0}, timebuf[32] = {0};
    jstr(pt, "f891012afe301f1ed6b0d65d77ed68c62", codebuf, sizeof codebuf);
    jstr(pt, "bf921c5bf4325e0cea243fb1e89424921", timebuf, sizeof timebuf);
    if (serverTime && timebuf[0]) *serverTime = atoll(timebuf);

    long code = atol(codebuf);
    free(pt); free(frame); free(b.p);
    curl_slist_free_all(h); curl_easy_cleanup(c);
    return code;
}

int main(void)
{
    wy2_from_hex(SRV_X, srvX, 32);
    wy2_from_hex(SRV_ED, srvEd, 32);
    wy2_from_hex(LIC_PUB, licPub, 32);
    wy2_from_hex(LIC_CLI, licCli, 32);

    const char *card = getenv("WY_CARD");
    if (!card) card = "TEST-CARD-0000";
    srand((unsigned)time(NULL));

    char plain[1024];
    long long st = 0;
    long code = exec_login(card, 0, &st, plain, sizeof plain);
    printf("[第 1 次] code=%ld\n  明文: %s\n", code, plain);

    if (code == 105) {
        long long local = now_ts();
        long long off = st > 0 ? (st - local) : 60;
        printf("\n检测到 105 系统时间出错 → 用服务器时间校正：本地 %lld, 服务器 %lld, 偏移 %+lld 秒\n",
               local, st, off);
        code = exec_login(card, off, &st, plain, sizeof plain);
        printf("[第 2 次] code=%ld\n  明文: %s\n", code, plain);
    }

    printf("\n=== 结论 ===\n");
    if (code == 2416) printf("登录成功（该卡密有效）\n");
    else if (code == 149) printf("协议完全正常：服务器判定『卡密不存在』（这是测试卡的预期结果）\n");
    else if (code == 150) printf("协议完全正常：『卡密已过期』\n");
    else printf("返回码 %ld，需进一步核对\n", code);
    return 0;
}

