/* wyguard.c —— 运行时防护实现 */
#include "wyguard.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(__APPLE__)

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#if __has_include(<sys/ptrace.h>)
#include <sys/ptrace.h>
#endif

#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

extern int ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);

/* -------- 1. 反调试 -------- */

static int dbg_traced(void)
{
    /* P_TRACED 标志位 */
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info;
    size_t sz = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &sz, NULL, 0) == 0) {
        if (info.kp_proc.p_flag & P_TRACED) return 1;
    }
    return 0;
}

static void dbg_deny_attach(void)
{
    /* 失败与否都要调，重复调用无害 */
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
}

/* -------- 2. 依赖链校验 -------- */

/* 在主程序（index 0）的 load command 里查找指向 sign 的 LC_LOAD_DYLIB
 * 返回 1 = 存在且为硬链接；0 = 缺失或被改成弱链接 */
static int has_hard_link(const char *sign)
{
    const struct mach_header_64 *mh = NULL;
    uint32_t nimg = _dyld_image_count();
    for (uint32_t i = 0; i < nimg; i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h) continue;
        if (h->filetype == MH_EXECUTE) {
            mh = (const struct mach_header_64 *)h;
            break;
        }
    }
    if (!mh) return 0;

    const uint8_t *p = (const uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_LOAD_DYLIB) {
            const struct dylib_command *dc = (const struct dylib_command *)lc;
            const char *name = (const char *)lc + dc->dylib.name.offset;
            if (name && strstr(name, sign)) return 1;   /* 硬链接命中 */
        } else if (lc->cmd == LC_LOAD_WEAK_DYLIB) {
            const struct dylib_command *dc = (const struct dylib_command *)lc;
            const char *name = (const char *)lc + dc->dylib.name.offset;
            if (name && strstr(name, sign)) return 0;   /* 被改成弱链接 */
        }
        if (lc->cmdsize == 0) break;
        p += lc->cmdsize;
    }
    return 0;
}

/* -------- 3. 自身镜像校验 -------- */

static int self_loaded(void)
{
    /* CardGate 必须作为一个已加载镜像存在 */
    uint32_t nimg = _dyld_image_count();
    for (uint32_t i = 0; i < nimg; i++) {
        const char *n = _dyld_get_image_name(i);
        if (!n) continue;
        if (strstr(n, "CardGate.dylib")) return 1;
    }
    return 0;
}

/* -------- 对外接口 -------- */

int wyguard_check_fast(void)
{
    /* 依赖链 + 自身镜像，都是 O(ncmds) 级，开销极低 */
    if (!self_loaded()) return 0;
    if (!has_hard_link("CardGate.dylib")) return 0;
    return 1;
}

int wyguard_check(void)
{
    dbg_deny_attach();
    if (dbg_traced()) return 0;
    return wyguard_check_fast();
}

/* -------- 字符串解密（分片 XOR，key 参与位置运算） -------- */

void wyguard_unseal(const unsigned char *in, unsigned char *out, int len, unsigned char key)
{
    for (int i = 0; i < len; i++) {
        out[i] = (unsigned char)(in[i] ^ (unsigned char)(key + i * 7 + (i >> 1)));
    }
    out[len] = 0;
}

#else   /* 非 Apple 平台：给自测用，恒通过 */

int wyguard_check_fast(void) { return 1; }
int wyguard_check(void) { return 1; }
void wyguard_unseal(const unsigned char *in, unsigned char *out, int len, unsigned char key)
{
    for (int i = 0; i < len; i++)
        out[i] = (unsigned char)(in[i] ^ (unsigned char)(key + i * 7 + (i >> 1)));
    out[len] = 0;
}

#endif