/* wyguard.h —— 运行时防护：反调试 / 依赖链校验 / 本体完整性 */
#ifndef WYGUARD_H
#define WYGUARD_H

/* 综合自检：任一项失败返回 0
 * 检查内容：
 *   1. 是否被调试器附加（ptrace / P_TRACED）
 *   2. 主程序 Mach-O 里是否仍有指向 CardGate 的【硬链接】LC_LOAD_DYLIB
 *   3. CardGate 自身镜像是否被正确加载
 */
int wyguard_check(void);

/* 轻量周期检查（心跳里调，只查依赖链，开销小） */
int wyguard_check_fast(void);

/* 字符串解密（分片 XOR） */
void wyguard_unseal(const unsigned char *in, unsigned char *out, int len, unsigned char key);

#endif