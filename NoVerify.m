// ============================================================
//  NoVerify.m —— Stocks.KS 卡密验证绕过（运行时接管版）
//
//  思路：不去理解 OLLVM 混淆后的判定逻辑，直接接管 UI 状态
//    1. showProgressOverlayWithServer:value:  → 不联网，直接隐藏进度
//    2. hideProgressOverlay                    → 原样保留
//    3. updateMenuButtonStates                 → 原实现后强制全部控件可用
//    4. forceExitButtonClicked:                → 空实现（取消强制退出）
//    5. viewDidLoad / viewDidAppear            → 延时再强制一轮，压过验证回写
//    6. isHUDEnabled                           → 恒 YES
//
//  目标：com.apple.Stocks（三角洲 KS 内部三服）
// ============================================================
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#pragma mark - 工具

static void NYSwizzle(Class cls, SEL sel, IMP newImp, IMP *outOrig) {
    if (!cls) return;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    if (outOrig) *outOrig = method_getImplementation(m);
    method_setImplementation(m, newImp);
}

// 遍历视图树，强制所有控件可见、可用
static void NYForceEnable(UIView *v, int depth) {
    if (!v || depth > 12) return;
    if ([v isKindOfClass:[UIControl class]]) {
        UIControl *c = (UIControl *)v;
        c.enabled = YES;
        c.userInteractionEnabled = YES;
        c.alpha = MAX(c.alpha, 0.85f);
    }
    v.userInteractionEnabled = YES;
    // 只解开被验证隐藏的层，不强行显示系统遮罩
    if (v.hidden) {
        NSString *cls = NSStringFromClass([v class]);
        if ([cls containsString:@"Progress"] || [cls containsString:@"Overlay"] ||
            [cls containsString:@"Exit"] || [cls containsString:@"Alert"]) {
            v.hidden = YES;   // 进度/退出层保持隐藏
        }
    }
    for (UIView *sub in v.subviews) {
        NYForceEnable(sub, depth + 1);
    }
}

#pragma mark - 被替换的方法

// ---- showProgressOverlayWithServer:value: ----
static void (*orig_showProgress)(id, SEL, id, id);
static void ny_showProgress(id self, SEL _cmd, id server, id value) {
    NSLog(@"[NoVerify] 拦截验证请求 server=%@ value=%@", server, value);
    // 不联网、不校验，直接收尾
    SEL hideSel = @selector(hideProgressOverlay);
    if ([self respondsToSelector:hideSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        [self performSelector:hideSel];
        [self performSelector:@selector(updateMenuButtonStates)];
#pragma clang diagnostic pop
    }
    // 再把 UI 放开一次（覆盖验证逻辑可能写入的禁用状态）
    if ([self isKindOfClass:[UIViewController class]]) {
        NYForceEnable(((UIViewController *)self).view, 0);
    }
}

// ---- updateMenuButtonStates ----
static void (*orig_updateMenu)(id, SEL);
static void ny_updateMenu(id self, SEL _cmd) {
    if (orig_updateMenu) orig_updateMenu(self, _cmd);
    if ([self isKindOfClass:[UIViewController class]]) {
        NYForceEnable(((UIViewController *)self).view, 0);
    }
}

// ---- forceExitButtonClicked: ----
static void ny_forceExit(id self, SEL _cmd, id sender) {
    NSLog(@"[NoVerify] 已拦截强制退出");
}

// ---- isHUDEnabled ----
static BOOL ny_isHUDEnabled(id self, SEL _cmd) {
    return YES;
}

// ---- viewDidAppear: ----
static void (*orig_viewDidAppear)(id, SEL, BOOL);
static void ny_viewDidAppear(id self, SEL _cmd, BOOL animated) {
    if (orig_viewDidAppear) orig_viewDidAppear(self, _cmd, animated);
    // 验证往往是异步的，延时多轮覆盖
    for (int i = 1; i <= 5; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 1.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            if ([self isKindOfClass:[UIViewController class]]) {
                NYForceEnable(((UIViewController *)self).view, 0);
            }
        });
    }
}

#pragma mark - 安装

static void NYInstall(void) {
    Class rvc = NSClassFromString(@"RootViewController");
    if (!rvc) {
        NSLog(@"[NoVerify] 未找到 RootViewController");
        return;
    }
    NSLog(@"[NoVerify] 已找到 RootViewController，开始接管");

    NYSwizzle(rvc, @selector(showProgressOverlayWithServer:value:),
              (IMP)ny_showProgress, (IMP *)&orig_showProgress);
    NYSwizzle(rvc, @selector(forceExitButtonClicked:),
              (IMP)ny_forceExit, NULL);
    NYSwizzle(rvc, @selector(isHUDEnabled),
              (IMP)ny_isHUDEnabled, NULL);
    NYSwizzle(rvc, @selector(updateMenuButtonStates),
              (IMP)ny_updateMenu, (IMP *)&orig_updateMenu);
    NYSwizzle(rvc, @selector(viewDidAppear:),
              (IMP)ny_viewDidAppear, (IMP *)&orig_viewDidAppear);

    NSLog(@"[NoVerify] 接管完成");
}

__attribute__((constructor))
static void ny_entry(void) {
    // 主程序刚起来时 objc 还没完全就绪，延后一拍
    dispatch_async(dispatch_get_main_queue(), ^{
        NYInstall();
        // 兜底：有些版本会延迟加载
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            static BOOL done = NO;
            if (!done) { done = YES; NYInstall(); }
        });
    });
}