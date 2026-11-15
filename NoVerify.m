// ============================================================
//  NoVerify.m v2 —— Stocks.KS 卡密验证绕过
//
//  v1 的 bug：viewDidAppear: 不在 RootViewController 自身方法表里，
//             class_getInstanceMethod 会取到 UIViewController 的实现，
//             method_setImplementation 等于改全局 → 必崩。
//  v2 修正：
//    · NYSwizzleOwn 只替换"类自身"实现的方法，继承来的直接跳过
//    · viewDidAppear: → viewWillAppear:（RootViewController 自身有实现）
//    · 增加持续定时器（30 秒内每秒强制一次），压过异步回写
//    · 增加 toggleMenuButtonClicked: 直接放行
// ============================================================
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

#pragma mark - 只改自身实现的方法

static void NYSwizzleOwn(Class cls, SEL sel, IMP newImp, IMP *outOrig) {
    if (!cls || !sel) return;
    unsigned int count = 0;
    Method *list = class_copyMethodList(cls, &count);
    Method target = NULL;
    for (unsigned int i = 0; i < count; i++) {
        if (method_getName(list[i]) == sel) { target = list[i]; break; }
    }
    if (list) free(list);
    if (!target) {
        NSLog(@"[NoVerify] 跳过 %@（非自身实现）", NSStringFromSelector(sel));
        return;
    }
    if (outOrig) *outOrig = method_getImplementation(target);
    method_setImplementation(target, newImp);
    NSLog(@"[NoVerify] 已接管 %@", NSStringFromSelector(sel));
}

#pragma mark - 强制放开 UI

static BOOL NYIsBlockingLayer(UIView *v) {
    NSString *cls = NSStringFromClass([v class]);
    return [cls containsString:@"Progress"] || [cls containsString:@"Overlay"] ||
           [cls containsString:@"Exit"] || [cls containsString:@"Alert"] ||
           [cls containsString:@"Toast"];
}

static void NYForceEnable(UIView *v, int depth) {
    if (!v || depth > 14) return;
    if (NYIsBlockingLayer(v)) {
        v.hidden = YES;           // 遮罩类保持隐藏
        return;
    }
    v.userInteractionEnabled = YES;
    if ([v isKindOfClass:[UIControl class]]) {
        UIControl *c = (UIControl *)v;
        c.enabled = YES;
        if (c.alpha < 0.85f) c.alpha = 1.0f;
    }
    for (UIView *sub in v.subviews) {
        NYForceEnable(sub, depth + 1);
    }
}

static void NYSweep(id self) {
    if (![self isKindOfClass:[UIViewController class]]) return;
    UIViewController *vc = (UIViewController *)self;
    if (!vc.isViewLoaded) return;
    NYForceEnable(vc.view, 0);
}

#pragma mark - 被替换的方法

// showProgressOverlayWithServer:value: —— 核心：不联网、不验签
static void (*orig_showProgress)(id, SEL, id, id);
static void ny_showProgress(id self, SEL _cmd, id server, id value) {
    NSLog(@"[NoVerify] 拦截验证请求 server=%@ value=%@", server, value);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    if ([self respondsToSelector:@selector(hideProgressOverlay)]) {
        [self performSelector:@selector(hideProgressOverlay)];
    }
    if ([self respondsToSelector:@selector(updateMenuButtonStates)]) {
        [self performSelector:@selector(updateMenuButtonStates)];
    }
#pragma clang diagnostic pop
    NYSweep(self);
    // 延时再扫，覆盖后续异步写入
    for (int i = 1; i <= 3; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(i * 0.4 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ NYSweep(self); });
    }
}

// updateMenuButtonStates
static void (*orig_updateMenu)(id, SEL);
static void ny_updateMenu(id self, SEL _cmd) {
    if (orig_updateMenu) orig_updateMenu(self, _cmd);
    NYSweep(self);
}

// forceExitButtonClicked:
static void ny_forceExit(id self, SEL _cmd, id sender) {
    NSLog(@"[NoVerify] 已拦截强制退出");
}

// isHUDEnabled
static BOOL ny_isHUDEnabled(id self, SEL _cmd) {
    return YES;
}

// toggleMenuButtonClicked: —— 点击菜单入口，确保 HUD 处于开启状态
static void (*orig_toggleMenu)(id, SEL, id);
static void ny_toggleMenu(id self, SEL _cmd, id sender) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    if ([self respondsToSelector:@selector(setHUDEnabled:)]) {
        [self performSelector:@selector(setHUDEnabled:) withObject:nil];
    }
#pragma clang diagnostic pop
    if (orig_toggleMenu) orig_toggleMenu(self, _cmd, sender);
    NYSweep(self);
}

// viewWillAppear:（自身有实现）
static void (*orig_viewWillAppear)(id, SEL, BOOL);
static void ny_viewWillAppear(id self, SEL _cmd, BOOL animated) {
    if (orig_viewWillAppear) orig_viewWillAppear(self, _cmd, animated);
    NYSweep(self);
}

// viewWillLayoutSubviews（自身有实现）—— 布局后可能重建控件
static void (*orig_viewWillLayout)(id, SEL);
static void ny_viewWillLayout(id self, SEL _cmd) {
    if (orig_viewWillLayout) orig_viewWillLayout(self, _cmd);
    NYSweep(self);
}

#pragma mark - 安装

static BOOL gInstalled = NO;

static void NYInstall(void) {
    if (gInstalled) return;
    Class rvc = NSClassFromString(@"RootViewController");
    if (!rvc) { NSLog(@"[NoVerify] 未找到 RootViewController"); return; }
    gInstalled = YES;
    NSLog(@"[NoVerify] 找到 RootViewController，开始接管");

    NYSwizzleOwn(rvc, @selector(showProgressOverlayWithServer:value:),
                 (IMP)ny_showProgress, (IMP *)&orig_showProgress);
    NYSwizzleOwn(rvc, @selector(forceExitButtonClicked:), (IMP)ny_forceExit, NULL);
    NYSwizzleOwn(rvc, @selector(isHUDEnabled), (IMP)ny_isHUDEnabled, NULL);
    NYSwizzleOwn(rvc, @selector(updateMenuButtonStates),
                 (IMP)ny_updateMenu, (IMP *)&orig_updateMenu);
    NYSwizzleOwn(rvc, @selector(toggleMenuButtonClicked:),
                 (IMP)ny_toggleMenu, (IMP *)&orig_toggleMenu);
    NYSwizzleOwn(rvc, @selector(viewWillAppear:),
                 (IMP)ny_viewWillAppear, (IMP *)&orig_viewWillAppear);
    NYSwizzleOwn(rvc, @selector(viewWillLayoutSubviews),
                 (IMP)ny_viewWillLayout, (IMP *)&orig_viewWillLayout);

    // 持续兜底：30 秒内每秒扫一次现有 RootViewController 实例
    static dispatch_source_t timer = NULL;
    if (!timer) {
        timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                       dispatch_get_main_queue());
        dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 0),
                                  1ull * NSEC_PER_SEC, (uint64_t)(0.2 * NSEC_PER_SEC));
        dispatch_source_set_event_handler(timer, ^{
            static int tick = 0;
            if (++tick > 30) { dispatch_source_cancel(timer); return; }
            Class c = NSClassFromString(@"RootViewController");
            if (!c) return;
            // 遍历所有 window 找 RootViewController 实例
            for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
                if (![scene isKindOfClass:[UIWindowScene class]]) continue;
                for (UIWindow *w in ((UIWindowScene *)scene).windows) {
                    UIViewController *vc = w.rootViewController;
                    if ([vc isKindOfClass:c]) NYSweep(vc);
                    else if ([vc isKindOfClass:[UINavigationController class]])
                        NYSweep(((UINavigationController *)vc).topViewController);
                    else if ([vc isKindOfClass:[UITabBarController class]])
                        NYSweep(((UITabBarController *)vc).selectedViewController);
                }
            }
        });
        dispatch_resume(timer);
    }
}

__attribute__((constructor))
static void ny_entry(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NYInstall();
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ NYInstall(); });
    });
}
