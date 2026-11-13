// ============================================================
//  CardGate.m —— 卡密门禁 dylib（微验 动态密钥 v2）
//  安全通道：X25519 协商 → HKDF-SHA256 → ChaCha20-Poly1305 → Ed25519 验签
//  编译：clang -target arm64-apple-ios14.0（GitHub Actions 已配好）
// ============================================================
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <QuartzCore/QuartzCore.h>
#include "crypto/wy2.h"

#pragma mark - ========== 配置 ==========

static const char *WY_HOST     = "wy.llua.cn";
static const char *WY_APITOKRN = "992664d2b407c0f899284d7d5c0df89a";
static const char *WY_APPKEY   = "S0ZyYe9JJypNRRSY";
static const char *WY_LOGIN_ID = "8EE5C3CDF";

// 通道公钥 / 绑定密钥对（来自微验后台）
static const char *WY_SRV_X25519 = "2fc060d1a94db93817765b2f8d79e083dd24963aa1266428c9e619ace7426103";
static const char *WY_SRV_ED25519 = "97a8a1c13919f437fade2c27d2b0ccdefa74ed1532ff82029eb4e7aa754a9f01";
static const char *WY_LIC_PUB = "b88f2bb3257985e0f192324dcb9dbf05f39ec065b2ccdc0dcecf8d0f13f1272e";
static const char *WY_LIC_CLI = "9dd3d639dd59172726c6a44f936d411956de680b5a6e6ce0ef9fdf3b5337f5cb";

// 响应字段名（后台混淆）
static NSString *const F_CODE = @"f891012afe301f1ed6b0d65d77ed68c62";
static NSString *const F_MSG  = @"hd975c61e883e0fa83443c2e39bb959ec";
static NSString *const F_TIME = @"bf921c5bf4325e0cea243fb1e89424921";
static NSString *const F_VIP  = @"ff097bcdf608ccbf49dbdb114df1e2534";
static NSString *const W_KEY  = @"wbc0a389f8e8127f628d2d25a68ccad4c";
static NSString *const W_VAL  = @"05b7c29c6dac5855d41167f0ff4a14b3";

static NSString *const CODE_OK      = @"2416";   // 登录成功码
static NSString *const CODE_BADTIME = @"105";    // 系统时间出错

static NSString *const K_CARD   = @"wy2_card";
static NSString *const K_EXPIRE = @"wy2_expire";
static const  int      REVALIDATE_SEC = 1800;

static uint8_t gSrvX[32], gSrvEd[32], gLicPub[32], gLicCli[32];
static long long gTimeOffset = 0;   // 与服务器的时间差（秒）

#pragma mark - ========== 工具 ==========

static NSString *WYMD5(NSString *s) {
    const char *c = s.UTF8String;
    unsigned char d[CC_MD5_DIGEST_LENGTH];
    CC_MD5(c, (CC_LONG)strlen(c), d);
    NSMutableString *o = [NSMutableString stringWithCapacity:32];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [o appendFormat:@"%02x", d[i]];
    return o;
}

static NSString *WYMarkCode(void) {
    NSString *v = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
    if (!v.length) v = @"unknown-device";
    return [v stringByReplacingOccurrencesOfString:@"-" withString:@""];
}

static NSString *WYStr(NSDictionary *j, NSString *k) {
    if (![j isKindOfClass:NSDictionary.class]) return @"";
    id v = j[k];
    if (!v || v == NSNull.null) return @"";
    return [v description];
}

static void WYInitKeys(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        wy2_from_hex(WY_SRV_X25519, gSrvX, 32);
        wy2_from_hex(WY_SRV_ED25519, gSrvEd, 32);
        wy2_from_hex(WY_LIC_PUB, gLicPub, 32);
        wy2_from_hex(WY_LIC_CLI, gLicCli, 32);
    });
}

#pragma mark - ========== 单次登录（v2 安全通道）==========

typedef void (^WYDone)(BOOL ok, NSInteger code, NSString *msg, double expire, long long serverTime);

static void WYLoginOnce(NSString *card, long long timeOffset, WYDone done) {
    WYInitKeys();

    long long T = (long long)[[NSDate date] timeIntervalSince1970] + timeOffset;
    unsigned value = (unsigned)(100000 + arc4random_uniform(900000));
    NSString *valueStr = [NSString stringWithFormat:@"%lld%u", T, value];
    NSString *mark = WYMarkCode();

    NSString *signSrc = [NSString stringWithFormat:@"kami=%@&markcode=%@&t=%lld&%s",
                         card, mark, T, WY_APPKEY];
    NSString *sign = WYMD5(signSrc);
    NSString *plain = [NSString stringWithFormat:
                       @"id=%s&kami=%@&markcode=%@&t=%lld&sign=%@&value=%@",
                       WY_LOGIN_ID, card, mark, T, sign, valueStr];

    char *frame = NULL;
    // block 不能捕获数组，用 NSMutableData 持有内存，并由 block 强引用保证生命周期
    NSMutableData *keyData = [NSMutableData dataWithLength:32];
    uint8_t *respKey = (uint8_t *)keyData.mutableBytes;
    memset(respKey, 0, 32);
    if (wy2_seal(gSrvX, gLicPub, gLicCli, WY_APPKEY, plain.UTF8String, card.UTF8String,
                 &frame, respKey) != 0) {
        done(NO, -1, @"安全通道初始化失败", 0, 0);
        return;
    }
    NSString *body = [NSString stringWithUTF8String:frame];
    free(frame);

    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"https://%s/v2/%s",
                                       WY_HOST, WY_APITOKRN]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 20;
    [req setValue:@"text/plain" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];

    [[[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (e || !d.length) { done(NO, -1, @"网络错误", 0, 0); return; }
        uint8_t *rk = (uint8_t *)keyData.mutableBytes;   // 引用 keyData，保证 block 期间内存存活
        NSString *raw = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (!raw) { done(NO, -1, @"响应编码异常", 0, 0); return; }

        // 取信封字段
        NSDictionary *envelope = [NSJSONSerialization
                                  JSONObjectWithData:d options:0 error:nil];
        NSString *dataHex = WYStr(envelope, @"data");
        NSString *sigHex  = WYStr(envelope, @"sig");
        if (!dataHex.length || !sigHex.length) {
            // 未走安全信封（通常是配置/密钥不匹配）
            NSString *msg = WYStr(envelope, F_MSG);
            done(NO, [WYStr(envelope, F_CODE) integerValue], msg.length ? msg : @"通道未加密", 0, 0);
            return;
        }

        char *pt = NULL;
        int rc = wy2_open(gSrvEd, rk, dataHex.UTF8String, sigHex.UTF8String, &pt);
        if (rc != 0) {
            done(NO, -2, rc == -2 ? @"响应验签失败" : @"响应解密失败", 0, 0);
            return;
        }
        NSString *plainResp = [NSString stringWithUTF8String:pt];
        free(pt);

        NSData *jd = [plainResp dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *j = [NSJSONSerialization JSONObjectWithData:jd options:0 error:nil];
        if (![j isKindOfClass:NSDictionary.class]) { done(NO, -3, @"业务响应解析失败", 0, 0); return; }

        NSInteger code = [WYStr(j, F_CODE) integerValue];
        NSString *msg  = WYStr(j, F_MSG);

        // msg 里可能嵌一层 JSON（含 vip / 校验位）
        NSDictionary *inner = nil;
        if ([msg hasPrefix:@"{"]) {
            inner = [NSJSONSerialization JSONObjectWithData:
                     [msg dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
        }

        double expire = 0;
        if ([inner isKindOfClass:NSDictionary.class]) {
            NSString *vip = WYStr(inner, F_VIP);
            if (vip.length) expire = [vip doubleValue];
            if (W_VAL.length) {
                NSString *got = WYStr(inner, W_KEY);
                if (![got isEqualToString:W_VAL]) { done(NO, -4, @"响应校验失败", 0, 0); return; }
            }
        }
        if (!expire) {
            NSString *vip = WYStr(j, F_VIP);
            if (vip.length) expire = [vip doubleValue];
        }
        if (!expire) {
            NSString *tm = WYStr(j, F_TIME);
            double v = [tm doubleValue];
            if (v > 1e12) v /= 1000.0;
            if (v > 0 && [WYStr(j, F_CODE) isEqualToString:CODE_OK]) {
                expire = [[NSDate date] timeIntervalSince1970] + 3600;
            }
        }
        long long srvTime = [WYStr(j, F_TIME) longLongValue];
        done(YES, code, msg, expire, srvTime);
    }] resume];
}

#pragma mark - ========== 门禁 UI ==========

static UIImage *CGateLoadMascot(void);   // 前置声明

@interface CGate : NSObject
+ (instancetype)shared;
- (void)start;
- (void)show;
- (void)hide;
@end

#pragma mark - ========== 背景特效视图 ==========

@interface CGAuroraView : UIView
@end

@implementation CGAuroraView {
    CAGradientLayer *_base;
    NSMutableArray<CAGradientLayer *> *_blobs;
    CAEmitterLayer *_emitter;
}

- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        self.userInteractionEnabled = NO;
        self.backgroundColor = [UIColor blackColor];

        _base = [CAGradientLayer layer];
        _base.colors = @[
            (id)[UIColor colorWithRed:0.04 green:0.06 blue:0.14 alpha:1].CGColor,
            (id)[UIColor colorWithRed:0.08 green:0.05 blue:0.22 alpha:1].CGColor,
            (id)[UIColor colorWithRed:0.02 green:0.14 blue:0.20 alpha:1].CGColor,
            (id)[UIColor colorWithRed:0.06 green:0.03 blue:0.10 alpha:1].CGColor
        ];
        _base.startPoint = CGPointMake(0.0, 0.0);
        _base.endPoint = CGPointMake(1.0, 1.0);
        [self.layer addSublayer:_base];

        // 流动光斑：径向渐变 + 路径动画，形成"液态"流动感
        _blobs = [NSMutableArray array];
        NSArray *tints = @[
            [UIColor colorWithRed:0.20 green:0.55 blue:1.00 alpha:0.55],
            [UIColor colorWithRed:0.45 green:0.30 blue:1.00 alpha:0.50],
            [UIColor colorWithRed:0.00 green:0.80 blue:0.85 alpha:0.42],
            [UIColor colorWithRed:0.95 green:0.35 blue:0.75 alpha:0.38]
        ];
        for (int i = 0; i < tints.count; i++) {
            CAGradientLayer *b = [CAGradientLayer layer];
            b.type = kCAGradientLayerRadial;
            UIColor *c = tints[i];
            b.colors = @[
                (id)[c colorWithAlphaComponent:0.85].CGColor,
                (id)[c colorWithAlphaComponent:0.0].CGColor
            ];
            b.locations = @[@0.0, @1.0];
            [self.layer addSublayer:b];
            [_blobs addObject:b];
        }

        // 漂浮粒子
        _emitter = [CAEmitterLayer layer];
        _emitter.emitterShape = kCAEmitterLayerRectangle;
        _emitter.emitterMode = kCAEmitterLayerVolume;
        _emitter.renderMode = kCAEmitterLayerAdditive;

        CAEmitterCell *cell = [CAEmitterCell emitterCell];
        cell.contents = (id)[CGAuroraView dotImage].CGImage;
        cell.birthRate = 14;
        cell.lifetime = 9;
        cell.lifetimeRange = 3;
        cell.velocity = 16;
        cell.velocityRange = 12;
        cell.emissionRange = M_PI * 2;
        cell.scale = 0.35;
        cell.scaleRange = 0.25;
        cell.alphaSpeed = -0.10;
        cell.color = [UIColor colorWithRed:0.65 green:0.85 blue:1.0 alpha:0.55].CGColor;
        _emitter.emitterCells = @[cell];
        [self.layer addSublayer:_emitter];
    }
    return self;
}

+ (UIImage *)dotImage {
    static UIImage *img;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        CGFloat s = 12;
        UIGraphicsBeginImageContextWithOptions(CGSizeMake(s, s), NO, 0);
        CGContextRef ctx = UIGraphicsGetCurrentContext();
        CGContextSetFillColorWithColor(ctx, [UIColor whiteColor].CGColor);
        CGContextFillEllipseInRect(ctx, CGRectMake(0, 0, s, s));
        img = UIGraphicsGetImageFromCurrentImageContext();
        UIGraphicsEndImageContext();
    });
    return img;
}

- (void)layoutSubviews {
    [super layoutSubviews];
    [CATransaction begin];
    [CATransaction setDisableActions:YES];

    _base.frame = self.bounds;

    CGFloat w = self.bounds.size.width, h = self.bounds.size.height;
    CGFloat base = MAX(w, h);
    for (int i = 0; i < _blobs.count; i++) {
        CAGradientLayer *b = _blobs[i];
        CGFloat r = base * (0.42 + 0.12 * i);
        b.bounds = CGRectMake(0, 0, r, r);
        b.cornerRadius = r * 0.5;
    }
    _emitter.emitterPosition = CGPointMake(w * 0.5, h * 0.95);
    _emitter.emitterSize = CGSizeMake(w, h * 0.2);

    [CATransaction commit];

    [self restartBlobAnimations];
}

- (void)restartBlobAnimations {
    CGFloat w = self.bounds.size.width, h = self.bounds.size.height;
    for (int i = 0; i < _blobs.count; i++) {
        CAGradientLayer *b = _blobs[i];
        [b removeAllAnimations];

        CGPoint pts[4] = {
            CGPointMake(w * (0.22 + 0.18 * i), h * (0.30 + 0.10 * i)),
            CGPointMake(w * (0.78 - 0.12 * i), h * (0.40 + 0.16 * i)),
            CGPointMake(w * (0.62 - 0.20 * i), h * (0.80 - 0.08 * i)),
            CGPointMake(w * (0.18 + 0.22 * i), h * (0.62 + 0.20 * i))
        };
        CGMutablePathRef path = CGPathCreateMutable();
        CGPathMoveToPoint(path, NULL, pts[0].x, pts[0].y);
        for (int k = 1; k < 4; k++) CGPathAddLineToPoint(path, NULL, pts[k].x, pts[k].y);
        CGPathCloseSubpath(path);

        CAKeyframeAnimation *move = [CAKeyframeAnimation animationWithKeyPath:@"position"];
        move.path = path;
        move.duration = 16.0 + 5.0 * i;
        move.repeatCount = HUGE_VALF;
        move.calculationMode = kCAAnimationPaced;
        move.timingFunction = [CAMediaTimingFunction functionWithName:kCAMediaTimingFunctionEaseInEaseOut];
        [b addAnimation:move forKey:@"flow"];

        CABasicAnimation *pulse = [CABasicAnimation animationWithKeyPath:@"transform.scale"];
        pulse.fromValue = @0.92;
        pulse.toValue = @1.14;
        pulse.duration = 6.0 + i;
        pulse.autoreverses = YES;
        pulse.repeatCount = HUGE_VALF;
        [b addAnimation:pulse forKey:@"pulse"];

        CGPathRelease(path);
    }
}

@end

#pragma mark - ========== 登录界面（横竖屏自适应）==========

@interface CGGateVC : UIViewController
@property (nonatomic, copy) void (^onSubmit)(NSString *card);
@property (nonatomic, strong) UITextField *field;
@property (nonatomic, strong) UILabel *msg;
@property (nonatomic, strong) UIButton *btn;
@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UIImageView *mascot;
@property (nonatomic, strong) UIVisualEffectView *panel;
@end

@implementation CGGateVC

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];

    CGAuroraView *bg = [[CGAuroraView alloc] initWithFrame:self.view.bounds];
    bg.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.view addSubview:bg];

    // 液态玻璃面板
    UIVisualEffectView *panel = [[UIVisualEffectView alloc]
        initWithEffect:[UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemUltraThinMaterialDark]];
    panel.layer.cornerRadius = 26;
    panel.layer.masksToBounds = YES;
    panel.layer.borderWidth = 1.0;
    panel.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.18].CGColor;
    [self.view addSubview:panel];
    self.panel = panel;

    UIView *content = panel.contentView;

    self.titleLabel = [UILabel new];
    self.titleLabel.text = @"卡密登录";
    self.titleLabel.textColor = [UIColor whiteColor];
    self.titleLabel.font = [UIFont systemFontOfSize:28 weight:UIFontWeightSemibold];
    self.titleLabel.textAlignment = NSTextAlignmentCenter;
    self.titleLabel.layer.shadowColor = [UIColor colorWithRed:0.4 green:0.8 blue:1 alpha:1].CGColor;
    self.titleLabel.layer.shadowOpacity = 0.6;
    self.titleLabel.layer.shadowRadius = 10;
    self.titleLabel.layer.shadowOffset = CGSizeZero;
    [content addSubview:self.titleLabel];

    self.mascot = [UIImageView new];
    self.mascot.contentMode = UIViewContentModeScaleAspectFit;
    self.mascot.image = CGateLoadMascot();
    self.mascot.hidden = (self.mascot.image == nil);
    [self.view addSubview:self.mascot];

    self.field = [UITextField new];
    self.field.placeholder = @"请输入卡密";
    self.field.backgroundColor = [UIColor colorWithWhite:1 alpha:0.10];
    self.field.textColor = [UIColor whiteColor];
    self.field.layer.cornerRadius = 14;
    self.field.layer.borderWidth = 1;
    self.field.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.20].CGColor;
    self.field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    self.field.autocorrectionType = UITextAutocorrectionTypeNo;
    self.field.returnKeyType = UIReturnKeyGo;
    self.field.keyboardType = UIKeyboardTypeASCIICapable;
    [self.field setAttributedPlaceholder:
        [[NSAttributedString alloc] initWithString:@"请输入卡密"
                                        attributes:@{NSForegroundColorAttributeName:
                                                     [UIColor colorWithWhite:1 alpha:0.45]}]];
    [self.field addTarget:self action:@selector(submit) forControlEvents:UIControlEventEditingDidEndOnExit];
    [content addSubview:self.field];

    self.btn = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.btn setTitle:@"登 录" forState:UIControlStateNormal];
    [self.btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.btn.titleLabel.font = [UIFont systemFontOfSize:19 weight:UIFontWeightSemibold];
    self.btn.backgroundColor = [UIColor colorWithWhite:1 alpha:0.16];
    self.btn.layer.cornerRadius = 14;
    self.btn.layer.borderWidth = 1;
    self.btn.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.26].CGColor;
    [self.btn addTarget:self action:@selector(submit) forControlEvents:UIControlEventTouchUpInside];
    [content addSubview:self.btn];

    self.msg = [UILabel new];
    self.msg.textColor = [UIColor colorWithRed:1 green:0.55 blue:0.55 alpha:1];
    self.msg.font = [UIFont systemFontOfSize:14];
    self.msg.textAlignment = NSTextAlignmentCenter;
    self.msg.numberOfLines = 2;
    [content addSubview:self.msg];

    [self startMascotBobbing];
}

- (void)startMascotBobbing {
    if (self.mascot.hidden) return;
    self.mascot.transform = CGAffineTransformIdentity;
    [UIView animateWithDuration:1.8 delay:0
                        options:UIViewAnimationOptionAutoreverse | UIViewAnimationOptionRepeat |
                                UIViewAnimationOptionCurveEaseInOut
                     animations:^{
        self.mascot.transform = CGAffineTransformMakeTranslation(0, -14);
    } completion:nil];
}

- (void)submit {
    if (self.onSubmit) self.onSubmit(self.field.text ?: @"");
}

// 横竖屏共用的布局：全部按当前 bounds 实时计算
- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];

    CGRect b = self.view.bounds;
    CGFloat w = b.size.width, h = b.size.height;
    BOOL landscape = w > h;
    CGFloat safeTop = 0, safeBottom = 0;
    if (@available(iOS 11.0, *)) {
        safeTop = self.view.safeAreaInsets.top;
        safeBottom = self.view.safeAreaInsets.bottom;
    }

    CGFloat panelW = landscape ? MIN(w * 0.62, 560) : MIN(w - 48, 460);
    CGFloat rowH = landscape ? 44 : 50;
    CGFloat gap = landscape ? 14 : 18;
    CGFloat titleH = landscape ? 40 : 46;
    CGFloat msgH = 40;
    CGFloat panelH = titleH + gap + rowH + gap + rowH + gap + msgH + (landscape ? 40 : 56);

    CGFloat panelX = (w - panelW) * 0.5;
    CGFloat panelY = (h - panelH) * 0.5 + (landscape ? 0 : MIN(40, h * 0.04));
    self.panel.frame = CGRectMake(panelX, panelY, panelW, panelH);

    CGFloat padX = 24;
    CGFloat innerW = panelW - padX * 2;
    CGFloat y = landscape ? 22 : 30;

    self.titleLabel.frame = CGRectMake(padX, y, innerW, titleH);
    y += titleH + gap;

    self.field.frame = CGRectMake(padX, y, innerW, rowH);
    y += rowH + gap;

    self.btn.frame = CGRectMake(padX, y, innerW, rowH);
    y += rowH + gap;

    self.msg.frame = CGRectMake(padX, y, innerW, msgH);

    // 吉祥物：竖屏放在面板上方，横屏放在左侧空白区
    if (!self.mascot.hidden) {
        CGFloat side = landscape ? MIN(h * 0.52, 240) : MIN(w * 0.42, 180);
        CGFloat mx, my;
        if (landscape) {
            mx = panelX - side - 28;
            if (mx < 12) mx = 12;
            my = (h - side) * 0.5;
        } else {
            mx = (w - side) * 0.5;
            my = panelY - side - (safeTop > 0 ? 6 : 14);
            if (my < safeTop + 8) my = safeTop + 8;
        }
        self.mascot.frame = CGRectMake(mx, my, side, side);
    }

    // 输入框左内边距
    UIView *lv = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 14, rowH)];
    self.field.leftView = lv;
    self.field.leftViewMode = UITextFieldViewModeAlways;

    (void)safeBottom;
}

- (UIStatusBarStyle)preferredStatusBarStyle { return UIStatusBarStyleLightContent; }
- (BOOL)prefersStatusBarHidden { return NO; }

@end

#pragma mark - ========== 门禁控制 ==========

@implementation CGate {
    UIWindow *_win;
    CGGateVC *_vc;
    NSString *_card;
    NSTimer *_timer;
}

+ (instancetype)shared {
    static CGate *g; static dispatch_once_t once;
    dispatch_once(&once, ^{ g = [CGate new]; });
    return g;
}

- (void)start {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *card = [d stringForKey:K_CARD];
    double exp = [d doubleForKey:K_EXPIRE];
    if (card.length && exp > [[NSDate date] timeIntervalSince1970]) {
        _card = [card copy];
        [self scheduleRevalidate];
        return;
    }
    [self show];
}

- (void)show {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self->_win) {
            [self->_win setHidden:NO];
            [self->_win makeKeyAndVisible];
            return;
        }
        CGRect scr = [UIScreen mainScreen].bounds;
        self->_win = [[UIWindow alloc] initWithFrame:scr];
        self->_win.windowLevel = UIWindowLevelAlert + 10;
        self->_win.backgroundColor = [UIColor blackColor];

        CGGateVC *vc = [CGGateVC new];
        __weak typeof(self) weakSelf = self;
        vc.onSubmit = ^(NSString *card) { [weakSelf handleSubmit:card]; };
        self->_vc = vc;
        self->_win.rootViewController = vc;
        [self->_win makeKeyAndVisible];
    });
}

- (void)hide {
    dispatch_async(dispatch_get_main_queue(), ^{ [self->_win setHidden:YES]; });
}

- (void)handleSubmit:(NSString *)raw {
    NSString *card = [raw stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!card.length) { _vc.msg.text = @"请输入卡密"; return; }
    _vc.btn.enabled = NO;
    _vc.msg.text = @"登录中…";
    [self loginCard:card attempt:0 done:^(BOOL ok, NSString *text) {
        self->_vc.btn.enabled = YES;
        self->_vc.msg.text = text;
        self->_vc.msg.textColor = ok ? [UIColor colorWithRed:0.55 green:1 blue:0.75 alpha:1]
                                     : [UIColor colorWithRed:1 green:0.55 blue:0.55 alpha:1];
        if (ok) {
            self->_card = [card copy];
            [self hide];
            [self scheduleRevalidate];
        }
    }];
}

static NSString *CodeName(NSInteger code) {
    switch (code) {
        case 105: return @"系统时间出错";
        case 149: return @"卡密不存在";
        case 150: return @"卡密已过期";
        case 151: return @"卡密已被使用";
        case 152: return @"设备不匹配";
        case 153: return @"卡密已被禁用";
        default:  return nil;
    }
}

- (void)loginCard:(NSString *)card attempt:(int)attempt done:(void (^)(BOOL, NSString *))done {
    WYLoginOnce(card, gTimeOffset, ^(BOOL netok, NSInteger code, NSString *msg, double expire, long long serverTime) {
        if (!netok && (code == -2 || code == -3) && attempt < 1) {
            [self loginCard:card attempt:attempt + 1 done:done];
            return;
        }
        if (!netok) { done(NO, msg.length ? msg : @"网络错误"); return; }

        if (code == 105 && attempt < 1) {
            long long local = (long long)[[NSDate date] timeIntervalSince1970];
            gTimeOffset = (serverTime > 0) ? (serverTime - local) : 60;
            [self loginCard:card attempt:attempt + 1 done:done];
            return;
        }

        if (code != 2416) {
            NSString *name = CodeName(code);
            done(NO, msg.length ? msg
                 : (name ?: [NSString stringWithFormat:@"登录失败(%ld)", (long)code]));
            return;
        }

        double exp = expire;
        if (exp <= 0) exp = [[NSDate date] timeIntervalSince1970] + 3600;
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        [d setObject:card forKey:K_CARD];
        [d setDouble:exp forKey:K_EXPIRE];
        [d synchronize];

        NSDateFormatter *df = [NSDateFormatter new];
        df.dateFormat = @"yyyy-MM-dd HH:mm";
        done(YES, [NSString stringWithFormat:@"登录成功\n到期 %@",
                   [df stringFromDate:[NSDate dateWithTimeIntervalSince1970:exp]]]);
    });
}

- (void)scheduleRevalidate {
    if (REVALIDATE_SEC <= 0 || !_card.length) return;
    [_timer invalidate];
    __weak typeof(self) weakSelf = self;
    _timer = [NSTimer scheduledTimerWithTimeInterval:REVALIDATE_SEC repeats:YES block:^(NSTimer *t) {
        CGate *strongSelf = weakSelf;
        if (!strongSelf) return;
        [strongSelf loginCard:strongSelf->_card attempt:0 done:^(BOOL ok, NSString *text) {
            if (!ok) {
                NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
                [d removeObjectForKey:K_EXPIRE];
                [d synchronize];
                [t invalidate];
                [strongSelf show];
            }
        }];
    }];
}

- (void)dealloc { [_timer invalidate]; }

@end

#pragma mark - ========== 吉祥物加载 ==========

static UIImage *CGateLoadMascot(void) {
    NSArray *names = @[@"NaiLong@3x", @"NaiLong@2x", @"NaiLong", @"nailong", @"Mascot"];
    for (NSString *n in names) {
        NSString *p = [[NSBundle mainBundle] pathForResource:n ofType:@"png"];
        if (p) return [UIImage imageWithContentsOfFile:p];
    }
    return nil;
}

#pragma mark - ========== 入口 ==========

__attribute__((constructor))
static void cgate_ctor(void) {
    dispatch_async(dispatch_get_main_queue(), ^{ [[CGate shared] start]; });
}

@interface CGateLoader : NSObject @end

@implementation CGateLoader
+ (void)load {
    dispatch_async(dispatch_get_main_queue(), ^{ [[CGate shared] start]; });
}
@end



