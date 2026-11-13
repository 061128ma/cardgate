// ============================================================
//  CardGate.m —— 卡密门禁 dylib（微验 动态密钥 v2）
//  安全通道：X25519 协商 → HKDF-SHA256 → ChaCha20-Poly1305 → Ed25519 验签
//  编译：clang -target arm64-apple-ios14.0（GitHub Actions 已配好）
// ============================================================
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <QuartzCore/QuartzCore.h>
#include "crypto/wy2.h"

#pragma mark - ========== 配置（密文，运行时解密）==========

#include "crypto/wyguard.h"
#include "crypto/sealed.h"

/* 解密后的工作缓冲区 */
static char gHost[64], gToken[64], gAppKey[64], gLoginId[32];
static char gSrvXHex[96], gSrvEdHex[96], gLicPubHex[96], gLicCliHex[96];
static char gFCode[64], gFMsg[64], gFTime[64], gFVip[64], gWKey[64], gWVal[64], gOkCode[16];

/* 二进制形式 */
static uint8_t gSrvX[32], gSrvEd[32], gLicPub[32], gLicCli[32];

static dispatch_once_t gSealOnce;
static int gGuardOK = 0;
static long long gTimeOffset = 0;

static void WYUnseal(void)
{
    dispatch_once(&gSealOnce, ^{
        wyguard_unseal(SEAL_HOST,    (unsigned char *)gHost,     SEAL_HOST_len,    SEAL_HOST_key);
        wyguard_unseal(SEAL_TOKEN,   (unsigned char *)gToken,    SEAL_TOKEN_len,   SEAL_TOKEN_key);
        wyguard_unseal(SEAL_APPKEY,  (unsigned char *)gAppKey,   SEAL_APPKEY_len,  SEAL_APPKEY_key);
        wyguard_unseal(SEAL_LOGINID, (unsigned char *)gLoginId,  SEAL_LOGINID_len, SEAL_LOGINID_key);
        wyguard_unseal(SEAL_SRVX,    (unsigned char *)gSrvXHex,  SEAL_SRVX_len,    SEAL_SRVX_key);
        wyguard_unseal(SEAL_SRVED,   (unsigned char *)gSrvEdHex, SEAL_SRVED_len,   SEAL_SRVED_key);
        wyguard_unseal(SEAL_LICPUB,  (unsigned char *)gLicPubHex,SEAL_LICPUB_len,  SEAL_LICPUB_key);
        wyguard_unseal(SEAL_LICCLI,  (unsigned char *)gLicCliHex,SEAL_LICCLI_len,  SEAL_LICCLI_key);
        wyguard_unseal(SEAL_FCODE,   (unsigned char *)gFCode,    SEAL_FCODE_len,   SEAL_FCODE_key);
        wyguard_unseal(SEAL_FMSG,    (unsigned char *)gFMsg,     SEAL_FMSG_len,    SEAL_FMSG_key);
        wyguard_unseal(SEAL_FTIME,   (unsigned char *)gFTime,    SEAL_FTIME_len,   SEAL_FTIME_key);
        wyguard_unseal(SEAL_FVIP,    (unsigned char *)gFVip,     SEAL_FVIP_len,    SEAL_FVIP_key);
        wyguard_unseal(SEAL_WKEY,    (unsigned char *)gWKey,     SEAL_WKEY_len,    SEAL_WKEY_key);
        wyguard_unseal(SEAL_WVAL,    (unsigned char *)gWVal,     SEAL_WVAL_len,    SEAL_WVAL_key);
        wyguard_unseal(SEAL_OKCODE,  (unsigned char *)gOkCode,   SEAL_OKCODE_len,  SEAL_OKCODE_key);

        wy2_from_hex(gSrvXHex,    gSrvX,    32);
        wy2_from_hex(gSrvEdHex,   gSrvEd,   32);
        wy2_from_hex(gLicPubHex,  gLicPub,  32);
        wy2_from_hex(gLicCliHex,  gLicCli,  32);
    });
}

/* ObjC 侧取字段名的便捷函数 */
static NSString *WYFieldCode(void) { WYUnseal(); return [NSString stringWithUTF8String:gFCode]; }
static NSString *WYFieldMsg(void)  { WYUnseal(); return [NSString stringWithUTF8String:gFMsg]; }
static NSString *WYFieldTime(void) { WYUnseal(); return [NSString stringWithUTF8String:gFTime]; }
static NSString *WYFieldVip(void)  { WYUnseal(); return [NSString stringWithUTF8String:gFVip]; }
static NSString *WYFieldWKey(void) { WYUnseal(); return [NSString stringWithUTF8String:gWKey]; }
static NSString *WYFieldWVal(void) { WYUnseal(); return [NSString stringWithUTF8String:gWVal]; }
static NSString *WYFieldOkCode(void){ WYUnseal(); return [NSString stringWithUTF8String:gOkCode]; }
static NSString *WYFieldBadTime(void){ return @"105"; }

static NSString *const K_CARD   = @"wy2_card";
static NSString *const K_EXPIRE = @"wy2_expire";
static const  int      REVALIDATE_SEC = 120;   // 心跳 2 分钟

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

#pragma mark - ========== 单次登录（v2 安全通道）==========

typedef void (^WYDone)(BOOL ok, NSInteger code, NSString *msg, double expire, long long serverTime);

static void WYLoginOnce(NSString *card, long long timeOffset, WYDone done) {
    WYUnseal();

    long long T = (long long)[[NSDate date] timeIntervalSince1970] + timeOffset;
    unsigned value = (unsigned)(100000 + arc4random_uniform(900000));
    NSString *valueStr = [NSString stringWithFormat:@"%lld%u", T, value];
    NSString *mark = WYMarkCode();

    WYUnseal();
    NSString *signSrc = [NSString stringWithFormat:@"kami=%@&markcode=%@&t=%lld&%s",
                         card, mark, T, gAppKey];
    NSString *sign = WYMD5(signSrc);
    NSString *plain = [NSString stringWithFormat:
                       @"id=%s&kami=%@&markcode=%@&t=%lld&sign=%@&value=%@",
                       gLoginId, card, mark, T, sign, valueStr];

    char *frame = NULL;
    // block 不能捕获数组，用 NSMutableData 持有内存，并由 block 强引用保证生命周期
    NSMutableData *keyData = [NSMutableData dataWithLength:32];
    uint8_t *respKey = (uint8_t *)keyData.mutableBytes;
    memset(respKey, 0, 32);
    if (wy2_seal(gSrvX, gLicPub, gLicCli, gAppKey, plain.UTF8String, card.UTF8String,
                 &frame, respKey) != 0) {
        done(NO, -1, @"安全通道初始化失败", 0, 0);
        return;
    }
    NSString *body = [NSString stringWithUTF8String:frame];
    free(frame);

    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"https://%s/v2/%s",
                                       gHost, gToken]];
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
            NSString *msg = WYStr(envelope, WYFieldMsg());
            done(NO, [WYStr(envelope, WYFieldCode()) integerValue], msg.length ? msg : @"通道未加密", 0, 0);
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

        NSInteger code = [WYStr(j, WYFieldCode()) integerValue];
        NSString *msg  = WYStr(j, WYFieldMsg());

        // msg 里可能嵌一层 JSON（含 vip / 校验位）
        NSDictionary *inner = nil;
        if ([msg hasPrefix:@"{"]) {
            inner = [NSJSONSerialization JSONObjectWithData:
                     [msg dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
        }

        double expire = 0;
        if ([inner isKindOfClass:NSDictionary.class]) {
            NSString *vip = WYStr(inner, WYFieldVip());
            if (vip.length) expire = [vip doubleValue];
            if (strlen(gWVal) > 0) {
                NSString *got = WYStr(inner, WYFieldWKey());
                if (![got isEqualToString:WYFieldWVal()]) { done(NO, -4, @"响应校验失败", 0, 0); return; }
            }
        }
        if (!expire) {
            NSString *vip = WYStr(j, WYFieldVip());
            if (vip.length) expire = [vip doubleValue];
        }
        if (!expire) {
            NSString *tm = WYStr(j, WYFieldTime());
            double v = [tm doubleValue];
            if (v > 1e12) v /= 1000.0;
            if (v > 0 && [WYStr(j, WYFieldCode()) isEqualToString:WYFieldOkCode()]) {
                expire = [[NSDate date] timeIntervalSince1970] + 3600;
            }
        }
        long long srvTime = [WYStr(j, WYFieldTime()) longLongValue];
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

#pragma mark - ========== 校验中遮罩 ==========

@interface CGCheckingVC : UIViewController
@property (nonatomic, strong) UILabel *textLabel;
@property (nonatomic, strong) UIActivityIndicatorView *spinner;
@end

@implementation CGCheckingVC
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];
    CGAuroraView *bg = [[CGAuroraView alloc] initWithFrame:self.view.bounds];
    bg.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.view addSubview:bg];

    self.spinner = [[UIActivityIndicatorView alloc]
                    initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleLarge];
    self.spinner.color = [UIColor whiteColor];
    [self.view addSubview:self.spinner];
    [self.spinner startAnimating];

    self.textLabel = [UILabel new];
    self.textLabel.text = @"正在校验授权…";
    self.textLabel.textColor = [UIColor colorWithWhite:1 alpha:0.85];
    self.textLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightMedium];
    self.textLabel.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:self.textLabel];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGRect b = self.view.bounds;
    self.spinner.center = CGPointMake(b.size.width * 0.5, b.size.height * 0.5 - 20);
    self.textLabel.frame = CGRectMake(0, b.size.height * 0.5 + 16, b.size.width, 24);
}

- (UIStatusBarStyle)preferredStatusBarStyle { return UIStatusBarStyleLightContent; }
@end

// ============================================================
//  公告 / 更新检查 / 通用请求（追加到 CardGate.m 末尾的独立段落）
//  协议来源：微验官方示例 Form1.cs 的 CheckNotice / CheckUpdate
//  公告与更新走【字面 code/msg】字段，不参与混淆字段名映射
// ============================================================

static char gNoticeId[16], gNoticeCode[16], gIniId[16], gIniCode[16], gAppVer[16];

static dispatch_once_t gExtOnce;
static void WYUnsealExt(void)
{
    dispatch_once(&gExtOnce, ^{
        wyguard_unseal(SEAL_NOTICEID,   (unsigned char *)gNoticeId,   SEAL_NOTICEID_len,   SEAL_NOTICEID_key);
        wyguard_unseal(SEAL_NOTICECODE, (unsigned char *)gNoticeCode, SEAL_NOTICECODE_len, SEAL_NOTICECODE_key);
        wyguard_unseal(SEAL_INIID,      (unsigned char *)gIniId,      SEAL_INIID_len,      SEAL_INIID_key);
        wyguard_unseal(SEAL_INICODE,    (unsigned char *)gIniCode,    SEAL_INICODE_len,    SEAL_INICODE_key);
        wyguard_unseal(SEAL_APPVER,     (unsigned char *)gAppVer,     SEAL_APPVER_len,     SEAL_APPVER_key);
    });
}

typedef void (^WYRawDone)(BOOL ok, NSDictionary *json, NSString *err);

/* 通用 v2 请求：不做业务判定，只负责封包/发送/验签/解密，返回业务明文 JSON */
static void WYExecRequest(const char *apiId, NSString *kami, WYRawDone done)
{
    WYUnseal();
    WYUnsealExt();

    NSString *card = kami ?: @"";
    long long T = (long long)[[NSDate date] timeIntervalSince1970] + gTimeOffset;
    unsigned value = (unsigned)(100000 + arc4random_uniform(900000));
    NSString *valueStr = [NSString stringWithFormat:@"%lld%u", T, value];
    NSString *mark = WYMarkCode();

    NSString *signSrc = [NSString stringWithFormat:@"kami=%@&markcode=%@&t=%lld&%s",
                         card, mark, T, gAppKey];
    NSString *sign = WYMD5(signSrc);
    NSString *plain = [NSString stringWithFormat:
                       @"id=%s&kami=%@&markcode=%@&t=%lld&sign=%@&value=%@",
                       apiId, card, mark, T, sign, valueStr];

    char *frame = NULL;
    NSMutableData *keyData = [NSMutableData dataWithLength:32];
    uint8_t *respKey = (uint8_t *)keyData.mutableBytes;
    memset(respKey, 0, 32);
    if (wy2_seal(gSrvX, gLicPub, gLicCli, gAppKey, plain.UTF8String, card.UTF8String,
                 &frame, respKey) != 0) {
        done(NO, nil, @"安全通道初始化失败");
        return;
    }
    NSString *body = [NSString stringWithUTF8String:frame];
    free(frame);

    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"https://%s/v2/%s",
                                       gHost, gToken]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 20;
    [req setValue:@"text/plain" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [body dataUsingEncoding:NSUTF8StringEncoding];

    [[[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (e || !d.length) { done(NO, nil, @"网络错误"); return; }
        uint8_t *rk = (uint8_t *)keyData.mutableBytes;
        NSDictionary *envelope = [NSJSONSerialization JSONObjectWithData:d options:0 error:nil];
        NSString *dataHex = WYStr(envelope, @"data");
        NSString *sigHex  = WYStr(envelope, @"sig");
        if (!dataHex.length || !sigHex.length) {
            done(NO, envelope, @"通道未加密");
            return;
        }
        char *pt = NULL;
        int rc = wy2_open(gSrvEd, rk, dataHex.UTF8String, sigHex.UTF8String, &pt);
        if (rc != 0) { done(NO, nil, rc == -2 ? @"响应验签失败" : @"响应解密失败"); return; }
        NSString *plainResp = [NSString stringWithUTF8String:pt];
        free(pt);
        NSDictionary *j = [NSJSONSerialization
                           JSONObjectWithData:[plainResp dataUsingEncoding:NSUTF8StringEncoding]
                           options:0 error:nil];
        if (![j isKindOfClass:NSDictionary.class]) { done(NO, nil, @"业务响应解析失败"); return; }
        done(YES, j, nil);
    }] resume];
}

/* 从字面 code/msg 里取值（公告/更新专用，避开混淆字段名） */
static NSString *WYLiteralField(NSDictionary *j, NSString *key) {
    if (![j isKindOfClass:NSDictionary.class]) return @"";
    id v = j[key];
    if (!v || v == NSNull.null) return @"";
    return [v description];
}

/* 拉公告：成功返回公告正文，没有公告返回 nil */
static void WYFetchNotice(void (^done)(NSString *text))
{
    WYUnsealExt();
    WYExecRequest(gNoticeId, @"", ^(BOOL ok, NSDictionary *j, NSString *err) {
        if (!ok || ![j isKindOfClass:NSDictionary.class]) { done(nil); return; }

        NSString *code = WYLiteralField(j, @"code");
        if (![code isEqualToString:[NSString stringWithUTF8String:gNoticeCode]]) { done(nil); return; }

        NSString *msg = WYLiteralField(j, @"msg");
        NSString *text = msg;
        if ([msg hasPrefix:@"{"]) {
            NSDictionary *mo = [NSJSONSerialization
                                JSONObjectWithData:[msg dataUsingEncoding:NSUTF8StringEncoding]
                                options:0 error:nil];
            if ([mo isKindOfClass:NSDictionary.class] && mo[@"app_gg"]) {
                text = [mo[@"app_gg"] description];
            }
        }
        // 过滤后台的占位内容，避免每次登录都弹
        NSArray *placeholders = @[@"", @"{}", @"null", @"暂无", @"无", @"-", @"（无）"];
        NSString *trimmed = [text stringByTrimmingCharactersInSet:
                             [NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if ([placeholders containsObject:trimmed]) { done(nil); return; }
        done(trimmed);
    });
}

/* 检查更新：有新版返回 YES 并回填信息 */
static void WYFetchUpdate(void (^done)(BOOL hasNew, NSString *ver, NSString *note,
                                       NSString *url, BOOL force))
{
    WYUnsealExt();
    WYExecRequest(gIniId, @"", ^(BOOL ok, NSDictionary *j, NSString *err) {
        if (!ok || ![j isKindOfClass:NSDictionary.class]) { done(NO, nil, nil, nil, NO); return; }

        NSString *code = WYLiteralField(j, @"code");
        if (![code isEqualToString:[NSString stringWithUTF8String:gIniCode]]) {
            done(NO, nil, nil, nil, NO);
            return;
        }
        NSString *msg = WYLiteralField(j, @"msg");
        NSDictionary *mo = nil;
        if ([msg hasPrefix:@"{"]) {
            mo = [NSJSONSerialization
                  JSONObjectWithData:[msg dataUsingEncoding:NSUTF8StringEncoding]
                  options:0 error:nil];
        }
        if (![mo isKindOfClass:NSDictionary.class]) { done(NO, nil, nil, nil, NO); return; }

        NSString *ver   = mo[@"version"] ? [mo[@"version"] description] : @"";
        NSString *show  = mo[@"updateshow"] ? [mo[@"updateshow"] description] : @"";
        NSString *url   = mo[@"updateurl"] ? [mo[@"updateurl"] description] : @"";
        NSString *must  = mo[@"updatemust"] ? [mo[@"updatemust"] description] : @"n";

        if (!ver.length) { done(NO, nil, nil, nil, NO); return; }
        if ([ver isEqualToString:[NSString stringWithUTF8String:gAppVer]]) {
            done(NO, ver, nil, nil, NO);
            return;
        }
        done(YES, ver, show, url, [must isEqualToString:@"y"]);
    });
}
#pragma mark - ========== 门禁控制 ==========

@implementation CGate {
    UIWindow *_win;
    CGGateVC *_vc;
    NSString *_card;
    NSTimer *_timer;
    BOOL _checking;
}

+ (instancetype)shared {
    static CGate *g; static dispatch_once_t once;
    dispatch_once(&once, ^{ g = [CGate new]; });
    return g;
}

#pragma mark 票据

- (void)saveTicket:(NSString *)card expire:(double)expire {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d setObject:card forKey:K_CARD];
    [d setDouble:expire forKey:K_EXPIRE];
    [d synchronize];
}

- (void)clearTicket {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    [d removeObjectForKey:K_EXPIRE];
    [d synchronize];
}

- (BOOL)hasTicket {
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *card = [d stringForKey:K_CARD];
    double exp = [d doubleForKey:K_EXPIRE];
    return card.length > 0 && exp > [[NSDate date] timeIntervalSince1970];
}

#pragma mark 启动流程

- (void)start {
    // 运行时自检：反调试 + 依赖链强校验 + 自身镜像
    WYUnseal();
    gGuardOK = wyguard_check();
    if (!gGuardOK) {
        // 环境被改动（调试器附加 / CardGate 被弱链接化或替换）
        [self lockOut];
        return;
    }
    if (![self hasTicket]) {
        [self showGateWithMessage:nil];
        return;
    }

    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    _card = [d stringForKey:K_CARD];

    // 每次启动都联网复核：卡被封/过期/掉绑定，立刻拦下
    [self showChecking];
    [self loginCard:_card attempt:0 done:^(BOOL ok, NSString *text) {
        if (ok) {
            [self hide];
            [self scheduleRevalidate];
            [self afterAuthorized];
        } else {
            [self clearTicket];
            [self showGateWithMessage:text];
        }
    }];
}

- (void)showGateWithMessage:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        self->_checking = NO;
        if (self->_win && self->_vc) {
            [self->_win setHidden:NO];
            [self->_win makeKeyAndVisible];
            if (message.length) self->_vc.msg.text = message;
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
        if (message.length) {
            vc.msg.text = message;
            vc.msg.textColor = [UIColor colorWithRed:1 green:0.55 blue:0.55 alpha:1];
        }
    });
}

- (void)showChecking {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self->_checking) return;
        self->_checking = YES;
        self->_vc = nil;
        CGRect scr = [UIScreen mainScreen].bounds;
        if (!self->_win) {
            self->_win = [[UIWindow alloc] initWithFrame:scr];
            self->_win.windowLevel = UIWindowLevelAlert + 10;
        }
        self->_win.frame = scr;
        self->_win.rootViewController = [CGCheckingVC new];
        self->_win.backgroundColor = [UIColor blackColor];
        [self->_win setHidden:NO];
        [self->_win makeKeyAndVisible];
    });
}

- (void)hide {
    dispatch_async(dispatch_get_main_queue(), ^{
        self->_checking = NO;
        [self->_win setHidden:YES];
        self->_vc = nil;
    });
}

#pragma mark 提交

- (void)afterAuthorized {
    // 授权通过后：拉公告 + 检查更新（失败静默，不阻断使用）
    __weak typeof(self) weakSelf = self;

    WYFetchNotice(^(NSString *text) {
        if (!text.length) return;
        dispatch_async(dispatch_get_main_queue(), ^{
            UIAlertController *a = [UIAlertController
                alertControllerWithTitle:@"公告" message:text
                         preferredStyle:UIAlertControllerStyleAlert];
            [a addAction:[UIAlertAction actionWithTitle:@"知道了"
                                                 style:UIAlertActionStyleDefault handler:nil]];
            [weakSelf presentOnTop:a];
        });
    });

    WYFetchUpdate(^(BOOL hasNew, NSString *ver, NSString *note, NSString *url, BOOL force) {
        if (!hasNew) return;
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *body = [NSString stringWithFormat:@"发现新版本 %@\n\n%@",
                              ver ?: @"", (note.length ? note : @"（无说明）")];
            if (url.length) body = [body stringByAppendingFormat:@"\n\n下载：\n%@", url];

            if (force) {
                UIAlertController *a = [UIAlertController
                    alertControllerWithTitle:@"强制更新" message:body
                             preferredStyle:UIAlertControllerStyleAlert];
                [a addAction:[UIAlertAction actionWithTitle:@"退出"
                                                     style:UIAlertActionStyleDestructive
                                                   handler:^(UIAlertAction *x) { exit(0); }]];
                [weakSelf presentOnTop:a];
                return;
            }
            UIAlertController *a = [UIAlertController
                alertControllerWithTitle:@"发现新版本" message:body
                         preferredStyle:UIAlertControllerStyleAlert];
            [a addAction:[UIAlertAction actionWithTitle:@"稍后"
                                                 style:UIAlertActionStyleCancel handler:nil]];
            if (url.length) {
                [a addAction:[UIAlertAction actionWithTitle:@"前往下载"
                                                     style:UIAlertActionStyleDefault
                                                   handler:^(UIAlertAction *x) {
                    NSURL *u = [NSURL URLWithString:url];
                    if (u) [[UIApplication sharedApplication] openURL:u options:@{} completionHandler:nil];
                }]];
            }
            [weakSelf presentOnTop:a];
        });
    });
}

- (void)presentOnTop:(UIViewController *)vc {
    UIWindow *w = self->_win ?: [UIApplication sharedApplication].keyWindow;
    UIViewController *root = w.rootViewController;
    if (!root) return;
    UIViewController *top = root;
    while (top.presentedViewController) top = top.presentedViewController;
    if (top.presentedViewController) return;
    [top presentViewController:vc animated:YES completion:nil];
}

- (void)lockOut {
    // 环境校验失败：直接终止进程，避免被继续使用
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *msg = @"环境异常，请重新安装";
        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"无法启动"
                                                                 message:msg
                                                          preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"退出" style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *x) { exit(0); }]];
        UIWindow *w = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        w.windowLevel = UIWindowLevelAlert + 20;
        w.rootViewController = [UIViewController new];
        [w makeKeyAndVisible];
        [w.rootViewController presentViewController:a animated:YES completion:^{
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ exit(0); });
        }];
    });
}

- (void)handleSubmit:(NSString *)raw {
    NSString *card = [raw stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!card.length) { _vc.msg.text = @"请输入卡密"; return; }
    _vc.btn.enabled = NO;
    _vc.msg.text = @"登录中…";
    _vc.msg.textColor = [UIColor colorWithWhite:1 alpha:0.7];
    [self loginCard:card attempt:0 done:^(BOOL ok, NSString *text) {
        self->_vc.btn.enabled = YES;
        self->_vc.msg.text = text;
        self->_vc.msg.textColor = ok ? [UIColor colorWithRed:0.55 green:1 blue:0.75 alpha:1]
                                     : [UIColor colorWithRed:1 green:0.55 blue:0.55 alpha:1];
        if (ok) {
            self->_card = [card copy];
            [self hide];
            [self scheduleRevalidate];
            [self afterAuthorized];
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
        case 154: return @"卡密已被封禁";
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

        if (code != atol(gOkCode)) {
            NSString *name = CodeName(code);
            done(NO, msg.length ? msg
                 : (name ?: [NSString stringWithFormat:@"登录失败(%ld)", (long)code]));
            return;
        }

        double exp = expire;
        if (exp <= 0) exp = [[NSDate date] timeIntervalSince1970] + 3600;
        [self saveTicket:card expire:exp];

        NSDateFormatter *df = [NSDateFormatter new];
        df.dateFormat = @"yyyy-MM-dd HH:mm";
        done(YES, [NSString stringWithFormat:@"登录成功\n到期 %@",
                   [df stringFromDate:[NSDate dateWithTimeIntervalSince1970:exp]]]);
    });
}

#pragma mark 心跳与回前台复查

- (void)scheduleRevalidate {
    if (REVALIDATE_SEC <= 0 || !_card.length) return;
    [_timer invalidate];
    __weak typeof(self) weakSelf = self;
    _timer = [NSTimer scheduledTimerWithTimeInterval:REVALIDATE_SEC repeats:YES block:^(NSTimer *t) {
        CGate *strongSelf = weakSelf;
        if (!strongSelf) return;
        [strongSelf silentRevalidate];
    }];

    [[NSNotificationCenter defaultCenter] removeObserver:self
        name:UIApplicationDidBecomeActiveNotification object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self
        selector:@selector(onBecomeActive)
        name:UIApplicationDidBecomeActiveNotification object:nil];
}

- (void)onBecomeActive {
    // 切回前台立刻复查，避免"封卡后仍在使用"
    if (_checking) return;
    if (![self hasTicket]) { [self showGateWithMessage:nil]; return; }
    [self silentRevalidate];
}

- (void)silentRevalidate {
    if (!wyguard_check_fast()) { [self lockOut]; return; }
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    NSString *card = [d stringForKey:K_CARD] ?: _card;
    if (!card.length) { [self showGateWithMessage:nil]; return; }

    [self loginCard:card attempt:0 done:^(BOOL ok, NSString *text) {
        if (ok) return;
        [self clearTicket];
        [self->_timer invalidate];
        [self showGateWithMessage:text];
    }];
}

- (void)dealloc {
    [_timer invalidate];
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

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



