// ============================================================
//  CardGate.m —— 卡密门禁 dylib（微验 动态密钥 v2）
//  安全通道：X25519 协商 → HKDF-SHA256 → ChaCha20-Poly1305 → Ed25519 验签
//  编译：clang -target arm64-apple-ios14.0（GitHub Actions 已配好）
// ============================================================
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
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

typedef void (^WYDone)(BOOL ok, NSInteger code, NSString *msg, double expire);

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
    uint8_t respKey[32] = {0};
    if (wy2_seal(gSrvX, gLicPub, gLicCli, WY_APPKEY, plain.UTF8String, card.UTF8String,
                 &frame, respKey) != 0) {
        done(NO, -1, @"安全通道初始化失败", 0);
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
        if (e || !d.length) { done(NO, -1, @"网络错误", 0); return; }
        NSString *raw = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (!raw) { done(NO, -1, @"响应编码异常", 0); return; }

        // 取信封字段
        NSDictionary *envelope = [NSJSONSerialization
                                  JSONObjectWithData:d options:0 error:nil];
        NSString *dataHex = WYStr(envelope, @"data");
        NSString *sigHex  = WYStr(envelope, @"sig");
        if (!dataHex.length || !sigHex.length) {
            // 未走安全信封（通常是配置/密钥不匹配）
            NSString *msg = WYStr(envelope, F_MSG);
            done(NO, [WYStr(envelope, F_CODE) integerValue], msg.length ? msg : @"通道未加密", 0);
            return;
        }

        char *pt = NULL;
        int rc = wy2_open(gSrvEd, respKey, dataHex.UTF8String, sigHex.UTF8String, &pt);
        if (rc != 0) {
            done(NO, -2, rc == -2 ? @"响应验签失败" : @"响应解密失败", 0);
            return;
        }
        NSString *plainResp = [NSString stringWithUTF8String:pt];
        free(pt);

        NSData *jd = [plainResp dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *j = [NSJSONSerialization JSONObjectWithData:jd options:0 error:nil];
        if (![j isKindOfClass:NSDictionary.class]) { done(NO, -3, @"业务响应解析失败", 0); return; }

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
                if (![got isEqualToString:W_VAL]) { done(NO, -4, @"响应校验失败", 0); return; }
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
        done(YES, code, msg, expire);
    }] resume];
}

#pragma mark - ========== 门禁 UI ==========

@interface CGate : NSObject <UITextFieldDelegate>
@property (nonatomic, strong) UIWindow *win;
@property (nonatomic, strong) UITextField *field;
@property (nonatomic, strong) UILabel *msg;
@property (nonatomic, strong) UIButton *btn;
@property (nonatomic, copy) NSString *card;
@property (nonatomic, strong) NSTimer *timer;
@end

@implementation CGate

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
        self.card = card;
        [self scheduleRevalidate];
        return;
    }
    [self show];
}

- (void)show {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.win) { [self.win setHidden:NO]; [self.win makeKeyAndVisible]; return; }
        CGRect scr = [UIScreen mainScreen].bounds;
        self.win = [[UIWindow alloc] initWithFrame:scr];
        self.win.windowLevel = UIWindowLevelAlert + 10;
        self.win.backgroundColor = [UIColor colorWithWhite:0 alpha:0.92];

        UIViewController *vc = [UIViewController new];
        self.win.rootViewController = vc;
        CGFloat w = scr.size.width - 48;

        UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(24, scr.size.height/2 - 150, w, 34)];
        title.text = @"卡密登录";
        title.textColor = UIColor.whiteColor;
        title.font = [UIFont boldSystemFontOfSize:24];
        title.textAlignment = NSTextAlignmentCenter;
        [vc.view addSubview:title];

        self.field = [[UITextField alloc] initWithFrame:CGRectMake(24, scr.size.height/2 - 100, w, 48)];
        self.field.placeholder = @"请输入卡密";
        self.field.backgroundColor = [UIColor colorWithWhite:1 alpha:0.10];
        self.field.textColor = UIColor.whiteColor;
        self.field.layer.cornerRadius = 12;
        self.field.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
        self.field.autocorrectionType = UITextAutocorrectionTypeNo;
        self.field.delegate = self;
        UIView *pad = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 12, 48)];
        self.field.leftView = pad;
        self.field.leftViewMode = UITextFieldViewModeAlways;
        [vc.view addSubview:self.field];

        self.btn = [UIButton buttonWithType:UIButtonTypeSystem];
        self.btn.frame = CGRectMake(24, scr.size.height/2 - 40, w, 48);
        [self.btn setTitle:@"登录" forState:UIControlStateNormal];
        self.btn.backgroundColor = [UIColor colorWithWhite:1 alpha:0.18];
        self.btn.layer.cornerRadius = 12;
        [self.btn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
        [self.btn addTarget:self action:@selector(submit) forControlEvents:UIControlEventTouchUpInside];
        [vc.view addSubview:self.btn];

        self.msg = [[UILabel alloc] initWithFrame:CGRectMake(24, scr.size.height/2 + 16, w, 24)];
        self.msg.textColor = [UIColor colorWithRed:1 green:0.45 blue:0.45 alpha:1];
        self.msg.textAlignment = NSTextAlignmentCenter;
        self.msg.font = [UIFont systemFontOfSize:14];
        [vc.view addSubview:self.msg];

        [self.win makeKeyAndVisible];
    });
}

- (void)hide {
    dispatch_async(dispatch_get_main_queue(), ^{ [self.win setHidden:YES]; });
}

- (void)submit {
    NSString *card = [self.field.text stringByTrimmingCharactersInSet:
                      [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (!card.length) { self.msg.text = @"请输入卡密"; return; }
    self.btn.enabled = NO;
    self.msg.text = @"登录中…";
    [self loginCard:card attempt:0 done:^(BOOL ok, NSString *text) {
        self.btn.enabled = YES;
        self.msg.text = text;
        if (ok) { self.card = card; [self hide]; [self scheduleRevalidate]; }
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
    WYLoginOnce(card, gTimeOffset, ^(BOOL netok, NSInteger code, NSString *msg, double expire) {
        if (!netok) { done(NO, msg.length ? msg : @"网络错误"); return; }

        // 时间偏差：用服务器时间来校正后重试一次
        if ([[NSString stringWithFormat:@"%ld", (long)code] isEqualToString:CODE_BADTIME] && attempt < 1) {
            NSString *tm = nil;
            // 服务器时间从业务响应拿不到时，简单加 1 分钟再试
            (void)tm;
            gTimeOffset += 60;
            [self loginCard:card attempt:attempt + 1 done:done];
            return;
        }

        NSString *codeStr = [NSString stringWithFormat:@"%ld", (long)code];
        if (![codeStr isEqualToString:CODE_OK]) {
            NSString *name = CodeName(code);
            NSString *show = msg.length ? msg : (name ?: [NSString stringWithFormat:@"登录失败(%ld)", (long)code]);
            done(NO, show);
            return;
        }

        if (expire <= 0) expire = [[NSDate date] timeIntervalSince1970] + 3600;
        NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
        [d setObject:card forKey:K_CARD];
        [d setDouble:expire forKey:K_EXPIRE];
        [d synchronize];

        NSDateFormatter *df = [NSDateFormatter new];
        df.dateFormat = @"yyyy-MM-dd HH:mm";
        done(YES, [NSString stringWithFormat:@"登录成功，到期 %@",
                   [df stringFromDate:[NSDate dateWithTimeIntervalSince1970:expire]]]);
    });
}

- (void)scheduleRevalidate {
    if (REVALIDATE_SEC <= 0 || !self.card.length) return;
    [self.timer invalidate];
    __weak typeof(self) weakSelf = self;
    self.timer = [NSTimer scheduledTimerWithTimeInterval:REVALIDATE_SEC repeats:YES block:^(NSTimer *t) {
        [weakSelf loginCard:weakSelf.card attempt:0 done:^(BOOL ok, NSString *text) {
            if (!ok) {
                NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
                [d removeObjectForKey:K_EXPIRE];
                [d synchronize];
                [t invalidate];
                [weakSelf show];
            }
        }];
    }];
}

- (void)dealloc { [self.timer invalidate]; }

@end

#pragma mark - ========== 入口（constructor + +load 双保险）==========

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
