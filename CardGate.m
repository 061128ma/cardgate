// ============================================================
//  CardGate.m —— 卡密门禁 dylib（微验 v1：RC4 + MD5）
//  编译：Theos（GitHub Actions 已配好）
//  依赖：UIKit / Foundation / CommonCrypto（系统自带）
//
//  服务端协议（与官方示例 Form1.cs 对齐）：
//    T      = unix 秒
//    VALUE  = T + random(100000..999999)
//    SIGN   = MD5("kami=<卡密>&markcode=<设备>&t=<T>&<APPKEY>")
//    DATA   = "id=<接口ID>&kami=<卡密>&markcode=<设备>&t=<T>&sign=<SIGN>&value=<VALUE>"
//    ENC    = hex(RC4(DATA, RC4KEY))
//    POST   https://<WEIURL>/v2/<APITOKRN>   Content-Type: text/plain
//    响应   纯 hex → RC4 解密得 JSON；否则按明文 JSON 处理
// ============================================================
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>

#pragma mark - ========== 配置区 ==========

static NSString *const WEIURL    = @"wy.llua.cn";
static NSString *const APITOKRN  = @"992664d2b407c0f899284d7d5c0df89a";
static NSString *const APPKEY    = @"S0ZyYe9JJypNRRSY";
static NSString *const RC4KEY    = @"m0m7k00gi0M86156";

static NSString *const LOGIN_ID   = @"8EE5C3CDF";
static NSString *const LOGIN_CODE = @"2416";
static NSString *const DISMISS_ID = @"0686B3105";

// 后台混淆过的响应字段名（不是默认 code/msg）
static NSString *const F_CODE = @"f891012afe301f1ed6b0d65d77ed68c62";
static NSString *const F_MSG  = @"hd975c61e883e0fa83443c2e39bb959ec";
static NSString *const F_TIME = @"bf921c5bf4325e0cea243fb1e89424921";
static NSString *const F_VIP  = @"ff097bcdf608ccbf49dbdb114df1e2534";

// 响应校验位
static NSString *const W_KEY = @"wbc0a389f8e8127f628d2d25a68ccad4c";
static NSString *const W_VAL = @"05b7c29c6dac5855d41167f0ff4a14b3";

static NSString *const K_CARD   = @"wy1_card";
static NSString *const K_EXPIRE = @"wy1_expire";
static const  int      REVALIDATE_SEC = 1800;

#pragma mark - ========== 原语 ==========

static NSData *WYRC4(NSData *key, NSData *input) {
    if (!key.length || !input.length) return nil;
    uint8_t s[256];
    for (int i = 0; i < 256; i++) s[i] = (uint8_t)i;
    const uint8_t *k = key.bytes;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + k[i % key.length]) & 0xFF;
        uint8_t t = s[i]; s[i] = s[j]; s[j] = t;
    }
    const uint8_t *in = input.bytes;
    uint8_t *out = malloc(input.length);
    if (!out) return nil;
    int a = 0; j = 0;
    for (NSUInteger n = 0; n < input.length; n++) {
        a = (a + 1) & 0xFF;
        j = (j + s[a]) & 0xFF;
        uint8_t t = s[a]; s[a] = s[j]; s[j] = t;
        out[n] = in[n] ^ s[(s[a] + s[j]) & 0xFF];
    }
    NSData *d = [NSData dataWithBytes:out length:input.length];
    free(out);
    return d;
}

static NSString *WYHex(NSData *d) {
    const uint8_t *b = d.bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:d.length * 2];
    for (NSUInteger i = 0; i < d.length; i++) [s appendFormat:@"%02x", b[i]];
    return s;
}

static BOOL WYIsHex(NSString *s) {
    if (!s.length || (s.length % 2)) return NO;
    const char *c = [s UTF8String];
    for (NSUInteger i = 0; i < s.length; i++) {
        char ch = c[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) return NO;
    }
    return YES;
}

static NSData *WYFromHex(NSString *hex) {
    if (!WYIsHex(hex)) return nil;
    NSUInteger n = hex.length / 2;
    NSMutableData *d = [NSMutableData dataWithCapacity:n];
    for (NSUInteger i = 0; i < n; i++) {
        unsigned int v = 0;
        NSScanner *sc = [NSScanner scannerWithString:[hex substringWithRange:NSMakeRange(i * 2, 2)]];
        if (![sc scanHexInt:&v]) return nil;
        uint8_t b = (uint8_t)v;
        [d appendBytes:&b length:1];
    }
    return d;
}

static NSString *WYRC4Hex(NSString *plain) {
    NSData *c = WYRC4([RC4KEY dataUsingEncoding:NSUTF8StringEncoding],
                      [plain dataUsingEncoding:NSUTF8StringEncoding]);
    return c ? WYHex(c) : @"";
}

static NSString *WYRC4Unhex(NSString *hex) {
    NSData *c = WYFromHex(hex);
    if (!c) return nil;
    NSData *p = WYRC4([RC4KEY dataUsingEncoding:NSUTF8StringEncoding], c);
    if (!p) return nil;
    return [[NSString alloc] initWithData:p encoding:NSUTF8StringEncoding];
}

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

static NSString *WYField(NSDictionary *j, NSString *key) {
    if (![j isKindOfClass:NSDictionary.class]) return @"";
    id v = j[key];
    if (!v || v == NSNull.null) return @"";
    return [v description];
}

#pragma mark - ========== 请求 ==========

static void WYRequest(NSString *apiId, NSString *kami,
                      void (^done)(BOOL ok, NSDictionary *json, NSString *err)) {
    long long T = (long long)[[NSDate date] timeIntervalSince1970];
    NSString *value = [NSString stringWithFormat:@"%lld%u", T, (unsigned)(100000 + arc4random_uniform(900000))];
    NSString *mark = WYMarkCode();

    NSString *signSrc = [NSString stringWithFormat:@"kami=%@&markcode=%@&t=%lld&%@", kami, mark, T, APPKEY];
    NSString *sign = WYMD5(signSrc);
    NSString *data = [NSString stringWithFormat:
                      @"id=%@&kami=%@&markcode=%@&t=%lld&sign=%@&value=%@",
                      apiId, kami, mark, T, sign, value];
    NSString *enc = WYRC4Hex(data);

    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"https://%@/v2/%@", WEIURL, APITOKRN]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 15;
    [req setValue:@"text/plain" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [enc dataUsingEncoding:NSUTF8StringEncoding];

    [[[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (e || !d.length) { done(NO, nil, @"网络错误"); return; }
        NSString *raw = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (!raw) raw = [[NSString alloc] initWithData:d encoding:NSISOLatin1StringEncoding];
        raw = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (!raw.length) { done(NO, nil, @"空响应"); return; }

        NSString *jsonText = raw;
        if (WYIsHex(raw)) {
            NSString *dec = WYRC4Unhex(raw);
            if (dec.length) jsonText = dec;
        }
        NSRange brace = [jsonText rangeOfString:@"{"];
        if (brace.location == NSNotFound) { done(NO, nil, @"返回格式异常"); return; }
        NSData *jd = [[jsonText substringFromIndex:brace.location] dataUsingEncoding:NSUTF8StringEncoding];
        NSDictionary *j = [NSJSONSerialization JSONObjectWithData:jd options:0 error:nil];
        if (![j isKindOfClass:NSDictionary.class]) { done(NO, nil, @"JSON 解析失败"); return; }
        done(YES, j, nil);
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

    [self loginCard:card done:^(BOOL ok, NSString *text) {
        self.btn.enabled = YES;
        self.msg.text = text;
        if (ok) { self.card = card; [self hide]; [self scheduleRevalidate]; }
    }];
}

- (void)loginCard:(NSString *)card done:(void (^)(BOOL, NSString *))done {
    WYRequest(LOGIN_ID, card, ^(BOOL netok, NSDictionary *j, NSString *err) {
        if (!netok) { done(NO, err ?: @"网络错误"); return; }

        NSString *code = WYField(j, F_CODE);
        NSString *msg  = WYField(j, F_MSG);
        if (![code isEqualToString:LOGIN_CODE]) {
            if ([msg hasPrefix:@"{"]) {
                NSDictionary *inner = [NSJSONSerialization
                    JSONObjectWithData:[msg dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
                NSString *im = WYField(inner, @"msg");
                if (!im.length) im = WYField(inner, F_MSG);
                if (!im.length) im = WYField(inner, @"info");
                if (im.length) msg = im;
            }
            done(NO, msg.length ? msg : @"卡密无效");
            return;
        }

        NSDictionary *inner = nil;
        if ([msg hasPrefix:@"{"]) {
            inner = [NSJSONSerialization
                     JSONObjectWithData:[msg dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil];
        }
        if (W_VAL.length) {
            NSString *got = inner ? WYField(inner, W_KEY) : @"";
            if (![got isEqualToString:W_VAL]) { done(NO, @"响应校验失败"); return; }
        }

        double expire = 0;
        NSString *vip = inner ? WYField(inner, F_VIP) : @"";
        if (!vip.length) vip = WYField(j, F_VIP);
        if (vip.length) expire = [vip doubleValue];
        if (!expire) {
            NSString *tm = inner ? WYField(inner, F_TIME) : @"";
            if (!tm.length) tm = WYField(j, F_TIME);
            double v = [tm doubleValue];
            if (v > 1e12) v /= 1000.0;
            if (v > 0) expire = v;
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
        [weakSelf loginCard:weakSelf.card done:^(BOOL ok, NSString *text) {
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

#pragma mark - ========== 入口 ==========

__attribute__((constructor))
static void cgate_entry(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[CGate shared] start];
    });
}
