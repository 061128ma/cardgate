# CardGate —— 卡密门禁插件（微验 v1）

给 `鱼骨头`（MobileStore）HUD 加一层卡密登录。**纯 Objective-C，不需要第三方库**，GitHub Actions 里自动编译成 `.dylib`。

## 怎么拿到 dylib（不需要 Mac）

1. 打开 https://github.com/new → 仓库名随便填（例如 `cardgate`）→ **Public** 或 Private 都行 → Create
2. 点 **uploading an existing file** → 把这个文件夹里的全部内容拖进去 → Commit
3. 点上方 **Actions** 标签 → 左侧 `build` → 右上 **Run workflow** → 再点绿色按钮
4. 等 3~5 分钟，进去点最新一次运行 → 页面底部 **Artifacts** → 下载 `CardGate-dylib`
5. 解压得到 `CardGate.dylib`，发给我，我注入进 IPA 出成品包

## 目录结构

```
CardGate.m                    ← 门禁源码（配置已填好）
Makefile                      ← Theos 构建配置
.github/workflows/build.yml   ← GitHub Actions 自动编译
```

## 里面的配置

已经按你的微验后台填好（见 `CardGate.m` 顶部）：

| 常量 | 值 |
|---|---|
| `WEIURL` | `wy.llua.cn` |
| `APITOKRN` | `992664d2b407c0f899284d7d5c0df89a` |
| `APPKEY` / `RC4KEY` | `S0ZyYe9JJypNRRSY` / `m0m7k00gi0M86156` |
| `LOGIN_ID` / `LOGIN_CODE` | `8EE5C3CDF` / `2416` |

响应字段名用的是你后台的混淆名（`f891012a…`=code 等），校验位 `wbc0a389…` 必须等于 `05b7c29c…`。

## 运行逻辑

- 启动时：本地票据未过期 → 直接放行；否则弹全屏卡密框
- 登录：组装 `id/kami/markcode/t/sign/value` → RC4-hex → POST `https://wy.llua.cn/v2/<token>`
- 响应：纯 hex 自动 RC4 解密，明文 JSON 直接解析
- 成功：写入票据 + 到期时间，收起窗口
- 每 30 分钟静默复查，失败清票据并重新弹框
- 网络异常一律不放行

## 设备码说明

`markcode` 用 `identifierForVendor`，**卸载重装会变**，微验会当成换设备（可能触发换绑）。
要稳定绑定，把 `WYMarkCode()` 换成读取设备 UDID 即可。
