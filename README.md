# HyperPasskey Sync Fix

本项目主要针对旧款小米和 REDMI 机型移植新版 HyperOS 后的兼容问题。移植包带来的新版云服务如果无法调用设备保留的旧 KeyBag HAL／TEE 接口，开启「同步此设备」时可能提示「服务器繁忙」，导致小米原生通行密钥无法正常云同步。

模块使用 LSPosed API 102，通过小米旧版云空间恢复原生通行密钥的自动双向同步，普通密码继续走原厂同步流程。

An LSPosed fix for Xiaomi's native passkey cloud sync on older devices ported to newer HyperOS builds that still use a legacy KeyBag HAL and trusted application. Tested on Redmi Note 12 Turbo (`marble`).

## 当前兼容范围

| 机型 | 固件 | 验证范围 |
| --- | --- | --- |
| Redmi Note 12 Turbo（`marble`） | `OS4.0.6.0.XPCCNXM` 移植包，目标 APK 与源码中的 SHA-256 一致 | 实机验证自动上传、恢复、恢复后网页验签、双向软删除，以及从「最近删除」恢复 |

REDMI Note 12 Turbo（`marble`）上的上述组合已通过实机测试。云端恢复测试通过移除同一台设备上的测试副本完成。其他旧机型的移植包可能遇到同样的接口失配，实际适配需单独核对。目前模块会校验机型、固件版本和两个目标 APK 的 SHA-256。

旧版 Xiaomi MasterKey 必须已经恢复到系统并写入 TEE。同步前，模块会确认系统安装版本、TEE 版本和旧云空间版本三者相同。旧密钥的初次恢复和 TEE 导入需要原厂流程处理。云端删除使用旧服务的软删除语义。

## 使用

1. 从 [Releases](https://github.com/JoyElliot/HyperPasskeySyncFix/releases) 下载并安装 APK。
2. 在支持 API 102 的 LSPosed 中启用模块，选择 `com.miui.cloudservice` 和 `com.miui.passwords` 作为作用域。
3. 重启这两个作用域应用，打开系统密码管理中的「同步此设备」。本机变更会请求系统同步，云端变更由系统后台任务拉取。

模块调用原厂签名的 FIDO 服务封装和导入凭据，并复用小米原厂账号认证发出云请求。系统 APK、HAL 和 TEE 固件继续由设备上的原厂签名组件提供。

## 构建

准备 JDK 17 或更高版本、Android SDK Platform 36 和 Build Tools 36.0.0。配置 `ANDROID_HOME`，或在 Android Studio 中指定 SDK 路径。

```sh
./gradlew :app:assembleDebug
```

在 Windows 上用 `gradlew.bat :app:assembleDebug`。产物位于 `app/build/outputs/apk/debug/app-debug.apk`，使用本机调试签名。覆盖已安装的发布版需要匹配原 APK 的签名。

模块编译依赖由框架提供的 [libxposed API 102](https://github.com/libxposed/api)。项目使用 [Apache License 2.0](LICENSE)。
