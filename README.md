# HyperPasskey Sync Fix

本项目主要针对旧款小米和 REDMI 机型移植新版 HyperOS 后的兼容问题。移植包带来的新版云服务如果无法调用设备保留的旧 KeyBag HAL／TEE 接口，开启「同步此设备」时可能提示「服务器繁忙」，导致小米原生通行密钥无法正常云同步。

模块使用 LSPosed API 102，通过小米旧版云空间恢复原生通行密钥的自动双向同步，普通密码继续走原厂同步流程。

An LSPosed fix for Xiaomi's native passkey cloud sync on older devices ported to newer HyperOS builds that still use a legacy KeyBag HAL and trusted application. Tested on Redmi Note 12 Turbo (`marble`).

## 当前兼容范围

| 机型 | 固件 | 验证范围 |
| --- | --- | --- |
| Redmi Note 12 Turbo（`marble`） | `OS4.0.6.0.XPCCNXM` 江南移植包 | 实机验证自动上传、恢复、恢复后网页验签、双向软删除，以及从「最近删除」恢复 |

云端恢复测试通过移除同一台设备上的测试副本完成。模块在 `marble` 上按各进程所需的 Hook 点和反射接口判断兼容性。同一机型可以尝试不同固件和 APK 版本。如果接口变动导致安装失败，该进程的模块 Hook 会保持停用。其他机型需要单独适配 KeyBag 和 FIDO 服务。

旧版 Xiaomi MasterKey 必须已经恢复到系统并写入 TEE。同步前，模块会确认系统安装版本、TEE 版本和旧云空间版本三者相同。旧密钥的初次恢复和 TEE 导入需要原厂流程处理。云端删除使用旧服务的软删除语义。

本地扫描只读取待处理的记录。若创建请求已到达云端、设备却没收到确认，模块会在下次同步时核对创建时的显示信息，再决定保留哪一端的改名。两端都有不同修改且无法判断先后时，会保留两端的数据，并在同步日志的 `conflicts` 中计数。

## 使用

1. 从 [Releases](https://github.com/JoyElliot/HyperPasskeySyncFix/releases) 下载并安装 APK。
2. 在支持 API 102 的 LSPosed 中启用模块，选择 `com.miui.cloudservice` 和 `com.miui.passwords` 作为作用域。
3. 重启这两个作用域应用，打开系统密码管理中的「同步此设备」。本机变更会请求系统同步，云端变更由系统后台任务拉取。

模块调用原厂签名的 FIDO 服务封装和导入凭据，并复用小米原厂账号认证发出云请求。系统 APK、HAL 和 TEE 固件继续由设备上的原厂签名组件提供。

## 构建

准备 JDK 17 或更高版本、Android SDK Platform 37.0 和 Build Tools 36.0.0。模块以 Android 17（API 37）为目标，最低安装版本为 Android 14（API 34）。配置 `ANDROID_HOME`，或在 Android Studio 中指定 SDK 路径。

```sh
./gradlew :app:assembleDebug
```

在 Windows 上用 `gradlew.bat :app:assembleDebug`。产物位于 `app/build/outputs/apk/debug/app-debug.apk`，使用本机调试签名。覆盖已安装的发布版需要匹配原 APK 的签名。

模块编译依赖由框架提供的 [libxposed API 102](https://github.com/libxposed/api)。项目使用 [Apache License 2.0](LICENSE)。
