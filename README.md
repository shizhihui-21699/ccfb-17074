# 近场快传安全改造（NearShare Guard）

针对系统自带"蓝牙发现 + Wi-Fi Direct 传文件"近场快传功能的安全改造。
解决两类真实社工攻击：

1. **设备名仿冒**：攻击者在地铁里把设备名改成受害者通讯录联系人的名字，
   诱导接收方误以为是熟人而接收文件；
2. **内容伪装**：推送不雅图片，或把恶意 APK/可执行文件改名为 `合同.pdf`
   诱导点击安装。

## 核心目标

| 需求 | 实现方式 |
|------|---------|
| 发送方身份可验证 | 长期 Ed25519 身份密钥 + 配对 PSK 绑定的认证握手，设备名不参与信任决策 |
| 区分熟人 / 同账号 / 陌生人 | 三档 `TrustTier`，由本机离线目录中的身份公钥与 PSK 决定 |
| 陌生人模糊预览 | 图片仅模糊缩略图，需主动揭开；非图片不生成预览 |
| 限制可执行文件 | 基于内容魔数（非扩展名）嗅探，陌生人的可执行文件一律拦截 |
| 完全离线 | 所有验证材料在配对阶段已存本机，握手/传输不访问任何服务器 |
| 发现阶段防追踪 | BLE 广播只含轮换临时公钥 + Bloom 过滤器，无稳定身份标识 |

## 模块结构

```
secure-core/           纯 JVM 安全核心，可离线单测（55 个测试中的 52 个）
  crypto/              X25519、Ed25519、HKDF、HMAC、ChaCha20-Poly1305（BouncyCastle）
  discovery/           私有集合匹配（Bloom + HMAC 标签）、广播编解码
  pairing/             面对面扫码配对 + SAS 短认证码、同账号预置
  handshake/           M1/M2/M3 双向认证握手、认证信封、会话密钥派生
  transport/           SecureTransport 抽象、加密通道（防重放、通道绑定）
  files/               魔数嗅探、伪装检测、三档接收策略、清单与流式校验
  directory/           本机可信联系人目录
  model/               身份与信任模型
android-integration/   平台适配骨架（BLE/Wi-Fi Direct/通讯录/UI 接口 + 编排器）
```

设计原则：**所有密码学与策略逻辑都在可离线单测的 `secure-core`，
Android 侧只做薄适配**，不把安全判断散落在 Activity/Service 里。

## 构建与测试

需要 JDK 17（本机为 Homebrew `openjdk@17`），依赖全部已在 Gradle 缓存，离线可构建：

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
./gradlew test --offline
```

## 文档

- [威胁模型与安全论证](docs/THREAT_MODEL.md)
- [协议规格](docs/PROTOCOL.md)
- [Android 集成指南](docs/ANDROID_INTEGRATION.md)
