# Android 集成指南

`secure-core` 是纯 JVM 库，不依赖 Android API；`android-integration`
定义了需要由系统应用实现的平台接口。本指南说明各接口的落地方式。

## 1. 模块接线

真实系统工程中新增一个 `com.android.library`（或直接放在系统应用内），
依赖 `secure-core`，实现下列接口并通过构造注入：

| 平台接口 | Android 落地建议 |
|---------|-----------------|
| `IdentityVault` | Android Keystore，优先 StrongBox；不支持 X25519/Ed25519 时用加密存储 + 硬件认证 |
| `ContactSource` | Room 存储配对记录（`EncryptedSharedPreferences` 或 SQLCipher） |
| `AccountSource` | 账号服务 E2EE 通道，有网时同步一次同账号设备清单 |
| `BluetoothLeStack` | `BluetoothLeAdvertiser` + `BluetoothLeScanner`，强制 RPA |
| `WifiDirectStack` | `WifiP2pManager`，凭据由 `HandshakeResult.wifiCredentials()` 派生 |
| `PlatformTransportAdapter` | GATT 通知/写特征 或 P2P socket，桥接成 `SecureTransport` |

## 2. BLE 发现的隐私落地要点

1. **广播载荷**只放 `DiscoveryWire.encode()` 的字节，绝不塞设备名/自定义稳定 ID；
2. 广告模式使用可解析私有地址（RPA），地址轮换周期与 `newAdvertisement()`
   的临时密钥周期对齐（建议 8–10 分钟）；
3. 广播包超过 31 字节时改用扫描响应（Scan Response），或压缩 Bloom
   位图（联系人很多时分片/降误报率参数）；
4. 对畸形广播直接丢弃、不弹窗，避免广播洪泛造成通知骚扰。

## 3. 接收侧数据流（对应 `ReceiveCoordinator`）

```
BLE 扫描回调
  → ReceiveCoordinator.onAdvertisement(bytes)
      ├─ Malformed        → 忽略
      ├─ Stranger         → 进入陌生人流程，默认静默不主动通知
      └─ KnownCandidate   → 建立 GATT 连接
  → performHandshake(transport, match)
      → HandshakeResult（含 TrustTier、是否认证、显示名）
  → Wi-Fi Direct 用派生凭据建组 → SecureChannel
  → FileReceiveSession.receiveBatch()
      → 魔数嗅探 + ReceivePolicy → IncomingFileCard
```

## 4. UI 渲染规则（`IncomingFileCard`）

- `showVerifiedBadge=true` 才显示"已认证熟人/同账号"徽章；陌生人永不显示；
- `previewMode=BLURRED` 时用模糊缩略图（如 RenderEffect 模糊），点击
  "仍要查看"才揭开，且记录一次用户确认事件；
- `blocked=true` 时只展示拦截原因，不提供"强行接收"入口；
- `quarantined=true` 的文件写入隔离目录（无 MediaStore 可见性、
  不关联打开方式），用户手动确认前不允许调起安装器/浏览器；
- 可执行文件的二次确认对话框必须展示**真实嗅探类型**与声明扩展名的差异。

## 5. 权限与系统能力清单

```
BLUETOOTH_SCAN / BLUETOOTH_ADVERTISE / BLUETOOTH_CONNECT
NEARBY_WIFI_DEVICES
ACCESS_FINE_LOCATION（旧版 BLE 扫描需要，应配合运行时说明）
POST_NOTIFICATIONS（接收提醒）
```

## 6. 防止被现有代码路径绕过

系统改造的关键不是新增一条安全路径，而是**让旧的"按设备名信任"路径失效**：

1. 快传入口统一收口到 `ReceiveCoordinator`，删除任何直接用
   `BluetoothDevice.name` 作为信任/展示依据的代码；
2. 文件落盘统一经过 `FileReceiveSession`，禁止其他路径直接写公共目录；
3. 安装意图（`ACTION_INSTALL_PACKAGE` / PackageInstaller）前强制校验
   该文件存在一条 `allowed=true` 的接收记录，否则拒绝。

## 7. 测试策略

- 密码学、协议、策略全部在 `secure-core` 用 JVM 单测覆盖（52 个），
  可在无设备/无网络的 CI 上运行；
- Android 实现层再补充插桩测试：BLE 广播字节断言（不含稳定 ID）、
- Keystore 密钥不可导出性、隔离目录不可被其他应用访问等平台属性。
