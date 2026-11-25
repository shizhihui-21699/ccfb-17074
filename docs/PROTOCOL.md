# 协议规格

所有密码学算法基于 BouncyCastle 实现，参数固定：

| 用途 | 算法 | 参数 |
|------|------|------|
| 身份签名 | Ed25519 | 公钥/私钥 32B，签名 64B |
| 密钥协商 | X25519 ECDH | 公钥/私钥 32B，共享秘密 32B |
| 密钥派生 | HKDF-SHA256 (RFC 5869) | 输出 32B |
| 标签/MAC | HMAC-SHA256 | 32B |
| 认证加密 | ChaCha20-Poly1305 (RFC 8439) | key 32B，nonce 12B，tag 16B |
| 哈希 | SHA-256 | 32B |

每个协议阶段使用独立 `info` 域分隔字符串（见 `ProtocolDomains`），
禁止跨阶段复用密钥。

## 1. 离线配对（仅一次，面对面）

```
A（展示二维码）                         B（扫码）
  │  生成临时 X25519 eA、nonceA          │
  │  ── QR(身份公钥, 静态公钥, eA, nonceA, 名字) ──▶│
  │                                     │ 生成 eB、nonceB
  │                                     │ ECDH → shared
  │  ◀── Response(身份公钥, eB, nonceB, HMAC(PSK,"sas-ack")) ──│
  │  ECDH → shared                       │
  │  PSK = HKDF(shared, nonceA‖nonceB)   │ PSK（相同）
  │  SAS = 6 位十进制                    │ SAS（相同）
  │  ◀────── 用户目视核对两机 SAS 一致 ──────▶│
```

- 二维码走物理光学通道，攻击者无法远程注入；
- SAS 绑定 ECDH 转录，MITM 会导致两端 SAS 不同；
- 完成后双方各存 `ContactRecord(对端身份公钥, PSK, 层级)`。

## 2. 隐私发现（每个广播周期轮换）

发送方 S 为每个广播周期生成临时 X25519 密钥 `eS`，对目录中每个联系人 i：

```
tag_i = HMAC-SHA256(PSK_i, "DiscoveryTag/V1" ‖ eS)
```

所有 `tag_i` 插入 Bloom 过滤器，广播线上明文仅含：

```
DiscoveryWire = 版本 ‖ eS(32B) ‖ Bloom位图 ‖ 哈希函数数
```

接收方 R 用自己目录中每条记录的 PSK 独立计算标签并探测 Bloom：
- 命中 → 候选熟人（极小概率误报，握手验签兜底）；
- 未命中 → 陌生人。

**隐私属性**

- 广播中没有身份公钥、名字、MAC 之外的稳定 ID（MAC 层用 BLE RPA）；
- `eS` 每 ~10 分钟轮换 → 所有标签随之变化 → 无法跨周期关联同一设备；
- 无 PSK 的观察者既不能生成有效标签，也不能从 Bloom 反推联系人。

## 3. 认证握手（M1/M2/M3）

```
发起方 I                                 响应方 R
 │ eI = 临时 X25519                       │
 │ ── M1: ver ‖ eI ─────────────────────▶│
 │                                       │ eR = 临时 X25519
 │                                       │ ECDH(eR_priv, eI)
 │ ◀── M2: ver ‖ eR ‖ [envelope_R] ──────│
 │ ECDH(eI_priv, eR)                     │
 │ ── M3: ver ‖ [envelope_I] ───────────▶│
```

信封（仅当发现阶段匹配到 PSK 时存在）：

```
envelopeKey = HKDF(PSK, "EnvelopeKey/V1" ‖ eI ‖ eR)
plaintext   = TLV(身份公钥, 静态公钥, 显示名, Ed25519签名(当前转录))
envelope    = AEAD_Seal(envelopeKey, nonce, plaintext, AAD=当前转录)
```

- **PSK 错误 → AEAD 解密失败**，陌生人拿不到任何身份明文；
- 信封内身份公钥必须与目录记录逐字节相等，否则拒绝；
- Ed25519 签名覆盖握手转录，替换 `eI/eR` 的 MITM 验签失败；
- 陌生人无 PSK → 不带信封，双方不揭示长期身份，结果标记
  `authenticated=false, STRANGER`。

会话密钥（双方独立算出、永不传输）：

```
sessionKey = HKDF(ECDH ‖ PSK?, "SessionKey/V1" ‖ eI ‖ eR)
```

## 4. Wi-Fi Direct 凭据派生（不传凭据）

```
SSID = "NSG-" ‖ HKDF(sessionKey, "WifiCredential/V1"‖"SSID")
PASS =        HKDF(sessionKey, "WifiCredential/V1"‖"PASS") 的 hex
```

双方各自从会话密钥派生相同凭据，网络上不出现明文热点口令，
带外监听者无法劫持该 P2P 群组。

## 5. 加密传输通道

- 发送/接收方向用不同 HKDF 子密钥（`initiator` / `responder` 标签），防反射；
- 每条消息 nonce = 计数器（低 64 位），单会话内严格单调，杜绝 nonce 复用；
- AAD = 握手转录哈希 ‖ 计数器，实现通道与握手绑定 + 防重放；
- 线上帧 = nonce ‖ ChaCha20密文 ‖ Poly1305标签。

## 6. 文件接收策略

```
发送方 → 加密通道 → FileManifest(文件名, 大小, SHA256, 声明MIME)
发送方 → 16B 文件头
接收方：魔数嗅探 →（ZIP 时再查 APK 特征）→ 三档 ReceivePolicy
       ├─ 拒绝：回 RejectNotice 并终止，文件内容不落盘
       └─ 同意：回 AcceptNotice，再流式接收并校验 SHA256
```

类型判定**只信内容魔数**，文件名扩展名仅用于检测"伪装不一致"，
不作为类型依据。
