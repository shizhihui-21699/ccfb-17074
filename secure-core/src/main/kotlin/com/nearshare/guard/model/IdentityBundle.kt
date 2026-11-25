package com.nearshare.guard.model

import kotlinx.serialization.Serializable

/**
 * 一台设备的长期身份。
 *
 * - [identityPublicKey]：Ed25519 签名验证公钥，是设备身份的唯一稳定标识
 * - [keyExchangePublicKey]：X25519 静态公钥，仅用于配对信封封装，不参与发现广播
 *
 * 长期身份密钥绝不出现在 BLE 广播中；只在加密握手信封里、对已匹配的对端揭示。
 */
@Serializable
data class IdentityBundle(
    val identityPublicKey: ByteArray,
    val keyExchangePublicKey: ByteArray
) {
    override fun equals(other: Any?): Boolean =
        other is IdentityBundle &&
            identityPublicKey.contentEquals(other.identityPublicKey) &&
            keyExchangePublicKey.contentEquals(other.keyExchangePublicKey)

    override fun hashCode(): Int =
        31 * identityPublicKey.contentHashCode() + keyExchangePublicKey.contentHashCode()
}

/**
 * 本机持有的完整身份（含私钥）。私钥在 Android 上应由 Keystore/StrongBox 托管，
 * 这里的内存形态仅用于纯 JVM 核心模块的测试与协议实现。
 */
data class LocalIdentity(
    val identityPublicKey: ByteArray,
    val identityPrivateKey: ByteArray,
    val keyExchangePublicKey: ByteArray,
    val keyExchangePrivateKey: ByteArray
) {
    fun publicBundle(): IdentityBundle =
        IdentityBundle(identityPublicKey, keyExchangePublicKey)
}
