package com.nearshare.guard.handshake

import com.nearshare.guard.crypto.SymmetricCrypto
import com.nearshare.guard.model.IdentityBundle
import com.nearshare.guard.model.TrustTier

/**
 * 握手成功后的会话结果。
 *
 * @property sessionKey 双向认证后派生出的 32 字节会话主密钥
 * @property transcriptHash 完整握手转录（M1||M2||M3）的哈希，用于通道绑定
 * @property peerIdentity 对端长期身份；陌生人通道为 null（对端不揭示长期身份）
 * @property trustTier 最终信任层级
 * @property peerDisplayName 对端在本机目录中的显示名；陌生人为对端自报的临时别名
 * @property authenticated 是否为双向认证通道（false 表示陌生人临时通道，存在 MITM 可能）
 */
data class HandshakeResult(
    val sessionKey: ByteArray,
    val transcriptHash: ByteArray,
    val peerIdentity: IdentityBundle?,
    val trustTier: TrustTier,
    val peerDisplayName: String,
    val authenticated: Boolean
) {
    /**
     * 派生 Wi-Fi Direct 网络凭据（SSID 片段 + WPA2 通行短语）。
     * 凭据由双方共享密钥独立算出，无需在网络上传输，防止带外劫持。
     */
    fun wifiCredentials(): WifiCredentials {
        val ssidMaterial = SymmetricCrypto.hkdf(
            ikm = sessionKey,
            info = com.nearshare.guard.discovery.ProtocolDomains.WIFI_CREDENTIAL + "SSID".toByteArray(),
            length = 16
        )
        val passMaterial = SymmetricCrypto.hkdf(
            ikm = sessionKey,
            info = com.nearshare.guard.discovery.ProtocolDomains.WIFI_CREDENTIAL + "PASS".toByteArray(),
            length = 32
        )
        return WifiCredentials(
            ssid = "NSG-" + ssidMaterial.joinToString("") { "%02x".format(it) }.take(16),
            passphrase = passMaterial.joinToString("") { "%02x".format(it) }
        )
    }

    override fun equals(other: Any?): Boolean =
        other is HandshakeResult && sessionKey.contentEquals(other.sessionKey) &&
            transcriptHash.contentEquals(other.transcriptHash) && trustTier == other.trustTier

    override fun hashCode(): Int =
        31 * sessionKey.contentHashCode() + trustTier.hashCode()
}

data class WifiCredentials(val ssid: String, val passphrase: String)
