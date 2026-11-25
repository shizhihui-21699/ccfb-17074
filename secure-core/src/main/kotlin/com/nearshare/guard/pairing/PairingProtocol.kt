package com.nearshare.guard.pairing

import com.nearshare.guard.crypto.AsymmetricCrypto
import com.nearshare.guard.crypto.SymmetricCrypto
import com.nearshare.guard.discovery.ProtocolDomains
import com.nearshare.guard.model.ContactRecord
import com.nearshare.guard.model.IdentityBundle
import com.nearshare.guard.model.LocalIdentity
import com.nearshare.guard.model.TrustTier
import kotlinx.serialization.Serializable

/**
 * 二维码载荷（由发起方屏幕展示，响应方面对面扫码）。
 *
 * 物理扫码通道本身保证：载荷来自用户面前的真实设备，攻击者无法在地铁里
 * 远程注入。载荷不经过任何服务器，全程离线。
 */
@Serializable
data class PairingQrPayload(
    val version: Byte = ProtocolDomains.VERSION,
    val identityPublicKey: ByteArray,
    val staticPublicKey: ByteArray,
    val ephemeralPublicKey: ByteArray,
    val nonce: ByteArray,
    val displayName: String
) {
    override fun equals(other: Any?): Boolean =
        other is PairingQrPayload && version == other.version &&
            identityPublicKey.contentEquals(other.identityPublicKey) &&
            staticPublicKey.contentEquals(other.staticPublicKey) &&
            ephemeralPublicKey.contentEquals(other.ephemeralPublicKey) &&
            nonce.contentEquals(other.nonce) && displayName == other.displayName

    override fun hashCode(): Int {
        var r = version.toInt()
        r = 31 * r + identityPublicKey.contentHashCode()
        r = 31 * r + staticPublicKey.contentHashCode()
        r = 31 * r + ephemeralPublicKey.contentHashCode()
        r = 31 * r + nonce.contentHashCode()
        r = 31 * r + displayName.hashCode()
        return r
    }
}

/**
 * 配对完成后双方各自存储的记录（对端身份 + 成对 PSK）。
 */
data class PairingResult(
    val contactRecord: ContactRecord,
    val sas: String
)

/**
 * 离线配对协议（面对面扫码 + 短认证码 SAS 人工确认）。
 *
 * 流程：
 * 1. A 生成临时 X25519 密钥，把 [PairingQrPayload] 编成二维码展示；
 * 2. B 扫码后生成自己的临时密钥，与 A 做 ECDH；
 * 3. 双方由 ECDH 结果 + 双 nonce 经 HKDF 派生同一个 32B PSK；
 * 4. 双方各自显示 6 位 SAS（十进制短认证码），用户目视确认两机一致；
 * 5. 确认通过后，双方写入 [ContactRecord]，后续发现/握手都用该 PSK。
 *
 * SAS 绑定 ECDH 转录：若有人在交换临时公钥时做中间人，两端 SAS 必然不同，
 * 用户当场即可发现并取消。
 */
class PairingProtocol(
    private val localIdentity: LocalIdentity,
    private val displayName: String
) {

    private val ephemeral = AsymmetricCrypto.generateX25519KeyPair()
    private val nonce = SymmetricCrypto.randomBytes(16)

    // ---------------- 发起方（展示二维码） ----------------

    fun buildQrPayload(): PairingQrPayload = PairingQrPayload(
        identityPublicKey = localIdentity.identityPublicKey,
        staticPublicKey = localIdentity.keyExchangePublicKey,
        ephemeralPublicKey = ephemeral.publicKey,
        nonce = nonce,
        displayName = displayName
    )

    /**
     * 扫到对端回执后完成发起方侧计算。
     * @param peerResponse 对端（扫码方）的配对回执
     */
    fun completeInitiator(
        peerResponse: PairingResponse,
        peerDisplayName: String,
        tier: TrustTier = TrustTier.CONTACT
    ): PairingResult {
        val shared = AsymmetricCrypto.x25519Agree(ephemeral.privateKey, peerResponse.ephemeralPublicKey)
        val psk = derivePairingPsk(shared, nonce, peerResponse.nonce)
        val sas = computeSas(psk)
        verifySasBinding(psk, peerResponse, expectedIsInitiator = true)
        val record = ContactRecord(
            contactId = idOf(peerResponse.identityPublicKey),
            displayName = peerDisplayName,
            identityPublicKey = peerResponse.identityPublicKey,
            psk = psk,
            tier = tier
        )
        return PairingResult(record, sas)
    }

    // ---------------- 响应方（扫码方） ----------------

    /**
     * 扫描二维码后生成回执，并直接算出本机侧配对结果。
     * @param userConfirmedSas 用户已在本机确认 SAS 与对端屏幕一致
     */
    fun respondToQr(
        qr: PairingQrPayload,
        userConfirmedSas: Boolean,
        tier: TrustTier = TrustTier.CONTACT
    ): PairingExchange {
        require(qr.version == ProtocolDomains.VERSION) { "配对载荷版本不兼容" }
        val responderEphemeral = AsymmetricCrypto.generateX25519KeyPair()
        val responderNonce = SymmetricCrypto.randomBytes(16)
        val shared = AsymmetricCrypto.x25519Agree(responderEphemeral.privateKey, qr.ephemeralPublicKey)
        val psk = derivePairingPsk(shared, qr.nonce, responderNonce)
        val sas = computeSas(psk)
        check(userConfirmedSas) { "用户未确认 SAS，配对中止" }

        val response = PairingResponse(
            identityPublicKey = localIdentity.identityPublicKey,
            ephemeralPublicKey = responderEphemeral.publicKey,
            nonce = responderNonce,
            sasBinding = SymmetricCrypto.hmacSha256(psk, "sas-ack-responder".toByteArray())
        )
        val record = ContactRecord(
            contactId = idOf(qr.identityPublicKey),
            displayName = qr.displayName,
            identityPublicKey = qr.identityPublicKey,
            psk = psk,
            tier = tier
        )
        return PairingExchange(response, PairingResult(record, sas))
    }

    private fun verifySasBinding(psk: ByteArray, response: PairingResponse, expectedIsInitiator: Boolean) {
        val expected = SymmetricCrypto.hmacSha256(psk, "sas-ack-responder".toByteArray())
        if (!SymmetricCrypto.constantTimeEquals(expected, response.sasBinding)) {
            throw PairingException("配对回执校验失败：PSK 不一致或数据被篡改")
        }
    }

    companion object {
        fun derivePairingPsk(ecdh: ByteArray, nonceA: ByteArray, nonceB: ByteArray): ByteArray =
            SymmetricCrypto.hkdf(
                ikm = ecdh,
                info = "NearShareGuard/PairingPSK/V1".toByteArray() + nonceA + nonceB,
                length = SymmetricCrypto.AEAD_KEY_SIZE
            )

        /**
         * 6 位十进制短认证码。取自 PSK 派生摘要的前 20 bit，
         * 中间人猜中的概率 ≤ 1/1_000_000，且每次配对的 PSK 独立。
         */
        fun computeSas(psk: ByteArray): String {
            val digest = SymmetricCrypto.hkdf(
                ikm = psk,
                info = "NearShareGuard/SAS/V1".toByteArray(),
                length = 8
            )
            val value = ((digest[0].toLong() and 0xFF) shl 16) or
                ((digest[1].toLong() and 0xFF) shl 8) or
                (digest[2].toLong() and 0xFF)
            return "%06d".format(value % 1_000_000L)
        }

        fun idOf(identityPublicKey: ByteArray): String =
            identityPublicKey.joinToString("") { "%02x".format(it) }.take(16)
    }
}

@Serializable
data class PairingResponse(
    val identityPublicKey: ByteArray,
    val ephemeralPublicKey: ByteArray,
    val nonce: ByteArray,
    val sasBinding: ByteArray
) {
    override fun equals(other: Any?): Boolean =
        other is PairingResponse && identityPublicKey.contentEquals(other.identityPublicKey) &&
            ephemeralPublicKey.contentEquals(other.ephemeralPublicKey) &&
            nonce.contentEquals(other.nonce) && sasBinding.contentEquals(other.sasBinding)

    override fun hashCode(): Int {
        var r = identityPublicKey.contentHashCode()
        r = 31 * r + ephemeralPublicKey.contentHashCode()
        r = 31 * r + nonce.contentHashCode()
        r = 31 * r + sasBinding.contentHashCode()
        return r
    }
}

data class PairingExchange(val response: PairingResponse, val result: PairingResult)

class PairingException(message: String) : Exception(message)

/**
 * 同账号设备的预置入口。
 *
 * 真实系统中，账号服务在设备登录时通过端到端加密通道（仅这一步需要联网一次）
 * 下发每台设备的身份公钥与账号配对主密钥；之后所有近场验证完全离线。
 * 这里以可注入的抽象表示，便于测试与替换。
 */
fun interface AccountProvisioning {
    /** 返回同账号其它设备的可信记录（身份公钥 + 派生 PSK）。 */
    fun provisionSameAccountDevices(localIdentity: LocalIdentity): List<ContactRecord>
}

/**
 * 测试/演示用实现：给定账号主密钥与对端身份，确定性派生同账号 PSK。
 * 生产环境中主密钥应由账号服务经 E2EE 通道分别下发，从不在近场链路出现。
 */
class LocalAccountProvisioning(
    private val accountMasterKey: ByteArray,
    private val peerBundles: List<Pair<IdentityBundle, String>>
) : AccountProvisioning {

    override fun provisionSameAccountDevices(localIdentity: LocalIdentity): List<ContactRecord> =
        peerBundles.map { (bundle, name) ->
            // 两个身份公钥按字典序规范化排列，保证任意一方派生出完全相同的 PSK
            val ordered = listOf(localIdentity.identityPublicKey, bundle.identityPublicKey)
                .sortedWith(::lexicographicCompare)
            val psk = SymmetricCrypto.hkdf(
                ikm = accountMasterKey,
                info = "NearShareGuard/AccountPSK/V1".toByteArray() +
                    ordered[0] + ordered[1],
                length = SymmetricCrypto.AEAD_KEY_SIZE
            )
            ContactRecord(
                contactId = PairingProtocol.idOf(bundle.identityPublicKey),
                displayName = name,
                identityPublicKey = bundle.identityPublicKey,
                psk = psk,
                tier = TrustTier.SAME_ACCOUNT
            )
        }

    private fun lexicographicCompare(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val d = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return a.size - b.size
    }
}
