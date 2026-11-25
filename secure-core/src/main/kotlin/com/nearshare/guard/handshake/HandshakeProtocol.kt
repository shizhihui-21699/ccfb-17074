package com.nearshare.guard.handshake

import com.nearshare.guard.codec.Tlv
import com.nearshare.guard.crypto.AeadVerificationException
import com.nearshare.guard.crypto.AsymmetricCrypto
import com.nearshare.guard.crypto.SymmetricCrypto
import com.nearshare.guard.crypto.X25519KeyPair
import com.nearshare.guard.directory.ContactDirectory
import com.nearshare.guard.discovery.ProtocolDomains
import com.nearshare.guard.model.ContactRecord
import com.nearshare.guard.model.IdentityBundle
import com.nearshare.guard.model.LocalIdentity
import com.nearshare.guard.model.TrustTier
import com.nearshare.guard.transport.SecureTransport
import java.security.SecureRandom

/**
 * 无服务器、离线可用的双向认证握手。
 *
 * 三条消息（类似 Noise XX，但认证凭据改为配对 PSK + 身份签名）：
 *
 *   M1 (发起方 → 响应方): 版本 || e_i 临时 X25519 公钥
 *   M2 (响应方 → 发起方): 版本 || e_r 临时公钥 || sealedEnvelope(匹配时)
 *   M3 (发起方 → 响应方): 版本 || sealedEnvelope(匹配时)
 *
 * 信封（仅在发现阶段匹配到 PSK 时存在）：
 *   envelopeKey = HKDF(PSK, "EnvelopeKey" || e_i || e_r)
 *   plaintext   = 身份公钥 || 静态 X25519 公钥 || 自报名 || Sig_identity(当前转录)
 *   envelope    = AEAD_Seal(envelopeKey, nonce, plaintext, aad = 当前转录)
 *
 * 转录约定：签名与 AEAD 的 AAD 一律使用**裸载荷**（不含长度前缀帧头），
 * 保证两端字节完全一致。传输层的 u16 长度帧仅用于分包重组，不参与密码学计算。
 *
 * 安全属性：
 * - PSK 错误 → AEAD 解密必然失败，陌生人/攻击者拿不到任何身份明文；
 * - 身份签名绑定握手转录，替换临时公钥的中间人攻击会导致验签失败；
 * - 陌生人没有 PSK，双方走无信封临时通道，不揭示长期身份，UI 标记为未认证。
 */
class HandshakeProtocol(
    private val localIdentity: LocalIdentity,
    private val displayName: String,
    private val rng: SecureRandom = SecureRandom()
) {

    // ---------------- 发起方（发送文件的一方） ----------------

    /**
     * @param matchedPeer 发现阶段命中的联系人；null 表示对方是陌生人
     */
    fun initiate(
        transport: SecureTransport,
        matchedPeer: ContactRecord?
    ): HandshakeResult {
        val ephemeral = AsymmetricCrypto.generateX25519KeyPair()

        // ---- M1 ----
        val m1 = Tlv.encode(
            TLV_VERSION to byteArrayOf(ProtocolDomains.VERSION),
            TLV_EPHEMERAL to ephemeral.publicKey
        )
        transport.sendFrame(m1)

        // ---- M2 ----
        val m2 = transport.receiveFrame() ?: throw HandshakeException("等待 M2 时连接关闭")
        val m2Fields = Tlv.decode(m2)
        requireVersion(m2Fields)
        val peerEphemeral = m2Fields[TLV_EPHEMERAL]
            ?: throw HandshakeException("M2 缺少临时公钥")
        val peerEnvelopeM2 = m2Fields[TLV_ENVELOPE]

        val ecdhSecret = AsymmetricCrypto.x25519Agree(ephemeral.privateKey, peerEphemeral)
        val transcriptAfterM2 = m1 + m2

        val peerInfo = if (peerEnvelopeM2 != null) {
            if (matchedPeer == null) {
                throw HandshakeException("对端发来未授权的身份信封")
            }
            openEnvelope(
                peer = matchedPeer,
                initiatorEphemeral = ephemeral.publicKey,
                responderEphemeral = peerEphemeral,
                sealed = peerEnvelopeM2,
                transcript = m1
            )
        } else null

        // ---- M3 ----
        val m3 = buildM3(
            ephemeral = ephemeral,
            peerEphemeral = peerEphemeral,
            matchedPeer = matchedPeer,
            transcript = transcriptAfterM2
        )
        transport.sendFrame(m3)

        val fullTranscript = SymmetricCrypto.sha256(m1 + m2 + m3)
        val sessionKey = deriveSessionKey(ecdhSecret, matchedPeer?.psk, ephemeral.publicKey, peerEphemeral)

        return buildResult(sessionKey, fullTranscript, peerInfo, matchedPeer)
    }

    // ---------------- 响应方（接收文件的一方） ----------------

    /**
     * @param match 发现阶段在本机目录中匹配到的联系人；null 表示陌生人
     */
    fun respond(
        transport: SecureTransport,
        directory: ContactDirectory,
        match: ContactRecord?
    ): HandshakeResult {
        // ---- M1 ----
        val m1 = transport.receiveFrame() ?: throw HandshakeException("等待 M1 时连接关闭")
        val m1Fields = Tlv.decode(m1)
        requireVersion(m1Fields)
        val peerEphemeral = m1Fields[TLV_EPHEMERAL]
            ?: throw HandshakeException("M1 缺少临时公钥")

        val ephemeral = AsymmetricCrypto.generateX25519KeyPair()
        val ecdhSecret = AsymmetricCrypto.x25519Agree(ephemeral.privateKey, peerEphemeral)

        // ---- M2 ----
        val m2Builder = mutableListOf(
            TLV_VERSION to byteArrayOf(ProtocolDomains.VERSION),
            TLV_EPHEMERAL to ephemeral.publicKey
        )
        if (match != null) {
            m2Builder.add(
                TLV_ENVELOPE to sealEnvelope(
                    psk = match.psk,
                    initiatorEphemeral = peerEphemeral,
                    responderEphemeral = ephemeral.publicKey,
                    transcript = m1
                )
            )
        }
        val m2 = Tlv.encode(*m2Builder.toTypedArray())
        transport.sendFrame(m2)

        // ---- M3 ----
        val m3 = transport.receiveFrame() ?: throw HandshakeException("等待 M3 时连接关闭")
        val m3Fields = Tlv.decode(m3)
        requireVersion(m3Fields)
        val peerEnvelope = m3Fields[TLV_ENVELOPE]
        val peerInfo = if (peerEnvelope != null) {
            val peer = match ?: throw HandshakeException("对端发来未授权的身份信封")
            openEnvelope(
                peer = peer,
                initiatorEphemeral = peerEphemeral,
                responderEphemeral = ephemeral.publicKey,
                sealed = peerEnvelope,
                transcript = m1 + m2
            )
        } else null

        val fullTranscript = SymmetricCrypto.sha256(m1 + m2 + m3)
        val sessionKey = deriveSessionKey(ecdhSecret, match?.psk, peerEphemeral, ephemeral.publicKey)

        return buildResult(sessionKey, fullTranscript, peerInfo, match)
    }

    // ---------------- 信封与密钥 ----------------

    private fun sealEnvelope(
        psk: ByteArray,
        initiatorEphemeral: ByteArray,
        responderEphemeral: ByteArray,
        transcript: ByteArray
    ): ByteArray {
        val envelopeKey = SymmetricCrypto.hkdf(
            ikm = psk,
            info = ProtocolDomains.ENVELOPE_KEY + initiatorEphemeral + responderEphemeral,
            length = SymmetricCrypto.AEAD_KEY_SIZE
        )
        val identity = localIdentity.publicBundle()
        val signature = AsymmetricCrypto.ed25519Sign(localIdentity.identityPrivateKey, transcript)
        val plaintext = Tlv.encode(
            TLV_IDENTITY_KEY to identity.identityPublicKey,
            TLV_STATIC_KEY to identity.keyExchangePublicKey,
            TLV_DISPLAY_NAME to displayName.toByteArray(Charsets.UTF_8),
            TLV_SIGNATURE to signature
        )
        return SymmetricCrypto.aeadSealWithRandomNonce(envelopeKey, plaintext, aad = transcript)
    }

    private fun openEnvelope(
        peer: ContactRecord,
        initiatorEphemeral: ByteArray,
        responderEphemeral: ByteArray,
        sealed: ByteArray,
        transcript: ByteArray
    ): PeerIdentityInfo {
        val envelopeKey = SymmetricCrypto.hkdf(
            ikm = peer.psk,
            info = ProtocolDomains.ENVELOPE_KEY + initiatorEphemeral + responderEphemeral,
            length = SymmetricCrypto.AEAD_KEY_SIZE
        )
        val plaintext = try {
            SymmetricCrypto.aeadOpenWithRandomNonce(envelopeKey, sealed, aad = transcript)
        } catch (e: AeadVerificationException) {
            throw HandshakeException("身份信封解密失败：PSK 不匹配或数据被篡改")
        }
        val fields = Tlv.decode(plaintext)
        val identityKey = fields[TLV_IDENTITY_KEY]
            ?: throw HandshakeException("信封缺少身份公钥")
        val staticKey = fields[TLV_STATIC_KEY]
            ?: throw HandshakeException("信封缺少静态公钥")
        val name = fields[TLV_DISPLAY_NAME]?.toString(Charsets.UTF_8).orEmpty()
        val signature = fields[TLV_SIGNATURE]
            ?: throw HandshakeException("信封缺少身份签名")

        if (!identityKey.contentEquals(peer.identityPublicKey)) {
            throw HandshakeException("信封身份公钥与目录记录不一致，拒绝连接")
        }
        if (!AsymmetricCrypto.ed25519Verify(identityKey, transcript, signature)) {
            throw HandshakeException("身份签名校验失败：可能遭遇中间人攻击")
        }
        return PeerIdentityInfo(IdentityBundle(identityKey.copyOf(), staticKey.copyOf()), name)
    }

    private fun buildM3(
        ephemeral: X25519KeyPair,
        peerEphemeral: ByteArray,
        matchedPeer: ContactRecord?,
        transcript: ByteArray
    ): ByteArray {
        if (matchedPeer == null) {
            // 陌生人通道：仅回版本标记，不泄露长期身份
            return Tlv.encode(TLV_VERSION to byteArrayOf(ProtocolDomains.VERSION))
        }
        val envelope = sealEnvelope(
            psk = matchedPeer.psk,
            initiatorEphemeral = ephemeral.publicKey,
            responderEphemeral = peerEphemeral,
            transcript = transcript
        )
        return Tlv.encode(
            TLV_VERSION to byteArrayOf(ProtocolDomains.VERSION),
            TLV_ENVELOPE to envelope
        )
    }

    private fun deriveSessionKey(
        ecdhSecret: ByteArray,
        psk: ByteArray?,
        initiatorEphemeral: ByteArray,
        responderEphemeral: ByteArray
    ): ByteArray {
        // PSK 并入 IKM，使会话密钥同时依赖 ECDH 与配对秘密
        val ikm = if (psk != null) ecdhSecret + psk else ecdhSecret
        return SymmetricCrypto.hkdf(
            ikm = ikm,
            info = ProtocolDomains.SESSION_KEY + initiatorEphemeral + responderEphemeral,
            length = SymmetricCrypto.AEAD_KEY_SIZE
        )
    }

    private fun buildResult(
        sessionKey: ByteArray,
        transcriptHash: ByteArray,
        peerInfo: PeerIdentityInfo?,
        matchedPeer: ContactRecord?
    ): HandshakeResult {
        return if (matchedPeer != null && peerInfo != null) {
            HandshakeResult(
                sessionKey = sessionKey,
                transcriptHash = transcriptHash,
                peerIdentity = peerInfo.bundle,
                trustTier = matchedPeer.tier,
                peerDisplayName = matchedPeer.displayName,
                authenticated = true
            )
        } else {
            // 陌生人：双方不揭示长期身份；临时别名仅作 UI 展示，绝不作为信任依据
            HandshakeResult(
                sessionKey = sessionKey,
                transcriptHash = transcriptHash,
                peerIdentity = null,
                trustTier = TrustTier.STRANGER,
                peerDisplayName = randomAlias(),
                authenticated = false
            )
        }
    }

    private fun randomAlias(): String {
        val adjectives = listOf("蓝色", "静默", "明亮", "遥远", "清晨", "微风")
        val nouns = listOf("设备", "终端", "手机", "节点", "站点", "终端")
        val a = adjectives[rng.nextInt(adjectives.size)]
        val n = nouns[rng.nextInt(nouns.size)]
        val suffix = SymmetricCrypto.randomBytes(2).joinToString("") { "%02x".format(it) }
        return "$a$n-$suffix"
    }

    private fun requireVersion(fields: Map<Byte, ByteArray>) {
        val version = fields[TLV_VERSION]?.singleOrNull()
            ?: throw HandshakeException("握手消息缺少版本")
        if (version != ProtocolDomains.VERSION) throw HandshakeException("协议版本不兼容")
    }

    data class PeerIdentityInfo(val bundle: IdentityBundle, val displayName: String)

    companion object {
        const val TLV_VERSION: Byte = 0x01
        const val TLV_EPHEMERAL: Byte = 0x02
        const val TLV_ENVELOPE: Byte = 0x03
        const val TLV_IDENTITY_KEY: Byte = 0x10
        const val TLV_STATIC_KEY: Byte = 0x11
        const val TLV_DISPLAY_NAME: Byte = 0x12
        const val TLV_SIGNATURE: Byte = 0x13
    }
}

class HandshakeException(message: String) : Exception(message)
