package com.nearshare.guard.transport

import com.nearshare.guard.crypto.AeadVerificationException
import com.nearshare.guard.crypto.SymmetricCrypto
import com.nearshare.guard.discovery.ProtocolDomains
import com.nearshare.guard.handshake.HandshakeResult

/**
 * 握手完成后的加密通道。
 *
 * - 发送/接收方向使用不同的子密钥（HKDF 方向标签），避免反射攻击；
 * - 每条消息使用单调递增 nonce 计数器，杜绝 nonce 复用；
 * - 转录哈希作为 AAD 的一部分，实现通道与握手绑定（防止通道被嫁接）。
 *
 * 线上帧 = u16 长度前缀 || AEAD(nonce || ciphertext || tag)。
 */
class SecureChannel(
    private val transport: SecureTransport,
    handshake: HandshakeResult,
    private val isInitiator: Boolean
) {
    private val sendKey: ByteArray
    private val receiveKey: ByteArray
    private val transcriptHash: ByteArray = handshake.transcriptHash
    private var sendCounter = 0L
    private var receiveCounter = 0L

    init {
        val base = handshake.sessionKey
        val initiatorKey = SymmetricCrypto.hkdf(
            base,
            info = ProtocolDomains.TRANSPORT_KEY + "initiator".toByteArray(),
            length = SymmetricCrypto.AEAD_KEY_SIZE
        )
        val responderKey = SymmetricCrypto.hkdf(
            base,
            info = ProtocolDomains.TRANSPORT_KEY + "responder".toByteArray(),
            length = SymmetricCrypto.AEAD_KEY_SIZE
        )
        if (isInitiator) {
            sendKey = initiatorKey; receiveKey = responderKey
        } else {
            sendKey = responderKey; receiveKey = initiatorKey
        }
    }

    fun send(plaintext: ByteArray) {
        val nonce = nonceFor(sendCounter++)
        val aad = transcriptHash + encodeCounter(sendCounter - 1)
        val sealed = SymmetricCrypto.aeadSeal(sendKey, nonce, plaintext, aad)
        transport.sendFrame(nonce + sealed)
    }

    fun receive(): ByteArray? {
        val frame = transport.receiveFrame() ?: return null
        if (frame.size < SymmetricCrypto.AEAD_NONCE_SIZE) {
            throw ChannelIntegrityException("加密帧过短")
        }
        val nonce = frame.copyOfRange(0, SymmetricCrypto.AEAD_NONCE_SIZE)
        val sealed = frame.copyOfRange(SymmetricCrypto.AEAD_NONCE_SIZE, frame.size)
        val expectedNonce = nonceFor(receiveCounter)
        if (!nonce.contentEquals(expectedNonce)) {
            throw ChannelIntegrityException("nonce 计数不匹配：检测到重放/乱序攻击")
        }
        val aad = transcriptHash + encodeCounter(receiveCounter)
        receiveCounter++
        return try {
            SymmetricCrypto.aeadOpen(receiveKey, nonce, sealed, aad)
        } catch (e: AeadVerificationException) {
            throw ChannelIntegrityException("通道消息完整性校验失败")
        }
    }

    fun close() = transport.close()

    private fun nonceFor(counter: Long): ByteArray {
        val nonce = ByteArray(SymmetricCrypto.AEAD_NONCE_SIZE)
        // 96 位 nonce：低 64 位放计数器，高 32 位保持零（单会话不会溢出）
        System.arraycopy(encodeCounter(counter), 0, nonce, 4, 8)
        return nonce
    }

    private fun encodeCounter(counter: Long): ByteArray = ByteArray(8) { i ->
        (counter ushr (56 - i * 8)).toByte()
    }
}

class ChannelIntegrityException(message: String) : Exception(message)
