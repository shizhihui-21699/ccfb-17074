package com.nearshare.guard.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.security.SecureRandom
import java.util.Arrays

/**
 * 对称原语集合：
 * - HKDF-SHA256：从 ECDH 共享秘密派生会话密钥
 * - HMAC-SHA256：发现阶段的私有集合匹配标签
 * - ChaCha20-Poly1305 (RFC 8439)：握手信封与传输通道 AEAD
 * - SHA-256：会话转录绑定
 */
object SymmetricCrypto {

    const val AEAD_KEY_SIZE = 32
    const val AEAD_NONCE_SIZE = 12
    const val AEAD_TAG_SIZE = 16
    const val HMAC_SIZE = 32
    const val SHA256_SIZE = 32

    private val rng = SecureRandom()

    fun sha256(data: ByteArray): ByteArray {
        val digest = SHA256Digest()
        digest.update(data, 0, data.size)
        val out = ByteArray(SHA256_SIZE)
        digest.doFinal(out, 0)
        return out
    }

    fun sha256(vararg parts: ByteArray): ByteArray {
        val digest = SHA256Digest()
        for (part in parts) digest.update(part, 0, part.size)
        val out = ByteArray(SHA256_SIZE)
        digest.doFinal(out, 0)
        return out
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = HMac(SHA256Digest())
        mac.init(KeyParameter(key))
        mac.update(data, 0, data.size)
        val out = ByteArray(HMAC_SIZE)
        mac.doFinal(out, 0)
        return out
    }

    /**
     * HKDF-Extract + HKDF-Expand（RFC 5869，基于 SHA-256）。
     */
    fun hkdf(ikm: ByteArray, info: ByteArray, length: Int, salt: ByteArray? = null): ByteArray {
        val prk = hmacSha256(salt ?: ByteArray(HMAC_SIZE), ikm)
        // Expand
        require(length <= 255 * HMAC_SIZE) { "HKDF 输出过长" }
        val okm = ByteArray(length)
        var previous = ByteArray(0)
        var pos = 0
        var counter = 1
        while (pos < length) {
            val mac = HMac(SHA256Digest())
            mac.init(KeyParameter(prk))
            mac.update(previous, 0, previous.size)
            mac.update(info, 0, info.size)
            mac.update(counter.toByte())
            previous = ByteArray(HMAC_SIZE)
            mac.doFinal(previous, 0)
            val take = minOf(HMAC_SIZE, length - pos)
            System.arraycopy(previous, 0, okm, pos, take)
            pos += take
            counter++
        }
        return okm
    }

    fun randomBytes(size: Int): ByteArray = ByteArray(size).also { rng.nextBytes(it) }

    /**
     * ChaCha20-Poly1305 AEAD（RFC 8439，96 位 nonce）。
     * 返回密文（含 16 字节 Poly1305 标签，追加在密文尾部）。
     */
    fun aeadSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == AEAD_KEY_SIZE)
        require(nonce.size == AEAD_NONCE_SIZE)
        val engine = ChaCha7539Engine()
        engine.init(true, ParametersWithIV(KeyParameter(key), nonce))

        // 生成 Poly1305 子密钥（RFC 8439 §2.6）
        val polyKey = ByteArray(64)
        engine.processBytes(ByteArray(64), 0, 64, polyKey, 0)
        val macKey = polyKey.copyOf(32)

        val ciphertext = ByteArray(plaintext.size)
        var len = engine.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)
        if (len != plaintext.size) {
            throw IllegalStateException("ChaCha20 处理长度异常")
        }

        val tag = poly1305(macKey, ciphertext, aad)
        return ciphertext + tag
    }

    /**
     * 校验并解密。失败抛 [AeadVerificationException]，绝不返回部分明文。
     */
    fun aeadOpen(key: ByteArray, nonce: ByteArray, sealed: ByteArray, aad: ByteArray): ByteArray {
        require(key.size == AEAD_KEY_SIZE)
        require(nonce.size == AEAD_NONCE_SIZE)
        if (sealed.size < AEAD_TAG_SIZE) throw AeadVerificationException("密文过短")
        val ciphertext = sealed.copyOfRange(0, sealed.size - AEAD_TAG_SIZE)
        val expectedTag = sealed.copyOfRange(sealed.size - AEAD_TAG_SIZE, sealed.size)

        val engine = ChaCha7539Engine()
        engine.init(true, ParametersWithIV(KeyParameter(key), nonce))
        val polyKey = ByteArray(64)
        engine.processBytes(ByteArray(64), 0, 64, polyKey, 0)
        val macKey = polyKey.copyOf(32)

        val actualTag = poly1305(macKey, ciphertext, aad)
        if (!constantTimeEquals(actualTag, expectedTag)) {
            throw AeadVerificationException("AEAD 标签校验失败")
        }

        val plaintext = ByteArray(ciphertext.size)
        engine.processBytes(ciphertext, 0, ciphertext.size, plaintext, 0)
        return plaintext
    }

    /** 一次性生成 nonce 并封装，nonce 前置在输出中。 */
    fun aeadSealWithRandomNonce(key: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val nonce = randomBytes(AEAD_NONCE_SIZE)
        return nonce + aeadSeal(key, nonce, plaintext, aad)
    }

    fun aeadOpenWithRandomNonce(key: ByteArray, sealed: ByteArray, aad: ByteArray): ByteArray {
        if (sealed.size < AEAD_NONCE_SIZE) throw AeadVerificationException("密文过短")
        val nonce = sealed.copyOfRange(0, AEAD_NONCE_SIZE)
        val body = sealed.copyOfRange(AEAD_NONCE_SIZE, sealed.size)
        return aeadOpen(key, nonce, body, aad)
    }

    /**
     * Poly1305 MAC，输入为 AAD 与密文，按 RFC 8439 §2.8 做填充与长度拼接。
     */
    private fun poly1305(macKey: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray {
        val mac = Poly1305()
        mac.init(KeyParameter(macKey))
        fun updatePadded(data: ByteArray) {
            mac.update(data, 0, data.size)
            val rem = data.size % 16
            if (rem != 0) {
                val pad = ByteArray(16 - rem)
                mac.update(pad, 0, pad.size)
            }
        }
        if (aad.isNotEmpty()) updatePadded(aad)
        if (ciphertext.isNotEmpty()) updatePadded(ciphertext)
        val aadLen = ByteBuffer8(aad.size.toLong())
        val ctLen = ByteBuffer8(ciphertext.size.toLong())
        mac.update(aadLen.bytes, 0, 8)
        mac.update(ctLen.bytes, 0, 8)
        val tag = ByteArray(AEAD_TAG_SIZE)
        mac.doFinal(tag, 0)
        return tag
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) result = result or (a[i].toInt() xor b[i].toInt())
        return result == 0
    }

    private class ByteBuffer8(value: Long) {
        val bytes = ByteArray(8)
        init {
            var v = value
            for (i in 7 downTo 0) {
                bytes[i] = (v and 0xFF).toByte()
                v = v ushr 8
            }
        }
    }

    /** 常量时间比较包装，防止数组比较被优化短路。 */
    fun checkWipe(data: ByteArray) {
        Arrays.fill(data, 0)
    }
}

class AeadVerificationException(message: String) : Exception(message)
