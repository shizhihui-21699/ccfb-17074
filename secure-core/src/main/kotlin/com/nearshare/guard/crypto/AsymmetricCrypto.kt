package com.nearshare.guard.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom

/**
 * 非对称原语集合：
 * - Ed25519：身份签名（长期身份密钥）
 * - X25519：ECDH 密钥协商（临时握手密钥 + 信封封装）
 *
 * 所有对外暴露的密钥材料都是原始定长字节数组（Ed25519 公钥 32B、
 * X25519 公钥 32B、对应私钥 32B），便于序列化与跨平台实现。
 */
object AsymmetricCrypto {

    const val X25519_KEY_SIZE = 32
    const val ED25519_KEY_SIZE = 32
    const val SIGNATURE_SIZE = 64

    private fun rng(): SecureRandom = SecureRandom()

    // ---------- X25519 ----------

    fun generateX25519KeyPair(): X25519KeyPair {
        val generator = X25519KeyPairGenerator().apply {
            init(X25519KeyGenerationParameters(rng()))
        }
        val pair = generator.generateKeyPair()
        val pub = (pair.public as X25519PublicKeyParameters).encoded
        val priv = (pair.private as X25519PrivateKeyParameters).encoded
        return X25519KeyPair(publicKey = pub, privateKey = priv)
    }

    /**
     * X25519 ECDH，输出 32 字节共享秘密。
     * 调用方必须再经过 HKDF 派生后使用，禁止直接当密钥。
     */
    fun x25519Agree(privateKey: ByteArray, peerPublicKey: ByteArray): ByteArray {
        require(privateKey.size == X25519_KEY_SIZE) { "X25519 私钥必须为 32 字节" }
        require(peerPublicKey.size == X25519_KEY_SIZE) { "X25519 公钥必须为 32 字节" }
        val priv = X25519PrivateKeyParameters(privateKey, 0)
        val pub = X25519PublicKeyParameters(peerPublicKey, 0)
        val agreement = X25519Agreement()
        agreement.init(priv)
        val secret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(pub, secret, 0)
        return secret
    }

    // ---------- Ed25519 ----------

    fun generateEd25519KeyPair(): Ed25519KeyPair {
        val generator = Ed25519KeyPairGenerator().apply {
            init(Ed25519KeyGenerationParameters(rng()))
        }
        val pair = generator.generateKeyPair()
        val pub = (pair.public as Ed25519PublicKeyParameters).encoded
        val priv = (pair.private as Ed25519PrivateKeyParameters).encoded
        return Ed25519KeyPair(publicKey = pub, privateKey = priv)
    }

    fun ed25519Sign(privateKey: ByteArray, message: ByteArray): ByteArray {
        require(privateKey.size == ED25519_KEY_SIZE)
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(privateKey, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != ED25519_KEY_SIZE || signature.size != SIGNATURE_SIZE) return false
        return try {
            val signer = Ed25519Signer()
            signer.init(false, Ed25519PublicKeyParameters(publicKey, 0))
            signer.update(message, 0, message.size)
            signer.verifySignature(signature)
        } catch (e: Exception) {
            false
        }
    }
}

data class X25519KeyPair(val publicKey: ByteArray, val privateKey: ByteArray) {
    override fun equals(other: Any?): Boolean =
        other is X25519KeyPair && publicKey.contentEquals(other.publicKey) &&
            privateKey.contentEquals(other.privateKey)
    override fun hashCode(): Int = 31 * publicKey.contentHashCode() + privateKey.contentHashCode()
}

data class Ed25519KeyPair(val publicKey: ByteArray, val privateKey: ByteArray) {
    override fun equals(other: Any?): Boolean =
        other is Ed25519KeyPair && publicKey.contentEquals(other.publicKey) &&
            privateKey.contentEquals(other.privateKey)
    override fun hashCode(): Int = 31 * publicKey.contentHashCode() + privateKey.contentHashCode()
}
