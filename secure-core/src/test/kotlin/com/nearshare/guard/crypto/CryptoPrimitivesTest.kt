package com.nearshare.guard.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CryptoPrimitivesTest {

    @Test
    fun `X25519 双方协商出相同共享秘密`() {
        val alice = AsymmetricCrypto.generateX25519KeyPair()
        val bob = AsymmetricCrypto.generateX25519KeyPair()

        val aliceSecret = AsymmetricCrypto.x25519Agree(alice.privateKey, bob.publicKey)
        val bobSecret = AsymmetricCrypto.x25519Agree(bob.privateKey, alice.publicKey)

        assertArrayEquals(aliceSecret, bobSecret)
        assertEquals(32, aliceSecret.size)
    }

    @Test
    fun `不同密钥对产生不同共享秘密`() {
        val alice = AsymmetricCrypto.generateX25519KeyPair()
        val bob = AsymmetricCrypto.generateX25519KeyPair()
        val eve = AsymmetricCrypto.generateX25519KeyPair()

        val s1 = AsymmetricCrypto.x25519Agree(alice.privateKey, bob.publicKey)
        val s2 = AsymmetricCrypto.x25519Agree(alice.privateKey, eve.publicKey)
        assertFalse(s1.contentEquals(s2))
    }

    @Test
    fun `Ed25519 签名可被正确公钥验证`() {
        val pair = AsymmetricCrypto.generateEd25519KeyPair()
        val message = "近场快传握手转录".toByteArray()

        val signature = AsymmetricCrypto.ed25519Sign(pair.privateKey, message)
        assertEquals(64, signature.size)
        assertTrue(AsymmetricCrypto.ed25519Verify(pair.publicKey, message, signature))
    }

    @Test
    fun `Ed25519 对篡改消息验签失败`() {
        val pair = AsymmetricCrypto.generateEd25519KeyPair()
        val signature = AsymmetricCrypto.ed25519Sign(pair.privateKey, "原始消息".toByteArray())
        assertFalse(AsymmetricCrypto.ed25519Verify(pair.publicKey, "篡改消息".toByteArray(), signature))
    }

    @Test
    fun `Ed25519 用错误公钥验签失败`() {
        val signer = AsymmetricCrypto.generateEd25519KeyPair()
        val stranger = AsymmetricCrypto.generateEd25519KeyPair()
        val message = "test".toByteArray()
        val signature = AsymmetricCrypto.ed25519Sign(signer.privateKey, message)
        assertFalse(AsymmetricCrypto.ed25519Verify(stranger.publicKey, message, signature))
    }

    @Test
    fun `HKDF 相同输入派生相同密钥，不同 info 派生不同密钥`() {
        val ikm = SymmetricCrypto.randomBytes(32)
        val k1 = SymmetricCrypto.hkdf(ikm, "domainA".toByteArray(), 32)
        val k2 = SymmetricCrypto.hkdf(ikm, "domainA".toByteArray(), 32)
        val k3 = SymmetricCrypto.hkdf(ikm, "domainB".toByteArray(), 32)
        assertArrayEquals(k1, k2)
        assertFalse(k1.contentEquals(k3))
    }

    @Test
    fun `ChaCha20-Poly1305 正常加解密`() {
        val key = SymmetricCrypto.randomBytes(32)
        val nonce = SymmetricCrypto.randomBytes(12)
        val plaintext = "恶意安装包拦截测试".toByteArray()
        val aad = "transcript-hash".toByteArray()

        val sealed = SymmetricCrypto.aeadSeal(key, nonce, plaintext, aad)
        val opened = SymmetricCrypto.aeadOpen(key, nonce, sealed, aad)
        assertArrayEquals(plaintext, opened)
    }

    @Test
    fun `AEAD 篡改密文导致验签失败`() {
        val key = SymmetricCrypto.randomBytes(32)
        val nonce = SymmetricCrypto.randomBytes(12)
        val sealed = SymmetricCrypto.aeadSeal(key, nonce, "secret".toByteArray(), "aad".toByteArray())
        sealed[0] = (sealed[0].toInt() xor 0x01).toByte()
        assertThrows(AeadVerificationException::class.java) {
            SymmetricCrypto.aeadOpen(key, nonce, sealed, "aad".toByteArray())
        }
    }

    @Test
    fun `AEAD 错误 AAD 导致验签失败（通道绑定不可移植）`() {
        val key = SymmetricCrypto.randomBytes(32)
        val nonce = SymmetricCrypto.randomBytes(12)
        val sealed = SymmetricCrypto.aeadSeal(key, nonce, "secret".toByteArray(), "正确转录".toByteArray())
        assertThrows(AeadVerificationException::class.java) {
            SymmetricCrypto.aeadOpen(key, nonce, sealed, "伪造转录".toByteArray())
        }
    }

    @Test
    fun `随机 nonce 封装往返一致且 nonce 不重复`() {
        val key = SymmetricCrypto.randomBytes(32)
        val s1 = SymmetricCrypto.aeadSealWithRandomNonce(key, "a".toByteArray(), ByteArray(0))
        val s2 = SymmetricCrypto.aeadSealWithRandomNonce(key, "a".toByteArray(), ByteArray(0))
        assertNotEquals(s1.toList(), s2.toList())
        assertArrayEquals(
            "a".toByteArray(),
            SymmetricCrypto.aeadOpenWithRandomNonce(key, s1, ByteArray(0))
        )
    }
}
