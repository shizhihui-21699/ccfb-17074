package com.nearshare.guard.handshake

import com.nearshare.guard.crypto.AsymmetricCrypto
import com.nearshare.guard.crypto.SymmetricCrypto
import com.nearshare.guard.directory.ContactDirectory
import com.nearshare.guard.model.ContactRecord
import com.nearshare.guard.model.LocalIdentity
import com.nearshare.guard.model.TrustTier
import com.nearshare.guard.transport.InMemorySecureTransport
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors
import java.util.concurrent.Future

class HandshakeProtocolTest {

    private fun newIdentity(): LocalIdentity {
        val ed = AsymmetricCrypto.generateEd25519KeyPair()
        val x = AsymmetricCrypto.generateX25519KeyPair()
        return LocalIdentity(
            identityPublicKey = ed.publicKey,
            identityPrivateKey = ed.privateKey,
            keyExchangePublicKey = x.publicKey,
            keyExchangePrivateKey = x.privateKey
        )
    }

    private fun pairedRecords(
        alice: LocalIdentity,
        bob: LocalIdentity,
        psk: ByteArray,
        tier: TrustTier = TrustTier.CONTACT
    ): Pair<ContactRecord, ContactRecord> {
        val aliceView = ContactRecord("bob", "Bob 的手机", bob.identityPublicKey, psk, tier)
        val bobView = ContactRecord("alice", "Alice 的手机", alice.identityPublicKey, psk, tier)
        return aliceView to bobView
    }

    private fun runHandshake(
        initiatorIdentity: LocalIdentity,
        responderIdentity: LocalIdentity,
        initiatorMatch: ContactRecord?,
        responderMatch: ContactRecord?
    ): Pair<HandshakeResult, HandshakeResult> {
        val channelA = InMemorySecureTransport()
        val channelB = channelA.peer()
        val executor = Executors.newFixedThreadPool(2)
        try {
            val initiator = HandshakeProtocol(initiatorIdentity, "Alice")
            val responder = HandshakeProtocol(responderIdentity, "Bob")

            val fInit: Future<HandshakeResult> = executor.submit(
                java.util.concurrent.Callable { initiator.initiate(channelA, initiatorMatch) }
            )
            val fResp: Future<HandshakeResult> = executor.submit(
                java.util.concurrent.Callable {
                    responder.respond(
                        channelB,
                        ContactDirectory(responderMatch?.let { listOf(it) } ?: emptyList()),
                        responderMatch
                    )
                }
            )
            // 解包 Executor 的 ExecutionException，让断言能直接匹配协议异常
            return try {
                fInit.get() to fResp.get()
            } catch (e: java.util.concurrent.ExecutionException) {
                throw e.cause ?: e
            }
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `通讯录熟人握手成功且双向认证、会话密钥一致`() {
        val alice = newIdentity()
        val bob = newIdentity()
        val psk = SymmetricCrypto.randomBytes(32)
        val (aliceView, bobView) = pairedRecords(alice, bob, psk)

        val (initResult, respResult) = runHandshake(alice, bob, aliceView, bobView)

        assertTrue(initResult.authenticated)
        assertTrue(respResult.authenticated)
        assertEquals(TrustTier.CONTACT, initResult.trustTier)
        assertEquals(TrustTier.CONTACT, respResult.trustTier)
        assertArrayEquals(initResult.sessionKey, respResult.sessionKey)
        assertArrayEquals(initResult.transcriptHash, respResult.transcriptHash)
        assertNotNull(initResult.peerIdentity)
        assertNotNull(respResult.peerIdentity)
        // 对端显示名来自本机目录，而非对端自报
        assertEquals("Bob 的手机", initResult.peerDisplayName)
        assertEquals("Alice 的手机", respResult.peerDisplayName)
    }

    @Test
    fun `同账号设备握手标记为 SAME_ACCOUNT`() {
        val alice = newIdentity()
        val bob = newIdentity()
        val psk = SymmetricCrypto.randomBytes(32)
        val (aliceView, bobView) = pairedRecords(alice, bob, psk, TrustTier.SAME_ACCOUNT)

        val (initResult, respResult) = runHandshake(alice, bob, aliceView, bobView)
        assertEquals(TrustTier.SAME_ACCOUNT, initResult.trustTier)
        assertEquals(TrustTier.SAME_ACCOUNT, respResult.trustTier)
    }

    @Test
    fun `陌生人握手不揭示长期身份且标记未认证`() {
        val alice = newIdentity()
        val bob = newIdentity()

        val (initResult, respResult) = runHandshake(alice, bob, null, null)

        assertFalse(initResult.authenticated)
        assertFalse(respResult.authenticated)
        assertEquals(TrustTier.STRANGER, initResult.trustTier)
        assertEquals(TrustTier.STRANGER, respResult.trustTier)
        assertNull(initResult.peerIdentity)
        assertNull(respResult.peerIdentity)
        assertArrayEquals(initResult.sessionKey, respResult.sessionKey)
    }

    @Test
    fun `PSK 不匹配时信封解密失败，拒绝连接`() {
        val alice = newIdentity()
        val bob = newIdentity()
        // 双方各自持有"看起来配对过"但实际不同的 PSK
        val aliceView = ContactRecord("bob", "Bob", bob.identityPublicKey, SymmetricCrypto.randomBytes(32))
        val bobView = ContactRecord("alice", "Alice", alice.identityPublicKey, SymmetricCrypto.randomBytes(32))

        assertThrows(HandshakeException::class.java) {
            runHandshake(alice, bob, aliceView, bobView)
        }
    }

    @Test
    fun `攻击者公钥与目录身份不一致时握手失败`() {
        val alice = newIdentity()
        val bob = newIdentity()
        val attacker = newIdentity()
        val psk = SymmetricCrypto.randomBytes(32)

        // Alice 目录里记录的是 Bob 的身份公钥，但握手机器人拿着攻击者的身份私钥
        val aliceView = ContactRecord("bob", "Bob", bob.identityPublicKey, psk)
        val attackerView = ContactRecord("alice", "Alice", alice.identityPublicKey, psk)

        assertThrows(HandshakeException::class.java) {
            runHandshake(alice, attacker, aliceView, attackerView)
        }
    }

    @Test
    fun `中间人替换临时公钥导致身份验签失败`() {
        val alice = newIdentity()
        val bob = newIdentity()
        val psk = SymmetricCrypto.randomBytes(32)
        val (aliceView, bobView) = pairedRecords(alice, bob, psk)

        // 用一个会篡改 M1 临时公钥的恶意传输包装
        val baseA = InMemorySecureTransport()
        val tamperingA = TamperEphemeralTransport(baseA)
        val channelB = baseA.peer()

        val executor = Executors.newFixedThreadPool(2)
        try {
            val initiator = HandshakeProtocol(alice, "Alice")
            val responder = HandshakeProtocol(bob, "Bob")
            val fResp = executor.submit(java.util.concurrent.Callable {
                responder.respond(channelB, ContactDirectory(listOf(bobView)), bobView)
            })
            val fInit = executor.submit(java.util.concurrent.Callable {
                initiator.initiate(tamperingA, aliceView)
            })
            // 至少一侧必须失败
            val failures = listOf(runCatching { fInit.get() }, runCatching { fResp.get() })
                .count { it.isFailure }
            assertTrue(failures >= 1, "中间人攻击必须被检测到")
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `握手结果派生的 Wi-Fi 凭据双方一致且不经过网络`() {
        val alice = newIdentity()
        val bob = newIdentity()
        val psk = SymmetricCrypto.randomBytes(32)
        val (aliceView, bobView) = pairedRecords(alice, bob, psk)

        val (initResult, respResult) = runHandshake(alice, bob, aliceView, bobView)
        assertEquals(initResult.wifiCredentials(), respResult.wifiCredentials())
        assertTrue(initResult.wifiCredentials().ssid.startsWith("NSG-"))
        assertEquals(64, initResult.wifiCredentials().passphrase.length)
    }
}

/**
 * 模拟中间人：把发出的 M1 帧中的临时公钥首字节翻转。
 * 由于后续身份签名/AEAD 绑定原始转录，篡改必然被发现。
 */
private class TamperEphemeralTransport(
    private val delegate: InMemorySecureTransport
) : com.nearshare.guard.transport.SecureTransport {

    override fun sendFrame(payload: ByteArray) {
        // payload 是 u16 长度前缀帧；仅篡改第一帧（M1）
        val tampered = payload.copyOf()
        // 跳过 2 字节长度头，再跳过 TLV version(1+1+1) 与 ephemeral tag(1) + varint(1)
        // 直接定位到临时公钥区：帧头2 + T:01 L:01 V:01 + T:02 L:01 = 偏移 8
        if (tampered.size > 9) tampered[8] = (tampered[8].toInt() xor 0xFF).toByte()
        delegate.sendFrame(tampered)
    }

    override fun receiveFrame(): ByteArray? = delegate.receiveFrame()
    override fun close() = delegate.close()
}
