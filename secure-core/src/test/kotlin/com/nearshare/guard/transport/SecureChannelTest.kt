package com.nearshare.guard.transport

import com.nearshare.guard.crypto.AsymmetricCrypto
import com.nearshare.guard.crypto.SymmetricCrypto
import com.nearshare.guard.directory.ContactDirectory
import com.nearshare.guard.handshake.HandshakeProtocol
import com.nearshare.guard.handshake.HandshakeResult
import com.nearshare.guard.model.ContactRecord
import com.nearshare.guard.model.LocalIdentity
import com.nearshare.guard.model.TrustTier
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors

class SecureChannelTest {

    private fun newIdentity(): LocalIdentity {
        val ed = AsymmetricCrypto.generateEd25519KeyPair()
        val x = AsymmetricCrypto.generateX25519KeyPair()
        return LocalIdentity(ed.publicKey, ed.privateKey, x.publicKey, x.privateKey)
    }

    private fun establishedChannels(): Pair<SecureChannel, SecureChannel> {
        val alice = newIdentity()
        val bob = newIdentity()
        val psk = SymmetricCrypto.randomBytes(32)
        val aliceView = ContactRecord("b", "Bob", bob.identityPublicKey, psk)
        val bobView = ContactRecord("a", "Alice", alice.identityPublicKey, psk)

        val rawA = InMemorySecureTransport()
        val rawB = rawA.peer()
        val executor = Executors.newFixedThreadPool(2)
        val ha = HandshakeProtocol(alice, "A")
        val hb = HandshakeProtocol(bob, "B")
        val f1 = executor.submit(java.util.concurrent.Callable { ha.initiate(rawA, aliceView) })
        val f2 = executor.submit(java.util.concurrent.Callable {
            hb.respond(rawB, ContactDirectory(listOf(bobView)), bobView)
        })
        val r1 = f1.get(); val r2 = f2.get()
        executor.shutdownNow()
        return SecureChannel(rawA, r1, isInitiator = true) to
            SecureChannel(rawB, r2, isInitiator = false)
    }

    @Test
    fun `加密通道双向收发多条消息`() {
        val (a, b) = establishedChannels()
        val messages = listOf("第一条".toByteArray(), "second".toByteArray(), ByteArray(1000) { it.toByte() })
        for (msg in messages) {
            a.send(msg)
            assertArrayEquals(msg, b.receive())
        }
        b.send("回信".toByteArray())
        assertArrayEquals("回信".toByteArray(), a.receive())
    }

    @Test
    fun `重放旧帧因 nonce 计数推进被拒绝`() {
        // 用同一份握手结果构造通道，使两侧密钥完全一致
        val handshake = HandshakeResult(
            sessionKey = SymmetricCrypto.randomBytes(32),
            transcriptHash = SymmetricCrypto.sha256("transcript".toByteArray()),
            peerIdentity = null,
            trustTier = TrustTier.STRANGER,
            peerDisplayName = "x",
            authenticated = false
        )
        val senderRaw = InMemorySecureTransport()
        val sender = SecureChannel(senderRaw, handshake, isInitiator = true)
        sender.send("唯一消息".toByteArray())
        val captured = senderRaw.peer().receiveFrame()!!

        // 接收传输对每次读取都返回同一帧（模拟攻击者重放）
        val replayTransport = object : SecureTransport {
            override fun sendFrame(payload: ByteArray) {}
            override fun receiveFrame(): ByteArray = captured
            override fun close() {}
        }
        val receiver = SecureChannel(replayTransport, handshake, isInitiator = false)

        // 第一次：计数 0 对计数 0，正常解密
        assertArrayEquals("唯一消息".toByteArray(), receiver.receive())
        // 第二次：同一帧 nonce 仍是 0，但接收计数已推进到 1，必须拒绝
        assertThrows(ChannelIntegrityException::class.java) { receiver.receive() }
    }

    @Test
    fun `篡改通道消息导致完整性校验失败`() {
        val handshake = HandshakeResult(
            sessionKey = SymmetricCrypto.randomBytes(32),
            transcriptHash = SymmetricCrypto.sha256("t".toByteArray()),
            peerIdentity = null,
            trustTier = TrustTier.STRANGER,
            peerDisplayName = "x",
            authenticated = false
        )
        val senderRaw = InMemorySecureTransport()
        SecureChannel(senderRaw, handshake, isInitiator = true).send("data".toByteArray())
        val captured = senderRaw.peer().receiveFrame()!!.copyOf()
        // 翻转密文区一个比特（nonce 之后）
        val idx = captured.size - 5
        captured[idx] = (captured[idx].toInt() xor 0x01).toByte()

        val tamperedTransport = object : SecureTransport {
            override fun sendFrame(payload: ByteArray) {}
            override fun receiveFrame(): ByteArray = captured
            override fun close() {}
        }
        assertThrows(ChannelIntegrityException::class.java) {
            SecureChannel(tamperedTransport, handshake, isInitiator = false).receive()
        }
    }
}
