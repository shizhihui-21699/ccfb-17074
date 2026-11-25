package com.nearshare.guard

import com.nearshare.guard.crypto.AsymmetricCrypto
import com.nearshare.guard.crypto.SymmetricCrypto
import com.nearshare.guard.directory.ContactDirectory
import com.nearshare.guard.discovery.DiscoveryAdvertiser
import com.nearshare.guard.discovery.DiscoveryMatcher
import com.nearshare.guard.files.FileManifestEntry
import com.nearshare.guard.files.FileReceiveSession
import com.nearshare.guard.files.FileSendSession
import com.nearshare.guard.files.FileTransferException
import com.nearshare.guard.files.OutgoingFile
import com.nearshare.guard.handshake.HandshakeProtocol
import com.nearshare.guard.model.LocalIdentity
import com.nearshare.guard.model.TrustTier
import com.nearshare.guard.pairing.PairingProtocol
import com.nearshare.guard.transport.InMemorySecureTransport
import com.nearshare.guard.transport.SecureChannel
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.Executors

/**
 * 全链路集成测试：两台完全离线的手机，从配对到文件接收走完整协议栈。
 */
class EndToEndFlowTest {

    private fun newIdentity(): LocalIdentity {
        val ed = AsymmetricCrypto.generateEd25519KeyPair()
        val x = AsymmetricCrypto.generateX25519KeyPair()
        return LocalIdentity(ed.publicKey, ed.privateKey, x.publicKey, x.privateKey)
    }

    private fun pairDevices(
        alice: LocalIdentity,
        bob: LocalIdentity
    ): Pair<com.nearshare.guard.model.ContactRecord, com.nearshare.guard.model.ContactRecord> {
        val alicePairing = PairingProtocol(alice, "Alice")
        val bobPairing = PairingProtocol(bob, "Bob")
        val qr = alicePairing.buildQrPayload()
        val exchange = bobPairing.respondToQr(qr, userConfirmedSas = true)
        val aliceResult = alicePairing.completeInitiator(exchange.response, "Bob")
        return aliceResult.contactRecord to exchange.result.contactRecord
    }

    private class ConnectedPeers(
        val sender: SecureChannel,
        val receiver: SecureChannel,
        val receiverTier: TrustTier
    )

    private fun connect(
        senderIdentity: LocalIdentity,
        receiverIdentity: LocalIdentity,
        senderRecord: com.nearshare.guard.model.ContactRecord?,
        receiverRecord: com.nearshare.guard.model.ContactRecord?
    ): ConnectedPeers {
        val rawA = InMemorySecureTransport()
        val rawB = rawA.peer()
        val executor = Executors.newFixedThreadPool(2)
        try {
            val hsA = HandshakeProtocol(senderIdentity, "Sender")
            val hsB = HandshakeProtocol(receiverIdentity, "Receiver")
            val fA = executor.submit(java.util.concurrent.Callable {
                hsA.initiate(rawA, senderRecord)
            })
            val fB = executor.submit(java.util.concurrent.Callable {
                hsB.respond(
                    rawB,
                    ContactDirectory(receiverRecord?.let { listOf(it) } ?: emptyList()),
                    receiverRecord
                )
            })
            val rA = fA.get(); val rB = fB.get()
            return ConnectedPeers(
                SecureChannel(rawA, rA, isInitiator = true),
                SecureChannel(rawB, rB, isInitiator = false),
                rB.trustTier
            )
        } finally {
            executor.shutdownNow()
        }
    }

    private fun outgoing(name: String, bytes: ByteArray, mime: String? = null): OutgoingFile {
        val entry = FileManifestEntry(
            fileName = name,
            sizeBytes = bytes.size.toLong(),
            sha256 = SymmetricCrypto.sha256(bytes),
            declaredMimeType = mime
        )
        return OutgoingFile(entry, bytes)
    }

    @Test
    fun `完整流程_配对后发现匹配并安全收到图片`() {
        val alice = newIdentity()
        val bob = newIdentity()
        val (aliceView, bobView) = pairDevices(alice, bob)

        // 发现阶段：Alice（发送方）广播，Bob（接收方）匹配
        val advert = DiscoveryAdvertiser().newAdvertisement(listOf(aliceView))
        val candidates = DiscoveryMatcher(ContactDirectory(listOf(bobView))).match(advert.toWire())
        assertEquals(1, candidates.size)

        // 握手 + 通道
        val peers = connect(alice, bob, aliceView, bobView)
        assertEquals(TrustTier.CONTACT, peers.receiverTier)

        // 文件传输
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47) + ByteArray(200) { (it % 256).toByte() }
        val file = outgoing("合照.png", png, "image/png")

        val executor = Executors.newFixedThreadPool(2)
        try {
            val fSend = executor.submit { FileSendSession(peers.sender).sendBatch(listOf(file)) }
            val fRecv = executor.submit(java.util.concurrent.Callable {
                FileReceiveSession(peers.receiver, peers.receiverTier).receiveBatch()
            })
            fSend.get()
            val received = fRecv.get()
            assertEquals(1, received.size)
            assertArrayEquals(png, received.single().bytes)
            assertEquals("合照.png", received.single().fileName)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `陌生人发送伪装成 PDF 的安装包被拦截`() {
        val alice = newIdentity()
        val bob = newIdentity()
        // 无配对记录 → 陌生人
        val peers = connect(alice, bob, null, null)
        assertEquals(TrustTier.STRANGER, peers.receiverTier)

        // DEX 魔数，却命名为 .pdf —— 对应真实攻击：恶意安装包伪装文档
        val malware = "dex\n035".toByteArray() + ByteArray(512)
        val disguised = outgoing("工资条.pdf", malware, "application/pdf")

        val executor = Executors.newFixedThreadPool(2)
        try {
            val fSend = executor.submit(java.util.concurrent.Callable {
                runCatching { FileSendSession(peers.sender).sendBatch(listOf(disguised)) }
            })
            val fRecv = executor.submit(java.util.concurrent.Callable {
                runCatching {
                    FileReceiveSession(peers.receiver, peers.receiverTier).receiveBatch()
                }
            })
            val receiverOutcome = fRecv.get()
            assertTrue(receiverOutcome.isFailure)
            assertTrue(receiverOutcome.exceptionOrNull() is FileTransferException)
            // 发送侧也应收到拒绝通知而异常
            val senderOutcome = fSend.get()
            assertTrue(senderOutcome.isFailure)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `陌生人发图片仅模糊预览且隔离存放`() {
        val alice = newIdentity()
        val bob = newIdentity()
        val peers = connect(alice, bob, null, null)

        val image = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47) + ByteArray(128)
        val file = outgoing("unsolicited.png", image)

        val executor = Executors.newFixedThreadPool(2)
        try {
            val fSend = executor.submit { FileSendSession(peers.sender).sendBatch(listOf(file)) }
            val fRecv = executor.submit(java.util.concurrent.Callable {
                FileReceiveSession(peers.receiver, peers.receiverTier).receiveBatch()
            })
            fSend.get()
            val received = fRecv.get().single()
            assertEquals(com.nearshare.guard.files.PreviewMode.BLURRED, received.decision.previewMode)
            assertTrue(received.decision.quarantine)
            assertTrue(received.decision.requireExplicitConsent)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `文件内容被篡改导致哈希校验失败`() {
        val alice = newIdentity()
        val bob = newIdentity()
        val (aliceView, bobView) = pairDevices(alice, bob)
        val peers = connect(alice, bob, aliceView, bobView)

        val bytes = "hello".toByteArray()
        // 清单哈希对应原始内容，但实际发送被篡改的内容
        val entry = FileManifestEntry("f.txt", bytes.size.toLong(), SymmetricCrypto.sha256(bytes), "text/plain")
        val tampered = OutgoingFile(entry, "hXllo".toByteArray())

        val executor = Executors.newFixedThreadPool(2)
        try {
            executor.submit { runCatching { FileSendSession(peers.sender).sendBatch(listOf(tampered)) } }
            val outcome = runCatching {
                FileReceiveSession(peers.receiver, peers.receiverTier).receiveBatch()
            }
            assertTrue(outcome.isFailure)
            assertTrue(outcome.exceptionOrNull()!!.message!!.contains("哈希"))
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `地铁攻击者改设备名无法通过身份验证`() {
        // 受害者 Bob 与真实 Alice 配对过
        val realAlice = newIdentity()
        val bob = newIdentity()
        val (aliceView, bobView) = pairDevices(realAlice, bob)

        // 攻击者拿着自己的全新身份，把设备名改成 "Alice"，但没有配对 PSK
        val attacker = newIdentity()
        val attackerProtocol = HandshakeProtocol(attacker, "Alice") // 自报同名
        val rawA = InMemorySecureTransport()
        val rawB = rawA.peer()
        val bobProtocol = HandshakeProtocol(bob, "Bob")

        val executor = Executors.newFixedThreadPool(2)
        try {
            // 攻击者无 Alice 的 PSK，只能走陌生人通道
            val fAttack = executor.submit {
                runCatching { attackerProtocol.initiate(rawA, null) }
            }
            val fBob = executor.submit(java.util.concurrent.Callable {
                runCatching {
                    bobProtocol.respond(rawB, ContactDirectory(listOf(bobView)), null)
                }
            })
            val bobResult = fBob.get().getOrThrow()
            fAttack.get()

            // 关键断言：尽管自报名相同，信任层级仍是陌生人，不显示任何目录中的熟人信息
            assertEquals(TrustTier.STRANGER, bobResult.trustTier)
            assertFalse(bobResult.authenticated)
            assertEquals(null, bobResult.peerIdentity)
        } finally {
            executor.shutdownNow()
        }
    }
}
