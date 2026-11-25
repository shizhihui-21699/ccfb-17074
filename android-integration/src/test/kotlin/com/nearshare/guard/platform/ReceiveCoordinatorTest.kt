package com.nearshare.guard.platform

import com.nearshare.guard.crypto.AsymmetricCrypto
import com.nearshare.guard.crypto.SymmetricCrypto
import com.nearshare.guard.directory.ContactDirectory
import com.nearshare.guard.discovery.DiscoveryAdvertiser
import com.nearshare.guard.files.FileCategory
import com.nearshare.guard.files.FileDetection
import com.nearshare.guard.files.FileTypeDetector
import com.nearshare.guard.files.PreviewMode
import com.nearshare.guard.files.ReceiveDecision
import com.nearshare.guard.files.ReceivePolicy
import com.nearshare.guard.model.ContactRecord
import com.nearshare.guard.model.LocalIdentity
import com.nearshare.guard.model.TrustTier
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ReceiveCoordinatorTest {

    private fun identity(): LocalIdentity {
        val ed = AsymmetricCrypto.generateEd25519KeyPair()
        val x = AsymmetricCrypto.generateX25519KeyPair()
        return LocalIdentity(ed.publicKey, ed.privateKey, x.publicKey, x.privateKey)
    }

    private class FixedSources(
        private val records: List<ContactRecord>
    ) : ContactSource, AccountSource {
        override fun loadPairedContacts(): List<ContactRecord> =
            records.filter { it.tier == TrustTier.CONTACT }
        override fun loadSameAccountDevices(): List<ContactRecord> =
            records.filter { it.tier == TrustTier.SAME_ACCOUNT }
    }

    @Test
    fun `共享 PSK 的广播识别为熟人候选，无 PSK 识别为陌生人`() {
        val psk = SymmetricCrypto.randomBytes(32)
        val friendRecord = ContactRecord(
            contactId = "friend",
            displayName = "老王",
            identityPublicKey = SymmetricCrypto.sha256("friend-id".toByteArray()),
            psk = psk
        )
        val sources = FixedSources(listOf(friendRecord))
        val coordinator = ReceiveCoordinator(
            InMemoryIdentityVault(),
            DirectoryProvider(sources, sources),
            "我的手机"
        )

        // 熟人广播（发送方目录里持有同一 PSK）
        val friendAd = DiscoveryAdvertiser()
            .newAdvertisement(listOf(friendRecord))
            .toWire()
            .encode()
        val known = coordinator.onAdvertisement(friendAd)
        assertTrue(known is ReceiveCoordinator.DiscoveryOutcome.KnownCandidate)

        // 陌生人广播（不同 PSK 集合）
        val strangerRecord = ContactRecord(
            "x", "x", SymmetricCrypto.sha256("x".toByteArray()), SymmetricCrypto.randomBytes(32)
        )
        val strangerAd = DiscoveryAdvertiser()
            .newAdvertisement(listOf(strangerRecord))
            .toWire()
            .encode()
        assertTrue(coordinator.onAdvertisement(strangerAd) is ReceiveCoordinator.DiscoveryOutcome.Stranger)

        // 畸形广播不产生弹窗
        assertEquals(
            ReceiveCoordinator.DiscoveryOutcome.Malformed,
            coordinator.onAdvertisement(byteArrayOf(9, 9, 9))
        )
    }

    @Test
    fun `陌生人图片卡片为模糊预览且无认证徽章`() {
        val sources = FixedSources(emptyList())
        val coordinator = ReceiveCoordinator(
            InMemoryIdentityVault(), DirectoryProvider(sources, sources), "本机"
        )
        val handshake = HandshakeResultBuilder.stranger()
        val detection = FileTypeDetector.sniff(
            byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47), "a.png"
        )
        val decision = ReceivePolicy().evaluate(TrustTier.STRANGER, detection, 1024)

        val card = ReceiveCoordinator.toUiCard(handshake, detection, decision)
        assertEquals(PreviewMode.BLURRED, card.previewMode)
        assertFalse(card.showVerifiedBadge)
        assertTrue(card.quarantined)
        assertTrue(card.warnings.isNotEmpty())
    }

    @Test
    fun `熟人文档卡片显示认证徽章与正常预览`() {
        val sources = FixedSources(emptyList())
        val handshake = HandshakeResultBuilder.contact()
        val detection = FileDetection(FileCategory.PDF, "pdf", false, false)
        val decision = ReceiveDecision(true, PreviewMode.NORMAL, false, emptyList(), false)

        val card = ReceiveCoordinator.toUiCard(handshake, detection, decision)
        assertTrue(card.showVerifiedBadge)
        assertEquals(TrustTier.CONTACT, card.trustTier)
        assertFalse(card.blocked)
    }
}
