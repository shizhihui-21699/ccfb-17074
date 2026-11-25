package com.nearshare.guard.discovery

import com.nearshare.guard.crypto.SymmetricCrypto
import com.nearshare.guard.directory.ContactDirectory
import com.nearshare.guard.model.ContactRecord
import com.nearshare.guard.model.TrustTier
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DiscoveryProtocolTest {

    private fun contact(id: String, psk: ByteArray, tier: TrustTier = TrustTier.CONTACT) =
        ContactRecord(
            contactId = id,
            displayName = "联系人-$id",
            identityPublicKey = SymmetricCrypto.sha256("id-$id".toByteArray()),
            psk = psk,
            tier = tier
        )

    @Test
    fun `共享 PSK 的双方在发现阶段互相匹配`() {
        val psk = SymmetricCrypto.randomBytes(32)
        val aliceContact = contact("bob", psk)
        val bobContact = contact("alice", psk)

        val advertiser = DiscoveryAdvertiser()
        val advertisement = advertiser.newAdvertisement(listOf(aliceContact))
        val wire = advertisement.toWire()

        val matcher = DiscoveryMatcher(ContactDirectory(listOf(bobContact)))
        val candidates = matcher.match(wire)

        assertEquals(1, candidates.size)
        assertEquals("alice", candidates.single().record.contactId)
    }

    @Test
    fun `无 PSK 的陌生人不产生任何匹配`() {
        val advertiser = DiscoveryAdvertiser()
        val advertisement = advertiser.newAdvertisement(
            listOf(contact("friend", SymmetricCrypto.randomBytes(32)))
        )

        val strangersDirectory = ContactDirectory(
            listOf(contact("other", SymmetricCrypto.randomBytes(32)))
        )
        val matcher = DiscoveryMatcher(strangersDirectory)
        assertTrue(matcher.match(advertisement.toWire()).isEmpty())
    }

    @Test
    fun `广播材料不包含身份公钥或显示名等稳定标识`() {
        val record = contact("secret-friend", SymmetricCrypto.randomBytes(32))
        val advertisement = DiscoveryAdvertiser().newAdvertisement(listOf(record))
        val wireBytes = advertisement.toWire().encode()
        val identityString = record.identityPublicKey
        val nameBytes = record.displayName.toByteArray()

        // 身份公钥的任何连续 8 字节都不应出现在广播里
        for (i in 0..identityString.size - 8) {
            val window = identityString.copyOfRange(i, i + 8)
            assertFalse(containsSubarray(wireBytes, window), "发现广播泄露了身份公钥片段")
        }
        assertFalse(containsSubarray(wireBytes, nameBytes), "发现广播泄露了联系人显示名")
    }

    @Test
    fun `临时密钥轮换后标签全部变化，无法跨周期追踪`() {
        val advertiser = DiscoveryAdvertiser()
        val contacts = listOf(contact("c1", SymmetricCrypto.randomBytes(32)))

        val ad1 = advertiser.newAdvertisement(contacts)
        val ad2 = advertiser.newAdvertisement(contacts)

        val tag1 = DiscoveryAdvertiser.matchingTag(contacts[0].psk, ad1.ephemeralKeyPair.publicKey)
        val tag2 = DiscoveryAdvertiser.matchingTag(contacts[0].psk, ad2.ephemeralKeyPair.publicKey)
        assertFalse(tag1.contentEquals(tag2), "不同广播周期的匹配标签必须不同")
        assertFalse(
            ad1.ephemeralKeyPair.publicKey.contentEquals(ad2.ephemeralKeyPair.publicKey),
            "临时公钥必须每周期轮换"
        )
    }

    @Test
    fun `发现消息编码解码往返一致`() {
        val advertisement = DiscoveryAdvertiser()
            .newAdvertisement(listOf(contact("c", SymmetricCrypto.randomBytes(32))))
        val wire = advertisement.toWire()
        val decoded = DiscoveryWire.decode(wire.encode())
        assertEquals(wire, decoded)
    }

    @Test
    fun `resolveMatches 只确认真实联系人，忽略伪造标签`() {
        val psk = SymmetricCrypto.randomBytes(32)
        val real = contact("real", psk)
        val advertiser = DiscoveryAdvertiser()
        val ad = advertiser.newAdvertisement(listOf(real))

        val validTag = DiscoveryAdvertiser.matchingTag(psk, ad.ephemeralKeyPair.publicKey)
        val forgedTag = SymmetricCrypto.randomBytes(32)
        val resolved = advertiser.resolveMatches(
            listOf(real), ad.ephemeralKeyPair.publicKey, listOf(validTag, forgedTag)
        )
        assertEquals(1, resolved.size)
        assertNotNull(resolved.single())
    }

    @Test
    fun `恶意广播伪造超大哈希数或位图被拒绝，防止资源耗尽`() {
        val matcher = DiscoveryMatcher(ContactDirectory(listOf(contact("c", SymmetricCrypto.randomBytes(32)))))
        val oversizedHash = DiscoveryWire(
            version = ProtocolDomains.VERSION,
            ephemeralPublicKey = SymmetricCrypto.randomBytes(32),
            bloomBytes = ByteArray(8),
            hashCount = 10_000
        )
        assertThrows(IllegalArgumentException::class.java) { matcher.match(oversizedHash) }

        val oversizedBloom = DiscoveryWire(
            version = ProtocolDomains.VERSION,
            ephemeralPublicKey = SymmetricCrypto.randomBytes(32),
            bloomBytes = ByteArray(4096),
            hashCount = 3
        )
        assertThrows(IllegalArgumentException::class.java) { matcher.match(oversizedBloom) }
    }

    private fun containsSubarray(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty()) return true
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }
}
