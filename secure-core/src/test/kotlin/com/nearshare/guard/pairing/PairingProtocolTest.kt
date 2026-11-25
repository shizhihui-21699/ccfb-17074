package com.nearshare.guard.pairing

import com.nearshare.guard.crypto.AsymmetricCrypto
import com.nearshare.guard.crypto.SymmetricCrypto
import com.nearshare.guard.model.LocalIdentity
import com.nearshare.guard.model.TrustTier
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PairingProtocolTest {

    private fun newIdentity(): LocalIdentity {
        val ed = AsymmetricCrypto.generateEd25519KeyPair()
        val x = AsymmetricCrypto.generateX25519KeyPair()
        return LocalIdentity(ed.publicKey, ed.privateKey, x.publicKey, x.privateKey)
    }

    @Test
    fun `扫码配对双方派生出相同 PSK 与 SAS`() {
        val aliceIdentity = newIdentity()
        val bobIdentity = newIdentity()
        val alice = PairingProtocol(aliceIdentity, "Alice 手机")
        val bob = PairingProtocol(bobIdentity, "Bob 手机")

        val qr = alice.buildQrPayload()
        val exchange = bob.respondToQr(qr, userConfirmedSas = true)
        val aliceResult = alice.completeInitiator(exchange.response, "Bob 手机")

        assertArrayEquals(aliceResult.contactRecord.psk, exchange.result.contactRecord.psk)
        assertEquals(aliceResult.sas, exchange.result.sas)
        assertEquals(6, aliceResult.sas.length)
        // 双方各自存的是对端身份
        assertArrayEquals(bobIdentity.identityPublicKey, aliceResult.contactRecord.identityPublicKey)
        assertArrayEquals(aliceIdentity.identityPublicKey, exchange.result.contactRecord.identityPublicKey)
    }

    @Test
    fun `SAS 是 6 位十进制且不同 PSK 产生不同 SAS`() {
        val psk1 = SymmetricCrypto.randomBytes(32)
        val psk2 = SymmetricCrypto.randomBytes(32)
        val sas1 = PairingProtocol.computeSas(psk1)
        val sas2 = PairingProtocol.computeSas(psk2)
        assertTrue(sas1.matches(Regex("\\d{6}")))
        assertNotEquals(sas1, sas2)
    }

    @Test
    fun `配对回执被篡改时发起方校验失败`() {
        val aliceIdentity = newIdentity()
        val bobIdentity = newIdentity()
        val alice = PairingProtocol(aliceIdentity, "A")
        val bob = PairingProtocol(bobIdentity, "B")

        val exchange = bob.respondToQr(alice.buildQrPayload(), userConfirmedSas = true)
        val tampered = exchange.response.copy(
            ephemeralPublicKey = exchange.response.ephemeralPublicKey.also { it[0] = (it[0].toInt() xor 1).toByte() }
        )
        assertThrows(PairingException::class.java) {
            alice.completeInitiator(tampered, "B")
        }
    }

    @Test
    fun `同账号预置产生 SAME_ACCOUNT 层级且 PSK 双向一致`() {
        val phone = newIdentity()
        val tablet = newIdentity()
        val masterKey = SymmetricCrypto.randomBytes(32)

        val phoneProvisioning = LocalAccountProvisioning(
            masterKey, listOf(tablet.publicBundle() to "我的平板")
        )
        val tabletProvisioning = LocalAccountProvisioning(
            masterKey, listOf(phone.publicBundle() to "我的手机")
        )

        val phoneRecords = phoneProvisioning.provisionSameAccountDevices(phone)
        val tabletRecords = tabletProvisioning.provisionSameAccountDevices(tablet)

        assertEquals(TrustTier.SAME_ACCOUNT, phoneRecords.single().tier)
        assertArrayEquals(
            phoneRecords.single().psk,
            tabletRecords.single().psk
        )
    }
}
