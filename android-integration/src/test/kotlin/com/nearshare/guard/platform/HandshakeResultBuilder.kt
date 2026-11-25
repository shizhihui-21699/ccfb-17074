package com.nearshare.guard.platform

import com.nearshare.guard.crypto.SymmetricCrypto
import com.nearshare.guard.handshake.HandshakeResult
import com.nearshare.guard.model.TrustTier

/** 测试用握手结果构造器。 */
object HandshakeResultBuilder {

    private fun base(tier: TrustTier, name: String, authenticated: Boolean) = HandshakeResult(
        sessionKey = SymmetricCrypto.randomBytes(32),
        transcriptHash = SymmetricCrypto.randomBytes(32),
        peerIdentity = null,
        trustTier = tier,
        peerDisplayName = name,
        authenticated = authenticated
    )

    fun stranger() = base(TrustTier.STRANGER, "微风设备-a1b2", authenticated = false)

    fun contact() = base(TrustTier.CONTACT, "老王", authenticated = true)
}
