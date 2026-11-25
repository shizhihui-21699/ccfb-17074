package com.nearshare.guard.model

import kotlinx.serialization.Serializable

/**
 * 通讯录中的一条可信联系人记录。
 *
 * @property contactId 业务侧联系人 ID（与系统通讯录关联），不参与协议
 * @property displayName 本机存储的显示名，仅用于接收 UI；设备自身广播的名字不可信
 * @property identityPublicKey 对端 Ed25519 身份公钥
 * @property psk 配对阶段（面对面扫码或 E2EE 通道）协商出的 32 字节成对预共享密钥
 * @property tier 普通联系人或同账号设备
 */
@Serializable
data class ContactRecord(
    val contactId: String,
    val displayName: String,
    val identityPublicKey: ByteArray,
    val psk: ByteArray,
    val tier: TrustTier = TrustTier.CONTACT
) {
    override fun equals(other: Any?): Boolean =
        other is ContactRecord &&
            contactId == other.contactId &&
            identityPublicKey.contentEquals(other.identityPublicKey) &&
            psk.contentEquals(other.psk) &&
            tier == other.tier

    override fun hashCode(): Int {
        var result = contactId.hashCode()
        result = 31 * result + identityPublicKey.contentHashCode()
        result = 31 * result + psk.contentHashCode()
        result = 31 * result + tier.hashCode()
        return result
    }
}
