package com.nearshare.guard.directory

import com.nearshare.guard.model.ContactRecord
import com.nearshare.guard.model.TrustTier

/**
 * 本机可信联系人/同账号设备目录。
 *
 * 目录数据是离线可用的：所有验证材料（身份公钥 + 配对 PSK）在配对阶段
 * 就已经存放在本机，握手全程不需要联网查询。
 */
class ContactDirectory(records: List<ContactRecord> = emptyList()) {

    private val byIdentity = HashMap<ByteArray, ContactRecord>(records.size * 2)
    private val all: List<ContactRecord> = records

    init {
        for (record in records) {
            byIdentity[record.identityPublicKey.copyOf()] = record
        }
    }

    fun allRecords(): List<ContactRecord> = all

    fun size(): Int = all.size

    /** 按身份公钥精确查找；找不到返回 null（即陌生人）。 */
    fun findByIdentity(identityPublicKey: ByteArray): ContactRecord? =
        byIdentity.entries.firstOrNull { it.key.contentEquals(identityPublicKey) }?.value

    fun sameAccountDevices(): List<ContactRecord> =
        all.filter { it.tier == TrustTier.SAME_ACCOUNT }

    fun contacts(): List<ContactRecord> =
        all.filter { it.tier == TrustTier.CONTACT }
}
