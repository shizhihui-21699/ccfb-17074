package com.nearshare.guard.platform

import com.nearshare.guard.crypto.AsymmetricCrypto
import com.nearshare.guard.directory.ContactDirectory
import com.nearshare.guard.model.ContactRecord
import com.nearshare.guard.model.IdentityBundle
import com.nearshare.guard.model.LocalIdentity
import com.nearshare.guard.model.TrustTier

/**
 * 系统数据源适配接口。真实 Android 实现分别对接：
 * - [ContactSource]：系统通讯录 + 应用内置的配对记录存储（Room/EncryptedSharedPreferences）
 * - [AccountSource]：账号服务下发的同账号设备清单（仅在有网时同步一次，近场验证离线）
 */
interface ContactSource {
    /** 返回所有已配对联系人的可信记录（身份公钥 + PSK）。 */
    fun loadPairedContacts(): List<ContactRecord>
}

interface AccountSource {
    fun loadSameAccountDevices(): List<ContactRecord>
}

/**
 * 本地身份保管接口。生产实现应使用 Android Keystore（优先 StrongBox）：
 * - Ed25519/X25519 私钥在 Keystore 内生成且不可导出；
 * - 若 Keystore 不支持这两种算法，则落库到加密存储并绑定硬件认证。
 * 这里抽象出来，使核心协议可在纯 JVM 上测试。
 */
interface IdentityVault {
    fun loadOrCreateLocalIdentity(): LocalIdentity
}

/** 测试/演示用内存身份库。 */
class InMemoryIdentityVault : IdentityVault {
    private val identity: LocalIdentity by lazy {
        val ed = AsymmetricCrypto.generateEd25519KeyPair()
        val x = AsymmetricCrypto.generateX25519KeyPair()
        LocalIdentity(ed.publicKey, ed.privateKey, x.publicKey, x.privateKey)
    }
    override fun loadOrCreateLocalIdentity(): LocalIdentity = identity
}

/** 聚合两个来源，构建接收侧使用的可信目录。 */
class DirectoryProvider(
    private val contactSource: ContactSource,
    private val accountSource: AccountSource
) {
    fun buildDirectory(): ContactDirectory {
        val records = ArrayList<ContactRecord>()
        records += accountSource.loadSameAccountDevices().onEach {
            check(it.tier == TrustTier.SAME_ACCOUNT) { "同账号来源层级标记错误" }
        }
        records += contactSource.loadPairedContacts()
        // 以身份公钥去重，同账号优先
        val dedup = LinkedHashMap<String, ContactRecord>()
        for (record in records) {
            val key = record.identityPublicKey.joinToString("") { "%02x".format(it) }
            dedup.putIfAbsent(key, record)
        }
        return ContactDirectory(dedup.values.toList())
    }
}
