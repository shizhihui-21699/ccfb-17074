package com.nearshare.guard.discovery

import com.nearshare.guard.crypto.AsymmetricCrypto
import com.nearshare.guard.crypto.SymmetricCrypto
import com.nearshare.guard.crypto.X25519KeyPair
import com.nearshare.guard.directory.ContactDirectory
import com.nearshare.guard.model.ContactRecord
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * 协议域分隔常量。所有 HKDF/HMAC 的 info 都带版本前缀，
 * 保证不同协议阶段的密钥域不会复用。
 */
object ProtocolDomains {
    const val VERSION: Byte = 1

    val DISCOVERY_TAG = "NearShareGuard/DiscoveryTag/V1".toByteArray()
    val ENVELOPE_KEY = "NearShareGuard/EnvelopeKey/V1".toByteArray()
    val SESSION_KEY = "NearShareGuard/SessionKey/V1".toByteArray()
    val TRANSPORT_KEY = "NearShareGuard/TransportKey/V1".toByteArray()
    val WIFI_CREDENTIAL = "NearShareGuard/WifiCredential/V1".toByteArray()
}

/**
 * 一次广播周期内的发现材料。
 *
 * @property ephemeralKeyPair 本周期临时 X25519 密钥（每 ~10 分钟轮换）
 * @property bloom 由所有联系人的匹配标签构成的 Bloom 过滤器
 * @property hashCount Bloom 过滤器哈希函数数
 */
class DiscoveryAdvertisement(
    val ephemeralKeyPair: X25519KeyPair,
    val bloom: BloomFilter,
    val hashCount: Int
) {
    /** 上线传输的明文部分：临时公钥 + 位图。不含任何稳定身份信息。 */
    fun toWire(): DiscoveryWire {
        return DiscoveryWire(
            version = ProtocolDomains.VERSION,
            ephemeralPublicKey = ephemeralKeyPair.publicKey,
            bloomBytes = bloom.serialize(),
            hashCount = hashCount
        )
    }
}

/**
 * 发送方（发起发现的一方）的发现逻辑。
 */
class DiscoveryAdvertiser {

    /**
     * 生成一个新的广播周期材料。
     *
     * 标签构造：tag_i = HMAC-SHA256(psk_i, DOMAIN || ephemeralPub)
     * - 同一联系人在不同周期（不同临时公钥）标签完全不同 → 不可跨周期追踪
     * - 不知道 PSK 的攻击者无法生成有效标签，也无法从 Bloom 反推联系人
     */
    fun newAdvertisement(
        contacts: List<ContactRecord>,
        falsePositiveProbability: Double = 0.01
    ): DiscoveryAdvertisement {
        val ephemeral = AsymmetricCrypto.generateX25519KeyPair()
        val bloom = BloomFilter.create(
            expectedInsertions = contacts.size.coerceAtLeast(1),
            falsePositiveProbability = falsePositiveProbability
        )
        for (contact in contacts) {
            bloom.put(matchingTag(contact.psk, ephemeral.publicKey))
        }
        return DiscoveryAdvertisement(ephemeral, bloom, bloom.hashCount)
    }

    /**
     * 接收方回传候选命中标签后，发送方确认哪些命中对应自己真正的联系人，
     * 从而只给已匹配的对端发送身份信封。
     */
    fun resolveMatches(
        contacts: List<ContactRecord>,
        ephemeralPublicKey: ByteArray,
        returnedTags: List<ByteArray>
    ): List<MatchedContact> {
        val byTag = contacts.associateBy { matchingTag(it.psk, ephemeralPublicKey).toList() }
        return returnedTags.mapNotNull { tag ->
            byTag[tag.toList()]?.let { MatchedContact(it, tag) }
        }
    }

    companion object {
        fun matchingTag(psk: ByteArray, ephemeralPublicKey: ByteArray): ByteArray =
            SymmetricCrypto.hmacSha256(
                psk,
                ProtocolDomains.DISCOVERY_TAG + ephemeralPublicKey
            )
    }
}

data class MatchedContact(val contact: ContactRecord, val tag: ByteArray)

/**
 * 接收方（可被发现的一方）的私有匹配逻辑。
 */
class DiscoveryMatcher(private val directory: ContactDirectory) {

    /**
     * 收到对端广播后，用本机目录中每条记录的 PSK 独立探测 Bloom 过滤器。
     * 命中即意味着对端持有与该联系人相同的 PSK（极小概率为 Bloom 误报，
     * 后续信封验签会彻底排除误报）。
     *
     * @return 候选命中，包含可回传给对端的标签；空列表表示对端是陌生人
     */
    fun match(wire: DiscoveryWire): List<MatchCandidate> {
        // 广播字段不可信：限制哈希数与位图大小，防止恶意广播触发超大数组分配
        require(wire.hashCount in 1..MAX_BLOOM_HASH_COUNT) { "Bloom 哈希数越界" }
        require(wire.bloomBytes.size <= MAX_BLOOM_BYTES) { "Bloom 位图超过上限" }
        val bloom = BloomFilter.deserialize(wire.bloomBytes, wire.hashCount, expectedInsertions = 0)
        return directory.allRecords().mapNotNull { record ->
            val tag = DiscoveryAdvertiser.matchingTag(record.psk, wire.ephemeralPublicKey)
            if (bloom.mightContain(tag)) MatchCandidate(record, tag) else null
        }
    }
}

data class MatchCandidate(val record: ContactRecord, val tag: ByteArray)

/** 发现消息体积上限：BLE 广播/扫描响应受限，同时作为抗 DoS 边界。 */
const val MAX_BLOOM_HASH_COUNT = 64
const val MAX_BLOOM_BYTES = 1024

/**
 * 广播/扫描响应的线上编码（明文段）。
 * 序列化为 TLV 风格的紧凑字节，避免依赖 Android Bundle。
 */
data class DiscoveryWire(
    val version: Byte,
    val ephemeralPublicKey: ByteArray,
    val bloomBytes: ByteArray,
    val hashCount: Int
) {
    fun encode(): ByteArray {
        check(ephemeralPublicKey.size == AsymmetricCrypto.X25519_KEY_SIZE)
        val out = java.io.ByteArrayOutputStream()
        out.write(version.toInt())
        out.write(ephemeralPublicKey.size)
        out.write(ephemeralPublicKey)
        out.write(hashCount and 0xFF)
        writeVarInt(out, bloomBytes.size)
        out.write(bloomBytes)
        return out.toByteArray()
    }

    override fun equals(other: Any?): Boolean =
        other is DiscoveryWire && version == other.version &&
            ephemeralPublicKey.contentEquals(other.ephemeralPublicKey) &&
            bloomBytes.contentEquals(other.bloomBytes) && hashCount == other.hashCount

    override fun hashCode(): Int {
        var r = version.toInt()
        r = 31 * r + ephemeralPublicKey.contentHashCode()
        r = 31 * r + bloomBytes.contentHashCode()
        r = 31 * r + hashCount
        return r
    }

    companion object {
        fun decode(data: ByteArray): DiscoveryWire {
            val input = ByteArrayInputStream(data)
            val version = input.read().toByte()
            val keyLen = input.read()
            require(keyLen == AsymmetricCrypto.X25519_KEY_SIZE) { "临时公钥长度非法" }
            val key = readFully(input, keyLen)
            val hashCount = input.read()
            val bloomLen = readVarInt(input)
            val bloom = readFully(input, bloomLen)
            require(input.read() == -1) { "发现消息存在尾随字节" }
            return DiscoveryWire(version, key, bloom, hashCount)
        }

        private fun readFully(input: ByteArrayInputStream, length: Int): ByteArray {
            val buffer = ByteArray(length)
            var off = 0
            while (off < length) {
                val n = input.read(buffer, off, length - off)
                require(n > 0) { "发现消息被截断" }
                off += n
            }
            return buffer
        }

        private fun writeVarInt(out: ByteArrayOutputStream, value: Int) {
            var v = value
            while (v >= 0x80) {
                out.write((v and 0x7F) or 0x80)
                v = v ushr 7
            }
            out.write(v)
        }

        private fun readVarInt(input: ByteArrayInputStream): Int {
            var shift = 0
            var result = 0
            while (true) {
                val b = input.read()
                require(b >= 0) { "VarInt 被截断" }
                result = result or ((b and 0x7F) shl shift)
                if (b and 0x80 == 0) return result
                shift += 7
                require(shift <= 28) { "VarInt 过长" }
            }
        }
    }
}
