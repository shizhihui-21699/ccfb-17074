package com.nearshare.guard.discovery

import com.nearshare.guard.crypto.SymmetricCrypto

/**
 * 发现阶段使用的 Bloom 过滤器与私有集合匹配（PSI-CA 风格）原语。
 *
 * 设计要点：
 * 1. 发送方把每个联系人的匹配标签放入 Bloom 过滤器后随广播/扫描响应发出，
 *    不直接发送任何身份公钥、名字或稳定标识；
 * 2. 标签 = HMAC-SHA256(配对 PSK, 会话临时公钥 || 固定域分隔)，
 *    对每个广播周期（临时密钥轮换）都不同，因此被动观察者无法跨周期关联；
 * 3. 接收方用自己目录里的 PSK 逐个计算标签并在过滤器中探测，只有真正持有
 *    同一 PSK 的一方能产生命中，攻击者无法从过滤器反推联系人身份。
 *
 * 误报率参数：预期元素 [expectedInsertions]、目标误报率 [falsePositiveProbability]。
 */
class BloomFilter private constructor(
    private val bitSet: BooleanArray,
    val hashCount: Int,
    val expectedInsertions: Int
) {

    val bitSize: Int get() = bitSet.size

    fun mightContain(tag: ByteArray): Boolean {
        val hashes = doubleHash(tag, hashCount, bitSize)
        return hashes.all { bitSet[it] }
    }

    fun serialize(): ByteArray {
        // 紧凑位图：每字节存 8 个 bit
        val out = ByteArray((bitSize + 7) / 8)
        for (i in bitSet.indices) {
            if (bitSet[i]) out[i / 8] = (out[i / 8].toInt() or (1 shl (7 - (i % 8)))).toByte()
        }
        return out
    }

    companion object {
        /**
         * 标准最优参数：m = -n ln p / (ln2)^2，k = (m/n) ln2。
         */
        fun create(expectedInsertions: Int, falsePositiveProbability: Double = 0.01): BloomFilter {
            require(expectedInsertions >= 0)
            require(falsePositiveProbability in 0.0001..0.5)
            if (expectedInsertions == 0) {
                return BloomFilter(BooleanArray(64), hashCount = 3, expectedInsertions = 0)
            }
            val m = optimalM(expectedInsertions, falsePositiveProbability)
            val k = optimalK(m, expectedInsertions)
            return BloomFilter(BooleanArray(m), k, expectedInsertions)
        }

        fun deserialize(bytes: ByteArray, hashCount: Int, expectedInsertions: Int): BloomFilter {
            val m = bytes.size * 8
            val bits = BooleanArray(m)
            for (i in bits.indices) {
                val b = bytes[i / 8].toInt()
                bits[i] = (b and (1 shl (7 - (i % 8)))) != 0
            }
            return BloomFilter(bits, hashCount, expectedInsertions)
        }

        fun optimalM(n: Int, p: Double): Int {
            val m = -n * Math.log(p) / (Math.log(2.0) * Math.log(2.0))
            return maxOf(64, Math.ceil(m).toInt())
        }

        fun optimalK(m: Int, n: Int): Int =
            maxOf(1, Math.round(m.toDouble() / n * Math.log(2.0)).toInt())

        /**
         * 双哈希（Kirsch–Mitzenmacher）：g_i(x) = h1 + i*h2，由两次 SHA-256 派生。
         */
        fun doubleHash(tag: ByteArray, k: Int, modulus: Int): IntArray {
            val h1 = SymmetricCrypto.sha256(tag, byteArrayOf(0x01))
            val h2 = SymmetricCrypto.sha256(tag, byteArrayOf(0x02))
            val v1 = leUInt(h1)
            val v2 = leUInt(h2)
            val out = IntArray(k)
            for (i in 0 until k) {
                // Long 运算避免 int 溢出
                out[i] = ((v1 + i.toLong() * v2) % modulus).toInt()
            }
            return out
        }

        private fun leUInt(b: ByteArray): Long =
            (b[0].toLong() and 0xFF) or
                ((b[1].toLong() and 0xFF) shl 8) or
                ((b[2].toLong() and 0xFF) shl 16) or
                ((b[3].toLong() and 0xFF) shl 24)
    }

    /** 写入一个标签（仅构建方使用）。 */
    fun put(tag: ByteArray) {
        val hashes = doubleHash(tag, hashCount, bitSize)
        for (h in hashes) bitSet[h] = true
    }
}
