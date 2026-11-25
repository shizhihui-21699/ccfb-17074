package com.nearshare.guard.discovery

import com.nearshare.guard.crypto.SymmetricCrypto
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BloomFilterTest {

    @Test
    fun `已插入标签必然命中`() {
        val bloom = BloomFilter.create(expectedInsertions = 100, falsePositiveProbability = 0.01)
        val tags = (0 until 100).map { SymmetricCrypto.hmacSha256("k$it".toByteArray(), "t".toByteArray()) }
        tags.forEach { bloom.put(it) }
        tags.forEach { assertTrue(bloom.mightContain(it)) }
    }

    @Test
    fun `未插入随机标签的误报率接近设计目标`() {
        val n = 500
        val bloom = BloomFilter.create(n, 0.01)
        repeat(n) { bloom.put(SymmetricCrypto.sha256("inserted-$it".toByteArray())) }

        var falsePositives = 0
        val trials = 5_000
        repeat(trials) {
            val probe = SymmetricCrypto.sha256("foreign-$it".toByteArray())
            if (bloom.mightContain(probe)) falsePositives++
        }
        val rate = falsePositives.toDouble() / trials
        // 留足统计裕量：设计 1%，断言不超过 3%
        assertTrue(rate < 0.03, "实际误报率 $rate 超出预期")
    }

    @Test
    fun `位图序列化与反序列化保持一致`() {
        val bloom = BloomFilter.create(50, 0.01)
        val tags = (0 until 50).map { SymmetricCrypto.sha256("x$it".toByteArray()) }
        tags.forEach { bloom.put(it) }

        val restored = BloomFilter.deserialize(bloom.serialize(), bloom.hashCount, 50)
        tags.forEach { assertTrue(restored.mightContain(it)) }
        assertFalse(restored.mightContain(SymmetricCrypto.sha256("absent".toByteArray())))
    }

    @Test
    fun `空过滤器也能正常构建与查询`() {
        val bloom = BloomFilter.create(0)
        assertEquals(64, bloom.bitSize)
        assertFalse(bloom.mightContain(SymmetricCrypto.randomBytes(32)))
    }
}
