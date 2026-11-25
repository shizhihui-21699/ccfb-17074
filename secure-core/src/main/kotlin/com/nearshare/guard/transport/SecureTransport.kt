package com.nearshare.guard.transport

/**
 * 有序、可靠的双向字节流抽象。
 *
 * BLE GATT 实现可用通知/指示 + 写特征封装；Wi-Fi Direct 实现可直接套 socket。
 * 握手层只依赖该接口，因此纯 JVM 测试可以用内存管道完整跑通协议。
 */
interface SecureTransport {
    /** 阻塞写入一帧（实现方负责分片与重组）。 */
    fun sendFrame(payload: ByteArray)

    /** 阻塞读取下一帧。连接关闭时返回 null。 */
    fun receiveFrame(): ByteArray?

    fun close()
}

/**
 * 内存双工管道，用于单元测试与协议演示。两个端点互为对端。
 */
class InMemorySecureTransport private constructor(
    private val inbound: java.util.concurrent.LinkedBlockingDeque<ByteArray>,
    private val outbound: java.util.concurrent.LinkedBlockingDeque<ByteArray>
) : SecureTransport {

    constructor() : this(
        java.util.concurrent.LinkedBlockingDeque(),
        java.util.concurrent.LinkedBlockingDeque()
    )

    fun peer(): InMemorySecureTransport = InMemorySecureTransport(outbound, inbound)

    override fun sendFrame(payload: ByteArray) {
        outbound.put(payload.copyOf())
    }

    override fun receiveFrame(): ByteArray? =
        try {
            inbound.pollFirst(5, java.util.concurrent.TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        }

    override fun close() {
        // 内存管道无资源需要释放
    }
}
