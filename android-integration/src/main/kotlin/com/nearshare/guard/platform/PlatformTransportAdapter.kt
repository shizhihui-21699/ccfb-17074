package com.nearshare.guard.platform

import com.nearshare.guard.transport.SecureTransport
import java.util.concurrent.LinkedBlockingDeque

/**
 * 把平台 [WifiDirectStack.ReliableByteChannel] 或 GATT 连接适配为
 * secure-core 需要的 [SecureTransport]。
 *
 * 帧定界约定：平台实现写入的每个 payload 即一帧（u16 长度前缀由平台
 * 在 socket 层处理，或在此统一封装）。这里提供阻塞式队列桥接，
 * 使握手/加密通道代码完全不感知底层是 BLE 还是 Wi-Fi。
 */
class PlatformTransportAdapter(
    private val writer: (ByteArray) -> Unit,
    private val closer: () -> Unit = {}
) : SecureTransport {

    private val inbound = LinkedBlockingDeque<ByteArray>()

    /** 平台回调线程在收到完整一帧时调用。 */
    fun onFrame(frame: ByteArray) {
        inbound.put(frame.copyOf())
    }

    override fun sendFrame(payload: ByteArray) = writer(payload)

    override fun receiveFrame(): ByteArray? =
        try {
            inbound.pollFirst(30, java.util.concurrent.TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        }

    override fun close() = closer()
}
