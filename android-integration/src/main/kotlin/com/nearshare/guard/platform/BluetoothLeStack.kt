package com.nearshare.guard.platform

/**
 * 蓝牙 BLE 协议栈适配接口（真实实现由 Android 模块提供）。
 *
 * 隐私约束（必须在实现中遵守）：
 * - 广播载荷只承载 [com.nearshare.guard.discovery.DiscoveryWire] 的编码字节，
 *   不得加入设备名、MAC、厂商自定义稳定 ID；
 * - 优先使用 BLE 随机可解析私有地址（RPA），并与发现周期同步轮换；
 * - 广播周期建议 8–10 分钟，到期同时轮换临时 X25519 密钥与 RPA。
 */
interface BluetoothLeStack {

    /** 开始按给定原始字节广播（调用方即 DiscoveryWire.encode() 的结果）。 */
    fun startAdvertising(payload: ByteArray)

    fun stopAdvertising()

    /** 扫描附近广播，每条结果回调一次原始字节（DiscoveryWire）与信号强度。 */
    fun startScanning(onDiscovered: (payload: ByteArray, rssiDbm: Int) -> Unit)

    fun stopScanning()

    /**
     * 发现匹配后建立面向连接的 GATT 通道所需的信息。
     * 返回的 [GattConnection] 需适配为 secure-core 的 SecureTransport。
     */
    fun connect(advertisementPayload: ByteArray): GattConnection
}

/** BLE GATT 连接的最小抽象，真实实现负责 MTU 分片与通知重组。 */
interface GattConnection {
    fun write(payload: ByteArray)
    fun onRead(callback: (ByteArray) -> Unit)
    fun close()
}
