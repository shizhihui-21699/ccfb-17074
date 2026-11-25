package com.nearshare.guard.platform

/**
 * Wi-Fi Direct（Wi-Fi P2P）适配接口。
 *
 * 安全要点：网络凭据（SSID/通行短语）不是协商出来再明文发送的，
 * 而是握手完成后由双方会话密钥各自独立派生（见 HandshakeResult.wifiCredentials），
 * 因此带外监听者无法获知或劫持该热点。
 */
interface WifiDirectStack {

    /** 用握手派生凭据创建群组/热点，等待对端加入。 */
    fun createGroup(ssid: String, passphrase: String): GroupHandle

    /** 加入对端创建的群组。 */
    fun joinGroup(ssid: String, passphrase: String): GroupHandle

    interface GroupHandle {
        /** 群组就绪后，返回用于文件传输的有序可靠字节流端点。 */
        fun openReliableChannel(): ReliableByteChannel
        fun close()
    }

    /** 对应 secure-core 的 SecureTransport，实现负责帧定界。 */
    interface ReliableByteChannel {
        fun sendFrame(payload: ByteArray)
        fun receiveFrame(): ByteArray?
        fun close()
    }
}
