package com.nearshare.guard.files

import com.nearshare.guard.crypto.SymmetricCrypto
import com.nearshare.guard.model.TrustTier
import com.nearshare.guard.transport.SecureChannel
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.ByteArrayOutputStream

/**
 * 单个文件传输的接收端校验状态。
 */
data class IncomingFile(
    val manifestEntry: FileManifestEntry,
    val detection: FileDetection,
    val decision: ReceiveDecision
)

/**
 * 基于加密通道的文件接收会话（接收方视角）。
 *
 * 协议（每条消息都是 [SecureChannel] 的一条 AEAD 帧，JSON 编解码）：
 *   1. 发送方 → 接收方：FileManifest（文件名/大小/哈希/声明 MIME）
 *   2. 接收方本地做策略评估，拒绝的条目立即回 RejectNotice 并终止；
 *   3. 发送方按条目分块发送文件内容（二进制帧），接收方边收边算 SHA-256；
 *   4. 哈希与清单不一致即拒绝并标记污染。
 *
 * 接收侧的核心安全动作：先嗅探文件头、再按信任层级套用 [ReceivePolicy]，
 * 任何可执行文件在陌生人通道都不会落盘。
 */
class FileReceiveSession(
    private val channel: SecureChannel,
    private val tier: TrustTier,
    private val policy: ReceivePolicy = ReceivePolicy(),
    private val maxChunkSize: Int = 64 * 1024
) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    /**
     * 阻塞处理一次完整的文件批次。
     * @return 被策略允许、且哈希校验通过的文件（已在内存中；Android 层据此落隔离区）
     */
    fun receiveBatch(): List<ReceivedFile> {
        val manifestRaw = channel.receive()
            ?: throw FileTransferException("等待清单时通道关闭")
        val manifest = json.decodeFromString<FileManifest>(manifestRaw.decodeToString())

        val accepted = ArrayList<IncomingFile>()
        for (entry in manifest.entries) {
            // 先取前 16 字节做魔数嗅探：需要发送方先给文件头。
            // 协议约定：清单之后、内容之前，对每个条目先发一个 16B 嗅探头帧。
            val header = channel.receive()
                ?: throw FileTransferException("等待文件头时通道关闭")
            require(header.size <= FileTypeDetector.SNIFF_HEADER_SIZE) { "嗅探头超长" }
            val detection = FileTypeDetector.sniff(header, entry.fileName)
            val decision = policy.evaluate(tier, detection, entry.sizeBytes)

            if (!decision.allowed) {
                channel.send(
                    json.encodeToString(
                        RejectNotice(entry.fileName, decision.warnings)
                    ).encodeToByteArray()
                )
                throw FileTransferException(
                    "文件「${entry.fileName}」被接收策略拦截：${decision.warnings.joinToString("；")}"
                )
            }
            channel.send(json.encodeToString(AcceptNotice(entry.fileName)).encodeToByteArray())
            accepted += IncomingFile(entry, detection, decision)
        }

        // 策略全部通过后再接收内容，避免被拒文件白占带宽与磁盘
        return accepted.map { incoming ->
            streamFile(incoming)
        }
    }

    private fun streamFile(incoming: IncomingFile): ReceivedFile {
        val entry = incoming.manifestEntry
        val sink = ByteArrayOutputStream()
        var remaining = entry.sizeBytes

        while (remaining > 0) {
            val chunk = channel.receive()
                ?: throw FileTransferException("文件内容传输中断：${entry.fileName}")
            require(chunk.size <= maxChunkSize) { "数据块超过上限" }
            sink.write(chunk)
            remaining -= chunk.size
            if (remaining < 0) {
                throw FileTransferException("文件实际大小超过清单声明：${entry.fileName}")
            }
        }
        val bytes = sink.toByteArray()
        val actualHash = SymmetricCrypto.sha256(bytes)
        if (!actualHash.contentEquals(entry.sha256)) {
            throw FileTransferException("文件哈希与清单不一致，内容可能被篡改：${entry.fileName}")
        }
        return ReceivedFile(
            fileName = entry.fileName,
            bytes = bytes,
            detection = incoming.detection,
            decision = incoming.decision
        )
    }
}

/**
 * 发送方视角：先推清单与嗅探头、等待接收方逐文件同意，再流式发送内容。
 */
class FileSendSession(private val channel: SecureChannel) {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val maxChunkSize = 64 * 1024

    fun sendBatch(files: List<OutgoingFile>) {
        val manifest = FileManifest(files.map { it.entry })
        channel.send(json.encodeToString(manifest).encodeToByteArray())

        for (file in files) {
            val header = file.bytes.copyOfRange(
                0,
                minOf(FileTypeDetector.SNIFF_HEADER_SIZE, file.bytes.size)
            )
            channel.send(header)
            val decisionRaw = channel.receive()
                ?: throw FileTransferException("等待接收方策略决定时通道关闭")
            val notice = runCatching {
                json.decodeFromString<RejectNotice>(decisionRaw.decodeToString())
            }.getOrNull()
            if (notice != null) {
                throw FileTransferException(
                    "接收方拒绝了「${file.entry.fileName}」：${notice.reasons.joinToString("；")}"
                )
            }
            // 内容分块
            var off = 0
            while (off < file.bytes.size) {
                val end = minOf(off + maxChunkSize, file.bytes.size)
                channel.send(file.bytes.copyOfRange(off, end))
                off = end
            }
        }
    }
}

data class OutgoingFile(val entry: FileManifestEntry, val bytes: ByteArray) {
    override fun equals(other: Any?): Boolean =
        other is OutgoingFile && entry == other.entry && bytes.contentEquals(other.bytes)
    override fun hashCode(): Int = 31 * entry.hashCode() + bytes.contentHashCode()
}

data class ReceivedFile(
    val fileName: String,
    val bytes: ByteArray,
    val detection: FileDetection,
    val decision: ReceiveDecision
) {
    override fun equals(other: Any?): Boolean =
        other is ReceivedFile && fileName == other.fileName && bytes.contentEquals(other.bytes)
    override fun hashCode(): Int = 31 * fileName.hashCode() + bytes.contentHashCode()
}

@kotlinx.serialization.Serializable
data class RejectNotice(val rejectedFile: String, val reasons: List<String>)

@kotlinx.serialization.Serializable
data class AcceptNotice(val acceptedFile: String)

class FileTransferException(message: String) : Exception(message)
