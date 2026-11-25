package com.nearshare.guard.files

import com.nearshare.guard.model.TrustTier
import kotlinx.serialization.Serializable

/**
 * 发送方在传文件前必须先发送的清单（走加密通道，AEAD 保护）。
 * 接收方依据清单 + 实际嗅探结果决定是否接收，防止文件名欺诈与类型伪装。
 */
@Serializable
data class FileManifestEntry(
    val fileName: String,
    val sizeBytes: Long,
    val sha256: ByteArray,
    val declaredMimeType: String?
) {
    override fun equals(other: Any?): Boolean =
        other is FileManifestEntry && fileName == other.fileName &&
            sizeBytes == other.sizeBytes && sha256.contentEquals(other.sha256)

    override fun hashCode(): Int {
        var result = fileName.hashCode()
        result = 31 * result + sizeBytes.hashCode()
        result = 31 * result + sha256.contentHashCode()
        return result
    }
}

@Serializable
data class FileManifest(val entries: List<FileManifestEntry>)

/**
 * 接收 UI 的展示方式。
 */
enum class PreviewMode {
    /** 正常展示缩略图与文件名（熟人/同账号）。 */
    NORMAL,

    /** 模糊缩略图 + 隐藏文件名细节，必须用户主动点击"仍要查看"才揭开。 */
    BLURRED,

    /** 不生成任何缩略图，只显示风险提示。 */
    HIDDEN
}

/**
 * 接收策略对单个文件的判定。
 */
data class ReceiveDecision(
    val allowed: Boolean,
    val previewMode: PreviewMode,
    val quarantine: Boolean,
    val warnings: List<String>,
    val requireExplicitConsent: Boolean
)

/**
 * 三档信任接收策略（离线生效，纯本地规则）。
 *
 * | 层级        | 可执行文件       | 图片预览 | 扩展名伪装 | 落盘位置       |
 * |------------|-----------------|---------|-----------|---------------|
 * | 同账号      | 允许，正常提示   | 正常    | 强警告     | 正常目录       |
 * | 通讯录熟人  | 允许，二次确认   | 正常    | 强警告     | 正常目录       |
 * | 陌生人      | 一律拒绝         | 模糊    | 直接拒绝   | 仅隔离区(若允许)|
 */
class ReceivePolicy(
    private val maxStrangerFileBytes: Long = 50L * 1024 * 1024
) {

    fun evaluate(
        tier: TrustTier,
        detection: FileDetection,
        sizeBytes: Long
    ): ReceiveDecision {
        val warnings = mutableListOf<String>()

        // 陌生人 + 可执行文件：最高优先级直接拦截（无论是否同时存在伪装）
        if (tier == TrustTier.STRANGER && detection.executable) {
            warnings += "陌生人发送的可执行文件「${detection.category.displayName}」已被系统拦截"
            return reject(warnings)
        }

        // 扩展名与真实类型不一致：所有层级都强警告，陌生人直接拒绝
        if (detection.extensionMismatch) {
            warnings += "文件扩展名 .${detection.declaredExtension ?: "?"} 与真实内容类型" +
                "「${detection.category.displayName}」不一致，存在伪装风险"
            if (tier == TrustTier.STRANGER) {
                return reject(warnings)
            }
        }

        return when (tier) {
            TrustTier.SAME_ACCOUNT -> sameAccountPolicy(detection, warnings)
            TrustTier.CONTACT -> contactPolicy(detection, warnings)
            TrustTier.STRANGER -> strangerPolicy(detection, sizeBytes, warnings)
        }
    }

    private fun sameAccountPolicy(
        detection: FileDetection,
        warnings: List<String>
    ): ReceiveDecision {
        val consent = detection.executable
        return ReceiveDecision(
            allowed = true,
            previewMode = PreviewMode.NORMAL,
            quarantine = false,
            warnings = warnings + if (detection.executable)
                listOf("可执行文件「${detection.category.displayName}」，打开前请确认来源") else emptyList(),
            requireExplicitConsent = consent
        )
    }

    private fun contactPolicy(
        detection: FileDetection,
        warnings: List<String>
    ): ReceiveDecision {
        val extra = if (detection.executable) {
            listOf("可执行文件「${detection.category.displayName}」来自联系人，仍需手动确认后才能打开")
        } else emptyList()
        return ReceiveDecision(
            allowed = true,
            previewMode = PreviewMode.NORMAL,
            quarantine = detection.executable,
            warnings = warnings + extra,
            requireExplicitConsent = detection.executable
        )
    }

    private fun strangerPolicy(
        detection: FileDetection,
        sizeBytes: Long,
        warnings: MutableList<String>
    ): ReceiveDecision {
        // 1. 可执行文件一律拒绝（APK/DEX/ELF/PE/脚本）
        if (detection.executable) {
            warnings += "陌生人发送的可执行文件已被系统拦截"
            return reject(warnings)
        }
        // 2. 大小限制
        if (sizeBytes > maxStrangerFileBytes) {
            warnings += "文件超过陌生人接收上限 ${maxStrangerFileBytes / 1024 / 1024}MB"
            return reject(warnings)
        }
        // 3. 图片模糊预览（对抗不雅图片社工）；非图片不生成预览
        val preview = if (detection.category == FileCategory.IMAGE) PreviewMode.BLURRED
        else PreviewMode.HIDDEN
        warnings += "来自未验证的陌生人设备，文件已隔离存放，不会自动打开"
        return ReceiveDecision(
            allowed = true,
            previewMode = preview,
            quarantine = true,
            warnings = warnings,
            requireExplicitConsent = true
        )
    }

    private fun reject(warnings: List<String>): ReceiveDecision =
        ReceiveDecision(
            allowed = false,
            previewMode = PreviewMode.HIDDEN,
            quarantine = true,
            warnings = warnings,
            requireExplicitConsent = true
        )
}
