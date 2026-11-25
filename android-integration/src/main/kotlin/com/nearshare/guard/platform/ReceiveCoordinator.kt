package com.nearshare.guard.platform

import com.nearshare.guard.directory.ContactDirectory
import com.nearshare.guard.discovery.DiscoveryMatcher
import com.nearshare.guard.discovery.DiscoveryWire
import com.nearshare.guard.files.FileDetection
import com.nearshare.guard.files.ReceiveDecision
import com.nearshare.guard.handshake.HandshakeProtocol
import com.nearshare.guard.handshake.HandshakeResult
import com.nearshare.guard.model.TrustTier
import com.nearshare.guard.transport.SecureTransport

/**
 * 接收侧编排器：把发现匹配、握手、信任判定按安全顺序串起来。
 *
 * 它不含任何 Android API，所有平台差异通过构造参数注入，便于单测与审计。
 */
class ReceiveCoordinator(
    private val identityVault: IdentityVault,
    private val directoryProvider: DirectoryProvider,
    private val localDisplayName: String
) {
    /**
     * 收到一条 BLE 广播后的处理结果。
     */
    fun onAdvertisement(payload: ByteArray): DiscoveryOutcome {
        val wire = try {
            DiscoveryWire.decode(payload)
        } catch (e: Exception) {
            return DiscoveryOutcome.Malformed
        }
        val directory = directoryProvider.buildDirectory()
        val candidates = DiscoveryMatcher(directory).match(wire)
        return if (candidates.isEmpty()) {
            DiscoveryOutcome.Stranger(wire)
        } else {
            // Bloom 可能误报：命中的第一条作为候选，最终以握手信封验签为准
            DiscoveryOutcome.KnownCandidate(wire, candidates.first().record)
        }
    }

    /**
     * 在已建立的 [transport] 上完成响应方握手。
     * @param match 发现阶段候选；陌生人传 null
     */
    fun performHandshake(transport: SecureTransport, match: com.nearshare.guard.model.ContactRecord?): HandshakeResult {
        val identity = identityVault.loadOrCreateLocalIdentity()
        val directory = directoryProvider.buildDirectory()
        return HandshakeProtocol(identity, localDisplayName)
            .respond(transport, directory, match)
    }

    companion object {
        /**
         * 把信任层级 + 文件策略转成 UI 可直接渲染的卡片模型。
         * 这是"陌生人模糊预览、可执行文件受限"需求的统一出口。
         */
        fun toUiCard(result: HandshakeResult, detection: FileDetection, decision: ReceiveDecision): IncomingFileCard =
            IncomingFileCard(
                trustTier = result.trustTier,
                authenticated = result.authenticated,
                senderLabel = result.peerDisplayName,
                showVerifiedBadge = result.trustTier != TrustTier.STRANGER,
                previewMode = decision.previewMode,
                blocked = !decision.allowed,
                quarantined = decision.quarantine,
                requireManualOpen = decision.requireExplicitConsent,
                warnings = decision.warnings
            )
    }

    sealed interface DiscoveryOutcome {
        /** 协议格式非法，直接忽略，不弹窗（防广播洪泛骚扰）。 */
        data object Malformed : DiscoveryOutcome

        /** 未匹配到任何可信联系人：按陌生人处理，默认不主动通知。 */
        data class Stranger(val wire: DiscoveryWire) : DiscoveryOutcome

        /** 命中候选，等待连接后用握手验签确认。 */
        data class KnownCandidate(
            val wire: DiscoveryWire,
            val match: com.nearshare.guard.model.ContactRecord
        ) : DiscoveryOutcome
    }
}

/**
 * 接收卡片 UI 模型。真实 Android 用 Compose 渲染，字段语义在此固定。
 */
data class IncomingFileCard(
    val trustTier: TrustTier,
    val authenticated: Boolean,
    val senderLabel: String,
    val showVerifiedBadge: Boolean,
    val previewMode: com.nearshare.guard.files.PreviewMode,
    val blocked: Boolean,
    val quarantined: Boolean,
    val requireManualOpen: Boolean,
    val warnings: List<String>
)
