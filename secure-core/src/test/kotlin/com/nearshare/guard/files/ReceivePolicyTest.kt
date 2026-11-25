package com.nearshare.guard.files

import com.nearshare.guard.model.TrustTier
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ReceivePolicyTest {

    private val policy = ReceivePolicy()

    // 常见文件头样本
    private val pngHeader = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A)
    private val pdfHeader = "%PDF-1.7".toByteArray()
    private val apkZipHeader = byteArrayOf(0x50, 0x4B, 0x03, 0x04) // ZIP/APK 共同魔数
    private val elfHeader = byteArrayOf(0x7F, 0x45, 0x4C, 0x46)
    private val dexHeader = "dex\n035".toByteArray()
    private val peHeader = "MZ".toByteArray() + ByteArray(2)
    private val scriptHeader = "#!/system/bin/sh\n".toByteArray()

    @Test
    fun `陌生人发送 APK 被直接拦截`() {
        // 场景一：DEX 魔数直接暴露
        val dexDetection = FileTypeDetector.sniff(dexHeader, "资料.pdf")
        assertTrue(dexDetection.executable)
        assertFalse(policy.evaluate(TrustTier.STRANGER, dexDetection, 1024).allowed)

        // 场景二：真实攻击——ZIP 容器的 APK 改名为 .pdf
        val apkDetection = FileTypeDetector.detect(
            apkZipHeader,
            declaredName = "合同.pdf",
            zipEntryNames = listOf("AndroidManifest.xml", "classes.dex", "resources.arsc")
        )
        assertEquals(FileCategory.ANDROID_PACKAGE, apkDetection.category)
        assertTrue(apkDetection.executable)
        val apkDecision = policy.evaluate(TrustTier.STRANGER, apkDetection, 1024)
        assertFalse(apkDecision.allowed)
        assertTrue(apkDecision.warnings.any { it.contains("拦截") })
    }

    @Test
    fun `普通 ZIP 不会被误判为 APK`() {
        val zipDetection = FileTypeDetector.detect(
            apkZipHeader,
            declaredName = "backup.zip",
            zipEntryNames = listOf("photos/a.jpg", "docs/notes.txt")
        )
        assertEquals(FileCategory.ARCHIVE, zipDetection.category)
        assertFalse(zipDetection.executable)
    }

    @Test
    fun `陌生人发送 ELF 可执行文件被拦截`() {
        val detection = FileTypeDetector.sniff(elfHeader, "update.bin")
        assertTrue(detection.executable)
        assertFalse(policy.evaluate(TrustTier.STRANGER, detection, 1024).allowed)
    }

    @Test
    fun `陌生人发送 PE 程序和脚本均被拦截`() {
        assertFalse(policy.evaluate(TrustTier.STRANGER, FileTypeDetector.sniff(peHeader, "x.exe"), 10).allowed)
        assertFalse(policy.evaluate(TrustTier.STRANGER, FileTypeDetector.sniff(scriptHeader, "x.sh"), 10).allowed)
    }

    @Test
    fun `陌生人发图片只给模糊预览并隔离`() {
        val detection = FileTypeDetector.sniff(pngHeader, "photo.png")
        val decision = policy.evaluate(TrustTier.STRANGER, detection, 2048)
        assertTrue(decision.allowed)
        assertEquals(PreviewMode.BLURRED, decision.previewMode)
        assertTrue(decision.quarantine)
        assertTrue(decision.requireExplicitConsent)
    }

    @Test
    fun `陌生人发普通文档不生成预览`() {
        val detection = FileTypeDetector.sniff(pdfHeader, "doc.pdf")
        val decision = policy.evaluate(TrustTier.STRANGER, detection, 2048)
        assertTrue(decision.allowed)
        assertEquals(PreviewMode.HIDDEN, decision.previewMode)
    }

    @Test
    fun `联系人发可执行文件需要二次确认并隔离`() {
        val detection = FileTypeDetector.sniff(dexHeader, "tool.dex")
        val decision = policy.evaluate(TrustTier.CONTACT, detection, 4096)
        assertTrue(decision.allowed)
        assertTrue(decision.requireExplicitConsent)
        assertTrue(decision.quarantine)
        assertEquals(PreviewMode.NORMAL, decision.previewMode)
    }

    @Test
    fun `同账号设备发可执行文件允许但提示风险`() {
        val detection = FileTypeDetector.sniff(elfHeader, "binary.so")
        val decision = policy.evaluate(TrustTier.SAME_ACCOUNT, detection, 4096)
        assertTrue(decision.allowed)
        assertTrue(decision.requireExplicitConsent)
        assertFalse(decision.quarantine)
    }

    @Test
    fun `扩展名伪装在陌生人通道直接拒绝`() {
        // 真实内容是 PNG，却命名成 .pdf
        val detection = FileTypeDetector.sniff(pngHeader, "会议纪要.pdf")
        assertTrue(detection.extensionMismatch)
        assertFalse(policy.evaluate(TrustTier.STRANGER, detection, 1024).allowed)
    }

    @Test
    fun `扩展名伪装在联系人通道强警告但不直接拒绝`() {
        val detection = FileTypeDetector.sniff(pngHeader, "会议纪要.pdf")
        val decision = policy.evaluate(TrustTier.CONTACT, detection, 1024)
        assertTrue(decision.allowed)
        assertTrue(decision.warnings.any { it.contains("伪装") })
    }

    @Test
    fun `陌生人文件超过大小上限被拒绝`() {
        val detection = FileTypeDetector.sniff(pdfHeader, "big.pdf")
        val policy = ReceivePolicy(maxStrangerFileBytes = 1024)
        assertFalse(policy.evaluate(TrustTier.STRANGER, detection, 4096).allowed)
    }

    @Test
    fun `魔数嗅探识别常见媒体与文档格式`() {
        assertEquals(FileCategory.IMAGE, FileTypeDetector.sniff(pngHeader, null).category)
        assertEquals(FileCategory.PDF, FileTypeDetector.sniff(pdfHeader, null).category)
        assertEquals(
            FileCategory.IMAGE,
            FileTypeDetector.sniff(byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte()), null).category
        )
        val mp4 = ByteArray(12)
        mp4[4] = 'f'.code.toByte(); mp4[5] = 't'.code.toByte()
        mp4[6] = 'y'.code.toByte(); mp4[7] = 'p'.code.toByte()
        assertEquals(FileCategory.VIDEO, FileTypeDetector.sniff(mp4, null).category)
    }

    @Test
    fun `APK 识别依据 ZIP 内特征条目而非扩展名`() {
        assertTrue(
            FileTypeDetector.identifyApk(listOf("AndroidManifest.xml", "classes.dex", "res/icon.png"))
        )
        assertFalse(
            FileTypeDetector.identifyApk(listOf("doc/document.xml", "[Content_Types].xml"))
        )
    }
}
