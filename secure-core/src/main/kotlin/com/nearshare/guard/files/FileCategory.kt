package com.nearshare.guard.files

/**
 * 按风险归类的文件类别。分类依据是内容魔数，不是文件扩展名。
 */
enum class FileCategory(val displayName: String, val executable: Boolean) {
    IMAGE("图片", false),
    VIDEO("视频", false),
    AUDIO("音频", false),
    PDF("PDF 文档", false),
    OFFICE_DOCUMENT("办公文档", false),
    ARCHIVE("压缩包", false),
    ANDROID_PACKAGE("安卓安装包", true),
    ELF_EXECUTABLE("ELF 可执行文件", true),
    PE_EXECUTABLE("Windows 可执行文件", true),
    SHELL_SCRIPT("脚本文件", true),
    GENERIC("其它文件", false);

    companion object {
        val EXECUTABLE_CATEGORIES = entries.filter { it.executable }.toSet()
    }
}
