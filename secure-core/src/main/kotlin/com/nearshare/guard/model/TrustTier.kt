package com.nearshare.guard.model

/**
 * 发送方身份的三个信任层级。
 *
 * - [SAME_ACCOUNT]：同一云账号下的自有设备，持有账号配对密钥，最高信任
 * - [CONTACT]：身份密钥在本机通讯录目录中、且通过配对 PSK 验证的熟人
 * - [STRANGER]：以上均不匹配。设备名等自报信息一律不可信
 */
enum class TrustTier {
    SAME_ACCOUNT,
    CONTACT,
    STRANGER
}
