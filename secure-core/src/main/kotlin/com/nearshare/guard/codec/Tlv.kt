package com.nearshare.guard.codec

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * 极简 TLV 编解码：type 为单字节，length 为无符号 VarInt，value 为原始字节。
 * 用于握手信封等不适合 JSON 的定长密码学材料。
 */
object Tlv {

    fun encode(vararg fields: Pair<Byte, ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        for ((type, value) in fields) {
            out.write(type.toInt())
            writeVarInt(out, value.size)
            out.write(value)
        }
        return out.toByteArray()
    }

    fun decode(data: ByteArray): Map<Byte, ByteArray> {
        val input = ByteArrayInputStream(data)
        val result = LinkedHashMap<Byte, ByteArray>()
        while (input.available() > 0) {
            val type = input.read().toByte()
            val length = readVarInt(input)
            val value = ByteArray(length)
            var off = 0
            while (off < length) {
                val n = input.read(value, off, length - off)
                require(n > 0) { "TLV 字段被截断" }
                off += n
            }
            require(!result.containsKey(type)) { "TLV 类型重复: $type" }
            result[type] = value
        }
        return result
    }

    fun writeVarInt(out: ByteArrayOutputStream, value: Int) {
        var v = value
        while (v >= 0x80) {
            out.write((v and 0x7F) or 0x80)
            v = v ushr 7
        }
        out.write(v)
    }

    fun readVarInt(input: ByteArrayInputStream): Int {
        var shift = 0
        var result = 0
        while (true) {
            val b = input.read()
            require(b >= 0) { "VarInt 被截断" }
            result = result or ((b and 0x7F) shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
            require(shift <= 28) { "VarInt 过长" }
        }
    }

    /** u16 大端长度前缀帧，适合 GATT / socket 流式传输。 */
    fun frame(payload: ByteArray): ByteArray {
        require(payload.size <= 0xFFFF) { "帧过长" }
        val out = ByteArrayOutputStream(payload.size + 2)
        out.write(payload.size ushr 8)
        out.write(payload.size and 0xFF)
        out.write(payload)
        return out.toByteArray()
    }

    class FrameReader {
        private val buffer = ByteArrayOutputStream()

        /** 喂入流式数据，每凑成一帧返回一帧，半包留在内部缓冲。 */
        fun feed(chunk: ByteArray): List<ByteArray> {
            buffer.write(chunk)
            val raw = buffer.toByteArray()
            val frames = ArrayList<ByteArray>()
            var pos = 0
            while (pos + 2 <= raw.size) {
                val len = ((raw[pos].toInt() and 0xFF) shl 8) or (raw[pos + 1].toInt() and 0xFF)
                if (pos + 2 + len > raw.size) break
                frames.add(raw.copyOfRange(pos + 2, pos + 2 + len))
                pos += 2 + len
            }
            buffer.reset()
            if (pos < raw.size) buffer.write(raw, pos, raw.size - pos)
            return frames
        }
    }
}
