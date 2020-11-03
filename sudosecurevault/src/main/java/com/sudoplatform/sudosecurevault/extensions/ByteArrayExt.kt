package com.sudoplatform.sudosecurevault.extensions

import kotlin.experimental.xor

fun ByteArray.xor(rhs: ByteArray): ByteArray {
    val bytes = ByteArray(this.size)
    for (i in this.indices) bytes[i] = this[i].xor(rhs[i])
    return bytes
}