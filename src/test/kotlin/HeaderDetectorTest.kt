package org.iotsplab.akiba.process

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * Header parsing has no dependencies beyond the bytes, so every format is
 * exercised with a hand-built header: a real binary would make the test depend
 * on the build machine's toolchain.
 */
class HeaderDetectorTest {

    private fun tempFile(bytes: ByteArray): Path {
        val dir = createTempDirectory("akiba-arch-test")
        val file = dir.resolve("sample.bin")
        Files.write(file, bytes)
        return file
    }

    /** ELF64 little-endian, e_machine = 0x3E (x86-64). */
    @Test
    fun `reads the elf machine field`() {
        val header = ByteArray(64)
        header[0] = 0x7F
        header[1] = 'E'.code.toByte()
        header[2] = 'L'.code.toByte()
        header[3] = 'F'.code.toByte()
        header[4] = 2            // ELFCLASS64
        header[5] = 1            // little endian
        header[18] = 0x3E        // EM_X86_64
        val result = HeaderDetector.detect(tempFile(header))
        assertEquals("x86:LE:64:default", result?.languageId)
        assertEquals("Executable and Linking Format (ELF)", result?.format)
    }

    /** ELF32 big-endian, e_machine = 0x08 (MIPS). */
    @Test
    fun `honours big endian elf headers`() {
        val header = ByteArray(64)
        header[0] = 0x7F
        header[1] = 'E'.code.toByte()
        header[2] = 'L'.code.toByte()
        header[3] = 'F'.code.toByte()
        header[4] = 1            // ELFCLASS32
        header[5] = 2            // big endian
        header[18] = 0x00
        header[19] = 0x08        // EM_MIPS
        val result = HeaderDetector.detect(tempFile(header))
        assertEquals("MIPS:BE:32:R6", result?.languageId)
    }

    /** PE32+, COFF machine = 0x8664 (AMD64). */
    @Test
    fun `reads the pe machine field`() {
        val header = ByteArray(256)
        header[0] = 'M'.code.toByte()
        header[1] = 'Z'.code.toByte()
        header[0x3C] = 0x80.toByte()
        header[0x80] = 'P'.code.toByte()
        header[0x81] = 'E'.code.toByte()
        header[0x84] = 0x64
        header[0x85] = 0x86.toByte()   // IMAGE_FILE_MACHINE_AMD64
        val result = HeaderDetector.detect(tempFile(header))
        assertEquals("x86:LE:64:default", result?.languageId)
        assertEquals("Portable Executable (PE)", result?.format)
    }

    /** Mach-O 64-bit little-endian, cputype = CPU_TYPE_ARM64. */
    @Test
    fun `reads the mach-o cpu type`() {
        val header = ByteArray(64)
        header[0] = 0xCF.toByte()
        header[1] = 0xFA.toByte()
        header[2] = 0xED.toByte()
        header[3] = 0xFE.toByte()      // MH_MAGIC_64, little endian
        header[4] = 0x0C
        header[7] = 0x01               // CPU_TYPE_ARM64 = 0x0100000C
        val result = HeaderDetector.detect(tempFile(header))
        assertEquals("AARCH64:LE:64:v8A", result?.languageId)
        assertEquals("Mach-O", result?.format)
    }

    @Test
    fun `rejects a file that is not an executable`() {
        assertNull(HeaderDetector.detect(tempFile(ByteArray(128) { 0x41 })))
    }

    @Test
    fun `rejects a truncated file`() {
        assertNull(HeaderDetector.detect(tempFile(ByteArray(8))))
    }
}
