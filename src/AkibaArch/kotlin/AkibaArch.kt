package org.iotsplab.akiba.process

import ghidra.program.model.listing.Program
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists
import org.apache.logging.log4j.Level
import org.iotsplab.akiba.managers.ProgramManager
import org.iotsplab.akiba.managers.WorkspaceManager
import org.iotsplab.akiba.module.AkibaModule
import org.iotsplab.akiba.utils.DoNotCreateTable

/**
 * Identify the architecture of one binary from its file header.
 *
 * Import registers binaries without a format or architecture, so this module
 * fills both in afterwards: it reads the ELF, PE or Mach-O header, maps the
 * machine field onto a Ghidra language id and writes `arch` and `format` back to
 * `binaries`. Header fields are authoritative for these formats, so no analysis
 * runs and a batch costs milliseconds per file.
 *
 * A header it cannot map leaves the row untouched and reports failure: guessing
 * here would hand later analysis a wrong language, which is worse than an
 * explicit "not identified".
 */
@DoNotCreateTable
class AkibaArch(
    id: Int,
    program: Program? = null,
    consoleLogLevel: Level = Level.INFO,
    fileLogLevel: Level = Level.INFO,
    tableName: String? = null,
) : AkibaModule(
    id = id,
    program = program,
    consoleLogLevel = consoleLogLevel,
    fileLogLevel = fileLogLevel,
    tableName = tableName,
) {

    override suspend fun startProcess() {
        val metadata = try {
            dbClient.getMetadata(id.toLong())
        } catch (e: Exception) {
            fail("Cannot read metadata of binary #$id: ${e.message}")
            return
        }

        val path = resolvePath()
        if (path == null) {
            fail("Binary #$id has no file on disk (originalPath=${metadata.originalPath})")
            return
        }

        val detection = try {
            HeaderDetector.detect(path)
        } catch (e: Exception) {
            fail("Cannot read the header of $path: ${e.message}")
            return
        }
        if (detection == null) {
            fail("Unrecognised header in $path: not ELF, PE or Mach-O, or the machine is unknown")
            return
        }

        try {
            // The daemon updates one locked table at a time; `binaries` is the
            // table this module owns for the duration of the call.
            dbClient.tableLock("binaries")
            try {
                dbClient.updateData(
                    "binaries",
                    id.toLong(),
                    mapOf("arch" to detection.languageId, "format" to detection.format),
                )
            } finally {
                dbClient.tableUnlock("binaries")
            }
        } catch (e: Exception) {
            fail("Cannot write arch '${detection.languageId}' for binary #$id: ${e.message}")
            return
        }

        logger.info(
            "Binary #{} identified as {} ({}, {}, {} bit)",
            id, detection.languageId, detection.format, detection.machine, detection.bits
        )
    }

    /** Prefer the processed copy (unpacked, patched), fall back to the original. */
    private fun resolvePath(): Path? {
        val candidates = buildList {
            val processed = WorkspaceManager.processedBinaryPath.resolve("$id.bin")
            if (processed.exists()) add(processed)
            val original = WorkspaceManager.binaryPath.resolve("$id.bin")
            if (original.exists()) add(original)
        }
        return candidates.firstOrNull()
    }

    private fun fail(message: String) {
        logger.error(message)
        failureSign = FAILED
    }
}

/**
 * Minimal file-header reader for the three formats Akiba accepts.
 *
 * Only fixed-layout fields are read, so this works on truncated firmware images
 * as long as the header itself arrived. [languageId] is chosen from
 * [ProgramManager.GUESSED_PRIMARY_LEVEL_ARCHES] so the result is always a
 * language the importer can open, rather than a name assembled by hand.
 */
object HeaderDetector {

    data class Detection(
        val format: String,
        val machine: String,
        val bits: Int,
        val languageId: String,
    )

    private const val FORMAT_ELF = "Executable and Linking Format (ELF)"
    private const val FORMAT_PE = "Portable Executable (PE)"
    private const val FORMAT_MACHO = "Mach-O"

    fun detect(path: Path): Detection? {
        val head = Files.newInputStream(path).use { it.readNBytes(4096) }
        if (head.size < 64) return null
        return when {
            isElf(head) -> elf(head)
            isPe(head) -> pe(head)
            isMachO(head) -> machO(head)
            else -> null
        }
    }

    private fun isElf(b: ByteArray) =
        b[0] == 0x7F.toByte() && b[1] == 'E'.code.toByte() &&
            b[2] == 'L'.code.toByte() && b[3] == 'F'.code.toByte()

    private fun isPe(b: ByteArray) =
        b[0] == 'M'.code.toByte() && b[1] == 'Z'.code.toByte() &&
            b.size > 0x40 && le32(b, 0x3C).let { it in 0 until (b.size - 4).toLong() } &&
            b[le32(b, 0x3C).toInt()] == 'P'.code.toByte() &&
            b[le32(b, 0x3C).toInt() + 1] == 'E'.code.toByte()

    private fun isMachO(b: ByteArray): Boolean {
        val magic = be32(b, 0)
        return magic == 0xFEEDFACEL || magic == 0xFEEDFACFL ||
            magic == 0xCEFAEDFEL || magic == 0xCFFAEDFEL
    }

    /** ELF: `e_ident` gives class and byte order, `e_machine` the CPU family. */
    private fun elf(b: ByteArray): Detection? {
        val bits = when (b[4].toInt()) { 1 -> 32; 2 -> 64; else -> return null }
        val little = b[5].toInt() == 1
        val machine = if (little) le16(b, 18) else be16(b, 18)
        val family = when (machine) {
            0x03 -> "x86"
            0x3E -> "x86"
            0x28 -> "ARM"
            0xB7 -> "AARCH64"
            0x08 -> "MIPS"
            0x14 -> "PowerPC"
            0x15 -> "PowerPC"
            0xF3 -> "RISCV"
            else -> return null
        }
        val order = if (little) "LE" else "BE"
        val language = pickLanguage(family, order, bits) ?: return null
        return Detection(FORMAT_ELF, "EM_$machine", bits, language)
    }

    /** PE: the machine field sits in the COFF header right after the `PE\0\0` signature. */
    private fun pe(b: ByteArray): Detection? {
        val peOffset = le32(b, 0x3C).toInt()
        if (peOffset + 6 >= b.size) return null
        val machine = le16(b, peOffset + 4)
        val (family, bits) = when (machine) {
            0x014C -> "x86" to 32
            0x8664 -> "x86" to 64
            0x01C0, 0x01C4 -> "ARM" to 32
            0xAA64 -> "AARCH64" to 64
            else -> return null
        }
        val language = pickLanguage(family, "LE", bits) ?: return null
        return Detection(FORMAT_PE, "IMAGE_FILE_MACHINE_${machine.toString(16)}", bits, language)
    }

    /** Mach-O: cputype and the magic decide family, word size and byte order. */
    private fun machO(b: ByteArray): Detection? {
        val magic = be32(b, 0)
        val little = magic == 0xCEFAEDFEL || magic == 0xCFFAEDFEL
        val bits = if (magic == 0xFEEDFACFL || magic == 0xCFFAEDFEL) 64 else 32
        val cpu = if (little) le32(b, 4) else be32(b, 4)
        val family = when (cpu) {
            7L -> "x86"
            0x01000007L -> "x86"
            12L -> "ARM"
            0x0100000CL -> "AARCH64"
            18L -> "PowerPC"
            0x01000012L -> "PowerPC"
            else -> return null
        }
        val order = if (little) "LE" else "BE"
        val language = pickLanguage(family, order, bits) ?: return null
        return Detection(FORMAT_MACHO, "CPU_TYPE_${cpu}", bits, language)
    }

    /** First known language that matches family, byte order and word size. */
    private fun pickLanguage(family: String, order: String, bits: Int): String? =
        ProgramManager.GUESSED_PRIMARY_LEVEL_ARCHES.firstOrNull {
            val parts = it.split(':')
            parts.size >= 3 && parts[0] == family && parts[1] == order && parts[2] == bits.toString()
        }

    private fun le16(b: ByteArray, offset: Int) =
        (b[offset].toInt() and 0xFF) or ((b[offset + 1].toInt() and 0xFF) shl 8)

    private fun be16(b: ByteArray, offset: Int) =
        ((b[offset].toInt() and 0xFF) shl 8) or (b[offset + 1].toInt() and 0xFF)

    private fun le32(b: ByteArray, offset: Int): Long =
        ByteBuffer.wrap(b, offset, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xFFFFFFFFL

    private fun be32(b: ByteArray, offset: Int): Long =
        ByteBuffer.wrap(b, offset, 4).order(ByteOrder.BIG_ENDIAN).int.toLong() and 0xFFFFFFFFL
}
