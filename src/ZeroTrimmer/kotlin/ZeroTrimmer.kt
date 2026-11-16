package org.iotsplab.akiba.process

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import org.apache.logging.log4j.Level
import org.iotsplab.akiba.module.AkibaModule
import org.iotsplab.akiba.utils.WithConfigClass
import org.iotsplab.akiba.utils.WithTableColumn

/**
 * Removes long runs of zero bytes from a program's memory.
 *
 * The trimming happens inside the program: no file is written and no second binary is
 * produced. A run that covers a whole block removes the block; a run inside a block
 * splits it and the zero part goes away, so the remaining pieces keep their addresses.
 */
/**
 * How aggressive to be. A run of zeros shorter than [minRun] is ordinary padding.
 */
data class ZeroTrimmerConfig(val minRun: Int = 0x10000)

@WithConfigClass(ZeroTrimmerConfig::class)
@WithTableColumn("removed_bytes", "bigint")
@WithTableColumn("blocks", "integer")
class ZeroTrimmer(
    id: Int,
    program: Program,
    consoleLogLevel: Level = Level.INFO,
    fileLogLevel: Level = Level.INFO,
    tableName: String? = null
) : AkibaModule(
    id = id,
    program = program,
    consoleLogLevel = consoleLogLevel,
    fileLogLevel = fileLogLevel,
    tableName = tableName
) {
    private val prog: Program
        get() = program!!

    private var removedBytes = 0L
    private var blocksLeft = 0

    override suspend fun startProcess() {
        var removed = 0L
        val tx = prog.startTransaction("trim zero runs")
        try {
            val blocks = prog.memory.blocks.toList()
            blocks.forEach { removed += trimBlock(it.start) }
        } finally {
            prog.endTransaction(tx, true)
        }
        removedBytes = removed
        blocksLeft = prog.memory.blocks.size
        logger.info("Removed $removed bytes of zero padding, $blocksLeft blocks left")
    }

    override fun result(): Map<String, Any?> = mapOf(
        "removed_bytes" to removedBytes,
        "blocks" to blocksLeft,
    )

    private fun trimBlock(start: Address): Long {
        val block = prog.memory.getBlock(start) ?: return 0
        val runs = zeroRuns(block.start, block.size, minRun())
        var removed = 0L
        // Back to front: cutting the tail never invalidates the addresses still to come.
        runs.asReversed().forEach { run ->
            val current = prog.memory.getBlock(run.first) ?: return@forEach
            var middle = current
            if (run.first > current.start) {
                prog.memory.split(middle, run.first)
                middle = prog.memory.getBlock(run.first) ?: return@forEach
            }
            if (run.second < middle.end.add(1)) {
                prog.memory.split(middle, run.second)
                middle = prog.memory.getBlock(run.first) ?: return@forEach
            }
            val size = middle.size
            prog.memory.removeBlock(middle, TaskMonitor.DUMMY)
            removed += size
        }
        return removed
    }

    /** Half-open address ranges inside the block whose bytes are all zero and long enough. */
    /** The config's threshold, or the default when the plan did not set one. */
    private fun minRun(): Long = ((config as? ZeroTrimmerConfig) ?: ZeroTrimmerConfig()).minRun.toLong()

    private fun zeroRuns(blockStart: Address, blockSize: Long, minRun: Long): List<Pair<Address, Address>> {
        val runs = mutableListOf<Pair<Address, Address>>()
        val chunk = ByteArray(SCAN_CHUNK)
        var runStart = -1L
        var offset = 0L
        while (offset < blockSize) {
            val want = minOf(SCAN_CHUNK.toLong(), blockSize - offset).toInt()
            readBytes(blockStart, offset, chunk, want) ?: return runs
            for (i in 0 until want) {
                val zero = chunk[i] == 0.toByte()
                if (zero && runStart < 0) runStart = offset + i
                if (!zero && runStart >= 0) {
                    collect(runs, blockStart, runStart, offset + i, minRun)
                    runStart = -1L
                }
            }
            offset += want
        }
        if (runStart >= 0) collect(runs, blockStart, runStart, blockSize, minRun)
        return runs
    }

    private fun collect(runs: MutableList<Pair<Address, Address>>, base: Address, from: Long, to: Long, minRun: Long) {
        if (to - from >= minRun)
            runs.add(base.add(from) to base.add(to))
    }

    private fun readBytes(base: Address, offset: Long, buffer: ByteArray, length: Int): ByteArray? =
        try {
            prog.memory.getBytes(base.add(offset), buffer, 0, length)
            buffer
        } catch (e: Exception) {
            logger.warn("Could not read bytes at ${base.add(offset)}: ${e.message}")
            null
        }

    companion object {
        private const val SCAN_CHUNK = 4 * 1024 * 1024
    }
}
