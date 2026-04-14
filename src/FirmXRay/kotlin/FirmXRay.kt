package org.iotsplab.akiba.process

import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import org.apache.logging.log4j.Level
import org.iotsplab.akiba.module.AkibaModule
import org.iotsplab.akiba.process.structure.ArmcmIVT
import org.iotsplab.akiba.utils.WithTableColumn
import org.iotsplab.akiba.utils.IgnoreRuntimeTimeout
import org.iotsplab.akiba.utils.WithConfigClass
import java.nio.file.Path
import java.util.concurrent.locks.ReentrantLock
import kotlin.io.path.absolutePathString
import kotlin.io.path.isDirectory

@WithTableColumn("base_address", "BIGINT")
@WithTableColumn("entry_valid", "TEXT")
@WithTableColumn("max_memory_kb", "BIGINT")
@WithConfigClass(FirmXRayConfig::class)
@IgnoreRuntimeTimeout
class FirmXRay (
    configPath: String? = null,
    id: Int,
    program: Program,
    consoleLogLevel: Level = Level.INFO,
    fileLogLevel: Level = Level.INFO,
    tableName: String? = null
) : AkibaModule (
    id = id,
    configPath = configPath,
    program = program,
    consoleLogLevel = consoleLogLevel,
    fileLogLevel = fileLogLevel,
    tableName = tableName
) {
    val prog: Program
        get() = program!!

    val conf: FirmXRayConfig
        get() = config as FirmXRayConfig
    val firmxrayRoot: Path = Path.of(conf.firmxrayRoot!!)
    val firmxrayOutputDir: Path = firmxrayRoot.resolve("output")

    @Throws(IllegalArgumentException::class, IllegalStateException::class)
    override suspend fun startProcess() {
        if (!firmxrayRoot.isDirectory())
            throw IllegalArgumentException("Invalid FirmXRay root directory")

            try {
                val result = runFirmXRay()
                val base = result.base
                val maxMemoryKb = result.maxMemoryKb

                // Added for enhanced FirmXRay, If you want to run original FirmXRay, please comment out the below lines
                // Enhanced FirmXRay: https://github.com/MCUSec/RealworldFirmware/tree/main/FirmXRay
                if (base == -1L) {
                    logger.error("FirmXRay failed to get base address")
                    updateErr("failed")
                    updateData(mapOf("base_address" to null, "entry_valid" to null, "max_memory_kb" to maxMemoryKb))
                    failureSign = FAILED
                    return
                }
                // Added ended

                val entryValid = testBaseAddress(base)
                updateData(
                    mapOf(
                        "base_address" to base,
                        "entry_valid" to if (entryValid) "valid" else "invalid",
                        "max_memory_kb" to maxMemoryKb
                    )
                )
            } catch (e: Exception) {
                logger.error("Failed to run FirmXRay: ${e.message}")
                if (logger.isDebugEnabled)
                    e.printStackTrace()
                updateErr("failed")
                updateData(
                    mapOf("base_address" to null, "entry_valid" to null, "max_memory_kb" to null)
                )
                failureSign = FAILED
            }
    }

    @Throws(IllegalArgumentException::class)
    private suspend fun runFirmXRay(): FirmXRayRunResult = coroutineScope {
        firmxrayLock.lock()
        logger.debug("Lock acquired, holds: ${firmxrayLock.isLocked}")

        try {
            val firmxrayCmd = "cd ${firmxrayRoot.absolutePathString()} && " +
                    "${conf.javaBinPath} -cp out:lib/ghidra.jar:lib/json.jar main.Main " +
                    "${originalFile.absolutePath} Nordic"
            logger.debug("Execute: $firmxrayCmd")
            val builder = ProcessBuilder(*conf.cmdPrefix.toTypedArray(), firmxrayCmd)
                .redirectErrorStream(true)
            val process: Process = builder.start()
            var base: Long? = null
            var maxMemoryKb = 0L
            val pid = process.pid()

            val outReader = CoroutineScope(coroutineContext).launch {
                withContext(Dispatchers.IO) {
                    process.inputStream.bufferedReader().use { reader ->
                        while (true) {
                            val currentLine = reader.readLine() ?: break
                            logger.trace(currentLine)

                            if (currentLine.contains("Base: 0x")) {
                                base = currentLine.substringAfter("Base: 0x").toLong(16)
                            } else if (currentLine.startsWith("Result already exist for ")) {
                                val path = currentLine.substringAfter("Result already exist for ")
                                base = firmxrayOutputDir.resolve(path).toFile().readLines().filter {
                                    it.contains("Base: 0x")
                                }.map {
                                    it.substringAfter("Base: 0x").toLong(16)
                                }.first()
                            }
                        }
                    }
                }
            }

            val memoryMonitor = CoroutineScope(coroutineContext).launch {
                logger.debug("Memory monitor started")
                while (isActive && process.isAlive) {
                    val currentMemoryKb = getProcessMemoryKb(pid)
                    if (currentMemoryKb != null && currentMemoryKb > maxMemoryKb) {
                        maxMemoryKb = currentMemoryKb
                    }
                    delay(5_000)
                }
                val finalMemoryKb = getProcessMemoryKb(pid)
                if (finalMemoryKb != null && finalMemoryKb > maxMemoryKb) {
                    maxMemoryKb = finalMemoryKb
                }
            }

            outReader.join()
            memoryMonitor.join()

            val finalBase = base ?: throw IllegalStateException("FirmXRay failed to find base address")
            return@coroutineScope FirmXRayRunResult(base = finalBase, maxMemoryKb = maxMemoryKb)
        } catch (e: Exception) {
            if (logger.isDebugEnabled)
                e.printStackTrace()
            throw e
        } finally {
            logger.debug("Before unlock, holds: ${firmxrayLock.isLocked}")
            firmxrayLock.unlock()
        }
    }

    private fun testBaseAddress(base: Long): Boolean {
        val api = FlatProgramAPI(prog)
        val entry: Address = if (Regex("ARM:(LE|BE):32:.*").matches(prog.languageID.toString())) {
            val ivt = ArmcmIVT.fromAddress(prog, prog.memory.minAddress) ?: run {
                logger.error("Header is not a valid IVT")
                return false
            }
            ivt.entries[4] ?. let { api.toAddr(it) } ?: run {
                logger.error("Entry point invalid")
                return false
            }
        } else {
            logger.error("Cannot get entry point")
            return false
        }

        val emulator = try {
            StartupDynamicChecker.Companion.CheckerEmulator(
                program = prog,
                baseAddress = api.toAddr(base),
                entryPoint = entry,
                masterStackPointer = api.toAddr(STACK_POINTER),
                logger = logger,
                monitor = taskGlobalMonitor
            )
        } catch(e: Exception) {
            logger.error("Failed to initialize emulator: ${e.message}")
            return false
        }
        emulator.go()
        logger.info("Emulation valid: ${emulator.startupInfoValid} for ${usingFile.name}")
        return emulator.startupInfoValid
    }

    companion object {
        const val STACK_POINTER = 0xFFFF_8000

        // FirmXRay does not support parallel execution, or the FirmXRay program may cause unexpected failures
        private val firmxrayLock: Mutex = Mutex()
    }

    private data class FirmXRayRunResult(
        val base: Long,
        val maxMemoryKb: Long
    )

    private fun getProcessMemoryKb(pid: Long): Long? {
        val statusFile = Path.of("/proc/$pid/status").toFile()
        if (!statusFile.exists()) return null

        val vmRssLine = statusFile.readLines().firstOrNull { it.startsWith("VmRSS:") } ?: run {
            logger.warn("Failed to get memory cost (Unable to find VmRSS line in /proc/$pid/status)")
            return null
        }
        logger.debug(vmRssLine)
        val memCost = vmRssLine.substringAfter("VmRSS:").substringBefore("kB").trim().toLongOrNull()
        if (memCost == null)
            logger.warn("Failed to get memory cost")
        else
            logger.debug("Process $pid memory cost: $memCost KB")
        return memCost
    }
}