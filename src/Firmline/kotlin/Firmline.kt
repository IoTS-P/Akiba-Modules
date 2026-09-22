package org.iotsplab.akiba.process

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.apache.logging.log4j.Level
import org.iotsplab.akiba.module.AkibaModule
import org.iotsplab.akiba.utils.IgnoreRuntimeTimeout
import org.iotsplab.akiba.utils.WithConfigClass
import org.iotsplab.akiba.utils.WithTableColumn
import java.lang.IllegalArgumentException
import java.nio.file.Path
import kotlin.io.path.absolutePathString
import kotlin.io.path.copyTo
import kotlin.io.path.deleteIfExists
import kotlin.io.path.name
import kotlin.io.path.notExists

@WithConfigClass(FirmlineConfig::class)
@WithTableColumn("max_memory_kb", "BIGINT")
@IgnoreRuntimeTimeout
class Firmline (
    configPath: String? = null,
    id: Int,
    consoleLogLevel: Level = Level.INFO,
    fileLogLevel: Level = Level.INFO,
    tableName: String? = null
) : AkibaModule (
    id = id,
    configPath = configPath,
    defaultConfig = FirmlineConfig(),
    consoleLogLevel = consoleLogLevel,
    fileLogLevel = fileLogLevel,
    tableName = tableName
) {
    private val conf: FirmlineConfig
        get() = config as FirmlineConfig

    override suspend fun startProcess() {
        // Check if FirmRCA environment is ready
        if (!checkFirmlineEnv()) {
            logger.error("Checks for Firmline environment failed. There may be something wrong in your Firmline")
            failureSign = FAILED
            return
        }

        runFirmline()
    }

    private fun checkFirmlineEnv(): Boolean {
        synchronized(checkLock) {
            if (firmlineEnvCheckDone)
                return firmlineEnvReady

            // Check paths
            conf.firmlineRoot ?: run {
                firmlineEnvCheckDone = true
                throw IllegalArgumentException("Firmline Root Directory not specified")
            }
            conf.ghidraHome ?: {
                firmlineEnvCheckDone = true
                throw IllegalArgumentException("Ghidra Home not specified")
            }

            // Check python version
            val process = ProcessBuilder(
                *conf.cmdPrefix.toTypedArray(), "${conf.pythonRoot} --version")
                .redirectErrorStream(true).start()
            process.waitFor()
            process.inputStream.bufferedReader().readText().let {
                logger.trace(it)
                val lastLine = it.split("\n").last { line -> line.isNotEmpty() }
                if (!(lastLine.startsWith("Python 3.11") || lastLine.startsWith("Python 3.10"))) {
                    logger.error("Python env error, must be python 3.10 or 3.11")
                    firmlineEnvCheckDone = true
                    return false
                }
            }

            // Check database file
            if (Path.of("${conf.firmlineRoot}/fwdb.db").notExists()) {
                val process2 = ProcessBuilder(
                    *conf.cmdPrefix.toTypedArray(),
                    "cd ${conf.firmlineRoot} && sqlite3 fwdb.db < schema.sql")
                    .redirectErrorStream(true).start()
                process2.waitFor()
            }
            if (Path.of("${conf.firmlineRoot}/fwdb.db").notExists()) {
                logger.error("Failed to generate sqlite file, maybe `sqlite3` is not installed?")
                firmlineEnvCheckDone = true
                return false
            }

            // Check bgrep
            if (Path.of("/usr/local/opt/bgrep/usr/bin/bgrep").notExists()) {
                logger.error("bgrep not found")
                firmlineEnvCheckDone = true
                return false
            }

            firmlineEnvCheckDone = true
            firmlineEnvReady = true
            return true
        }
    }

    private suspend fun runFirmline() = coroutineScope {
        // Firmline will move the file into its own directory, so we need to create a copy
        val bin: Path = originalFile.toPath().let {
            val tempFile = it.parent.resolve(it.name + "_tmpforFirmline")
            it.copyTo(tempFile, true)
            tempFile
        }

        // Effective way to run Firmline in timeout, I tested many ways and this works in docker :)
        // But it cannot be stopped by sending Ctrl+C to Akiba :(
        val process = ProcessBuilder(
            *conf.cmdPrefix.toTypedArray(), "${conf.cmdPredo} && " +
                    "export GHIDRA_HOME=${conf.ghidraHome} && " +
                    "cd ${conf.firmlineRoot} && " +
                    "LD_LIBRARY_PATH=/usr/local/lib " +
                    "${conf.pythonRoot} pipeline.py ${bin.absolutePathString()}"
        ).redirectErrorStream(true).start()
        val pid = process.pid()
        var maxMemoryKb = 0L

        val outReader = CoroutineScope(coroutineContext).launch {
            withContext(Dispatchers.IO) {
                process.inputStream.bufferedReader().use { reader ->
                    var line: String?
                    while (reader.readLine().also { line = it } != null)
                        logger.trace(line)
                }
            }
        }

        val memoryMonitor = CoroutineScope(coroutineContext).launch {
            logger.debug("Memory monitor started")
            while (isActive && process.isAlive) {
                val currentMemoryKb = getProcessTreeMemoryKb(pid)
                if (currentMemoryKb != null && currentMemoryKb > maxMemoryKb) {
                    maxMemoryKb = currentMemoryKb
                }
                if (maxMemoryKb > conf.memoryCostMeltdownThreshold) {
                    logger.error("Memory cost meltdown detected, terminating process tree")
                    killProcessTree(pid)
                    break
                }
                delay(5_000)
            }
            val finalMemoryKb = getProcessTreeMemoryKb(pid)
            if (finalMemoryKb != null && finalMemoryKb > maxMemoryKb) {
                maxMemoryKb = finalMemoryKb
            }
        }

        outReader.join()
        memoryMonitor.join()
        process.waitFor()

        updateData(mapOf("max_memory_kb" to maxMemoryKb))

        when (process.exitValue()) {
            in listOf(143, 1) -> {
                logger.warn("Firmline terminated by timeout")
                updateErr("radare2 timeout")
                failureSign = FAILED
            }
            0 -> logger.info("Firmline finished successfully")
            2 -> {
                logger.info("Firmline interrupted")
                updateErr("interrupted")
                failureSign = FAILED
            }
            else -> {
                logger.warn("Firmline failed returning ${process.exitValue()}")
                updateErr("unknown error returning ${process.exitValue()}")
                failureSign = FAILED
            }
        }

        bin.deleteIfExists()
    }

    private fun getProcessTreeMemoryKb(pid: Long): Long? {
        val pids = getChildPids(pid).toMutableList().also { it.add(pid) }
        var totalMemoryKb = 0L
        for (p in pids) {
            val statusFile = Path.of("/proc/$p/status").toFile()
            if (!statusFile.exists()) continue
            val vmRssLine = statusFile.readLines().firstOrNull { it.startsWith("VmRSS:") } ?: continue
            val memCost = vmRssLine.substringAfter("VmRSS:").substringBefore("kB").trim().toLongOrNull() ?: continue
            // Without this println, the memory cost could not be added normally and I don't know what the hell is going on
            println("Process $p memory cost: $memCost KB")
            totalMemoryKb += memCost
        }
        if (totalMemoryKb > 0) {
            logger.debug("Process tree $pid memory cost: $totalMemoryKb KB")
        }
        return totalMemoryKb
    }

    private fun getChildPids(pid: Long): List<Long> {
        val childPids = mutableListOf<Long>()
        val tasksDir = Path.of("/proc/$pid/task")
        if (!tasksDir.toFile().exists()) return childPids
        try {
            tasksDir.toFile().listFiles()?.forEach { taskDir ->
                val childrenFile = taskDir.resolve("children")
                if (childrenFile.exists()) {
                    childrenFile.readText().split("\\s+".toRegex()).filter { it.isNotEmpty() }.forEach { childPidStr ->
                        val childPid = childPidStr.toLongOrNull() ?: return@forEach
                        childPids.add(childPid)
                        childPids.addAll(getChildPids(childPid))
                    }
                }
            }
        } catch (_: Exception) {
            // Ignore permission errors or other exceptions
        }
        return childPids
    }

    private fun killProcessTree(pid: Long) {
        val stoppedPids = mutableSetOf<Long>()
        val toProcess = ArrayDeque<Long>()
        toProcess.add(pid)
        while (!toProcess.isEmpty()) {
            val currentPid = toProcess.removeFirst()
            if (stoppedPids.contains(currentPid)) continue
            try {
                Runtime.getRuntime().exec(arrayOf("kill", "-STOP", currentPid.toString())).waitFor()
                stoppedPids.add(currentPid)
            } catch (_: Exception) { }
            getChildPids(currentPid).forEach { childPid ->
                if (!stoppedPids.contains(childPid)) {
                    toProcess.add(childPid)
                }
            }
        }
        stoppedPids.forEach { p ->
            try {
                Runtime.getRuntime().exec(arrayOf("kill", "-9", p.toString())).waitFor()
            } catch (_: Exception) { }
        }
    }

    companion object {
        private var firmlineEnvCheckDone: Boolean = false
        private var firmlineEnvReady: Boolean = false
        private val checkLock = Any()
    }
}
