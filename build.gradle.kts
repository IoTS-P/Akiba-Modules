plugins {
    kotlin("jvm") version "2.1.20"
    kotlin("plugin.serialization") version "2.1.20"
}

group = "org.iotsplab.akiba.process"   // Change this to your own group

repositories {
    mavenCentral()
}

// Define modules
val AddressSpaceAnalyzer by configurations.register("AddressSpaceAnalyzer")
val ArchChecker by configurations.register("ArchChecker")
val ARMBaseFinder by configurations.register("ARMBaseFinder")
val ConvertFirmToELF by configurations.register("ConvertFirmToELF")
val CortexEmulator by configurations.register("CortexEmulator")
val EnhancedFunctionFinder by configurations.register("EnhancedFunctionFinder")
val Entropy by configurations.register("Entropy")
val EntryFinder by configurations.register("EntryFinder")
val ExternalDynamicChecker by configurations.register("ExternalDynamicChecker")
val Firmline by configurations.register("Firmline")
val FirmlineBaseChecker by configurations.register("FirmlineBaseChecker")
val FirmlineOnFuzzware by configurations.register("FirmlineOnFuzzware")
val FirmlineOnFuzzwareReplay by configurations.register("FirmlineOnFuzzwareReplay")
val FirmRCA by configurations.register("FirmRCA")
val FirmXRay by configurations.register("FirmXRay")
val FirmXRayOnFuzzware by configurations.register("FirmXRayOnFuzzware")
val FirmXRayOnFuzzwareReplay by configurations.register("FirmXRayOnFuzzwareReplay")
val FunctionFinder by configurations.register("FunctionFinder")
val FuzzwareEmu by configurations.register("FuzzwareEmu")
val FuzzwareGateway by configurations.register("FuzzwareGateway")
val FuzzwarePipeline by configurations.register("FuzzwarePipeline")
val FuzzwareReplay by configurations.register("FuzzwareReplay")
val FuzzwareStat by configurations.register("FuzzwareStat")
val HasRTOS by configurations.register("HasRTOS")
val HoedurFuzz by configurations.register("HoedurFuzz")
val HoedurStatistics by configurations.register("HoedurStatistics")
val IoTGeneralStructures by configurations.register("IoTGeneralStructures")
val MultiFuzz by configurations.register("MultiFuzz")
val ProgramInitialization by configurations.register("ProgramInitialization")
val ProgramServer by configurations.register("ProgramServer")
val RBaseFind by configurations.register("RBaseFind")
val StartupDynamicChecker by configurations.register("StartupDynamicChecker")
val StringAdder by configurations.register("StringAdder")
val StringBaseFinder by configurations.register("StringBaseFinder")

// A module that is used for testing
val TestModule by configurations.register("TestModule")
// A test module as a dependency of TestModule
val TestModule2 by configurations.register("TestModule2")
// A test module for testing module db tables
val TestModule3 by configurations.register("TestModule3")

val PublicConfiguration by configurations.register("Public")

val bfModules = mapOf(         // Register module versions here
    AddressSpaceAnalyzer to "1.2",
    ArchChecker to "1.0",
    ARMBaseFinder to "1.3",
    ConvertFirmToELF to "1.2",
    CortexEmulator to "1.0",
    EnhancedFunctionFinder to "1.0",
    Entropy to "1.0",
    EntryFinder to "1.1",
    ExternalDynamicChecker to "1.1",
    Firmline to "1.0",
    FirmlineBaseChecker to "1.0",
    FirmlineOnFuzzware to "1.0",
    FirmlineOnFuzzwareReplay to "1.0",
    FirmRCA to "1.0",
    FirmXRay to "1.0",
    FirmXRayOnFuzzware to "1.0",
    FirmXRayOnFuzzwareReplay to "1.0",
    FunctionFinder to "1.2",
    FuzzwareEmu to "1.1",
    FuzzwareGateway to "1.1",
    FuzzwarePipeline to "1.0",
    FuzzwareReplay to "1.0",
    FuzzwareStat to "1.0",
    HasRTOS to "1.1",
    HoedurFuzz to "1.0",
    HoedurStatistics to "1.0",
    IoTGeneralStructures to "1.0",
    MultiFuzz to "1.0",
    ProgramInitialization to "1.0",
    ProgramServer to "1.0",
    RBaseFind to "1.0",
    StartupDynamicChecker to "1.1",
    StringAdder to "1.0",
    StringBaseFinder to "1.1",

    TestModule to "1.0",
    TestModule2 to "1.0",
    TestModule3 to "1.0"
)

val underDevelopmentModules = listOf(
    "EnhancedFunctionFinder"
)

dependencies {
    // Module-specified dependencies
    ConvertFirmToELF("net.fornwall:jelf:0.9.0")
    FirmlineBaseChecker("org.xerial:sqlite-jdbc:3.51.1.0")
    FuzzwareReplay("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
    HoedurStatistics("com.github.luben:zstd-jni:1.4.9-2")
    HoedurStatistics("org.yaml:snakeyaml:2.4")
    HoedurStatistics("com.fasterxml.jackson.module:jackson-module-kotlin:2.20.0")

    // You can also add other modules as dependencies
    AddressSpaceAnalyzer(moduleDependency(listOf(ARMBaseFinder, IoTGeneralStructures)))
    ArchChecker(moduleDependency(listOf(ProgramInitialization)))
    ARMBaseFinder(moduleDependency(listOf(IoTGeneralStructures, ProgramServer, StartupDynamicChecker)))
    ConvertFirmToELF(moduleDependency(listOf(IoTGeneralStructures)))
    CortexEmulator(moduleDependency(listOf(ARMBaseFinder)))
    ExternalDynamicChecker(moduleDependency(listOf(ARMBaseFinder, StartupDynamicChecker)))
    FirmlineBaseChecker(moduleDependency(listOf(ARMBaseFinder, StartupDynamicChecker)))
    FirmlineOnFuzzware(moduleDependency(listOf(FuzzwareGateway, FuzzwarePipeline)))
    FirmlineOnFuzzwareReplay(moduleDependency(listOf(FuzzwareGateway)))
    FirmRCA(moduleDependency(listOf(FuzzwareGateway, FuzzwareReplay)))
    FirmXRay(moduleDependency(listOf(ARMBaseFinder, StartupDynamicChecker)))
    FirmXRayOnFuzzware(moduleDependency(listOf(FuzzwareGateway, FuzzwarePipeline)))
    FirmXRayOnFuzzwareReplay(moduleDependency(listOf(FuzzwareGateway)))
    FunctionFinder(moduleDependency(listOf(ARMBaseFinder)))
    FuzzwareEmu(moduleDependency(listOf(FuzzwareGateway)))
    FuzzwareGateway(moduleDependency(listOf(ARMBaseFinder)))
    FuzzwarePipeline(moduleDependency(listOf(FuzzwareGateway)))
    FuzzwareReplay(moduleDependency(listOf(FuzzwareGateway)))
    HoedurFuzz(moduleDependency(listOf(FuzzwareGateway)))
    MultiFuzz(moduleDependency(listOf(FuzzwareGateway, HoedurFuzz)))
    StartupDynamicChecker(moduleDependency(listOf(IoTGeneralStructures)))

    TestModule(moduleDependency(listOf(TestModule2)))

    // public dependencies
    PublicConfiguration("org.apache.logging.log4j:log4j-api:2.24.3")
    PublicConfiguration("org.apache.logging.log4j:log4j-core:2.24.3")
    PublicConfiguration("org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.10.2")
    PublicConfiguration(project(":akiba_framework"))
    PublicConfiguration(fileTree(mapOf("dir" to "modules", "include" to listOf("*.jar"))))
    PublicConfiguration("io.ktor:ktor-server:3.1.3")
    PublicConfiguration("io.ktor:ktor-server-netty:3.1.3")
    testImplementation(kotlin("test"))
}

fun moduleDependency(modules: List<Configuration>): ConfigurableFileCollection {
    return files(modules.map { "build/libs/amod-${it.name}-${bfModules[it]}.jar" }.toTypedArray())
}

val finalizeTasks: Map<String, Jar.() -> Unit> = mapOf(
    // Add additional tasks here, like copying files
    "ConvertFirmToELF" to {
        from(
            project.rootDir.resolve("build/resources/ConvertFirmToELF/ELFBuilder/cmake-build-debug/ELFBuilder")) {
            into("/")
        }
    }
)

bfModules.forEach { module, ver ->
    val moduleName = module.name
    val globalGroup = group

    configurations[moduleName].extendsFrom(configurations["Public"])

    sourceSets.create(moduleName) {
        kotlin.srcDir("src/${moduleName}/kotlin")

        compileClasspath += configurations[moduleName]
        runtimeClasspath += configurations[moduleName]
    }

    // Exclude modules that are under development
    if (underDevelopmentModules.firstOrNull { it == moduleName } == null) {
        tasks.register<Jar>("moduleJar-$moduleName") {
            group = globalGroup as String
            archiveBaseName.set("amod-$moduleName")
            archiveVersion.set(ver)

            duplicatesStrategy = DuplicatesStrategy.EXCLUDE

            from(sourceSets[moduleName].output) {
                duplicatesStrategy = DuplicatesStrategy.EXCLUDE
            }

            // Pack all jars except Akiba and Ghidra
            from(
                configurations[moduleName].resolve()
                    .filter {
                        it.name.endsWith("jar") &&
                                // exclude all common jar
                                !configurations["Public"].contains(it) &&
                                !it.name.startsWith("amod")
                    }
                    .map { zipTree(it) }
            ) {
                duplicatesStrategy = DuplicatesStrategy.EXCLUDE
            }

            exclude("META-INF/*.RSA", "META-INF/*.SF", "META-INF/*.DSA", "**/.*/**")

            // Write dependency class names into 'META-INF/module-deps'
            val dependencyClassNames = configurations[moduleName].resolve()
                .filter { it.name.startsWith("amod") }
                .map { group + "." + it.name.substringAfter("amod-").substringBefore("-") }
            val depFile = temporaryDir.resolve("META-INF/module-deps")
            depFile.parentFile.mkdirs()
            depFile.writeText(dependencyClassNames.joinToString("\n"))
            from(depFile) { into("META-INF") }

            manifest {
                attributes["Main-Class"] = "$group.$moduleName"
            }

            finalizeTasks[moduleName]?.invoke(this)
        }
    }
}

fun recDepend(allTask: Task, undone: MutableList<Task>, selected: Task) {
    val moduleName = selected.name.substringAfter("moduleJar-")
    val dependencies = configurations[moduleName].resolve()
        .filter { it.name.startsWith("amod") && !it.path.contains("/modules/") }
    if (dependencies.isEmpty()) {
        allTask.dependsOn(selected)
    } else {
        for (dependency in dependencies) {
            val dependencyName = dependency.name.substringAfter("amod-").substringBefore("-")
            val dependencyTask = tasks.getByName("moduleJar-$dependencyName")
            selected.mustRunAfter(dependencyTask)
            if (undone.contains(dependencyTask))
                recDepend(allTask, undone, dependencyTask)
        }
        allTask.dependsOn(selected)
    }
    undone.remove(selected)
}

tasks.register("moduleJar-ALL") {
    val undoneTasks = tasks.filter { it.name.startsWith("moduleJar-") && it.name != "moduleJar-ALL" }
        .toMutableList()
    while (!undoneTasks.isEmpty()) {
        val selected = undoneTasks.first()
        recDepend(this, undoneTasks, selected)
    }
}

tasks.register<Zip>("bundle-zip") {
    archiveBaseName.set("akiba_modules")
    archiveVersion.set(version.toString())
    description = "Bundle all akiba module JARs into one zip file"

    val libDir = layout.buildDirectory.dir("libs")
    destinationDirectory.set(libDir)

    from(libDir) {
        include("amod-*.jar")
        exclude("amod-Test*.jar")
    }
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(21)
}