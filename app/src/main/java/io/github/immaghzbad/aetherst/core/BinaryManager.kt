package io.github.immaghzbad.aetherst.core

import android.content.Context
import android.os.Build
import io.github.immaghzbad.aetherst.shared.data.LogRepository
import java.io.File
import java.io.IOException

object BinaryManager {

    data class ArchInfo(
        val abi: String,
        val targetName: String
    )

    fun detectArchitecture(): ArchInfo {
        val supportedAbis = Build.SUPPORTED_ABIS
        if (supportedAbis == null || supportedAbis.isEmpty()) {
            throw IOException("Device reports no supported ABIs.")
        }

        for (abi in supportedAbis) {
            when {
                abi.contains("x86_64", ignoreCase = true) -> return ArchInfo(abi, "x86_64")
                abi.contains("x86", ignoreCase = true) || abi.contains("i686", ignoreCase = true) || abi.contains("i386", ignoreCase = true) -> return ArchInfo(abi, "x86")
                abi.contains("arm64", ignoreCase = true) || abi.contains("aarch64", ignoreCase = true) -> return ArchInfo(abi, "arm64")
                abi.contains("v7", ignoreCase = true) || abi.contains("arm", ignoreCase = true) -> return ArchInfo(abi, "armv7")
            }
        }

        throw IOException("No compatible core binary found for device ABIs: ${supportedAbis.joinToString(", ")}")
    }

    /**
     * Resolves the Sing-box core binary (`libsing-box.so` / `sing-box`) as the primary network engine.
     * Falls back to `libaether.so` only if `libsing-box.so` is not yet bundled in the APK.
     */
    @Synchronized
    fun prepareBinary(context: Context): File {
        prepareSingBoxBinary(context)?.let { return it }

        val archInfo = detectArchitecture()
        val nativeLibDir = context.applicationInfo.nativeLibraryDir
        val bundledBinary = File(nativeLibDir, "libaether.so")

        if (bundledBinary.exists() && bundledBinary.isFile && bundledBinary.length() > 0) {
            if (bundledBinary.canExecute()) return bundledBinary
            try {
                makeExecutable(bundledBinary)
                if (bundledBinary.canExecute()) return bundledBinary
            } catch (e: Exception) {
                LogRepository.w("makeExecutable bundled failed: ${e.message}")
            }
        }

        val binDir = File(context.filesDir, "bin")
        if (!binDir.exists() && !binDir.mkdirs()) {
            throw IOException("Failed to create binary directory: ${binDir.absolutePath}")
        }

        val targetFile = File(binDir, "sing-box")
        if (targetFile.exists() && targetFile.isFile && targetFile.length() > 0) {
            if (targetFile.canExecute()) return targetFile
            makeExecutable(targetFile)
            if (targetFile.canExecute()) return targetFile
        }

        val legacyTarget = File(binDir, "aether_core")
        if (!bundledBinary.exists() || !bundledBinary.canExecute()) {
            try {
                val apkFile = File(context.applicationInfo.sourceDir)
                if (apkFile.exists() && apkFile.isFile) {
                    java.util.zip.ZipFile(apkFile).use { zip ->
                        val entry = zip.getEntry("lib/${archInfo.abi}/libsing-box.so")
                            ?: zip.getEntry("lib/${archInfo.abi}/libaether.so")
                        if (entry != null) {
                            val tempFile = File(binDir, "core.tmp")
                            zip.getInputStream(entry).use { input ->
                                tempFile.outputStream().use { output -> input.copyTo(output) }
                            }
                            makeExecutable(tempFile)
                            val dest = if (entry.name.contains("sing-box")) targetFile else legacyTarget
                            if (tempFile.renameTo(dest) || (dest.delete() && tempFile.renameTo(dest))) {
                                makeExecutable(dest)
                                if (dest.canExecute()) return dest
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                LogRepository.w("APK zip extraction fallback failed: ${e.message}")
            }
        }

        if (legacyTarget.exists() && legacyTarget.isFile && legacyTarget.length() > 0) {
            if (legacyTarget.canExecute()) return legacyTarget
            makeExecutable(legacyTarget)
            if (legacyTarget.canExecute()) return legacyTarget
        }

        throw IOException("Sing-box core binary is missing or not executable for architecture: ${archInfo.abi}")
    }

    @Synchronized
    fun prepareSingBoxBinary(context: Context): File? {
        val archInfo = runCatching { detectArchitecture() }.getOrNull()
        val nativeLibDir = context.applicationInfo.nativeLibraryDir

        for (soName in listOf("libsing-box.so", "libsingbox.so")) {
            val bundledBinary = File(nativeLibDir, soName)
            if (bundledBinary.exists() && bundledBinary.isFile && bundledBinary.length() > 0) {
                if (bundledBinary.canExecute()) return bundledBinary
                try {
                    makeExecutable(bundledBinary)
                    if (bundledBinary.canExecute()) return bundledBinary
                } catch (_: Exception) {}
            }
        }

        val binDir = File(context.filesDir, "bin")
        if (!binDir.exists()) binDir.mkdirs()

        val targetFile = File(binDir, "sing-box")
        if (targetFile.exists() && targetFile.length() > 0) {
            if (targetFile.canExecute()) return targetFile
            try {
                makeExecutable(targetFile)
                if (targetFile.canExecute()) return targetFile
            } catch (_: Exception) {}
        }

        // Check assets/bin/sing-box if packaged in assets
        try {
            context.assets.open("bin/sing-box").use { input ->
                val tempFile = File(binDir, "sing-box.tmp")
                tempFile.outputStream().use { output -> input.copyTo(output) }
                makeExecutable(tempFile)
                if (tempFile.renameTo(targetFile) || (targetFile.delete() && tempFile.renameTo(targetFile))) {
                    makeExecutable(targetFile)
                    if (targetFile.canExecute()) return targetFile
                }
            }
        } catch (_: Exception) {}

        // Check if bundled inside APK zip
        if (archInfo != null) {
            try {
                val apkFile = File(context.applicationInfo.sourceDir)
                if (apkFile.exists() && apkFile.isFile) {
                    java.util.zip.ZipFile(apkFile).use { zip ->
                        val entry = zip.getEntry("lib/${archInfo.abi}/libsing-box.so")
                            ?: zip.getEntry("lib/${archInfo.abi}/libsingbox.so")
                        if (entry != null) {
                            val tempFile = File(binDir, "sing-box.tmp")
                            zip.getInputStream(entry).use { input ->
                                tempFile.outputStream().use { output -> input.copyTo(output) }
                            }
                            makeExecutable(tempFile)
                            if (tempFile.renameTo(targetFile) || (targetFile.delete() && tempFile.renameTo(targetFile))) {
                                makeExecutable(targetFile)
                                if (targetFile.canExecute()) return targetFile
                            }
                        }
                    }
                }
            } catch (_: Exception) {}
        }

        return targetFile.takeIf { it.exists() && it.canExecute() }
    }

    private fun makeExecutable(file: File) {
        try {
            val pb = ProcessBuilder("chmod", "700", file.absolutePath)
            val proc = pb.start()
            proc.waitFor()
        } catch (e: Exception) {
            LogRepository.w("chmod 700 exception for ${file.name}: ${e.message}")
        }

        try {
            file.setExecutable(true, true)
            file.setReadable(true, true)
            file.setWritable(true, true)
        } catch (e: Exception) {
            LogRepository.w("setExecutable exception for ${file.name}: ${e.message}")
        }

        if (!file.canExecute()) {
            throw IOException("Failed to set executable permissions on ${file.name}")
        }
    }
}
