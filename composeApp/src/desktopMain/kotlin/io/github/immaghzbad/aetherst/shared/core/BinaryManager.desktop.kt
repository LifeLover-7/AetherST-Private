package io.github.immaghzbad.aetherst.shared.core

import io.github.immaghzbad.aetherst.platform.PlatformContext
import java.io.File

class DesktopBinaryManager : BinaryManager {

    fun prepareBinary(): String = prepareBinary("sing-box")

    override fun prepareBinary(name: String): String {
        val requestedName = if (name.equals("aether", ignoreCase = true)) "sing-box" else name
        val isWin = System.getProperty("os.name").lowercase().contains("win")
        val binName = if (isWin) {
            if (requestedName.endsWith(".exe")) requestedName else "$requestedName.exe"
        } else {
            requestedName
        }

        System.getProperty("compose.application.resources.dir")?.let { resourcesDir ->
            val candidates = listOf(
                File(resourcesDir, binName),
                File(resourcesDir, "bin/$binName"),
                File(File(resourcesDir, "app/resources"), binName),
                File(File(resourcesDir, "app/resources/bin"), binName)
            )
            for (file in candidates) {
                if (file.exists()) return file.absolutePath
            }
        }

        val userDir = File(System.getProperty("user.dir"))
        val devDirs = listOf(
            userDir,
            File(userDir, "bin"),
            File(userDir, "src/desktopMain/resources/bin"),
            File(userDir, "composeApp/src/desktopMain/resources/bin")
        )
        for (dir in devDirs) {
            val file = File(dir, binName)
            if (file.exists()) return file.absolutePath
            val fileInBin = File(File(dir, "bin"), binName)
            if (fileInBin.exists()) return fileInBin.absolutePath
        }

        val appData = System.getenv("AppData") ?: System.getProperty("user.home")
        val targetDir = File(appData, "AetherST-Tunnel/bin")
        if (!targetDir.exists()) targetDir.mkdirs()

        val targetFile = File(targetDir, binName)
        val needsLibs = binName.contains("hev-socks5-tunnel") || binName.contains("sing-box")

        if (!targetFile.exists() || targetFile.length() == 0L) {
            try {
                val stream = getResourceStream(binName) ?: getResourceStream("bin/$binName")
                stream?.use { input ->
                    targetFile.outputStream().use { output -> input.copyTo(output) }
                    if (!isWin) targetFile.setExecutable(true)
                }
            } catch (_: Exception) {}
        }

        if (needsLibs) {
            runCatching {
                extractResource("wintun.dll", targetDir)
                extractResource("msys-2.0.dll", targetDir)
            }
        }

        return if (targetFile.exists()) targetFile.absolutePath else binName
    }

    private fun getResourceStream(path: String): java.io.InputStream? {
        val clean = path.removePrefix("/")
        return javaClass.getResourceAsStream("/$clean")
            ?: javaClass.getResourceAsStream("/bin/$clean")
            ?: javaClass.classLoader.getResourceAsStream(clean)
            ?: javaClass.classLoader.getResourceAsStream("bin/$clean")
    }

    private fun extractResource(name: String, targetDir: File) {
        val targetFile = File(targetDir, name)
        if (!targetFile.exists() || targetFile.length() == 0L) {
            getResourceStream(name)?.use { input ->
                targetFile.outputStream().use { output -> input.copyTo(output) }
            } ?: getResourceStream("bin/$name")?.use { input ->
                targetFile.outputStream().use { output -> input.copyTo(output) }
            }
        }
    }
}

actual fun getBinaryManager(context: PlatformContext): BinaryManager = DesktopBinaryManager()
