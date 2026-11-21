package io.github.immaghzbad.aetherst.shared.core

import io.github.immaghzbad.aetherst.platform.PlatformContext
import io.github.immaghzbad.aetherst.platform.getSystemUtils
import io.github.immaghzbad.aetherst.shared.data.IpInfoRepository
import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.model.*
import io.github.immaghzbad.aetherst.shared.net.FirefoxVpnExitTunnel
import io.github.immaghzbad.aetherst.shared.net.WireGuardCrypto
import io.github.immaghzbad.aetherst.shared.net.WireGuardExitTunnel
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.DataInputStream
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration.Companion.milliseconds

/**
 * Sing-box Core Process Runner (Common / Desktop).
 *
 * The application acts strictly as a UI & Configuration Manager:
 *  1. Generates `config.json` containing:
 *     - A `"tun"` inbound (`"auto_route": true`, `"strict_route": true`, `"mtu": 1120`) plus local SOCKS/HTTP inbounds.
 *     - Two `"wireguard"` outbounds:
 *       a) `"warp-out"` connected to the Cloudflare WARP server (`"mtu": 1280`, `"keepalive": 25`).
 *       b) `"proton-out"` connected to the ProtonVPN / Custom WireGuard server with
 *          `"detour": "warp-out"`, `"mtu": 1120`, and `"keepalive": 25`.
 *  2. Executes the bundled `sing-box` binary (`sing-box run -c config.json`) and monitors its lifecycle.
 */
class AetherProcessRunner(private val context: PlatformContext) {
    private val systemUtils = getSystemUtils(context)
    private var process: PlatformProcess? = null
    private var runnerJob: Job? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val currentAttemptId = AtomicLong(0)
    private var lastBindAddress: String = "127.0.0.1:2021"

    private val _connectionStatus = MutableStateFlow(ConnectionStatus.STOPPED)
    val connectionStatus: StateFlow<ConnectionStatus> = _connectionStatus.asStateFlow()

    data class WarpAccount(
        val deviceId: String,
        val accessToken: String,
        val server: String,
        val serverPort: Int,
        val ipv4: String,
        val ipv6: String,
        val privateKey: String,
        val peerPublicKey: String,
        val reserved: List<Int>
    )

    fun start(
        config: AetherConfig,
        bindAddress: String,
        onCodeRequired: () -> Unit = {},
        inputProvider: suspend () -> String = { "" }
    ) {
        if (runnerJob?.isActive == true) return
        LogRepository.currentAppLogLevel = config.appLogLevel
        LogRepository.currentCoreLogLevel = config.coreLogLevel
        val attemptId = currentAttemptId.incrementAndGet()
        lastBindAddress = bindAddress
        updateState(ConnectionStatus.STARTING, attemptId)

        runnerJob = scope.launch {
            var retryCount = 0
            while (isActive && (currentAttemptId.get() == attemptId)) {
                if (!config.smartReconnect && retryCount > 0) {
                    LogRepository.e("Smart Reconnect disabled -> stopping retry")
                    updateState(ConnectionStatus.ERROR, attemptId)
                    break
                }
                if (config.smartReconnect && retryCount >= config.reconnectRetryLimit) {
                    LogRepository.e("Smart Reconnect limit reached ($retryCount). Stopping...")
                    updateState(ConnectionStatus.ERROR, attemptId)
                    break
                }
                if (retryCount > 0) {
                    val waitTime = (retryCount * 1000L).coerceAtMost(10000L)
                    LogRepository.i("Recovering Sing-box connection (Retry $retryCount)...")
                    updateState(ConnectionStatus.RECONNECTING, attemptId)
                    delay(waitTime.milliseconds)
                } else {
                    LogRepository.i("Starting Sing-box core at $bindAddress")
                }

                try {
                    val success = runSingBoxBinary(config, attemptId, bindAddress)
                    if (currentAttemptId.get() != attemptId) break
                    if (!success) {
                        LogRepository.e("Sing-box core execution terminated unexpectedly.")
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    LogRepository.e("Sing-box execution cycle error: ${e.message}")
                }
                retryCount++
                if (connectionStatus.value == ConnectionStatus.RUNNING) {
                    retryCount = 1
                }
            }
        }
    }

    private suspend fun runSingBoxBinary(
        config: AetherConfig,
        attemptId: Long,
        bindAddress: String
    ): Boolean = coroutineScope {
        val workDir = File(systemUtils.getFilesDir()).apply { mkdirs() }
        val binaryPath = runCatching {
            getBinaryManager(context).prepareBinary("sing-box")
        }.getOrElse {
            getBinaryManager(context).prepareBinary("aether")
        }

        val warpAccount = resolveOrRegisterWarpAccount(config, workDir)
        val configFile = File(workDir, "config.json")

        // Always write the canonical config.json with tun (auto_route=true, strict_route=true)
        // and two wireguard outbounds (warp-out + proton-out with detour="warp-out", mtu=1120, keepalive=25)
        val primaryJson = generateSingBoxConfigJson(
            config = config,
            bindAddress = bindAddress,
            warpAccount = warpAccount,
            includeTunInbound = true,
            includeKeepaliveField = true
        )
        configFile.writeText(primaryJson)
        LogRepository.i("Generated Sing-box config.json (${configFile.absolutePath})", "SingBoxCore")

        // First attempt: execute sing-box with the primary config.json
        val needFallbackKeepalive = AtomicBoolean(false)
        val needFallbackNoTun = AtomicBoolean(false)

        val exitOk = executeSingBoxProcess(
            binaryPath = binaryPath,
            configPath = configFile.absolutePath,
            workDir = workDir,
            attemptId = attemptId,
            onUnknownKeepalive = { needFallbackKeepalive.set(true) },
            onTunPermissionDenied = { needFallbackNoTun.set(true) }
        )

        if (currentAttemptId.get() != attemptId) return@coroutineScope true

        // If the bundled sing-box binary rejected "keepalive" in its strict Go struct decoder
        // or lacked root/admin privilege for the internal tun interface, retry immediately with
        // the runtime-adapted JSON while keeping config.json intact on disk.
        if (!exitOk && (needFallbackKeepalive.get() || needFallbackNoTun.get())) {
            val runtimeFile = File(workDir, "config-runtime.json")
            val runtimeJson = generateSingBoxConfigJson(
                config = config,
                bindAddress = bindAddress,
                warpAccount = warpAccount,
                includeTunInbound = !needFallbackNoTun.get(),
                includeKeepaliveField = !needFallbackKeepalive.get()
            )
            runtimeFile.writeText(runtimeJson)
            LogRepository.i(
                "Retrying Sing-box with runtime profile (tun=${!needFallbackNoTun.get()}, strictSchema=${needFallbackKeepalive.get()})",
                "SingBoxCore"
            )
            return@coroutineScope executeSingBoxProcess(
                binaryPath = binaryPath,
                configPath = runtimeFile.absolutePath,
                workDir = workDir,
                attemptId = attemptId,
                onUnknownKeepalive = {},
                onTunPermissionDenied = {}
            )
        }

        exitOk
    }

    private suspend fun executeSingBoxProcess(
        binaryPath: String,
        configPath: String,
        workDir: File,
        attemptId: Long,
        onUnknownKeepalive: () -> Unit,
        onTunPermissionDenied: () -> Unit
    ): Boolean = coroutineScope {
        val proc = PlatformProcess()
        try {
            val command = listOf(binaryPath, "run", "-c", configPath)
            LogRepository.d("Executing Sing-box: ${command.joinToString(" ")}", "SingBoxCore")
            if (!proc.start(command, workDir.absolutePath, emptyMap())) {
                LogRepository.e("Failed to start Sing-box binary: $binaryPath", "SingBoxCore")
                return@coroutineScope false
            }
            process = proc
            updateState(ConnectionStatus.VALIDATING, attemptId)

            while (isActive && currentAttemptId.get() == attemptId) {
                val line = proc.readLine() ?: break
                parseSingBoxOutputLine(
                    line = line,
                    attemptId = attemptId,
                    onUnknownKeepalive = onUnknownKeepalive,
                    onTunPermissionDenied = onTunPermissionDenied
                )
            }

            val exitCode = proc.waitFor()
            LogRepository.i("Sing-box process terminated (Exit code: $exitCode)", "SingBoxCore")
            exitCode == 0
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (currentAttemptId.get() == attemptId) {
                LogRepository.e("Sing-box runtime error: ${e.message}", "SingBoxCore")
            }
            false
        } finally {
            proc.destroy()
            if (process === proc) process = null
        }
    }

    private fun parseSingBoxOutputLine(
        line: String,
        attemptId: Long,
        onUnknownKeepalive: () -> Unit,
        onTunPermissionDenied: () -> Unit
    ) {
        if (currentAttemptId.get() != attemptId) return
        val lower = line.lowercase()

        when {
            lower.contains("error") || lower.contains("fatal") || lower.contains("panic") ->
                LogRepository.e(line, "SingBoxCore")
            lower.contains("warn") ->
                LogRepository.w(line, "SingBoxCore")
            else ->
                LogRepository.i(line, "SingBoxCore")
        }

        if ((lower.contains("unknown field") && lower.contains("keepalive")) || (lower.contains("wireguard") && lower.contains("deprecated"))) {
            onUnknownKeepalive()
        }
        if ((lower.contains("configure tun interface") || lower.contains("inbound/tun")) &&
            (lower.contains("operation not permitted") || lower.contains("access is denied") || lower.contains("permission denied") || lower.contains("wintun"))
        ) {
            onTunPermissionDenied()
        }

        when {
            lower.contains("sing-box started") ||
            (lower.contains("inbound/socks") && lower.contains("started")) ||
            (lower.contains("inbound/tun") && lower.contains("started")) -> {
                updateState(ConnectionStatus.DATAPLANE_VALIDATED, attemptId)
                updateState(ConnectionStatus.SOCKS_READY, attemptId)
                updateState(ConnectionStatus.RUNNING, attemptId)
            }
            lower.contains("outbound/wireguard") -> {
                if (_connectionStatus.value == ConnectionStatus.STARTING) {
                    updateState(ConnectionStatus.VALIDATING, attemptId)
                }
            }
        }
    }

    /**
     * Generates the Sing-box JSON configuration (`config.json`) with:
     *  - Inbound 1: `"type": "tun"` (`"auto_route": true`, `"strict_route": true`, `"mtu": 1120`)
     *  - Local SOCKS/HTTP inbounds on `127.0.0.1` for seamless local proxy & readiness probes
     *  - Outbound 1 (`"warp-out"`): `"type": "wireguard"` -> Cloudflare WARP server
     *  - Outbound 2 (`"proton-out"`): `"type": "wireguard"` -> ProtonVPN / Custom WireGuard server
     *    with `"detour": "warp-out"`, `"mtu": 1120`, and `"keepalive": 25`
     */
    fun generateSingBoxConfigJson(
        config: AetherConfig,
        bindAddress: String,
        warpAccount: WarpAccount,
        includeTunInbound: Boolean = true,
        includeKeepaliveField: Boolean = true
    ): String {
        val socksHost = bindAddress.substringBefore(':').ifBlank { "127.0.0.1" }
        val socksPort = bindAddress.substringAfter(':', "2021").toIntOrNull() ?: 2021
        val rawHttpPort = config.httpPort.toIntOrNull() ?: 2020
        val httpPort = if (rawHttpPort == socksPort) socksPort + 1 else rawHttpPort

        val targetWg = if (config.customWgAutoSelect && config.customWgProfiles.isNotEmpty()) {
            WireGuardExitTunnel.selectFastestProfile(config.customWgProfiles, config.customWgConfig)
        } else {
            config.customWgConfig
        }

        val hasProtonWg = targetWg.isValid()
        val protonEndpointRaw = targetWg.endpoint.trim().ifBlank { "185.159.157.1:51820" }
        val protonHostRaw = if (protonEndpointRaw.startsWith("[")) {
            protonEndpointRaw.substringAfter('[').substringBefore(']')
        } else {
            protonEndpointRaw.substringBeforeLast(':')
        }.trim()
        val protonPort = protonEndpointRaw.substringAfterLast(':', "51820").trim().toIntOrNull() ?: 51820
        val protonServer = resolveHostToIpv4(protonHostRaw)
        val protonV4 = targetWg.addressV4.substringBefore('/').trim().ifBlank { "10.2.0.2" }
        val protonPrivKey = targetWg.privateKey.trim().ifBlank { warpAccount.privateKey }
        val protonPubKey = targetWg.publicKey.trim().ifBlank { warpAccount.peerPublicKey }

        val finalOutboundTag = when {
            config.exitNodeMode == ExitNodeMode.CUSTOM_WG && hasProtonWg -> "proton-out"
            config.exitNodeMode == ExitNodeMode.FIREFOX_VPN && config.firefoxVpnToken.isNotBlank() -> "firefox-out"
            config.exitNodeMode == ExitNodeMode.CUSTOM_SOCKS5 && config.customSocks5Host.isNotBlank() -> "custom-socks-out"
            hasProtonWg && config.exitNodeMode == ExitNodeMode.CUSTOM_WG -> "proton-out"
            else -> "warp-out"
        }

        val keepaliveProp = if (includeKeepaliveField) ",\n      \"keepalive\": 25" else ""

        val inboundsList = mutableListOf<String>()
        if (includeTunInbound) {
            inboundsList.add(
                """
                {
                  "type": "tun",
                  "tag": "tun-in",
                  "interface_name": "aether-tun0",
                  "inet4_address": "172.19.0.1/30",
                  "mtu": 1120,
                  "auto_route": true,
                  "strict_route": true,
                  "stack": "system",
                  "sniff": true
                }
                """.trimIndent()
            )
        }
        inboundsList.add(
            """
            {
              "type": "socks",
              "tag": "socks-in",
              "listen": "$socksHost",
              "listen_port": $socksPort,
              "sniff": true
            }
            """.trimIndent()
        )
        inboundsList.add(
            """
            {
              "type": "http",
              "tag": "http-in",
              "listen": "$socksHost",
              "listen_port": $httpPort,
              "sniff": true
            }
            """.trimIndent()
        )
        if (socksPort != 10805) {
            inboundsList.add(
                """
                {
                  "type": "socks",
                  "tag": "socks-wg-exit-in",
                  "listen": "127.0.0.1",
                  "listen_port": 10805,
                  "sniff": true
                }
                """.trimIndent()
            )
        }

        val extraOutbounds = mutableListOf<String>()
        if (config.exitNodeMode == ExitNodeMode.FIREFOX_VPN && config.firefoxVpnToken.isNotBlank()) {
            val jwt = runCatching {
                FirefoxVpnExitTunnel.resolveLiveProxyPassJwt(config.firefoxVpnToken, "127.0.0.1", 0)
            }.getOrNull() ?: config.firefoxVpnToken.trim()
            val ffEdge = FirefoxVpnExitTunnel.resolveCountryExitCandidates(config.firefoxVpnCountry, "127.0.0.1", 0).first()
            val authVal = if (jwt.startsWith("ProxyPass ", ignoreCase = true) || jwt.startsWith("Bearer ", ignoreCase = true)) {
                jwt
            } else {
                "ProxyPass $jwt"
            }
            extraOutbounds.add(
                """
                {
                  "type": "http",
                  "tag": "firefox-out",
                  "detour": "warp-out",
                  "server": "${ffEdge.host}",
                  "server_port": ${ffEdge.port},
                  "tls": {
                    "enabled": true,
                    "server_name": "${ffEdge.host}"
                  },
                  "headers": {
                    "Proxy-Authorization": "$authVal",
                    "User-Agent": "MozillaVPN/2.35.0 (sys:linux; iap:true)"
                  }
                }
                """.trimIndent()
            )
        }
        if (config.exitNodeMode == ExitNodeMode.CUSTOM_SOCKS5 && config.customSocks5Host.isNotBlank()) {
            extraOutbounds.add(
                """
                {
                  "type": "socks",
                  "tag": "custom-socks-out",
                  "detour": "warp-out",
                  "server": "${config.customSocks5Host.trim()}",
                  "server_port": ${config.customSocks5Port},
                  "username": "${config.customSocks5Username}",
                  "password": "${config.customSocks5Password}"
                }
                """.trimIndent()
            )
        }

        val extraOutboundBlock = if (extraOutbounds.isNotEmpty()) {
            ",\n    " + extraOutbounds.joinToString(",\n    ")
        } else ""

        val logLevel = if (config.coreLogLevel == AetherLogLevel.DEBUG) "debug" else "info"

        return """
{
  "log": {
    "level": "$logLevel",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "dns-remote",
        "address": "tcp://1.1.1.1",
        "detour": "$finalOutboundTag"
      },
      {
        "tag": "dns-direct",
        "address": "local",
        "detour": "direct"
      }
    ],
    "final": "dns-remote"
  },
  "inbounds": [
    ${inboundsList.joinToString(",\n    ")}
  ],
  "outbounds": [
    {
      "type": "wireguard",
      "tag": "warp-out",
      "server": "${warpAccount.server}",
      "server_port": ${warpAccount.serverPort},
      "local_address": [
        "${warpAccount.ipv4}/32"
      ],
      "private_key": "${warpAccount.privateKey}",
      "peer_public_key": "${warpAccount.peerPublicKey}",
      "reserved": [${warpAccount.reserved.joinToString(", ")}],
      "mtu": 1280$keepaliveProp
    },
    {
      "type": "wireguard",
      "tag": "proton-out",
      "detour": "warp-out",
      "server": "$protonServer",
      "server_port": $protonPort,
      "local_address": [
        "$protonV4/32"
      ],
      "private_key": "$protonPrivKey",
      "peer_public_key": "$protonPubKey",
      "mtu": 1120$keepaliveProp
    }$extraOutboundBlock,
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "final": "$finalOutboundTag"
  }
}
        """.trimIndent()
    }

    private fun resolveOrRegisterWarpAccount(config: AetherConfig, workDir: File): WarpAccount {
        val configuredEndpoint = config.wgPeer.trim().ifEmpty { config.peer.trim() }
            .ifEmpty { config.wiwOuter.trim() }
        val defaultEndpoint = if (configuredEndpoint.contains(':')) {
            val h = configuredEndpoint.substringBeforeLast(':').trim()
            val p = configuredEndpoint.substringAfterLast(':', "2408").toIntOrNull() ?: 2408
            h to p
        } else {
            resolveBestSavedWarpEndpoint(workDir)
        }

        val customPriv = config.customWgConfig.privateKey.trim()
        val candidateFiles = listOf(
            File(workDir, "aether-singbox-warp.toml"),
            File(workDir, "aether.toml"),
            File(workDir, "aether-wg.toml"),
            File(File(System.getProperty("user.home") ?: ".", ".aether"), "aether.toml")
        )

        for (file in candidateFiles) {
            if (file.exists() && file.length() > 0) {
                val parsed = parseWarpToml(file, customPriv, defaultEndpoint)
                if (parsed != null) return parsed
            }
        }

        val registered = registerCloudflareWarpOnline(workDir, defaultEndpoint)
        if (registered != null) return registered

        val fallbackKeys = WireGuardCrypto.generateKeyPair()
        return WarpAccount(
            deviceId = UUID.randomUUID().toString(),
            accessToken = UUID.randomUUID().toString(),
            server = defaultEndpoint.first,
            serverPort = defaultEndpoint.second,
            ipv4 = "172.16.0.2",
            ipv6 = "2606:4700:110::2",
            privateKey = fallbackKeys.privateKey,
            peerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            reserved = listOf(0, 0, 0)
        )
    }

    private fun resolveBestSavedWarpEndpoint(workDir: File): Pair<String, Int> {
        val epRegex = Regex("""(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})""")
        val activeFile = File(workDir, "aether-active-endpoint.txt")
        if (activeFile.exists()) {
            val m = epRegex.find(runCatching { activeFile.readText() }.getOrDefault(""))
            if (m != null) {
                val ip = m.groupValues[1]
                val port = m.groupValues[2].toIntOrNull() ?: 2408
                if (!ip.startsWith("127.") && ip != "0.0.0.0") return ip to port
            }
        }
        val lastConnFiles = workDir.listFiles { f -> f.name.contains("lastconn", ignoreCase = true) }
            ?.sortedByDescending { it.lastModified() }
            .orEmpty()
        for (f in lastConnFiles) {
            val m = epRegex.find(runCatching { f.readText() }.getOrDefault(""))
            if (m != null) {
                val ip = m.groupValues[1]
                val port = m.groupValues[2].toIntOrNull() ?: 2408
                if (!ip.startsWith("127.") && ip != "0.0.0.0") return ip to port
            }
        }
        return "162.159.192.1" to 2408
    }

    private fun parseWarpToml(file: File, customPrivateKey: String, endpoint: Pair<String, Int>): WarpAccount? {
        return try {
            val text = file.readText()
            if (text.contains("custom-wg-inner")) return null
            var devId = UUID.randomUUID().toString()
            var token = UUID.randomUUID().toString()
            var server = endpoint.first
            var port = endpoint.second
            var ipv4 = "172.16.0.2"
            var ipv6 = "2606:4700:110::2"
            var privKey = ""
            var pubKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
            val reserved = mutableListOf(0, 0, 0)

            for (line in text.lines()) {
                val clean = line.substringBefore('#').trim()
                if (!clean.contains('=')) continue
                val k = clean.substringBefore('=').trim().lowercase()
                val v = clean.substringAfter('=').trim().trim('"', '\'')
                when (k) {
                    "device_id" -> if (v.isNotBlank()) devId = v
                    "access_token" -> if (v.isNotBlank()) token = v
                    "assigned_endpoint" -> {
                        if (v.isNotBlank() && !v.startsWith("0.0.0.0") && server == "162.159.192.1") {
                            server = v.substringBefore(':')
                            port = v.substringAfter(':', "2408").toIntOrNull() ?: 2408
                        }
                    }
                    "ipv4" -> if (v.isNotBlank()) ipv4 = v.substringBefore('/')
                    "ipv6" -> if (v.isNotBlank()) ipv6 = v.substringBefore('/')
                    "wg_private_key" -> if (v.isNotBlank()) privKey = v
                    "wg_peer_public_key" -> if (v.isNotBlank()) pubKey = v
                    "client_id" -> {
                        if (v.isNotBlank()) {
                            runCatching {
                                val bytes = Base64.getDecoder().decode(v)
                                if (bytes.size >= 3) {
                                    reserved[0] = bytes[0].toInt() and 0xFF
                                    reserved[1] = bytes[1].toInt() and 0xFF
                                    reserved[2] = bytes[2].toInt() and 0xFF
                                }
                            }
                        }
                    }
                }
            }

            if (privKey.isNotBlank() && privKey != customPrivateKey) {
                WarpAccount(
                    deviceId = devId,
                    accessToken = token,
                    server = server,
                    serverPort = port,
                    ipv4 = ipv4,
                    ipv6 = ipv6,
                    privateKey = privKey,
                    peerPublicKey = pubKey,
                    reserved = reserved
                )
            } else null
        } catch (_: Exception) {
            null
        }
    }

    private fun registerCloudflareWarpOnline(workDir: File, endpoint: Pair<String, Int>): WarpAccount? {
        return try {
            val keyPair = WireGuardCrypto.generateKeyPair()
            val regBody = """{"key":"${keyPair.publicKey}","install_id":"","fcm_token":"","tos":"2026-01-01T00:00:00.000Z","model":"PC","serial_number":"${UUID.randomUUID()}","locale":"en_US"}"""
            val url = java.net.URL("https://api.cloudflareclient.com/v0a2158/reg")
            val conn = (url.openConnection() as java.net.HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 5000
                readTimeout = 5000
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Accept", "application/json")
                setRequestProperty("CF-Client-Version", "a-6.30-2158")
            }
            conn.outputStream.use { it.write(regBody.toByteArray(Charsets.UTF_8)) }
            val resp = conn.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            val devId = Regex(""""id"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1) ?: return null
            val token = Regex(""""token"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1) ?: devId
            val clientId = Regex(""""client_id"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1) ?: "AAAA"
            val v4 = Regex(""""v4"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1)?.substringBefore('/') ?: "172.16.0.2"
            val v6 = Regex(""""v6"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1)?.substringBefore('/') ?: "2606:4700:110::2"
            val peerPub = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

            val toml = buildString {
                appendLine("""device_id = "$devId"""")
                appendLine("""access_token = "$token"""")
                appendLine("""ipv4 = "$v4"""")
                appendLine("""ipv6 = "$v6"""")
                appendLine("""wg_private_key = "${keyPair.privateKey}"""")
                appendLine("""wg_peer_public_key = "$peerPub"""")
                appendLine("""assigned_endpoint = "${endpoint.first}:${endpoint.second}"""")
                appendLine("""client_id = "$clientId"""")
            }
            runCatching { File(workDir, "aether-singbox-warp.toml").writeText(toml) }

            val reserved = runCatching {
                val b = Base64.getDecoder().decode(clientId)
                if (b.size >= 3) listOf(b[0].toInt() and 0xFF, b[1].toInt() and 0xFF, b[2].toInt() and 0xFF)
                else listOf(0, 0, 0)
            }.getOrDefault(listOf(0, 0, 0))

            WarpAccount(
                deviceId = devId,
                accessToken = token,
                server = endpoint.first,
                serverPort = endpoint.second,
                ipv4 = v4,
                ipv6 = v6,
                privateKey = keyPair.privateKey,
                peerPublicKey = peerPub,
                reserved = reserved
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun resolveHostToIpv4(host: String): String {
        if (host.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$""")) || host.contains(':')) return host
        return runCatching {
            InetAddress.getAllByName(host).firstOrNull { it is Inet4Address }?.hostAddress ?: host
        }.getOrDefault(host)
    }

    private fun updateState(state: ConnectionStatus, attemptId: Long) {
        if (currentAttemptId.get() == attemptId) _connectionStatus.value = state
    }

    fun stop() {
        currentAttemptId.incrementAndGet()
        _connectionStatus.value = ConnectionStatus.STOPPED
        runnerJob?.cancel()
        process?.destroy()
        process = null
        LogRepository.i("Sing-box core shutdown initiated.", "SingBoxCore")
    }

    fun release() {
        stop()
        scope.cancel()
    }
}