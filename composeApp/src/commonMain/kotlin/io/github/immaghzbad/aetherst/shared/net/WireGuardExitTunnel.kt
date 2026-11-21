package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.model.CustomWireGuardConfig
import java.io.BufferedReader
import java.io.File
import java.io.InputStream
import java.io.InputStreamReader
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Sing-box WireGuard Exit Tunnel Manager (WARP -> ProtonVPN / Custom WireGuard via `detour: "warp-out"`).
 *
 * All manual UDP packet relays and Kotlin TCP/SOCKS socket bridges have been removed.
 * Data-plane routing and WireGuard-in-WireGuard encapsulation are handled 100% by `sing-box`
 * using `config.json` with:
 *  - Inbound `"type": "tun"` (`"auto_route": true`, `"strict_route": true`, `"mtu": 1120`)
 *  - Outbound 1 (`"tag": "warp-out"`, `"type": "wireguard"`, `"mtu": 1280`, `"keepalive": 25`)
 *  - Outbound 2 (`"tag": "proton-out"`, `"type": "wireguard"`, `"detour": "warp-out"`, `"mtu": 1120`, `"keepalive": 25`)
 */
class WireGuardExitTunnel(
    private val config: CustomWireGuardConfig,
    private val binaryPath: String? = null,
    private val workingDir: String? = null,
    private val primarySocksHost: String = "127.0.0.1",
    private val primarySocksPort: Int = 2021,
    val localListenPort: Int = 10805
) {
    private val isRunning = AtomicBoolean(false)
    private var process: Process? = null
    private var logThread: Thread? = null
    private var configFile: File? = null
    @Volatile private var attachedToPrimarySingBox = false

    @Volatile
    var verifiedExitIp: String? = null
        private set

    @Volatile
    var lastErrorMessage: String? = null
        private set

    data class WarpIdentity(
        val deviceId: String,
        val accessToken: String,
        val endpoint: String,
        val port: Int,
        val ipv4: String,
        val ipv6: String,
        val privateKey: String,
        val publicKey: String,
        val clientId: String,
        val reserved: List<Int>
    )

    fun activePort(): Int =
        if (isPortListening("127.0.0.1", localListenPort)) localListenPort else primarySocksPort

    @Synchronized
    fun start(): Boolean {
        if (isRunning.get() && isHealthy()) return true
        stopInternal()
        isRunning.set(true)
        verifiedExitIp = null
        lastErrorMessage = null

        if (!config.isValid()) {
            lastErrorMessage = "Invalid WireGuard config: Endpoint, PrivateKey or PublicKey is missing"
            LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
            isRunning.set(false)
            return false
        }

        return try {
            val workDirStr = workingDir ?: runCatching {
                val home = System.getProperty("user.home") ?: "."
                val dir = File(home, ".aether")
                dir.mkdirs()
                dir.absolutePath
            }.getOrDefault(".")
            val workDir = File(workDirStr).apply { mkdirs() }

            // If AetherProcessRunner's primary Sing-box instance is already running with proton-out
            // and listening on localListenPort (10805) or primarySocksPort (2021), attach directly!
            if (isPortListening("127.0.0.1", localListenPort) || isPortListening(primarySocksHost, primarySocksPort)) {
                val checkPort = if (isPortListening("127.0.0.1", localListenPort)) localListenPort else primarySocksPort
                val exitIp = probeExitIpViaSocks(checkPort)
                attachedToPrimarySingBox = true
                verifiedExitIp = exitIp ?: config.endpoint.substringBefore(':')
                LogRepository.i(
                    "[WgExit] Attached to active Sing-box core on port $checkPort (detour=warp-out -> proton-out, Exit IP: $verifiedExitIp)",
                    "WgExit"
                )
                return true
            }

            // Otherwise, generate config.json and launch sing-box directly
            val singBoxBin = binaryPath?.takeIf { File(it).exists() } ?: findSingBoxBinary()
            if (singBoxBin == null) {
                lastErrorMessage = "Sing-box binary not found"
                LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
                stopInternal()
                return false
            }

            val rawEndpoint = config.endpoint.trim()
            val endpointHostRaw = if (rawEndpoint.startsWith("[")) {
                rawEndpoint.substringAfter('[').substringBefore(']')
            } else {
                rawEndpoint.substringBeforeLast(':')
            }.trim()
            val endpointPort = rawEndpoint.substringAfterLast(':', "51820").trim().toIntOrNull() ?: 51820
            val endpointHost = resolveEndpointHostIfNeeded(endpointHostRaw)
            val v4 = config.addressV4.substringBefore('/').trim().ifBlank { "10.2.0.2" }
            val v6 = config.addressV6.substringBefore('/').trim()

            val warpIdentity = loadOrRegisterWarpIdentity(workDir, config.privateKey.trim())
            val primaryJson = buildSingBoxConfig(
                listenPort = localListenPort,
                endpointHost = endpointHost,
                endpointPort = endpointPort,
                v4 = v4,
                v6 = v6,
                privateKey = config.privateKey.trim(),
                publicKey = config.publicKey.trim(),
                mtu = INNER_WG_SAFE_MTU,
                warpIdentity = warpIdentity,
                includeTunInbound = true,
                includeKeepaliveField = true
            )

            val cFile = File(workDir, "config.json")
            cFile.writeText(primaryJson)
            configFile = cFile

            if (launchSingBoxProcess(singBoxBin, cFile, workDir)) {
                return true
            }

            // Fallback runtime profile if strict schema or non-root Android TUN permission requires socks-only inbound
            val runtimeFile = File(workDir, "config-runtime.json")
            runtimeFile.writeText(
                buildSingBoxConfig(
                    listenPort = localListenPort,
                    endpointHost = endpointHost,
                    endpointPort = endpointPort,
                    v4 = v4,
                    v6 = v6,
                    privateKey = config.privateKey.trim(),
                    publicKey = config.publicKey.trim(),
                    mtu = INNER_WG_SAFE_MTU,
                    warpIdentity = warpIdentity,
                    includeTunInbound = false,
                    includeKeepaliveField = false
                )
            )
            configFile = runtimeFile
            if (launchSingBoxProcess(singBoxBin, runtimeFile, workDir)) {
                return true
            }

            lastErrorMessage = "Sing-box WireGuard chain (warp-out -> proton-out) failed to start"
            LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
            stopInternal()
            false
        } catch (e: Exception) {
            lastErrorMessage = "Sing-box WireGuard exception: ${e.message}"
            LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
            stopInternal()
            false
        }
    }

    private fun launchSingBoxProcess(binPath: String, cfgFile: File, workDir: File): Boolean {
        return try {
            stopChildProcessOnly()
            val pb = ProcessBuilder(listOf(binPath, "run", "-c", cfgFile.absolutePath))
            pb.directory(workDir)
            pb.redirectErrorStream(true)
            val proc = pb.start()
            process = proc

            logThread = Thread({
                try {
                    BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                        var line: String?
                        while (proc.isAlive && reader.readLine().also { line = it } != null) {
                            val l = line ?: break
                            if (l.contains("ERROR", ignoreCase = true) || l.contains("FATAL", ignoreCase = true)) {
                                LogRepository.e("[sing-box] $l", "sing-box")
                            } else {
                                LogRepository.i("[sing-box] $l", "sing-box")
                            }
                        }
                    }
                } catch (_: Exception) {}
            }, "SingBox-WgExit-Logger").apply { isDaemon = true; start() }

            val startWait = System.currentTimeMillis()
            while (System.currentTimeMillis() - startWait < 8_000L) {
                if (!proc.isAlive) return false
                if (isPortListening("127.0.0.1", localListenPort)) {
                    verifiedExitIp = probeExitIpViaSocks(localListenPort) ?: config.endpoint.substringBefore(':')
                    return true
                }
                Thread.sleep(200)
            }
            false
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Generates the Sing-box JSON configuration with:
     *  - Inbound `"type": "tun"` (`"auto_route": true`, `"strict_route": true`, `"mtu": 1120`)
     *  - Outbound 1 (`"tag": "warp-out"`, `"type": "wireguard"`, `"mtu": 1280`, `"keepalive": 25`)
     *  - Outbound 2 (`"tag": "proton-out"`, `"type": "wireguard"`, `"detour": "warp-out"`, `"mtu": 1120`, `"keepalive": 25`)
     */
    fun buildSingBoxConfig(
        listenPort: Int,
        endpointHost: String,
        endpointPort: Int,
        v4: String,
        v6: String,
        privateKey: String,
        publicKey: String,
        mtu: Int = INNER_WG_SAFE_MTU,
        warpIdentity: WarpIdentity,
        includeTunInbound: Boolean = true,
        includeKeepaliveField: Boolean = true
    ): String {
        val cleanV4 = if (v4.contains('/')) v4 else "$v4/32"
        val localAddresses = mutableListOf("\"$cleanV4\"")
        if (v6.isNotBlank()) {
            val safeV6 = if (v6.contains('/')) v6 else "$v6/128"
            localAddresses.add("\"$safeV6\"")
        }

        val primaryWgDns = config.dnsServers.firstOrNull {
            it.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))
        } ?: "10.2.0.1"

        val keepaliveProp = if (includeKeepaliveField) ",\n              \"keepalive\": 25" else ""

        val tunInboundBlock = if (includeTunInbound) {
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
            },
            """.trimIndent()
        } else ""

        return """
        {
          "log": {
            "level": "info",
            "timestamp": true
          },
          "dns": {
            "servers": [
              {
                "tag": "dns-proton",
                "address": "udp://$primaryWgDns",
                "detour": "proton-out"
              },
              {
                "tag": "dns-cf",
                "address": "tcp://1.1.1.1",
                "detour": "proton-out"
              }
            ],
            "final": "dns-proton"
          },
          "inbounds": [
            $tunInboundBlock
            {
              "type": "socks",
              "tag": "socks-in",
              "listen": "127.0.0.1",
              "listen_port": $listenPort
            },
            {
              "type": "http",
              "tag": "http-in",
              "listen": "127.0.0.1",
              "listen_port": ${listenPort - 1}
            }
          ],
          "outbounds": [
            {
              "type": "wireguard",
              "tag": "warp-out",
              "server": "${warpIdentity.endpoint}",
              "server_port": ${warpIdentity.port},
              "local_address": ["${warpIdentity.ipv4}/32"],
              "private_key": "${warpIdentity.privateKey}",
              "peer_public_key": "${warpIdentity.publicKey}",
              "reserved": [${warpIdentity.reserved.joinToString(", ")}],
              "mtu": 1280$keepaliveProp
            },
            {
              "type": "wireguard",
              "tag": "proton-out",
              "detour": "warp-out",
              "server": "$endpointHost",
              "server_port": $endpointPort,
              "local_address": [${localAddresses.joinToString(", ")}],
              "private_key": "$privateKey",
              "peer_public_key": "$publicKey",
              "mtu": $mtu$keepaliveProp
            },
            {
              "type": "direct",
              "tag": "direct"
            }
          ],
          "route": {
            "auto_detect_interface": true,
            "final": "proton-out"
          }
        }
        """.trimIndent()
    }

    @Synchronized
    fun stop() {
        stopInternal()
    }

    private fun stopChildProcessOnly() {
        try {
            process?.let { p ->
                if (p.isAlive) {
                    p.destroy()
                    p.waitFor(1000, TimeUnit.MILLISECONDS)
                    if (p.isAlive) p.destroyForcibly()
                }
            }
        } catch (_: Exception) {}
        process = null
        runCatching { logThread?.interrupt() }
        logThread = null
    }

    private fun stopInternal() {
        isRunning.set(false)
        verifiedExitIp = null
        attachedToPrimarySingBox = false
        stopChildProcessOnly()
    }

    fun isConnected(): Boolean =
        isRunning.get() && (attachedToPrimarySingBox || process?.isAlive == true)

    fun isHealthy(): Boolean =
        isRunning.get() && (attachedToPrimarySingBox || process?.isAlive == true) &&
            (isPortListening("127.0.0.1", localListenPort) || isPortListening(primarySocksHost, primarySocksPort))

    private fun loadOrRegisterWarpIdentity(workDir: File, customPrivateKey: String): WarpIdentity {
        val searchDirs = listOf(
            workDir,
            File(System.getProperty("user.home") ?: ".", ".aether"),
            File(System.getenv("AppData") ?: ".", "AetherST-Tunnel/bin")
        )
        val bestEndpoint = "162.159.192.1" to 2408

        for (dir in searchDirs) {
            for (fn in listOf("aether-singbox-warp.toml", "aether.toml", "aether-wg.toml")) {
                val f = File(dir, fn)
                if (f.exists() && f.length() > 0) {
                    val parsed = parseWarpIdentityFromToml(f, customPrivateKey, bestEndpoint)
                    if (parsed != null) return parsed
                }
            }
        }

        val keyPair = WireGuardCrypto.generateKeyPair()
        return WarpIdentity(
            deviceId = UUID.randomUUID().toString(),
            accessToken = UUID.randomUUID().toString(),
            endpoint = bestEndpoint.first,
            port = bestEndpoint.second,
            ipv4 = "172.16.0.2",
            ipv6 = "2606:4700:110::2",
            privateKey = keyPair.privateKey,
            publicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            clientId = "AAAA",
            reserved = listOf(0, 0, 0)
        )
    }

    private fun parseWarpIdentityFromToml(
        file: File,
        customPrivateKey: String,
        bestEndpoint: Pair<String, Int>
    ): WarpIdentity? {
        return try {
            val text = file.readText()
            if (text.contains("custom-wg-inner")) return null
            var devId = UUID.randomUUID().toString()
            var token = UUID.randomUUID().toString()
            var endpoint = bestEndpoint.first
            var port = bestEndpoint.second
            var ipv4 = "172.16.0.2"
            var ipv6 = "2606:4700:110::2"
            var privKey = ""
            var pubKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
            var clientId = "AAAA"
            val reservedList = mutableListOf(0, 0, 0)

            for (line in text.lines()) {
                val clean = line.substringBefore('#').trim()
                if (!clean.contains('=')) continue
                val k = clean.substringBefore('=').trim().lowercase()
                val v = clean.substringAfter('=').trim().trim('"', '\'')
                when (k) {
                    "device_id" -> if (v.isNotBlank()) devId = v
                    "access_token" -> if (v.isNotBlank()) token = v
                    "assigned_endpoint" -> {
                        if (v.isNotBlank() && !v.startsWith("0.0.0.0")) {
                            endpoint = v.substringBefore(':')
                            port = v.substringAfter(':', "2408").toIntOrNull() ?: 2408
                        }
                    }
                    "ipv4" -> if (v.isNotBlank()) ipv4 = v.substringBefore('/')
                    "ipv6" -> if (v.isNotBlank()) ipv6 = v.substringBefore('/')
                    "wg_private_key" -> if (v.isNotBlank()) privKey = v
                    "wg_peer_public_key" -> if (v.isNotBlank()) pubKey = v
                    "client_id" -> {
                        if (v.isNotBlank()) {
                            clientId = v
                            runCatching {
                                val bytes = Base64.getDecoder().decode(v)
                                if (bytes.size >= 3) {
                                    reservedList[0] = bytes[0].toInt() and 0xFF
                                    reservedList[1] = bytes[1].toInt() and 0xFF
                                    reservedList[2] = bytes[2].toInt() and 0xFF
                                }
                            }
                        }
                    }
                }
            }

            if (privKey.isNotBlank() && privKey != customPrivateKey) {
                WarpIdentity(
                    deviceId = devId,
                    accessToken = token,
                    endpoint = endpoint,
                    port = port,
                    ipv4 = ipv4,
                    ipv6 = ipv6,
                    privateKey = privKey,
                    publicKey = pubKey,
                    clientId = clientId,
                    reserved = reservedList
                )
            } else null
        } catch (_: Exception) {
            null
        }
    }

    private fun resolveEndpointHostIfNeeded(host: String): String {
        val isIpv4 = host.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))
        val isIpv6 = host.contains(':')
        if (isIpv4 || isIpv6) return host
        return runCatching {
            InetAddress.getAllByName(host)
                .firstOrNull { it is Inet4Address }
                ?.hostAddress ?: host
        }.getOrDefault(host)
    }

    private fun findSingBoxBinary(): String? {
        val binName = if ((System.getProperty("os.name") ?: "").lowercase().contains("win")) "sing-box.exe" else "sing-box"
        val candidates = listOf(
            File("composeApp/src/desktopMain/resources/bin", binName),
            File("bin", binName),
            File(binName)
        )
        return candidates.firstOrNull { it.exists() && it.isFile }?.absolutePath
    }

    private fun probeExitIpViaSocks(socksPort: Int): String? {
        return try {
            Socket().use { socket ->
                socket.soTimeout = 4000
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2000)
                val out = socket.getOutputStream()
                val input = socket.getInputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val authResp = ByteArray(2)
                readFully(input, authResp)
                if (authResp[0] == 0x05.toByte() && authResp[1] == 0x00.toByte()) {
                    val req = byteArrayOf(0x05, 0x01, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x50)
                    out.write(req)
                    out.flush()
                    val connResp = ByteArray(4)
                    readFully(input, connResp)
                    if (connResp[1] == 0x00.toByte()) {
                        when (connResp[3]) {
                            0x01.toByte() -> readFully(input, ByteArray(6))
                            0x03.toByte() -> {
                                val len = input.read()
                                if (len > 0) readFully(input, ByteArray(len + 2))
                            }
                            0x04.toByte() -> readFully(input, ByteArray(18))
                        }
                        val httpReq = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n"
                        out.write(httpReq.toByteArray(Charsets.US_ASCII))
                        out.flush()
                        val text = input.bufferedReader(Charsets.US_ASCII).readText()
                        Regex("""(?m)^ip=(.+)$""").find(text)?.groupValues?.get(1)?.trim()
                    } else null
                } else null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val count = input.read(buffer, offset, buffer.size - offset)
            if (count < 0) throw java.io.EOFException("Premature EOF")
            offset += count
        }
    }

    private fun isPortListening(host: String, port: Int): Boolean {
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(host, port), 250)
                true
            }
        } catch (_: Exception) {
            false
        }
    }

    companion object {
        const val INNER_WG_SAFE_MTU = 1120

        fun probeProfilesFast(
            profiles: List<CustomWireGuardConfig>,
            timeoutMs: Int = 1200
        ): List<CustomWireGuardConfig> {
            val valid = profiles.filter { it.isValid() }
            if (valid.isEmpty()) return profiles

            val executor = Executors.newFixedThreadPool(valid.size.coerceIn(1, 8))
            val updated = ConcurrentHashMap<String, Long>()

            val futures = valid.map { cfg ->
                executor.submit {
                    val endpoint = cfg.endpoint.substringBefore(':').trim()
                    val port = cfg.endpoint.substringAfter(':', "51820").toIntOrNull() ?: 51820
                    val start = System.currentTimeMillis()
                    var ping = -1L
                    try {
                        Socket().use { s ->
                            s.connect(InetSocketAddress(endpoint, port), timeoutMs)
                            ping = System.currentTimeMillis() - start
                        }
                    } catch (_: Exception) {
                        val elapsed = System.currentTimeMillis() - start
                        if (elapsed in 10..timeoutMs) {
                            ping = elapsed
                        }
                    }
                    updated[cfg.id] = ping
                }
            }

            for (f in futures) {
                runCatching { f.get(timeoutMs.toLong() + 200, TimeUnit.MILLISECONDS) }
            }
            executor.shutdownNow()

            return profiles.map { p ->
                val newPing = updated[p.id]
                if (newPing != null && newPing > 0) p.copy(lastPingMs = newPing) else p
            }
        }

        fun selectFastestProfile(
            profiles: List<CustomWireGuardConfig>,
            fallback: CustomWireGuardConfig
        ): CustomWireGuardConfig {
            val valid = profiles.filter { it.isValid() }
            if (valid.isEmpty()) return fallback
            if (valid.size == 1) return valid.first()

            val sorted = valid.sortedBy { if (it.lastPingMs > 0) it.lastPingMs else Long.MAX_VALUE }
            return sorted.first()
        }
    }
}
