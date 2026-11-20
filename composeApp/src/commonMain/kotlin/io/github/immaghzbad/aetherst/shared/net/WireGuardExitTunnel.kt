package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.model.CustomWireGuardConfig
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.BufferedReader
import java.io.DataInputStream
import java.io.File
import java.io.InputStream
import java.io.InputStreamReader
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.net.URL
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Userspace Two-Layer WireGuard Exit Tunnel Manager (Cloudflare WARP Layer 1 -> Proton/Custom WireGuard Layer 2).
 *
 * Dual-Engine Architecture:
 *  1. **Engine 1 (Isolated Native `aether --gool-classic` in `wg_chain/` on `127.0.0.1:10805`)**:
 *     - Uses the freshly validated Cloudflare WARP endpoint (`aether-active-endpoint.txt` / `*lastconn*.toml`)
 *       from Layer 1 as `--wiw-outer <warp_ip:port>` and the Proton/Custom WireGuard endpoint as
 *       `--wiw-inner <proton_ip:port>`, skipping endpoint scanning completely.
 *     - Provisions a dedicated secondary Cloudflare WARP identity in `wg_chain/aether.toml` (so it never
 *       collides with Layer-1 `aether.toml`'s active WireGuard session) and writes `wg_chain/aether-secondary.toml`
 *       with all 6 mandatory TOML fields (`device_id`, `access_token`, `ipv4`, `ipv6`, `wg_private_key`,
 *       `wg_peer_public_key`, plus `assigned_endpoint` and `client_id = "AAAA"`).
 *     - Sets `AETHER_REPROVISION=0` (keeping the Proton identity intact) and `AETHER_WG_NO_DATA_CHECK=1`
 *       (since the outer hop produces `obf=1` noise while the inner hop uses standard `obf=0` WireGuard).
 *  2. **Engine 2 (`sing-box` Two-Stage Userspace WireGuard Chain via `LocalWarpUdpRelay`)**:
 *     - Starts an in-process `LocalWarpUdpRelay` on `127.0.0.1:<ephemeral_udp_port>` holding a single
 *       persistent outbound `DatagramSocket` to `<warp_ip:port>`. Whenever `sing-box` sends a 148-byte
 *       WireGuard Type-1 Handshake Initiation packet (`0x01 0x00 0x00 0x00`), `LocalWarpUdpRelay` injects
 *       the `aethernoize` UDP opener burst on that exact same outbound `DatagramSocket` (same 5-tuple source
 *       port) 20ms before forwarding the handshake packet.
 *     - Uses dedicated `aether-singbox-warp.toml` for `"outer-warp"` and chains `"proton-exit"` (`"detour": "outer-warp"`),
 *       with automatic fallback across Proton VPN's official WireGuard UDP ports (`51820`, `443`, `53`, `88`, `4500`).
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
    private var udpRelay: LocalWarpUdpRelay? = null

    @Volatile private var bridgeSocksServer: ServerSocket? = null
    @Volatile private var bridgeHttpServer: ServerSocket? = null
    @Volatile private var bridgeModeActive: Boolean = false
    private val bridgeExecutor = Executors.newCachedThreadPool()

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

    data class TraceProbeResult(
        val ip: String,
        val country: String,
        val warpState: String
    )

    /**
     * Same-5-Tuple UDP Relay for `sing-box` `"outer-warp"`.
     * Holds a single outbound `DatagramSocket` to the Cloudflare WARP endpoint so that the UDP noise opener
     * burst and `sing-box`'s 148-byte WireGuard Type-1 Handshake Initiation share the exact same local UDP
     * source port (5-tuple).
     */
    private class LocalWarpUdpRelay(
        private val remoteHost: String,
        private val remotePort: Int
    ) {
        private val active = AtomicBoolean(false)
        private var localSocket: DatagramSocket? = null
        private var remoteSocket: DatagramSocket? = null
        @Volatile private var singBoxClientAddr: SocketAddress? = null
        @Volatile private var lastNoiseSentAt: Long = 0L

        val listenPort: Int
            get() = localSocket?.localPort ?: 0

        fun start(): Boolean {
            return try {
                val remoteAddr = InetAddress.getByName(remoteHost)
                val loc = DatagramSocket(InetSocketAddress("127.0.0.1", 0))
                val rem = DatagramSocket()
                rem.connect(remoteAddr, remotePort)
                localSocket = loc
                remoteSocket = rem
                active.set(true)

                // Send initial noise burst on the connected outbound socket immediately
                sendNoiseOnRemoteSocket(rem, remoteAddr)
                lastNoiseSentAt = System.currentTimeMillis()

                // Upstream loop: sing-box (127.0.0.1) -> remote Cloudflare WARP
                thread(start = true, isDaemon = true, name = "WgExit-WarpUdpUp") {
                    val buf = ByteArray(4096)
                    while (active.get() && !loc.isClosed && !rem.isClosed) {
                        try {
                            val pkt = DatagramPacket(buf, buf.size)
                            loc.receive(pkt)
                            singBoxClientAddr = pkt.socketAddress
                            val len = pkt.length
                            val off = pkt.offset

                            // Detect WireGuard Type-1 Handshake Initiation (148 bytes, type 0x01 0x00 0x00 0x00)
                            val isWgInit = len >= 148 &&
                                buf[off] == 0x01.toByte() &&
                                buf[off + 1] == 0x00.toByte() &&
                                buf[off + 2] == 0x00.toByte() &&
                                buf[off + 3] == 0x00.toByte()

                            val now = System.currentTimeMillis()
                            if (isWgInit && (now - lastNoiseSentAt > 1500L)) {
                                sendNoiseOnRemoteSocket(rem, remoteAddr)
                                lastNoiseSentAt = System.currentTimeMillis()
                                Thread.sleep(18)
                            }

                            rem.send(DatagramPacket(buf, off, len, remoteAddr, remotePort))
                        } catch (_: Exception) {
                            if (!active.get()) break
                        }
                    }
                }

                // Downstream loop: remote Cloudflare WARP -> sing-box (127.0.0.1)
                thread(start = true, isDaemon = true, name = "WgExit-WarpUdpDown") {
                    val buf = ByteArray(4096)
                    while (active.get() && !loc.isClosed && !rem.isClosed) {
                        try {
                            val pkt = DatagramPacket(buf, buf.size)
                            rem.receive(pkt)
                            val client = singBoxClientAddr ?: continue
                            loc.send(DatagramPacket(buf, pkt.offset, pkt.length, client))
                        } catch (_: Exception) {
                            if (!active.get()) break
                        }
                    }
                }

                true
            } catch (e: Exception) {
                LogRepository.w("[WgExit] LocalWarpUdpRelay failed to start: ${e.message}", "WgExit")
                stop()
                false
            }
        }

        private fun sendNoiseOnRemoteSocket(rem: DatagramSocket, remoteAddr: InetAddress) {
            runCatching {
                val rng = SecureRandom()
                for (size in intArrayOf(38, 64, 92, 128, 76)) {
                    val noise = ByteArray(size)
                    rng.nextBytes(noise)
                    noise[0] = (0x80 or (noise[0].toInt() and 0x7F)).toByte()
                    rem.send(DatagramPacket(noise, noise.size, remoteAddr, remotePort))
                    Thread.sleep(10)
                }
            }
        }

        fun stop() {
            active.set(false)
            runCatching { localSocket?.close() }
            localSocket = null
            runCatching { remoteSocket?.close() }
            remoteSocket = null
        }
    }

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
            val workDir = File(workDirStr)
            workDir.mkdirs()

            // Wait up to 6s for Layer-1 SOCKS5 (127.0.0.1:2021) if it is finishing startup
            if (primarySocksPort > 0 && !isPortListening(primarySocksHost, primarySocksPort)) {
                val deadline = System.currentTimeMillis() + 6_000L
                while (System.currentTimeMillis() < deadline && !isPortListening(primarySocksHost, primarySocksPort)) {
                    Thread.sleep(200)
                }
            }

            val hasNativeInnerConfig = runCatching {
                val sec = File(workDir, "aether-secondary.toml")
                sec.exists() && sec.readText().contains("custom-wg-inner")
            }.getOrDefault(false)

            if (primarySocksPort > 0 && isPortListening(primarySocksHost, primarySocksPort)) {
                val traceAttempts = if (hasNativeInnerConfig) 3 else 1
                for (attempt in 1..traceAttempts) {
                    val primaryTrace = probeCloudflareTraceFull(primarySocksPort)
                    if (primaryTrace != null &&
                        primaryTrace.country != "IR" &&
                        (primaryTrace.warpState.equals("off", ignoreCase = true) || hasNativeInnerConfig)
                    ) {
                        LogRepository.i(
                            "[WgExit] Layer-1 port $primarySocksPort is already exiting via inner WireGuard " +
                                "(IP: ${primaryTrace.ip}, Country: ${primaryTrace.country}, warp=${primaryTrace.warpState}). Starting local bridge on $localListenPort...",
                            "WgExit"
                        )
                        if (startNativePassthroughBridge(localListenPort)) {
                            verifiedExitIp = primaryTrace.ip
                            return true
                        }
                    }
                    if (hasNativeInnerConfig) {
                        val fallbackIp = verifyDataPlane(primarySocksPort)
                        if (fallbackIp != null) {
                            LogRepository.i(
                                "[WgExit] Layer-1 port $primarySocksPort native 2-layer data-plane verified (Exit IP: $fallbackIp). Starting local bridge on $localListenPort...",
                                "WgExit"
                            )
                            if (startNativePassthroughBridge(localListenPort)) {
                                verifiedExitIp = fallbackIp
                                return true
                            }
                        }
                        if (attempt < traceAttempts) Thread.sleep(800)
                    }
                }
            }

            if (isPortListening("127.0.0.1", localListenPort) || isPortListening("127.0.0.1", localListenPort - 1)) {
                LogRepository.w("[WgExit] Port $localListenPort is busy; cleaning up stale process...", "WgExit")
                killStaleProcess(localListenPort)
                Thread.sleep(350)
            }

            val rawEndpoint = config.endpoint.trim()
            val endpointHostRaw = if (rawEndpoint.startsWith("[")) {
                rawEndpoint.substringAfter('[').substringBefore(']')
            } else {
                rawEndpoint.substringBeforeLast(':')
            }.trim()
            val configuredPort = rawEndpoint.substringAfterLast(':', "51820").trim().toIntOrNull() ?: 51820
            val endpointHost = resolveEndpointHostIfNeeded(endpointHostRaw)

            val v4 = config.addressV4.substringBefore('/').trim().ifBlank { "10.2.0.2" }
            val v6 = config.addressV6.substringBefore('/').trim().ifBlank { "fd00::2" }
            val safeInnerMtu = config.mtu.takeIf { it in 1000..1140 } ?: INNER_WG_SAFE_MTU

            // Load or register a DEDICATED secondary Cloudflare WARP identity (aether-singbox-warp.toml)
            // so Layer-2 never collides with Layer-1's active aether.toml WireGuard peer session.
            val warpIdentity = loadOrRegisterDedicatedWarpIdentity(workDir, config.privateKey.trim(), primarySocksPort)

            // Candidate Proton/Custom WireGuard UDP ports (configured port first, then Proton's official alternative ports)
            val candidatePorts = linkedSetOf(configuredPort, 51820, 443, 53, 88, 4500).toList()

            // =================================================================
            // ENGINE 1: Isolated Native Aether `--gool-classic` in `wg_chain/`
            // =================================================================
            val aetherBin = findAetherBinary(workDir)
            if (aetherBin != null && warpIdentity != null) {
                for (tryPort in candidatePorts.take(2)) {
                    LogRepository.i(
                        "[WgExit] Starting Engine 1 (Native Aether 2-Layer WireGuard: Outer ${warpIdentity.endpoint}:${warpIdentity.port} -> Inner $endpointHost:$tryPort)...",
                        "WgExit"
                    )
                    if (tryStartIsolatedAetherChain(
                            aetherBin = aetherBin,
                            workDir = workDir,
                            warpIdentity = warpIdentity,
                            innerHost = endpointHost,
                            innerPort = tryPort,
                            cleanIpv4 = v4,
                            cleanIpv6 = v6
                        )
                    ) {
                        return true
                    }
                    stopChildProcessOnly()
                }
            }

            // =================================================================
            // ENGINE 2: `sing-box` Two-Stage Userspace WireGuard via Same-5-Tuple `LocalWarpUdpRelay`
            // =================================================================
            val singBoxBin = binaryPath?.takeIf { File(it).exists() } ?: findSingBoxBinary()
            if (singBoxBin != null) {
                for (tryPort in candidatePorts.take(3)) {
                    if (tryStartSingBoxChain(
                            binPath = singBoxBin,
                            workDir = workDir,
                            warpIdentity = warpIdentity,
                            endpointHost = endpointHost,
                            endpointPort = tryPort,
                            v4 = v4,
                            v6 = config.addressV6.substringBefore('/').trim(),
                            mtu = safeInnerMtu
                        )
                    ) {
                        return true
                    }
                    stopChildProcessOnly()
                }
            }

            lastErrorMessage = "Layer-2 WireGuard handshake failed over Layer-1 (verify Proton WireGuard key/server or generate a fresh config)"
            LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
            stopInternal()
            false
        } catch (e: Exception) {
            lastErrorMessage = "Startup exception: ${e.message}"
            LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
            stopInternal()
            false
        }
    }

    private fun tryStartIsolatedAetherChain(
        aetherBin: String,
        workDir: File,
        warpIdentity: WarpIdentity,
        innerHost: String,
        innerPort: Int,
        cleanIpv4: String,
        cleanIpv6: String
    ): Boolean {
        return try {
            if (!isRunning.get()) return false
            val chainDir = File(workDir, "wg_chain")
            chainDir.mkdirs()

            // Remove any stale .corrupt or lastconn files
            chainDir.listFiles()?.forEach { f ->
                if (f.name.endsWith(".corrupt") || f.name.contains("lastconn")) {
                    runCatching { f.delete() }
                }
            }

            val outerEp = "${warpIdentity.endpoint}:${warpIdentity.port}"
            val innerEp = "$innerHost:$innerPort"

            // Outer Cloudflare WARP identity (with mandatory ipv6 field!)
            val outerTomlContent = buildString {
                appendLine("""device_id = "${warpIdentity.deviceId}"""")
                appendLine("""access_token = "${warpIdentity.accessToken}"""")
                appendLine("""ipv4 = "${warpIdentity.ipv4}"""")
                appendLine("""ipv6 = "${warpIdentity.ipv6}"""")
                appendLine("""wg_private_key = "${warpIdentity.privateKey}"""")
                appendLine("""wg_peer_public_key = "${warpIdentity.publicKey}"""")
                appendLine("""assigned_endpoint = "$outerEp"""")
                appendLine("""client_id = "${warpIdentity.clientId}"""")
            }
            for (name in listOf("aether.toml", "aether-wg.toml")) {
                File(chainDir, name).writeText(outerTomlContent)
            }

            // Inner Proton/Custom WireGuard identity (with mandatory ipv6 field!)
            val innerTomlContent = buildString {
                appendLine("""device_id = "custom-wg-inner"""")
                appendLine("""access_token = "custom-wg-token"""")
                appendLine("""ipv4 = "$cleanIpv4"""")
                appendLine("""ipv6 = "$cleanIpv6"""")
                appendLine("""wg_private_key = "${config.privateKey.trim()}"""")
                appendLine("""wg_peer_public_key = "${config.publicKey.trim()}"""")
                appendLine("""assigned_endpoint = "$innerEp"""")
                appendLine("""client_id = "AAAA"""")
            }
            for (name in listOf("aether-secondary.toml", "aether-wg-secondary.toml", "aether-gool.toml", "aether-masque-gool.toml")) {
                File(chainDir, name).writeText(innerTomlContent)
            }

            val customDns = config.dnsServers.firstOrNull { it.isNotBlank() } ?: "10.2.0.1"
            val combinedDns = "$customDns,1.1.1.1,1.0.0.1"

            val cmd = listOf(
                aetherBin,
                "--bind", "127.0.0.1:$localListenPort",
                "--http-proxy", "127.0.0.1:${localListenPort - 1}",
                "--gool-classic",
                "--wiw-outer", outerEp,
                "--wiw-inner", innerEp,
                "--api-address", "127.0.0.1:1",
                "--no-data-check",
                "--noize", "balanced",
                "-4",
                "--keepalive", "15",
                "--dns", combinedDns
            )

            val pb = ProcessBuilder(cmd)
            pb.directory(chainDir)
            val env = pb.environment()
            env.remove("AETHER_EXIT_LOC")
            env["AETHER_PROTOCOL"] = "gool"
            env["AETHER_GOOL_MODE"] = "classic"
            env["AETHER_WIW_OUTER_PEER"] = outerEp
            env["AETHER_WIW_INNER_PEER"] = innerEp
            env["AETHER_API_ADDRESS"] = "127.0.0.1:1"
            env["AETHER_REPROVISION"] = "0"
            env["AETHER_WG_NO_DATA_CHECK"] = "1"
            env["AETHER_WG_STALE_SECS"] = "86400"
            env["AETHER_DNS"] = combinedDns
            env["AETHER_LOG_LEVEL"] = "debug"
            pb.redirectErrorStream(true)

            val proc = pb.start()
            process = proc

            val establishingInner = AtomicBoolean(false)
            val innerHandshakeDone = AtomicBoolean(false)
            val innerReadySignal = AtomicBoolean(false)
            val innerFailedSignal = AtomicBoolean(false)
            @Volatile var loggedExitIp: String? = null
            val exitRegex = Regex("""(?i)\b(?:warp-in-warp|gool)\s+exit:\s*([0-9a-fA-F.:]+),\s*([A-Za-z]{2})""")
            val acceptedRegex = Regex("""(?i)exit\s+location\s+([A-Za-z]{2})\s+accepted\s*\(([0-9a-fA-F.:]+)\)""")

            logThread = Thread({
                try {
                    BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                        var line: String? = null
                        while (proc.isAlive && reader.readLine().also { line = it } != null) {
                            val l = line ?: break
                            val low = l.lowercase()
                            if (!low.contains("[wg] timer") && !low.contains("[wg] recv")) {
                                LogRepository.i("[AetherChain] $l", "WgExit")
                            }
                            exitRegex.find(l)?.let { m ->
                                val ip = m.groupValues[1].trim()
                                val cc = m.groupValues[2].trim().uppercase()
                                if (ip.isNotEmpty() && cc != "IR") {
                                    loggedExitIp = ip
                                    innerReadySignal.set(true)
                                }
                            }
                            acceptedRegex.find(l)?.let { m ->
                                val cc = m.groupValues[1].trim().uppercase()
                                val ip = m.groupValues[2].trim()
                                if (ip.isNotEmpty() && cc != "IR") {
                                    loggedExitIp = ip
                                    innerReadySignal.set(true)
                                }
                            }
                            if (low.contains("establishing inner warp tunnel") ||
                                (low.contains("inner endpoint") && low.contains("tunneled through outer"))
                            ) {
                                establishingInner.set(true)
                            } else if (establishingInner.get() && (
                                low.contains("[wg] handshake done") ||
                                low.contains("[wg] handshake success") ||
                                low.contains("[wg] dataplane ok")
                            )) {
                                innerHandshakeDone.set(true)
                            } else if ((low.contains("inner endpoint") || low.contains("outer endpoint")) && low.contains("failed")) {
                                innerFailedSignal.set(true)
                            }
                        }
                    }
                } catch (_: Exception) {}
            }, "Aether-WgChain-Logger").apply { isDaemon = true; start() }

            // Wait up to 18s for outer WARP + inner Proton WireGuard handshake to complete.
            // CRITICAL: Do NOT probe 127.0.0.1:localListenPort BEFORE innerHandshakeDone or innerReadySignal,
            // because aether binds localListenPort at t=0.05s before the inner tunnel is established!
            val deadline = System.currentTimeMillis() + 18_000L
            while (System.currentTimeMillis() < deadline && isRunning.get()) {
                if (!proc.isAlive || innerFailedSignal.get()) break

                if (innerReadySignal.get()) {
                    val exitIp = loggedExitIp ?: innerHost
                    verifiedExitIp = exitIp
                    LogRepository.i(
                        "[WgExit] Engine 1 (Native Aether 2-Layer WireGuard) verified via exitloc! Exit IP: $exitIp",
                        "WgExit"
                    )
                    return true
                }

                if (innerHandshakeDone.get()) {
                    Thread.sleep(300)
                    if (innerReadySignal.get()) {
                        val exitIp = loggedExitIp ?: innerHost
                        verifiedExitIp = exitIp
                        LogRepository.i(
                            "[WgExit] Engine 1 (Native Aether 2-Layer WireGuard) verified! Exit IP: $exitIp",
                            "WgExit"
                        )
                        return true
                    }
                    val probedIp = verifyDataPlane(localListenPort)
                    if (probedIp != null) {
                        verifiedExitIp = probedIp
                        LogRepository.i(
                            "[WgExit] Engine 1 (Native Aether 2-Layer WireGuard) handshake + data-plane verified! Exit IP: $probedIp",
                            "WgExit"
                        )
                        return true
                    }
                    if (innerReadySignal.get() || proc.isAlive) {
                        val fallbackIp = loggedExitIp ?: innerHost
                        verifiedExitIp = fallbackIp
                        LogRepository.i(
                            "[WgExit] Engine 1 (Native Aether 2-Layer WireGuard) inner handshake active! Exit: $fallbackIp",
                            "WgExit"
                        )
                        return true
                    }
                }
                Thread.sleep(200)
            }
            false
        } catch (e: Exception) {
            LogRepository.w("[WgExit] Engine 1 exception: ${e.message}", "WgExit")
            false
        }
    }

    private fun sendDirectUdpNoiseOpener(host: String, port: Int) {
        runCatching {
            val addr = InetAddress.getByName(host)
            DatagramSocket().use { sock ->
                val rng = SecureRandom()
                for (sz in intArrayOf(38, 64, 92, 128, 76)) {
                    val buf = ByteArray(sz)
                    rng.nextBytes(buf)
                    buf[0] = (0x80 or (buf[0].toInt() and 0x7F)).toByte()
                    sock.send(DatagramPacket(buf, buf.size, addr, port))
                    Thread.sleep(12)
                }
            }
        }
    }

    private fun tryStartSingBoxChain(
        binPath: String,
        workDir: File,
        warpIdentity: WarpIdentity?,
        endpointHost: String,
        endpointPort: Int,
        v4: String,
        v6: String,
        mtu: Int
    ): Boolean {
        return try {
            var effectiveWarpIdentity = warpIdentity
            if (warpIdentity != null) {
                val relay = LocalWarpUdpRelay(warpIdentity.endpoint, warpIdentity.port)
                if (relay.start() && relay.listenPort > 0) {
                    udpRelay = relay
                    effectiveWarpIdentity = warpIdentity.copy(endpoint = "127.0.0.1", port = relay.listenPort)
                    LogRepository.i(
                        "[WgExit] LocalWarpUdpRelay active on 127.0.0.1:${relay.listenPort} -> ${warpIdentity.endpoint}:${warpIdentity.port}",
                        "WgExit"
                    )
                } else {
                    sendDirectUdpNoiseOpener(warpIdentity.endpoint, warpIdentity.port)
                }
            }

            val cfgJson = buildSingBoxConfig(
                listenPort = localListenPort,
                endpointHost = endpointHost,
                endpointPort = endpointPort,
                v4 = v4,
                v6 = v6,
                privateKey = config.privateKey.trim(),
                publicKey = config.publicKey.trim(),
                mtu = mtu,
                warpIdentity = effectiveWarpIdentity
            )

            val cFile = File(workDir, "singbox-wg-${localListenPort}.json")
            cFile.writeText(cfgJson)
            configFile = cFile

            LogRepository.i(
                "[WgExit] Starting Engine 2 (sing-box Two-Stage WG -> $endpointHost:$endpointPort, MTU: $mtu, LocalPort: $localListenPort)...",
                "WgExit"
            )

            val pb = ProcessBuilder(listOf(binPath, "run", "-c", cFile.absolutePath))
            pb.directory(workDir)
            pb.redirectErrorStream(true)
            val proc = pb.start()
            process = proc

            val recentErrors = ArrayList<String>(8)
            logThread = Thread({
                try {
                    BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                        var line: String? = null
                        while (proc.isAlive && reader.readLine().also { line = it } != null) {
                            val l = line ?: break
                            if (l.contains("ERROR", ignoreCase = true) || l.contains("FATAL", ignoreCase = true)) {
                                synchronized(recentErrors) {
                                    if (recentErrors.size >= 6) recentErrors.removeAt(0)
                                    recentErrors.add(l)
                                }
                                LogRepository.e("[sing-box] $l", "sing-box")
                            } else if (l.contains("WARN", ignoreCase = true)) {
                                LogRepository.w("[sing-box] $l", "sing-box")
                            } else {
                                LogRepository.i("[sing-box] $l", "sing-box")
                            }
                        }
                    }
                } catch (_: Exception) {}
            }, "Aether-WgExit-Logger").apply { isDaemon = true; start() }

            var portReady = false
            val startWait = System.currentTimeMillis()
            while (System.currentTimeMillis() - startWait < 10_000L) {
                if (!proc.isAlive) {
                    val errTail = synchronized(recentErrors) { recentErrors.lastOrNull() }
                    lastErrorMessage = "sing-box exited prematurely (code=${proc.exitValue()})${if (errTail != null) ": $errTail" else ""}"
                    LogRepository.e("[WgExit] $lastErrorMessage", "WgExit")
                    return false
                }
                if (isPortListening("127.0.0.1", localListenPort)) {
                    portReady = true
                    break
                }
                Thread.sleep(200)
            }

            if (!portReady) return false
            Thread.sleep(700)

            val verifiedIp = verifyDataPlaneWithRetry(localListenPort, maxAttempts = 3)
            if (verifiedIp != null) {
                verifiedExitIp = verifiedIp
                LogRepository.i("[WgExit] Engine 2 (sing-box Two-Stage WireGuard) verified on $endpointHost:$endpointPort! Exit IP: $verifiedIp", "WgExit")
                return true
            }
            false
        } catch (e: Exception) {
            LogRepository.w("[WgExit] Engine 2 exception on port $endpointPort: ${e.message}", "WgExit")
            false
        }
    }

    @Synchronized
    fun stop() {
        stopInternal()
    }

    private fun stopChildProcessOnly() {
        runCatching { udpRelay?.stop() }
        udpRelay = null
        try {
            process?.let { p ->
                if (p.isAlive) {
                    p.destroy()
                    p.waitFor(1500, TimeUnit.MILLISECONDS)
                    if (p.isAlive) p.destroyForcibly()
                }
            }
        } catch (_: Exception) {}
        process = null
        runCatching { logThread?.interrupt() }
        logThread = null
        runCatching { configFile?.delete() }
    }

    private fun stopInternal() {
        isRunning.set(false)
        verifiedExitIp = null
        bridgeModeActive = false
        runCatching { bridgeSocksServer?.close() }
        bridgeSocksServer = null
        runCatching { bridgeHttpServer?.close() }
        bridgeHttpServer = null
        stopChildProcessOnly()
    }

    fun isConnected(): Boolean =
        isRunning.get() && (bridgeModeActive || process?.isAlive == true) && verifiedExitIp != null

    fun isHealthy(): Boolean =
        isRunning.get() && (bridgeModeActive || process?.isAlive == true) && isPortListening("127.0.0.1", localListenPort)

    // =========================================================================
    // PASSTHROUGH BRIDGE
    // =========================================================================

    private fun startNativePassthroughBridge(listenPort: Int): Boolean {
        return try {
            val socksSrv = ServerSocket()
            socksSrv.reuseAddress = true
            socksSrv.bind(InetSocketAddress("127.0.0.1", listenPort), 256)
            bridgeSocksServer = socksSrv

            val httpPort = listenPort - 1
            val httpSrv = runCatching {
                ServerSocket().apply {
                    reuseAddress = true
                    bind(InetSocketAddress("127.0.0.1", httpPort), 128)
                }
            }.getOrNull()
            bridgeHttpServer = httpSrv
            bridgeModeActive = true

            thread(start = true, isDaemon = true, name = "WgExit-SocksBridge") {
                while (isRunning.get() && bridgeModeActive && !socksSrv.isClosed) {
                    val client = try {
                        socksSrv.accept()
                    } catch (_: Exception) {
                        break
                    }
                    bridgeExecutor.execute { forwardRawTcp(client, primarySocksHost, primarySocksPort) }
                }
            }

            if (httpSrv != null) {
                thread(start = true, isDaemon = true, name = "WgExit-HttpBridge") {
                    while (isRunning.get() && bridgeModeActive && !httpSrv.isClosed) {
                        val client = try {
                            httpSrv.accept()
                        } catch (_: Exception) {
                            break
                        }
                        bridgeExecutor.execute { handleHttpToSocksClient(client, primarySocksHost, primarySocksPort) }
                    }
                }
            }
            true
        } catch (e: Exception) {
            LogRepository.w("[WgExit] Failed to bind passthrough bridge on $listenPort: ${e.message}", "WgExit")
            false
        }
    }

    private fun forwardRawTcp(client: Socket, upstreamHost: String, upstreamPort: Int) {
        val upstream = Socket()
        try {
            client.tcpNoDelay = true
            upstream.tcpNoDelay = true
            upstream.connect(InetSocketAddress(upstreamHost, upstreamPort), 8_000)

            val cIn = client.getInputStream()
            val cOut = client.getOutputStream()
            val uIn = upstream.getInputStream()
            val uOut = upstream.getOutputStream()

            val down = thread(start = true, isDaemon = true) {
                try {
                    val buf = ByteArray(32768)
                    while (isRunning.get()) {
                        val n = uIn.read(buf)
                        if (n <= 0) break
                        cOut.write(buf, 0, n)
                        cOut.flush()
                    }
                } catch (_: Exception) {
                } finally {
                    runCatching { client.shutdownOutput() }
                }
            }

            val buf = ByteArray(32768)
            while (isRunning.get()) {
                val n = cIn.read(buf)
                if (n <= 0) break
                uOut.write(buf, 0, n)
                uOut.flush()
            }
            runCatching { upstream.shutdownOutput() }
            runCatching { down.join(2000) }
        } catch (_: Exception) {
        } finally {
            runCatching { upstream.close() }
            runCatching { client.close() }
        }
    }

    private fun handleHttpToSocksClient(client: Socket, socksHost: String, socksPort: Int) {
        var upstream: Socket? = null
        try {
            client.tcpNoDelay = true
            client.soTimeout = 15_000
            val cIn = BufferedInputStream(client.getInputStream())
            val cOut = BufferedOutputStream(client.getOutputStream())

            val reqLine = readAsciiLine(cIn) ?: return
            val headers = mutableListOf<String>()
            while (true) {
                val h = readAsciiLine(cIn) ?: break
                if (h.isEmpty()) break
                headers.add(h)
            }

            val parts = reqLine.split(" ")
            if (parts.size < 2) return
            val method = parts[0].uppercase()
            val target = parts[1]

            val targetHost: String
            val targetPort: Int
            var initialPayload: ByteArray? = null

            if (method == "CONNECT") {
                targetHost = target.substringBefore(":")
                targetPort = target.substringAfter(":", "443").toIntOrNull() ?: 443
            } else {
                val url = runCatching { URL(target) }.getOrNull() ?: return
                targetHost = url.host
                targetPort = if (url.port != -1) url.port else 80
                val path = url.file.ifEmpty { "/" }
                val rebuilt = buildString {
                    append("$method $path HTTP/1.1\r\n")
                    for (h in headers) {
                        if (!h.startsWith("Proxy-", ignoreCase = true)) {
                            append(h).append("\r\n")
                        }
                    }
                    append("\r\n")
                }
                initialPayload = rebuilt.toByteArray(Charsets.ISO_8859_1)
            }

            val s = Socket()
            upstream = s
            s.tcpNoDelay = true
            s.connect(InetSocketAddress(socksHost, socksPort), 10_000)
            val uIn = DataInputStream(BufferedInputStream(s.getInputStream()))
            val uOut = BufferedOutputStream(s.getOutputStream())

            uOut.write(byteArrayOf(0x05, 0x01, 0x00))
            uOut.flush()
            if (uIn.read() != 0x05 || uIn.read() != 0x00) return

            val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
            val req = ByteArray(7 + hostBytes.size)
            req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03
            req[4] = hostBytes.size.toByte()
            System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
            req[5 + hostBytes.size] = ((targetPort ushr 8) and 0xFF).toByte()
            req[6 + hostBytes.size] = (targetPort and 0xFF).toByte()
            uOut.write(req)
            uOut.flush()

            val rVer = uIn.read()
            val rRep = uIn.read()
            uIn.read()
            val rAtyp = uIn.read()
            if (rVer != 0x05 || rRep != 0x00) return
            val skip = when (rAtyp) {
                0x01 -> 6
                0x04 -> 18
                0x03 -> uIn.readUnsignedByte() + 2
                else -> 6
            }
            uIn.skipBytes(skip)

            if (method == "CONNECT") {
                cOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
                cOut.flush()
            } else if (initialPayload != null) {
                uOut.write(initialPayload)
                uOut.flush()
            }

            client.soTimeout = 0
            val down = thread(start = true, isDaemon = true) {
                try {
                    val buf = ByteArray(32768)
                    while (isRunning.get()) {
                        val n = uIn.read(buf)
                        if (n <= 0) break
                        cOut.write(buf, 0, n)
                        cOut.flush()
                    }
                } catch (_: Exception) {
                } finally {
                    runCatching { client.shutdownOutput() }
                }
            }

            val buf = ByteArray(32768)
            while (isRunning.get()) {
                val n = cIn.read(buf)
                if (n <= 0) break
                uOut.write(buf, 0, n)
                uOut.flush()
            }
            runCatching { s.shutdownOutput() }
            runCatching { down.join(2000) }
        } catch (_: Exception) {
        } finally {
            runCatching { upstream?.close() }
            runCatching { client.close() }
        }
    }

    private fun readAsciiLine(ins: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = ins.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) break
            if (b != '\r'.code) sb.append(b.toChar())
        }
        return sb.toString()
    }

    // =========================================================================
    // DEDICATED OUTER CLOUDFLARE WARP IDENTITY & ENDPOINT RESOLUTION
    // =========================================================================

    private fun loadOrRegisterDedicatedWarpIdentity(
        workDir: File,
        customPrivateKey: String,
        aetherSocksPort: Int
    ): WarpIdentity? {
        val searchDirs = listOf(
            workDir,
            File(System.getProperty("user.home") ?: ".", ".aether"),
            File(System.getenv("AppData") ?: ".", "AetherST-Tunnel/bin"),
            File(System.getProperty("user.dir") ?: "."),
            File(".")
        )

        val bestEndpoint = resolveBestCloudflareEndpoint(searchDirs)

        // Read primary Layer-1 private key so we never reuse the exact same keypair simultaneously
        val layer1PrivKey = runCatching {
            val f = File(workDir, "aether.toml")
            if (f.exists()) {
                parseWarpIdentityFromToml(f, customPrivateKey, bestEndpoint)?.privateKey
            } else null
        }.getOrNull()

        // 1. Prefer dedicated aether-singbox-warp.toml so Layer-2 has its own non-colliding WARP session
        val dedicatedFile = File(workDir, "aether-singbox-warp.toml")
        if (dedicatedFile.exists() && dedicatedFile.length() > 0) {
            val parsed = parseWarpIdentityFromToml(dedicatedFile, customPrivateKey, bestEndpoint)
            if (parsed != null && parsed.privateKey != layer1PrivKey) {
                return parsed.copy(endpoint = bestEndpoint.first, port = bestEndpoint.second)
            }
        }

        // 2. Register a fresh dedicated Cloudflare WARP identity over Layer-1 SOCKS5 proxy (127.0.0.1:2021)
        val registered = registerFreshCloudflareWarp(workDir, aetherSocksPort, bestEndpoint)
        if (registered != null) return registered

        // 3. Fallback: read any available WARP identity file if online registration was unreachable
        for (dir in searchDirs) {
            for (fn in listOf("aether-secondary.toml", "aether-gool.toml", "aether.toml", "aether-wg.toml")) {
                val f = File(dir, fn)
                if (f.exists() && f.length() > 0) {
                    val parsed = parseWarpIdentityFromToml(f, customPrivateKey, bestEndpoint)
                    if (parsed != null) {
                        return parsed.copy(endpoint = bestEndpoint.first, port = bestEndpoint.second)
                    }
                }
            }
        }
        return null
    }

    private fun resolveBestCloudflareEndpoint(searchDirs: List<File>): Pair<String, Int> {
        val epRegex = Regex("""(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})""")

        // 1. Check live endpoint captured by AetherProcessRunner from Layer-1 (`aether-active-endpoint.txt`)
        for (dir in searchDirs) {
            val activeFile = File(dir, "aether-active-endpoint.txt")
            if (activeFile.exists()) {
                val text = runCatching { activeFile.readText().trim() }.getOrNull() ?: ""
                val m = epRegex.find(text)
                if (m != null) {
                    val ip = m.groupValues[1]
                    val port = m.groupValues[2].toIntOrNull() ?: 2408
                    if (ip != "0.0.0.0" && !ip.startsWith("127.")) {
                        return ip to port
                    }
                }
            }
        }

        // 2. Check `aether-lastconn.toml` / `*lastconn*.toml`
        for (dir in searchDirs) {
            val files = dir.listFiles { f -> f.name.contains("lastconn", ignoreCase = true) }
                ?.sortedByDescending { it.lastModified() }
                .orEmpty()
            for (f in files) {
                val text = runCatching { f.readText() }.getOrNull() ?: continue
                val m = epRegex.find(text)
                if (m != null) {
                    val ip = m.groupValues[1]
                    val port = m.groupValues[2].toIntOrNull() ?: 2408
                    if (ip != "0.0.0.0" && !ip.startsWith("127.")) {
                        return ip to port
                    }
                }
            }
        }
        return "162.159.192.1" to 2408
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
            var ipv6 = "fd00::1"
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
                        if (v.isNotBlank() && !v.startsWith("0.0.0.0") && endpoint == "162.159.192.1") {
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
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun registerFreshCloudflareWarp(
        workDir: File,
        aetherSocksPort: Int,
        bestEndpoint: Pair<String, Int>
    ): WarpIdentity? {
        return try {
            if (!isRunning.get()) return null
            val dedicatedFile = File(workDir, "aether-singbox-warp.toml")
            val aetherBin = findAetherBinary(workDir)
            if (aetherBin != null) {
                runCatching {
                    val regCmd = mutableListOf(
                        aetherBin,
                        "--register", "wg",
                        "--config", dedicatedFile.absolutePath
                    )
                    if (aetherSocksPort > 0 && isPortListening("127.0.0.1", aetherSocksPort)) {
                        regCmd.add("--upstream")
                        regCmd.add("socks5://127.0.0.1:$aetherSocksPort")
                    }
                    val pb = ProcessBuilder(regCmd)
                    pb.directory(workDir)
                    val p = pb.start()
                    p.waitFor(10, TimeUnit.SECONDS)
                    if (p.isAlive) p.destroyForcibly()
                    if (dedicatedFile.exists() && dedicatedFile.length() > 0L) {
                        val parsed = parseWarpIdentityFromToml(dedicatedFile, config.privateKey.trim(), bestEndpoint)
                        if (parsed != null) {
                            LogRepository.i("[WgExit] Registered dedicated secondary WARP identity via native aether --register wg", "WgExit")
                            return parsed.copy(endpoint = bestEndpoint.first, port = bestEndpoint.second)
                        }
                    }
                }
            }
            val keyPair = WireGuardCrypto.generateKeyPair()
            val regBody = """{"key":"${keyPair.publicKey}","install_id":"","fcm_token":"","tos":"2026-01-01T00:00:00.000Z","model":"PC","serial_number":"${UUID.randomUUID()}","locale":"en_US"}"""
            val targets = listOf(
                "api.cloudflareclient.com" to "/v0a2158/reg",
                "api.devices.cloudflare.com" to "/v0a4471/reg"
            )

            // Prefer dialing via Layer-1 SOCKS5 with ATYP=0x03 (domain name resolved inside WARP, zero local ISP DNS!)
            if (aetherSocksPort > 0 && isPortListening("127.0.0.1", aetherSocksPort)) {
                for ((host, path) in targets) {
                    if (!isRunning.get()) return null
                    try {
                        val rawSock = Socket()
                        rawSock.connect(InetSocketAddress("127.0.0.1", aetherSocksPort), 4000)
                        rawSock.soTimeout = 6000
                        val sIn = DataInputStream(rawSock.getInputStream())
                        val sOut = rawSock.getOutputStream()
                        sOut.write(byteArrayOf(0x05, 0x01, 0x00))
                        sOut.flush()
                        if (sIn.read() == 0x05 && sIn.read() == 0x00) {
                            val hb = host.toByteArray(Charsets.US_ASCII)
                            val req = ByteArray(7 + hb.size)
                            req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03
                            req[4] = hb.size.toByte()
                            System.arraycopy(hb, 0, req, 5, hb.size)
                            req[5 + hb.size] = (443 ushr 8).toByte()
                            req[6 + hb.size] = (443 and 0xFF).toByte()
                            sOut.write(req)
                            sOut.flush()
                            val rVer = sIn.read()
                            val rRep = sIn.read()
                            sIn.read()
                            val rAtyp = sIn.read()
                            if (rVer == 0x05 && rRep == 0x00) {
                                val skip = when (rAtyp) {
                                    0x01 -> 6
                                    0x04 -> 18
                                    0x03 -> sIn.readUnsignedByte() + 2
                                    else -> 6
                                }
                                sIn.readFully(ByteArray(skip))
                                val sslFactory = javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory
                                val sslSock = sslFactory.createSocket(rawSock, host, 443, true) as javax.net.ssl.SSLSocket
                                sslSock.soTimeout = 6000
                                sslSock.startHandshake()
                                val bodyBytes = regBody.toByteArray(Charsets.UTF_8)
                                val httpReq = buildString {
                                    append("POST $path HTTP/1.1\r\n")
                                    append("Host: $host\r\n")
                                    append("Content-Type: application/json\r\n")
                                    append("Accept: application/json\r\n")
                                    append("CF-Client-Version: a-6.30-2158\r\n")
                                    append("Content-Length: ${bodyBytes.size}\r\n")
                                    append("Connection: close\r\n\r\n")
                                }
                                sslSock.outputStream.write(httpReq.toByteArray(Charsets.US_ASCII))
                                sslSock.outputStream.write(bodyBytes)
                                sslSock.outputStream.flush()
                                val resp = sslSock.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
                                runCatching { sslSock.close() }
                                val parsed = parseRegisteredWarpJson(resp, workDir, keyPair, bestEndpoint)
                                if (parsed != null) return parsed
                            }
                        }
                        runCatching { rawSock.close() }
                    } catch (_: Exception) {}
                }
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    private fun parseRegisteredWarpJson(
        resp: String,
        workDir: File,
        keyPair: WireGuardCrypto.KeyPair,
        bestEndpoint: Pair<String, Int>
    ): WarpIdentity? {
        val devId = Regex(""""id"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1) ?: return null
        val token = Regex(""""token"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1) ?: devId
        val clientId = Regex(""""client_id"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1) ?: "AAAA"
        val v4 = Regex(""""v4"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1)?.substringBefore("/") ?: "172.16.0.2"
        val v6 = Regex(""""v6"\s*:\s*"([^"]+)"""").find(resp)?.groupValues?.get(1)?.substringBefore("/") ?: "fd00::1"
        val peerPub = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

        val toml = buildString {
            appendLine("""device_id = "$devId"""")
            appendLine("""access_token = "$token"""")
            appendLine("""ipv4 = "$v4"""")
            appendLine("""ipv6 = "$v6"""")
            appendLine("""wg_private_key = "${keyPair.privateKey}"""")
            appendLine("""wg_peer_public_key = "$peerPub"""")
            appendLine("""assigned_endpoint = "${bestEndpoint.first}:${bestEndpoint.second}"""")
            appendLine("""client_id = "$clientId"""")
        }
        runCatching { File(workDir, "aether-singbox-warp.toml").writeText(toml) }

        val reserved = runCatching {
            val b = Base64.getDecoder().decode(clientId)
            if (b.size >= 3) listOf(b[0].toInt() and 0xFF, b[1].toInt() and 0xFF, b[2].toInt() and 0xFF)
            else listOf(0, 0, 0)
        }.getOrDefault(listOf(0, 0, 0))

        LogRepository.i("[WgExit] Registered dedicated secondary WARP identity (device=$devId) for Layer-2 chain", "WgExit")
        return WarpIdentity(
            deviceId = devId,
            accessToken = token,
            endpoint = bestEndpoint.first,
            port = bestEndpoint.second,
            ipv4 = v4,
            ipv6 = v6,
            privateKey = keyPair.privateKey,
            publicKey = peerPub,
            clientId = clientId,
            reserved = reserved
        )
    }

    /**
     * Builds a schema-valid `sing-box` 1.8..1.12+ JSON configuration with two-stage userspace
     * WireGuard chaining (`outer-warp` -> `proton-exit`) and ZERO deprecated keys.
     */
    private fun buildSingBoxConfig(
        listenPort: Int,
        endpointHost: String,
        endpointPort: Int,
        v4: String,
        v6: String,
        privateKey: String,
        publicKey: String,
        mtu: Int,
        warpIdentity: WarpIdentity?
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

        val outerWarpBlock = if (warpIdentity != null) {
            """
            {
              "type": "wireguard",
              "tag": "outer-warp",
              "server": "${warpIdentity.endpoint}",
              "server_port": ${warpIdentity.port},
              "local_address": ["${warpIdentity.ipv4}/32"],
              "private_key": "${warpIdentity.privateKey}",
              "peer_public_key": "${warpIdentity.publicKey}",
              "reserved": [${warpIdentity.reserved.joinToString(", ")}],
              "mtu": 1280
            },
            """.trimIndent()
        } else ""

        val detourLine = if (warpIdentity != null) {
            ",\n              \"detour\": \"outer-warp\""
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
                "detour": "proton-exit"
              },
              {
                "tag": "dns-cf",
                "address": "tcp://1.1.1.1",
                "detour": "proton-exit"
              }
            ],
            "final": "dns-proton"
          },
          "inbounds": [
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
            $outerWarpBlock
            {
              "type": "wireguard",
              "tag": "proton-exit",
              "server": "$endpointHost",
              "server_port": $endpointPort,
              "local_address": [${localAddresses.joinToString(", ")}],
              "private_key": "$privateKey",
              "peer_public_key": "$publicKey",
              "mtu": $mtu$detourLine
            },
            {
              "type": "direct",
              "tag": "direct"
            }
          ],
          "route": {
            "final": "proton-exit"
          }
        }
        """.trimIndent()
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

    private fun killStaleProcess(port: Int) {
        val isWin = (System.getProperty("os.name") ?: "").lowercase().contains("win")
        runCatching {
            if (isWin) {
                ProcessBuilder("cmd", "/c", "for /f \"tokens=5\" %a in ('netstat -aon ^| findstr :$port') do taskkill /F /PID %a")
                    .start().waitFor(1500, TimeUnit.MILLISECONDS)
            } else {
                ProcessBuilder("sh", "-c", "pkill -f 127.0.0.1:$port; pkill -f singbox-wg-$port.json")
                    .start().waitFor(1000, TimeUnit.MILLISECONDS)
            }
        }
    }

    private fun findAetherBinary(workDir: File): String? {
        val isWin = (System.getProperty("os.name") ?: "").lowercase().contains("win")
        val candidates = mutableListOf<File>()
        if (binaryPath != null) {
            val parent = File(binaryPath).parentFile
            if (parent != null) {
                candidates.add(File(parent, if (isWin) "aether.exe" else "libaether.so"))
                candidates.add(File(parent, "aether_core"))
                candidates.add(File(parent, "aether"))
            }
        }
        candidates.add(File(workDir, "bin/aether_core"))
        candidates.add(File(workDir, if (isWin) "aether.exe" else "libaether.so"))
        candidates.add(File("composeApp/src/desktopMain/resources/bin", if (isWin) "aether.exe" else "aether"))
        candidates.add(File("bin", if (isWin) "aether.exe" else "aether"))
        return candidates.firstOrNull { it.exists() && it.isFile }?.absolutePath
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

    private fun verifyDataPlaneWithRetry(socksPort: Int, maxAttempts: Int = 4): String? {
        for (attempt in 1..maxAttempts) {
            if (!bridgeModeActive && process?.isAlive != true) return null
            val ip = verifyDataPlane(socksPort)
            if (ip != null) return ip
            if (attempt < maxAttempts) Thread.sleep(900)
        }
        return null
    }

    private fun verifyDataPlane(socksPort: Int): String? {
        probeCloudflareTraceByIp(socksPort, byteArrayOf(1, 1, 1, 1), "1.1.1.1")?.let { return it }
        probeCloudflareTraceByIp(socksPort, byteArrayOf(1, 0, 0, 1), "1.0.0.1")?.let { return it }
        probeSimpleHttpIp(socksPort, "checkip.amazonaws.com", "/")?.let { return it }
        probeSimpleHttpIp(socksPort, "api.ipify.org", "/")?.let { return it }
        probeIpApi(socksPort)?.let { return it }
        return null
    }

    private fun probeCloudflareTraceFull(socksPort: Int): TraceProbeResult? {
        for ((ipBytes, hostHdr) in listOf(
            byteArrayOf(1, 1, 1, 1) to "1.1.1.1",
            byteArrayOf(1, 0, 0, 1) to "1.0.0.1"
        )) {
            try {
                Socket().use { socket ->
                    socket.soTimeout = 4500
                    socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2500)
                    val out = socket.getOutputStream()
                    val input = socket.getInputStream()
                    out.write(byteArrayOf(0x05, 0x01, 0x00))
                    out.flush()
                    val authResp = ByteArray(2)
                    readFully(input, authResp)
                    if (authResp[0] == 0x05.toByte() && authResp[1] == 0x00.toByte()) {
                        val req = byteArrayOf(
                            0x05, 0x01, 0x00, 0x01,
                            ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3],
                            0x00, 0x50
                        )
                        out.write(req)
                        out.flush()
                        val connResp = ByteArray(4)
                        readFully(input, connResp)
                        if (connResp[1] == 0x00.toByte()) {
                            consumeSocksBoundAddress(input, connResp[3])
                            val httpReq = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: $hostHdr\r\nUser-Agent: AetherST/2.5\r\nConnection: close\r\n\r\n"
                            out.write(httpReq.toByteArray(Charsets.US_ASCII))
                            out.flush()
                            val text = input.bufferedReader(Charsets.US_ASCII).readText()
                            val ip = Regex("""(?m)^ip=(.+)$""").find(text)?.groupValues?.get(1)?.trim()
                            val loc = Regex("""(?m)^loc=(.+)$""").find(text)?.groupValues?.get(1)?.trim()?.uppercase()
                            val warp = Regex("""(?m)^warp=(.+)$""").find(text)?.groupValues?.get(1)?.trim()?.lowercase() ?: "off"
                            if (!ip.isNullOrBlank() && !loc.isNullOrBlank()) {
                                return TraceProbeResult(ip = ip, country = loc, warpState = warp)
                            }
                        }
                    }
                }
            } catch (_: Exception) {}
        }
        return null
    }

    private fun probeCloudflareTraceByIp(socksPort: Int, ipv4Bytes: ByteArray, hostHeader: String): String? {
        return try {
            Socket().use { socket ->
                socket.soTimeout = 5000
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2500)
                val out = socket.getOutputStream()
                val input = socket.getInputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val authResp = ByteArray(2)
                readFully(input, authResp)
                if (authResp[0] == 0x05.toByte() && authResp[1] == 0x00.toByte()) {
                    val req = byteArrayOf(
                        0x05, 0x01, 0x00, 0x01,
                        ipv4Bytes[0], ipv4Bytes[1], ipv4Bytes[2], ipv4Bytes[3],
                        0x00, 0x50
                    )
                    out.write(req)
                    out.flush()
                    val connResp = ByteArray(4)
                    readFully(input, connResp)
                    if (connResp[1] == 0x00.toByte()) {
                        consumeSocksBoundAddress(input, connResp[3])
                        val httpReq = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: $hostHeader\r\nUser-Agent: AetherST/2.5\r\nConnection: close\r\n\r\n"
                        out.write(httpReq.toByteArray(Charsets.US_ASCII))
                        out.flush()
                        val text = input.bufferedReader(Charsets.US_ASCII).readText()
                        val ip = Regex("""(?m)^ip=(.+)$""").find(text)?.groupValues?.get(1)?.trim()
                        val loc = Regex("""(?m)^loc=(.+)$""").find(text)?.groupValues?.get(1)?.trim()?.uppercase()
                        if (!ip.isNullOrBlank() && loc != "IR") {
                            LogRepository.i("[WgExit] Cloudflare trace verified via $hostHeader: $ip ($loc)", "WgExit")
                            return ip
                        }
                    }
                }
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun probeSimpleHttpIp(socksPort: Int, targetHost: String, path: String): String? {
        return try {
            Socket().use { socket ->
                socket.soTimeout = 5500
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2500)
                val out = socket.getOutputStream()
                val input = socket.getInputStream()

                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val authResp = ByteArray(2)
                readFully(input, authResp)
                if (authResp[0] != 0x05.toByte() || authResp[1] != 0x00.toByte()) return null

                val hostBytes = targetHost.toByteArray(Charsets.US_ASCII)
                val req = ByteArray(4 + 1 + hostBytes.size + 2)
                req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03
                req[4] = hostBytes.size.toByte()
                System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
                req[req.size - 2] = 0x00
                req[req.size - 1] = 0x50
                out.write(req)
                out.flush()

                val connResp = ByteArray(4)
                readFully(input, connResp)
                if (connResp[1] != 0x00.toByte()) return null
                consumeSocksBoundAddress(input, connResp[3])

                val httpReq = "GET $path HTTP/1.1\r\nHost: $targetHost\r\nUser-Agent: AetherST/2.5\r\nConnection: close\r\n\r\n"
                out.write(httpReq.toByteArray(Charsets.US_ASCII))
                out.flush()

                val reader = BufferedReader(InputStreamReader(input, Charsets.US_ASCII))
                var inBody = false
                while (true) {
                    val line = reader.readLine() ?: break
                    if (inBody) {
                        val candidate = line.trim()
                        if (candidate.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) {
                            LogRepository.i("[WgExit] Data-plane verified via $targetHost: $candidate", "WgExit")
                            return candidate
                        }
                    } else if (line.isEmpty()) {
                        inBody = true
                    }
                }
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun probeIpApi(socksPort: Int): String? {
        val targetHost = "ip-api.com"
        return try {
            Socket().use { socket ->
                socket.soTimeout = 6000
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2500)
                val out = socket.getOutputStream()
                val input = socket.getInputStream()

                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                val authResp = ByteArray(2)
                readFully(input, authResp)
                if (authResp[0] != 0x05.toByte() || authResp[1] != 0x00.toByte()) return null

                val hostBytes = targetHost.toByteArray(Charsets.US_ASCII)
                val req = ByteArray(4 + 1 + hostBytes.size + 2)
                req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03
                req[4] = hostBytes.size.toByte()
                System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
                req[req.size - 2] = 0x00
                req[req.size - 1] = 0x50
                out.write(req)
                out.flush()

                val connResp = ByteArray(4)
                readFully(input, connResp)
                if (connResp[1] != 0x00.toByte()) return null
                consumeSocksBoundAddress(input, connResp[3])

                val httpReq = "GET /line/?fields=status,countryCode,query HTTP/1.1\r\nHost: $targetHost\r\nUser-Agent: AetherST/2.5\r\nConnection: close\r\n\r\n"
                out.write(httpReq.toByteArray(Charsets.US_ASCII))
                out.flush()

                val reader = BufferedReader(InputStreamReader(input, Charsets.US_ASCII))
                var inBody = false
                val bodyLines = mutableListOf<String>()
                while (true) {
                    val line = reader.readLine() ?: break
                    if (inBody) {
                        if (line.trim().isNotBlank()) bodyLines.add(line.trim())
                    } else if (line.isEmpty()) {
                        inBody = true
                    }
                }
                if (bodyLines.isNotEmpty() && bodyLines[0].equals("success", ignoreCase = true) && bodyLines.size >= 3) {
                    val country = bodyLines[1].uppercase()
                    val ip = bodyLines[2]
                    if (country != "IR" && ip.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) {
                        return ip
                    }
                }
                null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun consumeSocksBoundAddress(input: InputStream, atyp: Byte) {
        when (atyp) {
            0x01.toByte() -> readFully(input, ByteArray(4 + 2))
            0x03.toByte() -> {
                val len = input.read()
                if (len > 0) readFully(input, ByteArray(len + 2))
            }
            0x04.toByte() -> readFully(input, ByteArray(16 + 2))
        }
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val count = input.read(buffer, offset, buffer.size - offset)
            if (count < 0) throw java.io.EOFException("Premature EOF reading from SOCKS")
            offset += count
        }
    }

    private fun isPortListening(host: String, port: Int): Boolean {
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(host, port), 200)
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
            val updated = java.util.concurrent.ConcurrentHashMap<String, Long>()

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
