package io.github.immaghzbad.aetherst.shared.net

import io.github.immaghzbad.aetherst.shared.data.LogRepository
import kotlinx.coroutines.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import kotlin.concurrent.thread

/**
 * Exception thrown when Firefox Accounts requires a 6-digit email verification code
 * on a newly created sessionToken before issuing OAuth tokens.
 */
class FxaVerificationRequiredException(
    val sessionTokenHex: String,
    override val message: String
) : IllegalStateException(message)

/**
 * Two-stage chained tunnel: Aether (Stage 1 anti-censorship) -> Firefox VPN / Mozilla Fastly (Stage 2 exit node).
 *
 * Implements the verified Mozilla Firefox VPN / FoxyVPN / Kumiho protocol specification:
 *  1. Control Plane:
 *     - FxA Hawk-signed requests with mandatory `hash="<payloadHash>"` (`hawk.1.payload\napplication/json\n<body>\n`).
 *     - PKCE Authorization Code Grant (`POST /v1/oauth/authorization` -> `POST /v1/token` / `/v1/oauth/token`)
 *       across both `https://oauth.accounts.firefox.com/v1` (sibling host not blocked by Fastly 406) and
 *       `https://api.accounts.firefox.com/v1`, with direct Hawk `POST /v1/oauth/token` fallback.
 *     - Guardian ProxyPass minting via `GET https://vpn.mozilla.org/api/v1/fpn/token` with mandatory
 *       `User-Agent: MozillaVPN/2.35.0 (sys:linux; iap:true)` and automatic entitlement activation
 *       via `POST https://vpn.mozilla.org/api/v1/fpn/activate` on HTTP 401/403.
 *     - Live Server List discovery from Mozilla Remote Settings:
 *       `GET https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records`
 *       extracting `protocols` -> `connect` (`host:port`), skipping `quarantined == true`, with official
 *       Fastly MASQUE/CONNECT aggregate fallbacks (`<cc>.m1.fastly-masque.net:443`).
 *  2. Data Plane:
 *     - Native Kotlin HTTP/2 (`ALPN h2`) multiplexed `CONNECT` client + HTTP/1.1 `CONNECT` fallback
 *       tunneled over Aether's Layer-1 SOCKS5 proxy (`primarySocksHost:primarySocksPort`).
 *     - Sends `Proxy-Authorization: ProxyPass <proxy_pass_jwt>` and `User-Agent: MozillaVPN/2.35.0 (sys:linux; iap:true)`.
 *     - Intercepts all DNS queries (both SOCKS5 TCP `:53` and SOCKS5 `UDP ASSOCIATE` `:53`) and resolves
 *       them via in-tunnel DNS-over-HTTPS (`POST https://1.1.1.1/dns-query` over an H2 CONNECT stream to `1.1.1.1:443`)
 *       because Mozilla's Fastly edge permits TCP ports 80 and 443 only.
 */
class FirefoxVpnExitTunnel(
    private val token: String = "",
    private val country: String = "",
    private val binaryPath: String?,
    private val workingDir: String,
    private val primarySocksHost: String = "127.0.0.1",
    private val primarySocksPort: Int = 2021,
    val localListenPort: Int = 10810
) {
    private val isRunning = AtomicBoolean(false)
    @Volatile private var socksServerSocket: ServerSocket? = null
    @Volatile private var httpServerSocket: ServerSocket? = null
    @Volatile private var udpRelaySocket: DatagramSocket? = null
    @Volatile private var activeH2Session: H2ConnectSession? = null
    @Volatile private var currentProxyPass: String = ""
    @Volatile private var currentEdgeHost: String = "us.m1.fastly-masque.net"
    @Volatile private var currentEdgePort: Int = 443
    @Volatile private var renewalThread: Thread? = null
    private val executor = Executors.newCachedThreadPool()

    @Volatile
    var verifiedExitIp: String? = null
        private set

    @Volatile
    var lastErrorMessage: String? = null
        private set

    data class EdgeEndpoint(
        val host: String,
        val port: Int,
        val countryCode: String
    )

    @Synchronized
    fun start(): Boolean {
        if (isRunning.get() && isHealthy()) return true
        stopInternal()
        isRunning.set(true)
        verifiedExitIp = null
        lastErrorMessage = null

        val cleanToken = token.trim()
        if (cleanToken.isBlank()) {
            lastErrorMessage = "Firefox VPN token is empty. Please sign in with Firefox WebView or enter a token."
            LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
            isRunning.set(false)
            return false
        }

        return try {
            // 1. Mint a fresh 10-minute Guardian ProxyPass JWT through Aether's Layer-1 SOCKS5 proxy
            LogRepository.i("[FirefoxVpn] Minting Guardian ProxyPass JWT via Aether ($primarySocksHost:$primarySocksPort)...", "FirefoxVpn")
            val proxyPass = resolveLiveProxyPassJwt(cleanToken, primarySocksHost, primarySocksPort)
            if (proxyPass.isNullOrBlank()) {
                lastErrorMessage = "Failed to obtain Mozilla Guardian ProxyPass JWT (check Firefox Account VPN entitlement or region)"
                LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
                stopInternal()
                return false
            }
            currentProxyPass = proxyPass
            LogRepository.i("[FirefoxVpn] Guardian ProxyPass JWT ready (${proxyPass.take(16)}...).", "FirefoxVpn")

            // 2. Resolve live Fastly/Mozilla CONNECT edge candidates from Remote Settings vpn-serverlist
            val edgeCandidates = resolveCountryExitCandidates(country.trim(), primarySocksHost, primarySocksPort)
            var connectedEdge: EdgeEndpoint? = null

            for (candidate in edgeCandidates.take(4)) {
                LogRepository.i("[FirefoxVpn] Dialing Mozilla Fastly edge ${candidate.host}:${candidate.port} (${candidate.countryCode}) via Aether $primarySocksHost:$primarySocksPort...", "FirefoxVpn")
                val session = H2ConnectSession(
                    edgeHost = candidate.host,
                    edgePort = candidate.port,
                    socksHost = primarySocksHost,
                    socksPort = primarySocksPort,
                    proxyPassProvider = { currentProxyPass }
                )
                if (session.connect()) {
                    activeH2Session = session
                    currentEdgeHost = candidate.host
                    currentEdgePort = candidate.port
                    connectedEdge = candidate
                    LogRepository.i("[FirefoxVpn] Connected to Mozilla edge ${candidate.host}:${candidate.port} (ALPN=${session.negotiatedProtocol}).", "FirefoxVpn")
                    break
                } else {
                    session.close()
                }
            }

            if (connectedEdge == null) {
                lastErrorMessage = "Could not establish TLS/HTTP2 session to Mozilla Fastly VPN edge"
                LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
                stopInternal()
                return false
            }

            // 3. Start local UDP DoH Relay, SOCKS5 (localListenPort = 10810), and HTTP Proxy (10809)
            startLocalUdpDnsRelay()
            startLocalSocks5Server(localListenPort)
            startLocalHttpServer(localListenPort - 1)
            startProxyPassRenewalLoop(cleanToken)

            var listening = false
            for (i in 1..25) {
                if (probePort("127.0.0.1", localListenPort)) {
                    listening = true
                    break
                }
                Thread.sleep(100)
            }

            if (!listening) {
                lastErrorMessage = "Listening port $localListenPort failed to open"
                LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
                stopInternal()
                return false
            }

            val exitIp = verifyDataPlaneWithRetry(localListenPort, maxAttempts = 4)
            if (exitIp != null) {
                verifiedExitIp = exitIp
                LogRepository.i("[FirefoxVpn] Two-stage Firefox VPN tunnel active & verified! Exit IP: $exitIp", "FirefoxVpn")
                true
            } else {
                lastErrorMessage = "Firefox VPN data-plane check failed (edge rejected CONNECT or ProxyPass expired/quota exceeded)"
                LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
                stopInternal()
                false
            }
        } catch (e: Exception) {
            lastErrorMessage = "Firefox VPN startup failed: ${e.message}"
            LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
            stopInternal()
            false
        }
    }

    @Synchronized
    fun stop() {
        stopInternal()
    }

    private fun stopInternal() {
        val wasRunning = isRunning.getAndSet(false)
        verifiedExitIp = null
        runCatching { renewalThread?.interrupt() }
        renewalThread = null
        runCatching { socksServerSocket?.close() }
        socksServerSocket = null
        runCatching { httpServerSocket?.close() }
        httpServerSocket = null
        runCatching { udpRelaySocket?.close() }
        udpRelaySocket = null
        runCatching { activeH2Session?.close() }
        activeH2Session = null
        if (wasRunning) {
            LogRepository.i("[FirefoxVpn] Exit node stopped.", "FirefoxVpn")
        }
    }

    fun isHealthy(): Boolean =
        isRunning.get() && activeH2Session?.isAlive() == true && probePort("127.0.0.1", localListenPort)

    @Synchronized
    private fun ensureActiveSession(): H2ConnectSession? {
        val current = activeH2Session
        if (current != null && current.isAlive()) return current
        if (!isRunning.get()) return null

        val session = H2ConnectSession(
            edgeHost = currentEdgeHost,
            edgePort = currentEdgePort,
            socksHost = primarySocksHost,
            socksPort = primarySocksPort,
            proxyPassProvider = { currentProxyPass }
        )
        return if (session.connect()) {
            activeH2Session = session
            session
        } else {
            session.close()
            null
        }
    }

    private fun startProxyPassRenewalLoop(rawToken: String) {
        renewalThread = thread(start = true, isDaemon = true, name = "FirefoxVPN-PassRenewal") {
            while (isRunning.get()) {
                try {
                    Thread.sleep(240_000L) // Renew every 4 minutes (Guardian passes expire in 10 minutes)
                    if (!isRunning.get()) break
                    val refreshed = resolveLiveProxyPassJwt(rawToken, primarySocksHost, primarySocksPort, forceRefresh = true)
                    if (!refreshed.isNullOrBlank()) {
                        currentProxyPass = refreshed
                        LogRepository.i("[FirefoxVpn] Renewed Guardian ProxyPass JWT in-place.", "FirefoxVpn")
                    }
                } catch (_: InterruptedException) {
                    break
                } catch (_: Exception) {}
            }
        }
    }

    // =========================================================================
    // DATA PLANE: HTTP/2 (`ALPN h2`) MULTIPLEXED CONNECT + SOCKS5 + DoH
    // =========================================================================

    private class H2ConnectSession(
        val edgeHost: String,
        val edgePort: Int,
        val socksHost: String,
        val socksPort: Int,
        val proxyPassProvider: () -> String
    ) {
        @Volatile var negotiatedProtocol: String = "h2"
            private set

        private var sslSocket: SSLSocket? = null
        private var rawIn: DataInputStream? = null
        private var rawOut: OutputStream? = null
        private val writeLock = Any()
        private val closed = AtomicBoolean(false)
        private val nextStreamId = AtomicInteger(1)
        private val streams = ConcurrentHashMap<Int, H2Stream>()

        fun isAlive(): Boolean = !closed.get() && sslSocket?.isClosed == false && sslSocket?.isConnected == true

        fun connect(): Boolean {
            return try {
                val underlying = dialViaSocks5(socksHost, socksPort, edgeHost, edgePort, 12_000) ?: return false
                underlying.tcpNoDelay = true
                underlying.keepAlive = true
                underlying.soTimeout = 0

                val edgeTrustAll = arrayOf<javax.net.ssl.TrustManager>(
                    object : javax.net.ssl.X509TrustManager {
                        override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                        override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>?, authType: String?) {}
                        override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
                    }
                )
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, edgeTrustAll, SecureRandom())
                val ssl = (sslContext.socketFactory.createSocket(underlying, edgeHost, edgePort, true) as SSLSocket).apply {
                    val params = sslParameters
                    runCatching { params.serverNames = listOf(SNIHostName(edgeHost)) }
                    runCatching { params.applicationProtocols = arrayOf("h2", "http/1.1") }
                    sslParameters = params
                    soTimeout = 15_000
                }

                ssl.startHandshake()
                ssl.soTimeout = 0
                val alpn = runCatching { ssl.applicationProtocol }.getOrNull()
                negotiatedProtocol = if (alpn.isNullOrBlank() || alpn == "http/1.1") "http/1.1" else "h2"

                sslSocket = ssl
                rawIn = DataInputStream(BufferedInputStream(ssl.inputStream, 65536))
                rawOut = BufferedOutputStream(ssl.outputStream, 65536)

                if (negotiatedProtocol == "h2") {
                    sendH2PrefaceAndSettings()
                    startH2ReaderLoop()
                }
                true
            } catch (e: Exception) {
                LogRepository.w("[FirefoxVpn] Edge TLS handshake to $edgeHost:$edgePort failed: ${e.message}", "FirefoxVpn")
                close()
                false
            }
        }

        private fun sendH2PrefaceAndSettings() {
            synchronized(writeLock) {
                val out = rawOut ?: return
                out.write("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII))
                // SETTINGS: ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=16MiB, MAX_FRAME_SIZE=16384
                val settingsPayload = byteArrayOf(
                    0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x04, 0x01, 0x00, 0x00, 0x00,
                    0x00, 0x05, 0x00, 0x00, 0x40, 0x00
                )
                writeFrameLocked(out, type = 0x04, flags = 0x00, streamId = 0, payload = settingsPayload)
                // Connection WINDOW_UPDATE +16MiB
                writeFrameLocked(out, type = 0x08, flags = 0x00, streamId = 0, payload = byteArrayOf(0x01, 0x00, 0x00, 0x00))
                out.flush()
            }
        }

        private fun startH2ReaderLoop() {
            thread(start = true, isDaemon = true, name = "FirefoxVPN-H2Reader") {
                val input = rawIn ?: return@thread
                try {
                    while (!closed.get()) {
                        val b0 = input.read()
                        if (b0 < 0) break
                        val b1 = input.readUnsignedByte()
                        val b2 = input.readUnsignedByte()
                        val length = ((b0 and 0xFF) shl 16) or (b1 shl 8) or b2
                        val type = input.readUnsignedByte()
                        val flags = input.readUnsignedByte()
                        val streamId = input.readInt() and 0x7FFFFFFF

                        val payload = ByteArray(length)
                        if (length > 0) input.readFully(payload)

                        when (type) {
                            0x00 -> { // DATA
                                var dataOffset = 0
                                var dataLen = length
                                if ((flags and 0x08) != 0 && length > 0) {
                                    val padLen = payload[0].toInt() and 0xFF
                                    dataOffset = 1
                                    dataLen = (length - 1 - padLen).coerceAtLeast(0)
                                }
                                if (dataLen > 0) {
                                    streams[streamId]?.onData(payload.copyOfRange(dataOffset, dataOffset + dataLen))
                                }
                                if (length > 0) {
                                    sendWindowUpdate(0, length)
                                    if (streamId != 0) sendWindowUpdate(streamId, length)
                                }
                                if ((flags and 0x01) != 0) {
                                    streams[streamId]?.onRemoteClose()
                                }
                            }
                            0x01 -> { // HEADERS
                                var hdrOffset = 0
                                var hdrLen = length
                                if ((flags and 0x08) != 0 && hdrLen > 0) {
                                    val padLen = payload[0].toInt() and 0xFF
                                    hdrOffset += 1
                                    hdrLen = (hdrLen - 1 - padLen).coerceAtLeast(0)
                                }
                                if ((flags and 0x20) != 0 && hdrLen >= 5) {
                                    hdrOffset += 5
                                    hdrLen -= 5
                                }
                                val status = decodeH2Status(payload, hdrOffset, hdrLen)
                                streams[streamId]?.onHeaders(status)
                                if ((flags and 0x01) != 0) {
                                    streams[streamId]?.onRemoteClose()
                                }
                            }
                            0x03 -> { // RST_STREAM
                                streams.remove(streamId)?.onReset()
                            }
                            0x04 -> { // SETTINGS
                                if ((flags and 0x01) == 0) {
                                    synchronized(writeLock) {
                                        rawOut?.let {
                                            writeFrameLocked(it, type = 0x04, flags = 0x01, streamId = 0, payload = ByteArray(0))
                                            it.flush()
                                        }
                                    }
                                }
                            }
                            0x06 -> { // PING
                                if ((flags and 0x01) == 0 && payload.size == 8) {
                                    synchronized(writeLock) {
                                        rawOut?.let {
                                            writeFrameLocked(it, type = 0x06, flags = 0x01, streamId = 0, payload = payload)
                                            it.flush()
                                        }
                                    }
                                }
                            }
                            0x07 -> { // GOAWAY
                                break
                            }
                        }
                    }
                } catch (_: Exception) {
                } finally {
                    close()
                }
            }
        }

        fun openConnectStream(targetHost: String, targetPort: Int, timeoutMs: Long = 10_000L): H2Stream? {
            if (!isAlive()) return null
            val authority = if (targetHost.contains(":") && !targetHost.startsWith("[")) {
                "[$targetHost]:$targetPort"
            } else {
                "$targetHost:$targetPort"
            }

            for (scheme in listOf("ProxyPass", "Bearer")) {
                val streamId = nextStreamId.getAndAdd(2)
                val stream = H2Stream(streamId, this)
                streams[streamId] = stream

                val tokenVal = proxyPassProvider().trim()
                val authHeaderVal = if (tokenVal.startsWith("ProxyPass ", ignoreCase = true) || tokenVal.startsWith("Bearer ", ignoreCase = true)) {
                    tokenVal
                } else {
                    "$scheme $tokenVal"
                }
                val out = ByteArrayOutputStream(256)
                writeHpackLiteralHeader(out, ":method", "CONNECT")
                writeHpackLiteralHeader(out, ":authority", authority)
                writeHpackLiteralHeader(out, "proxy-authorization", authHeaderVal)
                writeHpackLiteralHeader(out, "user-agent", MOZILLA_VPN_UA)
                val hpack = out.toByteArray()

                try {
                    synchronized(writeLock) {
                        val raw = rawOut ?: throw IllegalStateException("H2 output closed")
                        writeFrameLocked(raw, type = 0x01, flags = 0x04, streamId = streamId, payload = hpack)
                        raw.flush()
                    }
                } catch (_: Exception) {
                    streams.remove(streamId)
                    return null
                }

                val status = stream.awaitResponseStatus(timeoutMs)
                if (status in 200..299) {
                    return stream
                }
                streams.remove(streamId)
                sendRstStream(streamId)
                if (status != 407 && status != 401) {
                    LogRepository.w("[FirefoxVpn] Edge CONNECT to $authority rejected with HTTP status $status", "FirefoxVpn")
                    return null
                }
            }
            LogRepository.w("[FirefoxVpn] Edge CONNECT to $authority rejected after auth attempts", "FirefoxVpn")
            return null
        }

        fun sendDataFrame(streamId: Int, data: ByteArray, offset: Int, length: Int, endStream: Boolean) {
            var pos = offset
            var remaining = length
            synchronized(writeLock) {
                val out = rawOut ?: throw IllegalStateException("H2 output closed")
                if (remaining == 0 && endStream) {
                    writeFrameLocked(out, type = 0x00, flags = 0x01, streamId = streamId, payload = ByteArray(0))
                    out.flush()
                    return
                }
                while (remaining > 0) {
                    val chunk = minOf(14000, remaining)
                    val isLast = (remaining - chunk == 0) && endStream
                    val flags = if (isLast) 0x01 else 0x00
                    val frameBytes = data.copyOfRange(pos, pos + chunk)
                    writeFrameLocked(out, type = 0x00, flags = flags, streamId = streamId, payload = frameBytes)
                    pos += chunk
                    remaining -= chunk
                }
                out.flush()
            }
        }

        fun sendWindowUpdate(streamId: Int, increment: Int) {
            if (increment <= 0) return
            val inc = increment and 0x7FFFFFFF
            val payload = byteArrayOf(
                ((inc ushr 24) and 0x7F).toByte(),
                ((inc ushr 16) and 0xFF).toByte(),
                ((inc ushr 8) and 0xFF).toByte(),
                (inc and 0xFF).toByte()
            )
            runCatching {
                synchronized(writeLock) {
                    val out = rawOut ?: return
                    writeFrameLocked(out, type = 0x08, flags = 0x00, streamId = streamId, payload = payload)
                    out.flush()
                }
            }
        }

        fun sendRstStream(streamId: Int) {
            streams.remove(streamId)
            val payload = byteArrayOf(0x00, 0x00, 0x00, 0x08)
            runCatching {
                synchronized(writeLock) {
                    val out = rawOut ?: return
                    writeFrameLocked(out, type = 0x03, flags = 0x00, streamId = streamId, payload = payload)
                    out.flush()
                }
            }
        }

        private fun writeFrameLocked(out: OutputStream, type: Int, flags: Int, streamId: Int, payload: ByteArray) {
            val len = payload.size
            val sid = streamId and 0x7FFFFFFF
            val header = byteArrayOf(
                ((len ushr 16) and 0xFF).toByte(),
                ((len ushr 8) and 0xFF).toByte(),
                (len and 0xFF).toByte(),
                (type and 0xFF).toByte(),
                (flags and 0xFF).toByte(),
                ((sid ushr 24) and 0x7F).toByte(),
                ((sid ushr 16) and 0xFF).toByte(),
                ((sid ushr 8) and 0xFF).toByte(),
                (sid and 0xFF).toByte()
            )
            out.write(header)
            if (len > 0) out.write(payload)
        }

        fun close() {
            if (closed.getAndSet(true)) return
            streams.values.forEach { it.onReset() }
            streams.clear()
            runCatching { sslSocket?.close() }
            sslSocket = null
        }
    }

    private class H2Stream(
        val streamId: Int,
        private val session: H2ConnectSession
    ) {
        private val statusQueue = LinkedBlockingQueue<Int>(1)
        private val dataQueue = LinkedBlockingQueue<ByteArray>(2048)
        private val eofSentinel = ByteArray(0)
        private val closed = AtomicBoolean(false)

        fun onHeaders(status: Int) {
            statusQueue.offer(status)
        }

        fun onData(bytes: ByteArray) {
            if (!closed.get() && bytes.isNotEmpty()) {
                dataQueue.offer(bytes)
            }
        }

        fun onRemoteClose() {
            dataQueue.offer(eofSentinel)
        }

        fun onReset() {
            closed.set(true)
            statusQueue.offer(-1)
            dataQueue.offer(eofSentinel)
        }

        fun awaitResponseStatus(timeoutMs: Long): Int {
            return try {
                statusQueue.poll(timeoutMs, TimeUnit.MILLISECONDS) ?: -1
            } catch (_: Exception) {
                -1
            }
        }

        fun readChunk(timeoutMs: Long = 120_000L): ByteArray? {
            if (closed.get() && dataQueue.isEmpty()) return null
            val chunk = try {
                dataQueue.poll(timeoutMs, TimeUnit.MILLISECONDS)
            } catch (_: Exception) {
                null
            } ?: return null
            if (chunk === eofSentinel || chunk.isEmpty()) {
                closed.set(true)
                return null
            }
            return chunk
        }

        fun write(data: ByteArray, offset: Int = 0, length: Int = data.size) {
            if (closed.get()) throw IllegalStateException("Stream $streamId closed")
            session.sendDataFrame(streamId, data, offset, length, endStream = false)
        }

        fun close() {
            if (closed.getAndSet(true)) return
            runCatching { session.sendDataFrame(streamId, ByteArray(0), 0, 0, endStream = true) }
            session.sendRstStream(streamId)
        }
    }

    private fun startLocalSocks5Server(port: Int) {
        val server = ServerSocket()
        server.reuseAddress = true
        server.bind(InetSocketAddress("127.0.0.1", port), 256)
        socksServerSocket = server

        thread(start = true, isDaemon = true, name = "FirefoxVPN-Socks5") {
            while (isRunning.get() && !server.isClosed) {
                val client = try {
                    server.accept()
                } catch (_: Exception) {
                    break
                }
                executor.execute { handleSocks5Client(client) }
            }
        }
    }

    private fun handleSocks5Client(client: Socket) {
        try {
            client.tcpNoDelay = true
            client.soTimeout = 15_000
            val ins = DataInputStream(BufferedInputStream(client.getInputStream()))
            val out = BufferedOutputStream(client.getOutputStream())

            if (ins.read() != 0x05) {
                client.close()
                return
            }
            val nMethods = ins.readUnsignedByte()
            ins.readFully(ByteArray(nMethods))
            out.write(byteArrayOf(0x05, 0x00))
            out.flush()

            if (ins.read() != 0x05) {
                client.close()
                return
            }
            val cmd = ins.readUnsignedByte()
            ins.readUnsignedByte()
            val atyp = ins.readUnsignedByte()

            val targetHost: String = when (atyp) {
                0x01 -> {
                    val ip = ByteArray(4)
                    ins.readFully(ip)
                    InetAddress.getByAddress(ip).hostAddress ?: "0.0.0.0"
                }
                0x03 -> {
                    val dLen = ins.readUnsignedByte()
                    val dBytes = ByteArray(dLen)
                    ins.readFully(dBytes)
                    String(dBytes, Charsets.UTF_8)
                }
                0x04 -> {
                    val ip6 = ByteArray(16)
                    ins.readFully(ip6)
                    InetAddress.getByAddress(ip6).hostAddress ?: "::"
                }
                else -> {
                    client.close()
                    return
                }
            }
            val targetPort = ins.readUnsignedShort()

            when (cmd) {
                0x01 -> { // CONNECT
                    if (targetPort == 53) {
                        out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 53))
                        out.flush()
                        handleTcpDnsOverDoH(ins, out)
                        return
                    }

                    val session = ensureActiveSession()
                    if (session == null) {
                        out.write(byteArrayOf(0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        out.flush()
                        return
                    }

                    val stream = session.openConnectStream(targetHost, targetPort)
                    if (stream == null) {
                        out.write(byteArrayOf(0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        out.flush()
                        return
                    }

                    out.write(byteArrayOf(0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0))
                    out.flush()
                    client.soTimeout = 0
                    pipeClientAndH2Stream(client, ins, out, stream)
                }
                0x03 -> { // UDP ASSOCIATE
                    val relayPort = udpRelaySocket?.localPort ?: 0
                    if (relayPort <= 0) {
                        out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                        out.flush()
                        return
                    }
                    out.write(
                        byteArrayOf(
                            0x05, 0x00, 0x00, 0x01,
                            127, 0, 0, 1,
                            ((relayPort ushr 8) and 0xFF).toByte(),
                            (relayPort and 0xFF).toByte()
                        )
                    )
                    out.flush()
                    client.soTimeout = 0
                    while (isRunning.get() && !client.isClosed) {
                        if (ins.read() < 0) break
                    }
                }
                else -> {
                    out.write(byteArrayOf(0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0))
                    out.flush()
                }
            }
        } catch (_: Exception) {
        } finally {
            runCatching { client.close() }
        }
    }

    private fun pipeClientAndH2Stream(client: Socket, ins: InputStream, out: OutputStream, stream: H2Stream) {
        val downThread = thread(start = true, isDaemon = true) {
            try {
                while (isRunning.get() && !client.isClosed) {
                    val chunk = stream.readChunk(120_000L) ?: break
                    out.write(chunk)
                    out.flush()
                }
            } catch (_: Exception) {
            } finally {
                runCatching { client.shutdownOutput() }
            }
        }

        try {
            val buf = ByteArray(14000)
            while (isRunning.get() && !client.isClosed) {
                val n = ins.read(buf)
                if (n <= 0) break
                stream.write(buf, 0, n)
            }
        } catch (_: Exception) {
        } finally {
            stream.close()
            runCatching { downThread.join(2000) }
            runCatching { client.close() }
        }
    }

    private fun startLocalUdpDnsRelay() {
        val ds = DatagramSocket(InetSocketAddress("127.0.0.1", 0))
        udpRelaySocket = ds
        thread(start = true, isDaemon = true, name = "FirefoxVPN-UdpDoH") {
            val buf = ByteArray(4096)
            while (isRunning.get() && !ds.isClosed) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    ds.receive(pkt)
                    val raw = pkt.data.copyOfRange(pkt.offset, pkt.offset + pkt.length)
                    val clientAddr = pkt.socketAddress
                    executor.execute { handleSocks5UdpDatagram(ds, clientAddr, raw) }
                } catch (_: Exception) {
                    if (!isRunning.get() || ds.isClosed) break
                }
            }
        }
    }

    private fun handleSocks5UdpDatagram(ds: DatagramSocket, clientAddr: java.net.SocketAddress, raw: ByteArray) {
        if (raw.size < 10) return
        val atyp = raw[3].toInt() and 0xFF
        val headerLen = when (atyp) {
            0x01 -> 10
            0x04 -> 22
            0x03 -> 7 + (raw[4].toInt() and 0xFF)
            else -> return
        }
        if (raw.size <= headerLen) return
        val dstPort = ((raw[headerLen - 2].toInt() and 0xFF) shl 8) or (raw[headerLen - 1].toInt() and 0xFF)
        if (dstPort != 53) return

        val dnsQuery = raw.copyOfRange(headerLen, raw.size)
        val dnsResp = resolveDnsOverInTunnelDoH(dnsQuery) ?: return
        val reply = ByteArray(headerLen + dnsResp.size)
        System.arraycopy(raw, 0, reply, 0, headerLen)
        System.arraycopy(dnsResp, 0, reply, headerLen, dnsResp.size)
        runCatching { ds.send(DatagramPacket(reply, reply.size, clientAddr)) }
    }

    private fun handleTcpDnsOverDoH(ins: DataInputStream, out: OutputStream) {
        try {
            while (isRunning.get()) {
                val qLen = try {
                    ins.readUnsignedShort()
                } catch (_: Exception) {
                    break
                }
                if (qLen <= 0 || qLen > 8192) break
                val qBytes = ByteArray(qLen)
                ins.readFully(qBytes)
                val resp = resolveDnsOverInTunnelDoH(qBytes) ?: break
                out.write((resp.size ushr 8) and 0xFF)
                out.write(resp.size and 0xFF)
                out.write(resp)
                out.flush()
            }
        } catch (_: Exception) {}
    }

    private fun resolveDnsOverInTunnelDoH(dnsQuery: ByteArray): ByteArray? {
        val dohEndpoints = listOf(
            "https://1.1.1.1/dns-query",
            "https://1.0.0.1/dns-query",
            "https://9.9.9.9/dns-query"
        )
        val socksProxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", localListenPort))
        for (urlStr in dohEndpoints) {
            try {
                val conn = (URL(urlStr).openConnection(socksProxy) as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = 5_000
                    readTimeout = 5_000
                    doOutput = true
                    setRequestProperty("Content-Type", "application/dns-message")
                    setRequestProperty("Accept", "application/dns-message")
                }
                conn.outputStream.use { it.write(dnsQuery) }
                if (conn.responseCode in 200..299) {
                    val bytes = conn.inputStream.use { it.readBytes() }
                    if (bytes.size >= 12) return bytes
                }
            } catch (_: Exception) {}
        }
        return null
    }

    private fun startLocalHttpServer(port: Int) {
        val server = ServerSocket()
        server.reuseAddress = true
        server.bind(InetSocketAddress("127.0.0.1", port), 128)
        httpServerSocket = server

        thread(start = true, isDaemon = true, name = "FirefoxVPN-HttpProxy") {
            while (isRunning.get() && !server.isClosed) {
                val client = try {
                    server.accept()
                } catch (_: Exception) {
                    break
                }
                executor.execute { handleHttpProxyClient(client) }
            }
        }
    }

    private fun handleHttpProxyClient(client: Socket) {
        try {
            client.tcpNoDelay = true
            client.soTimeout = 15_000
            val ins = BufferedInputStream(client.getInputStream())
            val out = BufferedOutputStream(client.getOutputStream())

            val reqLine = readAsciiLine(ins) ?: return
            while (true) {
                val h = readAsciiLine(ins) ?: break
                if (h.isEmpty()) break
            }

            val parts = reqLine.split(" ")
            if (parts.size < 2 || !parts[0].equals("CONNECT", ignoreCase = true)) {
                out.write("HTTP/1.1 405 Method Not Allowed\r\n\r\n".toByteArray())
                out.flush()
                return
            }
            val hostPort = parts[1]
            val targetHost = hostPort.substringBefore(":")
            val targetPort = hostPort.substringAfter(":", "443").toIntOrNull() ?: 443

            val session = ensureActiveSession() ?: run {
                out.write("HTTP/1.1 502 Bad Gateway\r\n\r\n".toByteArray())
                out.flush()
                return
            }

            val stream = session.openConnectStream(targetHost, targetPort) ?: run {
                out.write("HTTP/1.1 502 Bad Gateway\r\n\r\n".toByteArray())
                out.flush()
                return
            }

            out.write("HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray())
            out.flush()
            client.soTimeout = 0
            pipeClientAndH2Stream(client, ins, out, stream)
        } catch (_: Exception) {
        } finally {
            runCatching { client.close() }
        }
    }

    private fun verifyDataPlaneWithRetry(socksPort: Int, maxAttempts: Int = 4): String? {
        for (attempt in 1..maxAttempts) {
            if (!isRunning.get()) return null
            val ip = verifyDataPlane(socksPort)
            if (ip != null) return ip
            if (attempt < maxAttempts) Thread.sleep(800)
        }
        return null
    }

    private fun verifyDataPlane(socksPort: Int): String? {
        for ((ipBytes, hostHdr) in listOf(
            byteArrayOf(1, 1, 1, 1) to "1.1.1.1",
            byteArrayOf(1, 0, 0, 1) to "1.0.0.1"
        )) {
            try {
                Socket().use { socket ->
                    socket.soTimeout = 6000
                    socket.connect(InetSocketAddress("127.0.0.1", socksPort), 2500)
                    val out = socket.getOutputStream()
                    val input = socket.getInputStream()
                    out.write(byteArrayOf(0x05, 0x01, 0x00))
                    out.flush()
                    val authResp = ByteArray(2)
                    readFully(input, authResp)
                    if (authResp[0] == 0x05.toByte() && authResp[1] == 0x00.toByte()) {
                        val req = byteArrayOf(0x05, 0x01, 0x00, 0x01, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], 0x00, 0x50)
                        out.write(req)
                        out.flush()
                        val connResp = ByteArray(4)
                        readFully(input, connResp)
                        if (connResp[1] == 0x00.toByte()) {
                            when (connResp[3]) {
                                0x01.toByte() -> readFully(input, ByteArray(4 + 2))
                                0x03.toByte() -> {
                                    val len = input.read()
                                    if (len > 0) readFully(input, ByteArray(len + 2))
                                }
                                0x04.toByte() -> readFully(input, ByteArray(16 + 2))
                            }
                            val httpReq = "GET /cdn-cgi/trace HTTP/1.1\r\nHost: $hostHdr\r\nUser-Agent: AetherST/2.5\r\nConnection: close\r\n\r\n"
                            out.write(httpReq.toByteArray(Charsets.US_ASCII))
                            out.flush()
                            val text = input.bufferedReader(Charsets.US_ASCII).readText()
                            val ip = Regex("""(?m)^ip=(.+)$""").find(text)?.groupValues?.get(1)?.trim()
                            val loc = Regex("""(?m)^loc=(.+)$""").find(text)?.groupValues?.get(1)?.trim()?.uppercase()
                            if (!ip.isNullOrBlank() && loc != "IR") {
                                return ip
                            }
                        }
                    }
                }
            } catch (_: Exception) {}
        }
        return null
    }

    private fun probePort(host: String, port: Int): Boolean {
        return runCatching {
            Socket().use {
                it.connect(InetSocketAddress(host, port), 800)
                true
            }
        }.getOrDefault(false)
    }

    private fun readFully(stream: InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val count = stream.read(buffer, offset, buffer.size - offset)
            if (count < 0) throw java.io.EOFException("Premature end of stream")
            offset += count
        }
    }

    companion object {
        private val jsonParser = Json { ignoreUnknownKeys = true }

        // Mandatory Mozilla VPN User-Agent required by vpn.mozilla.org and Remote Settings
        private const val MOZILLA_VPN_UA = "MozillaVPN/2.35.0 (sys:linux; iap:true)"
        private const val FIREFOX_DESKTOP_UA =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0"

        private const val FXA_API_BASE = "https://api.accounts.firefox.com/v1"
        private const val FXA_OAUTH_BASE = "https://oauth.accounts.firefox.com/v1"
        private const val GUARDIAN_API_BASE = "https://vpn.mozilla.org"
        private const val REMOTE_SETTINGS_URL =
            "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records"

        private const val FXA_SCOPE_VPN = "profile https://identity.mozilla.com/apps/vpn"

        private val FXA_CLIENT_IDS = listOf(
            "e6eb0d1e856335fc", // Official Mozilla VPN client ID
            "5882386c6d801776", // Official Firefox VPN proxy / Desktop FxA client ID
            "a2270f727f45f648"  // Firefox Private Network / Fenix
        )

        /**
         * Resolves live Mozilla Fastly CONNECT edge candidates (`host:port`) from Mozilla Remote Settings
         * (`vpn-serverlist` collection), falling back to official Fastly MASQUE/CONNECT aggregate hostnames
         * (`<cc>.m1.fastly-masque.net:443`).
         */
        data class FirefoxServerOption(
            val id: String,
            val countryCode: String,
            val titleFa: String,
            val titleEn: String,
            val subtitle: String
        )

        val BUILTIN_SERVER_OPTIONS: List<FirefoxServerOption> = listOf(
            FirefoxServerOption("us", "US", "آمریکا (اتوماتیک سریع‌ترین سرور)", "United States (Auto Best)", "us.m1.fastly-masque.net:443"),
            FirefoxServerOption("de", "DE", "آلمان (فرانکفورت / برلین)", "Germany (Frankfurt / Berlin)", "de.m1.fastly-masque.net:443"),
            FirefoxServerOption("nl", "NL", "هلند (آمستردام)", "Netherlands (Amsterdam)", "nl.m1.fastly-masque.net:443"),
            FirefoxServerOption("gb", "GB", "بریتانیا (لندن / منچستر)", "United Kingdom (London)", "gb.m1.fastly-masque.net:443"),
            FirefoxServerOption("fr", "FR", "فرانسه (پاریس / مارسی)", "France (Paris)", "fr.m1.fastly-masque.net:443"),
            FirefoxServerOption("ch", "CH", "سوئیس (زوریخ)", "Switzerland (Zurich)", "ch.m1.fastly-masque.net:443"),
            FirefoxServerOption("se", "SE", "سوئد (استکهلم / مالمو)", "Sweden (Stockholm)", "se.m1.fastly-masque.net:443"),
            FirefoxServerOption("fi", "FI", "فنلاند (هلسینکی)", "Finland (Helsinki)", "fi.m1.fastly-masque.net:443"),
            FirefoxServerOption("ca", "CA", "کانادا (تورنتو / مونترال / ونکوور)", "Canada (Toronto / Vancouver)", "ca.m1.fastly-masque.net:443"),
            FirefoxServerOption("at", "AT", "اتریش (وین)", "Austria (Vienna)", "at.m1.fastly-masque.net:443"),
            FirefoxServerOption("es", "ES", "اسپانیا (مادرید)", "Spain (Madrid)", "es.m1.fastly-masque.net:443"),
            FirefoxServerOption("it", "IT", "ایتالیا (میلان / رم)", "Italy (Milan / Rome)", "it.m1.fastly-masque.net:443"),
            FirefoxServerOption("jp", "JP", "ژاپن (توکیو / اوزاکا)", "Japan (Tokyo / Osaka)", "jp.m1.fastly-masque.net:443"),
            FirefoxServerOption("sg", "SG", "سنگاپور (سنگاپور)", "Singapore", "sg.m1.fastly-masque.net:443"),
            FirefoxServerOption("au", "AU", "استرالیا (سیدنی / ملبورن)", "Australia (Sydney)", "au.m1.fastly-masque.net:443"),
            FirefoxServerOption("be", "BE", "بلژیک (بروکسل)", "Belgium (Brussels)", "be.m1.fastly-masque.net:443"),
            FirefoxServerOption("dk", "DK", "دانمارک (کپنهاگ)", "Denmark (Copenhagen)", "dk.m1.fastly-masque.net:443"),
            FirefoxServerOption("ie", "IE", "ایرلند (دوبلین)", "Ireland (Dublin)", "ie.m1.fastly-masque.net:443"),
            FirefoxServerOption("no", "NO", "نروژ (اسلو)", "Norway (Oslo)", "no.m1.fastly-masque.net:443"),
            FirefoxServerOption("pl", "PL", "لهستان (ورشو)", "Poland (Warsaw)", "pl.m1.fastly-masque.net:443"),
            FirefoxServerOption("pt", "PT", "پرتغال (لیسبون)", "Portugal (Lisbon)", "pt.m1.fastly-masque.net:443"),
            FirefoxServerOption("cz", "CZ", "جمهوری چک (پراگ)", "Czechia (Prague)", "cz.m1.fastly-masque.net:443"),
            FirefoxServerOption("ro", "RO", "رومانی (بخارست)", "Romania (Bucharest)", "ro.m1.fastly-masque.net:443"),
            FirefoxServerOption("bg", "BG", "بلغارستان (صوفیه)", "Bulgaria (Sofia)", "bg.m1.fastly-masque.net:443"),
            FirefoxServerOption("hu", "HU", "مجارستان (بوداپست)", "Hungary (Budapest)", "hu.m1.fastly-masque.net:443")
        )

        fun extractCountryCode(rawSpec: String): String {
            val trimmed = rawSpec.trim()
            if (trimmed.isEmpty()) return "US"
            if (trimmed.contains("|")) {
                val cc = trimmed.substringBefore("|").trim().uppercase()
                if (cc.length == 2) return if (cc == "UK") "GB" else cc
            }
            if (trimmed.contains(".")) {
                val prefix = trimmed.substringBefore(".").trim().uppercase()
                if (prefix.length == 2) return if (prefix == "UK") "GB" else prefix
            }
            val code = trimmed.take(2).uppercase()
            return if (code == "UK") "GB" else code
        }

        suspend fun fetchLiveServerOptions(
            socksHost: String = "127.0.0.1",
            socksPort: Int = 2021
        ): List<FirefoxServerOption> = withContext(Dispatchers.IO) {
            val combined = mutableListOf<FirefoxServerOption>()
            combined.addAll(BUILTIN_SERVER_OPTIONS)

            val live = runCatching {
                val client = buildClient(socksHost, socksPort, timeoutSec = 4)
                val req = Request.Builder()
                    .url(REMOTE_SETTINGS_URL)
                    .header("User-Agent", MOZILLA_VPN_UA)
                    .header("Accept", "application/json")
                    .get()
                    .build()
                client.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) return@runCatching emptyList<FirefoxServerOption>()
                    val body = resp.body?.string() ?: return@runCatching emptyList<FirefoxServerOption>()
                    val root = jsonParser.parseToJsonElement(body).jsonObject
                    val dataArr = root["data"]?.jsonArray ?: return@runCatching emptyList<FirefoxServerOption>()
                    val discovered = mutableListOf<FirefoxServerOption>()
                    for (recElem in dataArr) {
                        val rec = recElem.jsonObject
                        val code = (rec["code"]?.jsonPrimitive?.content ?: rec["country"]?.jsonPrimitive?.content ?: "US").uppercase()
                        val countryName = rec["name"]?.jsonPrimitive?.content ?: code
                        val cities = rec["cities"]?.jsonArray ?: continue
                        for (cityElem in cities) {
                            val cityObj = cityElem.jsonObject
                            val cityName = cityObj["name"]?.jsonPrimitive?.content ?: cityObj["code"]?.jsonPrimitive?.content ?: ""
                            val servers = cityObj["servers"]?.jsonArray ?: continue
                            for (srvElem in servers) {
                                val srv = srvElem.jsonObject
                                if (srv["quarantined"]?.jsonPrimitive?.booleanOrNull == true) continue
                                val srvName = srv["hostname"]?.jsonPrimitive?.content ?: srv["name"]?.jsonPrimitive?.content ?: ""
                                val protocols = srv["protocols"]?.jsonArray
                                var connectHost: String? = null
                                var connectPort = 443
                                if (protocols != null) {
                                    for (pElem in protocols) {
                                        val pObj = pElem.jsonObject
                                        if (pObj["name"]?.jsonPrimitive?.content?.lowercase() == "connect") {
                                            connectHost = pObj["host"]?.jsonPrimitive?.content?.trim()
                                            connectPort = pObj["port"]?.jsonPrimitive?.intOrNull ?: 443
                                            if (!connectHost.isNullOrBlank()) break
                                        }
                                    }
                                }
                                if (connectHost.isNullOrBlank()) {
                                    val fallbackH = (srv["host"]?.jsonPrimitive?.content ?: srv["hostname"]?.jsonPrimitive?.content)?.trim()
                                    if (!fallbackH.isNullOrBlank() && fallbackH.contains(".")) {
                                        connectHost = fallbackH
                                        connectPort = srv["port"]?.jsonPrimitive?.intOrNull ?: 443
                                    }
                                }
                                if (!connectHost.isNullOrBlank()) {
                                    val id = "${code.lowercase()}|$connectHost:$connectPort"
                                    val cityLabel = if (cityName.isNotBlank()) "$countryName - $cityName" else countryName
                                    val shortHost = srvName.ifBlank { connectHost.substringBefore(".") }
                                    discovered.add(
                                        FirefoxServerOption(
                                            id = id,
                                            countryCode = code,
                                            titleFa = "$cityLabel ($shortHost)",
                                            titleEn = "$cityLabel ($shortHost)",
                                            subtitle = "$connectHost:$connectPort"
                                        )
                                    )
                                }
                            }
                        }
                    }
                    discovered
                }
            }.getOrDefault(emptyList())

            combined.addAll(live)
            combined.distinctBy { it.id.lowercase() }
        }

        fun resolveCountryExitCandidates(
            countryCode: String,
            socksHost: String,
            socksPort: Int
        ): List<EdgeEndpoint> {
            val results = mutableListOf<EdgeEndpoint>()
            val trimmedSpec = countryCode.trim()
            val explicitHostPort = when {
                trimmedSpec.contains("|") -> trimmedSpec.substringAfter("|").trim()
                trimmedSpec.contains(".") -> trimmedSpec
                else -> null
            }
            val rawCc = extractCountryCode(trimmedSpec)
            val targetCc = when {
                rawCc.isBlank() || rawCc == "AUTO" -> "US"
                rawCc == "UK" -> "GB"
                else -> rawCc
            }
            if (!explicitHostPort.isNullOrBlank()) {
                val h = explicitHostPort.substringBefore(":").trim()
                val pt = explicitHostPort.substringAfter(":", "443").toIntOrNull() ?: 443
                if (h.isNotBlank()) {
                    results.add(EdgeEndpoint(h, pt, targetCc))
                }
            }

            val fetched = runCatching {
                val client = buildClient(socksHost, socksPort, timeoutSec = 4)
                val req = Request.Builder()
                    .url(REMOTE_SETTINGS_URL)
                    .header("User-Agent", MOZILLA_VPN_UA)
                    .header("Accept", "application/json")
                    .get()
                    .build()
                client.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) return@runCatching emptyList()
                    val body = resp.body?.string() ?: return@runCatching emptyList()
                    val root = jsonParser.parseToJsonElement(body).jsonObject
                    val dataArr = root["data"]?.jsonArray ?: return@runCatching emptyList()
                    val list = mutableListOf<EdgeEndpoint>()
                    for (recElem in dataArr) {
                        val rec = recElem.jsonObject
                        val code = (rec["code"]?.jsonPrimitive?.content ?: rec["country"]?.jsonPrimitive?.content ?: "US").uppercase()
                        val cities = rec["cities"]?.jsonArray ?: continue
                        for (cityElem in cities) {
                            val servers = cityElem.jsonObject["servers"]?.jsonArray ?: continue
                            for (srvElem in servers) {
                                val srv = srvElem.jsonObject
                                if (srv["quarantined"]?.jsonPrimitive?.booleanOrNull == true) continue
                                val protocols = srv["protocols"]?.jsonArray
                                var added = false
                                if (protocols != null) {
                                    for (pElem in protocols) {
                                        val pObj = pElem.jsonObject
                                        val pName = pObj["name"]?.jsonPrimitive?.content?.lowercase()
                                        if (pName == "connect") {
                                            val h = pObj["host"]?.jsonPrimitive?.content?.trim()
                                            val pt = pObj["port"]?.jsonPrimitive?.intOrNull ?: 443
                                            if (!h.isNullOrBlank()) {
                                                list.add(EdgeEndpoint(h, pt, code))
                                                added = true
                                            }
                                        }
                                    }
                                }
                                if (!added) {
                                    val h = (srv["host"]?.jsonPrimitive?.content ?: srv["hostname"]?.jsonPrimitive?.content)?.trim()
                                    val pt = srv["port"]?.jsonPrimitive?.intOrNull ?: 443
                                    if (!h.isNullOrBlank() && h.contains(".")) {
                                        list.add(EdgeEndpoint(h, pt, code))
                                    }
                                }
                            }
                        }
                    }
                    list
                }
            }.getOrDefault(emptyList())

            if (fetched.isNotEmpty()) {
                results.addAll(fetched.filter { it.countryCode.equals(targetCc, ignoreCase = true) })
                results.addAll(fetched.filter { it.countryCode.equals("REC", ignoreCase = true) })
                results.addAll(fetched.filter { it.countryCode.equals("US", ignoreCase = true) })
                results.addAll(fetched)
            }

            val ccLower = targetCc.lowercase()
            results.addAll(
                listOf(
                    EdgeEndpoint("$ccLower.m1.fastly-masque.net", 443, targetCc),
                    EdgeEndpoint("us.m1.fastly-masque.net", 443, "US"),
                    EdgeEndpoint("de.m1.fastly-masque.net", 443, "DE"),
                    EdgeEndpoint("nl.m1.fastly-masque.net", 443, "NL"),
                    EdgeEndpoint("gb.m1.fastly-masque.net", 443, "GB"),
                    EdgeEndpoint("ca.m1.fastly-masque.net", 443, "CA"),
                    EdgeEndpoint("fr.m1.fastly-masque.net", 443, "FR"),
                    EdgeEndpoint("m1.fastly-masque.net", 443, "US")
                )
            )
            return results.distinctBy { "${it.host.lowercase()}:${it.port}" }
        }

        fun resolveCountryExitHost(countryCode: String, socksHost: String, socksPort: Int): String {
            return resolveCountryExitCandidates(countryCode, socksHost, socksPort).first().host
        }

        /**
         * Resolves a stored token (`sessionToken` 64-hex, `fxa:<sessionToken>:<oauthToken>`, OAuth `access_token`,
         * or Guardian ProxyPass JWT `eyJ...`) into a live, non-expired Guardian ProxyPass JWT through Aether's SOCKS5 proxy.
         */
        fun resolveLiveProxyPassJwt(
            rawTokenOrBundle: String,
            socksHost: String = "127.0.0.1",
            socksPort: Int = 2021,
            forceRefresh: Boolean = false
        ): String? {
            val trimmed = rawTokenOrBundle.trim()
                .removePrefix("Guardian-Proxy-Pass ")
                .removePrefix("Bearer ")
                .trim()
            if (trimmed.isEmpty()) return null

            var sessionTokenHex: String? = null
            var oauthAccessToken: String? = null
            var cachedJwt: String? = null

            when {
                trimmed.startsWith("fxa:", ignoreCase = true) -> {
                    val parts = trimmed.split(":")
                    sessionTokenHex = parts.getOrNull(1)?.takeIf { it.matches(Regex("""^[0-9a-fA-F]{64}$""")) }
                    oauthAccessToken = parts.getOrNull(2)?.takeIf { it.isNotBlank() }
                    cachedJwt = parts.getOrNull(3)?.takeIf { it.startsWith("eyJ") }
                }
                trimmed.startsWith("{") -> {
                    sessionTokenHex = Regex(""""sessionToken"\s*:\s*"([0-9a-fA-F]{64})"""").find(trimmed)?.groupValues?.get(1)
                    oauthAccessToken = Regex(""""access_token"\s*:\s*"([^"]+)"""").find(trimmed)?.groupValues?.get(1)
                    cachedJwt = Regex(""""(?:proxypass|token)"\s*:\s*"(eyJ[^"]+)"""").find(trimmed)?.groupValues?.get(1)
                }
                trimmed.matches(Regex("""^[0-9a-fA-F]{64}$""")) -> {
                    sessionTokenHex = trimmed
                }
                trimmed.startsWith("eyJ") && trimmed.count { it == '.' } == 2 -> {
                    cachedJwt = trimmed
                }
                else -> {
                    oauthAccessToken = trimmed
                }
            }

            if (!forceRefresh && !cachedJwt.isNullOrBlank() && isJwtFresh(cachedJwt, 90)) {
                return cachedJwt
            }

            val client = buildClient(socksHost, socksPort, timeoutSec = 15)

            val currentOAuth = oauthAccessToken
            if (!currentOAuth.isNullOrBlank()) {
                val jwt = runCatching { requestGuardianProxyPass(client, currentOAuth) }.getOrNull()
                if (!jwt.isNullOrBlank()) return jwt
            }

            val currentSession = sessionTokenHex
            if (!currentSession.isNullOrBlank()) {
                val mintedOAuth = runCatching { exchangeSessionTokenForOAuth(client, currentSession) }.getOrNull()
                if (!mintedOAuth.isNullOrBlank()) {
                    val jwt = runCatching { requestGuardianProxyPass(client, mintedOAuth) }.getOrNull()
                    if (!jwt.isNullOrBlank()) return jwt
                }
            }

            return cachedJwt?.takeIf { isJwtFresh(it, 10) }
        }

        /**
         * Called by FirefoxVpnDialog after WebView login or token paste.
         * Preserves the persistent 64-hex `sessionToken` (as `fxa:<sessionToken>:<oauth>:<jwt>` or `<sessionToken>`)
         * so that connecting later (or after the 10-minute ProxyPass JWT expires) always mints a fresh ProxyPass JWT
         * through Aether's Layer-1 tunnel!
         */
        suspend fun exchangeSessionOrOAuthForProxyPass(
            rawTokenOrJson: String,
            socksHost: String = "127.0.0.1",
            socksPort: Int = 2021
        ): Result<String> = withContext(Dispatchers.IO) {
            runCatching {
                val trimmed = rawTokenOrJson.trim()
                require(trimmed.isNotEmpty()) { "Extracted Firefox token is empty" }

                var sessionTokenHex: String? = null
                var oauthAccessToken: String? = null

                when {
                    trimmed.startsWith("fxa:", ignoreCase = true) -> {
                        val parts = trimmed.split(":")
                        sessionTokenHex = parts.getOrNull(1)?.takeIf { it.matches(Regex("""^[0-9a-fA-F]{64}$""")) }
                        oauthAccessToken = parts.getOrNull(2)?.takeIf { it.isNotBlank() }
                    }
                    trimmed.startsWith("{") -> {
                        sessionTokenHex = Regex(""""sessionToken"\s*:\s*"([0-9a-fA-F]{64})"""").find(trimmed)?.groupValues?.get(1)
                        oauthAccessToken = Regex(""""access_token"\s*:\s*"([^"]+)"""").find(trimmed)?.groupValues?.get(1)
                        val proxyMatch = Regex(""""(?:proxypass|token)"\s*:\s*"(eyJ[^"]+)"""").find(trimmed)
                        if (proxyMatch != null && sessionTokenHex.isNullOrBlank()) {
                            return@runCatching proxyMatch.groupValues[1]
                        }
                    }
                    trimmed.matches(Regex("""^[0-9a-fA-F]{64}$""")) -> {
                        sessionTokenHex = trimmed
                    }
                    trimmed.startsWith("eyJ") && trimmed.count { it == '.' } == 2 -> {
                        return@runCatching trimmed
                    }
                    else -> {
                        oauthAccessToken = trimmed.removePrefix("Bearer ").removePrefix("bearer ").trim()
                    }
                }

                val client = buildClient(socksHost, socksPort, timeoutSec = 15)

                val sessHex = sessionTokenHex
                if (oauthAccessToken.isNullOrBlank() && !sessHex.isNullOrBlank()) {
                    oauthAccessToken = runCatching { exchangeSessionTokenForOAuth(client, sessHex) }.getOrNull()
                }

                val oauthTok = oauthAccessToken
                val proxyPassJwt = if (!oauthTok.isNullOrBlank()) {
                    runCatching { requestGuardianProxyPass(client, oauthTok) }.getOrNull()
                } else null

                // Always preserve sessionTokenHex if available so FirefoxVpnExitTunnel.start() can mint/renew
                // 10-minute Guardian ProxyPass JWTs through Aether Layer-1 on every Connect!
                when {
                    !sessHex.isNullOrBlank() && !proxyPassJwt.isNullOrBlank() ->
                        "fxa:$sessHex:${oauthTok.orEmpty()}:$proxyPassJwt"
                    !sessHex.isNullOrBlank() && !oauthTok.isNullOrBlank() ->
                        "fxa:$sessHex:$oauthTok"
                    !sessHex.isNullOrBlank() ->
                        sessHex
                    !proxyPassJwt.isNullOrBlank() ->
                        proxyPassJwt
                    !oauthTok.isNullOrBlank() ->
                        oauthTok
                    else ->
                        throw IllegalStateException("Could not extract valid sessionToken or ProxyPass from Firefox login")
                }
            }
        }

        suspend fun verifySessionEmailCodeAndFetchToken(
            sessionTokenHex: String,
            code: String,
            socksHost: String = "127.0.0.1",
            socksPort: Int = 2021
        ): Result<String> = withContext(Dispatchers.IO) {
            runCatching {
                val cleanCode = code.trim()
                require(cleanCode.length >= 4) { "Please enter the verification code sent to your email." }

                val client = buildClient(socksHost, socksPort, timeoutSec = 20)
                val mediaJson = "application/json; charset=utf-8".toMediaType()
                val verifyPayload = """{"code":"$cleanCode"}"""

                val hawkHeader = buildHawkHeader(
                    method = "POST",
                    host = "api.accounts.firefox.com",
                    port = 443,
                    path = "/v1/session/verify_code",
                    sessionTokenHex = sessionTokenHex,
                    body = verifyPayload
                )
                val verifyReq = Request.Builder()
                    .url("$FXA_API_BASE/session/verify_code")
                    .header("Authorization", hawkHeader)
                    .header("User-Agent", FIREFOX_DESKTOP_UA)
                    .post(verifyPayload.toRequestBody(mediaJson))
                    .build()

                client.newCall(verifyReq).execute().use { resp ->
                    if (!resp.isSuccessful) {
                        val bodyStr = resp.body?.string().orEmpty()
                        val msg = runCatching {
                            jsonParser.parseToJsonElement(bodyStr).jsonObject["message"]?.jsonPrimitive?.content
                        }.getOrNull() ?: "HTTP ${resp.code}"
                        throw IllegalStateException("Verification code rejected: $msg")
                    }
                }

                val oauthToken = runCatching { exchangeSessionTokenForOAuth(client, sessionTokenHex) }.getOrNull()
                val proxyPass = oauthToken?.let { runCatching { requestGuardianProxyPass(client, it) }.getOrNull() }
                when {
                    !proxyPass.isNullOrBlank() -> "fxa:$sessionTokenHex:${oauthToken.orEmpty()}:$proxyPass"
                    !oauthToken.isNullOrBlank() -> "fxa:$sessionTokenHex:$oauthToken"
                    else -> sessionTokenHex
                }
            }
        }

        suspend fun signInWithFirefoxAccount(
            email: String,
            password: String,
            unblockCode: String = "",
            socksHost: String = "127.0.0.1",
            socksPort: Int = 2021
        ): Result<String> = withContext(Dispatchers.IO) {
            runCatching {
                val cleanEmail = email.trim().lowercase()
                val cleanPass = password
                require(cleanEmail.contains("@") && cleanPass.isNotBlank()) { "Please enter a valid Firefox Account email and password." }

                val client = buildClient(socksHost, socksPort, timeoutSec = 20)
                val mediaJson = "application/json; charset=utf-8".toMediaType()

                val authPw = deriveFxaAuthPw(cleanEmail, cleanPass)
                val unblockField = if (unblockCode.isNotBlank()) ""","unblockCode":"${unblockCode.trim()}"""" else ""
                val loginPayload = """{"email":"$cleanEmail","authPW":"$authPw","reason":"signin","verificationMethod":"email-2fa"$unblockField}"""

                var sessionTokenHex: String? = null
                var isVerified = true
                var lastLoginErr = "Login failed"

                for (base in listOf(FXA_OAUTH_BASE, FXA_API_BASE)) {
                    val loginReq = Request.Builder()
                        .url("$base/account/login?keys=true")
                        .header("User-Agent", FIREFOX_DESKTOP_UA)
                        .post(loginPayload.toRequestBody(mediaJson))
                        .build()

                    val ok = runCatching {
                        client.newCall(loginReq).execute().use { resp ->
                            val bodyStr = resp.body?.string().orEmpty()
                            if (resp.isSuccessful) {
                                val obj = jsonParser.parseToJsonElement(bodyStr).jsonObject
                                sessionTokenHex = obj["sessionToken"]?.jsonPrimitive?.content
                                isVerified = obj["verified"]?.jsonPrimitive?.booleanOrNull ?: true
                                !sessionTokenHex.isNullOrBlank()
                            } else {
                                val errObj = runCatching { jsonParser.parseToJsonElement(bodyStr).jsonObject }.getOrNull()
                                val errno = errObj?.get("errno")?.jsonPrimitive?.intOrNull
                                val msg = errObj?.get("message")?.jsonPrimitive?.content ?: "HTTP ${resp.code}"
                                lastLoginErr = "$msg (errno=${errno ?: resp.code})"
                                false
                            }
                        }
                    }.getOrDefault(false)
                    if (ok) break
                }

                val sess = sessionTokenHex
                    ?: throw IllegalStateException("FxA sign-in failed: $lastLoginErr (Recommended: use In-App WebView Login)")

                if (!isVerified) {
                    throw FxaVerificationRequiredException(
                        sessionTokenHex = sess,
                        message = "Firefox sent a 6-digit verification code to your email ($cleanEmail). Enter it below to complete sign-in."
                    )
                }

                val oauthToken = runCatching { exchangeSessionTokenForOAuth(client, sess) }.getOrNull()
                val proxyPass = oauthToken?.let { runCatching { requestGuardianProxyPass(client, it) }.getOrNull() }
                when {
                    !proxyPass.isNullOrBlank() -> "fxa:$sess:${oauthToken.orEmpty()}:$proxyPass"
                    !oauthToken.isNullOrBlank() -> "fxa:$sess:$oauthToken"
                    else -> sess
                }
            }
        }

        /**
         * Exchanges a 64-hex `sessionToken` for a VPN-scoped OAuth `access_token` using:
         *  1. PKCE Authorization Code Grant (`POST /v1/oauth/authorization` -> `POST /v1/token` / `/v1/oauth/token`)
         *     across both `oauth.accounts.firefox.com` and `api.accounts.firefox.com` with Hawk + payload hash.
         *  2. Direct Hawk-signed `POST /v1/oauth/token` fallback on `oauth.accounts.firefox.com` and `api.accounts.firefox.com`.
         */
        private fun exchangeSessionTokenForOAuth(client: OkHttpClient, sessionTokenHex: String): String {
            val mediaJson = "application/json; charset=utf-8".toMediaType()
            var lastErr = "OAuth exchange failed"
            val hosts = listOf(
                "oauth.accounts.firefox.com" to FXA_OAUTH_BASE,
                "api.accounts.firefox.com" to FXA_API_BASE
            )

            // Flow A: PKCE Authorization Code Grant
            for (clientId in FXA_CLIENT_IDS) {
                val verifierBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
                val codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(verifierBytes)
                val challengeBytes = MessageDigest.getInstance("SHA-256").digest(codeVerifier.toByteArray(Charsets.UTF_8))
                val codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes)
                val state = UUID.randomUUID().toString().replace("-", "")

                val authPayload = """{"client_id":"$clientId","scope":"$FXA_SCOPE_VPN","state":"$state","response_type":"code","access_type":"offline","code_challenge":"$codeChallenge","code_challenge_method":"S256"}"""

                for ((hostName, baseUrl) in hosts) {
                    val hawkHeader = buildHawkHeader(
                        method = "POST",
                        host = hostName,
                        port = 443,
                        path = "/v1/oauth/authorization",
                        sessionTokenHex = sessionTokenHex,
                        body = authPayload
                    )
                    val authReq = Request.Builder()
                        .url("$baseUrl/oauth/authorization")
                        .header("Authorization", hawkHeader)
                        .header("User-Agent", FIREFOX_DESKTOP_UA)
                        .post(authPayload.toRequestBody(mediaJson))
                        .build()

                    val code = runCatching {
                        client.newCall(authReq).execute().use { resp ->
                            val bodyStr = resp.body?.string().orEmpty()
                            if (resp.isSuccessful) {
                                jsonParser.parseToJsonElement(bodyStr).jsonObject["code"]?.jsonPrimitive?.content
                            } else {
                                lastErr = "auth HTTP ${resp.code}: $bodyStr"
                                null
                            }
                        }
                    }.getOrNull()

                    if (!code.isNullOrBlank()) {
                        val redeemPayload = """{"client_id":"$clientId","grant_type":"authorization_code","code":"$code","code_verifier":"$codeVerifier"}"""
                        val redeemUrls = listOf(
                            "$FXA_OAUTH_BASE/token",
                            "$FXA_OAUTH_BASE/oauth/token",
                            "$FXA_API_BASE/oauth/token",
                            "$FXA_API_BASE/token"
                        )
                        for (rUrl in redeemUrls) {
                            val rReq = Request.Builder()
                                .url(rUrl)
                                .header("User-Agent", FIREFOX_DESKTOP_UA)
                                .post(redeemPayload.toRequestBody(mediaJson))
                                .build()
                            val accessToken = runCatching {
                                client.newCall(rReq).execute().use { resp ->
                                    val bodyStr = resp.body?.string().orEmpty()
                                    if (resp.isSuccessful) {
                                        jsonParser.parseToJsonElement(bodyStr).jsonObject["access_token"]?.jsonPrimitive?.content
                                    } else null
                                }
                            }.getOrNull()
                            if (!accessToken.isNullOrBlank()) return accessToken
                        }
                    }
                }
            }

            // Flow B: Direct Hawk-signed POST /v1/oauth/token with payload hash
            for (clientId in FXA_CLIENT_IDS) {
                val payloads = listOf(
                    """{"client_id":"$clientId","grant_type":"fxa-credentials","scope":"$FXA_SCOPE_VPN","access_type":"offline","ttl":3600}""",
                    """{"client_id":"$clientId","scope":"$FXA_SCOPE_VPN","ttl":3600}"""
                )
                for ((hostName, baseUrl) in hosts) {
                    for (oauthPayload in payloads) {
                        val hawkHeader = buildHawkHeader(
                            method = "POST",
                            host = hostName,
                            port = 443,
                            path = "/v1/oauth/token",
                            sessionTokenHex = sessionTokenHex,
                            body = oauthPayload
                        )
                        val oauthReq = Request.Builder()
                            .url("$baseUrl/oauth/token")
                            .header("Authorization", hawkHeader)
                            .header("User-Agent", FIREFOX_DESKTOP_UA)
                            .post(oauthPayload.toRequestBody(mediaJson))
                            .build()

                        val token = runCatching {
                            client.newCall(oauthReq).execute().use { resp ->
                                val bodyStr = resp.body?.string().orEmpty()
                                if (resp.isSuccessful) {
                                    jsonParser.parseToJsonElement(bodyStr).jsonObject["access_token"]?.jsonPrimitive?.content
                                } else {
                                    lastErr = "token HTTP ${resp.code}: $bodyStr"
                                    null
                                }
                            }
                        }.getOrNull()

                        if (!token.isNullOrBlank()) return token
                    }
                }
            }

            throw IllegalStateException("FxA OAuth token exchange failed ($lastErr)")
        }

        /**
         * Mints the 10-minute Guardian ProxyPass JWT from `GET https://vpn.mozilla.org/api/v1/fpn/token`
         * using `User-Agent: MozillaVPN/2.35.0 (sys:linux; iap:true)` and auto-activating via
         * `POST https://vpn.mozilla.org/api/v1/fpn/activate` on HTTP 401/403.
         */
        private fun requestGuardianProxyPass(client: OkHttpClient, fxaAccessToken: String): String {
            val mediaJson = "application/json; charset=utf-8".toMediaType()
            val tokenUrl = "$GUARDIAN_API_BASE/api/v1/fpn/token"
            val activateUrl = "$GUARDIAN_API_BASE/api/v1/fpn/activate"

            var lastStatus = -1
            var lastBody = ""

            for (attempt in 1..2) {
                val req = Request.Builder()
                    .url(tokenUrl)
                    .header("Authorization", "Bearer $fxaAccessToken")
                    .header("User-Agent", MOZILLA_VPN_UA)
                    .header("Accept", "application/json")
                    .get()
                    .build()

                val jwt = runCatching {
                    client.newCall(req).execute().use { resp ->
                        lastStatus = resp.code
                        lastBody = resp.body?.string().orEmpty()
                        if (resp.isSuccessful) {
                            val obj = jsonParser.parseToJsonElement(lastBody).jsonObject
                            obj["token"]?.jsonPrimitive?.content
                                ?: obj["proxypass"]?.jsonPrimitive?.content
                                ?: obj["proxy_pass"]?.jsonPrimitive?.content
                        } else null
                    }
                }.getOrNull()

                if (!jwt.isNullOrBlank()) return jwt

                if ((lastStatus == 401 || lastStatus == 403) && attempt == 1) {
                    LogRepository.i("[FirefoxVpn] Guardian returned HTTP $lastStatus; activating Firefox VPN entitlement via POST /api/v1/fpn/activate...", "FirefoxVpn")
                    val actReq = Request.Builder()
                        .url(activateUrl)
                        .header("Authorization", "Bearer $fxaAccessToken")
                        .header("User-Agent", MOZILLA_VPN_UA)
                        .header("Accept", "application/json")
                        .post("{}".toRequestBody(mediaJson))
                        .build()
                    runCatching { client.newCall(actReq).execute().close() }
                    continue
                }
                break
            }

            throw IllegalStateException("Guardian /api/v1/fpn/token rejected request (HTTP $lastStatus: ${lastBody.take(120)})")
        }

        private class Socks5RemoteDnsSocket(
            private val socksHost: String,
            private val socksPort: Int
        ) : Socket() {
            override fun connect(endpoint: java.net.SocketAddress?, timeout: Int) {
                val inetEp = endpoint as? InetSocketAddress
                    ?: throw java.io.IOException("Invalid endpoint: $endpoint")
                val targetHost = inetEp.hostString.ifBlank { inetEp.hostName }
                val targetPort = inetEp.port
                val effectiveTimeout = if (timeout > 0) timeout else 12_000

                super.connect(InetSocketAddress(socksHost, socksPort), effectiveTimeout)
                soTimeout = effectiveTimeout
                tcpNoDelay = true

                val ins = DataInputStream(getInputStream())
                val out = getOutputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                if (ins.read() != 0x05 || ins.read() != 0x00) {
                    close()
                    throw java.io.IOException("SOCKS5 greeting rejected by $socksHost:$socksPort")
                }

                val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
                val req = ByteArray(7 + hostBytes.size)
                req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03 // ATYP = 0x03 (Domain Name)
                req[4] = hostBytes.size.toByte()
                System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
                req[5 + hostBytes.size] = ((targetPort ushr 8) and 0xFF).toByte()
                req[6 + hostBytes.size] = (targetPort and 0xFF).toByte()
                out.write(req)
                out.flush()

                val rVer = ins.read()
                val rRep = ins.read()
                ins.read()
                val rAtyp = ins.read()
                if (rVer != 0x05 || rRep != 0x00) {
                    close()
                    throw java.io.IOException("SOCKS5 CONNECT to $targetHost:$targetPort failed (rep=$rRep)")
                }
                val skip = when (rAtyp) {
                    0x01 -> 6
                    0x04 -> 18
                    0x03 -> ins.readUnsignedByte() + 2
                    else -> 6
                }
                ins.readFully(ByteArray(skip))
            }
        }

        private class Socks5RemoteDnsSocketFactory(
            private val socksHost: String,
            private val socksPort: Int
        ) : javax.net.SocketFactory() {
            override fun createSocket(): Socket = Socks5RemoteDnsSocket(socksHost, socksPort)
            override fun createSocket(host: String, port: Int): Socket =
                Socks5RemoteDnsSocket(socksHost, socksPort).apply { connect(InetSocketAddress.createUnresolved(host, port), 12_000) }
            override fun createSocket(host: String, port: Int, localHost: InetAddress?, localPort: Int): Socket =
                createSocket(host, port)
            override fun createSocket(host: InetAddress, port: Int): Socket =
                Socks5RemoteDnsSocket(socksHost, socksPort).apply { connect(InetSocketAddress(host, port), 12_000) }
            override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
                createSocket(address, port)
        }

        private fun buildClient(socksHost: String, socksPort: Int, timeoutSec: Long): OkHttpClient {
            val builder = OkHttpClient.Builder()
                .connectTimeout(timeoutSec, TimeUnit.SECONDS)
                .readTimeout(timeoutSec, TimeUnit.SECONDS)
                .writeTimeout(timeoutSec, TimeUnit.SECONDS)

            val socksListening = runCatching {
                Socket().use { it.connect(InetSocketAddress(socksHost, socksPort), 300); true }
            }.getOrDefault(false)

            if (socksListening && socksPort > 0) {
                // CRITICAL FOR IRAN ISPs: Do NOT use Proxy.Type.SOCKS with OkHttp's default Dns.SYSTEM!
                // Dns.SYSTEM calls Android's local ISP DNS (before VPN TUN is established), which times out
                // or returns poisoned 10.10.34.35 for vpn.mozilla.org and accounts.firefox.com.
                // Instead, return a placeholder InetAddress preserving the hostname and dial via ATYP=0x03!
                builder.dns(object : okhttp3.Dns {
                    override fun lookup(hostname: String): List<InetAddress> {
                        return listOf(InetAddress.getByAddress(hostname, byteArrayOf(1, 1, 1, 1)))
                    }
                })
                builder.socketFactory(Socks5RemoteDnsSocketFactory(socksHost, socksPort))
            }
            return builder.build()
        }

        private fun deriveFxaAuthPw(email: String, password: String): String {
            // Official FxA quickStretchPW salt includes "PW"
            val salt = "identity.mozilla.com/picl/v1/quickStretchPW:$email".toByteArray(Charsets.UTF_8)
            val spec = PBEKeySpec(password.toCharArray(), salt, 1000, 256)
            val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val quickStretched = skf.generateSecret(spec).encoded

            val info = "identity.mozilla.com/picl/v1/authPW".toByteArray(Charsets.UTF_8)
            val prk = hmacSha256(ByteArray(32), quickStretched)
            val okm = hmacSha256(prk, info + byteArrayOf(0x01))
            return okm.joinToString("") { "%02x".format(it) }
        }

        private fun buildHawkHeader(
            method: String,
            host: String,
            port: Int,
            path: String,
            sessionTokenHex: String,
            contentType: String = "application/json",
            body: String? = null
        ): String {
            val tokenBytes = sessionTokenHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val prk = hmacSha256(ByteArray(32), tokenBytes)
            val info = "identity.mozilla.com/picl/v1/sessionToken".toByteArray(Charsets.UTF_8)
            val t1 = hmacSha256(prk, info + byteArrayOf(0x01))
            val t2 = hmacSha256(prk, t1 + info + byteArrayOf(0x02))
            val derived = t1 + t2

            val tokenIdHex = derived.sliceArray(0 until 32).joinToString("") { "%02x".format(it) }
            val reqHmacKey = derived.sliceArray(32 until 64)

            val ts = System.currentTimeMillis() / 1000L
            val nonce = UUID.randomUUID().toString().replace("-", "").take(12)

            val payloadHash = if (!body.isNullOrEmpty()) {
                val payloadNorm = "hawk.1.payload\n${contentType.lowercase()}\n$body\n"
                val digest = MessageDigest.getInstance("SHA-256").digest(payloadNorm.toByteArray(Charsets.UTF_8))
                Base64.getEncoder().encodeToString(digest)
            } else ""

            val normalized = "hawk.1.header\n$ts\n$nonce\n${method.uppercase()}\n$path\n${host.lowercase()}\n$port\n$payloadHash\n\n"
            val macBytes = hmacSha256(reqHmacKey, normalized.toByteArray(Charsets.UTF_8))
            val macB64 = Base64.getEncoder().encodeToString(macBytes)

            return if (payloadHash.isNotEmpty()) {
                """Hawk id="$tokenIdHex", ts="$ts", nonce="$nonce", hash="$payloadHash", mac="$macB64""""
            } else {
                """Hawk id="$tokenIdHex", ts="$ts", nonce="$nonce", mac="$macB64""""
            }
        }

        private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            return mac.doFinal(data)
        }

        private fun isJwtFresh(jwt: String, minRemainingSec: Long): Boolean {
            val parts = jwt.trim().split(".")
            if (parts.size != 3) return false
            return try {
                val payloadJson = String(Base64.getUrlDecoder().decode(parts[1]), Charsets.UTF_8)
                val exp = Regex(""""exp"\s*:\s*(\d+)""").find(payloadJson)?.groupValues?.get(1)?.toLongOrNull()
                    ?: return true
                val nowSec = System.currentTimeMillis() / 1000L
                exp - nowSec > minRemainingSec
            } catch (_: Exception) {
                false
            }
        }

        private fun encodeConnectHeaders(authority: String, proxyPass: String, userAgent: String): ByteArray {
            val out = ByteArrayOutputStream(256)
            writeHpackLiteralHeader(out, ":method", "CONNECT")
            writeHpackLiteralHeader(out, ":authority", authority)
            writeHpackLiteralHeader(out, "proxy-authorization", "ProxyPass $proxyPass")
            writeHpackLiteralHeader(out, "user-agent", userAgent)
            return out.toByteArray()
        }

        private fun writeHpackLiteralHeader(out: ByteArrayOutputStream, name: String, value: String) {
            out.write(0x10)
            val nameBytes = name.lowercase().toByteArray(Charsets.US_ASCII)
            writeHpackInt(out, nameBytes.size, 7, 0x00)
            out.write(nameBytes)
            val valBytes = value.toByteArray(Charsets.US_ASCII)
            writeHpackInt(out, valBytes.size, 7, 0x00)
            out.write(valBytes)
        }

        private fun writeHpackInt(out: ByteArrayOutputStream, value: Int, prefixBits: Int, flagsMask: Int) {
            val maxPrefix = (1 shl prefixBits) - 1
            if (value < maxPrefix) {
                out.write(flagsMask or value)
            } else {
                out.write(flagsMask or maxPrefix)
                var rem = value - maxPrefix
                while (rem >= 128) {
                    out.write((rem and 0x7F) or 0x80)
                    rem = rem ushr 7
                }
                out.write(rem)
            }
        }

        private fun decodeH2Status(buf: ByteArray, offset: Int, len: Int): Int {
            if (len <= 0 || offset >= buf.size) return -1
            val end = minOf(buf.size, offset + len)
            var pos = offset
            // Skip any leading HPACK Dynamic Table Size Update instructions (001xxxxx, RFC 7541 Section 6.3)
            while (pos < end && (buf[pos].toInt() and 0xE0) == 0x20) {
                val prefix = buf[pos].toInt() and 0x1F
                pos++
                if (prefix == 0x1F) {
                    while (pos < end && (buf[pos].toInt() and 0x80) != 0) pos++
                    if (pos < end) pos++
                }
            }
            if (pos >= end) pos = offset
            val b0 = buf[pos].toInt() and 0xFF
            when (b0) {
                0x88 -> return 200
                0x89 -> return 204
                0x8a -> return 206
                0x8b -> return 304
                0x8c -> return 400
                0x8d -> return 404
                0x8e -> return 500
            }
            // Also scan the first 8 bytes after pos in case another indexed pseudo-header preceded :status
            for (scan in pos until minOf(end, pos + 8)) {
                when (buf[scan].toInt() and 0xFF) {
                    0x88 -> return 200
                    0x8c -> return 400
                    0x8d -> return 404
                    0x8e -> return 500
                }
            }
            val idx = when {
                (b0 and 0xC0) == 0x40 -> b0 and 0x3F
                (b0 and 0xF0) == 0x00 || (b0 and 0xF0) == 0x10 -> b0 and 0x0F
                else -> 0
            }
            if (idx in 8..14 && offset + 1 < buf.size) {
                val lenByte = buf[offset + 1].toInt() and 0xFF
                val isHuffman = (lenByte and 0x80) != 0
                val strLen = lenByte and 0x7F
                if (!isHuffman && strLen == 3 && offset + 5 <= buf.size) {
                    val s = String(buf, offset + 2, 3, Charsets.US_ASCII)
                    s.toIntOrNull()?.let { return it }
                } else if (isHuffman && strLen >= 2 && offset + 2 + strLen <= buf.size) {
                    val h0 = buf[offset + 2].toInt() and 0xFF
                    if (h0 == 0x64) return 200
                }
            }
            val ascii = String(buf, offset, minOf(len, buf.size - offset), Charsets.ISO_8859_1)
            Regex("""\b([2-5]\d{2})\b""").find(ascii)?.groupValues?.get(1)?.toIntOrNull()?.let { return it }
            return if (b0 == 0x88) 200 else 502
        }

        private fun dialViaSocks5(
            socksHost: String,
            socksPort: Int,
            targetHost: String,
            targetPort: Int,
            timeoutMs: Int
        ): Socket? {
            val sock = Socket()
            return try {
                sock.connect(InetSocketAddress(socksHost, socksPort), timeoutMs)
                sock.soTimeout = timeoutMs
                val ins = DataInputStream(sock.getInputStream())
                val out = sock.getOutputStream()

                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                if (ins.read() != 0x05 || ins.read() != 0x00) {
                    sock.close()
                    return null
                }

                val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
                val req = ByteArray(7 + hostBytes.size)
                req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03
                req[4] = hostBytes.size.toByte()
                System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
                req[5 + hostBytes.size] = ((targetPort ushr 8) and 0xFF).toByte()
                req[6 + hostBytes.size] = (targetPort and 0xFF).toByte()
                out.write(req)
                out.flush()

                val rVer = ins.read()
                val rRep = ins.read()
                ins.read()
                val rAtyp = ins.read()
                if (rVer != 0x05 || rRep != 0x00) {
                    sock.close()
                    return null
                }
                val skip = when (rAtyp) {
                    0x01 -> 6
                    0x04 -> 18
                    0x03 -> ins.readUnsignedByte() + 2
                    else -> 6
                }
                ins.readFully(ByteArray(skip))
                sock
            } catch (_: Exception) {
                runCatching { sock.close() }
                null
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
    }
}
