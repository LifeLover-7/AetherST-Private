package io.github.immaghzbad.aetherst.shared.core

import io.github.immaghzbad.aetherst.shared.data.AetherConfigRepository
import io.github.immaghzbad.aetherst.shared.data.ActiveProxyProvider
import io.github.immaghzbad.aetherst.shared.data.IpInfoRepository
import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.model.*
import io.github.immaghzbad.aetherst.core.CloakController
import io.github.immaghzbad.aetherst.core.PsiphonController
import io.github.immaghzbad.aetherst.platform.PlatformContext
import io.github.immaghzbad.aetherst.platform.getSettings
import io.github.immaghzbad.aetherst.platform.getTrafficProvider
import io.github.immaghzbad.aetherst.platform.getSystemUtils
import io.github.immaghzbad.aetherst.shared.platform.Bridge
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.time.Duration.Companion.milliseconds

actual object ConnectionController {
    private val _isWaitingForCode = MutableStateFlow(false)
    actual val isWaitingForCode: StateFlow<Boolean> = _isWaitingForCode.asStateFlow()

    private val _status = MutableStateFlow(ConnectionStatus.STOPPED)
    actual val status: StateFlow<ConnectionStatus> = _status.asStateFlow()

    private val _elapsedSeconds = MutableStateFlow(0L)
    actual val elapsedSeconds: StateFlow<Long> = _elapsedSeconds.asStateFlow()

    private val _sessionTraffic = MutableStateFlow(SessionTraffic())
    actual val sessionTraffic: StateFlow<SessionTraffic> = _sessionTraffic.asStateFlow()

    actual fun markStatus(status: ConnectionStatus) {
        _status.value = status
    }

    @Volatile
    private var INSTANCE: ControllerImpl? = null

    actual fun getInstance(context: PlatformContext) {
        if (INSTANCE == null) {
            synchronized(this) {
                if (INSTANCE == null) INSTANCE = ControllerImpl(context)
            }
        }
    }

    fun submitLoginCode(code: String) {
        _isWaitingForCode.value = false
        INSTANCE?.submitLoginCode(code)
    }

    fun getImpl(context: PlatformContext): ControllerImpl {
        getInstance(context)
        return INSTANCE!!
    }

    class ControllerImpl(private val context: PlatformContext) {
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        private val actionMutex = Mutex()
        private val runner = AetherProcessRunner(context)
        private val trafficProvider = getTrafficProvider(context)
        private val loginCodeChannel = Channel<String>(Channel.UNLIMITED)

        private var connectJob: Job? = null
        private var timerJob: Job? = null
        private var baseTx = 0L
        private var baseRx = 0L
        private var prevTx = 0L
        private var prevRx = 0L

        @Volatile private var tunnelModeStarted = false
        @Volatile private var activeTargetPort = 2021
        @Volatile private var isPsiphonActive = false
        @Volatile private var isUserInitiatedStop = false
        @Volatile private var wgExitTunnel: io.github.immaghzbad.aetherst.shared.net.WireGuardExitTunnel? = null
        @Volatile private var customSocksRelay: io.github.immaghzbad.aetherst.shared.net.CustomSocks5Relay? = null
        @Volatile private var firefoxVpnTunnel: io.github.immaghzbad.aetherst.shared.net.FirefoxVpnExitTunnel? = null
        private var statusJob: Job? = null
        private var watchdogJob: Job? = null
        private var reconnectJob: Job? = null

        private val neighborCountries = setOf("TR", "AZ", "AM", "GE", "AE", "OM", "IQ", "BH", "KW", "QA")

        init {
            scope.launch {
                Bridge.statusOverride.collect { s ->
                    if (s != null) {
                        _status.value = s
                        if (s == ConnectionStatus.STOPPED || s == ConnectionStatus.ERROR) {
                            stopTimer()
                        }
                    }
                }
            }
            scope.launch {
                Bridge.trafficOverride.collect { if (it != null) _sessionTraffic.value = it }
            }
            scope.launch {
                Bridge.elapsedOverride.collect { if (it != null) _elapsedSeconds.value = it }
            }
        }

        fun start() {
            scope.launch {
                actionMutex.withLock {
                    if (connectJob?.isActive == true ||
                        _status.value == ConnectionStatus.RUNNING ||
                        _status.value == ConnectionStatus.VALIDATING
                    ) return@withLock

                    isUserInitiatedStop = false
                    watchdogJob?.cancel()
                    watchdogJob = null
                    reconnectJob?.cancel()
                    reconnectJob = null
                    doStop()
                    _status.value = ConnectionStatus.STARTING

                    connectJob = scope.launch {
                        try {
                            doStart()
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Throwable) {
                            LogRepository.e("[Controller] Connection error: ${e.message}")
                            doStop()
                            _status.value = ConnectionStatus.ERROR
                        }
                    }
                }
            }
        }

        private suspend fun doStart() {
            LogRepository.i("[Controller] Initializing connection process...", "AetherSystem")
if (!canReachGatewayOrInternet()) {
                throw IllegalStateException("No internet connection detected")
            }
            val config = AetherConfigRepository.getInstance(getSettings(context)).config.value.effectiveZeroTrustConfig()
            var effectiveConfig = config

            // تنظیم بهینه GOOL مطابق معماری مدرن Aether v2.4.0 (تونل WireGuard داخل MASQUE)
            if (effectiveConfig.protocol == AetherProtocol.GOOL) {
                effectiveConfig = effectiveConfig.copy(
                    ipMode = if (effectiveConfig.ipMode == AetherIpMode.AUTO) AetherIpMode.IPV4 else effectiveConfig.ipMode,
                    noise = if (effectiveConfig.noise == AetherNoise.OFF) AetherNoise.BALANCED else effectiveConfig.noise,
                    h2Mode = true,
                    h2Fragment = true,
                    fragmentSize = effectiveConfig.fragmentSize.ifBlank { "30-60" },
                    fragmentDelay = effectiveConfig.fragmentDelay.ifBlank { "5-15" },
                    masqueSni = effectiveConfig.masqueSni.ifBlank { "consumer-masque.cloudflareclient.com" },
                    mtu = effectiveConfig.mtu.coerceIn(1120, 1280),
                    validateSecs = effectiveConfig.validateSecs.coerceAtLeast(15)
                )
            } else if (effectiveConfig.protocol == AetherProtocol.MASQUE || effectiveConfig.protocol == AetherProtocol.MIM) {
                if (effectiveConfig.masqueSni.isBlank()) {
                    effectiveConfig = effectiveConfig.copy(masqueSni = "consumer-masque.cloudflareclient.com")
                }
            } else if (CloakController.isSupported(effectiveConfig)) {
                val started = runCatching { CloakController.start(context, effectiveConfig) }.getOrDefault(false)
                if (started && CloakController.isRunning()) {
                    effectiveConfig = effectiveConfig.copy(peer = CloakController.getEffectivePeer(effectiveConfig))
                    LogRepository.i("[Controller] Cloak active, routing via ${effectiveConfig.peer}", "Cloak")
                }
            }

            baseTx = getWintunBytes().first
            baseRx = getWintunBytes().second

            val coreSocksPort = effectiveConfig.socksPort.toIntOrNull() ?: 2021
            val configuredHttpPort = effectiveConfig.httpPort.toIntOrNull() ?: 2020
            val actualHttpPort = if (configuredHttpPort == coreSocksPort) coreSocksPort + 1 else configuredHttpPort

            val needsExitNode = effectiveConfig.exitNodeMode != ExitNodeMode.DIRECT

            statusJob?.cancel()
            statusJob = scope.launch {
                runner.connectionStatus.collect { s ->
                    if (!isUserInitiatedStop) {
                        if (s == ConnectionStatus.ERROR || s == ConnectionStatus.FAILED) {
                            if (_status.value == ConnectionStatus.RUNNING && effectiveConfig.smartReconnect) {
                                LogRepository.w("[Controller] Runner reported $s during active session. Holding network and starting auto-reconnect...", "Watchdog")
                                triggerPersistentReconnect(effectiveConfig, coreSocksPort, actualHttpPort)
                                return@collect
                            }
                        }
                        if (_status.value != ConnectionStatus.STOPPED && s != ConnectionStatus.STOPPED) {
                            if (s == ConnectionStatus.RUNNING || s == ConnectionStatus.SOCKS_READY || s == ConnectionStatus.DATAPLANE_VALIDATED) {
                                // Only promote to RUNNING directly if no secondary ExitNode is pending
                                if (!needsExitNode || activeTargetPort != coreSocksPort) {
                                    _status.value = ConnectionStatus.RUNNING
                                }
                            } else if (_status.value != ConnectionStatus.RECONNECTING) {
                                _status.value = s
                            }
                        }
                    }
                }
            }

            val maxGoolRerolls = if (effectiveConfig.protocol == AetherProtocol.GOOL && effectiveConfig.goolNeighborEgress) 3 else 1
            var coreReady = false

            for (reroll in 1..maxGoolRerolls) {
                if (reroll > 1) {
                    LogRepository.i("[GOOL] Exit country was not a neighboring region; re-rolling endpoint ($reroll/$maxGoolRerolls)...", "GOOL")
                    runner.stop()
                    delay(600.milliseconds)
                    _status.value = ConnectionStatus.STARTING
                }

                runner.start(
                    config = effectiveConfig.copy(httpProxyEnabled = true, httpPort = actualHttpPort.toString()),
                    bindAddress = "127.0.0.1:$coreSocksPort",
                    onCodeRequired = { _isWaitingForCode.value = true },
                    inputProvider = { loginCodeChannel.receive() }
                )

                coreReady = false
                val maxWaitLoops = if (effectiveConfig.protocol == AetherProtocol.GOOL) 150 else 120
                for (i in 0..maxWaitLoops) {
                    currentCoroutineContext().ensureActive()
                    val currentRunnerStatus = runner.connectionStatus.value
                    val portOpen = probePort("127.0.0.1", coreSocksPort)
                    if (currentRunnerStatus == ConnectionStatus.RUNNING ||
                        currentRunnerStatus == ConnectionStatus.DATAPLANE_VALIDATED ||
                        currentRunnerStatus == ConnectionStatus.SOCKS_READY ||
                        (i > 35 && portOpen)
                    ) {
                        coreReady = true
                        break
                    }
                    if (i > 10 && currentRunnerStatus == ConnectionStatus.ERROR) {
                        break
                    }
                    delay(300.milliseconds)
                }

                if (!coreReady) break

                // Do not kill validated GOOL connections when Cloudflare WARP tags its FRA/GYD egress pool as IR
                break
                break
            }

            if (!coreReady) {
                LogRepository.e("[Controller] Core connection timed out")
                doStop()
                _status.value = ConnectionStatus.ERROR
                return
            }

            var effectiveTargetPort = coreSocksPort
            isPsiphonActive = false

            if (effectiveConfig.exitNodeMode == ExitNodeMode.PSIPHON_POOL && PsiphonController.isSupported(effectiveConfig)) {
                _status.value = ConnectionStatus.VALIDATING
                val upstreamUrl = "http://127.0.0.1:$actualHttpPort"
                LogRepository.i("[Controller] Chaining Psiphon over HTTP proxy $upstreamUrl", "Psiphon")

                val psiphonStarted = PsiphonController.start(
                    context = context,
                    config = effectiveConfig,
                    upstream = upstreamUrl
                )

                if (psiphonStarted) {
                    var psiphonReady = false
                    for (i in 0..30) {
                        currentCoroutineContext().ensureActive()
                        if (PsiphonController.isConnected()) {
                            psiphonReady = true
                            break
                        }
                        delay(1000.milliseconds)
                    }

                    if (psiphonReady) {
                        effectiveTargetPort = PsiphonController.getPort()
                        isPsiphonActive = true
                        ActiveProxyProvider.psiphonProxyUrl = PsiphonController.getUpstreamProxy()
                        LogRepository.i("[Controller] Psiphon Chain ready! Port: $effectiveTargetPort", "Psiphon")
                    } else {
                        throw IllegalStateException("Psiphon exit node connection timed out (30s)")
                    }
                } else {
                    throw IllegalStateException("Psiphon exit node failed to launch")
                }
            } else if (effectiveConfig.exitNodeMode == ExitNodeMode.CUSTOM_WG) {
                _status.value = ConnectionStatus.VALIDATING
                val targetWgCfg = if (effectiveConfig.customWgAutoSelect && effectiveConfig.customWgProfiles.isNotEmpty()) {
                    io.github.immaghzbad.aetherst.shared.net.WireGuardExitTunnel.selectFastestProfile(
                        effectiveConfig.customWgProfiles,
                        effectiveConfig.customWgConfig
                    )
                } else {
                    effectiveConfig.customWgConfig
                }
                if (targetWgCfg.isValid()) {
                    val binaryPath = runCatching {
                        io.github.immaghzbad.aetherst.shared.core.getBinaryManager(context).prepareBinary("sing-box")
                    }.getOrNull()
                    val workDir = getSystemUtils(context).getFilesDir()
                    java.io.File(workDir).mkdirs()
                    val tunnel = io.github.immaghzbad.aetherst.shared.net.WireGuardExitTunnel(
                        config = targetWgCfg,
                        binaryPath = binaryPath,
                        workingDir = workDir,
                        primarySocksHost = "127.0.0.1",
                        primarySocksPort = coreSocksPort,
                        localListenPort = 10805
                    )
                    val started = runCatching { tunnel.start() }.getOrDefault(false)
                    if (started) {
                        wgExitTunnel = tunnel
                        effectiveTargetPort = 10805
                        ActiveProxyProvider.customWgPort = 10805
                        LogRepository.i("[Controller] Custom WireGuard Exit ready on port 10805 (Exit IP: ${tunnel.verifiedExitIp ?: "Active"})", "WireGuard")
                    } else {
                        val err = tunnel.lastErrorMessage ?: "Proton WireGuard handshake or data-plane verification failed"
                        throw IllegalStateException(err)
                    }
                } else {
                    throw IllegalStateException("Custom WireGuard config is incomplete or missing")
                }
            } else if (effectiveConfig.exitNodeMode == ExitNodeMode.CUSTOM_SOCKS5 && effectiveConfig.customSocks5Host.isNotBlank()) {
                _status.value = ConnectionStatus.VALIDATING
                val relay = io.github.immaghzbad.aetherst.shared.net.CustomSocks5Relay(
                    listenPort = 10806,
                    primarySocksHost = "127.0.0.1",
                    primarySocksPort = coreSocksPort,
                    remoteHost = effectiveConfig.customSocks5Host.trim(),
                    remotePort = effectiveConfig.customSocks5Port,
                    username = effectiveConfig.customSocks5Username,
                    password = effectiveConfig.customSocks5Password
                )
                val started = runCatching { relay.start() }.getOrDefault(false)
                if (started) {
                    customSocksRelay = relay
                    effectiveTargetPort = 10806
                    LogRepository.i("[Controller] Custom SOCKS5 Exit ready on port 10806", "SOCKS5")
                } else {
                    throw IllegalStateException("Custom SOCKS5 relay failed to connect")
                }
            } else if (effectiveConfig.exitNodeMode == ExitNodeMode.FIREFOX_VPN) {
                _status.value = ConnectionStatus.VALIDATING
                val binaryPath = runCatching {
                    io.github.immaghzbad.aetherst.shared.core.getBinaryManager(context).prepareBinary("sing-box")
                }.getOrNull()
                val workDir = getSystemUtils(context).getFilesDir()
                java.io.File(workDir).mkdirs()
                val tunnel = io.github.immaghzbad.aetherst.shared.net.FirefoxVpnExitTunnel(
                    token = effectiveConfig.firefoxVpnToken,
                    country = effectiveConfig.firefoxVpnCountry,
                    binaryPath = binaryPath,
                    workingDir = workDir,
                    primarySocksHost = "127.0.0.1",
                    primarySocksPort = coreSocksPort,
                    localListenPort = effectiveConfig.firefoxVpnPort
                )
                val started = runCatching { tunnel.start() }.getOrDefault(false)
                if (started) {
                    firefoxVpnTunnel = tunnel
                    effectiveTargetPort = effectiveConfig.firefoxVpnPort
                    ActiveProxyProvider.firefoxVpnPort = effectiveConfig.firefoxVpnPort
                    LogRepository.i("[Controller] Firefox VPN Exit ready on port ${effectiveConfig.firefoxVpnPort} (Exit IP: ${tunnel.verifiedExitIp ?: "Active"})", "FirefoxVpn")
                } else {
                    val err = tunnel.lastErrorMessage ?: "Firefox VPN authentication or data-plane failed"
                    throw IllegalStateException(err)
                }
            }

            currentCoroutineContext().ensureActive()
            activeTargetPort = effectiveTargetPort

            if (effectiveConfig.connectionMode == ConnectionMode.TUNNEL) {
                startTunnelMode(effectiveConfig, effectiveTargetPort)
            } else if (effectiveConfig.connectionMode == ConnectionMode.SYSTEM_PROXY) {
                when (effectiveConfig.exitNodeMode) {
                    ExitNodeMode.DIRECT -> {
                        getSystemUtils(context).setSystemProxy("127.0.0.1", httpPort = actualHttpPort, socksPort = coreSocksPort)
                    }
                    ExitNodeMode.PSIPHON_POOL -> {
                        val psiphonHttpPort = effectiveTargetPort + 1
                        getSystemUtils(context).setSystemProxy("127.0.0.1", httpPort = psiphonHttpPort, socksPort = effectiveTargetPort)
                    }
                    ExitNodeMode.CUSTOM_WG -> {
                        getSystemUtils(context).setSystemProxy("127.0.0.1", httpPort = 10804, socksPort = 10805)
                    }
                    ExitNodeMode.FIREFOX_VPN -> {
                        getSystemUtils(context).setSystemProxy("127.0.0.1", httpPort = effectiveTargetPort - 1, socksPort = effectiveTargetPort)
                    }
                    else -> {
                        getSystemUtils(context).setSystemProxy("127.0.0.1", httpPort = 0, socksPort = effectiveTargetPort)
                    }
                }
            }

            _status.value = ConnectionStatus.RUNNING
            startTimer()
            startWatchdog(effectiveConfig, coreSocksPort, actualHttpPort)
            if (effectiveConfig.exitNodeMode != ExitNodeMode.DIRECT) {
                scope.launch {
                    delay(400.milliseconds)
                    IpInfoRepository.fetchIpInfo("127.0.0.1", effectiveTargetPort, useProxy = true, provider = effectiveConfig.ipInfoProvider)
                }
            }
        }

        private fun startWatchdog(effectiveConfig: AetherConfig, coreSocksPort: Int, actualHttpPort: Int) {
            watchdogJob?.cancel()
            watchdogJob = scope.launch {
                var consecutiveFailures = 0
                while (isActive && !isUserInitiatedStop) {
                    delay(5000.milliseconds)
                    if (_status.value == ConnectionStatus.RUNNING && !isUserInitiatedStop) {
                        val portOk = probePort("127.0.0.1", coreSocksPort)
                        if (!portOk) {
                            consecutiveFailures++
                            LogRepository.w("[Controller] Core port $coreSocksPort probe failed ($consecutiveFailures/3)", "Watchdog")
                            if (consecutiveFailures >= 3) {
                                if (effectiveConfig.smartReconnect && !isUserInitiatedStop) {
                                    LogRepository.w("[Controller] Core port $coreSocksPort probe failed 3 consecutive times. Holding TUN interface...", "Watchdog")
                                    triggerPersistentReconnect(effectiveConfig, coreSocksPort, actualHttpPort)
                                }
                            }
                        } else {
                            consecutiveFailures = 0
                        }
                    } else {
                        consecutiveFailures = 0
                    }
                }
            }
        }

        private fun triggerPersistentReconnect(effectiveConfig: AetherConfig, coreSocksPort: Int, actualHttpPort: Int) {
            if (reconnectJob?.isActive == true || isUserInitiatedStop) return
            _status.value = ConnectionStatus.RECONNECTING
            LogRepository.i("[Controller] State -> RECONNECTING. Keeping Wintun interface & routes intact to prevent app disconnects.", "Watchdog")

            reconnectJob = scope.launch {
                var attempt = 0
                val maxAttempts = effectiveConfig.reconnectRetryLimit.coerceIn(5, 60)
                while (isActive && !isUserInitiatedStop && attempt < maxAttempts) {
                    attempt++
                    LogRepository.i("[Controller] Hold & Reconnect attempt $attempt of $maxAttempts...", "Watchdog")

                    try { wgExitTunnel?.stop() } catch (_: Throwable) {}
                    wgExitTunnel = null
                    try { firefoxVpnTunnel?.stop() } catch (_: Throwable) {}
                    firefoxVpnTunnel = null
                    try { customSocksRelay?.stop() } catch (_: Throwable) {}
                    customSocksRelay = null
                    try { runner.stop() } catch (_: Throwable) {}
                    delay(1500.milliseconds)

                    if (isUserInitiatedStop) break

                    val hasPhysicalRoute = canReachGatewayOrInternet()
                    if (!hasPhysicalRoute) {
                        LogRepository.i("[Controller] Physical internet / mobile hotspot link unavailable. Holding...", "Watchdog")
                        delay(2500.milliseconds)
                        continue
                    }

                    try {
                        runner.start(
                            config = effectiveConfig.copy(httpProxyEnabled = true, httpPort = actualHttpPort.toString()),
                            bindAddress = "127.0.0.1:$coreSocksPort",
                            onCodeRequired = { _isWaitingForCode.value = true },
                            inputProvider = { loginCodeChannel.receive() }
                        )

                        var ready = false
                        for (w in 0..40) {
                            if (isUserInitiatedStop) break
                            val rStatus = runner.connectionStatus.value
                            if (rStatus == ConnectionStatus.RUNNING ||
                                rStatus == ConnectionStatus.DATAPLANE_VALIDATED ||
                                rStatus == ConnectionStatus.SOCKS_READY ||
                                (w > 20 && probePort("127.0.0.1", coreSocksPort))
                            ) {
                                ready = true
                                break
                            }
                            delay(500.milliseconds)
                        }

                        if (ready) {
                            if (effectiveConfig.exitNodeMode == ExitNodeMode.CUSTOM_WG) {
                                val targetWgCfg = if (effectiveConfig.customWgAutoSelect && effectiveConfig.customWgProfiles.isNotEmpty()) {
                                    io.github.immaghzbad.aetherst.shared.net.WireGuardExitTunnel.selectFastestProfile(
                                        effectiveConfig.customWgProfiles,
                                        effectiveConfig.customWgConfig
                                    )
                                } else {
                                    effectiveConfig.customWgConfig
                                }
                                if (targetWgCfg.isValid()) {
                                    val binaryPath = runCatching {
                                        io.github.immaghzbad.aetherst.shared.core.getBinaryManager(context).prepareBinary("sing-box")
                                    }.getOrNull()
                                    val workDir = getSystemUtils(context).getFilesDir()
                                    java.io.File(workDir).mkdirs()
                                    val tunnel = io.github.immaghzbad.aetherst.shared.net.WireGuardExitTunnel(
                                        config = targetWgCfg,
                                        binaryPath = binaryPath,
                                        workingDir = workDir,
                                        primarySocksHost = "127.0.0.1",
                                        primarySocksPort = coreSocksPort,
                                        localListenPort = 10805
                                    )
                                    if (!tunnel.start()) {
                                        throw IllegalStateException(tunnel.lastErrorMessage ?: "Layer-2 WireGuard failed to reconnect")
                                    }
                                    wgExitTunnel = tunnel
                                    ActiveProxyProvider.customWgPort = 10805
                                }
                            } else if (effectiveConfig.exitNodeMode == ExitNodeMode.CUSTOM_SOCKS5) {
                                val relay = io.github.immaghzbad.aetherst.shared.net.CustomSocks5Relay(
                                    listenPort = 10806,
                                    primarySocksHost = "127.0.0.1",
                                    primarySocksPort = coreSocksPort,
                                    remoteHost = effectiveConfig.customSocks5Host.trim(),
                                    remotePort = effectiveConfig.customSocks5Port,
                                    username = effectiveConfig.customSocks5Username,
                                    password = effectiveConfig.customSocks5Password
                                )
                                if (!relay.start()) {
                                    throw IllegalStateException("Custom SOCKS5 relay failed to reconnect")
                                }
                                customSocksRelay = relay
                            } else if (effectiveConfig.exitNodeMode == ExitNodeMode.FIREFOX_VPN) {
                                val binaryPath = runCatching {
                                    io.github.immaghzbad.aetherst.shared.core.getBinaryManager(context).prepareBinary("sing-box")
                                }.getOrNull()
                                val workDir = getSystemUtils(context).getFilesDir()
                                java.io.File(workDir).mkdirs()
                                val tunnel = io.github.immaghzbad.aetherst.shared.net.FirefoxVpnExitTunnel(
                                    token = effectiveConfig.firefoxVpnToken,
                                    country = effectiveConfig.firefoxVpnCountry,
                                    binaryPath = binaryPath,
                                    workingDir = workDir,
                                    primarySocksHost = "127.0.0.1",
                                    primarySocksPort = coreSocksPort,
                                    localListenPort = effectiveConfig.firefoxVpnPort
                                )
                                if (!tunnel.start()) {
                                    throw IllegalStateException(tunnel.lastErrorMessage ?: "Firefox VPN failed to reconnect")
                                }
                                firefoxVpnTunnel = tunnel
                                ActiveProxyProvider.firefoxVpnPort = effectiveConfig.firefoxVpnPort
                            }

                            _status.value = ConnectionStatus.RUNNING
                            LogRepository.i("[Controller] Resilient reconnect SUCCESSFUL! Session restored without dropping application sockets.", "Watchdog")
                            return@launch
                        }
                    } catch (e: Exception) {
                        LogRepository.w("[Controller] Reconnect attempt failed: ${e.message}", "Watchdog")
                    }

                    delay(2000.milliseconds)
                }

                if (!isUserInitiatedStop && _status.value == ConnectionStatus.RECONNECTING) {
                    LogRepository.e("[Controller] Persistent reconnect exhausted after $maxAttempts attempts.", "Watchdog")
                    _status.value = ConnectionStatus.ERROR
                    doStop()
                }
            }
        }

        private suspend fun canReachGatewayOrInternet(): Boolean = withContext(Dispatchers.IO) {
            runCatching {
                Socket().use {
                    it.connect(InetSocketAddress("1.1.1.1", 53), 1500)
                    true
                }
            }.getOrElse {
                runCatching {
                    Socket().use {
                        it.connect(InetSocketAddress("8.8.8.8", 53), 1500)
                        true
                    }
                }.getOrDefault(false)
            }
        }

        private fun startTunnelMode(config: AetherConfig, targetPort: Int) {
            if (tunnelModeStarted) return
            tunnelModeStarted = true
            val maxSafeMtu = if (config.exitNodeMode == ExitNodeMode.CUSTOM_WG) 1120 else 1280
            val effectiveMtu = maxSafeMtu.coerceAtMost(config.mtu.coerceIn(576, 9000))
            val ipv4CidrRegex = Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$""")
            val directIps = if (config.bypassIran || config.routingRules.any { it.mode == RoutingMode.DIRECT }) {
                config.routingRules
                    .filter { it.mode == RoutingMode.DIRECT }
                    .map { it.pattern.removePrefix("ip:").trim() }
                    .filter { ipv4CidrRegex.matches(it) }
                    .distinct()
            } else {
                emptyList()
            }
            val udpMode = if (isPsiphonActive || config.exitNodeMode == ExitNodeMode.PSIPHON_POOL) "tcp" else "udp"
            TunHelper.start(
                socksTargetPort = targetPort,
                configuredMtu = effectiveMtu,
                bypassExes = config.excludedPackages,
                blockedExes = config.blockedPackages,
                tunnelAllApps = config.tunnelAllApps,
                directIps = directIps,
                udpMode = udpMode
            )
            LogRepository.i("[Controller] TUN helper started on port $targetPort, mtu=$effectiveMtu, bypass=${config.excludedPackages.size}, blocked=${config.blockedPackages.size}, directRoutes=${directIps.size}")
        }

        fun stop() {
            scope.launch {
                actionMutex.withLock {
                    isUserInitiatedStop = true
                    watchdogJob?.cancel()
                    watchdogJob = null
                    reconnectJob?.cancel()
                    reconnectJob = null

                    if (_status.value == ConnectionStatus.STOPPED && connectJob?.isActive != true) return@withLock
                    _status.value = ConnectionStatus.STOPPED
                    _isWaitingForCode.value = false
                    stopTimer()
                    connectJob?.cancelAndJoin()
                    connectJob = null
                    doStop()
                }
            }
        }

        private fun doStop() {
            LogRepository.i("[Controller] Stopping all components")
            watchdogJob?.cancel()
            watchdogJob = null
            reconnectJob?.cancel()
            reconnectJob = null
            statusJob?.cancel()
            statusJob = null

            try { PsiphonController.stop() } catch (_: Throwable) {}
            try { wgExitTunnel?.stop() } catch (_: Throwable) {}
            wgExitTunnel = null
            try { customSocksRelay?.stop() } catch (_: Throwable) {}
            customSocksRelay = null
            try { firefoxVpnTunnel?.stop() } catch (_: Throwable) {}
            firefoxVpnTunnel = null
            try { runner.stop() } catch (_: Throwable) {}
            try { CloakController.stop() } catch (_: Throwable) {}

            ActiveProxyProvider.psiphonProxyUrl = null
            ActiveProxyProvider.customWgPort = null
            ActiveProxyProvider.firefoxVpnPort = null
            isPsiphonActive = false

            try { getSystemUtils(context).clearSystemProxy() } catch (_: Throwable) {}
            tunnelModeStarted = false
            try { TunHelper.stop() } catch (_: Throwable) {}
        }

        private suspend fun probePort(host: String, port: Int): Boolean = withContext(Dispatchers.IO) {
            runCatching {
                Socket().use {
                    it.connect(InetSocketAddress(host, port), 1500)
                    true
                }
            }.getOrDefault(false)
        }

        private fun startTimer() {
            timerJob?.cancel()
            _elapsedSeconds.value = 0
            prevTx = 0L
            prevRx = 0L
            timerJob = scope.launch {
                var seconds = 0L
                while (isActive) {
                    delay(1000.milliseconds)
                    seconds++
                    _elapsedSeconds.value = seconds
                    updateTraffic()
                }
            }
        }

        private fun stopTimer() {
            timerJob?.cancel()
            _elapsedSeconds.value = 0L
            _sessionTraffic.value = SessionTraffic()
        }

        private fun getWintunBytes(): Pair<Long, Long> {
            return try {
                val proc = ProcessBuilder("netsh", "interface", "ipv4", "show", "subinterfaces", "AetherST")
                    .redirectErrorStream(true).start()
                val lines = proc.inputStream.bufferedReader().readLines()
                var rx = 0L
                var tx = 0L
                for (line in lines) {
                    if (line.contains("AetherST", ignoreCase = true)) {
                        val toks = line.trim().split(Regex("\\s+"))
                        if (toks.size >= 5) {
                            rx = toks[2].toLongOrNull() ?: 0L
                            tx = toks[3].toLongOrNull() ?: 0L
                            break
                        }
                    }
                }
                Pair(tx, rx)
            } catch (_: Exception) {
                Pair(trafficProvider.getTxBytes(), trafficProvider.getRxBytes())
            }
        }

        private fun updateTraffic() {
            val (currentTx, currentRx) = getWintunBytes()
            val totalTx = (currentTx - baseTx).coerceAtLeast(0L)
            val totalRx = (currentRx - baseRx).coerceAtLeast(0L)

            val uploadSpeed = (totalTx - prevTx).coerceAtLeast(0L).toDouble()
            val downloadSpeed = (totalRx - prevRx).coerceAtLeast(0L).toDouble()
            prevTx = totalTx
            prevRx = totalRx

            _sessionTraffic.value = SessionTraffic(
                uploadedBytes = totalTx,
                downloadedBytes = totalRx,
                uploadSpeedBps = uploadSpeed,
                downloadSpeedBps = downloadSpeed
            )
        }

        fun submitLoginCode(code: String) {
            _isWaitingForCode.value = false
            loginCodeChannel.trySend(code)
        }
    }
}
