package io.github.immaghzbad.aetherst.shared.core

import io.github.immaghzbad.aetherst.shared.data.IpInfoRepository
import io.github.immaghzbad.aetherst.shared.data.LogRepository
import io.github.immaghzbad.aetherst.shared.model.*
import io.github.immaghzbad.aetherst.platform.PlatformContext
import io.github.immaghzbad.aetherst.platform.getSystemUtils
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.atomic.AtomicLong
import kotlin.time.Duration.Companion.milliseconds

private val ExitDetailRegex = Regex("""(?i)\b(?:gool|warp-in-warp|masque-in-masque|masque|wireguard|wg|mim)\s+exit:\s*([0-9a-fA-F.:]+),\s*([A-Za-z]{2})(?:\s+via\s+([A-Za-z0-9]+))?""")
    private val SelectedWgEndpointRegex = Regex("""(?i)(?:selected|endpoint|gateway|validating|establishing|peer|using)[^\n]*?\b((?:162\.159|188\.114|198\.41)\.\d{1,3}\.\d{1,3}:\d{2,5})\b""")

class AetherProcessRunner(private val context: PlatformContext) {
    private val systemUtils = getSystemUtils(context)
    private var process: PlatformProcess? = null
    private var runnerJob: Job? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val currentAttemptId = AtomicLong(0)
    private var goolOuterValidated = false
    private var lastBindAddress: String = "127.0.0.1:2021"

    private val _connectionStatus = MutableStateFlow(ConnectionStatus.STOPPED)
    val connectionStatus: StateFlow<ConnectionStatus> = _connectionStatus.asStateFlow()

    fun start(config: AetherConfig, bindAddress: String, onCodeRequired: () -> Unit = {}, inputProvider: suspend () -> String = { "" }) {
        if (runnerJob?.isActive == true) return
        LogRepository.currentAppLogLevel = config.appLogLevel
        LogRepository.currentCoreLogLevel = config.coreLogLevel
        val attemptId = currentAttemptId.incrementAndGet()
        goolOuterValidated = false
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
                    LogRepository.i("Recovering connection (Retry $retryCount)...")
                    updateState(ConnectionStatus.RECONNECTING, attemptId)
                    delay(waitTime.milliseconds)
                } else {
                    LogRepository.i("Starting system core at $bindAddress")
                    lastBindAddress = bindAddress
                }
                try {
                    val success = runBinary(config, attemptId, bindAddress, onCodeRequired, inputProvider)
                    if (currentAttemptId.get() != attemptId) break
                    if (!success) {
                        LogRepository.e("Core execution failed or terminated unexpectedly.")
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    LogRepository.e("Execution cycle critical error: ${e.message}")
                }
                retryCount++
                if (connectionStatus.value == ConnectionStatus.RUNNING) {
                    retryCount = 1
                }
            }
        }
    }

    private suspend fun runBinary(config: AetherConfig, attemptId: Long, bindAddress: String, onCodeRequired: () -> Unit, inputProvider: suspend () -> String): Boolean = coroutineScope {
        val proc = PlatformProcess()
        try {
            val binaryPath = getBinaryManager(context).prepareBinary("aether")
            val command = mutableListOf(binaryPath, "--bind", bindAddress)

            // انتخاب صریح پروتکل مطابق راهنمای رسمی باینری aether.exe
            when (config.protocol) {
                AetherProtocol.MASQUE -> command.add("--masque")
                AetherProtocol.WG -> command.add("--wg")
                AetherProtocol.GOOL -> {} // Added below based on config.goolClassic
                AetherProtocol.MIM -> command.add("--mim")
                AetherProtocol.ZERO_TRUST -> {}
            }

            // تنظیم حالت اسکن و پروفایل Obfuscation (Noise)
            command.add("--scan")
            command.add(config.scanMode.rawValue)
            command.add("--noize")
            command.add(config.noise.rawValue)

            val httpBindHost = bindAddress.substringBefore(':')
            val actualHttpPort = config.httpPort.ifBlank { "2020" }
            if (config.httpProxyEnabled) {
                command.add("--http-proxy")
                command.add("$httpBindHost:$actualHttpPort")
            }

            val routingFile = writeRoutingFile(config)
            if (routingFile != null) {
                command.add("--routes")
                command.add(routingFile.absolutePath)
            }

            if (config.protocol == AetherProtocol.ZERO_TRUST) {
                if (config.teamName.isNotEmpty()) {
                    command.add("--team")
                    command.add(config.teamName)
                }
                when {
                    config.accessToken.isNotEmpty() -> {
                        command.add("--access-token")
                        command.add(config.accessToken)
                    }
                    config.accessId.isNotEmpty() || config.accessSecret.isNotEmpty() -> {
                        command.add("--access-id")
                        command.add(config.accessId)
                        command.add("--access-secret")
                        command.add(config.accessSecret)
                    }
                    config.accessEmail.isNotEmpty() -> {
                        command.add("--access-email")
                        command.add(config.accessEmail)
                    }
                }
                if (config.useGateway) command.add("--gateway")
            }

            val effectiveIp = config.effectiveIpMode()
            command.add(when (effectiveIp) {
                AetherIpMode.IPV4 -> "-4"
                AetherIpMode.IPV6 -> "-6"
                else -> "--dual"
            })

            val isMasqueBased = config.protocol == AetherProtocol.MASQUE || config.protocol == AetherProtocol.MIM || config.protocol == AetherProtocol.ZERO_TRUST || (config.protocol == AetherProtocol.GOOL && !config.goolClassic) || config.mimEnabled
            if (isMasqueBased) {
                when (config.effectiveHttpVersion()) {
                    MasqueHttpVersion.H2 -> {
                        command.add("--h2")
                    }
                    MasqueHttpVersion.H1 -> {
                        command.add("--no-h2")
                        command.add("--no-quic-v2")
                    }
                    MasqueHttpVersion.H3 -> {
                        // H3 uses native QUIC without --h2 flag
                    }
                    MasqueHttpVersion.AUTO -> {
                        if (config.h2Mode) command.add("--h2")
                    }
                }
                if (config.echEnabled) {
                    command.add("--ech")
                    command.add("auto")
                }
                if (config.h2Fragment) {
                    command.add("--fragment")
                    command.add("--fragment-size")
                    command.add(config.fragmentSize.ifBlank { "30-60" })
                    command.add("--fragment-delay")
                    command.add(config.fragmentDelay.ifBlank { "5-15" })
                }
                val effectiveSni = if (config.masqueSni.isNotBlank()) {
                    config.masqueSni.trim()
                } else if (config.protocol != AetherProtocol.ZERO_TRUST) {
                    "consumer-masque.cloudflareclient.com"
                } else {
                    ""
                }
                if (effectiveSni.isNotBlank()) {
                    command.add("--masque-sni")
                    command.add(effectiveSni)
                }
            }


            val mimActive = config.protocol == AetherProtocol.MIM || config.mimEnabled
            if (mimActive) {
                if (config.protocol != AetherProtocol.MIM) {
                    command.add("--mim")
                }
                if (config.mimOuter.isNotBlank()) {
                    command.add("--mim-outer")
                    command.add(config.mimOuter.trim())
                }
                if (config.mimInner.isNotBlank()) {
                    command.add("--mim-inner")
                    command.add(config.mimInner.trim())
                }
                if (config.mimScan) {
                    command.add("--mim-scan")
                }
            }

            if (config.noDataCheck) command.add("--no-data-check")
            if (config.quickReconnect) command.add("--quick-reconnect") else command.add("--no-quick-reconnect")

            val wiwOuter = if (config.protocol == AetherProtocol.GOOL) config.wiwOuter.trim().ifEmpty { config.peer.trim() } else ""
            val wiwInner = if (config.protocol == AetherProtocol.GOOL) config.wiwInner.trim().ifEmpty { config.wgPeer.trim() } else ""

            when (config.protocol) {
                AetherProtocol.GOOL -> {
                    if (config.goolClassic) {
                        command.add("--gool-classic")
                        if (wiwOuter.isNotEmpty()) {
                            command.add("--wiw-outer")
                            command.add(wiwOuter)
                        }
                        if (wiwInner.isNotEmpty()) {
                            command.add("--wiw-inner")
                            command.add(wiwInner)
                        }
                        if (config.wiwScan) {
                            command.add("--wiw-scan")
                        }
                    } else {
                        command.add("--gool")
                        if (wiwOuter.isNotEmpty()) {
                            command.add("--peer")
                            command.add(wiwOuter)
                        }
                        if (wiwInner.isNotEmpty()) {
                            command.add("--gool-peer")
                            command.add(wiwInner)
                        }
                    }
                }
                AetherProtocol.WG -> {
                    val wgPeer = config.wgPeer.trim().ifEmpty { config.peer.trim() }
                    if (wgPeer.isNotEmpty()) {
                        command.add("--peer")
                        command.add(wgPeer)
                    }
                }
                else -> {
                    val peer = config.peer.trim()
                    if (peer.isNotEmpty()) {
                        command.add("--peer")
                        command.add(peer)
                    }
                }
            }

            if (config.protocol == AetherProtocol.WG || config.protocol == AetherProtocol.GOOL) {
                command.add("--keepalive")
                command.add(if (config.keepaliveEnabled) config.keepalive.toString() else "0")
            }
            if (config.tlsGroups.isNotEmpty()) {
                command.add("--tls-groups")
                command.add(config.tlsGroups)
            }
            command.add("--validate-secs")
            command.add(config.validateSecs.toString())
            command.add("--reconnect-secs")
            command.add(config.reconnectSecs.toString())
            if (config.noProfileRetry) command.add("--no-profile-retry")
            if (config.dnsEnabled && config.dnsList.isNotEmpty()) {
                command.add("--dns")
                command.add(config.dnsList)
            }

            val logLevelArg = if (config.coreLogLevel == AetherLogLevel.DEBUG) "debug" else "info"
            command.add("--log-level")
            command.add(logLevelArg)

            val env = mutableMapOf<String, String>()
            env["AETHER_PROTOCOL"] = config.protocol.rawValue
            env["AETHER_NOIZE"] = config.noise.rawValue
            env["AETHER_SCAN"] = config.scanMode.rawValue
            env["AETHER_IP"] = config.effectiveIpMode().rawValue
            env["AETHER_SOCKS"] = bindAddress
            env["AETHER_LOG_LEVEL"] = logLevelArg
            env["AETHER_PERF_PROFILE"] = config.perfProfile.rawValue
            if (routingFile != null) {
                env["AETHER_ROUTES_FILE"] = routingFile.absolutePath
            }
            if (isMasqueBased) {
            when (config.effectiveHttpVersion()) {
                MasqueHttpVersion.H2 -> {
                    env["AETHER_MASQUE_HTTP2"] = "1"
                }
                MasqueHttpVersion.H1 -> {
                    env["AETHER_MASQUE_HTTP2"] = "0"
                    env["AETHER_QUIC_V2"] = "0"
                }
                MasqueHttpVersion.H3 -> {
                    env["AETHER_MASQUE_HTTP2"] = "0"
                    env["AETHER_QUIC_V2"] = "1"
                }
                MasqueHttpVersion.AUTO -> {
                    if (config.h2Mode) env["AETHER_MASQUE_HTTP2"] = "1"
                }
            }
            if (config.echEnabled) env["AETHER_ECH"] = "auto"
            if (config.h2Fragment) {
                env["AETHER_MASQUE_H2_FRAGMENT"] = "1"
                env["AETHER_MASQUE_H2_FRAGMENT_SIZE"] = config.fragmentSize.ifBlank { "30-60" }
                env["AETHER_MASQUE_H2_FRAGMENT_DELAY"] = config.fragmentDelay.ifBlank { "5-15" }
            }
            val effectiveSni = if (config.masqueSni.isNotBlank()) {
                config.masqueSni.trim()
            } else if (config.protocol != AetherProtocol.ZERO_TRUST) {
                "consumer-masque.cloudflareclient.com"
            } else {
                ""
            }
            if (effectiveSni.isNotBlank()) {
                env["AETHER_MASQUE_SNI"] = effectiveSni
            }
        }
            if (config.mimEnabled) {
                env["AETHER_MIM"] = "1"
                if (config.mimOuter.isNotBlank()) env["AETHER_MIM_OUTER_PEER"] = config.mimOuter.trim()
                if (config.mimInner.isNotBlank()) env["AETHER_MIM_INNER_PEER"] = config.mimInner.trim()
            }
            if (config.httpProxyEnabled) env["AETHER_HTTP_PROXY"] = "$httpBindHost:$actualHttpPort"
            if (config.noDataCheck) {
                env["AETHER_MASQUE_NO_DATA_CHECK"] = "1"
                env["AETHER_WG_NO_DATA_CHECK"] = "1"
            }
            env["AETHER_QUICK_RECONNECT"] = if (config.quickReconnect) "1" else "0"


            when (config.protocol) {
                AetherProtocol.GOOL -> {
                    if (config.goolClassic) {
                        env["AETHER_GOOL_MODE"] = "classic"
                        if (wiwOuter.isNotEmpty()) env["AETHER_WIW_OUTER_PEER"] = wiwOuter
                        if (wiwInner.isNotEmpty()) env["AETHER_WIW_INNER_PEER"] = wiwInner
                        if (config.wiwScan) env["AETHER_WIW_PEERS"] = "auto"
                    } else {
                        if (wiwOuter.isNotEmpty()) env["AETHER_PEER"] = wiwOuter
                        if (wiwInner.isNotEmpty()) env["AETHER_GOOL_PEER"] = wiwInner
                    }
                }
                AetherProtocol.WG -> {
                    val wgPeer = config.wgPeer.trim().ifEmpty { config.peer.trim() }
                    if (wgPeer.isNotEmpty()) {
                        env["AETHER_WG_PEER"] = wgPeer
                        env["AETHER_PEER"] = wgPeer
                    }
                }
                else -> {
                    if (config.peer.isNotEmpty()) env["AETHER_PEER"] = config.peer
                }
            }

            env["AETHER_WG_KEEPALIVE"] = if (config.keepaliveEnabled) config.keepalive.toString() else "0"
            env["AETHER_WG_ENDPOINT_COOLDOWN_SECS"] = config.wgEndpointCooldownSecs.toString()
            env["AETHER_MASQUE_VALIDATE_SECS"] = config.validateSecs.toString()
            env["AETHER_WG_VALIDATE_SECS"] = config.validateSecs.toString()
            env["AETHER_MASQUE_RECONNECT_SECS"] = config.reconnectSecs.toString()
            env["AETHER_WG_RECONNECT_SECS"] = config.reconnectSecs.toString()
            if (config.noProfileRetry) env["AETHER_WG_NO_PROFILE_RETRY"] = "1"
            if (config.tlsGroups.isNotEmpty()) env["AETHER_TLS_GROUPS"] = config.tlsGroups
            if (config.masqueMtu > 0) env["AETHER_MASQUE_MTU"] = config.masqueMtu.toString()
            if (config.netstackTcpRx > 0) env["AETHER_NETSTACK_TCP_RX"] = config.netstackTcpRx.toString()
            if (config.netstackTcpTx > 0) env["AETHER_NETSTACK_TCP_TX"] = config.netstackTcpTx.toString()
            if (config.protocol == AetherProtocol.ZERO_TRUST) {
                if (config.teamName.isNotEmpty()) env["AETHER_TEAM"] = config.teamName
                when {
                    config.accessToken.isNotEmpty() -> env["AETHER_ACCESS_TOKEN"] = config.accessToken
                    config.accessId.isNotEmpty() || config.accessSecret.isNotEmpty() -> {
                        env["AETHER_ACCESS_ID"] = config.accessId
                        env["AETHER_ACCESS_SECRET"] = config.accessSecret
                        env["AETHER_ACCESS_CLIENT_ID"] = config.accessId
                        env["AETHER_ACCESS_CLIENT_SECRET"] = config.accessSecret
                    }
                    config.accessEmail.isNotEmpty() -> env["AETHER_ACCESS_EMAIL"] = config.accessEmail
                }
                if (config.useGateway) env["AETHER_GATEWAY"] = "1"
            }
            if (config.dnsEnabled && config.dnsList.isNotEmpty()) env["AETHER_DNS"] = config.dnsList
            if (config.upstreamProxyEnabled && config.upstreamProxy.isNotEmpty()) env["AETHER_UPSTREAM"] = config.upstreamProxy
            env["AETHER_ROUTE_SNIFF"] = if (config.routeSniffing) "1" else "0"
            env["AETHER_ROUTE_SNIFF_MS"] = config.sniffingTimeoutMs.toString()
            env["AETHER_REPROVISION"] = if (config.reprovision) "1" else "0"

            prepareCustomWireGuardNativeChain(config, java.io.File(systemUtils.getFilesDir()), binaryPath, command, env)
            LogRepository.d("Executing: ${command.joinToString(" ")}")
            if (!proc.start(command, systemUtils.getFilesDir(), env)) {
                LogRepository.e("Failed to start process: $binaryPath")
                return@coroutineScope false
            }
            process = proc
            val inputJob = launch {
                while (isActive) {
                    val text = inputProvider()
                    if (text.isNotEmpty()) {
                        proc.writeLine(text)
                        LogRepository.d("Sent input to binary")
                    }
                }
            }
            while (isActive && currentAttemptId.get() == attemptId) {
                val line = proc.readLine() ?: break
                val effectiveProtocol = if (
                    config.exitNodeMode == ExitNodeMode.CUSTOM_WG &&
                    config.customWgConfig.isValid() &&
                    config.protocol in setOf(AetherProtocol.MASQUE, AetherProtocol.WG, AetherProtocol.GOOL)
                ) AetherProtocol.GOOL else config.protocol
                parseOutputLine(line, attemptId, effectiveProtocol, config.exitNodeMode, onCodeRequired)
            }
            inputJob.cancel()
            val exitCode = proc.waitFor()
            LogRepository.i("Core process terminated (Exit code: $exitCode)")
            exitCode == 0
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            if (currentAttemptId.get() == attemptId) {
                LogRepository.e("Binary execution runtime error: ${e.message}")
            }
            false
        } finally {
            proc.destroy()
        }
    }

    private fun parseOutputLine(line: String, attemptId: Long, protocol: AetherProtocol, exitNodeMode: ExitNodeMode, onCodeRequired: () -> Unit) {
        if (currentAttemptId.get() != attemptId) return
        val lower = line.lowercase()
        when {
            lower.contains(" error ") || lower.contains("[error]") || lower.startsWith("error:") -> LogRepository.e(line, "AetherCore")
            lower.contains(" warn ") || lower.contains("[warn]") -> LogRepository.w(line, "AetherCore")
            else -> LogRepository.i(line, "AetherCore")
        }

        ExitDetailRegex.find(line)?.let { match ->
            val ip = match.groupValues.getOrNull(1)?.trim() ?: ""
            val country = match.groupValues.getOrNull(2)?.trim()?.uppercase() ?: ""
            val colo = match.groupValues.getOrNull(3)?.trim() ?: ""
            if (ip.isNotEmpty() && country.length == 2 && exitNodeMode == ExitNodeMode.DIRECT) {
                IpInfoRepository.updateFromExitLine(ip, country, colo)
            }
        }

        if (protocol == AetherProtocol.ZERO_TRUST && isZeroTrustCodePrompt(lower)) {
            onCodeRequired()
            return
        }

        SelectedWgEndpointRegex.find(line)?.let { match ->
            val ep = match.groupValues.getOrNull(1)?.trim() ?: ""
            if (ep.isNotEmpty() && !ep.startsWith("127.") && !ep.startsWith("0.")) {
                runCatching { java.io.File(systemUtils.getFilesDir(), "aether-active-endpoint.txt").writeText(ep) }
            }
        }

        when {
            lower.contains("scanning") || lower.contains("hunting for") -> {
                goolOuterValidated = false
                updateState(ConnectionStatus.STARTING, attemptId)
            }
            lower.contains("validating") || lower.contains("establishing outer") || lower.contains("establishing inner") -> {
                if (lower.contains("establishing inner") || (lower.contains("inner endpoint") && lower.contains("tunneled through outer"))) {
                    goolOuterValidated = true
                }
                updateState(ConnectionStatus.VALIDATING, attemptId)
            }
            (protocol == AetherProtocol.MASQUE && (lower.contains("tunnel validated") || lower.contains("connect-ip status: 200") || (lower.contains("exit location") && lower.contains("accepted")) || (lower.contains("socks") && lower.contains("listening")))) ||
            (protocol == AetherProtocol.MIM && (lower.contains("masque-in-masque ready") || lower.contains("inner masque tunnel established") || lower.contains("masque-in-masque exit:") || lower.contains("mim ready") || lower.contains("mim exit:") || (lower.contains("exit location") && lower.contains("accepted")))) ||
            (protocol == AetherProtocol.ZERO_TRUST && (lower.contains("tunnel validated") || lower.contains("connect-ip status: 200") || lower.contains("handshake complete") || (lower.contains("socks") && lower.contains("listening")))) ||
            (protocol == AetherProtocol.WG && (lower.contains("wireguard tunnel validated") || lower.contains("handshake complete") || lower.contains("tunnel validated") || (lower.contains("socks") && lower.contains("listening")))) -> {
                updateState(ConnectionStatus.RUNNING, attemptId)
            }
            (protocol == AetherProtocol.GOOL || (exitNodeMode == ExitNodeMode.CUSTOM_WG && (protocol == AetherProtocol.WG || protocol == AetherProtocol.MASQUE))) -> {
                if (lower.contains("registering the gool") ||
                    (lower.contains("inner endpoint") && lower.contains("tunneled through outer")) ||
                    lower.contains("establishing inner warp tunnel") ||
                    lower.contains("connect-ip status: 200") ||
                    (lower.contains("tunnel validated") && !lower.contains("inner"))
                ) {
                    goolOuterValidated = true
                    updateState(ConnectionStatus.VALIDATING, attemptId)
                }
                if ((lower.contains("inner") && (lower.contains("tunnel validated") || lower.contains("handshake complete"))) ||
                    (goolOuterValidated && !lower.contains("[outer]") && (lower.contains("wireguard tunnel validated") || lower.contains("[wg] handshake done") || lower.contains("[wg] handshake success") || lower.contains("could not read the exit of"))) ||
                    lower.contains("gool ready") ||
                    lower.contains("gool tunnel validated") ||
                    lower.contains("wiw tunnel validated") ||
                    lower.contains("warp-in-warp tunnel validated") ||
                    lower.contains("gool exit:") ||
                    lower.contains("warp-in-warp exit:") ||
                    (goolOuterValidated && lower.contains("serving socks5") && !lower.contains("[outer]")) ||
                    (lower.contains("socks") && lower.contains("listening") && lower.contains("1819")) ||
                    (lower.contains("socks") && lower.contains("listening") && lower.contains("2021")) ||
                    (lower.contains("exit location") && lower.contains("accepted"))
                ) {
                    updateState(ConnectionStatus.RUNNING, attemptId)
                }
            }
            (_connectionStatus.value == ConnectionStatus.RUNNING && (
                lower.contains("reconnecting to") || lower.contains("connection lost, reconnecting") || lower.contains("tunnel lost") || lower.contains("tunnel ended") ||
                lower.contains("wireguard tunnel exited") || lower.contains("masque tunnel ended") || lower.contains("tunnel exited")
            )) || lower.contains("all gateways failed") -> {
                goolOuterValidated = false
                updateState(ConnectionStatus.RECONNECTING, attemptId)
            }
        }
    }

    private fun isZeroTrustCodePrompt(line: String): Boolean {
        return line.contains("code") && (
            line.contains("enter") || line.contains("login") || line.contains("verif") ||
            line.contains("confirm") || line.contains("otp") || line.contains("one-time") ||
            line.contains("type the") || line.contains("paste") || line.contains("prompt")
        )
    }

    private fun updateState(state: ConnectionStatus, attemptId: Long) {
        if (currentAttemptId.get() == attemptId) _connectionStatus.value = state
    }

    private fun writeRoutingFile(config: AetherConfig): java.io.File? {
        val block = config.routingRules.filter { it.mode == RoutingMode.BLOCK }
        val direct = config.routingRules.filter { it.mode == RoutingMode.DIRECT }

        if (block.isEmpty() && direct.isEmpty()) return null

        return try {
            val file = java.io.File(systemUtils.getFilesDir(), "routing.ast")
            val content = StringBuilder()

            if (block.isNotEmpty()) {
                content.append("[block]\n")
                block.forEach { content.append(formatRoutingPattern(it.pattern)).append("\n") }
                content.append("\n")
            }

            if (direct.isNotEmpty()) {
                content.append("[direct]\n")
                direct.forEach { content.append(formatRoutingPattern(it.pattern)).append("\n") }
                content.append("\n")
            }

            file.writeText(content.toString())
            LogRepository.i("Routing file generated with ${block.size} blocked and ${direct.size} direct rules.")
            file
        } catch (e: Exception) {
            LogRepository.e("Failed to write routing file: ${e.message}")
            null
        }
    }

    private fun formatRoutingPattern(pattern: String): String {
        val trimmed = pattern.trim()
        if (trimmed.startsWith("domain:") || trimmed.startsWith("ip:") ||
            trimmed.startsWith("keyword:") || trimmed.startsWith("regexp:") ||
            trimmed == "private") {
            return trimmed
        }

        val isIp = trimmed.all { it.isDigit() || it == '.' || it == ':' || it == '/' || (it.lowercaseChar() in 'a'..'f') } &&
                (trimmed.contains('.') || trimmed.contains(':'))

        return if (isIp) "ip:$trimmed" else "domain:$trimmed"
    }

    fun stop() {
        currentAttemptId.incrementAndGet()
        goolOuterValidated = false
        _connectionStatus.value = ConnectionStatus.STOPPED
        runnerJob?.cancel()
        process?.destroy()
        process = null
        LogRepository.i("System core shutdown initiated.")
    }

    fun release() {
        stop()
        scope.cancel()
    }

    private fun prepareCustomWireGuardNativeChain(
        config: AetherConfig,
        workDir: java.io.File,
        binaryPath: String,
        command: MutableList<String>,
        env: MutableMap<String, String>
    ) {
        val innerFiles = listOf(
            java.io.File(workDir, "aether-gool.toml"),
            java.io.File(workDir, "aether-masque-gool.toml"),
            java.io.File(workDir, "aether-secondary.toml"),
            java.io.File(workDir, "aether-wg-secondary.toml")
        )

        if (config.exitNodeMode != ExitNodeMode.CUSTOM_WG || !config.customWgConfig.isValid()) {
            for (f in innerFiles) {
                runCatching {
                    val corrupt = java.io.File(workDir, "${f.name}.corrupt")
                    if (corrupt.exists()) corrupt.delete()
                    if (f.exists()) {
                        val txt = f.readText()
                        if (txt.contains("custom-wg-inner")) {
                            f.delete()
                        }
                    }
                }
            }
            return
        }

        workDir.listFiles()?.forEach { f ->
            if (f.name.endsWith(".corrupt")) runCatching { f.delete() }
        }

        val customWg = config.customWgConfig
        val rawEndpoint = customWg.endpoint.trim()
        val hostPart = if (rawEndpoint.startsWith("[")) {
            rawEndpoint.substringAfter('[').substringBefore(']')
        } else {
            rawEndpoint.substringBeforeLast(':')
        }.trim()
        val portPart = rawEndpoint.substringAfterLast(':', "51820").trim().toIntOrNull() ?: 51820
        val resolvedHost = runCatching {
            if (hostPart.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$""")) || hostPart.contains(':')) {
                hostPart
            } else {
                java.net.InetAddress.getAllByName(hostPart)
                    .firstOrNull { it is java.net.Inet4Address }
                    ?.hostAddress ?: hostPart
            }
        }.getOrDefault(hostPart)
        val innerEndpoint = "$resolvedHost:$portPart"

        val cleanIpv4 = customWg.addressV4.substringBefore('/').trim().ifBlank { "10.2.0.2" }
        val cleanIpv6 = customWg.addressV6.substringBefore('/').trim().ifBlank { "fd00::2" }

        val customPriv = customWg.privateKey.trim()
        for (outerName in listOf("aether.toml", "aether-wg.toml", "aether-masque.toml")) {
            val outerFile = java.io.File(workDir, outerName)
            runCatching {
                if (outerFile.exists()) {
                    val txt = outerFile.readText()
                    if ((customPriv.isNotEmpty() && txt.contains(customPriv)) || !txt.contains("ipv6")) {
                        outerFile.delete()
                    }
                }
            }
        }
        val primaryOuter = java.io.File(workDir, "aether.toml")
        if (!primaryOuter.exists() || primaryOuter.length() == 0L) {
            runCatching {
                val regPb = ProcessBuilder(binaryPath, "--register", "wg", "--config", primaryOuter.absolutePath)
                regPb.directory(workDir)
                val p = regPb.start()
                p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)
                if (p.isAlive) p.destroyForcibly()
            }
        }

        if (primaryOuter.exists() && primaryOuter.length() > 0L &&
            (config.protocol == AetherProtocol.WG || config.protocol == AetherProtocol.GOOL || config.protocol == AetherProtocol.MASQUE)
        ) {
            val innerToml = buildString {
                appendLine("""device_id = "custom-wg-inner"""")
                appendLine("""access_token = "custom-wg-token"""")
                appendLine("""ipv4 = "$cleanIpv4"""")
                appendLine("""ipv6 = "$cleanIpv6"""")
                appendLine("""wg_private_key = "${customWg.privateKey.trim()}"""")
                appendLine("""wg_peer_public_key = "${customWg.publicKey.trim()}"""")
                appendLine("""assigned_endpoint = "$innerEndpoint"""")
                appendLine("""client_id = "AAAA"""")
            }
            for (f in innerFiles) {
                runCatching { f.writeText(innerToml) }
            }

            val useClassic = config.protocol == AetherProtocol.WG || (config.protocol == AetherProtocol.GOOL && config.goolClassic)
            command.removeAll(listOf("--wg", "--masque", "--gool", "--gool-classic", "--no-data-check"))

            fun removeFlagWithArg(flag: String) {
                var idx = command.indexOf(flag)
                while (idx != -1) {
                    command.removeAt(idx)
                    if (idx < command.size) command.removeAt(idx)
                    idx = command.indexOf(flag)
                }
            }
            removeFlagWithArg("--wiw-inner")
            removeFlagWithArg("--gool-peer")
            removeFlagWithArg("--api-address")
            removeFlagWithArg("--dns")

            val customDns = customWg.dnsServers.firstOrNull { it.isNotBlank() } ?: "10.2.0.1"
            val combinedDns = "$customDns,1.1.1.1,1.0.0.1"

            if (useClassic) {
                command.add("--gool-classic")
                command.add("--wiw-inner")
                command.add(innerEndpoint)
                env["AETHER_PROTOCOL"] = "gool"
                env["AETHER_GOOL_MODE"] = "classic"
                env["AETHER_WIW_INNER_PEER"] = innerEndpoint
            } else {
                command.add("--gool")
                command.add("--gool-peer")
                command.add(innerEndpoint)
                env["AETHER_PROTOCOL"] = "gool"
                env["AETHER_GOOL_INNER"] = innerEndpoint
                env["AETHER_GOOL_PEER"] = innerEndpoint
            }

            command.add("--api-address")
            command.add("127.0.0.1:1")
            command.add("--no-data-check")
            command.add("--dns")
            command.add(combinedDns)

            env["AETHER_API_ADDRESS"] = "127.0.0.1:1"
            env["AETHER_REPROVISION"] = "0"
            env["AETHER_WG_NO_DATA_CHECK"] = "1"
            env["AETHER_WG_STALE_SECS"] = "86400"
            env["AETHER_DNS"] = combinedDns
        }
    }

}
