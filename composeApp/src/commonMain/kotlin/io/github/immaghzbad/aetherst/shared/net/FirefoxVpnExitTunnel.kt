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
import java.io.BufferedReader
import java.io.DataInputStream
import java.io.File
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Exception thrown when Firefox Accounts requires a 6-digit email verification code
 * on a newly created sessionToken before issuing OAuth tokens.
 */
class FxaVerificationRequiredException(
    val sessionTokenHex: String,
    override val message: String
) : IllegalStateException(message)

/**
 * Sing-box Managed Firefox VPN Exit Tunnel.
 *
 * All manual Kotlin data-plane HTTP/2 frame multiplexing, SOCKS5 server loops, and UDP DoH
 * packet handlers have been completely removed.
 * This class acts strictly as a Control-Plane Manager (FxA OAuth + Guardian ProxyPass JWT minting)
 * and delegates all Data-Plane routing to the `sing-box` binary via `config.json`.
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
    private var process: Process? = null
    private var logThread: Thread? = null
    @Volatile private var attachedToPrimarySingBox = false

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
            val proxyPass = resolveLiveProxyPassJwt(cleanToken, primarySocksHost, primarySocksPort)
            if (proxyPass.isNullOrBlank()) {
                lastErrorMessage = "Failed to obtain Mozilla Guardian ProxyPass JWT"
                LogRepository.e("[FirefoxVpn] $lastErrorMessage", "FirefoxVpn")
                stopInternal()
                return false
            }

            val edge = resolveCountryExitCandidates(country.trim(), primarySocksHost, primarySocksPort).first()
            val workDir = File(workingDir).apply { mkdirs() }

            if (probePort("127.0.0.1", localListenPort)) {
                attachedToPrimarySingBox = true
                verifiedExitIp = edge.host
                LogRepository.i("[FirefoxVpn] Attached to active Sing-box Firefox outbound on port $localListenPort", "FirefoxVpn")
                return true
            }

            val singBoxBin = binaryPath?.takeIf { File(it).exists() } ?: findSingBoxBinary()
            if (singBoxBin == null) {
                if (probePort(primarySocksHost, primarySocksPort)) {
                    attachedToPrimarySingBox = true
                    verifiedExitIp = edge.host
                    return true
                }
                lastErrorMessage = "Sing-box binary not found"
                stopInternal()
                return false
            }

            val authVal = if (proxyPass.startsWith("ProxyPass ", ignoreCase = true) || proxyPass.startsWith("Bearer ", ignoreCase = true)) {
                proxyPass
            } else {
                "ProxyPass $proxyPass"
            }

            val cfgFile = File(workDir, "singbox-firefox-$localListenPort.json")
            cfgFile.writeText(
                """
                {
                  "log": {
                    "level": "info",
                    "timestamp": true
                  },
                  "inbounds": [
                    {
                      "type": "socks",
                      "tag": "socks-in",
                      "listen": "127.0.0.1",
                      "listen_port": $localListenPort
                    },
                    {
                      "type": "http",
                      "tag": "http-in",
                      "listen": "127.0.0.1",
                      "listen_port": ${localListenPort - 1}
                    }
                  ],
                  "outbounds": [
                    {
                      "type": "socks",
                      "tag": "warp-out",
                      "server": "$primarySocksHost",
                      "server_port": $primarySocksPort
                    },
                    {
                      "type": "http",
                      "tag": "firefox-out",
                      "detour": "warp-out",
                      "server": "${edge.host}",
                      "server_port": ${edge.port},
                      "tls": {
                        "enabled": true,
                        "server_name": "${edge.host}"
                      },
                      "headers": {
                        "Proxy-Authorization": "$authVal",
                        "User-Agent": "$MOZILLA_VPN_UA"
                      }
                    }
                  ],
                  "route": {
                    "final": "firefox-out"
                  }
                }
                """.trimIndent()
            )

            val pb = ProcessBuilder(listOf(singBoxBin, "run", "-c", cfgFile.absolutePath))
            pb.directory(workDir)
            pb.redirectErrorStream(true)
            val proc = pb.start()
            process = proc

            logThread = Thread({
                try {
                    BufferedReader(InputStreamReader(proc.inputStream)).use { reader ->
                        var line: String?
                        while (proc.isAlive && reader.readLine().also { line = it } != null) {
                            LogRepository.i("[sing-box-ff] ${line ?: break}", "FirefoxVpn")
                        }
                    }
                } catch (_: Exception) {}
            }, "SingBox-Firefox-Logger").apply { isDaemon = true; start() }

            for (i in 1..30) {
                if (!proc.isAlive) break
                if (probePort("127.0.0.1", localListenPort)) {
                    verifiedExitIp = edge.host
                    LogRepository.i("[FirefoxVpn] Sing-box Firefox VPN outbound active via ${edge.host}:${edge.port}", "FirefoxVpn")
                    return true
                }
                Thread.sleep(150)
            }

            lastErrorMessage = "Sing-box Firefox VPN outbound failed to bind port $localListenPort"
            stopInternal()
            false
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
        attachedToPrimarySingBox = false
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
        if (wasRunning) {
            LogRepository.i("[FirefoxVpn] Sing-box Firefox exit node stopped.", "FirefoxVpn")
        }
    }

    fun isHealthy(): Boolean =
        isRunning.get() && (attachedToPrimarySingBox || process?.isAlive == true) &&
            (probePort("127.0.0.1", localListenPort) || probePort(primarySocksHost, primarySocksPort))

    private fun findSingBoxBinary(): String? {
        val binName = if ((System.getProperty("os.name") ?: "").lowercase().contains("win")) "sing-box.exe" else "sing-box"
        val candidates = listOf(
            File("composeApp/src/desktopMain/resources/bin", binName),
            File("bin", binName),
            File(binName)
        )
        return candidates.firstOrNull { it.exists() && it.isFile }?.absolutePath
    }

    private fun probePort(host: String, port: Int): Boolean {
        return runCatching {
            Socket().use {
                it.connect(InetSocketAddress(host, port), 400)
                true
            }
        }.getOrDefault(false)
    }

    companion object {
        private val jsonParser = Json { ignoreUnknownKeys = true }

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
            "e6eb0d1e856335fc",
            "5882386c6d801776",
            "a2270f727f45f648"
        )

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
            val ccLower = targetCc.lowercase()
            results.addAll(
                listOf(
                    EdgeEndpoint("$ccLower.m1.fastly-masque.net", 443, targetCc),
                    EdgeEndpoint("us.m1.fastly-masque.net", 443, "US"),
                    EdgeEndpoint("de.m1.fastly-masque.net", 443, "DE"),
                    EdgeEndpoint("nl.m1.fastly-masque.net", 443, "NL"),
                    EdgeEndpoint("gb.m1.fastly-masque.net", 443, "GB")
                )
            )
            return results.distinctBy { "${it.host.lowercase()}:${it.port}" }
        }

        fun resolveCountryExitHost(countryCode: String, socksHost: String, socksPort: Int): String {
            return resolveCountryExitCandidates(countryCode, socksHost, socksPort).first().host
        }

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

            if (!oauthAccessToken.isNullOrBlank()) {
                val jwt = runCatching { requestGuardianProxyPass(client, oauthAccessToken) }.getOrNull()
                if (!jwt.isNullOrBlank()) return jwt
            }

            if (!sessionTokenHex.isNullOrBlank()) {
                val mintedOAuth = runCatching { exchangeSessionTokenForOAuth(client, sessionTokenHex) }.getOrNull()
                if (!mintedOAuth.isNullOrBlank()) {
                    val jwt = runCatching { requestGuardianProxyPass(client, mintedOAuth) }.getOrNull()
                    if (!jwt.isNullOrBlank()) return jwt
                }
            }

            return cachedJwt?.takeIf { isJwtFresh(it, 10) }
        }

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
                    ?: throw IllegalStateException("FxA sign-in failed: $lastLoginErr")

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

        private fun exchangeSessionTokenForOAuth(client: OkHttpClient, sessionTokenHex: String): String {
            val mediaJson = "application/json; charset=utf-8".toMediaType()
            var lastErr = "OAuth exchange failed"
            val hosts = listOf(
                "oauth.accounts.firefox.com" to FXA_OAUTH_BASE,
                "api.accounts.firefox.com" to FXA_API_BASE
            )

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
                        for (rUrl in listOf("$FXA_OAUTH_BASE/token", "$FXA_OAUTH_BASE/oauth/token", "$FXA_API_BASE/oauth/token")) {
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

            throw IllegalStateException("FxA OAuth token exchange failed ($lastErr)")
        }

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

            val socksListening = socksPort > 0 && runCatching {
                Socket().use { it.connect(InetSocketAddress(socksHost, socksPort), 300); true }
            }.getOrDefault(false)

            if (socksListening) {
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
                val exp = Regex(""""exp"\s*:\s*(\d+)""").find(payloadJson)?.groupValues?.get(1)?.toLongOrNull() ?: return true
                val nowSec = System.currentTimeMillis() / 1000L
                (exp - nowSec) > minRemainingSec
            } catch (_: Exception) {
                true
            }
        }
    }
}
