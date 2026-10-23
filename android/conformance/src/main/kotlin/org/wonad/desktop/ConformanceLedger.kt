package org.wonad.desktop

/** Small bounded journal rendered by dumpsys; it is evidence, never authority. */
internal class ConformanceLedger(
    val run: String,
    val mode: String,
    private val clock: () -> Long,
) : ConformanceStatus {
    private val started = clock()
    private var updated = started
    private var state = "running"
    private var phase = "created"
    private var failure: String? = null
    private var apiVersion = 0
    private var capabilities = 0L
    private var generation = 0L
    private var heartbeatCount = 0L
    private var displays = emptyList<Int>()
    private val operations = linkedSetOf<String>()
    private val callbackCounts = ConformanceContract.callbacks.associateWith { 0L }.toMutableMap()
    private val facades = mutableListOf<String>()

    private fun touched() { updated = clock() }
    @Synchronized fun phase(value: String, displayIds: List<Int> = displays) {
        require(value.matches(Regex("[a-z0-9-]{1,64}")))
        phase = value; displays = displayIds.distinct().sorted(); touched()
    }
    @Synchronized fun negotiated(version: Int, bits: Long) {
        apiVersion = version; capabilities = bits; touched()
    }
    @Synchronized fun generation(value: Long, displayIds: List<Int>) {
        generation = value; displays = displayIds.distinct().sorted(); touched()
    }
    @Synchronized fun operation(name: String) {
        require(name in ConformanceContract.allOperations)
        operations.add(name)
        if (name == "heartbeat") heartbeatCount++
        touched()
    }
    @Synchronized override fun callback(name: String) {
        require(name in ConformanceContract.callbacks)
        callbackCounts[name] = callbackCounts.getValue(name) + 1
        touched()
    }
    @Synchronized override fun facade(name: String, valid: Boolean) {
        require(name in listOf("ExternalHomeActivity", "ExternalShellActivity", "LauncherActivity"))
        if (facades.size < 64) facades.add(name + ":" + if (valid) "valid" else "rejected")
        touched()
    }
    @Synchronized fun pass() {
        check(operations.containsAll(ConformanceContract.allOperations)) {
            "operations missing: ${ConformanceContract.allOperations - operations}"
        }
        check(callbackCounts.values.all { it > 0 }) {
            "callbacks missing: ${callbackCounts.filterValues { it == 0L }.keys}"
        }
        check(ConformanceContract.requiredCapabilities and capabilities == ConformanceContract.requiredCapabilities)
        check(facades.any { it == "ExternalHomeActivity:valid" })
        check(facades.any { it == "ExternalShellActivity:valid" })
        check(facades.any { it == "LauncherActivity:valid" })
        state = "passed"; phase = "complete"; touched()
    }
    @Synchronized fun fail(error: Throwable) {
        state = "failed"; phase = "failed"
        failure = (error.javaClass.name + ": " + (error.message ?: "no message")).take(1024)
        touched()
    }
    @Synchronized override fun terminalState(): String = state

    private fun quote(value: String): String = buildString {
        append('"')
        value.forEach { character -> when (character) {
            '"' -> append("\\\""); '\\' -> append("\\\\"); '\n' -> append("\\n")
            '\r' -> append("\\r"); '\t' -> append("\\t")
            else -> if (character.code < 32) append("\\u%04x".format(character.code)) else append(character)
        } }
        append('"')
    }
    private fun strings(values: Iterable<String>) = values.joinToString(",", "[", "]") { quote(it) }
    private fun numbers(values: Iterable<Int>) = values.joinToString(",", "[", "]")

    @Synchronized override fun json(): String {
        val callbacks = ConformanceContract.callbacks.joinToString(",", "{", "}") {
            quote(it) + ":" + callbackCounts.getValue(it)
        }
        return buildString {
            append('{')
            append("\"schema\":1,\"run\":").append(quote(run))
            append(",\"mode\":").append(quote(mode))
            append(",\"state\":").append(quote(state))
            append(",\"phase\":").append(quote(phase))
            append(",\"started_elapsed_ms\":").append(started)
            append(",\"updated_elapsed_ms\":").append(updated)
            append(",\"api_version\":").append(apiVersion)
            append(",\"capabilities\":").append(capabilities)
            append(",\"generation\":").append(generation)
            append(",\"display_ids\":").append(numbers(displays))
            append(",\"heartbeat_count\":").append(heartbeatCount)
            append(",\"operations\":").append(strings(operations))
            append(",\"callbacks\":").append(callbacks)
            append(",\"facades\":").append(strings(facades))
            append(",\"failure\":").append(failure?.let(::quote) ?: "null")
            append('}')
        }
    }
}
