package org.wonad.desktop

/** Process-local status surface shared by the finite API-coverage script and
 * the distinct long-lived runtime probe. It is evidence only, never broker
 * authority. */
internal interface ConformanceStatus {
    fun json(): String
    fun terminalState(): String
    fun callback(name: String)
    fun facade(name: String, valid: Boolean)
}
