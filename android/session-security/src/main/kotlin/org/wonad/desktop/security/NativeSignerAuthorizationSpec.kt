package org.wonad.desktop.security

/** Test-only admission contract; the production OS trust pin is never changed. */
internal object NativeSignerAuthorizationSpec {
    const val API = 3
    const val PACKAGE = "org.wonad.desktop"
    const val SCOPE = "native_v3_wrong_signer"
    const val DENIAL = "Wonad signer not allowed"
    val METHODS = listOf("getApiVersion", "getCapabilities", "openSession")

    fun requireArguments(run: String, uid: Int, trusted: String, expected: String) {
        check(run.matches(Regex("[0-9a-f]{32}")))
        check(uid in 10000..19999)
        check(trusted.matches(Regex("[0-9a-f]{64}")) && expected.matches(Regex("[0-9a-f]{64}")))
        check(trusted != expected)
    }
}
