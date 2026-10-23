package org.wonad.fixture

import java.lang.reflect.InvocationTargetException

/** Public-method reflection keeps the compileSdk35 fixture independent of newer API symbols.
 * This reports requested window attributes, NOT proof system_server honored key capture. */
class PublicKeyboardCaptureRequest(private val publicParamsType: Class<*>) {
    enum class Status {
        ATTRIBUTES_APPLIED, API_UNAVAILABLE, NORMAL_PERMISSION_MISSING,
        PUBLIC_API_ERROR, WINDOW_UPDATE_ERROR, ATTRIBUTE_MISMATCH,
    }
    data class Result(val status: Status, val attributeEnabled: Boolean?, val errorClass: String?)

    private fun error(status: Status, failure: Throwable): Result {
        val cause = if (failure is InvocationTargetException) failure.cause ?: failure else failure
        if (cause is VirtualMachineError || cause is ThreadDeath) throw cause
        return Result(status, null, cause.javaClass.name.take(128))
        // Never retain exception messages or typed input; fatal failures are not false success.
    }

    fun request(params: Any, enabled: Boolean, permissionGranted: Boolean,
        updateWindow: (Any) -> Unit, currentParams: () -> Any): Result {
        if (!publicParamsType.isInstance(params)) {
            return Result(Status.PUBLIC_API_ERROR, null, "UnexpectedPublicParameterType")
        }
        val setter: java.lang.reflect.Method
        val getter: java.lang.reflect.Method
        try {
            setter = publicParamsType.getMethod("setKeyboardCaptureEnabled", java.lang.Boolean.TYPE)
            getter = publicParamsType.getMethod("hasKeyboardCapture")
        } catch (unavailable: NoSuchMethodException) {
            return error(Status.API_UNAVAILABLE, unavailable)
        } catch (denied: SecurityException) {
            return error(Status.PUBLIC_API_ERROR, denied)
        } catch (unavailable: LinkageError) {
            return error(Status.API_UNAVAILABLE, unavailable)
        }
        if (setter.returnType != Void.TYPE || getter.returnType != java.lang.Boolean.TYPE) {
            return Result(Status.PUBLIC_API_ERROR, null, "UnexpectedPublicMethodSignature")
        }
        if (enabled && !permissionGranted) {
            return Result(Status.NORMAL_PERMISSION_MISSING, null, null)
        }
        try {
            setter.invoke(params, enabled)
        } catch (failed: ReflectiveOperationException) {
            return error(Status.PUBLIC_API_ERROR, failed)
        } catch (failed: SecurityException) {
            return error(Status.PUBLIC_API_ERROR, failed)
        } catch (failed: IllegalArgumentException) {
            return error(Status.PUBLIC_API_ERROR, failed)
        } catch (failed: LinkageError) {
            return error(Status.PUBLIC_API_ERROR, failed)
        }
        try {
            updateWindow(params)
        } catch (failed: RuntimeException) {
            return error(Status.WINDOW_UPDATE_ERROR, failed)
        } catch (failed: LinkageError) {
            return error(Status.WINDOW_UPDATE_ERROR, failed)
        }
        try {
            val actual = currentParams()
            if (!publicParamsType.isInstance(actual)) {
                return Result(Status.PUBLIC_API_ERROR, null, "UnexpectedCurrentPublicParameterType")
            }
            val observed = getter.invoke(actual) as? Boolean
                ?: return Result(Status.PUBLIC_API_ERROR, null, "NonBooleanPublicGetter")
            return Result(if (observed == enabled) Status.ATTRIBUTES_APPLIED else Status.ATTRIBUTE_MISMATCH,
                observed, null)
        } catch (failed: ReflectiveOperationException) {
            return error(Status.PUBLIC_API_ERROR, failed)
        } catch (failed: RuntimeException) {
            return error(Status.PUBLIC_API_ERROR, failed)
        } catch (failed: LinkageError) {
            return error(Status.PUBLIC_API_ERROR, failed)
        }
    }
}
