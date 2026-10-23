package org.wonad.desktop.api

/** Frozen v3 wire constants. No platform service or authority is installed by this SDK. */
object DesktopProtocol {
    const val API_VERSION = 3
    const val MAX_TASKS = 128
    const val MAX_DISPLAYS = 9
    const val CLIENT_TIMEOUT_MILLIS = 5000L
    const val TRANSACTION_TIMEOUT_MILLIS = 15000L
    const val HEARTBEAT_INTERVAL_MILLIS = 1000L

    // Removed draft-v2 bits 0, 1, 2 and 4 are permanently reserved.
    const val CAP_SHORTCUTS = 1L shl 3
    const val CAP_TRANSFER_PICKER = 1L shl 5
    const val CAP_EXTERNAL_UI = 1L shl 6
    const val CAP_APK_LAUNCHER = 1L shl 7
    const val MAX_LAUNCH_PAGE = 128
    const val MAX_LAUNCH_ENTRIES = 4096
    const val LAUNCHER_TIMEOUT_MILLIS = 30000L

    const val CAP_FRAME = 1L shl 8
    const val CAP_SHELL = 1L shl 9
    // applyFrame stays monitor-contained even when
    // this bit is present; negotiate before using applySignedFrame.
    const val CAP_SIGNED_PLACEMENT = 1L shl 10
    const val CAP_SHORTCUT_KEYS = 1L shl 11
    const val CAP_CLIENT_PROMPT = 1L shl 12
    const val SHORTCUT_KEYSET_VERSION = 1
    const val PROMPT_ACTIVITY = ".DesktopPromptActivity"
    const val MAX_COORDINATE = 32768
    const val MAX_SHELL_REGIONS = 768
    const val SHELL_ACTIVITY = ".ExternalShellActivity"

    const val RESULT_APPLIED = 0
    const val RESULT_STALE = 1
    const val RESULT_INVALID = 2
    const val RESULT_UNSUPPORTED = 3
    const val RESULT_REVOKED = 4
    const val RESULT_BUSY = 5
    const val RESULT_PLATFORM_CONSTRAINT = 6

    const val REVOKED_DISABLED = 1
    const val REVOKED_UNDOCKED = 2
    const val REVOKED_LOCKED = 3
    const val REVOKED_USER_CHANGED = 4
    const val REVOKED_CLIENT_FAILED = 5
    const val REVOKED_IDENTITY_CHANGED = 6

    const val COMMAND_FOCUS_NEXT = 1
    const val COMMAND_FOCUS_PREVIOUS = 2
    const val COMMAND_SWAP_NEXT = 3
    const val COMMAND_SWAP_PREVIOUS = 4
    const val COMMAND_SHRINK_MASTER = 5
    const val COMMAND_EXPAND_MASTER = 6
    const val COMMAND_NEXT_LAYOUT = 7
    const val COMMAND_VIEW_WORKSPACE = 8
    const val COMMAND_MOVE_TO_WORKSPACE = 9
    const val COMMAND_CLOSE = 10
    const val COMMAND_SINK = 11
    const val COMMAND_LAUNCH = 12
    const val COMMAND_TOGGLE_FLOATING = 13
    const val COMMAND_TRANSFER = 14
    const val COMMAND_FOCUS_MONITOR = 15
    const val COMMAND_SEND_TO_MONITOR = 16
    // SDK 3.1.0 opt-in only. argument=(Android keycode<<1)|shifted.
    const val COMMAND_SHORTCUT_KEY = 17
}
