package com.goteleport.vnet.android

import android.content.Context

/** The handful of settings the prototype remembers between launches. */
object Prefs {
    private const val FILE = "teleport-vnet"

    private const val KEY_PROXY = "proxy"
    private const val KEY_USER = "user"
    private const val KEY_INSECURE = "insecure"
    private const val KEY_DEBUG_LOGS = "debug_logs"

    private fun prefs(context: Context) =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun proxy(context: Context): String = prefs(context).getString(KEY_PROXY, "").orEmpty()
    fun setProxy(context: Context, value: String) =
        prefs(context).edit().putString(KEY_PROXY, value).apply()

    fun user(context: Context): String = prefs(context).getString(KEY_USER, "").orEmpty()
    fun setUser(context: Context, value: String) =
        prefs(context).edit().putString(KEY_USER, value).apply()

    fun insecure(context: Context): Boolean = prefs(context).getBoolean(KEY_INSECURE, false)
    fun setInsecure(context: Context, value: Boolean) =
        prefs(context).edit().putBoolean(KEY_INSECURE, value).apply()

    fun debugLogs(context: Context): Boolean = prefs(context).getBoolean(KEY_DEBUG_LOGS, true)
    fun setDebugLogs(context: Context, value: Boolean) =
        prefs(context).edit().putBoolean(KEY_DEBUG_LOGS, value).apply()

    /** slog levels: -4 debug, 0 info. */
    fun logLevel(context: Context): Long = if (debugLogs(context)) -4L else 0L
}
