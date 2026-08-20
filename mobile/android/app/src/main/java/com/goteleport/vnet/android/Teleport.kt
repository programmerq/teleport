package com.goteleport.vnet.android

import android.content.Context
import android.util.Log
import com.goteleport.vnet.vnet.Client
import com.goteleport.vnet.vnet.Logger
import com.goteleport.vnet.vnet.Vnet

/**
 * Holds the single Go [Client] for the process.
 *
 * The Go side owns the Teleport profile directory and, once started, the VNet
 * session, so there must be exactly one of these no matter how many times the
 * activity is recreated.
 */
object Teleport {
    const val TAG = "TeleportVNet"

    @Volatile
    private var client: Client? = null

    fun client(context: Context): Client =
        client ?: synchronized(this) {
            client ?: create(context).also { client = it }
        }

    private fun create(context: Context): Client {
        // Route Go logging to logcat before anything else runs, so that startup
        // failures are visible. A gomobile-bound library writes to a file
        // descriptor nobody reads, so without this every log line is lost.
        Vnet.setLogger(LogcatLogger(), Prefs.logLevel(context))

        val appContext = context.applicationContext
        val client = Vnet.newClient(appContext.filesDir.absolutePath)
        client.setInsecure(Prefs.insecure(appContext))
        Log.i(TAG, "Teleport client created, home=${appContext.filesDir.absolutePath}")
        return client
    }

    /** Re-reads settings that are only applied when the client is created. */
    fun applySettings(context: Context) {
        Vnet.setLogger(LogcatLogger(), Prefs.logLevel(context))
        client?.setInsecure(Prefs.insecure(context))
    }
}

/** Forwards Go's log/slog records to logcat, mapping slog levels to priorities. */
private class LogcatLogger : Logger {
    override fun log(level: Long, message: String) {
        when {
            level >= 8 -> Log.e(Teleport.TAG, message)
            level >= 4 -> Log.w(Teleport.TAG, message)
            level >= 0 -> Log.i(Teleport.TAG, message)
            else -> Log.d(Teleport.TAG, message)
        }
    }
}
