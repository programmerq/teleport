package com.goteleport.vnet.android

import android.content.Context
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView

/**
 * The layout, built in code rather than XML so the whole prototype UI reads in
 * one place.
 */
class MainView(context: Context) {

    var onCheckCluster: () -> Unit = {}
    var onLoginHeadless: () -> Unit = {}
    var onLoginSSO: () -> Unit = {}
    var onConnect: () -> Unit = {}
    var onDisconnect: () -> Unit = {}
    var onListApps: () -> Unit = {}
    var onLogout: () -> Unit = {}
    var onSettingsChanged: () -> Unit = {}

    val proxy: EditText
    val user: EditText
    val insecure: CheckBox
    val debugLogs: CheckBox

    private val status: TextView
    private val progress: ProgressBar
    private val buttons: List<Button>
    private val loggedInOnly: List<Button>

    val root: View

    init {
        val density = context.resources.displayMetrics.density
        fun dp(value: Int) = (value * density).toInt()

        val column = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(20), dp(20), dp(20))
        }

        fun label(text: String) = TextView(context).apply {
            this.text = text
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(0, dp(12), 0, dp(2))
        }

        fun field(hint: String, inputType: Int) = EditText(context).apply {
            this.hint = hint
            this.setInputType(inputType)
            setSingleLine(true)
        }

        column.addView(TextView(context).apply {
            text = "Teleport VNet"
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 24f)
        })
        column.addView(TextView(context).apply {
            text = "Prototype. Proxies TCP applications in one root cluster."
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            alpha = 0.7f
        })

        column.addView(label("Proxy address"))
        proxy = field("teleport.example.com:443", InputType.TYPE_TEXT_VARIATION_URI)
        column.addView(proxy)

        column.addView(label("Teleport username (headless login)"))
        user = field("alice", InputType.TYPE_CLASS_TEXT)
        column.addView(user)

        val checkCluster = Button(context).apply {
            text = "Check cluster"
            setOnClickListener { onCheckCluster() }
        }
        column.addView(checkCluster)

        column.addView(label("Sign in — both open Chrome, where your security key already works"))

        val loginHeadless = Button(context).apply {
            text = "Log in (headless)"
            setOnClickListener { onLoginHeadless() }
        }
        column.addView(loginHeadless)

        val loginSSO = Button(context).apply {
            text = "Log in (SSO)"
            setOnClickListener { onLoginSSO() }
        }
        column.addView(loginSSO)

        column.addView(label("Tunnel"))

        val connect = Button(context).apply {
            text = "Connect"
            setOnClickListener { onConnect() }
        }
        column.addView(connect)

        val disconnect = Button(context).apply {
            text = "Disconnect"
            setOnClickListener { onDisconnect() }
        }
        column.addView(disconnect)

        val listApps = Button(context).apply {
            text = "List TCP apps"
            setOnClickListener { onListApps() }
        }
        column.addView(listApps)

        val logout = Button(context).apply {
            text = "Log out"
            setOnClickListener { onLogout() }
        }
        column.addView(logout)

        insecure = CheckBox(context).apply {
            text = "Skip TLS verification (self-signed clusters only)"
            setOnCheckedChangeListener { _, _ -> onSettingsChanged() }
        }
        column.addView(insecure)

        debugLogs = CheckBox(context).apply {
            text = "Debug logging (adb logcat -s TeleportVNet)"
            setOnCheckedChangeListener { _, _ -> onSettingsChanged() }
        }
        column.addView(debugLogs)

        progress = ProgressBar(context).apply {
            isIndeterminate = true
            visibility = View.GONE
        }
        column.addView(progress)

        status = TextView(context).apply {
            text = "Tunnel: stopped"
            setTextIsSelectable(true)
            typeface = android.graphics.Typeface.MONOSPACE
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            setPadding(0, dp(16), 0, 0)
            gravity = Gravity.START
        }
        column.addView(status)

        buttons = listOf(checkCluster, loginHeadless, loginSSO, connect, disconnect, listApps, logout)
        loggedInOnly = listOf(connect, disconnect, listApps, logout)

        root = ScrollView(context).apply {
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT,
            )
            addView(column)
        }
    }

    fun setStatus(text: String) {
        status.text = text
    }

    fun setBusy(busy: Boolean) {
        progress.visibility = if (busy) View.VISIBLE else View.GONE
        buttons.forEach { it.isEnabled = !busy }
    }

    fun setLoggedIn(loggedIn: Boolean) {
        loggedInOnly.forEach { it.alpha = if (loggedIn) 1f else 0.5f }
    }
}
