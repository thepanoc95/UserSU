package dev.github.thepanoc95.usersu

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.pm.ApplicationInfo
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.*
import dev.github.thepanoc95.usersu.service.UserSUDaemonService

class MainActivity : Activity() {

    private lateinit var statusText: TextView
    private lateinit var branchText: TextView
    private lateinit var branchContainer: LinearLayout
    private lateinit var appsContainer: LinearLayout
    private lateinit var hooksContainer: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Extract assets on startup
        extractAssets()
        
        // Root ScrollView
        val scrollView = ScrollView(this).apply {
            layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
            setBackgroundColor(Color.parseColor("#121212")) // Premium dark mode background
            isFillViewport = true
        }

        // Main Vertical Layout
        val mainLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT)
            val padding = dpToPx(16)
            setPadding(padding, padding, padding, padding)
        }

        // Header
        val header = TextView(this).apply {
            text = "UserSU Manager"
            textSize = 28f
            setTextColor(Color.parseColor("#BB86FC")) // Modern purple
            typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
            val params = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            params.setMargins(0, 0, 0, dpToPx(24))
            layoutParams = params
        }
        mainLayout.addView(header)

        // Status Card
        val statusCard = createCardView("Daemon Status").apply {
            val layout = getCardLayout(this)
            
            statusText = TextView(this@MainActivity).apply {
                text = "Checking status..."
                textSize = 18f
                setTextColor(Color.WHITE)
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                    setMargins(0, 0, 0, dpToPx(8))
                }
            }
            layout.addView(statusText)

            branchText = TextView(this@MainActivity).apply {
                text = "Active Branch: -"
                textSize = 16f
                setTextColor(Color.LTGRAY)
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                    setMargins(0, 0, 0, dpToPx(12))
                }
            }
            layout.addView(branchText)

            val howToText = TextView(this@MainActivity).apply {
                text = "To start daemon, run in ADB:\nadb shell sh /data/data/dev.github.thepanoc95.usersu/files/bin/start.sh"
                textSize = 12f
                setTextColor(Color.GRAY)
                typeface = Typeface.MONOSPACE
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            }
            layout.addView(howToText)
        }
        mainLayout.addView(statusCard)

        // Branch Operations Card
        val branchCard = createCardView("Branch Sandbox").apply {
            val layout = getCardLayout(this)

            val inputLayout = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                    setMargins(0, 0, 0, dpToPx(12))
                }
            }

            val branchInput = EditText(this@MainActivity).apply {
                hint = "New branch name"
                setHintTextColor(Color.GRAY)
                setTextColor(Color.WHITE)
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            inputLayout.addView(branchInput)

            val createBtn = Button(this@MainActivity).apply {
                text = "Create"
                setBackgroundColor(Color.parseColor("#03DAC6")) // Modern teal
                setTextColor(Color.BLACK)
                setOnClickListener {
                    val name = branchInput.text.toString().trim()
                    if (name.isNotEmpty()) {
                        try {
                            UserSUDaemonService.getBinder()?.createBranch(name)
                            branchInput.text.clear()
                            refreshDaemonInfo()
                            Toast.makeText(this@MainActivity, "Branch created", Toast.LENGTH_SHORT).show()
                        } catch (e: Exception) {
                            Toast.makeText(this@MainActivity, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
            inputLayout.addView(createBtn)
            layout.addView(inputLayout)

            // Button actions layout
            val actionLayout = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            }

            val switchBtn = Button(this@MainActivity).apply {
                text = "Switch"
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                    setMargins(0, 0, dpToPx(4), 0)
                }
                setOnClickListener {
                    showSwitchBranchDialog()
                }
            }
            actionLayout.addView(switchBtn)

            val rollbackBtn = Button(this@MainActivity).apply {
                text = "Rollback"
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                    setMargins(dpToPx(4), 0, 0, 0)
                }
                setOnClickListener {
                    try {
                        UserSUDaemonService.getBinder()?.rollbackActiveBranch()
                        Toast.makeText(this@MainActivity, "Rolled back changes", Toast.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Toast.makeText(this@MainActivity, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            }
            actionLayout.addView(rollbackBtn)
            layout.addView(actionLayout)
        }
        mainLayout.addView(branchCard)

        // App Redirection Card (LD_PRELOAD Wrap)
        val hookCard = createCardView("App Dynamic Links (su Redirect)").apply {
            val layout = getCardLayout(this)
            hooksContainer = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            }
            layout.addView(hooksContainer)
        }
        mainLayout.addView(hookCard)

        // Root Apps Card (Third-party authorizations)
        val appsCard = createCardView("Root Permissions").apply {
            val layout = getCardLayout(this)
            appsContainer = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            }
            layout.addView(appsContainer)
        }
        mainLayout.addView(appsCard)

        scrollView.addView(mainLayout)
        setContentView(scrollView)

        // Start polling daemon status
        startStatusPolling()
    }

    private fun startStatusPolling() {
        val handler = android.os.Handler(android.os.Looper.getMainLooper())
        handler.post(object : Runnable {
            override fun run() {
                refreshDaemonInfo()
                handler.postDelayed(this, 3000)
            }
        })
    }

    private fun refreshDaemonInfo() {
        val daemon = UserSUDaemonService.getBinder()
        if (daemon != null) {
            statusText.text = "Daemon Status: RUNNING"
            statusText.setTextColor(Color.parseColor("#03DAC6"))
            try {
                branchText.text = "Active Branch: ${daemon.activeBranch}"
            } catch (e: Exception) {
                branchText.text = "Active Branch: Error"
            }
            loadApps()
        } else {
            statusText.text = "Daemon Status: NOT RUNNING"
            statusText.setTextColor(Color.parseColor("#CF6679")) // Soft red
            branchText.text = "Active Branch: -"
            hooksContainer.removeAllViews()
            appsContainer.removeAllViews()
        }
    }

    private fun loadApps() {
        val daemon = UserSUDaemonService.getBinder() ?: return
        
        // List installed non-system apps
        val pm = packageManager
        val installedApps = pm.getInstalledApplications(0)
        
        hooksContainer.removeAllViews()
        appsContainer.removeAllViews()

        val prefs = getSharedPreferences("usersu_prefs", Context.MODE_PRIVATE)

        for (app in installedApps) {
            val isSystemApp = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            if (isSystemApp && app.packageName != "com.android.shell") continue

            val label = app.loadLabel(pm).toString()
            val pkgName = app.packageName

            // 1. Dynamic Links List (wrap properties)
            val isWrapped = try { daemon.isAppWrapped(pkgName) } catch (e: Exception) { false }
            val hookRow = createSwitchRow(label, pkgName, isWrapped) { checked ->
                try {
                    daemon.setAppWrapped(pkgName, checked)
                } catch (e: Exception) {
                    Toast.makeText(this, "Failed to toggle: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
            hooksContainer.addView(hookRow)

            // 2. Permission Requests List
            val hasRequested = prefs.getBoolean("requested_$pkgName", false)
            val isAuthorized = prefs.getBoolean("authorized_$pkgName", false)
            if (hasRequested || isAuthorized) {
                val appRow = createSwitchRow(label, pkgName, isAuthorized) { checked ->
                    prefs.edit().putBoolean("authorized_$pkgName", checked).apply()
                }
                appsContainer.addView(appRow)
            }
        }
    }

    private fun showSwitchBranchDialog() {
        val daemon = UserSUDaemonService.getBinder() ?: return
        val branches = try { daemon.listBranches().toTypedArray() } catch (e: Exception) { emptyArray() }
        
        AlertDialog.Builder(this)
            .setTitle("Switch Active Branch")
            .setItems(branches) { _, which ->
                val target = branches[which]
                try {
                    daemon.switchBranch(target)
                    refreshDaemonInfo()
                    Toast.makeText(this, "Switched to $target", Toast.LENGTH_SHORT).show()
                } catch (e: Exception) {
                    Toast.makeText(this, "Failed to switch: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun createCardView(title: String): LinearLayout {
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val padding = dpToPx(16)
            setPadding(padding, padding, padding, padding)
            
            // Rounded corners and background color
            background = GradientDrawable().apply {
                setColor(Color.parseColor("#1E1E1E"))
                cornerRadius = dpToPx(12).toFloat()
            }
            
            val params = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            params.setMargins(0, 0, 0, dpToPx(16))
            layoutParams = params
        }

        val titleView = TextView(this).apply {
            text = title
            textSize = 18f
            setTextColor(Color.parseColor("#BB86FC"))
            typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                setMargins(0, 0, 0, dpToPx(12))
            }
        }
        card.addView(titleView)

        val contentLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        }
        card.addView(contentLayout)

        return card
    }

    private fun getCardLayout(card: LinearLayout): LinearLayout {
        return card.getChildAt(1) as LinearLayout
    }

    private fun createSwitchRow(label: String, sublabel: String, checked: Boolean, onToggle: (Boolean) -> Unit): LinearLayout {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            val padding = dpToPx(8)
            setPadding(0, padding, 0, padding)
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        }

        val textLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }

        val titleView = TextView(this).apply {
            text = label
            textSize = 16f
            setTextColor(Color.WHITE)
        }
        textLayout.addView(titleView)

        val subtitleView = TextView(this).apply {
            text = sublabel
            textSize = 12f
            setTextColor(Color.GRAY)
        }
        textLayout.addView(subtitleView)

        row.addView(textLayout)

        val switchBtn = Switch(this).apply {
            isChecked = checked
            setOnCheckedChangeListener { _, isChecked -> onToggle(isChecked) }
        }
        row.addView(switchBtn)

        return row
    }

    private fun dpToPx(dp: Int): Int {
        val density = resources.displayMetrics.density
        return (dp * density).toInt()
    }

    private fun extractAssets() {
        val assetsList = listOf("proot", "psu", "psudo", "libusersuhook.so", "su", "usersu-server.dex", "start.sh", "startkernel.sh")
        val filesDir = filesDir
        val binDir = java.io.File(filesDir, "bin").apply { mkdirs() }
        val libDir = java.io.File(filesDir, "lib").apply { mkdirs() }

        for (assetName in assetsList) {
            val targetDir = if (assetName == "libusersuhook.so") libDir else binDir
            val targetFile = java.io.File(targetDir, assetName)
            try {
                assets.open(assetName).use { input ->
                    targetFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                targetFile.setExecutable(true)
                println("[UserSU] Extracted asset $assetName to ${targetFile.absolutePath}")
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }
}
