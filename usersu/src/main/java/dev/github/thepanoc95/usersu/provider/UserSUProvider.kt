package dev.github.thepanoc95.usersu.provider

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import dev.github.thepanoc95.usersu.service.UserSUDaemonService

class UserSUProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (method == "getBinder") {
            val callingPkg = callingPackage ?: return null

            val context = context ?: return null
            val prefs = context.getSharedPreferences("usersu_prefs", android.content.Context.MODE_PRIVATE)
            val isAuthorized = prefs.getBoolean("authorized_$callingPkg", false)
            
            val result = Bundle()
            if (!isAuthorized) {
                prefs.edit().putBoolean("requested_$callingPkg", true).apply()
                result.putBoolean("authorized", false)
                return result
            }

            val daemon = UserSUDaemonService.getBinder()
            if (daemon != null) {
                result.putBoolean("authorized", true)
                result.putBinder("binder", daemon.asBinder())
                return result
            }
        }
        return null
    }

    override fun query(uri: Uri, projection: Array<String>?, selection: String?, selectionArgs: Array<String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<String>?): Int = 0
}
