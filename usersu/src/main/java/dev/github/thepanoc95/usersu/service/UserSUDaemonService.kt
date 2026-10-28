package dev.github.thepanoc95.usersu.service

import android.app.Service
import android.content.Intent
import android.os.IBinder
import dev.github.thepanoc95.usersu.IUserSU

import dev.github.thepanoc95.usersu.service.IUserSUDaemonService

class UserSUDaemonService : Service() {
    companion object {
        private var daemonBinder: IUserSU? = null

        fun getBinder(): IUserSU? {
            val binder = daemonBinder
            if (binder != null && binder.asBinder().isBinderAlive) {
                return binder
            }
            return null
        }
    }

    private val binder = object : IUserSUDaemonService.Stub() {
        override fun registerServer(server: IBinder) {
            if (server != null) {
                daemonBinder = IUserSU.Stub.asInterface(server)
                println("[UserSU Service] Daemon binder registered successfully.")
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder {
        return binder.asBinder()
    }
}
