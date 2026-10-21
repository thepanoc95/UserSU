package me.usersu.manager.data

import android.net.LocalSocket
import android.net.LocalSocketAddress
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException

/**
 * Where usud listens.
 *
 * The daemon puts its socket in the root-only data directory when it can, and
 * falls back to the app's own files directory otherwise.  Both are tried so the
 * app works whether or not the daemon had real root.
 */
val DAEMON_SOCKETS: List<String> = listOf(
    "/data/me.usersu/usud.sock",
    "/data/data/me.usersu/files/usud.sock",
)

/** A decoded reply.  Callers branch on the concrete type. */
sealed interface Reply {
    data class Ok(val message: String) : Reply
    data class Hello(val payload: HelloPayload) : Reply
    data class Status(val payload: StatusPayload) : Reply
    data class Listing(val entries: List<String>) : Reply

    class FileBytes(val data: ByteArray) : Reply {
        override fun equals(other: Any?): Boolean =
            other is FileBytes && data.contentEquals(other.data)

        override fun hashCode(): Int = data.contentHashCode()
    }

    data class Providers(val providers: List<ProviderInfo>) : Reply
    data class Profiles(val profiles: List<ProfileInfo>) : Reply
    data class Executed(val code: Int?) : Reply

    /** The daemon refused the request. */
    data class Failure(val message: String) : Reply
}

/** Raised when no daemon socket can be reached. */
class DaemonUnavailable(message: String) : IOException(message)

/**
 * A blocking client for the usud protocol.
 *
 * Each call opens a fresh connection, performs the handshake and closes it.
 * Requests are rare and cheap, and a short-lived socket means a daemon restart
 * is picked up automatically rather than leaving a half-open descriptor behind.
 * Every method is blocking and must be called off the main thread.
 *
 * The daemon binds a filesystem-namespace Unix domain socket, so the address
 * carries the [LocalSocketAddress.Namespace.FILESYSTEM] namespace explicitly.
 */
class UsudClient(
    private val sockets: List<String> = DAEMON_SOCKETS,
) {
    /** Sends `request` and returns the decoded reply. */
    fun call(request: JsonElement): Reply = withConnection { input, output ->
        output.writeFrame(Protocol.hello())
        val hello = input.readFrame()
        when (hello["response"]?.jsonPrimitive?.content) {
            "hello" -> Unit
            "error" -> throw IOException("usud rejected the handshake: ${hello.message()}")
            else -> throw IOException("unexpected handshake reply: $hello")
        }

        output.writeFrame(request)
        readReply(input.readFrame())
    }

    private inline fun <T> withConnection(block: (DataInputStream, DataOutputStream) -> T): T {
        var lastError: IOException? = null
        for (socket in sockets) {
            val address = LocalSocketAddress(socket, LocalSocketAddress.Namespace.FILESYSTEM)
            val local = LocalSocket()
            var connected = false
            try {
                local.connect(address)
                connected = true
                val input = DataInputStream(local.inputStream)
                val output = DataOutputStream(local.outputStream)
                return block(input, output)
            } catch (e: IOException) {
                lastError = e
            } finally {
                if (connected) runCatching { local.close() }
            }
        }
        throw DaemonUnavailable(
            "could not reach usud on ${sockets.joinToString()}: ${lastError?.message}"
        )
    }

    private fun DataOutputStream.writeFrame(element: JsonElement) {
        val body = element.toString().toByteArray(Charsets.UTF_8)
        // Little-endian, matching Rust's `u32::to_le_bytes`.
        write(
            byteArrayOf(
                (body.size and 0xff).toByte(),
                ((body.size ushr 8) and 0xff).toByte(),
                ((body.size ushr 16) and 0xff).toByte(),
                ((body.size ushr 24) and 0xff).toByte(),
            )
        )
        write(body)
        flush()
    }

    private fun DataInputStream.readFrame(): JsonObject {
        val header = ByteArray(4)
        readFully(header)
        val length = (header[0].toInt() and 0xff) or
            ((header[1].toInt() and 0xff) shl 8) or
            ((header[2].toInt() and 0xff) shl 16) or
            ((header[3].toInt() and 0xff) shl 24)
        require(length in 0..Protocol.MAX_FRAME) { "implausible frame length $length" }
        val body = ByteArray(length)
        readFully(body)
        return Protocol.json.parseToJsonElement(String(body, Charsets.UTF_8)).jsonObject
    }

    private fun JsonObject.message(): String =
        this["message"]?.jsonPrimitive?.content ?: "no message"

    private fun readReply(document: JsonObject): Reply =
        when (val kind = document["response"]?.jsonPrimitive?.content) {
            "ok" -> Reply.Ok(document.message())
            "error" -> Reply.Failure(document.message())
            "hello" -> Reply.Hello(Protocol.json.decodeFromJsonElement(document))
            "status" -> {
                val inner = document["status"]!!.jsonObject
                Reply.Status(Protocol.json.decodeFromJsonElement(inner))
            }
            "listing" -> {
                val entries =
                    Protocol.json.decodeFromJsonElement<List<String>>(document["entries"]!!)
                Reply.Listing(entries)
            }
            "file" -> {
                // serde renders `Vec<u8>` as a JSON array of numbers.
                val numbers = Protocol.json.decodeFromJsonElement<List<Int>>(document["data"]!!)
                Reply.FileBytes(ByteArray(numbers.size) { numbers[it].toByte() })
            }
            "providers" -> Reply.Providers(
                Protocol.json.decodeFromJsonElement(document["providers"]!!)
            )
            "profiles" -> Reply.Profiles(
                Protocol.json.decodeFromJsonElement(document["profiles"]!!)
            )
            "executed" -> Reply.Executed(
                document["code"]?.let { Protocol.json.decodeFromJsonElement<Int?>(it) }
            )
            else -> Reply.Failure("unknown reply kind: $kind")
        }
}
