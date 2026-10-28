package me.usersu.manager.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject

/**
 * The manager's view of the usud wire protocol.
 *
 * usud frames every message as a 4-byte little-endian length followed by a
 * payload.  The payload is bincode for the CLI and JSON for this app; the
 * daemon decides which by sniffing the handshake, so nothing here needs a
 * bincode implementation.
 *
 * Requests are the tagged JSON objects serde produces for the Rust `Request`
 * enum, so a unit variant is the bare string `"status"` and a struct variant is
 * `{"list-dir":{"path":"/"}}`.  Field names stay in the crate's own
 * `snake_case` because that is what serde emits.
 */
object Protocol {
    const val VERSION: Int = 1
    const val MAX_FRAME: Int = 4 * 1024 * 1024

    val json: Json = Json {
        ignoreUnknownKeys = true
        isLenient = true
        encodeDefaults = true
    }

    private fun array(values: List<String>): JsonElement =
        JsonArray(values.map { JsonPrimitive(it) })

    /** Builds the mandatory first frame. */
    fun hello(client: String = "manager"): JsonElement = buildJsonObject {
        putJsonObject("hello") {
            put("version", VERSION)
            put("client", client)
        }
    }

    fun status(): JsonElement = JsonPrimitive("status")

    fun getConfig(): JsonElement = JsonPrimitive("get-config")

    fun listProfiles(): JsonElement = JsonPrimitive("list-profiles")

    fun providers(): JsonElement = JsonPrimitive("providers")

    fun shutdown(): JsonElement = JsonPrimitive("shutdown")

    fun activateProfile(name: String): JsonElement = buildJsonObject {
        putJsonObject("activate-profile") { put("name", name) }
    }

    fun listDir(path: String): JsonElement = buildJsonObject {
        putJsonObject("list-dir") { put("path", path) }
    }

    fun readFile(path: String): JsonElement = buildJsonObject {
        putJsonObject("read-file") { put("path", path) }
    }

    private fun bytes(data: ByteArray): JsonElement =
        JsonArray(data.map { JsonPrimitive(it.toInt() and 0xff) })

    fun writeFile(path: String, data: ByteArray): JsonElement = buildJsonObject {
        putJsonObject("write-file") {
            put("path", path)
            // serde's JSON form for a Rust `Vec<u8>` is an array of numbers.
            put("data", bytes(data))
        }
    }

    fun removeFile(path: String): JsonElement = buildJsonObject {
        putJsonObject("remove-file") { put("path", path) }
    }

    fun boot(init: String?, args: List<String>): JsonElement = buildJsonObject {
        putJsonObject("boot") {
            if (init != null) put("init", init)
            put("args", array(args))
        }
    }

    fun su(command: List<String>, uid: Int, gid: Int, keepEnv: Boolean): JsonElement =
        buildJsonObject {
            putJsonObject("su") {
                put("command", array(command))
                put("uid", uid)
                put("gid", gid)
                put("keep_env", keepEnv)
                // The app cannot lend its stdio over the socket, so the command
                // inherits the daemon's own descriptors and its output is read
                // back from the daemon log rather than captured directly.
                put("wants_stdio", false)
            }
        }
}

/** A parsed daemon response, discriminated by its `response` field. */
@Serializable
data class TaggedResponse(
    val response: String,
)

/** The `hello` response payload. */
@Serializable
data class HelloPayload(
    val version: Int = 0,
    val root: Boolean = false,
    val layout: String = "",
)

/** The `status` response payload. */
@Serializable
data class StatusPayload(
    val version: Int = 0,
    val root: Boolean = false,
    val euid: Int = 0,
    val layout: String = "",
    val userfs: String = "",
    val profile: String = "",
    val kernel: String = "",
    val arch: String = "",
    @SerialName("init_running") val initRunning: Boolean = false,
)

/** One privilege provider in a `providers` response. */
@Serializable
data class ProviderInfo(
    val name: String = "",
    val kind: String = "",
    val available: Boolean = false,
    val reason: String? = null,
)

/** One profile in a `profiles` response. */
@Serializable
data class ProfileInfo(
    val name: String = "",
    val upper: String = "upper",
    val work: String = "work",
    val lower: List<String> = emptyList(),
    @SerialName("rw_user_system") val rwUserSystem: Boolean = false,
    val active: Boolean = false,
)
