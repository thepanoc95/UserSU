package me.usersu.manager.data

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * These tests pin the Kotlin request encoding to the exact JSON serde emits for
 * the Rust `Request` enum. If either side drifts, the daemon stops understanding
 * the manager, so the shapes are asserted literally rather than structurally.
 */
class ProtocolTest {
    @Test
    fun `handshake is a tagged object`() {
        assertEquals(
            """{"hello":{"version":1,"client":"manager"}}""",
            Protocol.hello().toString(),
        )
    }

    @Test
    fun `unit variants are bare strings`() {
        assertEquals("\"status\"", Protocol.status().toString())
        assertEquals("\"get-config\"", Protocol.getConfig().toString())
        assertEquals("\"list-profiles\"", Protocol.listProfiles().toString())
        assertEquals("\"providers\"", Protocol.providers().toString())
        assertEquals("\"shutdown\"", Protocol.shutdown().toString())
    }

    @Test
    fun `su keeps the crate's snake_case field names`() {
        // Exactly what serde emits for the Rust `Request::Su`.
        val expected = buildJsonObject {
            putJsonObject("su") {
                put("command", JsonArray(listOf(JsonPrimitive("id"))))
                put("uid", 0)
                put("gid", 0)
                put("keep_env", true)
                put("wants_stdio", false)
            }
        }
        assertEquals(expected.toString(), Protocol.su(listOf("id"), 0, 0, true).toString())
    }

    @Test
    fun `struct variants nest their payload`() {
        assertEquals(
            """{"activate-profile":{"name":"work"}}""",
            Protocol.activateProfile("work").toString(),
        )
        assertEquals(
            """{"list-dir":{"path":"/system"}}""",
            Protocol.listDir("/system").toString(),
        )
        assertEquals(
            """{"remove-file":{"path":"tmp/x"}}""",
            Protocol.removeFile("tmp/x").toString(),
        )
    }

    @Test
    fun `file writes send a number array, not base64`() {
        // serde renders a Rust `Vec<u8>` as an array of numbers.
        assertEquals(
            """{"write-file":{"path":"a","data":[104,105]}}""",
            Protocol.writeFile("a", byteArrayOf(104, 105)).toString(),
        )
    }

    @Test
    fun `status payload tolerates unknown fields`() {
        val payload = Protocol.json.decodeFromString<StatusPayload>(
            """{"version":1,"root":false,"euid":1000,"layout":"fuse","userfs":"/u",
               "profile":"default","kernel":"6.8","arch":"x86_64","init_running":true,
               "something_new":42}""",
        )
        assertEquals("fuse", payload.layout)
        assertEquals(true, payload.initRunning)
    }
}
