package me.usersu.manager.data

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** What the UI is currently showing. */
sealed interface UiState {
    /** Nothing loaded yet. */
    data object Loading : UiState

    /** The daemon replied; `status` is the freshest snapshot. */
    data class Ready(
        val status: StatusPayload,
        val providers: List<ProviderInfo>,
        val profiles: List<ProfileInfo>,
    ) : UiState

    /** The daemon could not be reached, with the reason. */
    data class Unavailable(val reason: String) : UiState
}

/** A one-shot message for a snackbar. */
data class Notice(val text: String, val isError: Boolean = false)

/** The UserFS browser's state. */
data class BrowserState(
    val path: String = "/",
    val entries: List<String> = emptyList(),
    val error: String? = null,
)

/**
 * Drives the manager UI.
 *
 * All daemon traffic happens on the IO dispatcher; the UI only ever sees
 * immutable [UiState] snapshots.
 */
class ManagerViewModel(
    private val client: UsudClient = UsudClient(),
) : ViewModel() {
    private val _state = MutableStateFlow<UiState>(UiState.Loading)
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _notice = MutableStateFlow<Notice?>(null)
    val notice: StateFlow<Notice?> = _notice.asStateFlow()

    /** The UserFS browser's current directory and its entries. */
    private val _browser = MutableStateFlow(BrowserState())
    val browser: StateFlow<BrowserState> = _browser.asStateFlow()

    init {
        refresh()
    }

    /** Reloads status, providers and profiles. */
    fun refresh() {
        viewModelScope.launch {
            _state.value = UiState.Loading
            _state.value = withContext(Dispatchers.IO) { load() }
        }
    }

    /** Loads a UserFS directory into the browser. */
    fun browse(path: String) {
        viewModelScope.launch {
            val next = withContext(Dispatchers.IO) {
                try {
                    when (val reply = client.call(Protocol.listDir(path))) {
                        is Reply.Listing -> BrowserState(path, reply.entries)
                        is Reply.Failure -> BrowserState(path, emptyList(), reply.message)
                        else -> BrowserState(path, emptyList(), "unexpected reply")
                    }
                } catch (e: Exception) {
                    BrowserState(path, emptyList(), e.message ?: "unreachable")
                }
            }
            _browser.value = next
        }
    }

    /** Stops the daemon, then reloads so the UI shows it is gone. */
    fun shutdown() {
        viewModelScope.launch {
            val text = withContext(Dispatchers.IO) {
                try {
                    noticeFor(client.call(Protocol.shutdown()))
                } catch (e: Exception) {
                    Notice("could not stop usud: ${e.message}", isError = true)
                }
            }
            _notice.value = text
            refresh()
        }
    }

    private fun load(): UiState = try {
        val status = (client.call(Protocol.status()) as? Reply.Status)?.payload
            ?: return UiState.Unavailable("usud returned no status")
        val providers = (client.call(Protocol.providers()) as? Reply.Providers)?.providers.orEmpty()
        val profiles = (client.call(Protocol.listProfiles()) as? Reply.Profiles)?.profiles.orEmpty()
        UiState.Ready(status, providers, profiles)
    } catch (e: Exception) {
        UiState.Unavailable(e.message ?: e::class.java.simpleName)
    }

    /** Switches the active profile, then reloads. */
    fun activateProfile(name: String) {
        viewModelScope.launch {
            val text = withContext(Dispatchers.IO) {
                try {
                    noticeFor(client.call(Protocol.activateProfile(name)))
                } catch (e: Exception) {
                    Notice("could not activate $name: ${e.message}", isError = true)
                }
            }
            _notice.value = text
            refresh()
        }
    }

    /** Boots the sandboxed init system. */
    fun bootInit() {
        viewModelScope.launch {
            val text = withContext(Dispatchers.IO) {
                try {
                    when (val reply = client.call(Protocol.boot(init = null, args = emptyList()))) {
                        is Reply.Executed -> Notice("init exited with ${reply.code ?: "a signal"}")
                        is Reply.Failure -> Notice("boot failed: ${reply.message}", isError = true)
                        else -> Notice("unexpected boot reply")
                    }
                } catch (e: Exception) {
                    Notice("boot failed: ${e.message}", isError = true)
                }
            }
            _notice.value = text
            refresh()
        }
    }

    /** Clears the current snackbar once it has been shown. */
    fun consumeNotice() {
        _notice.value = null
    }

    private fun noticeFor(reply: Reply): Notice = when (reply) {
        is Reply.Ok -> Notice(reply.message)
        is Reply.Failure -> Notice(reply.message, isError = true)
        else -> Notice("done")
    }
}
