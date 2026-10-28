# UserSU Manager

The Android front end for `usud`, built with Jetpack Compose and Material 3.

The app does not ship the backend. It talks to a running `usud` over the daemon
socket, using the same framed protocol as the CLI but with a JSON payload
instead of bincode.

## Building

Requires the Android SDK, a JDK 17, and Gradle.

```sh
gradle :app:assembleDebug
```

The Gradle wrapper JAR is a binary and is not committed, so `gradle/wrapper` only
carries the properties file. Generate the wrapper once with a system Gradle if
you prefer `./gradlew`:

```sh
gradle wrapper
./gradlew :app:assembleDebug
```

## Screens

* **Home** — daemon status and the privilege-provider report.
* **Superuser** — the active profile and the list of profiles to switch between.
* **UserFS** — a browser for the merged layer tree.
* **Settings** — daemon details, the socket paths, refresh and stop.

## Talking to usud

`data/Protocol.kt` mirrors the Rust protocol types. `data/UsudClient.kt` opens a
filesystem-namespace Unix domain socket (`LocalSocket`), performs the JSON
handshake, and decodes tagged replies. `data/ManagerViewModel.kt` runs all
traffic on the IO dispatcher and exposes immutable state to the UI.

Socket candidates, tried in order:

```
/data/me.usersu/usud.sock
/data/data/me.usersu/files/usud.sock
```

The first is the root layout; the second is the fallback usud uses when it does
not have root.
