# UserSU

<img width="100" height="100" alt="SpoofySu Logo" src="./usersu_logo.png" />

UserMode root solution for Android devices

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](http://unlicense.org/)
[![Made with Rust](https://img.shields.io/badge/Made%20with-Rust-orange.svg)](https://www.rust-lang.org/)

## What is this?

So basically I got tired of all the hassle with unlocking bootloaders, flashing boot images, and risking bricking my devices just to get root access. SpoofySu is my solution - it's a userland root environment that tricks apps into thinking you have root without actually modifying anything on your device.

It's written in Rust because I wanted something fast and memory-safe, plus Rust on Android is pretty cool to work with.

## Features

- No bootloader unlock needed
- No boot image flashing
- Creates a fake root filesystem in `/sdcard/SpoofySu/`
- Spoofs all the environment variables apps check for root
- Interactive root shell with `psu` command
- Execute commands as "root" with `psudo`
- Works on any Android device (tested on my motorola harpia and moto g54)
- Pretty terminal colors because why not

## How does it work?

It's actually pretty simple. SpoofySu runs entirely in userspace and does three main things:

1. **Spoofs your environment variables** - Changes USER to "root", UID to 0, HOME to our fake root directory, etc.
2. **Creates a mini Unix filesystem** - Sets up `/sdcard/SpoofySu/` with all the standard directories like `/bin`, `/etc`, `/root`, etc.
3. **Manipulates your PATH** - Puts our fake filesystem first so commands find our stuff before the real system

The cool part is everything is sandboxed. When you "modify" system files, you're actually just editing files in `/sdcard/SpoofySu/`. Your actual system stays completely untouched.

## Building

You'll need Rust and the Android NDK. I usually build on my laptop but you can also build directly on your phone with Termux which is neat.

```bash
# Clone it
git clone https://github.com/oakymacintosh/spoofysu
cd spoofysu

# Build for Android
cargo ndk -t arm64-v8a build --release

# Or if you're in Termux on your phone
pkg install rust
cargo build --release
```

## Installation

```bash
# Push to your device
adb push target/aarch64-linux-android/release/envspoof /data/local/tmp/
adb shell chmod +x /data/local/tmp/envspoof

# Or in Termux just copy it
cp target/release/envspoof $PREFIX/bin/

# Install the aliases (this adds psu and psudo to your shell)
envspoof install
source ~/.bashrc
```

## Usage

```bash
# Check if everything is working
envspoof status

# Enter a root shell
psu

# Or run a single command
psudo whoami
```

Here's what it looks like when you use it:

```bash
$ psu
[*] Current UID: $
[!] UserSU is in constant development and is still a WIP project, most applications that use root privileges won't see UserSU's `psu` or `psudo`.

root@android:~# whoami
root
root@android:~# pwd
/root
root@android:~# exit
```

## The fake filesystem

First time you run it, SpoofySu creates this structure in `/sdcard/SpoofySu/`:

```
SpoofySu/
├── bin/          <- your "root" executables
├── sbin/         <- system binaries
├── etc/          <- config files (passwd, group, hosts, etc)
├── root/         <- root's home directory
├── home/         <- user home directories
├── tmp/          <- temp files
├── usr/          <- user programs
│   ├── bin/
│   ├── sbin/
│   └── lib/
└── var/          <- variable data
```

You can add your own scripts to `bin/`, edit config files in `etc/`, basically treat it like a real root filesystem.

## What works and what doesn't

**Works:**
- Apps that check environment variables for root
- Running shell scripts that expect root
- Modifying "system" files (they go to our sandbox)
- Learning about how root detection works
- Testing apps in a root-like environment

**Doesn't work:**
- Apps with kernel-level root checks (SafetyNet, banking apps, etc)
- Anything that needs actual kernel privileges
- Modifying the real system partition (by design!)
- Magisk modules (though I'm planning on compatibility)

This isn't a replacement for actual root. It's more like a development/testing tool or for apps that only do basic root checks.

## TODO

I'm still working on this project. Here's what I want to add:

- [ ] A proper GUI app instead of just CLI
- [ ] Better su binary emulation
- [ ] App-specific environment spoofing
- [ ] Maybe some basic Magisk compatibility
- [ ] More bypass techniques for root detection

## Why did I make this?

Mostly for fun and learning Rust better. But also because I have a work phone I can't unlock the bootloader on, and I wanted to test some root apps. This seemed like a good middle ground.

It's also useful if you're developing Android apps and want to test root detection without constantly switching between rooted/unrooted devices.

## Integration with other tools

Works pretty well with:
- **Shizuku** - Can enhance the fake root environment
- **Termux** - Great combo for a full Linux-like experience
- **ADB** - Obviously lol

## Contributing

If you want to contribute, cool! Just open a PR. I'm not super strict about code style or anything, just make sure it compiles and doesn't break existing stuff.

Bug reports and feature requests are welcome too.

## Community

I set up a Telegram channel for this project:
[Join here](https://t.me/usersu_root)

Feel free to ask questions or share what you're using it for!

## Credits

This project is inspired by the [OpenRoot](https://github.com/oakymacintosh/openroot) root-emulation approach I worked on before.

Built with: Rust, Clap, Colorize, Tokio

## License

Unlicense - public domain. Do whatever you want with it, no attribution needed (but appreciated).

---

**Heads up:** This is for educational/development purposes. Don't use it to bypass security on apps where you shouldn't have root access. Be responsible.

Also this is still kinda experimental so bugs are expected. Report them and I'll try to fix them when I have time.
