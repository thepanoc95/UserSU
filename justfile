default: build

build:
	# 1. Build Rust CLIs for Android
	cd psu && cargo ndk -t arm64-v8a build --release
	
	# 2. Compile LD_PRELOAD Hook
	aarch64-linux-android34-clang -shared -fPIC -o sandbox/proot/libusersuhook.so sandbox/proot/libusersuhook.c -ldl
	
	# 3. Ensure assets directory exists and download static proot if needed
	mkdir -p usersu/src/main/assets
	if [ ! -f usersu/src/main/assets/proot ]; then \
		curl -L -o usersu/src/main/assets/proot https://github.com/proot-me/proot-static-builds/raw/master/proot-aarch64; \
	fi
	
	# 4. Copy CLI, Hook, and Shell redirection scripts to assets
	cp psu/target/aarch64-linux-android/release/psu usersu/src/main/assets/psu 2>/dev/null || true
	cp psu/target/aarch64-linux-android/release/psudo usersu/src/main/assets/psudo 2>/dev/null || true
	cp sandbox/proot/libusersuhook.so usersu/src/main/assets/libusersuhook.so
	cp sandbox/proot/su usersu/src/main/assets/su
	cp sandbox/proot/start.sh usersu/src/main/assets/start.sh
	cp sandbox/proot/startkernel.sh usersu/src/main/assets/startkernel.sh
	
	# 5. Compile Java daemon and Manager app via Gradle
	gradle assembleRelease

# Run Dart tests
test-dart:
	cd dart && dart test

# Compile Dart su binary for host (AOT)
compile-su-dart:
	cd dart && dart compile exe bin/su.dart -o build/su

clean:
	cd psu && cargo clean
	gradle clean
	rm -rf usersu/src/main/assets/*
	rm -rf sandbox/proot/libusersuhook.so
