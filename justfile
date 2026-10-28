default: build

APK := "usersu/build/outputs/apk/release/usersu-release-unsigned.apk"
SIGNED_APK := "usersu/build/outputs/apk/release/usersu-release.apk"
HOME := env_var("HOME")
ANDROID_HOME := env_var("ANDROID_HOME")

build:
	# 0. Ensure debug keystore exists
	if [ ! -f "{{HOME}}/.android/debug.keystore" ]; then \
		echo "Generating debug keystore..."; \
		keytool -genkey -v -keystore "{{HOME}}/.android/debug.keystore" \
			-storepass android -alias androiddebugkey -keypass android \
			-keyalg RSA -keysize 2048 -validity 10000 \
			-dname "CN=Android Debug,O=Android,C=US"; \
	fi

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

	# 6. Sign the APK with debug key
	if [ -f "{{APK}}" ]; then \
		_SDK="{{ANDROID_HOME}}"; \
		_APKSIGNER=`ls "$_SDK"/build-tools/*/apksigner 2>/dev/null | head -1`; \
		if [ -n "$_APKSIGNER" ]; then \
			"$_APKSIGNER" sign --ks "{{HOME}}/.android/debug.keystore" --ks-pass pass:android \
				--ks-key-alias androiddebugkey "{{APK}}" && \
			cp "{{APK}}" "{{SIGNED_APK}}" && \
			echo "✓ Signed APK: {{SIGNED_APK}}"; \
		else \
			echo "⚠ apksigner not found, APK left unsigned"; \
		fi; \
	fi

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
