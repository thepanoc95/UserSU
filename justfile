default:
    cd psu && cargo build --release
    scripts/mksandbox -in sandbox/proot -out sandbox.bz2
    scripts/mkpackage

android:
    cd psu && cargo build --release
    scripts/mksandbox -in sandbox/proot -out sandbox.bz2
    cd usersu && gradle assembleRelease

clean:
    cd psu && cargo clean
    cd usersu && gradle clean
    rm -rf sandbox.bz2
