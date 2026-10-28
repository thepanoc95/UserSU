#!/system/bin/sh
export CLASSPATH=/data/local/tmp/usersu/bin/usersu-server.dex
exec app_process /system/bin dev.github.thepanoc95.usersu.server.UserSUServer "$@"
