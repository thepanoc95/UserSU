#!/system/bin/sh
export CLASSPATH=/data/data/dev.github.thepanoc95.usersu/files/bin/usersu-server.dex
exec app_process /system/bin dev.github.thepanoc95.usersu.server.UserSUServer "$@"
