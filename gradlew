#!/usr/bin/env sh
# Gradle Wrapper script for Unix
# This script bootstraps the Gradle Wrapper.
APP_NAME="gradlew"
APP_HOME=$(cd "$(dirname "$0")" && pwd)
GRADLE_WRAPPER_JAR="$APP_HOME/gradle/wrapper/gradle-wrapper.jar"
exec java -classpath "$GRADLE_WRAPPER_JAR" org.gradle.wrapper.GradleWrapperMain "$@"
