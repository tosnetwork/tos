#!/bin/sh
cp -r src/* ./test/tos/src/main/java/
mkdir -p ./test/tos/src/cpp/prebuilt/
cp -r libs/* ./test/tos/src/cpp/prebuilt/
cd test
./gradlew connectedAndroidTest
