# Generation of Toslib libraries for Android OS
**Tl;dr** Download the latest version of Toslib libraries for Android from TOS release page or check the artifacts from [Android JNI GitHub action](https://github.com/tosnetwork/tos/actions/workflows/toslib-android-jni.yml).

## Compile Toslib for Android manually
Prerequisite: installed Java and set environment variable JAVA_HOME.
```bash
git clone --recursive https://github.com/tosnetwork/tos.git
cd tos
cp assembly/android/build-android-toslib.sh .
chmod +x build-android-toslib.sh
sudo -E ./build-android-toslib.sh
```
# Generation of Toslib libraries for iOS in Xcode

1. Clone repository https://github.com/labraburn/tonlib-xcframework
2. Open repository directory in Terminal
3. Run command:
```bash
swift run builder --output ./build --clean
```
5. Run command:
```bash
echo ./build/TOS.xcframework/* | xargs -n 1 cp -R ./Resources/Headers
````
7. Import **OpenSSL.xcframework** and **TOS.xcframework** in XCode in section _"Frameworks, Libraries, and Embedded Content"_
8. Now you can start using Toslib client by importing it in C or Objective-C source files:
```objective-c
#import <toslib/toslib_client_json.h>
```

# Generation of Toslib libraries for Desktop applications
You can use Toslib compiled in an ordinary way for desktop applications. If you use Java you can load the library using JNA.

The latest Toslib library can be found among other TOS artifacts either on TOS release page or inside the [appropriate GitHub action](https://github.com/tosnetwork/tos/actions/).