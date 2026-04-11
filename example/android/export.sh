#!/bin/sh
pushd .
mkdir -p build_native
cd build_native
cmake -DTOS_ONLY_TOSLIB=ON -DBUILD_SHARED_LIBS=OFF .. || exit 1
cmake --build . --target prepare_cross_compiling || exit 2
#cmake --build . --target tl_generate_java || exit 1
popd
php AddIntDef.php src/drinkless/org/tos/TosApi.java || exit 1

./build-all.sh || exit 1

rm -rf toslib_export
mkdir -p toslib_export/toslib
echo src libs | xargs tar -c | tar -C toslib_export/toslib -xv

pushd .
cd toslib_export/toslib
#TODO javadoc
#javadoc -d javadoc -bootclasspath $ANDROID_SDK_ROOT/platforms/android-28/android.jar -extdirs ../../../../annotations/ -classpath java org.drinkless.td.libcore.telegram
popd

cd toslib_export
find . -name '.DS_Store' -type f -print0 | xargs -0 rm -f
jar -cMf toslib_debug.zip toslib
#zip -r toslib_debug libtd
rm toslib/libs/*/*.debug
jar -cMf toslib.zip toslib
#zip -r toslib libtd
