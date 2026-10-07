#!/bin/bash
set -euo pipefail
REPO_ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)

if [ ! -d "artifacts" ]; then
  echo "No artifacts found."
  exit 2
fi
# x86_64 or aarch64
ARCH=$1
case "$ARCH" in x86_64|aarch64) ;; *) echo "unsupported architecture" >&2; exit 1 ;; esac

rm -rf appimages

mkdir -p appimages/artifacts

wget -nc https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-$ARCH.AppImage
python3 "$REPO_ROOT/scripts/verify-build-tool.py" "appimagetool-$ARCH" "appimagetool-$ARCH.AppImage"
chmod +x ./appimagetool-$ARCH.AppImage

cd appimages
for file in ../artifacts/*; do
  if [[ -f "$file" && "$file" != *.so ]]; then
    appName=$(basename "$file")
    echo $appName
    # prepare AppDir
    mkdir -p $appName.AppDir/usr/{bin,lib}
    cp ../AppRun $appName.AppDir/AppRun
    sed -i "s/app/$appName/g" $appName.AppDir/AppRun
    chmod +x ./$appName.AppDir/AppRun
    printf '[Desktop Entry]\nName='$appName'\nExec='$appName'\nIcon='$appName'\nType=Application\nCategories=Utility;\n' > $appName.AppDir/$appName.desktop
    cp ../tos.png $appName.AppDir/$appName.png
    cp $file $appName.AppDir/usr/bin/
    cp /lib/$ARCH-linux-gnu/libatomic.so.1 \
      /lib/$ARCH-linux-gnu/libreadline.so.8 \
      /lib/$ARCH-linux-gnu/libstdc++.so.6 \
      /lib/$ARCH-linux-gnu/libgsl.so.27 \
      /lib/$ARCH-linux-gnu/libblas.so.3 \
      /lib/$ARCH-linux-gnu/libgslcblas.so.0 \
      $appName.AppDir/usr/lib/

    chmod +x ./$appName.AppDir/usr/bin/$appName
    # create AppImage
    ./../appimagetool-$ARCH.AppImage -l $appName.AppDir
    mv $appName-$ARCH.AppImage artifacts/$appName
  fi
done

ls -larth artifacts
cp -r ../artifacts/{smartcont,lib} artifacts/
pwd
ls -larth artifacts
