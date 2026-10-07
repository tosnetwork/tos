#!/usr/bin/env python3
"""Exercise packaging scripts with approved and tampered cached tooling."""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def executable(path, text):
    path.write_text(text)
    path.chmod(0o700)

class PipelineTests(unittest.TestCase):
    def fixture(self, root):
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        (root/"scripts").mkdir()
        shutil.copy(ROOT/"scripts/verify-build-tool.py", root/"scripts/verify-build-tool.py")
        tools = root/"bin"; tools.mkdir()
        for name in ["wget", "make", "cmake", "ninja", "sed"]:
            executable(tools/name, "#!/bin/sh\nexit 0\n")
        env = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}", MARKER=str(root/"executed"), JAVA_HOME=str(root/"java"))
        return tools, env

    def test_appimage_cached_tools_are_verified_before_execution(self):
        for arch in ["x86_64", "aarch64"]:
            for tampered in [False, True]:
                with self.subTest(arch=arch, tampered=tampered), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp); tools, env = self.fixture(root)
                    env["TEST_ARCH"] = arch
                    approved = b'#!/bin/bash\ntouch "$MARKER" "${2%.AppDir}-${TEST_ARCH}.AppImage"\n'
                    tool = root/f"appimagetool-{arch}.AppImage"
                    tool.write_bytes(approved + (b"# changed bytes\n" if tampered else b""))
                    (root/"scripts/build-tool-pins.json").write_text(json.dumps({f"appimagetool-{arch}":{"sha256":hashlib.sha256(approved).hexdigest()}}))
                    script = root/"create-appimages.sh"
                    shutil.copy(ROOT/"assembly/appimage/create-appimages.sh", script)
                    for name in ["artifacts", "artifacts/lib", "artifacts/smartcont"]: (root/name).mkdir(exist_ok=True)
                    (root/"artifacts/program").write_text("program")
                    (root/"AppRun").write_text("app")
                    (root/"tos.png").write_text("icon")
                    # The fixture substitutes host libraries, while copying real
                    # fixture files with the system cp. No system path is written.
                    executable(tools/"cp", '''#!/bin/bash
last="${@: -1}"
for src in "${@:1:$#-1}"; do
  [[ "$src" = -* ]] && continue
  if [ -e "$src" ]; then /bin/cp -r "$src" "$last"; else touch "$last/$(basename "$src")"; fi
done
''')
                    result = subprocess.run(["bash", str(script), arch], cwd=root, env=env, capture_output=True)
                    self.assertEqual(result.returncode == 0, not tampered, result.stderr.decode())
                    self.assertEqual((root/"executed").exists(), not tampered)

    def test_android_cached_archive_is_verified_before_extraction(self):
        for tampered in [False, True]:
            with self.subTest(tampered=tampered), tempfile.TemporaryDirectory() as temp:
                root = Path(temp); tools, env = self.fixture(root)
                approved = b"approved archive fixture"
                (root/"android-ndk-r27d-linux.zip").write_bytes(approved + (b"tampered" if tampered else b""))
                (root/"scripts/build-tool-pins.json").write_text(json.dumps({"android-ndk-r27d":{"sha256":hashlib.sha256(approved).hexdigest()}}))
                script = root/"build-android-toslib.sh"
                shutil.copy(ROOT/"assembly/android/build-android-toslib.sh", script)
                (root/"third-party/openssl").mkdir(parents=True)
                (root/"example/android").mkdir(parents=True)
                (root/"example/android/build-all.sh").write_text("return 0\n")
                executable(tools/"unzip", '#!/bin/sh\ntouch "$MARKER"\n')
                result = subprocess.run(["bash", str(script)], cwd=root, env=env, capture_output=True)
                self.assertEqual(result.returncode == 0, not tampered, result.stderr.decode())
                self.assertEqual((root/"executed").exists(), not tampered)

if __name__ == "__main__": unittest.main()
