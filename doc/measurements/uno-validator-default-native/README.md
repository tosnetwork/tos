# Default prepared validator registration

Source: f488facc2 (full commit and source/tool hashes in manifest.json).
Root CMake now defines the native target, adds it to all-tests, and registers its expiry-wrapper test unconditionally. The separate source-only expiry test remains default in crypto/CMakeLists.txt. The historical optional module contains no duplicate definitions. Private scope does not mean optional execution.

## Commands and results

1. `cmake -S /home/tomi/tos-m2 -B /tmp/uno-publication-build -U CMAKE_PROJECT_TOS_INCLUDE`, then `cmake --build /tmp/uno-publication-build --target all-tests -j32`: exit 1. The retained log shows the existing Tol stdlib auto-discovery defect on five generated fixtures. It also records inherited cache Cargo parallelism 48; this was corrected to 32 in the subsequent configure. This run is not guard evidence.
2. Repeat configure with `-DUNO_CRYPTO_BUILD_JOBS=32`. Repeat all-tests with existing environment entrances `FUNC_BIN=/tmp/uno-publication-build/crypto/func`, `FIFT_BIN=/tmp/uno-publication-build/crypto/fift`, `TOL_STDLIB=/home/tomi/tos-m2/crypto/smartcont/tol-stdlib`: exit 0. No source workaround or symlink was added. The first run compiled the prepared fixture object; the corrected run linked its executable. Ninja's archived all-tests dependency query independently lists that target.
3. `ctest --test-dir /tmp/uno-publication-build -N -R '^test-workchain-validator-(local-visitors|prepared-expiry)$'`: lists both tests. The archived cache has no CMAKE_PROJECT_TOS_INCLUDE.
4. Same selection with `-V --output-junit /tmp/uno-validator-default-native-audit/ctest.xml`: 2 passed, zero failures/errors/skips. Full successful output is retained, including the native fixture result and source guard result.

This is a targeted registration/build verification, not a full CTest regression. Existing isolated production-removal controls 1350/1351 and missing-file 1352 are archived in ../uno-validator-prepared-default; this change does not alter that guard. It makes the native preparation fixture default as well. No production gates moved; neither test supplies a live ValidateQuery call-site claim. Prepared expiry still requires deletion and retargeting to production when the gate opens.
