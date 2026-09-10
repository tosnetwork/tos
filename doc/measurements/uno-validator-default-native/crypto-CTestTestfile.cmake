# CMake generated Testfile for 
# Source directory: /home/tomi/tos-m2/crypto
# Build directory: /tmp/uno-publication-build/crypto
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(test-workchain-instance-identity "/tmp/uno-publication-build/crypto/test-workchain-instance-identity")
set_tests_properties(test-workchain-instance-identity PROPERTIES  LABELS "private;workchain;d40" TIMEOUT "60" _BACKTRACE_TRIPLES "/home/tomi/tos-m2/crypto/CMakeLists.txt;691;add_test;/home/tomi/tos-m2/crypto/CMakeLists.txt;0;")
add_test(test-workchain-genesis-installation "/home/tomi/.local/bin/python3" "/home/tomi/tos-m2/crypto/test/workchain-genesis-installation.py" "--repo" "/home/tomi/tos-m2" "--create-state" "/tmp/uno-publication-build/crypto/create-state" "--probe" "/tmp/uno-publication-build/crypto/test-workchain-instance-callsite")
set_tests_properties(test-workchain-genesis-installation PROPERTIES  LABELS "private;workchain;d40" TIMEOUT "180" _BACKTRACE_TRIPLES "/home/tomi/tos-m2/crypto/CMakeLists.txt;694;add_test;/home/tomi/tos-m2/crypto/CMakeLists.txt;0;")
add_test(test-workchain-handwritten-tags "/home/tomi/.local/bin/python3" "/home/tomi/tos-m2/crypto/test/workchain-handwritten-tags.py" "--repo" "/home/tomi/tos-m2")
set_tests_properties(test-workchain-handwritten-tags PROPERTIES  LABELS "workchain;d40" TIMEOUT "30" _BACKTRACE_TRIPLES "/home/tomi/tos-m2/crypto/CMakeLists.txt;703;add_test;/home/tomi/tos-m2/crypto/CMakeLists.txt;0;")
add_test(test-workchain-validator-prepared-expiry "/home/tomi/.local/bin/python3" "/home/tomi/tos-m2/crypto/test/workchain-validator-prepared-expiry.py" "--repo" "/home/tomi/tos-m2")
set_tests_properties(test-workchain-validator-prepared-expiry PROPERTIES  LABELS "workchain;prepared-expiry" TIMEOUT "30" _BACKTRACE_TRIPLES "/home/tomi/tos-m2/crypto/CMakeLists.txt;709;add_test;/home/tomi/tos-m2/crypto/CMakeLists.txt;0;")
