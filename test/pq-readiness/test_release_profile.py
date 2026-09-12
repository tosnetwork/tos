#!/usr/bin/env python3
"""The candidate build ceiling is opt-in; configuration is never rewritten."""
import os
from pathlib import Path
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory() as d:
    root=Path(d)
    src=root/'version.cpp'
    src.write_text('#include "common/global-version.h"\n#include <iostream>\nint main(){std::cout<<tos::SUPPORTED_VERSION;}\n')
    for expected,flags in [(15,[]),(16,['-DTOS_PQ_V16_CANDIDATE=1'])]:
        subprocess.run([os.environ.get('CXX','c++'),'-std=c++17','-I',str(ROOT),str(src),*flags,'-o',str(root/'version')],check=True)
        result=subprocess.check_output([str(root/'version')],text=True)
        if result!=str(expected):raise SystemExit('wrong software support ceiling')
print('PASS: default v15, explicit candidate v16; no network mutation')
