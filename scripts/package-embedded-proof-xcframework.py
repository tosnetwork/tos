#!/usr/bin/env python3
"""Package verified Apple mobile proof-library slices as an XCFramework."""
import argparse
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device', type=Path, required=True)
    parser.add_argument('--sim-arm64', type=Path, required=True)
    parser.add_argument('--sim-x86_64', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    slices = [(args.device, 'arm64', 'IOS'), (args.sim_arm64, 'arm64', 'IOSSIMULATOR'), (args.sim_x86_64, 'x86_64', 'IOSSIMULATOR')]
    for file, arch, platform in slices:
        metadata = subprocess.check_output(['xcrun', 'vtool', '-show-build', str(file)], text=True)
        platforms = [line.split()[-1] for line in metadata.splitlines() if line.strip().startswith('platform ')]
        arches = subprocess.check_output(['xcrun', 'lipo', '-archs', str(file)], text=True).strip().split()
        if platforms != [platform] or arches != [arch]:
            raise RuntimeError('Unexpected proof slice architecture/platform')
    output = args.output.resolve()
    if output.exists():
        parser.error('Output already exists; choose a fresh staging path')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='proof-framework-', dir=output.parent) as temporary:
        temp = Path(temporary)
        frameworks = []
        for name, binaries, platform in [('device', [args.device], 'iPhoneOS'), ('simulator', [args.sim_arm64, args.sim_x86_64], 'iPhoneSimulator')]:
            framework = temp / name / 'TOSProofVerify.framework'
            (framework / 'Headers').mkdir(parents=True)
            (framework / 'Modules').mkdir()
            binary = framework / 'TOSProofVerify'
            if len(binaries) == 1:
                shutil.copy2(binaries[0], binary)
            else:
                subprocess.run(['xcrun', 'lipo', '-create', *map(str, binaries), '-output', str(binary)], check=True)
            subprocess.run(['xcrun', 'install_name_tool', '-id', '@rpath/TOSProofVerify.framework/TOSProofVerify', str(binary)], check=True)
            for header in ['embedded.h', 'persisted.h']:
                shutil.copy2(root / 'lite-client/proof-verify' / header, framework / 'Headers' / header)
            (framework / 'Headers/TOSProofVerify.h').write_text('#include "embedded.h"\n#include "persisted.h"\n')
            (framework / 'Modules/module.modulemap').write_text('framework module TOSProofVerify {\n  umbrella header "TOSProofVerify.h"\n  export *\n}\n')
            info = {'CFBundleIdentifier': 'network.tos.proofverify', 'CFBundleExecutable': 'TOSProofVerify',
                    'CFBundleName': 'TOSProofVerify', 'CFBundlePackageType': 'FMWK', 'CFBundleVersion': '1',
                    'CFBundleShortVersionString': '1.0', 'CFBundleSupportedPlatforms': [platform], 'MinimumOSVersion': '15.0'}
            (framework / 'Info.plist').write_bytes(plistlib.dumps(info))
            frameworks += ['-framework', str(framework)]
        subprocess.run(['xcodebuild', '-create-xcframework', *frameworks, '-output', str(output)], check=True)


if __name__ == '__main__':
    main()
