#!/usr/bin/env python3
"""Resolver calibration: intentionally fails until the shared helper is wired.

The helper location/API is owned by the shared activation-helper unit. There is
no fallback classifier here. This driver does not simulate collator transactions
or candidate export; those observations belong to later live callers.
"""
import argparse
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--probe', required=True)
    parser.add_argument('--repo', required=True)
    args = parser.parse_args()
    result = subprocess.run([args.probe], check=False, capture_output=True)
    print(result.stdout.decode(), end='')
    if result.returncode:
        raise RuntimeError('resolver probe failed; disabled success requires immediate coordinator report')
    raise RuntimeError('shared activation helper integration pending; no classification performed')


if __name__ == '__main__':
    main()
