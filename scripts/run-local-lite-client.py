#!/usr/bin/env python3
"""Standalone read-only lite-client health queries; no wallet commands."""

import subprocess
import time


def main():
    while True:
        try:
            result = subprocess.run(
                [
                    "/usr/local/bin/tos-lite-client",
                    "-C",
                    "/data/configs/observers-lite.json",
                    "-v",
                    "0",
                    "-c",
                    "last",
                ],
                timeout=20,
                check=False,
            )
            print(f"lite-client query exit={result.returncode}", flush=True)
        except subprocess.TimeoutExpired:
            print("lite-client query timed out", flush=True)
        time.sleep(10)


if __name__ == "__main__":
    main()
