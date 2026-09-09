# Node linkage domain-scan controls

This is a historical execution record, not a claim that the scan included
untracked artifacts. The recorded final scan predates staging these files;
the final integration scan must include all new tracked evidence. Retired
symbols below are deliberate negative inputs, not implementation code.

```json
{
  "records": [
    {
      "file": "scripts/check-no-removed-execution-domains.sh",
      "from": "    \"validator-engine/CMakeLists.txt\",",
      "to": "    # Mutation control: remove the approved node build path.",
      "before": {
        "cmd": "sha256sum scripts/check-no-removed-execution-domains.sh",
        "exit_code": 0,
        "output": "998dacf9918129387b29cf3d6d54f2b64d3529004faa58dea36e5204c6802ef1  scripts/check-no-removed-execution-domains.sh\n"
      },
      "mutant": {
        "cmd": "sha256sum scripts/check-no-removed-execution-domains.sh",
        "exit_code": 0,
        "output": "bc50548f1be7ae1b611707c02cb7db7ae0adfd7796faf3630aaae4e0ba8a99f3  scripts/check-no-removed-execution-domains.sh\n"
      },
      "test": {
        "cmd": "scripts/check-no-removed-execution-domains.sh",
        "exit_code": 1,
        "output": "validator-engine/CMakeLists.txt:48: Uno outside approved engine paths: if (TOS_UNO_CRYPTO_NODE_LINK)\nremoved-execution-domain scan failed\n"
      },
      "after": {
        "cmd": "sha256sum scripts/check-no-removed-execution-domains.sh",
        "exit_code": 0,
        "output": "998dacf9918129387b29cf3d6d54f2b64d3529004faa58dea36e5204c6802ef1  scripts/check-no-removed-execution-domains.sh\n"
      },
      "restored": true
    },
    {
      "file": "validator-engine/CMakeLists.txt",
      "from": "if (TOS_UNO_CRYPTO_NODE_LINK)",
      "to": "if (TOS_UNO_CRYPTO_NODE_LINK)\n  # UnoToken",
      "before": {
        "cmd": "sha256sum validator-engine/CMakeLists.txt",
        "exit_code": 0,
        "output": "93060e22ed684c1f72d8789ca08a179da45f5041068dee94eb61fc07fafb9cd9  validator-engine/CMakeLists.txt\n"
      },
      "mutant": {
        "cmd": "sha256sum validator-engine/CMakeLists.txt",
        "exit_code": 0,
        "output": "6863d4699ea5ec3c810a9dc5e76f121983b928a36008d6ad3570231e9c5ea1b4  validator-engine/CMakeLists.txt\n"
      },
      "test": {
        "cmd": "scripts/check-no-removed-execution-domains.sh",
        "exit_code": 1,
        "output": "validator-engine/CMakeLists.txt:49: retired implementation symbol: UnoToken:   # UnoToken\nremoved-execution-domain scan failed\n"
      },
      "after": {
        "cmd": "sha256sum validator-engine/CMakeLists.txt",
        "exit_code": 0,
        "output": "93060e22ed684c1f72d8789ca08a179da45f5041068dee94eb61fc07fafb9cd9  validator-engine/CMakeLists.txt\n"
      },
      "restored": true
    }
  ],
  "final": {
    "cmd": "scripts/check-no-removed-execution-domains.sh",
    "exit_code": 0,
    "output": "removed-execution-domain scan passed: 5321 text files, 378 binary files and 0 directories skipped\n"
  }
}
```
