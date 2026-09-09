# Node linkage mutation restoration audit

The JSON below preserves exact mutation strings and observed hashes. Retired
symbols are negative test inputs, not executable implementation. Extract the
fenced JSON to repeat the reconstruction against the referenced source files.

```json
{
  "scope": "All five controls reconstructed from final source; no reconstructed value is substituted for the observed mutant hash.",
  "records": [
    {
      "kind": "retention",
      "source": "uno/crypto/CMakeLists.txt",
      "restored_sha256": "98c5eff9b6186132b04872cf35550cef7fd681da818ac1ccc380bc26204aa49d",
      "recorded_mutant_sha256": "e30e56fb5cfae30e04f914110e0867f6feee4ba9dcafb7507a408636ca3fd3db",
      "reconstructed_mutant_sha256": "e30e56fb5cfae30e04f914110e0867f6feee4ba9dcafb7507a408636ca3fd3db",
      "from_text": "  target_link_options(${node} PRIVATE\n    \"LINKER:--undefined=uno_crypto_verify_v2\"\n    \"LINKER:--undefined=uno_crypto_system_encrypt_v1\"\n    \"LINKER:--undefined=uno_crypto_system_verify_v1\")",
      "to_text": "  # Mutation control: intentionally omit entry-point retention."
    },
    {
      "kind": "cargo-fixture",
      "source": "uno/crypto/RequireCargo.cmake",
      "restored_sha256": "8cf88b805e9ffadbd593ea88a6f2a4c30a691ab03362e47c7934a96e690f70e9",
      "recorded_mutant_sha256": "b96758bb6c8de879cca013fdeea9bd40bf8fa2b11e8452d0fbc24d7f874b9184",
      "reconstructed_mutant_sha256": "b96758bb6c8de879cca013fdeea9bd40bf8fa2b11e8452d0fbc24d7f874b9184",
      "from_text": "      elseif (NOT _uno_cargo_version MATCHES \"^cargo 1\\\\.97\\\\.1 \")",
      "to_text": "      elseif (FALSE)"
    },
    {
      "kind": "cargo-fixture",
      "source": "uno/crypto/RequireCargo.cmake",
      "restored_sha256": "8cf88b805e9ffadbd593ea88a6f2a4c30a691ab03362e47c7934a96e690f70e9",
      "recorded_mutant_sha256": "ef48c8c1d42a5befc1cdb91b1b9da50cdf211d3e42664e8130385525c6194626",
      "reconstructed_mutant_sha256": "ef48c8c1d42a5befc1cdb91b1b9da50cdf211d3e42664e8130385525c6194626",
      "from_text": "      execute_process(COMMAND \"${CMAKE_COMMAND}\" -E env \"CARGO_NET_OFFLINE=true\" \"${_uno_cargo}\" --version",
      "to_text": "      execute_process(COMMAND \"${CMAKE_COMMAND}\" -E env \"${_uno_cargo}\" --version"
    },
    {
      "kind": "domain",
      "source": "scripts/check-no-removed-execution-domains.sh",
      "restored_sha256": "998dacf9918129387b29cf3d6d54f2b64d3529004faa58dea36e5204c6802ef1",
      "recorded_mutant_sha256": "bc50548f1be7ae1b611707c02cb7db7ae0adfd7796faf3630aaae4e0ba8a99f3",
      "reconstructed_mutant_sha256": "bc50548f1be7ae1b611707c02cb7db7ae0adfd7796faf3630aaae4e0ba8a99f3",
      "from_text": "    \"validator-engine/CMakeLists.txt\",",
      "to_text": "    # Mutation control: remove the approved node build path."
    },
    {
      "kind": "domain",
      "source": "validator-engine/CMakeLists.txt",
      "restored_sha256": "93060e22ed684c1f72d8789ca08a179da45f5041068dee94eb61fc07fafb9cd9",
      "recorded_mutant_sha256": "6863d4699ea5ec3c810a9dc5e76f121983b928a36008d6ad3570231e9c5ea1b4",
      "reconstructed_mutant_sha256": "6863d4699ea5ec3c810a9dc5e76f121983b928a36008d6ad3570231e9c5ea1b4",
      "from_text": "if (TOS_UNO_CRYPTO_NODE_LINK)",
      "to_text": "if (TOS_UNO_CRYPTO_NODE_LINK)\n  # UnoToken"
    }
  ]
}
```
