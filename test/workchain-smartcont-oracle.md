# Smart-contract regression oracle

CTest now passes TEST_OPTIONS to test-smartcont, including the committed answer
file. The four live Toslib rows were regenerated separately into four empty
scratch answer files. No batch refresh was performed.

| Row | Disposition |
| --- | --- |
| GenZerostateFiftRegression | 82bf2a... -> 512112...; the fixture now selects test global ID -23901, and the generator carries wc=2, version 16, identity configuration and ledger. State sizes/hashes change; deterministic system address bytes remain fixed. |
| GovernanceProposalFiftScriptRegression | Original 2292e0... reproduced exactly; unchanged. |
| GovernanceVoteFiftScriptRegression | Original db3f63... reproduced exactly; unchanged. |
| ValidatorFiftScriptRegression | Original 9db405... reproduced exactly; unchanged. |
| GenZerostateAllchainsFiftRegression | Removed orphan answer; no corresponding registered test remains. |
| GenZerostateTestFiftRegression | Removed orphan answer; no corresponding registered test remains. |

The old genesis answer hash alone does not provide its original BOC preimage.
The new canonical result text is archived in full alongside the four independent
runs. Descriptor consolidation subsequently reproduced the same 512112... value;
it does not account for an additional output change.
