# Node linkage follow-up final checks

After restoring the default-OFF mutation, the complete build-wiring suite ran
against the final test source (SHA-256
`1002fe6eaac010700d3971e1ef069cc6c07f40d8d9aa72f7925cac40c9f6a0b6`).

```text
..
----------------------------------------------------------------------
Ran 2 tests in 35.084s

OK
```

Exit status: 0. The mutation itself configured successfully and failed on the
presence of the unexpected node-link CTest, not an error-text assertion.
Independent reconstruction of its exact replacement produced observed mutant
SHA-256 `ec00f7358fde60cd0b1621a093bfdc16db32d9b2ceca95c814fe1e7f60484c54`;
restoration produced `98c5eff9b6186132b04872cf35550cef7fd681da818ac1ccc380bc26204aa49d`.

The intermediate scan covered 5,330 text files. After adding this final-check
record with intent-to-add, the repeated scan covered 5,331 text files and
passed (378 binary files, zero directories skipped). These are successive
enumerations, not claims that the earlier scan saw later files. No policy
exemption was added for evidence. The restored OFF node was checked again:
all three kernel entry symbol counts were zero. The original five crypto CTests
also passed again (10.07 seconds total); no source changed after restoration.
