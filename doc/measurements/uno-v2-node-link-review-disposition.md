# Experimental node-link review disposition

This unit is linkage evidence, not M2 acceptance, host invocation, or permission
to execute a confidential workchain. Raw review is retained in the internal
review archive.

- B1 accepted: two evidence records now use fenced JSON in Markdown, following
  the existing policy for documentation of deliberately retired test tokens.
  No scanner exception was added for evidence. All seven new files were added
  to the index with intent-to-add before repeating the scan: initially 5,328
  text files passed; subsequent records bring the final scan to 5,331. The
  earlier 5,321-file scan excluded those files and is not final-tree
  evidence. Historical command outputs remain unchanged.
- N1 accepted in part: fresh configuration now asserts that prototype tests ON
  does not register the node-link test without explicit node opt-in. The OFF
  executable symbol check remains manually recorded, not a default CTest gate.
  Absence of packaging/CI implicit enablement is likewise inspection evidence,
  not an automated assertion. The build-wiring test is not a default workflow.
- N2 deliberate: the approved node build path is explicitly allowlisted like
  other build entry points. This does not exempt it from retired-symbol or EVM
  checks; injection inside that same file fails. No extension-wide exemption.
- N3 accepted: land the preparatory guard change separately before linkage.
- N4 retained limitation: the helper has one caller and one fixed test name;
  calling it twice fails configuration rather than silently omitting a test.
- N5 narrowed: ON/OFF is configuration evidence plus a check of the existing
  ON/ON executable; its command log does not demonstrate another link. The
  OFF/ON restoration does relink. Do not count configuration changes as builds.
- N6/N7 retained limits: symbol presence proves retention, not provenance,
  execution, initializer equivalence, or unchanged memory/CPU cost. The linked
  executable's version command succeeds; this is not general node acceptance.
- N8 retained: the build-wiring test is not a standing default workflow gate.
  Its recorded run and mutations are one-time evidence. Existing kernel gates
  were not weakened.
- N9 retained: an overriding CMake program search environment can cause a
  diagnostic false failure of the controlled cargo fixture, not a false pass.

The matrix's test-file hash predates the additional default-OFF assertion.
The follow-up control records that final test source separately; no historical
hash or command output has been overwritten to imply it measured newer code.
