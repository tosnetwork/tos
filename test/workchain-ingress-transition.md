# Ingress continuity and activation controls (D58)

The two ordinary `test-counter-activation-*` registrations now run the existing
real scoped-resolver probe and shared activation classifier. They retain Param84
and construct inconsistent inputs directly in memory. They do not ask the genesis
generator to emit an invalid configuration. No deployment configuration is read
or changed, and no transaction count or candidate-export observation is simulated.
The former bootstrap failures are historical results, not current deferrals.

`test-workchain-ingress-transition.cpp` calls production
`valid_config_transition` and `validate_native_ingress_presence`. Cases 1231 and
1232 separately remove the whole ingress table and its workchain-2 entry while
preserving the same Param12 dictionary. Both reject; case 1230 accepts unchanged
content. The premise is an existing ingress entry, not arbitrary membership in
Param12: cases 1240/1241 exercise a descriptor without ingress successfully.

The transition predicate does not enforce monotonic global version. Cases
1233–1236 show its acceptance of version 16 -> 15 and 16 -> 14 with singleton
policy continuity intact, while the separate presence predicate accepts 15 and
rejects 14. Cases 1237–1239 show that a custody-bearing policy requires 16 even
though the continuity predicate itself permits 16 -> 15. Thus old-version
activation has its own negative control. This is evidence about the named
predicates, not acceptance of a synthesized full block. Source review at
b7947b836 covers `block.cpp::valid_config_transition`,
`workchain-execution-dispatch.cpp::validate_native_ingress_presence` and
`validate_workchain_block_activation`, plus the calls in
`ValidateQuery::check_config_update`; it found no additional monotonic-version
rule in those inspected paths.

Mutation controls use independent production-source copies and compiled objects.
Removing either continuity return makes only its own numerical assertion fail.
Removing the activation minimum-version or capability condition need not make
resolution succeed: the later ingress loader can still refuse the input. The
shared classifier must instead reject the changed final typed-result identity.
The other mode and the other three resolver rows must remain unchanged. Neither
logs nor the generic -7201 code alone establish activation rejection.

No genesis checks, activation gates, production error classifications, or live
collator/validator paths are relaxed by this unit. Future merged-tree regression
must execute all former nine deferred tests and inspect their actual outcomes;
no historical exception list transfers to that tree.
