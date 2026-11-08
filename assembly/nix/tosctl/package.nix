{ lib, rustPlatform, pkg-config, openssl, cmake, perl, sourceRevision, sourceEpoch
  # The shielded variant: the `shielded` Cargo feature (`tosctl shield`), its tests, and
  # the audited proving material wrapped in as the environment default. The standard
  # variant takes neither the wrapper nor the material into its derivation.
, shielded ? false, makeWrapper ? null, material ? null }:
assert shielded -> (makeWrapper != null && material != null);
let
  root = ../../..;
  # inputs.json is the only list of package inputs; check-inputs.py holds the CI trigger
  # paths and every embedded file of the packaged and tested crates to it.
  inputs = builtins.fromJSON (builtins.readFile ./inputs.json);
  path = relative: root + "/${relative}";
  # Suffix exclusions apply inside the included directories only, so evaluation never walks
  # the rest of the repository.
  excludedSuffixes = lib.fileset.unions (map
    (relative: lib.fileset.fileFilter
      (file: lib.any (suffix: lib.hasSuffix suffix file.name) inputs.exclude_suffixes)
      (path relative))
    (lib.filter (relative: lib.pathIsDirectory (path relative)) inputs.source));
  # Both variants' tests name their packages; the shielded one also turns the feature on in
  # each of them.
  features = lib.optionals shielded [ "--features" "tosctl/shielded,commands/shielded" ];
in rustPlatform.buildRustPackage ({
  pname = if shielded then "tosctl-shielded" else "tosctl";
  version = (builtins.fromTOML (builtins.readFile
    ../../../tosctl/src/node-control/nodectl/Cargo.toml)).package.version;

  # Keep the repository layout required by TL generation and embedded contracts. Build
  # scripts, docs, sample configuration and container files stay out of the store, so editing
  # them does not change the derivation.
  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.difference
      (lib.fileset.unions (map path inputs.source))
      (lib.fileset.unions ((map path inputs.exclude) ++ [ excludedSuffixes ]));
  };
  cargoLock.lockFile = ../../../tosctl/src/Cargo.lock;
  cargoRoot = "tosctl/src";
  buildAndTestSubdir = "tosctl/src";
  cargoBuildFlags = [ "--locked" "--package" "tosctl" "--bin" "tosctl" ]
    ++ lib.optionals shielded [ "--features" "shielded" ];

  nativeBuildInputs = [ pkg-config cmake perl ] ++ lib.optional shielded makeWrapper;
  buildInputs = [ openssl ];
  env = {
    OPENSSL_NO_VENDOR = "1";
    GIT_COMMIT = sourceRevision;
    # A Nix source tree has no branch; "Unknown" is the build script's own value when git
    # cannot say (common/build/build.rs).
    GIT_BRANCH = "Unknown";
    SOURCE_DATE_EPOCH = toString sourceEpoch;
  };
  # The same form as `git log -1 --date=iso` in every other build: "YYYY-MM-DD HH:MM:SS +0000".
  preBuild = ''
    export GIT_COMMIT_DATE="$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%d %H:%M:%S +0000')"
  '';

  # Unit tests of the packaged binary and of `commands`, where its command logic and tests
  # live, run in the sandbox against this exact source. Runtime acceptance is the NixOS VM
  # check. The standard variant keeps the standard CLI's features; native archive and PQ
  # signing are separate.
  doCheck = true;
  cargoTestFlags = [ "--locked" ]
    ++ lib.concatMap (name: [ "--package" name ]) inputs.tested_packages ++ features;
  # The build sandbox maps the real root to uid 65534, so `/` is owned by an unmapped user.
  # tosctl refuses to persist configuration or open a vault under a directory any ancestor of
  # which another user can modify, so these tests cannot pass in any sandbox directory; that is
  # the check working, not a defect. The VM acceptance test exercises the same configuration
  # persistence (private mode, symlink and unsafe-directory refusals) on a real system, and all
  # ten run in the repository's Rust CI. The receipt counts them as "filtered out".
  checkFlags = [ "--exact" ] ++ lib.concatMap (name: [ "--skip" name ]) ([
    "commands::nodectl::utils::tests::save_config_is_private_and_refuses_a_linked_target"
    "commands::nodectl::utils::tests::node_control_config_opens_the_vault_for_a_vault_key"
    "commands::nodectl::utils::tests::node_control_config_names_the_fix_for_a_non_extractable_key"
    "commands::nodectl::config_node_cmd::tests::node_add_refuses_a_non_extractable_control_client_secret"
    "commands::nodectl::agent_cmd::tests::legacy_generation_commands_require_explicit_choice"
    "commands::nodectl::agent_cmd::task_vault_tests::via_agent_task_releases_outer_file_vault_before_delegation"
    "commands::nodectl::native_registry_cmd::tests::controllers_live_in_the_vault_as_ml_dsa_44_seeds"
    "commands::nodectl::native_registry_cmd::tests::agent_guarantor_sign_and_verify_run_through_the_commands"
    "commands::nodectl::native_registry_cmd::tests::action_authority_sign_and_verify_run_through_the_commands"
    "commands::nodectl::native_registry_cmd::tests::custody_authorization_sign_and_verify_run_through_the_commands"
  ] ++ lib.optionals shielded [
    # The shield store persists state, pointers, locks and the journal under the same
    # private-directory rule, so every test that opens an instance on disk is refused in the
    # sandbox for the same reason. They run in the repository's Rust CI; the remaining shield
    # tests (planning, proving, relaying, auditing, parsing) run here.
    "commands::nodectl::shield::relay::tests::a_fee_descriptor_must_be_this_pools_at_the_quoted_index_and_not_the_recipients"
    "commands::nodectl::shield::relay::tests::a_request_is_journalled_byte_for_byte_before_it_is_submitted_and_its_outcome_after"
    "commands::nodectl::shield::relay::tests::a_request_whose_window_closed_while_journalling_is_withheld_unsent"
    "commands::nodectl::shield::relay::tests::the_session_is_on_disk_before_the_relayer_is_asked_and_the_quote_once_it_passes"
    "commands::nodectl::shield::spend::tests::a_spend_is_journalled_before_it_is_signed_and_before_it_is_sent"
    "commands::nodectl::shield::store::tests::an_earlier_format_is_refused_by_name"
    "commands::nodectl::shield::store::tests::another_pointer_naming_the_same_directory_is_found_and_garbage_fails_closed"
    "commands::nodectl::shield::store::tests::a_symlinked_or_shared_file_is_refused"
    "commands::nodectl::shield::store::tests::a_tampered_byte_and_a_swapped_kind_are_refused"
    "commands::nodectl::shield::store::tests::a_write_past_the_limit_is_refused_and_the_old_file_stays_readable"
    "commands::nodectl::shield::store::tests::the_journal_keeps_order_and_notices_a_cut_or_a_repeat"
    "commands::nodectl::shield::store::tests::the_lock_is_exclusive_per_instance"
    "commands::nodectl::shield::store::tests::the_name_lock_is_exclusive"
    "commands::nodectl::shield::store::tests::the_state_round_trips_and_a_foreign_binding_does_not_open"
    "commands::nodectl::shield::tests::a_migration_that_stopped_between_its_writes_is_repaired_and_keeps_the_journal"
    "commands::nodectl::shield::tests::an_initialisation_resumes_its_state_and_refuses_another_profile"
    "commands::nodectl::shield::tests::the_pool_master_is_stored_once_and_another_mnemonics_is_refused"
  ]);
  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    "$out/bin/tosctl" --version
    "$out/bin/tosctl" --help > /dev/null
    ${lib.optionalString shielded ''
      help="$("$out/bin/tosctl" shield --help)"
      for command in init sync balance address deposit withdraw send status audit-ceremony; do
        grep -qE "^  $command " <<< "$help" || { echo "shield --help lacks $command" >&2; exit 1; }
      done
      send="$("$out/bin/tosctl" shield send --help)"
      for flag in --relayer --direct --ceremony-dir --phase1-dir; do
        grep -q -- "$flag" <<< "$send" || { echo "shield send --help lacks $flag" >&2; exit 1; }
      done
      # The wrapper defaults each variable to the shipped material and never forces it: the
      # emitted form is `export VAR=''${VAR-'<material>'}`, so a variable the operator set
      # stands, and an explicit --ceremony-dir/--phase1-dir wins over both.
      for pair in "TOSCTL_SHIELD_CEREMONY_DIR ${material}/ceremony" \
                  "TOSCTL_SHIELD_PHASE1_DIR ${material}/phase1"; do
        set -- $pair
        grep -qF "export $1=\''${$1-'$2'}" "$out/bin/tosctl" \
          || { echo "the wrapper does not default $1 to $2" >&2; exit 1; }
      done
      ! grep -qE "^export TOSCTL_SHIELD_[A-Z0-9_]+='" "$out/bin/tosctl" \
        || { echo "the wrapper forces the material instead of defaulting it" >&2; exit 1; }
    ''}
    runHook postInstallCheck
  '';

  meta = {
    description = if shielded
      then "TOS node operator CLI with the shielded-pool client and its audited proving material"
      else "TOS node operator CLI (standard Cargo features)";
    homepage = "https://github.com/tosnetwork/tos";
    license = lib.licenses.gpl3Only;
    platforms = [ "x86_64-linux" ];
    mainProgram = "tosctl";
  };
} // lib.optionalAttrs shielded {
  # The audit test of the shield commands reads the committed material at the checkout's
  # layout; in the sandbox that layout is given the packaged material, so the tests run
  # against exactly what the installation ships.
  preCheck = ''
    mkdir -p artifacts/phase2-ceremony-2
    ln -s ${material}/phase1 artifacts/phase1
    ln -s ${material}/ceremony artifacts/phase2-ceremony-2/ceremony
  '';
  # The environment default an installation sets; `--set-default` leaves a variable the
  # operator set alone, and an explicit --ceremony-dir/--phase1-dir wins over both.
  postFixup = ''
    wrapProgram "$out/bin/tosctl" \
      --set-default TOSCTL_SHIELD_CEREMONY_DIR "${material}/ceremony" \
      --set-default TOSCTL_SHIELD_PHASE1_DIR "${material}/phase1"
  '';
})
