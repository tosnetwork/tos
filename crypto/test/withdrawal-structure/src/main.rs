//! D51 bounded AST capability inventory, not a side-effect verifier.
//! New interfaces, fields, or call targets expire the statement-only contract.
//! LIMIT: unchanged callees may acquire indirect effects; aliases, method
//! resolution and independent Native entry points are not analyzed here.
use std::{collections::BTreeSet, env, fs, process};
use quote::ToTokens;
use syn::{visit::{self, Visit}, Item, ImplItem};

fn spelling(value: &impl ToTokens) -> String { value.to_token_stream().to_string() }
fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|v| v.to_string()).collect()
}

#[derive(Default)]
struct Calls { targets: BTreeSet<String>, forbidden: bool }
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, value: &'ast syn::ExprCall) {
        self.targets.insert(spelling(&value.func));
        visit::visit_expr_call(self, value);
    }
    fn visit_expr_method_call(&mut self, value: &'ast syn::ExprMethodCall) {
        self.targets.insert(format!(".{}", value.method));
        visit::visit_expr_method_call(self, value);
    }
    fn visit_expr_unsafe(&mut self, _: &'ast syn::ExprUnsafe) { self.forbidden = true; }
    fn visit_expr_macro(&mut self, _: &'ast syn::ExprMacro) { self.forbidden = true; }
    fn visit_item_static(&mut self, _: &'ast syn::ItemStatic) { self.forbidden = true; }
}

fn check(source: &str) -> Result<(), String> {
    let file = syn::parse_file(source).map_err(|e| e.to_string())?;
    let mut calls = Calls::default();
    let mut api = BTreeSet::new();
    let mut fields = BTreeSet::new();
    for item in &file.items {
        match item {
            Item::Use(_) => {},
            Item::Mod(m) if m.ident == "tests" && m.attrs.iter().any(|a|
                spelling(&a.meta) == "cfg (test)") => {},
            Item::Struct(s) => {
                for f in &s.fields {
                    fields.insert(format!("{}.{}:{}", s.ident,
                        f.ident.as_ref().ok_or("unnamed field")?, spelling(&f.ty)));
                }
            },
            Item::Fn(f) => {
                api.insert(spelling(&f.sig));
                calls.visit_block(&f.block);
            },
            Item::Impl(i) if i.trait_.is_none() => {
                for member in &i.items {
                    let ImplItem::Fn(f) = member else { return Err("new impl item".into()); };
                    api.insert(format!("{}::{}", spelling(&i.self_ty), spelling(&f.sig)));
                    calls.visit_block(&f.block);
                }
            },
            _ => return Err("new statement module capability".into()),
        }
    }
    // Signatures and field types are parsed syntax, not file identities.
    // Keep the independently reviewed interface in a separate explicit fixture.
    let expected_api = include_str!("../api.txt").lines().map(str::to_owned).collect();
    if api != expected_api { return Err(format!("statement interface changed: {api:?}")); }
    let expected_fields = set(&[
        "WithdrawalAmounts.principal:u64", "WithdrawalAmounts.outward_fee:u64",
        "WithdrawalAmounts.return_reserve:u64", "WithdrawalAmounts.operation_fee:u64",
        "WithdrawalStatement.domain:[u8 ; 80]", "WithdrawalStatement.fee:u64",
        "WithdrawalStatement.context:Vec < u8 >", "WithdrawalStatement.points:[[u8 ; 32] ; 10]",
    ]);
    if fields != expected_fields { return Err(format!("statement storage changed: {fields:?}")); }
    let expected_calls = set(&[
        "Err", "Ok", "CompressedRistretto", "Transcript :: new", "nonzero_opening",
        "Scalar :: from_bytes_mod_order_wide", "relation :: validate_limits",
        "public_opening", "PedersenGens :: default", "Scalar :: from",
        "Vec :: with_capacity", "relation :: prepare", "relation :: verify_relation",
        ".checked_add", ".and_then", ".ok_or", ".decompress", ".is_identity",
        ".append_message", ".to_le_bytes", ".challenge_bytes", ".total", ".is_empty",
        ".len", ".compress", ".to_bytes", ".extend_from_slice",
    ]);
    if calls.forbidden || calls.targets != expected_calls {
        return Err(format!("statement call boundary changed: {:?}", calls.targets));
    }
    Ok(())
}

fn main() {
    let path = env::args().nth(1).expect("statement source argument required");
    let source = fs::read_to_string(path).expect("read statement source");
    if let Err(e) = check(&source) {
        eprintln!("withdrawal.statement_expired: {e}; install authenticated full pending-cut controls before enabling prepare");
        process::exit(1);
    }
    // Structural mutations of the actual parsed source, not fabricated effects.
    let mutations = [
        "\nimpl WithdrawalStatement { pub fn install_pending(&mut self) {} }",
        "\nstatic mut ACCOUNT_ROOT: u64 = 0;",
    ];
    for mutation in mutations {
        assert!(check(&format!("{source}{mutation}")).is_err(), "expiry mutation was accepted");
    }
    let call_mutation = source.replacen("relation::validate_limits(limits)?;",
        "account_store::install_pending(); relation::validate_limits(limits)?;", 1);
    assert_ne!(source, call_mutation, "call mutation was not installed");
    assert!(check(&call_mutation).is_err(), "new write call was accepted");
    assert!(check(&format!("// unrelated formatting/comment\n{source}\n")).is_ok(),
        "comment-only change expired structure");
    println!("statement AST boundary unchanged; new mutable outlet and global storage controls rejected; indirect side effects not covered");
}
