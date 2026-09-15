// The same states, decoded by the independent implementation.
//
// A policy that takes effect has to be attested by an activation. The guard is
// written twice, once here and once in the other implementation, and a guard
// written twice with nothing comparing the two is the shape this repository
// keeps producing. These are the exact bytes the other one answered about.
use std::{env, fs, path::Path};
use tos_validator_auth_native::{
    cells, registry::RegistryState, registry::StateReadBudget, registry_view::RegistryView,
};

fn check(ok: bool, label: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(label.to_owned())
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    check(args.len() == 2, "arguments")?;
    let path = Path::new(&args[1]);
    let count: usize = fs::read_to_string(path.join("complete"))
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "count")?;
    check(count >= 5, "complete-corpus")?;
    let mut refusals = 0;
    for i in 0..count {
        let meta = fs::read_to_string(path.join(format!("{i}.case"))).map_err(|e| e.to_string())?;
        let fields: Vec<_> = meta.split_whitespace().collect();
        check(fields.len() == 3, "fields")?;
        let coordinate: u32 = fields[0].parse().map_err(|_| "coordinate")?;
        let accepted = fields[1] == "1";
        let root = cells::read_boc(
            &fs::read(path.join(format!("{i}.boc"))).map_err(|e| e.to_string())?,
            true,
        )
        .map_err(|e| e.0.to_owned())?;
        let decoded = RegistryState::decode_cell(
            root.clone(),
            coordinate,
            StateReadBudget { entries: 64, bytes: 1 << 20 },
        );
        check(
            decoded.is_ok() == accepted,
            &format!("{}: {:?}", fields[2], decoded.as_ref().err()),
        )?;
        // The other reader of the same bytes. Committees are derived through
        // this one, so a state the full decoder refuses and this one accepts
        // would govern the chain under a policy the decoder calls illegitimate.
        let view =
            RegistryView::open(root, coordinate, StateReadBudget { entries: 64, bytes: 1 << 20 });
        check(view.is_ok() == accepted, &format!("view {}: {:?}", fields[2], view.as_ref().err()))?;
        if !accepted {
            refusals += 1;
        }
    }
    // A corpus this agreed with by accepting everything would agree with nothing.
    check(refusals >= 3, "corpus-refusals")?;
    println!("PASS: independent policy attestation {count} cases, both readers");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ASSERTION: {error}");
        std::process::exit(1);
    }
}
