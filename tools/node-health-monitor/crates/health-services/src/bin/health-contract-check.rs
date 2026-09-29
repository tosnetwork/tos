use tos_health_core::config::{production_doctor, ProductionEvidence, ResourceProfile};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err(
            "usage: health-contract-check RESOURCE_PROFILE_JSON DECLARED_EVIDENCE_JSON".into()
        );
    }
    let read = |path: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let bytes = std::fs::read(path)?;
        if bytes.len() > 16_384 {
            return Err("config too large".into());
        }
        Ok(bytes)
    };
    let profile: ResourceProfile = serde_json::from_slice(&read(&args[1])?)?;
    let evidence: ProductionEvidence = serde_json::from_slice(&read(&args[2])?)?;
    let missing = production_doctor(&profile, &evidence);
    println!(
        "{}",
        serde_json::json!({"check":"declarations_only","actual_host_verification":false,"missing":missing})
    );
    if !missing.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}
