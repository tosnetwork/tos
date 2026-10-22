//! Fixed repository inputs shared by Cargo and the manual generator.
use crate::{generate_code_for, Config};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub const SCHEMA_FILES: [&str; 3] = ["lite_api.tl", "tos_api.tl", "toslib_api.tl"];
pub const SCHEMA_DIRECTORY: &str = "tl/generate/scheme";
pub const CONFIG_FILE: &str = "tosctl/src/tl/api/tl/codegen.json";

pub struct RepositoryInput {
    pub files: Vec<PathBuf>,
    pub config_file: PathBuf,
    pub text: String,
    pub config: Config,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub fn repository_from_api(api: &Path) -> io::Result<PathBuf> {
    let root =
        api.ancestors().nth(4).ok_or_else(|| invalid("TL API directory has no repository root"))?;
    let root = root.canonicalize()?;
    if root.join("tosctl/src/tl/api").canonicalize()? != api.canonicalize()? {
        return Err(invalid("TL API directory is outside the expected repository layout"));
    }
    Ok(root)
}

pub fn load(root: &Path) -> io::Result<RepositoryInput> {
    let root = root.canonicalize()?;
    let mut files = Vec::new();
    let mut text = String::new();
    for name in SCHEMA_FILES {
        let file = root.join(SCHEMA_DIRECTORY).join(name);
        if file.canonicalize()? != file {
            return Err(invalid("authoritative TL inputs must not redirect through symlinks"));
        }
        if !text.is_empty() {
            text.push_str("---types---\n");
        }
        text.push_str(&fs::read_to_string(&file)?);
        files.push(file);
    }
    let config_file = root.join(CONFIG_FILE);
    let config = serde_json::from_str(&fs::read_to_string(&config_file)?)
        .map_err(|error| invalid(format!("invalid TL generator policy: {error}")))?;
    Ok(RepositoryInput { files, config_file, text, config })
}

fn rust_files(directory: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if directory.exists() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                files.extend(rust_files(&path)?);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    Ok(files)
}

/// Reconcile the generated Rust files, including modules retired by the schema.
pub fn generate(input: RepositoryInput, output: &Path) -> io::Result<()> {
    let stage = output.with_extension(format!("stage-{}", std::process::id()));
    fs::create_dir(&stage)?;
    generate_code_for(Some(input.config), &input.text, &stage);
    let generated = rust_files(&stage)?;
    for previous in rust_files(output)? {
        let relative = previous.strip_prefix(output).map_err(|error| invalid(error.to_string()))?;
        if !stage.join(relative).is_file() {
            fs::remove_file(previous)?;
        }
    }
    for file in generated {
        let relative = file.strip_prefix(&stage).map_err(|error| invalid(error.to_string()))?;
        let destination = output.join(relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = fs::read(&file)?;
        if fs::read(&destination).ok().as_deref() != Some(bytes.as_slice()) {
            fs::write(destination, bytes)?;
        }
    }
    fs::remove_dir_all(stage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "tl-input-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("tl/generate/scheme")).expect("fixture schema directory");
            fs::create_dir_all(root.join("tosctl/src/tl/api/tl"))
                .expect("fixture policy directory");
            for (index, name) in SCHEMA_FILES.iter().enumerate() {
                fs::write(
                    root.join(SCHEMA_DIRECTORY).join(name),
                    format!("probe{index} value:int = Probe{index};\n"),
                )
                .expect("fixture schema");
            }
            fs::write(root.join(CONFIG_FILE), r#"{"exclude_types":[],"need_box":[],"need_determiner":[],"replace_with_bytes":[],"additional_derives":{}}"#).expect("fixture policy");
            Self(root)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn fixed_repository_inputs_and_regeneration() {
        let fixture = Fixture::new();
        let api = fixture.0.join("tosctl/src/tl/api");
        let root = repository_from_api(&api).expect("repository root");
        let input = load(&root).expect("main schemas");
        assert_eq!(
            input.files,
            ["lite_api.tl", "tos_api.tl", "toslib_api.tl"]
                .map(|name| root.join("tl/generate/scheme").join(name)),
            "TL_INPUT_PATHS"
        );
        assert_eq!(
            input.config_file,
            root.join("tosctl/src/tl/api/tl/codegen.json"),
            "TL_POLICY_PATH"
        );
        let expected = ["lite_api.tl", "tos_api.tl", "toslib_api.tl"]
            .map(|name| {
                fs::read_to_string(root.join("tl/generate/scheme").join(name))
                    .expect("authoritative bytes")
            })
            .join("---types---\n");
        assert_eq!(input.text, expected, "TL_INPUT_CONTENTS");
        let output = fixture.0.join("tos");
        fs::create_dir(&output).expect("output directory");
        fs::write(output.join("retired.rs"), "retired").expect("stale module");
        generate(input, &output).expect("generate main schemas");
        assert!(!output.join("retired.rs").exists(), "TL_STALE_MODULE");
        let first: Vec<_> = rust_files(&output)
            .expect("generated files")
            .iter()
            .map(|p| (p.clone(), fs::read(p).expect("generated bytes")))
            .collect();
        generate(load(&root).expect("same inputs"), &output).expect("second generation");
        for (path, bytes) in first {
            assert_eq!(fs::read(path).expect("second bytes"), bytes, "TL_REPEATABLE_OUTPUT");
        }
        let schema = root.join(SCHEMA_DIRECTORY).join(SCHEMA_FILES[0]);
        fs::write(&schema, "added value:long = Added;\n").expect("changed schema");
        generate(load(&root).expect("changed authoritative input"), &output)
            .expect("new generation");
        assert!(output.join("added.rs").exists(), "TL_MAIN_CHANGE_PROPAGATES");
        fs::remove_file(schema).expect("remove schema");
        assert!(load(&root).is_err(), "TL_MISSING_INPUT_REFUSED");
    }

    #[cfg(unix)]
    #[test]
    fn authoritative_schema_symlink_is_refused() {
        let fixture = Fixture::new();
        let schema = fixture.0.join(SCHEMA_DIRECTORY).join(SCHEMA_FILES[0]);
        let alternate = fixture.0.join("alternate.tl");
        fs::rename(&schema, &alternate).expect("move fixture input");
        std::os::unix::fs::symlink(alternate, schema).expect("redirect fixture input");
        assert!(load(&fixture.0).is_err(), "TL_REDIRECT_REFUSED");
    }
}
