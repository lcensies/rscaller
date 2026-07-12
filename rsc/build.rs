use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    gen_syscall_nrs(&out_dir, &manifest_dir);
    gen_profiles(&out_dir, &manifest_dir);
}

// ---------------------------------------------------------------------------
// syscall_nrs.rs — generated from files/syscall_nrs
// ---------------------------------------------------------------------------

fn gen_syscall_nrs(out_dir: &PathBuf, manifest_dir: &PathBuf) {
    let src = manifest_dir.join("../files/syscall_nrs");
    println!("cargo:rerun-if-changed={}", src.display());

    let content = fs::read_to_string(&src)
        .unwrap_or_else(|e| panic!("build.rs: cannot read {}: {}", src.display(), e));

    let mut arms = String::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, nr_str) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("build.rs: syscall_nrs: expected name=number, got {:?}", line));
        let nr: u32 = nr_str
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("build.rs: syscall_nrs: {:?} is not u32", nr_str));
        arms.push_str(&format!("        {:?} => Some({nr}),\n", name.trim()));
    }

    let code = format!(
        "pub fn syscall_nr(name: &str) -> Option<u32> {{\n    match name {{\n{arms}        _ => None,\n    }}\n}}\n"
    );
    fs::write(out_dir.join("syscall_nrs.rs"), code).unwrap();
}

// ---------------------------------------------------------------------------
// profiles.rs — generated from profiles/*.yaml
// ---------------------------------------------------------------------------

fn gen_profiles(out_dir: &PathBuf, manifest_dir: &PathBuf) {
    let profiles_dir = manifest_dir.join("profiles");
    println!("cargo:rerun-if-changed={}", profiles_dir.display());

    let mut profiles: Vec<(String, String)> = fs::read_dir(&profiles_dir)
        .unwrap_or_else(|e| panic!("build.rs: cannot read profiles/: {}", e))
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let fname = entry.file_name();
            let fname = fname.to_str()?;
            if !fname.ends_with(".yaml") && !fname.ends_with(".yml") {
                return None;
            }
            let name = fname
                .trim_end_matches(".yml")
                .trim_end_matches(".yaml")
                .to_string();
            let path = profiles_dir.join(fname);
            println!("cargo:rerun-if-changed={}", path.display());
            let yaml = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("build.rs: cannot read {}: {}", path.display(), e));
            Some((name, yaml))
        })
        .collect();

    // Stable order so the generated file is deterministic.
    profiles.sort_by(|a, b| a.0.cmp(&b.0));

    let mut match_arms = String::new();
    let mut name_list = String::new();
    for (i, (name, yaml)) in profiles.iter().enumerate() {
        // Use r##"..."## so arbitrary YAML content is safe.
        match_arms.push_str(&format!("        {:?} => r##\"{}\"##,\n", name, yaml));
        if i > 0 {
            name_list.push_str(", ");
        }
        name_list.push_str(&format!("{:?}", name));
    }

    let code = format!(
        r#"pub fn builtin_preset(name: &str) -> Option<crate::mount_config::MountProfile> {{
    let yaml: &'static str = match name {{
{match_arms}        _ => return None,
    }};
    Some(serde_yaml::from_str(yaml).expect("malformed built-in profile"))
}}

pub fn builtin_names() -> &'static [&'static str] {{
    &[{name_list}]
}}
"#
    );
    fs::write(out_dir.join("profiles.rs"), code).unwrap();
}
