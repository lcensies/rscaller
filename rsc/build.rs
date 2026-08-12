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
// syscall_nrs.rs — auto-derived from the build host's <asm/unistd_64.h>
// (x86_64 syscall ABI; the same source bindgen would parse, without libclang).
// ponytail: build-host headers, cross-arch builds must set SYSCALL_HEADER.
// ---------------------------------------------------------------------------

fn gen_syscall_nrs(out_dir: &PathBuf, _manifest_dir: &PathBuf) {
    let mut candidates: Vec<PathBuf> = env::var("SYSCALL_HEADER")
        .map(PathBuf::from)
        .into_iter()
        .collect();
    candidates.extend([
        PathBuf::from("/usr/include/x86_64-linux-gnu/asm/unistd_64.h"),
        PathBuf::from("/usr/include/asm/unistd_64.h"),
    ]);
    let src = candidates.into_iter().find(|p| p.is_file()).unwrap_or_else(|| {
        panic!("build.rs: <asm/unistd_64.h> not found; install linux-libc-dev or set SYSCALL_HEADER")
    });
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-env-changed=SYSCALL_HEADER");

    let content = fs::read_to_string(&src)
        .unwrap_or_else(|e| panic!("build.rs: cannot read {}: {}", src.display(), e));

    let mut arms = String::new();
    for line in content.lines() {
        // "#define __NR_openat 257"
        let mut fields = line.split_whitespace();
        if fields.next() != Some("#define") {
            continue;
        }
        let Some(name) = fields.next().and_then(|n| n.strip_prefix("__NR_")) else {
            continue;
        };
        let Ok(nr) = fields.next().unwrap_or("").parse::<u32>() else {
            continue;
        };
        arms.push_str(&format!("        {:?} => Some({nr}),\n", name));
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
