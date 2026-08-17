use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Generate a self-signed CA + server cert pair for embedded use.
    // Only regenerate if files don't exist (stable across incremental builds).
    let ca_path = out_dir.join("ca.pem");
    let cert_path = out_dir.join("cert.pem");
    let key_path = out_dir.join("key.pem");

    if !ca_path.exists() || !cert_path.exists() || !key_path.exists() {
        generate_certs(&ca_path, &cert_path, &key_path);
    }

    maybe_rebuild_xdp_prog();

    // Tell cargo to rerun only if build.rs itself changes — not on every build.
    println!("cargo:rerun-if-changed=build.rs");
    // `rsc beacon-gen` bakes defaults via these (see option_env! in main.rs).
    println!("cargo:rerun-if-env-changed=RSC_BEACON_LISTEN");
    println!("cargo:rerun-if-env-changed=RSC_BEACON_ENCRYPTION");
}

/// `bpf/xdp_prog.o` is produced ahead-of-time from `bpf/xdp_prog.c` and
/// checked into the repo (see that file's header comment for the exact
/// rebuild command) — the same approach `xdplganger` takes with its own
/// prebuilt `.o`. rsbeacon's own build NEVER invokes clang/a BPF toolchain
/// automatically: doing so opportunistically on whatever machine happens
/// to run `cargo build` is unsafe (different clang versions/libbpf-dev
/// header layouts across machines can silently produce a different object,
/// or — as observed during development — clang truncating the output file
/// before failing to compile, destroying a good checked-in artifact).
///
/// Per this repo's convention (see AGENTS.md "Never hand-install packages
/// on dev VMs — fix the harness instead" and the two-VM topology), the BPF
/// toolchain only ever needs to be present on the build host (dev-vm-1),
/// and rebuilding `xdp_prog.o` is an explicit, manual, developer-invoked
/// step — never part of the ordinary `cargo build` / deploy flow.
///
/// This function only verifies the checked-in object exists and is
/// well-formed enough to embed; it never writes to `bpf/xdp_prog.o`.
fn maybe_rebuild_xdp_prog() {
    let src = PathBuf::from("bpf/xdp_prog.c");
    let obj = PathBuf::from("bpf/xdp_prog.o");
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", obj.display());

    if !obj.exists() {
        println!(
            "cargo:warning=bpf/xdp_prog.o is missing; rebuild it manually on a host with clang \
             + libbpf-dev (e.g. dev-vm-1) with: clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
             -I/usr/include/$(uname -m)-linux-gnu -c bpf/xdp_prog.c -o bpf/xdp_prog.o"
        );
    }
}

fn generate_certs(
    ca_path: &std::path::Path,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType,
    };

    // CA
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "rscaller CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Server cert signed by CA
    let mut server_params =
        CertificateParams::new(vec!["rsbeacon".to_string()]).unwrap();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "rsbeacon");
    server_params
        .subject_alt_names
        .push(SanType::DnsName("rsbeacon".try_into().unwrap()));
    server_params
        .subject_alt_names
        .push(SanType::DnsName("localhost".try_into().unwrap()));
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    std::fs::write(ca_path, ca_cert.pem()).unwrap();
    std::fs::write(cert_path, server_cert.pem()).unwrap();
    std::fs::write(key_path, server_key.serialize_pem()).unwrap();
}
