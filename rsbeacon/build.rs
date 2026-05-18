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

    // Tell cargo to rerun only if build.rs itself changes — not on every build.
    println!("cargo:rerun-if-changed=build.rs");
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
