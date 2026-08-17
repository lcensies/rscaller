//! `rsc certs-gen` — generate a CA + beacon server identity (PEM) for custom
//! TLS deployments. Replaces scripts/gen_certs.sh.
//!
//! ponytail: same rcgen recipe as rsbeacon/build.rs (embedded identity);
//! kept in sync manually — the only difference is the output location.

use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn run_certs_gen(out: PathBuf) -> Result<()> {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};

    std::fs::create_dir_all(&out)
        .with_context(|| format!("creating {}", out.display()))?;

    // CA
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "rscaller CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    // Server cert signed by CA. SAN must include DNS:rsbeacon — client SNI is
    // hardcoded to it (see rscaller-proto transport::connect).
    let mut server_params =
        CertificateParams::new(vec!["rsbeacon".to_string(), "localhost".to_string()]).unwrap();
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

    let write = |name: &str, data: &str| -> Result<()> {
        let p = out.join(name);
        std::fs::write(&p, data).with_context(|| format!("writing {}", p.display()))
    };
    write("ca.pem", &ca_cert.pem())?;
    write("cert.pem", &server_cert.pem())?;
    write("key.pem", &server_key.serialize_pem())?;

    eprintln!("rsc: certs written to {}", out.display());
    eprintln!("  beacon:  rsbeacon --encryption tls --cert {0}/cert.pem --key {0}/key.pem", out.display());
    eprintln!("  client:  --encryption tls --ca-cert {0}/ca.pem", out.display());
    Ok(())
}
