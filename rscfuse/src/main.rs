use anyhow::Result;
use clap::Parser;
use rscfuse::FuseArgs;

fn main() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("rscfuse=debug".parse()?),
        )
        .init();

    rscfuse::run(FuseArgs::parse())
}
