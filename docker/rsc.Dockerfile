FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    fuse3 \
    libfuse3-dev \
    ca-certificates \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /app
COPY . .
RUN cargo build --release -p rsc -p rscfuse -p rsclient -p rsbeacon
RUN mv target/release/rsc target/release/rscfuse target/release/rsclient target/release/rsbeacon /usr/local/bin/