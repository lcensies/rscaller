FROM ghcr.io/philips-software/amp-devcontainer-rust

RUN mkdir /app
WORKDIR /app

RUN apt update && apt install -y \
    clang \
    make \
    docker.io \
    python3 \
    python3-poetry 