FROM archlinux:base-devel-20250720.0.386825

RUN pacman -Syu --noconfirm base-devel \
    llvm \
    clang \
    openssl \
    python \
    rust \
    git


# FROM docker.io/library/rust:1.88.0-alpine
# RUN apk add llvm18 llvm18-dev musl-dev make cmake g++ 

# We use old cmake since c2rust can be built
# with cmake up to 4.0
RUN curl --output /tmp/cmake.pkg.tar.zst \
    https://archive.archlinux.org/packages/c/cmake/cmake-3.31.6-1-x86_64.pkg.tar.zst && \ 
    pacman -U --noconfirm /tmp/cmake.pkg.tar.zst


# TODO: consider using older llvm toolchain
RUN cargo install c2rust