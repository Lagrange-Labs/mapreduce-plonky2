FROM rustlang/rust:nightly-slim as base

ARG GO_VERSION=1.22.2

# Install necessary packages and Go
RUN apt-get update && apt-get install -y \
    wget \
    libssl-dev \
    git \
    pkg-config \
    libssl3

RUN rustup component add clippy rustfmt

# Install Go
RUN wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

# Set work directory
WORKDIR /lgn-coprocessor

# Copy the source code
COPY . .
