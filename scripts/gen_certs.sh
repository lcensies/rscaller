#!/usr/bin/env bash
# Generate self-signed TLS certs for rsbeacon dev/test
set -euo pipefail

CERT_DIR="${1:-certs}"
mkdir -p "$CERT_DIR"

# Generate CA key and cert
openssl req -x509 -newkey rsa:4096 -keyout "$CERT_DIR/ca.key" \
  -out "$CERT_DIR/ca.crt" -days 3650 -nodes \
  -subj "/CN=rscaller-ca"

# Generate server key and CSR
openssl req -newkey rsa:4096 -keyout "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.csr" -nodes \
  -subj "/CN=rsbeacon"

# Sign server cert with CA
openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" \
  -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/server.crt" -days 365 \
  -extfile <(printf "subjectAltName=IP:127.0.0.1,IP:0.0.0.0,DNS:localhost")

echo "Certs generated in $CERT_DIR/"
echo "  CA cert:     $CERT_DIR/ca.crt"
echo "  Server cert: $CERT_DIR/server.crt"
echo "  Server key:  $CERT_DIR/server.key"
