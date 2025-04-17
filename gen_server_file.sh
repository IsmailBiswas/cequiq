#!/bin/sh
set -e 
CERT_DIR="server_files"
KEY_FILE="$CERT_DIR/private_key.pem"
CERT_FILE="$CERT_DIR/certificate.pem"

mkdir -p "$CERT_DIR"

openssl req -x509 -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" \
    -days 365 -nodes -subj "/CN=localhost"
