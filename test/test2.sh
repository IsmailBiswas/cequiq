#!/bin/sh
set -e 

check_and_run() {
    for cmd in mkdir openssl date; do
        command -v "$cmd" >/dev/null 2>&1 || { echo "Error: $cmd not found" >&2; return 1; }
    done

    CERT_DIR="server_files"
    KEY_FILE="$CERT_DIR/private_key.pem"
    CERT_FILE="$CERT_DIR/certificate.pem"
    INVITE_FILE="$CERT_DIR/invite_keys.txt"

    mkdir -p "$CERT_DIR" || return 1

    openssl req -x509 -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -days 365 -nodes -subj "/CN=localhost" || return 1

    return 0
}

check_and_run || exit 1




# start the server
../bin/test2_server >server.log 2>&1 &
SERVER_PID=$!

# wait for server to initialize 
sleep .5

# run client 
../bin/test2_client 
CLIENT_EXIT_CODE=$?

# Kill the server after client test completes
kill $SERVER_PID || true
wait $SERVER_PID 2>/dev/null || true

# Return client's exit code to CTest
exit $CLIENT_EXIT_CODE
