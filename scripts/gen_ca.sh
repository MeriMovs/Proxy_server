#!/usr/bin/env bash
# gen_ca.sh — Generate a local CA key and self-signed certificate for the
# MITM proxy.  The resulting ca.key and ca.crt are placed in config/.
#
# Usage:  bash scripts/gen_ca.sh [output_dir]
#         Default output_dir = config
#
# After running this script you must install config/ca.crt as a trusted root
# CA in your browser or OS certificate store so that proxied connections
# do not produce "certificate error" warnings.
#
# Linux (system-wide):
#   sudo cp config/ca.crt /usr/local/share/ca-certificates/proxy-ca.crt
#   sudo update-ca-certificates
#
# Firefox: Settings > Privacy & Security > Certificates > View Certificates
#          > Authorities > Import  → select config/ca.crt
#
# Chrome/Chromium: Settings > Security > Manage device certificates
#                  > Authorities > Import → select config/ca.crt

set -euo pipefail

OUT_DIR="${1:-config}"
mkdir -p "$OUT_DIR"

KEY="$OUT_DIR/ca.key"
CERT="$OUT_DIR/ca.crt"

echo "[gen_ca] Generating 4096-bit RSA CA key..."
openssl genrsa -out "$KEY" 4096

echo "[gen_ca] Generating self-signed CA certificate (valid 10 years)..."
openssl req -new -x509 \
    -key  "$KEY"  \
    -out  "$CERT" \
    -days 3650    \
    -subj "/C=US/ST=Local/L=Proxy/O=OS-Networks Course/OU=Proxy CA/CN=Proxy Root CA" \
    -extensions v3_ca \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

echo ""
echo "[gen_ca] Done."
echo "  Private key : $KEY"
echo "  Certificate : $CERT"
echo ""
echo "To inspect the certificate:"
echo "  openssl x509 -in $CERT -text -noout"
echo ""
echo "IMPORTANT: Import $CERT as a trusted root CA in your browser/OS"
echo "           before using the proxy, otherwise you will see TLS errors."
