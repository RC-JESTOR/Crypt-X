#!/usr/bin/env bash
set -euo pipefail
mkdir -p out
javac -d out $(find src -name "*.java")
echo "[+] Build succeeded -> ./out"
echo "    Run: java -cp out com.rcjestor.cryptx.Main selftest"
