#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "          TCW-Mask: Automated System Demo"
echo "=========================================================="

cargo build --release
CLI="./target/release/tcw-mask"
TMP_DIR=$(mktemp -d /tmp/tcw_demo_XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

echo -e "\n[1] Generating 256-bit Master Key..."
$CLI generate --out "$TMP_DIR/master.key"
KEY=$(cat "$TMP_DIR/master.key")
echo "Generated Key: $KEY"

echo -e "\n[2] Splitting into 5 shares with threshold k=3..."
$CLI split --key "$TMP_DIR/master.key" --k 3 --n 5 --out-dir "$TMP_DIR/shares"

echo -e "\n[3] Verifying integrity of share bundles..."
$CLI verify --shares "$TMP_DIR/shares"/share_*.json

echo -e "\n[4] Reconstructing master key from 3 shares (shares 1, 3, 5)..."
$CLI reconstruct --shares "$TMP_DIR/shares/share_1.json" "$TMP_DIR/shares/share_3.json" "$TMP_DIR/shares/share_5.json" --out "$TMP_DIR/recovered.key"
RECOVERED=$(cat "$TMP_DIR/recovered.key")
echo "Recovered Key: $RECOVERED"

if [ "$KEY" == "$RECOVERED" ]; then
    echo "SUCCESS: Reconstructed key matches original master key exactly!"
else
    echo "ERROR: Key mismatch!"
    exit 1
fi

echo -e "\n[5] Running Attack Simulations..."
echo "--- Tamper Attack ---"
$CLI attack-sim --shares "$TMP_DIR/shares"/share_*.json --mode tamper || true

echo "--- Insufficient Shares Attack ---"
$CLI attack-sim --shares "$TMP_DIR/shares"/share_*.json --mode insufficient || true

echo "--- Replay / Mismatched Session Attack ---"
$CLI attack-sim --shares "$TMP_DIR/shares"/share_*.json --mode replay || true

echo -e "\n[6] Proactively Refreshing Shares to New Epoch (Zero-Polynomial Re-randomization)..."
$CLI refresh --shares "$TMP_DIR/shares"/share_*.json --out-dir "$TMP_DIR/refreshed_shares"
$CLI verify --shares "$TMP_DIR/refreshed_shares"/share_*.json
$CLI reconstruct --shares "$TMP_DIR/refreshed_shares/share_2.json" "$TMP_DIR/refreshed_shares/share_3.json" "$TMP_DIR/refreshed_shares/share_4.json" --out "$TMP_DIR/refreshed_recovered.key"
REFRESHED_REC=$(cat "$TMP_DIR/refreshed_recovered.key")
if [ "$KEY" == "$REFRESHED_REC" ]; then
    echo "SUCCESS: Key reconstructed from refreshed epoch shares matches original master key!"
fi

echo -e "\n[7] Simulating Correlation Power Analysis (CPA / DPA) Attack..."
$CLI cpa-sim --traces 1000

echo -e "\n[8] Running TVLA Statistical Timing Bench..."
$CLI bench --iterations 500

echo -e "\n=========================================================="
echo "          TCW-Mask Demonstration Completed Successfully"
echo "=========================================================="
