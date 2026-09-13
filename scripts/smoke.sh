#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../backend"
export ETHOSCAN_DISABLE_AUTH=true
export ETHOSCAN_ALLOW_MOCK=true
export ETHOSCAN_MODE=local
python -m pytest tests/test_smoke.py -q
