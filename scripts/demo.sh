#!/usr/bin/env bash
# Bring up the stack, run the agent's full protocol story, and tear down.
# Exits non-zero if any protocol assertion fails — used by CI as the
# containerized end-to-end test.
set -euo pipefail
cd "$(dirname "$0")/.."

cleanup() { docker compose down --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> building images"
docker compose --profile demo build

echo "==> starting authserver, tools-api, reports-api"
docker compose up -d --wait authserver tools-api reports-api

echo "==> running the agent scenario"
docker compose --profile demo run --rm agent

echo "==> demo completed successfully"
