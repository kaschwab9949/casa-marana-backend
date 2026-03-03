#!/usr/bin/env bash
set -euo pipefail

echo "Running security hygiene checks..."

blocked_artifact_pattern='\.(p12|p8|mobileprovision|key|crt|cer)$'
if git ls-files | grep -E "${blocked_artifact_pattern}" >/dev/null; then
  echo "Blocked sensitive artifact detected in tracked files."
  git ls-files | grep -E "${blocked_artifact_pattern}" || true
  exit 1
fi

secret_assignment_pattern='(CASA_APP_API_KEY|API_KEY|SQUARE_ACCESS_TOKEN|TWILIO_AUTH_TOKEN|SUPABASE_DATABASE_URL)\s*=\s*["'"'"']?[A-Za-z0-9_/\+\-\.]{12,}'
if git grep -nE -e "${secret_assignment_pattern}" -- . ':!*.example' ':!README.md' >/dev/null; then
  echo "Potential committed secret assignment detected."
  git grep -nE -e "${secret_assignment_pattern}" -- . ':!*.example' ':!README.md' || true
  exit 1
fi

private_key_pattern='-----BEGIN (RSA |EC )?PRIVATE KEY-----'
if git grep -nE -e "${private_key_pattern}" -- . ':!*.example' ':!README.md' >/dev/null; then
  echo "Private key material detected in tracked files."
  git grep -nE -e "${private_key_pattern}" -- . ':!*.example' ':!README.md' || true
  exit 1
fi

echo "Security hygiene checks passed."
