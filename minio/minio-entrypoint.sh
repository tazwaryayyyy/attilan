#!/usr/bin/sh
# minio-entrypoint.sh — starts minio server then runs WORM provisioning.
# Runs inside the minio_worm container (cgr.dev/chainguard/minio).
# Both `minio` and `mc` are available at /usr/bin/.
set -e

# Start MinIO server in the background.
echo "[minio-entrypoint] Starting MinIO server..."
minio server /data --console-address ":9001" &
MINIO_PID=$!

# Wait for the API to be ready.
echo "[minio-entrypoint] Waiting for MinIO API..."
until mc ready local 2>/dev/null; do
  sleep 1
done
echo "[minio-entrypoint] MinIO is ready."

# Authenticate local alias using root credentials
mc alias set local http://127.0.0.1:9000 "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}"

# Provision WORM bucket and API user.
echo "[minio-entrypoint] Creating bucket: ${MINIO_EVIDENCE_BUCKET}"
mc mb --with-lock "local/${MINIO_EVIDENCE_BUCKET}" 2>/dev/null || echo "[minio-entrypoint] Bucket already exists."

echo "[minio-entrypoint] Setting COMPLIANCE retention: 3650d"
mc retention set --default COMPLIANCE 3650d "local/${MINIO_EVIDENCE_BUCKET}" || true

echo "[minio-entrypoint] Creating API user: ${MINIO_API_USER}"
mc admin user add local "${MINIO_API_USER}" "${MINIO_API_PASSWORD}" 2>/dev/null || echo "[minio-entrypoint] User already exists."

echo "[minio-entrypoint] Attaching readwrite policy to: ${MINIO_API_USER}"
mc admin policy attach local readwrite --user "${MINIO_API_USER}" 2>/dev/null || true

echo "[minio-entrypoint] WORM provisioning complete."
mc stat "local/${MINIO_EVIDENCE_BUCKET}" || true

# Hand control back to the MinIO server process.
wait ${MINIO_PID}

